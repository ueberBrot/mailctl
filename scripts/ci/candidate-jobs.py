#!/usr/bin/env python3
"""Seal, restore and collect one build's parallel candidate acceptance evidence."""

import argparse
import json
import os
from pathlib import Path
import re
import platform
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import candidate_evidence as evidence


def context():
    return dict(repository=os.environ["GITHUB_REPOSITORY"], commit=os.environ["GITHUB_SHA"],
                run_id=int(os.environ["GITHUB_RUN_ID"]), run_attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]))


def artifact():
    return dict(id=int(os.environ["MAILCTL_BUILD_ARTIFACT_ID"]),
                digest=os.environ["MAILCTL_BUILD_ARTIFACT_DIGEST"].removeprefix("sha256:"))


def files(directory):
    result = {}
    for path in directory.iterdir():
        evidence.require(re.fullmatch(r"[A-Za-z0-9._-]+", path.name) and
                         stat.S_ISREG(path.lstat().st_mode), "Expected flat regular evidence files")
        evidence.require(path.stat().st_size <= 512 * 1024 * 1024, "Candidate file exceeds size limit")
        result[path.name] = path.read_bytes()
    return result


def load_build(root):
    build = json.loads((root / "build.json").read_bytes())
    evidence.require(build["context"] == context() and build["target"] == os.environ["MAILCTL_TARGET"],
                     "Prepared build belongs to another run or attempt; rerun all candidate jobs")
    return build


def verify_build(root, build, *, extra=False):
    for name in ("candidate", "harnesses"):
        contents = files(root / name)
        expected = build[name]
        evidence.require((set(expected) <= set(contents) if extra and name == "candidate" else set(expected) == set(contents)),
                         "Prepared build file set differs: " + name)
        evidence.require(evidence.hashes({key: contents[key] for key in expected}) == expected,
                         "Prepared build bytes changed: " + name)


def write(directory, contents):
    directory.mkdir()
    for name, data in contents.items():
        (directory / name).write_bytes(data)


def command_for_phase(target, phase):
    evidence.require(phase in evidence.phases(target), "Unexpected acceptance phase")
    scripts = Path(__file__).resolve().parent
    if target == evidence.WINDOWS:
        if phase == "installer":
            return ["pwsh", "-NoProfile", "-File", str(scripts / "windows-candidate.ps1"), "-Phase", "installer"]
        return ["pwsh", "-NoProfile", "-File", str(scripts / "windows-packaged-acceptance.ps1"), "-Phase", phase]
    if phase.startswith("desktop-"):
        return ["bash", str(scripts / "desktop-acceptance.sh"), phase.removeprefix("desktop-")]
    return ["bash", str(scripts / "candidate.sh"), phase]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "seal", "restore", "run", "record", "collect", "verify"))
    parser.add_argument("--phase")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        temporary = Path(os.environ["RUNNER_TEMP"])
        build = temporary / "mailctl-build"
        values = dict(MAILCTL_BUILD_DIR=build, MAILCTL_CANDIDATE_DIR=build / "candidate",
                      MAILCTL_HARNESS_DIR=build / "harnesses", MAILCTL_PACKAGED_BIN_DIR=temporary / "mailctl-installed")
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            for name, value in values.items():
                output.write(f"{name}={value}\n")
        return
    root = Path(os.environ["MAILCTL_BUILD_DIR"])
    candidate = root / "candidate"
    target = os.environ["MAILCTL_TARGET"]
    if args.command == "seal":
        contents = files(candidate)
        sums = {}
        for line in contents["SHA256SUMS"].decode().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
            evidence.require(match and match[2] not in sums, "Malformed prepared checksum manifest")
            sums[match[2]] = match[1]
        extras = {"windows-harnesses.json"} if target == evidence.WINDOWS else set()
        evidence.require(set(contents) == set(sums) | {"SHA256SUMS"} | extras and
                         all(evidence.digest(contents[name]) == value for name, value in sums.items()),
                         "Prepared candidate checksum mismatch")
        build = dict(format=1, context=context(), target=target,
                     candidate=evidence.hashes(contents), harnesses=evidence.hashes(files(root / "harnesses")))
        evidence.require(build["harnesses"], "Candidate acceptance harnesses are missing")
        (root / "build.json").write_bytes(evidence.canonical(build))
        return
    build = load_build(root)
    if args.command == "verify":
        contents = files(candidate)
        evidence.validate(json.loads(contents["parallel-acceptance.json"]), contents, target,
                          context()["commit"], context(), artifact())
        checksums = {}
        for line in contents["SHA256SUMS"].decode().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9._-]+)", line)
            evidence.require(match and match[2] not in checksums, "Malformed final checksum manifest")
            checksums[match[2]] = match[1]
        evidence.require(checksums == {name: evidence.digest(data) for name, data in contents.items() if name != "SHA256SUMS"},
                         "Final candidate checksums do not cover every file")
        return
    verify_build(root, build, extra=args.command == "record")
    if args.command == "run":
        evidence.require(args.phase is not None, "Execution requires an acceptance phase")
        execution = dict(argv=command_for_phase(target, args.phase), env={
            name: os.environ[name] for name in ("MAILCTL_CANDIDATE_DIR", "MAILCTL_HARNESS_DIR", "MAILCTL_PACKAGED_BIN_DIR")})
        ledger = root / "execution.json"
        ledger.unlink(missing_ok=True)
        subprocess.run(execution["argv"], check=True)
        ledger.write_bytes(evidence.canonical(dict(context=context(), phase=args.phase, execution=execution,
                                                 build_sha256=evidence.digest(evidence.canonical(build)), artifact=artifact())))
    elif args.command == "restore":
        # Actions artifacts preserve bytes but strip Unix executable permissions.
        for path in (root / "harnesses").iterdir():
            if path.suffix != ".json":
                path.chmod(0o755)
        for name in build["candidate"]:
            if name.startswith("mailctl-") and not name.endswith((".json", ".txt", ".sha256", ".zip", ".gz")):
                (candidate / name).chmod(0o755)
    elif args.command == "record":
        evidence.require(args.phase and args.evidence, "Recording requires phase and evidence directory")
        ledger = json.loads((root / "execution.json").read_bytes())
        evidence.require(ledger["context"] == context() and ledger["phase"] == args.phase
                         and ledger["build_sha256"] == evidence.digest(evidence.canonical(build))
                         and ledger["artifact"] == artifact(),
                         "Missing current executing shard command")
        contents = {name: data for name, data in files(candidate).items() if name not in build["candidate"]}
        receipt = evidence.receipt(build, args.phase, contents, artifact(),
                                  dict(system=platform.system(), release=platform.release(), machine=platform.machine()),
                                  ledger["execution"])
        # Store shared text without an encoding marker so it can be checked after collection.
        for name in receipt["shared"]:
            contents[name] = contents[name].decode("utf-8-sig").encode()
        receipt["files"] = evidence.hashes(contents)
        write(args.evidence, dict(contents, **{"receipt.json": evidence.canonical(receipt)}))
    elif args.command == "collect":
        evidence.require(args.evidence is not None, "Collection requires an evidence directory")
        shards = []
        payloads = []
        for folder in sorted(args.evidence.iterdir()):
            evidence.require(folder.is_dir() and not folder.is_symlink(), "Unsafe shard directory")
            payload = files(folder)
            receipt = json.loads(payload.pop("receipt.json"))
            evidence.require(evidence.hashes(payload) == receipt["files"], "Acceptance evidence bytes changed")
            shards.append(receipt)
            payloads.append(payload)
        proof = evidence.combine(build, shards, artifact())
        merged = {}
        for shard in proof["shards"]:
            payload = payloads[shards.index(shard)]
            for name, data in payload.items():
                evidence.require(name not in build["candidate"], "Shard replaced prepared bytes")
                if name in evidence.SHARED:
                    merged[name] = merged.get(name, b"") + evidence.normalized(data)
                else:
                    evidence.require(name not in merged, "Duplicate acceptance evidence file")
                    merged[name] = data
        for name, data in merged.items():
            (candidate / name).write_bytes(data)
        (candidate / "parallel-acceptance.json").write_bytes(evidence.canonical(proof))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError, subprocess.CalledProcessError) as error:
        sys.exit("candidate jobs: " + str(error))
