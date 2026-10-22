"""Bind parallel acceptance results to one prepared candidate and CI attempt."""

import hashlib
import json


MAC = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"
WINDOWS = "x86_64-pc-windows-msvc"
TARGETS = (MAC, LINUX, WINDOWS)
SHARED = {"linux-source-evidence.txt", "desktop-source-evidence.txt", "windows-source-evidence.txt"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hashes(files):
    return {name: dict(sha256=digest(data), size=len(data)) for name, data in sorted(files.items())}


def phases(target):
    require(target in TARGETS, "Unsupported candidate target")
    common = ("installer", "state", "process", "native", "reading", "drafts")
    if target == LINUX:
        return common + ("desktop-credentials", "desktop-reading", "desktop-drafts")
    return common + (("wsl",) if target == WINDOWS else ())


def acceptance_groups(target):
    require(target in TARGETS, "Unsupported candidate target")
    if target == WINDOWS:
        return {"installer": ("installer",), "state-native": ("state", "native"),
                **{phase: (phase,) for phase in ("process", "reading", "drafts", "wsl")}}
    groups = {"core": ("installer", "state", "process", "native"),
              "reading": ("reading",), "drafts": ("drafts",)}
    if target == LINUX:
        groups.update({"desktop-reading": ("desktop-reading",),
                       "desktop-drafts": ("desktop-credentials", "desktop-drafts")})
    return groups


def phase_files(target, phase):
    require(phase in phases(target), "Unexpected acceptance phase")
    selections = ("cli", "mcp", "cli-mcp")
    if target == WINDOWS:
        if phase == "installer":
            return {f"installer-acceptance-{host}.log" for host in ("powershell", "pwsh")}
        result = {f"installed-{phase}-{selection}-acceptance.log" for selection in selections}
        result |= {f"{phase}-session.{stream}.log" for stream in ("stdout", "stderr")}
        result.add("windows-source-evidence.txt")
        if phase == "wsl":
            result |= {"windows-wsl-evidence.txt", "windows-wsl.log"}
        return result
    if phase == "installer":
        return {"installer-acceptance.log"}
    if phase in ("state", "process") or (target == MAC and phase == "native"):
        return {f"installed-{phase}-acceptance.log"}
    if target == MAC:
        return {f"installed-{phase}-{selection}-acceptance.log" for selection in selections}
    if phase.startswith("desktop-"):
        suite = phase.removeprefix("desktop-")
        return {"desktop-source-evidence.txt"} | {
            f"installed-{suite}-native-{selection}-acceptance.log" for selection in selections}
    suite = "linux-credentials" if phase == "native" else phase
    result = {"linux-source-evidence.txt"} | {
        f"installed-{suite}-{source}-{selection}-acceptance.log"
        for source in ("command", "systemd") for selection in selections}
    if phase == "native":
        result |= {"installed-native-acceptance.log", "installed-linux-credentials-identity.log"}
        result |= {f"installed-linux-credentials-{name}-acceptance.log"
                   for name in ("systemd_credentials", "systemd_native")}
    return result


def normalized(data):
    return data.decode("utf-8-sig").replace("\r\n", "\n").encode()


def receipt(build, phase, files, artifact, host, execution):
    target = build["target"]
    require(set(files) == phase_files(target, phase), "Acceptance shard has missing or unexpected files: " + phase)
    return dict(format=1, context=build["context"], target=target, phase=phase, artifact=artifact, host=host,
                execution=execution,
                build_sha256=digest(canonical(build)), files=hashes(files),
                shared={name: data.decode("utf-8-sig") for name, data in files.items() if name in SHARED})


def combine(build, shards, artifact):
    target = build["target"]
    expected = phases(target)
    require(len(shards) == len(expected) and {shard["phase"] for shard in shards} == set(expected),
            "Missing or duplicate acceptance shard")
    ordered = sorted(shards, key=lambda shard: expected.index(shard["phase"]))
    for shard in ordered:
        require(shard["format"] == 1 and shard["context"] == build["context"] and shard["target"] == target
                and shard["build_sha256"] == digest(canonical(build)) and shard["artifact"] == artifact,
                "Acceptance shard belongs to another build or attempt")
        require(set(shard["host"]) == {"system", "release", "machine"} and all(shard["host"].values()),
                "Missing executing shard host evidence")
        execution = shard["execution"]
        require(isinstance(execution["argv"], list) and execution["argv"] and
                all(isinstance(value, str) and value for value in execution["argv"]), "Missing executing shard command")
        require(set(execution["env"]) == {"MAILCTL_CANDIDATE_DIR", "MAILCTL_HARNESS_DIR", "MAILCTL_PACKAGED_BIN_DIR"}
                and all(isinstance(value, str) and value for value in execution["env"].values()),
                "Missing installed candidate execution paths")
        require(set(shard["files"]) == phase_files(target, shard["phase"]), "Acceptance shard file set differs")
        require(set(shard["shared"]) == set(shard["files"]) & SHARED, "Shared evidence differs")
    return dict(format=1, build=build, artifact=artifact, shards=ordered)


def validate(proof, files, target, commit, context=None, artifact=None):
    require(proof["format"] == 1, "Unsupported parallel acceptance evidence")
    build = proof["build"]
    require(build["format"] == 1 and build["target"] == target and build["context"]["commit"] == commit,
            "Parallel acceptance candidate differs")
    require(build["context"]["repository"] == "ueberBrot/mailctl", "Unexpected candidate repository")
    if context is not None:
        require(build["context"] == context, "Parallel acceptance belongs to another CI run or attempt")
    if artifact is not None:
        require(proof["artifact"] == artifact, "Prepared artifact identity differs")
    combined = combine(build, proof["shards"], proof["artifact"])
    require(proof == combined, "Acceptance shards are out of order")
    prepared = {name: value for name, value in build["candidate"].items() if name != "SHA256SUMS"}
    outputs = set().union(*(phase_files(target, phase) for phase in phases(target)))
    require(set(files) == set(build["candidate"]) | outputs | {"acceptance-evidence.txt", "parallel-acceptance.json"},
            "Parallel candidate is incomplete or has unexpected files")
    require(set(build["candidate"]) == set(files) - outputs - {"acceptance-evidence.txt", "parallel-acceptance.json"},
            "Prepared candidate file coverage differs")
    require(build["harnesses"], "Missing prepared acceptance harnesses")
    require(hashes({name: files[name] for name in prepared}) == prepared,
            "Prepared candidate bytes changed")
    assembled = {}
    for shard in combined["shards"]:
        for name, metadata in shard["files"].items():
            if name in SHARED:
                text = shard["shared"][name]
                # Source records are normalized only when combining Windows and Unix output.
                data = normalized(text.encode())
                require(metadata["sha256"] == digest(text.encode()) and metadata["size"] == len(text.encode()),
                        "Shared shard evidence hash differs")
                assembled[name] = assembled.get(name, b"") + data
            else:
                require(hashes({name: files[name]})[name] == metadata, "Acceptance log changed: " + name)
    require(all(normalized(files[name]) == data for name, data in assembled.items()), "Merged source evidence differs")
