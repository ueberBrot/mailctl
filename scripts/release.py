#!/usr/bin/env python3
"""Verify mailctl release candidates and upload them to a release-plz draft.

Requires Python 3.11+ and gh. prepare and verify use only GitHub GET requests.
Downloaded programs and installers are never executed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import candidate_evidence
try:
    import tomllib
except ModuleNotFoundError:
    sys.exit("release: Python 3.11 or newer is required")


REPO = "ueberBrot/mailctl"
BASE = "repos/" + REPO + "/"
MAC = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-gnu"
WINDOWS = "x86_64-pc-windows-msvc"
TARGETS = {
    MAC: ("native-credentials", "Record passing candidate acceptance",
          "Keep candidate downloads and acceptance evidence"),
    LINUX: ("linux-candidate", "Record passing Linux candidate acceptance",
            "Keep Linux candidate and acceptance evidence"),
    WINDOWS: ("windows-candidate", "Record passing Windows candidate acceptance",
              "Keep Windows candidate and acceptance evidence"),
}
COMPONENTS = {"cli": "mailctl", "mcp": "mailctl-mcp"}
SELECTIONS = ("cli", "mcp", "cli-mcp")
PHASES = ("state", "process", "native", "reading", "drafts", "wsl")
SOURCE_FILES = ("Cargo.toml", "install.sh", "install.ps1", "CHANGELOG.md")


def archive_name(target):
    return "mailctl-" + target + (".zip" if target == WINDOWS else ".tar.gz")


def binary_name(binary, version, target):
    return f"{binary}-v{version}-{target}" + (".exe" if target == WINDOWS else "")


def artifact_name(target):
    return "mailctl-candidate-" + target


def ci_artifact_name(target, attempt):
    return artifact_name(target) + "-attempt-" + str(attempt)


def test_logs(target):
    if target == WINDOWS:
        return {f"installer-acceptance-{host}.log" for host in ("powershell", "pwsh")} | {
            f"installed-{phase}-{selection}-acceptance.log"
            for phase in PHASES for selection in SELECTIONS}
    logs = {"installer-acceptance.log", "installed-state-acceptance.log",
            "installed-process-acceptance.log", "installed-native-acceptance.log"}
    if target == MAC:
        return logs | {f"installed-{suite}-{selection}-acceptance.log"
                       for suite in ("reading", "drafts") for selection in SELECTIONS}
    return logs | {
        f"installed-{suite}-{source}-{selection}-acceptance.log"
        for suite in ("linux-credentials", "reading", "drafts")
        for source in ("command", "systemd") for selection in SELECTIONS
    } | {f"installed-linux-credentials-{suite}-acceptance.log"
         for suite in ("systemd_credentials", "systemd_native")} | {
        f"installed-{suite}-native-{selection}-acceptance.log"
        for suite in ("credentials", "reading", "drafts") for selection in SELECTIONS}


MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read(path):
    require(stat.S_ISREG(path.lstat().st_mode), "Expected regular file: " + str(path))
    require(path.stat().st_size <= MAX_FILE, "File exceeds size limit: " + str(path))
    return path.read_bytes()


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def fields(data, *, mixed=False):
    result = {}
    for line in data.decode().splitlines():
        if "=" not in line:
            require(mixed, "Malformed evidence line")
            continue  # sw_vers and uname also occur in acceptance evidence.
        key, value = line.split("=", 1)
        require(key not in result, "Duplicate evidence field: " + key)
        result[key] = value
    return result


def matches(actual, expected, context):
    for key, value in expected.items():
        require(type(actual.get(key)) is type(value) and actual.get(key) == value,
                f"{context}: unexpected {key}")


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "Timestamp requires timezone")
    return result


class GitHub:
    """Keep all external commands at one auditable boundary."""

    def call(self, args, *, data=None, output=None, absent_ok=False, cwd=None):
        env = dict(os.environ, GH_HOST="github.com", GH_PROMPT_DISABLED="1")
        result = subprocess.run(["gh", *args], input=data, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, cwd=cwd, check=False)
        if result.returncode:
            if absent_ok and b"(HTTP 404)" in result.stderr:
                return None
            raise ValueError("gh failed: " + result.stderr.decode(errors="replace").strip())
        return result.stdout

    def get(self, endpoint, *, raw=False, absent_ok=False):
        accept = "application/vnd.github.raw+json" if raw else "application/vnd.github+json"
        result = self.call(["api", "--hostname", "github.com", "--method", "GET",
                            BASE + endpoint, "-H", "Accept: " + accept], absent_ok=absent_ok)
        return result if raw or result is None else parse_json(result)

    def pages(self, endpoint, key):
        values = []
        for page in range(1, 101):
            response = self.get(f"{endpoint}?per_page=100&page={page}")
            entries = response[key] if key else response
            values.extend(entries)
            if (key and len(values) == response["total_count"]) or (not key and len(entries) < 100):
                return values
            require(len(entries) == 100, "Incomplete GitHub pagination")
        raise ValueError("GitHub pagination exceeds limit")

    def download(self, artifact_id, destination):
        with destination.open("xb") as output:
            self.call(["api", "--hostname", "github.com", "--method", "GET",
                       BASE + f"actions/artifacts/{artifact_id}/zip"], output=output)

    def job_log(self, job_id):
        return self.call(["api", "--hostname", "github.com", "--method", "GET",
                          BASE + f"actions/jobs/{job_id}/logs", "--allow-escape-sequences"])


def upload_receipt(gh, job, upload, artifact):
    # Runner step times and artifact-service creation times use different clocks.
    # Bind the ID and digest to the successful upload in this attempt's job log.
    expected = [
        "SHA256 digest of uploaded artifact is " + artifact["digest"].removeprefix("sha256:"),
        f"Artifact {artifact['name']} successfully finalized. Artifact ID {artifact['id']}",
        f"Artifact download URL: https://github.com/{REPO}/actions/runs/{job['run_id']}/artifacts/{artifact['id']}",
    ]
    found = []
    log = gh.job_log(job["id"])
    require(len(log) <= MAX_FILE, "Job log exceeds size limit")
    for line in log.decode(errors="replace").splitlines():
        match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z (.*)", line)
        if match and match[2] in expected:
            # The jobs API reports whole seconds; log timestamps retain fractions.
            require(timestamp(upload["started_at"]) <= timestamp(match[1] + "Z")
                    <= timestamp(upload["completed_at"]), "Upload receipt is outside the successful step")
            found.append(match[2])
    require(found == expected, "Missing or ambiguous artifact upload receipt")


def metadata(gh, commit, run_id, artifact_ids):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Use a full lowercase commit SHA")
    require(type(run_id) is int and run_id > 0, "Run ID must be a positive integer")
    require(isinstance(artifact_ids, (list, tuple)) and len(artifact_ids) == len(TARGETS)
            and all(type(value) is int and value > 0 for value in artifact_ids)
            and len(set(artifact_ids)) == len(TARGETS), "Supply three distinct positive artifact IDs")
    main = gh.get("git/ref/heads/main")
    matches(main["object"], {"type": "commit", "sha": commit}, "current main")
    workflow = gh.get("actions/workflows/ci.yml")
    matches(workflow, {"path": ".github/workflows/ci.yml", "state": "active"}, "workflow")
    run = gh.get(f"actions/runs/{run_id}")
    expected = {"id": run_id, "head_sha": commit, "head_branch": "main", "event": "push",
                "status": "completed", "conclusion": "success", "workflow_id": workflow["id"]}
    matches(run, expected, "CI run")
    require(run["path"] in (".github/workflows/ci.yml", ".github/workflows/ci.yml@main",
                            ".github/workflows/ci.yml@refs/heads/main"), "Unexpected run workflow path")
    matches(run["repository"], {"full_name": REPO}, "run repository")
    matches(run["head_repository"], {"full_name": REPO}, "run head repository")
    attempt_number = run["run_attempt"]
    require(type(attempt_number) is int and attempt_number > 0, "Invalid run attempt")
    attempt = gh.get(f"actions/runs/{run_id}/attempts/{attempt_number}")
    matches(attempt, dict(expected, run_attempt=attempt_number, path=run["path"]), "CI attempt")
    jobs = gh.pages(f"actions/runs/{run_id}/attempts/{attempt_number}/jobs", "jobs")
    artifacts = gh.pages(f"actions/runs/{run_id}/artifacts", "artifacts")
    selected = {}
    for artifact_id in artifact_ids:
        artifact = gh.get(f"actions/artifacts/{artifact_id}")
        targets = [target for target in TARGETS if artifact["name"] == ci_artifact_name(target, attempt_number)]
        require(len(targets) == 1 and targets[0] not in selected, "Missing, duplicate, or unsupported target artifact")
        target = targets[0]
        job_name, record_name, upload_name = TARGETS[target]
        candidates = [job for job in jobs if job["name"] == job_name]
        require(len(candidates) == 1, "Expected exactly one candidate job: " + job_name)
        job = candidates[0]
        matches(job, {"run_id": run_id, "head_sha": commit,
                      "status": "completed", "conclusion": "success"}, "candidate job " + target)
        if "run_attempt" in job:
            matches(job, {"run_attempt": attempt_number}, "candidate job attempt")
        steps = {}
        for name in (record_name, upload_name):
            found = [step for step in job["steps"] if step["name"] == name]
            require(len(found) == 1, "Missing candidate step: " + name)
            matches(found[0], {"status": "completed", "conclusion": "success"}, name)
            steps[name] = found[0]
        matches(artifact, {"id": artifact_id, "name": ci_artifact_name(target, attempt_number), "expired": False}, "artifact")
        matches(artifact["workflow_run"], {"id": run_id, "head_sha": commit, "head_branch": "main",
                                          "repository_id": run["repository"]["id"],
                                          "head_repository_id": run["repository"]["id"]}, "artifact run")
        require(type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= MAX_FILE,
                "Artifact exceeds size limit")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), "Missing artifact SHA256 digest")
        require(timestamp(artifact["expires_at"]) > datetime.now(timezone.utc), "Artifact expired")
        # Artifacts lack run_attempt; the job and its receipt identify the attempt.
        require(timestamp(job["started_at"]) <= timestamp(artifact["created_at"])
                <= timestamp(job["completed_at"]), "Artifact belongs to another attempt")
        upload = steps[upload_name]
        require(timestamp(upload["started_at"]) <= timestamp(artifact["created_at"]),
                "Artifact predates this attempt's upload step")
        upload_receipt(gh, job, upload, artifact)
        named = [entry for entry in artifacts if entry["name"] == ci_artifact_name(target, attempt_number)]
        require(len(named) == 1 and named[0] == artifact, "Ambiguous or mismatched run artifact")
        build_name = f"mailctl-build-{target}-attempt-{attempt_number}"
        builds = [entry for entry in artifacts if entry["name"] == build_name]
        require(len(builds) == 1, "Missing or duplicate prepared build artifact")
        build_artifact = builds[0]
        matches(build_artifact, {"expired": False}, "prepared build artifact")
        matches(build_artifact["workflow_run"], artifact["workflow_run"], "prepared build run")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", build_artifact.get("digest", "")) and
                timestamp(build_artifact["expires_at"]) > datetime.now(timezone.utc), "Prepared build digest or retention missing")
        require(type(build_artifact.get("size_in_bytes")) is int and 0 < build_artifact["size_in_bytes"] <= MAX_FILE,
                "Prepared artifact exceeds size limit")
        required = {"build-" + target: ("Seal candidate build", "Keep candidate build")}
        required.update({f"acceptance-{target}-{group}": ("Qualify installed candidate and record evidence",
                                                       "Keep acceptance evidence")
                         for group in candidate_evidence.acceptance_groups(target)})
        for name, required_steps in required.items():
            found = [value for value in jobs if value["name"] == name]
            require(len(found) == 1, "Missing or duplicate parallel candidate job: " + name)
            worker = found[0]
            matches(worker, dict(run_id=run_id, head_sha=commit, status="completed", conclusion="success"), name)
            if "run_attempt" in worker:
                matches(worker, dict(run_attempt=attempt_number), name + " attempt")
            for step_name in required_steps:
                passing = [step for step in worker["steps"] if step["name"] == step_name]
                require(len(passing) == 1, "Missing parallel candidate step: " + step_name)
                matches(passing[0], dict(status="completed", conclusion="success"), step_name)
            if name == "build-" + target:
                upload = next(step for step in worker["steps"] if step["name"] == "Keep candidate build")
                require(timestamp(worker["started_at"]) <= timestamp(build_artifact["created_at"])
                        <= timestamp(worker["completed_at"]), "Prepared build belongs to another attempt")
                upload_receipt(gh, worker, upload, build_artifact)
        selected[target] = dict(job=job, artifact=artifact, build_artifact=build_artifact)
    require(set(selected) == set(TARGETS), "All three qualified targets are required")
    return dict(workflow=workflow, run=run, attempt=attempt, platforms=selected)


def zip_files(path):
    result = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename
            require(name == entry.orig_filename and name and name not in (".", "..") and "/" not in name and "\\" not in name
                    and "\x00" not in name and ":" not in name, "Unsafe ZIP path: " + name)
            require(name not in result, "Duplicate ZIP path: " + name)
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not entry.external_attr & 0x10, "Nonregular ZIP member: " + name)
            total += entry.file_size
            require(entry.file_size <= MAX_FILE and total <= MAX_TOTAL, "ZIP exceeds size limit")
            result[name] = archive.read(entry)
    return result


def candidate_files(version, target):
    archive = archive_name(target)
    files = test_logs(target) | {
        "SHA256SUMS", "acceptance-evidence.txt", "build-evidence.txt", "dist-manifest.json", "parallel-acceptance.json",
        "install.ps1" if target == WINDOWS else "install.sh", archive, archive + ".sha256",
        f"manifest-{target}.txt"} | {
            binary_name(binary, version, target) for binary in COMPONENTS.values()}
    if target == LINUX:
        files |= {"linux-source-evidence.txt", "desktop-source-evidence.txt",
                  "installed-linux-credentials-identity.log"}
    if target == WINDOWS:
        files |= {"windows-source-evidence.txt", "windows-wsl-evidence.txt", "windows-wsl.log",
                  "windows-harnesses.json"} | {
            f"{phase}-session.{stream}.log" for phase in PHASES for stream in ("stdout", "stderr")}
    return files


def checksum_lines(data):
    result = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9._-]+)", line)
        require(match is not None, "Malformed checksum line")
        digest, name = match.groups()
        require(name not in result, "Duplicate checksum: " + name)
        result[name] = digest
    return result


def require_fields(data, expected, context):
    # Linux evidence concatenates host output and separate suite records.
    # Validate all occurrences of contract fields without flattening duplicates.
    values = {}
    for line in data.decode("utf-8-sig").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, []).append(value)
    for key, value in expected.items():
        wanted = value if isinstance(value, list) else [value]
        require(values.get(key) == wanted, f"{context}: unexpected {key}")
    return values


def command_fields(values, names, context):
    require(all(len(values.get(name, [])) == 1 and values[name][0].strip() for name in names),
            "Missing or repeated acceptance commands: " + context)


def validate_linux_sources(files):
    for name, expected in (
        ("linux-source-evidence.txt", dict(execution_identity="65534:65534", provisioning_identity="root",
             credential_sources="explicit-command,systemd-LoadCredential", desktop_session="absent",
             home="disposable-private-directory")),
        ("desktop-source-evidence.txt", dict(credential_source="native-secret-service",
             execution_identity="65534:65534", store="disposable-gnome-keyring", bus="private-session",
             topology="cooperative-embedded", isolation="not-qualified"))):
        blocks = re.split(rb"(?m)^suite=", files[name])
        require(len(blocks) == 4 and not blocks[0].strip(), "Missing Linux suite records: " + name)
        for suite, block in zip(("credentials", "reading", "drafts"), blocks[1:]):
            require(block.splitlines()[0] == suite.encode(), "Unexpected Linux suite order")
            values = require_fields(block, expected, name + " " + suite)
            command_fields(values, ("harness_build",), name)
            if name.startswith("desktop"):
                harness = "secret_service_credentials" if suite == "credentials" else "packaged_" + suite
                commands = {f"{harness}_native_{selection}" for selection in SELECTIONS}
            else:
                harness = "linux_credentials" if suite == "credentials" else "packaged_" + suite
                commands = {f"{harness}_{source}_{selection}"
                            for source in ("command", "systemd") for selection in SELECTIONS}
                if suite == "credentials":
                    commands |= {"systemd_credentials", "systemd_native"}
            command_fields(values, commands, name)
    require(re.search(rb"uid=65534\([^\n]*\).*gid=65534\(",
                      files["installed-linux-credentials-identity.log"]), "Missing disposable Linux identity")


def validate_windows_sources(files):
    records = files["windows-source-evidence.txt"].decode("utf-8-sig").splitlines()
    identities = {}
    selections = set()
    for line in records:
        identity = re.fullmatch(r"phase=(\w+) identity=([^\r\n]+) sid=(S-1-5-21-\d+-\d+-\d+-\d+) "
                                r"credential_source=windows-credential-manager", line)
        if identity:
            phase, name, sid = identity.groups()
            require(phase in PHASES and phase not in identities and
                    re.search(r"\\mailctl_[0-9a-f]{10}$", name), "Unexpected Windows acceptance identity")
            identities[phase] = sid
            continue
        selection = re.fullmatch(r"phase=(\w+) components=(cli|mcp|cli,mcp) installed=(.+) log=(\S+)", line)
        require(selection is not None, "Malformed Windows source record")
        phase, components, _, log = selection.groups()
        label = components.replace(",", "-")
        require(phase in PHASES and (phase, label) not in selections and
                log == f"installed-{phase}-{label}-acceptance.log", "Unexpected Windows source selection")
        selections.add((phase, label))
    require(set(identities) == set(PHASES) and len(set(identities.values())) == len(PHASES),
            "Missing or reused disposable Windows identities")
    require(selections == {(phase, label) for phase in PHASES for label in SELECTIONS},
            "Missing Windows source component selection")
    wsl = fields(files["windows-wsl-evidence.txt"])
    matches(wsl, dict(status="passed", rootfs_sha256="27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2",
                      linux_release="3.22.6", windows_identity_sid=identities["wsl"]), "WSL evidence")
    require(re.fullmatch(r"mailctl-wsl-[0-9a-f]{32}", wsl.get("distro", "")) and
            re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", wsl.get("wsl_version", "")) and
            "WSL2" in wsl.get("kernel", "").upper(), "Missing observed WSL2 environment")
    require(files["windows-wsl.log"].strip(), "Missing WSL command log")
    harnesses = parse_json(files["windows-harnesses.json"].decode("utf-8-sig"))
    require(isinstance(harnesses, list) and len(harnesses) == 3 and
            {selection["Features"] for selection in harnesses} == {"cli", "mcp", "cli,mcp"},
            "Missing Windows compiled component selections")
    for phase in PHASES:
        require(not files[f"{phase}-session.stderr.log"].strip(), "Windows session reported errors: " + phase)


def validate_binary(data, target):
    if target == MAC:
        require(len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe" and
                struct.unpack_from("<I", data, 4)[0] == 0x100000c, "Expected an arm64 Mach-O executable")
    elif target == LINUX:
        require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "Expected an ELF64 executable")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        require(header[1] in (2, 3) and header[2:4] == (62, 1) and header[8:10] == (64, 56),
                "Expected an x86_64 ELF executable")
        offset, count = header[5], header[10]
        require(64 <= offset and 1 <= count <= 128 and offset + count * 56 <= len(data), "Invalid ELF program headers")
        headers = [struct.unpack_from("<IIQQQQQQ", data, offset + index * 56) for index in range(count)]
        interpreters = [header for header in headers if header[0] == 3]
        require(len(interpreters) == 1, "GNU/Linux executable requires one glibc loader")
        start, size = interpreters[0][2], interpreters[0][5]
        require(2 <= size <= 4096 and start + size <= len(data) and data[start:start + size] in
                (b"/lib64/ld-linux-x86-64.so.2\0", b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\0"),
                "GNU/Linux executable requires the x86_64 glibc loader")
    else:
        require(len(data) >= 64 and data[:2] == b"MZ", "Expected a PE executable")
        offset = struct.unpack_from("<I", data, 60)[0]
        require(64 <= offset <= len(data) - 24, "Invalid PE offset")
        signature, machine, sections, _, _, _, optional_size, flags = struct.unpack_from("<4sHHIIIHH", data, offset)
        require(signature == b"PE\0\0" and machine == 0x8664 and 1 <= sections <= 96 and
                optional_size >= 112 and flags & 2 and not flags & 0x2000 and
                offset + 24 + optional_size + sections * 40 <= len(data) and
                data[offset + 24:offset + 26] == b"\x0b\x02", "Expected an x86_64 PE32+ executable")


def archive_binaries(data, target):
    binaries = {}
    names = set()
    total = 0
    def member(name, size, regular, directory, reader):
        nonlocal total
        path = PurePosixPath(name)
        require(name and not path.is_absolute() and ".." not in path.parts and "\\" not in name and
                "\0" not in name and ":" not in name, "Unsafe archive member")
        require(name not in names and (regular or directory), "Duplicate or nonregular archive member")
        names.add(name)
        total += size
        require(size <= MAX_FILE and total <= MAX_TOTAL, "Archive exceeds size limit")
        wanted = {binary + (".exe" if target == WINDOWS else "") for binary in COMPONENTS.values()}
        if path.name in wanted:
            require(regular and path.name not in binaries, "Ambiguous archive binary")
            binaries[path.name] = reader()
    if target == WINDOWS:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for item in archive.infolist():
                require(item.filename == item.orig_filename, "Unsafe ZIP archive member")
                mode = item.external_attr >> 16
                member(item.filename, item.file_size,
                       not item.is_dir() and not item.external_attr & 0x10 and stat.S_IFMT(mode) in (0, stat.S_IFREG),
                       item.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFDIR), lambda: archive.read(item))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for item in archive.getmembers():
                member(item.name, item.size, item.isfile(), item.isdir(), lambda: archive.extractfile(item).read())
    expected = {binary + (".exe" if target == WINDOWS else "") for binary in COMPONENTS.values()}
    require(set(binaries) == expected, "Archive binaries missing")
    return binaries


def validate_candidate(files, source, commit, target):
    version = tomllib.loads(source["Cargo.toml"].decode())["workspace"]["package"]["version"]
    require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version),
            "Source requires a stable release version")
    require(set(files) == candidate_files(version, target), "Candidate must contain the exact expected files: " + target)
    sums = checksum_lines(files["SHA256SUMS"])
    require(sums == {name: sha(data) for name, data in files.items() if name != "SHA256SUMS"},
            "SHA256SUMS must cover every other file with matching hashes")
    archive = archive_name(target)
    common = dict(version=version, target=target, commit=commit, compatibility="1")
    receipt = fields(files[f"manifest-{target}.txt"])
    require(set(receipt) == {"format", "version", "target", "commit", "compatibility"} | {
        component + "_" + key for component in COMPONENTS for key in ("file", "size", "sha256", "signing")},
        "Unexpected component manifest fields")
    matches(receipt, dict(common, format="1"), "component manifest")
    build = fields(files["build-evidence.txt"])
    matches(build, dict(common, status="prepared", source="clean", dist_version="0.33.0",
                        archive_sha256=sha(files[archive]), publication="not-performed", notarization="not-performed",
                        build_command=f"dist build --artifacts=local --target {target} --output-format=json"), "build evidence")
    require(build.get("rustc", "").startswith("rustc "), "Missing build compiler evidence")
    if target == MAC:
        matches(build, dict(architecture="arm64"), "macOS host")
        require(build.get("macos"), "Missing macOS host evidence")
    elif target == LINUX:
        matches(build, dict(architecture="x86_64", elf_class="ELF64", elf_machine="x86_64"), "Linux host")
        require(build.get("libc", "").startswith("glibc ") and build.get("kernel") and
                build.get("os_release") and build.get("os_version") and build.get("elf_interpreter") in
                ("/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), "Missing glibc host evidence")
    else:
        matches(build, dict(os_release="Windows", pe_machine="x86_64", pe_format="PE32+",
                            authenticode_status="NotSigned"), "Windows host")
        require(build.get("architecture", "").lower() in ("amd64", "x86_64") and
                all(build.get(key) for key in ("os_version", "windows_release", "windows_caption", "powershell_version")),
                "Missing Windows host evidence")
    expected = dict(status="passed", topology="cooperative-embedded", real_provider="not-qualified",
                    isolation="not-qualified", publication="not-performed")
    if target == MAC:
        fields(files["acceptance-evidence.txt"], mixed=True)
        expected.update(credential_source="disposable-apple-keychain")
        for suite in ("reading", "drafts"):
            expected[suite + "_credential_source"] = "disposable-command-helper"
            expected[suite + "_tls_source"] = "fixture-ca-via-SSL_CERT_FILE"
    elif target == LINUX:
        expected.update(credential_source=["command,systemd,interactive-session"] + ["native-secret-service"] * 3,
                        topology=["cooperative-embedded"] * 4, isolation=["not-qualified"] * 4)
        validate_linux_sources(files)
    else:
        expected.update(credential_source="disposable-windows-credential-manager", target=target,
                        windows_hosted_wsl="qualified", wsl_evidence="windows-wsl-evidence.txt")
        for suite in ("reading", "drafts"):
            expected[suite + "_credential_source"] = "disposable-windows-credential-manager"
            expected[suite + "_tls_source"] = "fixture-ca-via-SSL_CERT_FILE"
        validate_windows_sources(files)
    values = require_fields(files["acceptance-evidence.txt"], expected, "acceptance evidence")
    if target == WINDOWS:
        command_fields(values, {"installer_command_powershell", "installer_command_pwsh"}, target)
        require(values.get("windows_powershell_version", [""])[0].startswith("5.1.") and
                values.get("powershell_version", [""])[0].startswith("7."), "Missing qualified PowerShell hosts")
        require(files["windows-source-evidence.txt"].decode("utf-8-sig").replace("\r\n", "\n").strip() in
                files["acceptance-evidence.txt"].decode("utf-8-sig").replace("\r\n", "\n"),
                "Windows source evidence differs")
    else:
        commands = {suite + "_command" for suite in ("installer", "state", "process", "native")}
        if target == MAC:
            commands |= {f"{suite}{kind}_command_{selection}" for suite in ("reading", "drafts")
                         for kind in ("", "_components") for selection in ("cli", "mcp", "cli,mcp")}
        else:
            require(all(files[name].decode().strip() in files["acceptance-evidence.txt"].decode()
                        for name in ("linux-source-evidence.txt", "desktop-source-evidence.txt")),
                    "Linux source evidence differs")
        command_fields(values, commands, target)
    for name in test_logs(target):
        require(files[name].strip(), "Empty acceptance log: " + name)
        if name.startswith("installer-acceptance"):
            require(re.search(rb"^OK\s*$", files[name], re.MULTILINE), "Missing passing installer tests")
        else:
            results = re.findall(rb"^test result: (.+)$", files[name], re.MULTILINE)
            require(results and all(re.match(rb"ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;", result)
                                    for result in results), "Missing passing tests: " + name)
    installer = "install.ps1" if target == WINDOWS else "install.sh"
    source_installer = source[installer]
    source_bound = files[installer] == source_installer
    if target == WINDOWS and b"\r" not in source_installer:
        # Windows Git checkout may convert every source LF to CRLF. Preserve the
        # actual qualified bytes in assets; permit only this complete conversion.
        source_bound |= files[installer] == source_installer.replace(b"\n", b"\r\n")
    require(source_bound, "Installer differs from fixed source commit")
    compatibility = b"$Fields.compatibility -cne '1'" if target == WINDOWS else b"compatibility=1"
    require(compatibility in source[installer], "Source installer compatibility changed")
    manifest = parse_json(files["dist-manifest.json"].decode("utf-8-sig"))
    matches(manifest, {"dist_version": "0.33.0"}, "dist manifest")
    require(len(manifest["releases"]) == 1, "Expected one dist release")
    release = manifest["releases"][0]
    matches(release, {"app_name": "mailctl", "app_version": version}, "dist release")
    require(archive in release["artifacts"], "Dist release lacks candidate archive")
    dist_archive = manifest["artifacts"][archive]
    matches(dist_archive, {"name": archive, "target_triples": [target], "checksum": archive + ".sha256"}, "dist archive")
    matches(dist_archive["checksums"], {"sha256": sha(files[archive])}, "dist checksum")
    require({asset["name"] for asset in dist_archive["assets"] if asset["kind"] == "executable"}
            == set(COMPONENTS.values()), "Dist executables differ")
    matches(manifest["artifacts"][archive + ".sha256"], {"name": archive + ".sha256"}, "dist checksum artifact")
    checksum = files[archive + ".sha256"].decode().strip().split()
    require(len(checksum) in (1, 2) and checksum[0] == sha(files[archive]), "Archive checksum mismatch")
    if len(checksum) == 2:
        require(checksum[1].lstrip("*") == archive, "Unexpected archive checksum filename")
    binaries = archive_binaries(files[archive], target)
    for component, binary in COMPONENTS.items():
        name = binary_name(binary, version, target)
        require(0 < len(files[name]) <= 104857600, "Component size exceeds installer limit")
        matches(receipt, {component + "_file": name, component + "_size": str(len(files[name])),
                          component + "_sha256": sha(files[name])}, "component bytes")
        allowed = ("ad-hoc", "unsigned") if target == MAC else ("unsigned",)
        require(receipt[component + "_signing"] in allowed, "Unqualified signing evidence")
        require(binaries[binary + (".exe" if target == WINDOWS else "")] == files[name],
                "Raw binary differs from archive: " + binary)
        validate_binary(files[name], target)
    changelog = source["CHANGELOG.md"].decode()
    headings = list(re.finditer(r"^## \[?v?" + re.escape(version) +
                               r"\]?(?:\(https://[^\s)]+\))?(?:\s.*)?$", changelog, re.MULTILINE))
    require(len(headings) == 1, "Fixed source requires exactly one changelog entry for the release version")
    section = changelog[headings[0].end():].split("\n## ", 1)[0].strip()
    require(section, "Release changelog entry is empty")
    return version, section


def qualification(data, commit, meta):
    notes = parse_json(data)
    matches(notes, {"source_commit": commit}, "qualification source")
    associations = notes["artifact_associations"]
    require(set(associations) == set(TARGETS), "Qualification must cover all three targets")
    for target, platform in meta["platforms"].items():
        artifact = platform["artifact"]
        matches(associations[target], dict(commit=commit, run_id=meta["run"]["id"],
                run_attempt=meta["run"]["run_attempt"], artifact_id=artifact["id"],
                artifact_sha256=artifact["digest"]), "qualification association " + target)
    for key in ("operator", "association_notes"):
        require(isinstance(notes.get(key), str) and notes[key].strip(), "Missing qualification " + key)
    links = notes.get("accepted_source_evidence")
    require(isinstance(links, list) and links and all(isinstance(link, str) and
            re.fullmatch(r"https://[^\s]+", link) for link in links), "Supply accepted source evidence links")
    return notes


def release_assets(bundles, zips, version):
    assets = {}
    for target, files in bundles.items():
        archive = archive_name(target)
        names = {archive, archive + ".sha256", "manifest-" + target + ".txt",
                 "install.ps1" if target == WINDOWS else "install.sh"} | {
                     binary_name(binary, version, target) for binary in COMPONENTS.values()}
        for name in names:
            if name in assets:
                require(name == "install.sh" and assets[name] == files[name], "Conflicting release asset: " + name)
            assets[name] = files[name]
        name = artifact_name(target) + ".zip"
        require(name not in assets, "Conflicting evidence asset: " + name)
        assets[name] = zips[target]
    assets["SHA256SUMS"] = "".join(f"{sha(data)}  {name}\n" for name, data in sorted(assets.items())).encode()
    return assets


def plan_for(directory, meta, source, bundles, zips):
    commit = meta["run"]["head_sha"]
    versions = {validate_candidate(files, source, commit, target) for target, files in bundles.items()}
    context = dict(repository=REPO, commit=commit, run_id=meta["run"]["id"], run_attempt=meta["run"]["run_attempt"])
    for target, files in bundles.items():
        build = meta["platforms"][target]["build_artifact"]
        candidate_evidence.validate(parse_json(files["parallel-acceptance.json"]), files, target, commit, context,
                                    dict(id=build["id"], digest=build["digest"].removeprefix("sha256:")))
    require(len(versions) == 1, "Candidate release versions differ")
    version, changelog = versions.pop()
    note_bytes = read(directory / "qualification-notes.json")
    qualification(note_bytes, commit, meta)
    notes = changelog.encode()
    assets = release_assets(bundles, zips, version)
    plan = dict(format=2, repository=REPO, commit=commit, version=version, tag="v" + version,
                run_id=meta["run"]["id"], run_attempt=meta["run"]["run_attempt"],
                artifacts={target: dict(id=platform["artifact"]["id"], name=platform["artifact"]["name"],
                                        sha256=platform["artifact"]["digest"], job_id=platform["job"]["id"])
                           for target, platform in sorted(meta["platforms"].items())},
                assets={name: dict(size=len(data), sha256=sha(data)) for name, data in sorted(assets.items())},
                source={name: sha(data) for name, data in source.items()},
                metadata_sha256=sha(read(directory / "metadata.json")),
                qualification_notes_sha256=sha(note_bytes), release_notes_sha256=sha(notes))
    return plan, notes, assets


def load_bundles(directory, meta):
    root = directory / "candidates"
    require(root.is_dir() and not root.is_symlink() and
            {path.name for path in root.iterdir()} == set(TARGETS), "Unsafe or incomplete candidate directories")
    bundles, zips = {}, {}
    expanded_total = 0
    compressed_total = 0
    for target, platform in meta["platforms"].items():
        folder = root / target
        require(folder.is_dir() and not folder.is_symlink(), "Unsafe target directory")
        zipped = read(folder / "artifact.zip")
        require("sha256:" + sha(zipped) == platform["artifact"]["digest"], "ZIP digest mismatch: " + target)
        zips[target] = zipped
        bundles[target] = zip_files(folder / "artifact.zip")
        prepared = read(folder / "prepared.zip")
        require("sha256:" + sha(prepared) == platform["build_artifact"]["digest"], "Prepared ZIP digest mismatch")
        with zipfile.ZipFile(io.BytesIO(prepared)) as archive:
            entries = archive.infolist()
            require(len({entry.filename for entry in entries}) == len(entries), "Duplicate prepared artifact path")
            manifests = [entry for entry in entries if entry.filename == "build.json"]
            require(len(manifests) == 1 and manifests[0].file_size <= 1024 * 1024, "Missing prepared build manifest")
            build = parse_json(archive.read(manifests[0]))
            expected = {f"{group}/{name}": value for group in ("candidate", "harnesses")
                        for name, value in build[group].items()}
            require(set(expected) | {"build.json"} == {entry.filename for entry in entries},
                    "Prepared artifact file set differs")
            require(sum(entry.file_size for entry in entries) <= MAX_TOTAL, "Prepared artifact exceeds size limit")
            for entry in entries:
                require(entry.filename == entry.orig_filename and not entry.is_dir()
                        and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                        and entry.file_size <= MAX_FILE, "Unsafe prepared artifact member")
                if entry.filename != "build.json":
                    require(candidate_evidence.hashes({entry.filename: archive.read(entry)})[entry.filename]
                            == expected[entry.filename], "Prepared artifact manifest hash differs")
            proof = parse_json(bundles[target]["parallel-acceptance.json"])
            require(proof["build"] == build, "Collected manifest differs from authenticated prepared artifact")
        expanded_total += sum(len(data) for data in bundles[target].values())
        compressed_total += len(zipped) + len(prepared)
        require(expanded_total <= MAX_TOTAL and compressed_total <= MAX_TOTAL,
                "Combined candidates exceed size limit")
    return bundles, zips


def require_directory_files(directory, files):
    require(directory.is_dir() and not directory.is_symlink() and
            {path.name for path in directory.iterdir()} == set(files), "Local assets differ: " + str(directory))
    for name, data in files.items():
        require(read(directory / name) == data, "Local asset changed: " + name)


def prepare(gh, commit, run_id, artifact_ids, qualification_notes, directory):
    require(not directory.exists() and not directory.is_symlink(), "Output directory must not exist")
    meta = metadata(gh, commit, run_id, artifact_ids)
    directory.mkdir(parents=True, mode=0o700)
    (directory / "metadata.json").write_bytes(canonical(meta))
    (directory / "candidates").mkdir(mode=0o700)
    for target, platform in meta["platforms"].items():
        folder = directory / "candidates" / target
        folder.mkdir(mode=0o700)
        gh.download(platform["artifact"]["id"], folder / "artifact.zip")
        gh.download(platform["build_artifact"]["id"], folder / "prepared.zip")
    bundles, zips = load_bundles(directory, meta)
    source = {}
    (directory / "source").mkdir(mode=0o700)
    for name in SOURCE_FILES:
        source[name] = gh.get(f"contents/{name}?ref={commit}", raw=True)
        require(len(source[name]) <= MAX_FILE, "Source file exceeds size limit")
        (directory / "source" / name).write_bytes(source[name])
    (directory / "qualification-notes.json").write_bytes(read(qualification_notes))
    plan, notes, assets = plan_for(directory, meta, source, bundles, zips)
    for target, files in bundles.items():
        folder = directory / "candidates" / target / "files"
        folder.mkdir(mode=0o700)
        for name, data in files.items():
            (folder / name).write_bytes(data)
    (directory / "assets").mkdir(mode=0o700)
    for name, data in assets.items():
        (directory / "assets" / name).write_bytes(data)
    (directory / "release-notes.md").write_bytes(notes)
    encoded = canonical(plan)
    (directory / "plan.json").write_bytes(encoded)
    (directory / "PLAN_SHA256").write_text(sha(encoded) + "\n")
    return sha(encoded)


def source_version(gh, commit):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Use a full lowercase commit SHA")
    source = gh.get(f"contents/Cargo.toml?ref={commit}", raw=True)
    return tomllib.loads(source.decode())["workspace"]["package"]["version"]


def check_state(gh, commit):
    tag = "v" + source_version(gh, commit)
    ref = gh.get("git/ref/tags/" + tag, absent_ok=True)
    releases = [release for release in gh.pages("releases", None) if release["tag_name"] == tag]
    require((ref is None and not releases) or
            (ref is not None and len(releases) == 1 and releases[0]["draft"] is False),
            "Unfinished publication for " + tag + "; inspect the tag, draft and retained plan for manual recovery")


def prepare_ci(gh, commit, run_id, releases, directory):
    version = source_version(gh, commit)
    selected = parse_json(releases)
    require(isinstance(selected, list) and len(selected) == 1, "Expected one release-plz product release")
    matches(selected[0], dict(package_name="mailctl", version=version, tag="v" + version), "release-plz output")
    artifacts = gh.pages(f"actions/runs/{run_id}/artifacts", "artifacts")
    run = gh.get(f"actions/runs/{run_id}")
    names = {ci_artifact_name(target, run["run_attempt"]) for target in TARGETS}
    ids = [artifact["id"] for artifact in artifacts if artifact["name"] in names]
    meta = metadata(gh, commit, run_id, ids)
    notes = dict(source_commit=commit, operator="Maintainer merge of the release-plz PR",
                 accepted_source_evidence=[f"https://github.com/{REPO}/actions/runs/{run_id}"],
                 association_notes="These exact artifacts passed the automated installed reading, draft, "
                 "credential and platform checks in this CI attempt. Live provider and agent-client "
                 "qualification are historical; this run does not refresh them or qualify isolation.",
                 artifact_associations={target: dict(commit=commit, run_id=run_id,
                     run_attempt=meta["run"]["run_attempt"], artifact_id=platform["artifact"]["id"],
                     artifact_sha256=platform["artifact"]["digest"])
                     for target, platform in meta["platforms"].items()})
    with tempfile.TemporaryDirectory(prefix="mailctl-release-notes-", dir=directory.parent) as temporary:
        path = Path(temporary) / "qualification.json"
        path.write_bytes(canonical(notes))
        return prepare(gh, commit, run_id, ids, path, directory)


def verify(gh, directory):
    require(directory.is_dir() and not directory.is_symlink(), "Expected a plan directory")
    require(not (directory / "publication-started.json").exists(), "Publication already started; use manual recovery")
    encoded = read(directory / "plan.json")
    require(read(directory / "PLAN_SHA256") == (sha(encoded) + "\n").encode(), "Plan digest mismatch")
    plan = parse_json(encoded)
    matches(plan, dict(format=2), "plan format")
    saved = parse_json(read(directory / "metadata.json"))
    current = metadata(gh, plan["commit"], plan["run_id"], [artifact["id"] for artifact in plan["artifacts"].values()])
    require(current == saved, "Remote metadata changed since preparation")
    bundles, zips = load_bundles(directory, current)
    source = {}
    require((directory / "source").is_dir() and not (directory / "source").is_symlink(), "Unsafe source directory")
    for name in SOURCE_FILES:
        source[name] = read(directory / "source" / name)
        require(source[name] == gh.get(f"contents/{name}?ref={plan['commit']}", raw=True), "Fixed source changed: " + name)
    for target, files in bundles.items():
        require_directory_files(directory / "candidates" / target / "files", files)
    expected, notes, assets = plan_for(directory, saved, source, bundles, zips)
    require(encoded == canonical(expected), "Plan content mismatch")
    require_directory_files(directory / "assets", assets)
    require(read(directory / "release-notes.md") == notes, "Release notes changed")
    return plan, sha(encoded)


def approved_payload(directory, plan, digest):
    require(sha(read(directory / "plan.json")) == digest, "Approved plan changed during publication")
    require(sha(read(directory / "release-notes.md")) == plan["release_notes_sha256"],
            "Approved notes changed during publication")
    assets = directory / "assets"
    require(assets.is_dir() and not assets.is_symlink() and
            {path.name for path in assets.iterdir()} == set(plan["assets"]), "Approved assets changed during publication")
    for name, expected in plan["assets"].items():
        data = read(assets / name)
        require(len(data) == expected["size"] and sha(data) == expected["sha256"],
                "Approved asset changed during publication: " + name)


def require_tag(gh, plan):
    obj = gh.get("git/ref/tags/" + plan["tag"])["object"]
    if obj["type"] == "tag":
        annotated = gh.get("git/tags/" + obj["sha"])
        matches(annotated, {"tag": plan["tag"]}, "annotated release tag")
        obj = annotated["object"]
    matches(obj, {"type": "commit", "sha": plan["commit"]}, "release tag")


def draft_release(gh, plan):
    releases = [release for release in gh.pages("releases", None) if release["tag_name"] == plan["tag"]]
    require(len(releases) == 1, "Expected exactly one draft release")
    release = releases[0]
    matches(release, {"tag_name": plan["tag"], "draft": True}, "draft release")
    require(sha(release["body"].encode()) == plan["release_notes_sha256"], "Draft release notes differ from the changelog")
    return release


def publish_draft(gh, directory, plan, digest, *, latest=False):
    release = draft_release(gh, plan)
    assets = gh.pages(f"releases/{release['id']}/assets", None)
    require(len(assets) == len(plan["assets"]), "Remote asset count differs; draft remains unpublished")
    seen = set()
    for asset in assets:
        name = asset["name"]
        require(name in plan["assets"] and name not in seen, "Remote asset names differ; draft remains unpublished")
        seen.add(name)
        expected = plan["assets"][name]
        matches(asset, {"size": expected["size"], "digest": "sha256:" + expected["sha256"],
                       "state": "uploaded"}, "remote asset " + name)
    require_tag(gh, plan)
    approved_payload(directory, plan, digest)
    gh.call(["release", "edit", plan["tag"], "--draft=false", "--repo", REPO,
             *(["--latest"] if latest else [])])
    matches(gh.get(f"releases/{release['id']}"), {"tag_name": plan["tag"], "draft": False}, "published release")


def finalize(gh, directory):
    plan, digest = verify(gh, directory)
    require_tag(gh, plan)
    release = draft_release(gh, plan)
    require(not gh.pages(f"releases/{release['id']}/assets", None), "Draft already has assets; use manual recovery")
    with (directory / "publication-started.json").open("xb") as journal:
        journal.write(canonical(dict(plan_sha256=digest, tag=plan["tag"], commit=plan["commit"])))
    approved_payload(directory, plan, digest)
    gh.call(["release", "upload", plan["tag"], "--repo", REPO, *sorted(plan["assets"])],
            cwd=directory / "assets")
    publish_draft(gh, directory, plan, digest, latest=True)


def publish(gh, directory, approved):
    require(re.fullmatch(r"[0-9a-f]{64}", approved), "Approval requires the exact plan SHA256")
    require(sha(read(directory / "plan.json")) == approved, "Approved digest differs from this plan")
    plan, digest = verify(gh, directory)
    require(digest == approved, "Approved digest changed")
    tag = plan["tag"]
    require(gh.get("git/ref/tags/" + tag, absent_ok=True) is None, "Tag already exists; use manual recovery")
    require(not [release for release in gh.pages("releases", None) if release["tag_name"] == tag],
            "Release already exists; use manual recovery")
    # Exclusive journal: a failed or interrupted attempt cannot be retried automatically.
    with (directory / "publication-started.json").open("xb") as journal:
        journal.write(canonical(dict(plan_sha256=digest, tag=tag, commit=plan["commit"])))
    approved_payload(directory, plan, digest)
    gh.call(["api", "--hostname", "github.com", "--method", "POST", BASE + "git/refs",
             "--input", "-"], data=canonical(dict(ref="refs/tags/" + tag, sha=plan["commit"])))
    remote_tag = gh.get("git/ref/tags/" + tag)
    matches(remote_tag["object"], {"type": "commit", "sha": plan["commit"]}, "created tag")
    approved_payload(directory, plan, digest)
    gh.call(["release", "create", tag, "--draft", "--verify-tag", "--repo", REPO,
             "--title", tag, "--notes-file", str(directory / "release-notes.md"),
             *sorted(plan["assets"])], cwd=directory / "assets")
    publish_draft(gh, directory, plan, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="Preserve a current-main candidate using GET requests")
    prep.add_argument("--commit", required=True)
    prep.add_argument("--run-id", required=True, type=int)
    prep.add_argument("--artifact-id", required=True, type=int, action="append",
                      help="repeat once per qualified macOS, Linux and Windows target")
    prep.add_argument("--qualification-notes", required=True, type=Path)
    prep.add_argument("--output", required=True, type=Path)
    ci = commands.add_parser("prepare-ci", help="Verify the artifacts selected by a native release-plz release")
    ci.add_argument("--commit", required=True)
    ci.add_argument("--run-id", required=True, type=int)
    ci.add_argument("--output", required=True, type=Path)
    commands.add_parser("finalize", help="Upload verified artifacts and publish the release-plz draft").add_argument("directory", type=Path)
    commands.add_parser("check-state", help="Reject unfinished publication after release-plz skips a version").add_argument("--commit", required=True)
    commands.add_parser("verify", help="Revalidate local files and GitHub metadata using GET requests").add_argument("directory", type=Path)
    pub = commands.add_parser("publish", help="Create a tag and publish only the explicitly approved plan")
    pub.add_argument("directory", type=Path)
    pub.add_argument("--approve", required=True, metavar="PLAN_SHA256")
    args = parser.parse_args()
    gh = GitHub()
    try:
        if args.command == "prepare":
            result = prepare(gh, args.commit, args.run_id, args.artifact_id,
                             args.qualification_notes, args.output.absolute())
        elif args.command == "verify":
            _, result = verify(gh, args.directory.absolute())
        elif args.command == "prepare-ci":
            result = prepare_ci(gh, args.commit, args.run_id, os.environ.get("MAILCTL_RELEASES", ""), args.output.absolute())
        elif args.command == "finalize":
            finalize(gh, args.directory.absolute())
            result = "Published the verified release-plz draft"
        elif args.command == "check-state":
            check_state(gh, args.commit)
            result = "No unfinished publication"
        else:
            publish(gh, args.directory.absolute(), args.approve)
            result = "Published approved plan " + args.approve
        print(result)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, "release: " + str(error) + "\n")


if __name__ == "__main__":
    main()
