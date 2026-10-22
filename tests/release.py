#!/usr/bin/env python3
"""Run offline release-helper checks with Python 3.11 or later.

Run ``python3 tests/release.py`` from the repository root. Every GitHub command
stops at FakeGitHub.call. The fixture programs are bytes and never run.
"""

from copy import deepcopy
import importlib.util
import io
import json
import re
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("mailctl_release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

COMMIT = "a" * 40
VERSION = "0.1.0"
RUN_ID = 1234
ATTEMPT = 2
ARTIFACT_ID = 5678
RELEASE_ID = 9012
TARGETS = (release.MAC, release.LINUX, release.WINDOWS)
ARTIFACT_IDS = [ARTIFACT_ID + index for index in range(3)]
ACCEPTANCE_GROUPS = {
    release.MAC: ("core", "reading"),
    release.LINUX: ("core", "reading"),
    release.WINDOWS: ("core", "content"),
}


def prepared_zip(build, files):
    original = {name: files[name] for name in build["candidate"] if name != "SHA256SUMS"}
    original["SHA256SUMS"] = b"".join(f"{release.sha(data)}  {name}\n".encode() for name, data in sorted(original.items()))
    return make_zip([(name, data, stat.S_IFREG | 0o644) for name, data in [
        ("build.json", release.canonical(build)), ("harnesses/fixture-driver", b"driver"),
        *(("candidate/" + name, data) for name, data in original.items())]])


def parallel_proof(target, files):
    parallel = release.candidate_evidence
    phase_names = parallel.phases(target)
    outputs = set().union(*(parallel.phase_files(target, phase) for phase in phase_names))
    original = {name: data for name, data in files.items()
                if name not in outputs | {"acceptance-evidence.txt", "SHA256SUMS", "parallel-acceptance.json"}}
    original["SHA256SUMS"] = b"".join(f"{release.sha(data)}  {name}\n".encode() for name, data in sorted(original.items()))
    build = dict(format=1, target=target,
                 context=dict(repository=release.REPO, commit=COMMIT, run_id=RUN_ID, run_attempt=ATTEMPT),
                 candidate=parallel.hashes(original), harnesses=parallel.hashes({"fixture-driver": b"driver"}))
    artifact = dict(id=9000 + TARGETS.index(target), digest=release.sha(prepared_zip(build, files)))
    receipts = []
    for phase in phase_names:
        contents = {name: files[name] for name in parallel.phase_files(target, phase)}
        for name in set(contents) & parallel.SHARED:
            data = parallel.normalized(contents[name])
            if target == release.WINDOWS:
                contents[name] = b"".join(line + b"\n" for line in data.splitlines()
                                         if line.startswith(f"phase={phase} ".encode()))
            else:
                suite = "credentials" if phase in ("native", "desktop-credentials") else phase.removeprefix("desktop-")
                blocks = re.split(rb"(?m)^suite=", data)[1:]
                contents[name] = next(b"suite=" + block for block in blocks if block.splitlines()[0] == suite.encode())
        receipts.append(parallel.receipt(build, phase, contents, artifact,
                                        dict(system="fixture", release="fixture", machine="fixture"),
                                        dict(argv=["fixture-runner", phase], env={
                                            name: "/fixture/" + name for name in
                                            ("MAILCTL_CANDIDATE_DIR", "MAILCTL_HARNESS_DIR", "MAILCTL_PACKAGED_BIN_DIR")})))
    return parallel.canonical(parallel.combine(build, receipts, artifact))


MAC_LOGS = {
    "installer-acceptance.log", "installed-state-acceptance.log",
    "installed-process-acceptance.log", "installed-native-acceptance.log",
    "installed-reading-cli-acceptance.log", "installed-reading-mcp-acceptance.log",
    "installed-reading-cli-mcp-acceptance.log", "installed-drafts-cli-acceptance.log",
    "installed-drafts-mcp-acceptance.log", "installed-drafts-cli-mcp-acceptance.log",
}
LINUX_LOGS = {"installer-acceptance.log", "installed-state-acceptance.log",
              "installed-process-acceptance.log", "installed-native-acceptance.log"} | {
    f"installed-{suite}-{source}-{selection}-acceptance.log"
    for suite in ("linux-credentials", "reading", "drafts")
    for source in ("command", "systemd") for selection in ("cli", "mcp", "cli-mcp")
} | {f"installed-linux-credentials-{harness}-acceptance.log"
     for harness in ("systemd_credentials", "systemd_native")} | {
    f"installed-{suite}-native-{selection}-acceptance.log"
    for suite in ("credentials", "reading", "drafts") for selection in ("cli", "mcp", "cli-mcp")}
WINDOWS_LOGS = {"installer-acceptance-powershell.log", "installer-acceptance-pwsh.log"} | {
    f"installed-{phase}-{selection}-acceptance.log"
    for phase in ("state", "process", "native", "reading", "drafts", "wsl")
    for selection in ("cli", "mcp", "cli-mcp")}
LOGS_BY_TARGET = {release.MAC: MAC_LOGS, release.LINUX: LINUX_LOGS, release.WINDOWS: WINDOWS_LOGS}


def expected_assets():
    result = {"install.sh", "install.ps1", "SHA256SUMS"}
    for target in TARGETS:
        archive = "mailctl-" + target + (".zip" if target == release.WINDOWS else ".tar.gz")
        result |= {archive, archive + ".sha256", "manifest-" + target + ".txt",
                   "mailctl-candidate-" + target + ".zip"}
        result |= {f"{binary}-v{VERSION}-{target}" + (".exe" if target == release.WINDOWS else "")
                   for binary in ("mailctl", "mailctl-mcp")}
    return result


EXPECTED_CANDIDATE = expected_assets()

def evidence(values):
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


def make_zip(entries):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # Deliberate duplicate-member fixtures.
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, data)
    return output.getvalue()


def native_binary(target, payload):
    if target == release.MAC:
        return struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0) + payload
    if target == release.LINUX:
        loader = b"/lib64/ld-linux-x86-64.so.2\0"
        header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                             3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        return header + struct.pack("<IIQQQQQQ", 3, 0, 120, 0, 0, len(loader), len(loader), 1) + loader + payload
    header = bytearray(64)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    return bytes(header) + struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664, 1, 0, 0, 0, 112, 2) + b"\x0b\x02" + b"\0" * 150 + payload


class Candidate:
    """Model each native CI artifact, including source records and executable headers."""

    def __init__(self, target=release.MAC):
        self.target = target
        self.source = {
            "Cargo.toml": b'[workspace.package]\nversion = "0.1.0"\n',
            "install.sh": (ROOT / "install.sh").read_bytes(),
            "install.ps1": (ROOT / "install.ps1").read_bytes(),
            "CHANGELOG.md": b"# Changelog\n\n## [0.1.0] - 2026-10-15\n\nInitial release.\n",
        }
        self.binaries = {binary: native_binary(target, binary.encode() + b" candidate bytes\n")
                         for binary in ("mailctl", "mailctl-mcp")}
        self.files = {}
        receipt = dict(format="1", version=VERSION, target=target, commit=COMMIT, compatibility="1")
        for component, binary in release.COMPONENTS.items():
            name = release.binary_name(binary, VERSION, target)
            self.files[name] = self.binaries[binary]
            receipt.update({component + "_file": name, component + "_sha256": release.sha(self.binaries[binary]),
                            component + "_size": str(len(self.binaries[binary])),
                            component + "_signing": "ad-hoc" if target == release.MAC else "unsigned"})
        self.files[f"manifest-{target}.txt"] = evidence(receipt)
        installer = "install.ps1" if target == release.WINDOWS else "install.sh"
        self.files[installer] = (self.source[installer].replace(b"\n", b"\r\n")
                                 if target == release.WINDOWS else self.source[installer])
        build = dict(status="prepared", source="clean", commit=COMMIT, version=VERSION,
                     target=target, compatibility="1", dist_version="0.33.0", rustc="rustc 1.98.1 (fixture)",
                     archive_sha256="pending", build_command=f"dist build --artifacts=local --target {target} --output-format=json",
                     publication="not-performed", notarization="not-performed")
        if target == release.MAC:
            build.update(macos="26.0", architecture="arm64")
        elif target == release.LINUX:
            build.update(os_release="ubuntu", os_version="24.04", kernel="6.11.0", libc="glibc 2.39",
                         elf_class="ELF64", elf_machine="x86_64", elf_interpreter="/lib64/ld-linux-x86-64.so.2",
                         architecture="x86_64")
        else:
            build.update(os_release="Windows", os_version="10.0.26100", windows_release="2025Server",
                         pe_machine="x86_64", pe_format="PE32+", authenticode_status="NotSigned",
                         powershell_version="7.6.6", windows_caption="Microsoft Windows Server 2025", architecture="AMD64")
        self.files["build-evidence.txt"] = evidence(build)
        acceptance = dict(status="passed", topology="cooperative-embedded", packaged_bin_directory="native-installed-bin")
        if target == release.WINDOWS:
            acceptance.update(credential_source="disposable-windows-credential-manager", target=target,
                              windows_hosted_wsl="qualified", wsl_evidence="windows-wsl-evidence.txt",
                              windows_powershell_version="5.1.26100", powershell_version="7.6.6",
                              installer_command_powershell='["powershell.exe","tests/installer.ps1"]',
                              installer_command_pwsh='["pwsh","tests/installer.ps1"]')
        else:
            acceptance["credential_source"] = ("disposable-apple-keychain" if target == release.MAC else
                                                "command,systemd,interactive-session")
            acceptance.update({suite + "_command": "native acceptance " + suite
                               for suite in ("installer", "state", "process", "native")})
        if target in (release.MAC, release.WINDOWS):
            for suite in ("reading", "drafts"):
                acceptance[suite + "_credential_source"] = ("disposable-command-helper" if target == release.MAC else
                                                             "disposable-windows-credential-manager")
                acceptance[suite + "_tls_source"] = "fixture-ca-via-SSL_CERT_FILE"
                if target == release.MAC:
                    for selection in ("cli", "mcp", "cli,mcp"):
                        acceptance[f"{suite}_components_command_{selection}"] = "install --components " + selection
                        acceptance[f"{suite}_command_{selection}"] = "cargo test --test packaged_" + suite
        initial = evidence(acceptance)
        if target == release.LINUX:
            for name in ("linux-source-evidence.txt", "desktop-source-evidence.txt"):
                data = b""
                for suite in ("credentials", "reading", "drafts"):
                    record = dict(suite=suite, execution_identity="65534:65534", harness_build="cargo test --no-run")
                    if name.startswith("linux"):
                        record.update(provisioning_identity="root", credential_sources="explicit-command,systemd-LoadCredential",
                                      desktop_session="absent", home="disposable-private-directory")
                        harness = "linux_credentials" if suite == "credentials" else "packaged_" + suite
                        record.update({f"{harness}_{source}_{selection}": "systemd-run disposable-harness"
                                       for source in ("command", "systemd") for selection in release.SELECTIONS})
                        if suite == "credentials":
                            record.update(systemd_credentials="systemd-run credential-test", systemd_native="systemd-run native-test")
                    else:
                        record.update(credential_source="native-secret-service", store="disposable-gnome-keyring",
                                      bus="private-session", topology="cooperative-embedded", isolation="not-qualified")
                        harness = "secret_service_credentials" if suite == "credentials" else "packaged_" + suite
                        record.update({f"{harness}_native_{selection}": "systemd-run secret-service-session"
                                       for selection in release.SELECTIONS})
                    data += evidence(record) + b"Linux fixture host\n"
                self.files[name] = data
                initial += data
            self.files["installed-linux-credentials-identity.log"] = b"uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)\n"
        if target == release.WINDOWS:
            records = b""
            for index, phase in enumerate(release.PHASES):
                records += f"phase={phase} identity=HOST\\mailctl_{index:010x} sid=S-1-5-21-1-2-3-{1000 + index} credential_source=windows-credential-manager\n".encode()
                for selection in ("cli", "mcp", "cli,mcp"):
                    label = selection.replace(",", "-")
                    records += f"phase={phase} components={selection} installed=C:\\private bin log=installed-{phase}-{label}-acceptance.log\n".encode()
                for stream in ("stdout", "stderr"):
                    self.files[f"{phase}-session.{stream}.log"] = b""
            self.files["windows-source-evidence.txt"] = records.replace(b"\n", b"\r\n")
            initial += records
            self.files["windows-wsl-evidence.txt"] = evidence(dict(status="passed", distro="mailctl-wsl-" + "a" * 32,
                rootfs_sha256="27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2",
                kernel="6.18.40.1-microsoft-standard-WSL2", wsl_version="3.0.1.0", linux_release="3.22.6",
                windows_identity_sid="S-1-5-21-1-2-3-1005"))
            self.files["windows-wsl.log"] = b'wsl_arguments=["--version"]\nexit=0\nWSL version: 3.0.1.0\n'
            self.files["windows-harnesses.json"] = release.canonical([
                dict(Features=selection, Harnesses=[dict(Name="windows_wsl", Executable="C:\\harness.exe")])
                for selection in ("cli", "mcp", "cli,mcp")])
        self.files["acceptance-evidence.txt"] = initial + evidence(dict(real_provider="not-qualified", isolation="not-qualified", publication="not-performed"))
        for name in LOGS_BY_TARGET[target]:
            self.files[name] = (b"Ran 12 tests in 0.123s\n\nOK\n" if name.startswith("installer-acceptance") else
                b"test fixture ... ok\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
        self.archive()
        self.files["parallel-acceptance.json"] = parallel_proof(target, self.files)
        self.prepared_zip = prepared_zip(json.loads(self.files["parallel-acceptance.json"])["build"], self.files)
        self.sums()

    def archive(self, binaries=None, special_member=None, zip_entries=None):
        output = io.BytesIO()
        selected = binaries if binaries is not None else self.binaries
        if zip_entries is not None:
            output.write(make_zip(zip_entries))
        elif self.target == release.WINDOWS:
            with zipfile.ZipFile(output, "w") as archive:
                for name, data in selected.items():
                    archive.writestr("mailctl-" + self.target + "/" + name + ".exe", data)
        else:
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                for binary, data in selected.items():
                    info = tarfile.TarInfo(f"mailctl-{self.target}/{binary}")
                    info.mode = 0o755
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                if special_member is not None:
                    archive.addfile(special_member)
        name = release.archive_name(self.target)
        self.files[name] = output.getvalue()
        digest = release.sha(output.getvalue())
        self.files[name + ".sha256"] = f"{digest}  {name}\n".encode()
        build = release.fields(self.files["build-evidence.txt"])
        build["archive_sha256"] = digest
        self.files["build-evidence.txt"] = evidence(build)
        self.files["dist-manifest.json"] = release.canonical({
            "dist_version": "0.33.0", "releases": [{"app_name": "mailctl", "app_version": VERSION,
                "artifacts": [name, name + ".sha256"]}], "artifacts": {
                name: {"name": name, "kind": "executable-zip", "path": "/historical/" + name,
                    "target_triples": [self.target], "checksum": name + ".sha256", "checksums": {"sha256": digest},
                    "assets": [{"name": binary, "kind": "executable", "path": binary} for binary in self.binaries]},
                name + ".sha256": {"name": name + ".sha256", "kind": "checksum", "path": "/historical/" + name + ".sha256"}}})
        self.sums()

    def sums(self):
        self.files["SHA256SUMS"] = "".join(f"{release.sha(data)}  " +
            ("./" if self.target == release.LINUX and name.endswith(".log") else "") + name + "\n"
            for name, data in sorted(self.files.items()) if name != "SHA256SUMS").encode()

    def zip(self):
        return make_zip((name, data, stat.S_IFREG | 0o644) for name, data in sorted(self.files.items()))


class FakeGitHub(release.GitHub):
    """Override only the external-command boundary; use the real API adapters."""

    def __init__(self, candidate=None, zip_bytes=None, candidates=None):
        self.candidates = candidates or {target: Candidate(target) for target in TARGETS}
        if candidate is not None:
            self.candidates[candidate.target] = candidate
        self.candidate = self.candidates[release.MAC]
        self.zips = {target: value.zip() for target, value in self.candidates.items()}
        self.prepared_zips = {target: value.prepared_zip for target, value in self.candidates.items()}
        if zip_bytes is not None:
            self.zips[release.MAC] = zip_bytes
        self.zip_bytes = self.zips[release.MAC]
        self.calls = []
        self.tag = None
        self.draft = None
        self.remote_assets = []
        self.fail_upload = False
        self.asset_error = None
        self.after_tag = None
        self.after_create = None
        self.created_tag_sha = COMMIT
        self.annotated_tag = None
        self.workflow = dict(id=99, path=".github/workflows/ci.yml", state="active")
        repository = dict(id=42, full_name=release.REPO)
        self.run = dict(id=RUN_ID, head_sha=COMMIT, head_branch="main", event="push",
                        status="completed", conclusion="success", workflow_id=99,
                        path=".github/workflows/ci.yml", run_attempt=ATTEMPT,
                        repository=repository, head_repository=deepcopy(repository))
        self.attempt = deepcopy(self.run)
        self.jobs = []
        self.artifacts = []
        for index, target in enumerate(TARGETS):
            job_name, record_name, upload_name = release.TARGETS[target]
            self.jobs.append(dict(id=777 + index, name=job_name, run_id=RUN_ID,
                run_attempt=ATTEMPT, head_sha=COMMIT, status="completed", conclusion="success",
                started_at="2026-10-15T10:00:00Z", completed_at="2026-10-15T10:30:00Z", steps=[
                    dict(name=record_name, status="completed", conclusion="success", number=11,
                         started_at="2026-10-15T10:28:00Z", completed_at="2026-10-15T10:28:59Z"),
                    dict(name=upload_name, status="completed", conclusion="success", number=12,
                         started_at="2026-10-15T10:29:00Z", completed_at="2026-10-15T10:29:59Z")]))
            self.artifacts.append(dict(id=ARTIFACT_IDS[index], name=release.ci_artifact_name(target, ATTEMPT), expired=False,
                size_in_bytes=len(self.zips[target]), digest="sha256:" + release.sha(self.zips[target]),
                created_at="2026-10-15T10:29:30Z", updated_at="2026-10-15T10:29:30Z", expires_at="2099-10-29T10:29:30Z",
                workflow_run=dict(id=RUN_ID, head_sha=COMMIT, head_branch="main", repository_id=42, head_repository_id=42)))
        self.artifact = self.artifacts[0]
        self.main_sha = COMMIT
        self.logs = {
            job["id"]: ("\n".join("2026-10-15T10:29:59.4862900Z " + line for line in (
                "SHA256 digest of uploaded artifact is " + artifact["digest"].removeprefix("sha256:"),
                f"Artifact {artifact['name']} successfully finalized. Artifact ID {artifact['id']}",
                f"Artifact download URL: https://github.com/{release.REPO}/actions/runs/{RUN_ID}/artifacts/{artifact['id']}")) + "\n").encode()
            for job, artifact in zip(self.jobs, self.artifacts)}
        for index, target in enumerate(TARGETS):
            artifact = deepcopy(self.artifact)
            artifact.update(id=9000 + index, name=f"mailctl-build-{target}-attempt-{ATTEMPT}",
                            digest="sha256:" + release.sha(self.prepared_zips[target]),
                            size_in_bytes=len(self.prepared_zips[target]), created_at="2026-10-15T10:09:30Z")
            self.artifacts.append(artifact)
            names = {"build-" + target: ("Seal candidate build", "Keep candidate build")}
            names.update({f"acceptance-{target}-{group}": ("Qualify installed candidate and record evidence",
                                                        "Keep acceptance evidence")
                          for group in ACCEPTANCE_GROUPS[target]})
            for offset, (name, steps) in enumerate(names.items()):
                job_id = 1000 + index * 100 + offset
                job = dict(id=job_id, name=name, run_id=RUN_ID, run_attempt=ATTEMPT, head_sha=COMMIT,
                           status="completed", conclusion="success", started_at="2026-10-15T10:00:00Z",
                           completed_at="2026-10-15T10:25:00Z", steps=[
                               dict(name=step, status="completed", conclusion="success",
                                    started_at="2026-10-15T10:09:00Z", completed_at="2026-10-15T10:09:59Z") for step in steps])
                self.jobs.append(job)
                if offset == 0:
                    self.logs[job_id] = ("\n".join("2026-10-15T10:09:59.123Z " + line for line in (
                        "SHA256 digest of uploaded artifact is " + artifact["digest"].removeprefix("sha256:"),
                        f"Artifact {artifact['name']} successfully finalized. Artifact ID {artifact['id']}",
                        f"Artifact download URL: https://github.com/{release.REPO}/actions/runs/{RUN_ID}/artifacts/{artifact['id']}")) + "\n").encode()


    @property
    def mutations(self):
        return [call for call in self.calls if call["args"][0] != "api" or call["args"][4] != "GET"]

    def call(self, args, *, data=None, output=None, absent_ok=False, cwd=None):
        self.calls.append(dict(args=list(args), data=data, output=output is not None, absent_ok=absent_ok, cwd=cwd))
        if args[0] == "release":
            return self.release_command(args, cwd=cwd)
        if args[:4] != ["api", "--hostname", "github.com", "--method"]:
            raise AssertionError("Unexpected gh command: " + repr(args))
        method, endpoint = args[4:6]
        if not endpoint.startswith(release.BASE):
            raise AssertionError("Unexpected repository endpoint: " + endpoint)
        endpoint = endpoint[len(release.BASE):]
        if method == "POST":
            if endpoint != "git/refs" or args[6:] != ["--input", "-"]:
                raise AssertionError("Unexpected mutation: " + repr(args))
            payload = json.loads(data)
            if payload != {"ref": "refs/tags/v" + VERSION, "sha": COMMIT}:
                raise AssertionError("Unexpected tag payload: " + repr(payload))
            self.tag = {"ref": payload["ref"], "object": {"type": "commit", "sha": self.created_tag_sha}}
            if self.after_tag:
                self.after_tag()
            return b"{}"
        if method != "GET":
            raise AssertionError("Unexpected API mutation: " + repr(args))
        path = urlsplit(endpoint).path
        query = parse_qs(urlsplit(endpoint).query)
        for job_id, log in self.logs.items():
            if path == f"actions/jobs/{job_id}/logs":
                if args[6:] != ["--allow-escape-sequences"]:
                    raise AssertionError("Job logs require explicit escape-sequence handling")
                return log
        for target, artifact_id in zip(TARGETS, ARTIFACT_IDS):
            if path == f"actions/artifacts/{artifact_id}/zip":
                if output is None:
                    raise AssertionError("Download requires a destination")
                output.write(self.zips[target])
                return None
        for index, target in enumerate(TARGETS):
            if path == f"actions/artifacts/{9000 + index}/zip":
                if output is None:
                    raise AssertionError("Prepared download requires a destination")
                output.write(self.prepared_zips[target])
                return None
        raw = args[6:] == ["-H", "Accept: application/vnd.github.raw+json"]
        if not raw and args[6:] != ["-H", "Accept: application/vnd.github+json"]:
            raise AssertionError("Unexpected API headers: " + repr(args))
        if path.startswith("contents/"):
            if not raw or query != {"ref": [COMMIT]}:
                raise AssertionError("Source lookup must use the fixed commit")
            name = path.removeprefix("contents/")
            if name not in self.candidate.source:
                raise ValueError("gh failed: missing fixed source file")
            return self.candidate.source[name]
        values = {
            "git/ref/heads/main": {"object": {"type": "commit", "sha": self.main_sha}},
            "actions/workflows/ci.yml": self.workflow,
            f"actions/runs/{RUN_ID}": self.run,
            f"actions/runs/{RUN_ID}/attempts/{self.run['run_attempt']}": self.attempt,
            **{f"actions/artifacts/{artifact_id}": artifact for artifact_id, artifact in zip(ARTIFACT_IDS, self.artifacts)},
            **{f"actions/artifacts/{artifact['id']}": artifact for artifact in self.artifacts[3:]},
            f"git/ref/tags/v{VERSION}": self.tag,
            "git/tags/" + "c" * 40: self.annotated_tag,
            f"releases/{RELEASE_ID}": self.draft,
        }
        collections = {f"actions/runs/{RUN_ID}/attempts/{self.run['run_attempt']}/jobs": ("jobs", self.jobs),
                       f"actions/runs/{RUN_ID}/artifacts": ("artifacts", self.artifacts),
                       "releases": (None, [] if self.draft is None else [self.draft]),
                       f"releases/{RELEASE_ID}/assets": (None, self.remote_assets)}
        if path in collections:
            if query.get("per_page") != ["100"] or "page" not in query:
                raise AssertionError("Expected explicit pagination")
            key, items = collections[path]
            start = (int(query["page"][0]) - 1) * 100
            page = items[start:start + 100]
            value = page if key is None else {"total_count": len(items), key: page}
        elif path in values:
            value = values[path]
            if value is None:
                if absent_ok:
                    return None
                raise ValueError("gh failed: resource absent (HTTP 404)")
        else:
            raise AssertionError("Unexpected GET endpoint: " + endpoint)
        return release.canonical(value)

    def release_command(self, args, *, cwd=None):
        if args[:2] == ["release", "upload"]:
            if args[:5] != ["release", "upload", "v" + VERSION, "--repo", release.REPO]:
                raise AssertionError("Unexpected draft upload argv: " + repr(args))
            if not self.draft or not self.draft["draft"] or self.remote_assets:
                raise AssertionError("Upload requires an empty native draft")
            assets = [Path(cwd) / name for name in args[5:]]
            if {path.name for path in assets} != EXPECTED_CANDIDATE:
                raise AssertionError("Upload requires all qualified assets")
            self.remote_assets = [dict(id=index, name=path.name, size=path.stat().st_size,
                                      digest="sha256:" + release.sha(path.read_bytes()), state="uploaded")
                                  for index, path in enumerate(assets, 1)]
            if self.fail_upload:
                self.remote_assets = self.remote_assets[:1]
                raise ValueError("gh failed: simulated asset upload failure")
            if self.asset_error:
                self.asset_error(self.remote_assets)
            if self.after_create:
                self.after_create()
            return b""
        if args[:2] == ["release", "create"]:
            prefix = ["release", "create", "v" + VERSION, "--draft", "--verify-tag", "--repo",
                      release.REPO, "--title", "v" + VERSION, "--notes-file"]
            if args[:10] != prefix:
                raise AssertionError("Unexpected draft creation argv: " + repr(args))
            notes = Path(args[10])
            if notes.name != "release-notes.md" or not notes.is_file():
                raise AssertionError("Missing explicit release notes")
            # gh treats '#' inside an asset argument as its label delimiter.
            assets = [Path(value.split("#", 1)[0]) for value in args[11:]]
            if cwd is not None:
                assets = [Path(cwd) / path for path in assets]
            if {path.name for path in assets} != EXPECTED_CANDIDATE or len(assets) != 21:
                raise AssertionError("Draft creation must name all 21 assets")
            self.draft = dict(id=RELEASE_ID, tag_name="v" + VERSION, draft=True,
                              body=notes.read_text())
            self.remote_assets = [dict(id=index, name=path.name, size=path.stat().st_size,
                                       digest="sha256:" + release.sha(path.read_bytes()), state="uploaded")
                                  for index, path in enumerate(assets, 1)]
            if self.fail_upload:
                self.remote_assets = self.remote_assets[:1]
                raise ValueError("gh failed: simulated asset upload failure")
            if self.asset_error:
                self.asset_error(self.remote_assets)
            if self.after_create:
                self.after_create()
            return b""
        if args in (["release", "edit", "v" + VERSION, "--draft=false", "--repo", release.REPO],
                    ["release", "edit", "v" + VERSION, "--draft=false", "--repo", release.REPO, "--latest"]):
            if not self.draft or not self.draft["draft"]:
                raise AssertionError("Only the created draft can be published")
            self.draft["draft"] = False
            return b""
        raise AssertionError("Unexpected release command: " + repr(args))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mailctl-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.case_number = 0
        blocker = patch.object(release.subprocess, "run", side_effect=AssertionError("External commands are forbidden in offline tests"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def case(self, gh=None):
        gh = gh or FakeGitHub()
        self.case_number += 1
        directory = self.root / str(self.case_number)
        directory.mkdir()
        notes = dict(source_commit=COMMIT, operator="Release operator",
                     accepted_source_evidence=["https://github.com/ueberBrot/mailctl/issues/100#issuecomment-1"],
                     association_notes="The operator associates the accepted source evidence with these candidate bytes.",
                     artifact_associations={target: dict(commit=COMMIT, run_id=RUN_ID, run_attempt=ATTEMPT,
                         artifact_id=artifact["id"], artifact_sha256=artifact["digest"])
                         for target, artifact in zip(TARGETS, gh.artifacts)})
        note_path = directory / "notes.json"
        note_path.write_bytes(release.canonical(notes))
        return gh, directory / "plan", note_path

    def prepare(self, gh=None):
        gh, directory, notes = self.case(gh)
        digest = release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, notes, directory)
        return gh, directory, digest

    def rejected(self, gh, message=None):
        gh, directory, notes = self.case(gh)
        with self.assertRaises(ValueError) if message is None else self.assertRaisesRegex(ValueError, message):
            release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, notes, directory)
        self.assertEqual(gh.mutations, [])

    def test_prepare_and_verify_preserve_exact_bytes_without_mutations(self):
        gh, directory, digest = self.prepare()
        plan, actual = release.verify(gh, directory)
        self.assertEqual(actual, digest)
        self.assertEqual((directory / "candidates" / release.MAC / "artifact.zip").read_bytes(), gh.zip_bytes)
        self.assertEqual(set(plan["assets"]), EXPECTED_CANDIDATE)
        self.assertEqual(len(plan["assets"]), 21)
        self.assertEqual(plan["run_attempt"], ATTEMPT)
        for name, data in gh.candidate.files.items():
            self.assertEqual((directory / "candidates" / release.MAC / "files" / name).read_bytes(), data)
        for name, data in gh.candidate.source.items():
            self.assertEqual((directory / "source" / name).read_bytes(), data)
        self.assertEqual(gh.mutations, [])
        self.assertTrue(all(call["args"][:5] == ["api", "--hostname", "github.com", "--method", "GET"] for call in gh.calls))

    def test_ci_preparation_uses_native_release_selection_and_only_current_artifacts(self):
        gh, directory, _ = self.case()
        selected = release.canonical([dict(package_name="mailctl", version=VERSION, tag="v" + VERSION)])
        digest = release.prepare_ci(gh, COMMIT, RUN_ID, selected, directory)
        plan, actual = release.verify(gh, directory)
        self.assertEqual(actual, digest)
        self.assertEqual(plan["commit"], COMMIT)
        self.assertEqual((directory / "release-notes.md").read_text(), "Initial release.")
        self.assertEqual(gh.mutations, [])

    def test_ci_preparation_rejects_unexpected_release_plz_output(self):
        for selected in ([], [dict(package_name="other", version=VERSION, tag="v" + VERSION)],
                         [dict(package_name="mailctl", version="0.2.0", tag="v0.2.0")],
                         [dict(package_name="mailctl", version=VERSION, tag="other")], [{}, {}]):
            with self.subTest(selected=selected):
                gh, directory, _ = self.case()
                with self.assertRaises(ValueError):
                    release.prepare_ci(gh, COMMIT, RUN_ID, release.canonical(selected), directory)
                self.assertEqual(gh.mutations, [])

    def test_skipped_native_release_distinguishes_completed_absent_and_unfinished_state(self):
        gh = FakeGitHub()
        release.check_state(gh, COMMIT)
        gh.tag = {"object": {"type": "tag", "sha": "c" * 40}}
        gh.draft = dict(tag_name="v" + VERSION, draft=False)
        release.check_state(gh, COMMIT)
        self.assertEqual(gh.mutations, [])
        for tag, draft in ((True, None), (True, True), (False, True), (False, False)):
            with self.subTest(tag=tag, draft=draft):
                gh = FakeGitHub()
                if tag:
                    gh.tag = {"object": {"type": "commit", "sha": "b" * 40}}
                if draft is not None:
                    gh.draft = dict(tag_name="v" + VERSION, draft=draft)
                with self.assertRaisesRegex(ValueError, "manual recovery"):
                    release.check_state(gh, COMMIT)
                self.assertEqual(gh.mutations, [])

    def test_artifact_creation_can_follow_step_completion_when_the_receipt_matches(self):
        gh = FakeGitHub()
        gh.artifact.update(created_at="2026-10-15T10:30:00Z", updated_at="2026-10-15T10:30:00Z")
        self.prepare(gh)
        gh = FakeGitHub()
        gh.artifact["created_at"] = "2026-10-15T10:30:01Z"
        self.rejected(gh, "another attempt")

    def test_upload_receipt_must_match_the_id_digest_run_and_successful_step(self):
        original = FakeGitHub().logs[777]
        changes = [b"", original + original,
                   original.replace(str(ARTIFACT_ID).encode(), b"99999"),
                   original.replace(str(RUN_ID).encode(), b"9999"),
                   original.replace(b"SHA256 digest", b"Wrong digest"),
                   original.replace(b"10:29:59.4862900Z", b"10:30:00.0000000Z"),
                   b"\n".join(reversed(original.splitlines()))]
        for log in changes:
            with self.subTest(log=log[:80]):
                gh = FakeGitHub()
                gh.logs[777] = log
                self.rejected(gh)

    def test_all_three_targets_are_preserved_and_only_unambiguous_assets_are_uploaded(self):
        gh, directory, digest = self.prepare()
        plan, actual = release.verify(gh, directory)
        self.assertEqual(actual, digest)
        self.assertEqual(plan["format"], 2)
        self.assertEqual(set(plan["artifacts"]), set(TARGETS))
        self.assertEqual(len(plan["assets"]), 21)
        for target, expected_count in ((release.MAC, 21), (release.LINUX, 47), (release.WINDOWS, 47)):
            self.assertEqual(len(gh.candidates[target].files), expected_count)
        for target in TARGETS:
            candidate = gh.candidates[target]
            folder = directory / "candidates" / target
            self.assertEqual((folder / "artifact.zip").read_bytes(), gh.zips[target])
            self.assertEqual({path.name for path in (folder / "files").iterdir()}, set(candidate.files))
            for name, data in candidate.files.items():
                self.assertEqual((folder / "files" / name).read_bytes(), data)
            zipped = "mailctl-candidate-" + target + ".zip"
            self.assertEqual((directory / "assets" / zipped).read_bytes(), gh.zips[target])
            self.assertEqual(plan["artifacts"][target]["id"], ARTIFACT_IDS[TARGETS.index(target)])
        sums = release.checksum_lines((directory / "assets" / "SHA256SUMS").read_bytes())
        self.assertEqual(set(sums), EXPECTED_CANDIDATE - {"SHA256SUMS"})
        for name, checksum in sums.items():
            self.assertEqual(checksum, release.sha((directory / "assets" / name).read_bytes()))
        self.assertEqual(gh.mutations, [])
        release.publish(gh, directory, digest)
        self.assertEqual({asset["name"] for asset in gh.remote_assets}, EXPECTED_CANDIDATE)
        for name in EXPECTED_CANDIDATE:
            expected = plan["assets"][name]
            remote = next(asset for asset in gh.remote_assets if asset["name"] == name)
            self.assertEqual(remote["size"], expected["size"])
            self.assertEqual(remote["digest"], "sha256:" + expected["sha256"])
        self.assertFalse(gh.draft["draft"])

    def test_exactly_one_supported_artifact_per_target_is_required(self):
        for artifact_ids in ([], ARTIFACT_IDS[:1], ARTIFACT_IDS[:2], ARTIFACT_IDS + [9000],
                             [ARTIFACT_ID] * 3, [True, *ARTIFACT_IDS[1:]], [0, *ARTIFACT_IDS[1:]]):
            gh, directory, notes = self.case()
            with self.subTest(ids=artifact_ids), self.assertRaises(ValueError):
                release.prepare(gh, COMMIT, RUN_ID, artifact_ids, notes, directory)
            self.assertEqual(gh.mutations, [])
        for target_index in (1, 2):
            gh = FakeGitHub()
            gh.artifacts[target_index]["name"] = gh.artifact["name"]
            self.rejected(gh)
            gh = FakeGitHub()
            gh.artifacts[target_index]["name"] = "mailctl-candidate-unsupported-target"
            self.rejected(gh)

    def test_each_platform_job_steps_artifact_run_and_attempt_are_bound(self):
        for index in range(3):
            for field, value in (("run_attempt", ATTEMPT - 1), ("head_sha", "b" * 40),
                                 ("status", "in_progress"), ("conclusion", "failure")):
                with self.subTest(target=TARGETS[index], job_field=field):
                    gh = FakeGitHub()
                    gh.jobs[index][field] = value
                    self.rejected(gh)
            for step in (0, 1):
                gh = FakeGitHub()
                gh.jobs[index]["steps"][step]["conclusion"] = "skipped"
                self.rejected(gh)
            for field, value in (("id", RUN_ID + 1), ("head_sha", "b" * 40), ("head_branch", "other")):
                gh = FakeGitHub()
                gh.artifacts[index]["workflow_run"][field] = value
                self.rejected(gh)
            gh = FakeGitHub()
            gh.artifacts[index]["created_at"] = "2026-10-15T10:28:30Z"
            self.rejected(gh)
            gh = FakeGitHub()
            gh.artifacts[index]["size_in_bytes"] = release.MAX_FILE + 1
            self.rejected(gh)

    def test_each_platform_rejects_corrupt_bytes_and_cross_target_candidates(self):
        for target in TARGETS:
            with self.subTest(target=target):
                candidate = Candidate(target)
                raw = release.binary_name("mailctl", VERSION, target)
                candidate.files[raw] += b"corruption"
                candidate.sums()
                self.rejected(FakeGitHub(candidate), "component bytes")
                candidate = Candidate(target)
                candidate.binaries["mailctl"] = b"wrong native executable format"
                candidate.files[raw] = candidate.binaries["mailctl"]
                receipt = release.fields(candidate.files[f"manifest-{target}.txt"])
                receipt.update(cli_size=str(len(candidate.binaries["mailctl"])),
                               cli_sha256=release.sha(candidate.binaries["mailctl"]))
                candidate.files[f"manifest-{target}.txt"] = evidence(receipt)
                candidate.archive()
                self.rejected(FakeGitHub(candidate), "executable")
        for target in (release.LINUX, release.WINDOWS):
            gh = FakeGitHub()
            gh.zips[target] = gh.zips[release.MAC]
            index = TARGETS.index(target)
            artifact = gh.artifacts[index]
            old_digest = artifact["digest"].removeprefix("sha256:")
            artifact["digest"] = "sha256:" + release.sha(gh.zips[target])
            artifact["size_in_bytes"] = len(gh.zips[target])
            job_id = gh.jobs[index]["id"]
            gh.logs[job_id] = gh.logs[job_id].replace(old_digest.encode(), artifact["digest"].removeprefix("sha256:").encode())
            self.rejected(gh, "authenticated prepared artifact")

    def test_native_qualification_requires_each_component_log_and_source_record(self):
        for target in (release.LINUX, release.WINDOWS):
            for name in LOGS_BY_TARGET[target]:
                candidate = Candidate(target)
                candidate.files[name] = b"test result: ok. 0 passed; 0 failed; 0 ignored;\n"
                candidate.sums()
                with self.subTest(target=target, missing_log=name):
                    self.rejected(FakeGitHub(candidate))
        candidate = Candidate(release.LINUX)
        for name in ("linux-source-evidence.txt", "desktop-source-evidence.txt"):
            broken = deepcopy(candidate)
            broken.files[name] = broken.files[name].replace(b"suite=reading", b"suite=missing")
            broken.sums()
            self.rejected(FakeGitHub(broken))
        candidate = Candidate(release.WINDOWS)
        for before, after in ((b"sid=S-1-5-21-1-2-3-1001", b"sid=S-1-5-21-1-2-3-1000"),
                              (b"phase=reading components=mcp ", b"phase=reading components=cli "),
                              (b"credential_source=windows-credential-manager", b"credential_source=command")):
            broken = deepcopy(candidate)
            broken.files["windows-source-evidence.txt"] = broken.files["windows-source-evidence.txt"].replace(before, after)
            broken.sums()
            self.rejected(FakeGitHub(broken))
        for field, value in (("status", "prepared"), ("windows_identity_sid", "S-1-5-21-1-2-3-9999"),
                             ("kernel", "6.1-WSL1"), ("linux_release", "3.21.0"), ("wsl_version", "")):
            broken = deepcopy(candidate)
            values = release.fields(broken.files["windows-wsl-evidence.txt"])
            values[field] = value
            broken.files["windows-wsl-evidence.txt"] = evidence(values)
            broken.sums()
            self.rejected(FakeGitHub(broken))

    def test_windows_source_embedding_normalizes_line_endings_but_preserves_records(self):
        candidate = Candidate(release.WINDOWS)
        self.assertIn(b"\r\n", candidate.files["windows-source-evidence.txt"])
        self.assertNotIn(b"\r\n", candidate.files["acceptance-evidence.txt"])
        self.prepare(FakeGitHub(candidate))
        candidate.files["windows-source-evidence.txt"] = candidate.files["windows-source-evidence.txt"].replace(
            b"private bin", b"different private bin")
        candidate.sums()
        self.rejected(FakeGitHub(candidate), "Windows source evidence differs")

    def test_windows_installer_allows_only_complete_git_checkout_line_endings(self):
        candidate = Candidate(release.WINDOWS)
        source = candidate.source["install.ps1"]
        qualified = candidate.files["install.ps1"]
        self.assertNotEqual(qualified, source)
        self.assertEqual(qualified, source.replace(b"\n", b"\r\n"))
        _, directory, _ = self.prepare(FakeGitHub(candidate))
        plan = json.loads((directory / "plan.json").read_bytes())
        self.assertEqual((directory / "source" / "install.ps1").read_bytes(), source)
        self.assertEqual((directory / "assets" / "install.ps1").read_bytes(), qualified)
        self.assertEqual(plan["source"]["install.ps1"], release.sha(source))
        self.assertEqual(plan["assets"]["install.ps1"]["sha256"], release.sha(qualified))
        for changed in (qualified.replace(b"\r\n", b"\n", 1), qualified.replace(b"mailctl", b"mailctx", 1),
                        qualified + b" "):
            broken = deepcopy(candidate)
            broken.files["install.ps1"] = changed
            broken.sums()
            self.rejected(FakeGitHub(broken), "Installer differs")

    def test_only_macos_ad_hoc_signing_is_qualified_and_both_installers_are_source_bound(self):
        for target in TARGETS:
            candidate = Candidate(target)
            installer = "install.ps1" if target == release.WINDOWS else "install.sh"
            candidate.files[installer] += b"modified installer"
            candidate.sums()
            self.rejected(FakeGitHub(candidate), "Installer differs")
        for target in (release.LINUX, release.WINDOWS):
            candidate = Candidate(target)
            receipt = release.fields(candidate.files[f"manifest-{target}.txt"])
            receipt["cli_signing"] = "ad-hoc"
            candidate.files[f"manifest-{target}.txt"] = evidence(receipt)
            candidate.sums()
            self.rejected(FakeGitHub(candidate), "signing")
        # Shared asset names coalesce only when they name the identical installer.
        bundles = {target: Candidate(target).files for target in TARGETS}
        bundles[release.LINUX]["install.sh"] += b"different Unix installer"
        with self.assertRaisesRegex(ValueError, "Conflicting release asset"):
            release.release_assets(bundles, {target: b"zip" for target in TARGETS}, VERSION)

    def test_windows_archive_rejects_unsafe_duplicate_or_nonregular_members(self):
        valid = [("root/" + name + ".exe", data, stat.S_IFREG | 0o755)
                 for name, data in Candidate(release.WINDOWS).binaries.items()]
        for extra in (("../outside", b"bytes", stat.S_IFREG), ("root/C:drive", b"bytes", stat.S_IFREG),
                      ("root/link", b"mailctl.exe", stat.S_IFLNK), valid[0]):
            candidate = Candidate(release.WINDOWS)
            candidate.archive(zip_entries=valid + [extra])
            self.rejected(FakeGitHub(candidate))
        candidate = Candidate(release.WINDOWS)
        candidate.archive(zip_entries=[("other/mailctl.exe", candidate.binaries["mailctl"], stat.S_IFREG)] + valid)
        self.rejected(FakeGitHub(candidate), "Ambiguous")

    def test_aggregate_limits_and_normalized_checksum_duplicates(self):
        gh, directory, notes = self.case()
        with patch.object(release, "MAX_TOTAL", sum(len(value) for value in gh.zips.values()) - 1):
            with self.assertRaisesRegex(ValueError, "size limit"):
                release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, notes, directory)
        candidate = Candidate(release.LINUX)
        name = "installed-state-acceptance.log"
        candidate.files["SHA256SUMS"] += f"{release.sha(candidate.files[name])}  {name}\n".encode()
        self.rejected(FakeGitHub(candidate), "Duplicate checksum")

    def test_missing_or_mismatched_qualification_association_for_each_target(self):
        for target in TARGETS:
            for change in ("missing", "run", "attempt", "artifact", "digest"):
                gh, directory, path = self.case()
                notes = json.loads(path.read_bytes())
                if change == "missing":
                    del notes["artifact_associations"][target]
                else:
                    field, value = {"run": ("run_id", RUN_ID + 1), "attempt": ("run_attempt", ATTEMPT - 1),
                                    "artifact": ("artifact_id", 9999), "digest": ("artifact_sha256", "sha256:" + "0" * 64)}[change]
                    notes["artifact_associations"][target][field] = value
                path.write_bytes(release.canonical(notes))
                with self.subTest(target=target, change=change), self.assertRaises(ValueError):
                    release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, path, directory)
                self.assertEqual(gh.mutations, [])

    def test_publication_rechecks_approved_payload_before_each_mutation(self):
        for hook in ("after_tag", "after_create"):
            for name in ("plan.json", "release-notes.md", "assets/install.ps1", "assets/install.sh"):
                gh, directory, digest = self.prepare()
                path = directory / name
                def tamper(path=path):
                    path.write_bytes(path.read_bytes() + b"unapproved bytes")
                setattr(gh, hook, tamper)
                with self.subTest(hook=hook, file=name), self.assertRaisesRegex(ValueError, "Approved"):
                    release.publish(gh, directory, digest)
                self.assertEqual(len(gh.mutations), 1 if hook == "after_tag" else 2)
                self.assertTrue((directory / "publication-started.json").exists())
                if gh.draft is not None:
                    self.assertTrue(gh.draft["draft"])


    def test_linked_release_plz_changelog_heading(self):
        candidate = Candidate()
        candidate.source["CHANGELOG.md"] = b"## [0.1.0](https://github.com/ueberBrot/mailctl/compare/v0.0.0...v0.1.0) - 2026-10-15\n\nInitial release.\n"
        self.prepare(FakeGitHub(candidate))

    def test_invalid_or_noncurrent_commit_and_ids(self):
        for commit in ("a" * 39, "A" * 40, "b" * 40):
            with self.subTest(commit=commit):
                gh, directory, notes = self.case()
                with self.assertRaises(ValueError):
                    release.prepare(gh, commit, RUN_ID, ARTIFACT_IDS, notes, directory)
                self.assertEqual(gh.mutations, [])
        for run_id, artifact_ids in ((0, ARTIFACT_IDS), (RUN_ID, [-1, *ARTIFACT_IDS[1:]]), (True, ARTIFACT_IDS)):
            with self.subTest(run_id=run_id, artifact_ids=artifact_ids):
                gh, directory, notes = self.case()
                with self.assertRaises(ValueError):
                    release.prepare(gh, COMMIT, run_id, artifact_ids, notes, directory)
                self.assertEqual(gh.mutations, [])

    def test_wrong_ci_run_and_attempt(self):
        for field, value in (("head_sha", "b" * 40), ("head_branch", "feature"), ("event", "workflow_dispatch"),
                             ("status", "in_progress"), ("conclusion", "failure"), ("workflow_id", 100),
                             ("path", ".github/workflows/other.yml")):
            with self.subTest(field=field):
                gh = FakeGitHub()
                gh.run[field] = value
                self.rejected(gh)
        gh = FakeGitHub()
        gh.attempt["run_attempt"] = ATTEMPT - 1
        self.rejected(gh)
        gh = FakeGitHub()
        gh.run["head_repository"]["full_name"] = "another/repository"
        self.rejected(gh)

    def test_candidate_job_and_acceptance_steps_must_pass_in_this_attempt(self):
        for field, value in (("run_attempt", ATTEMPT - 1), ("head_sha", "b" * 40), ("run_id", RUN_ID + 1),
                             ("status", "queued"), ("conclusion", "failure")):
            with self.subTest(field=field):
                gh = FakeGitHub()
                gh.jobs[0][field] = value
                self.rejected(gh)
        for step in (0, 1):
            for conclusion in ("failure", "skipped"):
                gh = FakeGitHub()
                gh.jobs[0]["steps"][step]["conclusion"] = conclusion
                self.rejected(gh)
        gh = FakeGitHub()
        gh.jobs[0]["steps"].pop()
        self.rejected(gh)
        for count in (0, 2):
            gh = FakeGitHub()
            gh.jobs *= count
            self.rejected(gh)

    def test_parallel_workers_and_prepared_artifacts_must_match_this_attempt(self):
        names = ["build-" + target for target in TARGETS] + [
            f"acceptance-{target}-{group}" for target in TARGETS for group in ACCEPTANCE_GROUPS[target]]
        for name in names:
            for field, value in (("conclusion", "failure"), ("run_attempt", ATTEMPT - 1),
                                 ("head_sha", "b" * 40), ("run_id", RUN_ID + 1), ("status", "in_progress")):
                with self.subTest(job=name, field=field):
                    gh = FakeGitHub()
                    next(job for job in gh.jobs if job["name"] == name)[field] = value
                    self.rejected(gh, re.escape(name))
            for count in (0, 2):
                with self.subTest(job=name, count=count):
                    gh = FakeGitHub()
                    worker = next(job for job in gh.jobs if job["name"] == name)
                    gh.jobs = [job for job in gh.jobs if job["name"] != name] + [deepcopy(worker) for _ in range(count)]
                    self.rejected(gh, re.escape(name))
        for field, value in (("expired", True), ("digest", "missing"),
                             ("created_at", "2026-10-15T09:59:59Z")):
            gh = FakeGitHub()
            gh.artifacts[3][field] = value
            self.rejected(gh)

    def test_each_acceptance_group_requires_unique_successful_qualification_and_upload_steps(self):
        for target in TARGETS:
            for group in ACCEPTANCE_GROUPS[target]:
                name = f"acceptance-{target}-{group}"
                for step_name in ("Qualify installed candidate and record evidence", "Keep acceptance evidence"):
                    for field, value in (("conclusion", "failure"), ("conclusion", "skipped"),
                                         ("status", "in_progress")):
                        with self.subTest(job=name, step=step_name, field=field, value=value):
                            gh = FakeGitHub()
                            worker = next(job for job in gh.jobs if job["name"] == name)
                            step = next(step for step in worker["steps"] if step["name"] == step_name)
                            step[field] = value
                            self.rejected(gh, re.escape(step_name))
                    for count in (0, 2):
                        with self.subTest(job=name, step=step_name, count=count):
                            gh = FakeGitHub()
                            worker = next(job for job in gh.jobs if job["name"] == name)
                            step = next(step for step in worker["steps"] if step["name"] == step_name)
                            worker["steps"] = [step for step in worker["steps"] if step["name"] != step_name] + [
                                deepcopy(step) for _ in range(count)]
                            self.rejected(gh, re.escape(step_name))

    def test_previous_attempt_artifacts_do_not_shadow_current_candidates(self):
        gh, directory, _ = self.case()
        for artifact in list(gh.artifacts):
            previous = deepcopy(artifact)
            previous.update(id=previous["id"] + 10000,
                            name=previous["name"].removesuffix(str(ATTEMPT)) + str(ATTEMPT - 1))
            gh.artifacts.append(previous)
        releases = release.canonical([dict(package_name="mailctl", version=VERSION, tag="v" + VERSION)])
        release.prepare_ci(gh, COMMIT, RUN_ID, releases, directory)
        plan = json.loads((directory / "plan.json").read_bytes())
        self.assertEqual({entry["id"] for entry in plan["artifacts"].values()}, set(ARTIFACT_IDS))

    def test_parallel_receipts_cannot_relabel_a_different_build_or_attempt(self):
        for target in TARGETS:
            for field, value in (("run_id", RUN_ID + 1), ("run_attempt", ATTEMPT - 1),
                                 ("commit", "b" * 40)):
                with self.subTest(target=target, field=field):
                    candidate = Candidate(target)
                    proof = json.loads(candidate.files["parallel-acceptance.json"])
                    proof["build"]["context"][field] = value
                    candidate.files["parallel-acceptance.json"] = release.canonical(proof)
                    candidate.sums()
                    self.rejected(FakeGitHub(candidate))

    def test_successful_acceptance_groups_still_require_every_phase_receipt(self):
        for target in TARGETS:
            for phase in release.candidate_evidence.phases(target):
                for change in ("missing", "stale", "log-digest"):
                    with self.subTest(target=target, phase=phase, change=change):
                        candidate = Candidate(target)
                        proof = json.loads(candidate.files["parallel-acceptance.json"])
                        shard = next(shard for shard in proof["shards"] if shard["phase"] == phase)
                        if change == "missing":
                            proof["shards"].remove(shard)
                            message = "Missing or duplicate acceptance shard"
                        elif change == "stale":
                            shard["context"]["run_attempt"] = ATTEMPT - 1
                            message = "Acceptance shard belongs to another build or attempt"
                        else:
                            log = next(name for name in shard["files"] if name in LOGS_BY_TARGET[target])
                            shard["files"][log]["sha256"] = "0" * 64
                            message = "Acceptance log changed"
                        candidate.files["parallel-acceptance.json"] = release.canonical(proof)
                        candidate.sums()
                        self.rejected(FakeGitHub(candidate), message)

    def test_collector_cannot_replace_the_authenticated_prepared_manifest(self):
        candidate = Candidate()
        original = json.loads(candidate.files["parallel-acceptance.json"])["artifact"]
        replacement = candidate.binaries["mailctl"] + b"replacement bytes"
        candidate.binaries["mailctl"] = replacement
        candidate.files[release.binary_name("mailctl", VERSION, candidate.target)] = replacement
        manifest_name = "manifest-" + candidate.target + ".txt"
        manifest = release.fields(candidate.files[manifest_name])
        manifest.update(cli_sha256=release.sha(replacement), cli_size=str(len(replacement)))
        candidate.files[manifest_name] = evidence(manifest)
        candidate.archive()
        proof = json.loads(parallel_proof(candidate.target, candidate.files))
        proof["artifact"] = original
        for shard in proof["shards"]:
            shard["artifact"] = original
        candidate.files["parallel-acceptance.json"] = release.canonical(proof)
        candidate.sums()
        self.rejected(FakeGitHub(candidate), "authenticated prepared artifact")

    def test_artifact_identity_digest_retention_and_attempt_window(self):
        changes = (("id", ARTIFACT_ID + 1), ("name", "other-candidate"), ("expired", True),
                   ("digest", "sha256:" + "0" * 64), ("digest", "missing"),
                   ("expires_at", "2020-01-01T00:00:00Z"),
                   ("created_at", "2026-10-15T09:59:59Z"),
                   ("created_at", "2026-10-15T10:28:30Z"))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                gh = FakeGitHub()
                gh.artifact[field] = value
                self.rejected(gh)
        for field, value in (("id", RUN_ID + 1), ("head_sha", "b" * 40), ("head_branch", "other"),
                             ("repository_id", 999), ("head_repository_id", 999)):
            gh = FakeGitHub()
            gh.artifact["workflow_run"][field] = value
            self.rejected(gh)
        gh = FakeGitHub()
        gh.artifacts.append(deepcopy(gh.artifact))
        self.rejected(gh)

    def test_zip_rejects_unsafe_duplicate_and_nonregular_members(self):
        for name, mode in (("../outside", stat.S_IFREG), ("nested/file", stat.S_IFREG),
                           ("windows\\file", stat.S_IFREG), ("C:drive", stat.S_IFREG),
                           ("link", stat.S_IFLNK), ("pipe", stat.S_IFIFO)):
            with self.subTest(name=name):
                self.rejected(FakeGitHub(zip_bytes=make_zip([(name, b"bytes", mode | 0o644)])))
        self.rejected(FakeGitHub(zip_bytes=make_zip([("same", b"one", stat.S_IFREG),
                                                    ("same", b"two", stat.S_IFREG)])), "Duplicate ZIP")

    def test_checksums_and_exact_asset_set(self):
        for change in ("corrupt", "missing", "extra", "missing-sum", "duplicate-sum"):
            with self.subTest(change=change):
                candidate = Candidate()
                if change == "corrupt":
                    candidate.files["installed-state-acceptance.log"] += b"corruption"
                elif change == "missing":
                    del candidate.files["installed-state-acceptance.log"]
                    candidate.sums()
                elif change == "extra":
                    candidate.files["unexpected.txt"] = b"unexpected"
                    candidate.sums()
                elif change == "missing-sum":
                    candidate.files["SHA256SUMS"] = candidate.files["SHA256SUMS"].split(b"\n", 1)[1]
                else:
                    candidate.files["SHA256SUMS"] += candidate.files["SHA256SUMS"].splitlines(keepends=True)[0]
                self.rejected(FakeGitHub(candidate))

    def test_versioned_installer_and_manifest_aliases_are_rejected(self):
        for stable, versioned in (("install.sh", f"install-v{VERSION}.sh"),
                                  (f"manifest-{release.MAC}.txt",
                                   f"manifest-v{VERSION}-{release.MAC}.txt")):
            for replace in (False, True):
                with self.subTest(asset=versioned, replace=replace):
                    candidate = Candidate()
                    candidate.files[versioned] = candidate.files[stable]
                    if replace:
                        del candidate.files[stable]
                    candidate.sums()
                    self.rejected(FakeGitHub(candidate), "exact expected files")

    def test_dirty_mismatched_or_missing_build_evidence(self):
        for field, value in (("source", "dirty"), ("commit", "b" * 40), ("version", "0.2.0"),
                             ("target", "x86_64-apple-darwin"), ("compatibility", "2"),
                             ("status", "failed"), ("dist_version", "0.32.0"), ("rustc", "")):
            with self.subTest(field=field):
                candidate = Candidate()
                values = release.fields(candidate.files["build-evidence.txt"])
                values[field] = value
                candidate.files["build-evidence.txt"] = evidence(values)
                candidate.sums()
                self.rejected(FakeGitHub(candidate))
        candidate = Candidate()
        candidate.files["build-evidence.txt"] = candidate.files["build-evidence.txt"].replace(b"source=clean\n", b"")
        candidate.sums()
        self.rejected(FakeGitHub(candidate))

    def test_component_metadata_and_acceptance_evidence(self):
        candidate = Candidate()
        candidate.files["acceptance-evidence.txt"] += b"unexpected=one\nunexpected=two\n"
        candidate.sums()
        self.rejected(FakeGitHub(candidate), "Duplicate evidence field")
        manifest_name = f"manifest-{release.MAC}.txt"
        for field, value in (("commit", "b" * 40), ("version", "0.2.0"), ("compatibility", "2"),
                             ("cli_size", "999"), ("cli_sha256", "0" * 64),
                             ("cli_file", "../mailctl"), ("mcp_signing", "signed")):
            with self.subTest(field=field):
                candidate = Candidate()
                values = release.fields(candidate.files[manifest_name])
                values[field] = value
                candidate.files[manifest_name] = evidence(values)
                candidate.sums()
                self.rejected(FakeGitHub(candidate))
        for before, after in ((b"status=passed", b"status=failed"),
                              (b"real_provider=not-qualified", b"real_provider=qualified"),
                              (b"reading_command_cli=", b"missing_reading_command_cli=")):
            candidate = Candidate()
            candidate.files["acceptance-evidence.txt"] = candidate.files["acceptance-evidence.txt"].replace(before, after)
            candidate.sums()
            self.rejected(FakeGitHub(candidate))
        for name, data in (("installer-acceptance.log", b"FAILED (failures=1)\n"),
                           ("installed-reading-cli-acceptance.log", b"test result: ok. 0 passed; 0 failed; 0 ignored;\n"),
                           ("installed-drafts-mcp-acceptance.log", b"test result: FAILED. 1 passed; 1 failed; 0 ignored;\n"),
                           ("installed-native-acceptance.log", b"")):
            candidate = Candidate()
            candidate.files[name] = data
            candidate.sums()
            self.rejected(FakeGitHub(candidate))

    def test_archive_bytes_regular_members_and_dist_metadata(self):
        candidate = Candidate()
        candidate.archive(dict(candidate.binaries, mailctl=b"different archive bytes"))
        self.rejected(FakeGitHub(candidate), "Raw binary differs")
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            candidate = Candidate()
            member = tarfile.TarInfo("unexpected")
            member.type = kind
            member.linkname = "mailctl"
            candidate.archive(special_member=member)
            self.rejected(FakeGitHub(candidate))
        candidate = Candidate()
        manifest = json.loads(candidate.files["dist-manifest.json"])
        manifest["artifacts"][release.archive_name(release.MAC)]["target_triples"] = ["x86_64-apple-darwin"]
        candidate.files["dist-manifest.json"] = release.canonical(manifest)
        candidate.sums()
        self.rejected(FakeGitHub(candidate))

    def test_source_version_installer_and_changelog(self):
        for version in ("01.0.0", "0.1.0-rc.1", "v0.1.0"):
            candidate = Candidate()
            candidate.source["Cargo.toml"] = f'[workspace.package]\nversion = "{version}"\n'.encode()
            self.rejected(FakeGitHub(candidate))
        candidate = Candidate()
        candidate.files["install.sh"] += b"# changed\n"
        candidate.sums()
        self.rejected(FakeGitHub(candidate))
        for changelog in (b"# No version entry\n", b"## [0.1.0]\n", b"## [0.1.0]\nOne\n## [0.1.0]\nTwo\n"):
            candidate = Candidate()
            candidate.source["CHANGELOG.md"] = changelog
            self.rejected(FakeGitHub(candidate))
        candidate = Candidate()
        del candidate.source["CHANGELOG.md"]
        self.rejected(FakeGitHub(candidate))

    def test_qualification_notes_require_source_links_and_artifact_association(self):
        for field, value in (("source_commit", "b" * 40), ("operator", ""),
                             ("association_notes", " "), ("accepted_source_evidence", []),
                             ("accepted_source_evidence", ["file:///local-evidence"])):
            gh, directory, note_path = self.case()
            notes = json.loads(note_path.read_bytes())
            notes[field] = value
            note_path.write_bytes(release.canonical(notes))
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, note_path, directory)
            self.assertEqual(gh.mutations, [])
        for field, value in (("commit", "b" * 40), ("run_id", RUN_ID + 1), ("run_attempt", ATTEMPT - 1),
                             ("artifact_id", ARTIFACT_ID + 1), ("artifact_sha256", "sha256:" + "0" * 64)):
            gh, directory, note_path = self.case()
            notes = json.loads(note_path.read_bytes())
            notes["artifact_associations"][release.MAC][field] = value
            note_path.write_bytes(release.canonical(notes))
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_IDS, note_path, directory)
            self.assertEqual(gh.mutations, [])

    def test_verify_rejects_local_tampering_and_remote_changes(self):
        for relative in ("candidates/" + release.MAC + "/artifact.zip", "candidates/" + release.MAC + "/prepared.zip",
                         "qualification-notes.json", "release-notes.md", "metadata.json",
                         "source/install.sh", "candidates/" + release.MAC + "/files/installed-state-acceptance.log", "plan.json", "PLAN_SHA256"):
            with self.subTest(relative=relative):
                gh, directory, _ = self.prepare()
                path = directory / relative
                path.write_bytes(path.read_bytes() + b"tampered")
                with self.assertRaises(ValueError):
                    release.verify(gh, directory)
                self.assertEqual(gh.mutations, [])
        gh, directory, _ = self.prepare()
        gh.run["display_title"] = "Changed remote metadata"
        with self.assertRaises(ValueError):
            release.verify(gh, directory)
        self.assertEqual(gh.mutations, [])
        gh, directory, _ = self.prepare()
        gh.run["run_attempt"] = ATTEMPT + 1
        gh.attempt = deepcopy(gh.run)
        gh.jobs[0].update(run_attempt=ATTEMPT + 1, started_at="2026-10-15T11:00:00Z",
                          completed_at="2026-10-15T11:30:00Z")
        with self.assertRaises(ValueError):
            release.verify(gh, directory)
        self.assertEqual(gh.mutations, [])

    def test_verify_binds_qualification_bytes_and_rejects_nonregular_assets(self):
        gh, directory, _ = self.prepare()
        notes = directory / "qualification-notes.json"
        notes.write_bytes(notes.read_bytes() + b"\n")  # Same JSON, different approved bytes.
        with self.assertRaises(ValueError):
            release.verify(gh, directory)
        self.assertEqual(gh.mutations, [])
        gh, directory, _ = self.prepare()
        asset = directory / "candidates" / release.MAC / "files" / "installer-acceptance.log"
        asset.unlink()
        asset.symlink_to(directory / "source" / "install.sh")
        with self.assertRaises(ValueError):
            release.verify(gh, directory)
        self.assertEqual(gh.mutations, [])

    def test_publish_rejects_wrong_approval_existing_state_and_revalidation_failure(self):
        for approved in ("0" * 64, "not-a-digest"):
            gh, directory, _ = self.prepare()
            with self.assertRaises(ValueError):
                release.publish(gh, directory, approved)
            self.assertEqual(gh.mutations, [])
            self.assertFalse((directory / "publication-started.json").exists())
        for existing in ("tag", "release", "journal", "corrupt"):
            with self.subTest(existing=existing):
                gh, directory, digest = self.prepare()
                if existing == "tag":
                    gh.tag = {"object": {"type": "commit", "sha": COMMIT}}
                elif existing == "release":
                    gh.draft = dict(id=RELEASE_ID, tag_name="v" + VERSION, draft=True)
                elif existing == "journal":
                    (directory / "publication-started.json").write_bytes(b"{}\n")
                else:
                    (directory / "candidates" / release.MAC / "files" / "installer-acceptance.log").write_bytes(b"corrupt")
                with self.assertRaises(ValueError):
                    release.publish(gh, directory, digest)
                self.assertEqual(gh.mutations, [])

    def native_draft(self):
        gh, directory, _ = self.prepare()
        gh.tag = {"object": {"type": "tag", "sha": "c" * 40}}
        gh.annotated_tag = dict(tag="v" + VERSION, object=dict(type="commit", sha=COMMIT))
        gh.draft = dict(id=RELEASE_ID, tag_name="v" + VERSION, draft=True,
                        body=(directory / "release-notes.md").read_text())
        return gh, directory

    def test_finalize_uses_native_tag_and_notes_and_publishes_only_verified_assets(self):
        gh, directory = self.native_draft()
        release.finalize(gh, directory)
        self.assertEqual(len(gh.mutations), 2)
        upload, publish = gh.mutations
        self.assertEqual(upload["args"], ["release", "upload", "v" + VERSION, "--repo", release.REPO,
                                          *sorted(EXPECTED_CANDIDATE)])
        self.assertEqual(upload["cwd"], directory / "assets")
        self.assertEqual(publish["args"][-1], "--latest")
        self.assertEqual(gh.draft["body"], "Initial release.")
        self.assertFalse(gh.draft["draft"])
        self.assertTrue((directory / "publication-started.json").is_file())
        self.assertEqual({asset["name"] for asset in gh.remote_assets}, EXPECTED_CANDIDATE)

    def test_finalize_rejects_wrong_native_tag_draft_and_notes_before_upload(self):
        changes = {
            "wrong-commit": lambda gh: gh.annotated_tag["object"].update(sha="b" * 40),
            "wrong-tag-name": lambda gh: gh.annotated_tag.update(tag="v0.2.0"),
            "missing-tag": lambda gh: setattr(gh, "tag", None),
            "published": lambda gh: gh.draft.update(draft=False),
            "notes": lambda gh: gh.draft.update(body="Other release notes"),
            "existing-assets": lambda gh: gh.remote_assets.append(dict(name="unexpected")),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                gh, directory = self.native_draft()
                change(gh)
                with self.assertRaises(ValueError):
                    release.finalize(gh, directory)
                self.assertEqual(gh.mutations, [])
                self.assertFalse((directory / "publication-started.json").exists())

    def test_finalize_leaves_partial_drafts_unpublished_and_refuses_automatic_retry(self):
        gh, directory = self.native_draft()
        gh.fail_upload = True
        with self.assertRaisesRegex(ValueError, "upload failure"):
            release.finalize(gh, directory)
        self.assertTrue(gh.draft["draft"])
        self.assertEqual(len(gh.mutations), 1)
        self.assertEqual(len(gh.remote_assets), 1)
        with self.assertRaises(ValueError):
            release.finalize(gh, directory)
        self.assertEqual(len(gh.mutations), 1)

    def test_finalize_rechecks_remote_bytes_notes_and_tag_after_upload(self):
        for change in (lambda gh: gh.remote_assets[0].update(digest="sha256:" + "0" * 64),
                       lambda gh: gh.draft.update(body="Changed after upload"),
                       lambda gh: gh.annotated_tag["object"].update(sha="b" * 40)):
            gh, directory = self.native_draft()
            gh.after_create = lambda: change(gh)
            with self.assertRaises(ValueError):
                release.finalize(gh, directory)
            self.assertTrue(gh.draft["draft"])
            self.assertEqual(len(gh.mutations), 1)

    def test_publish_creates_exact_tag_then_draft_with_all_assets_then_publishes(self):
        gh, directory, digest = self.prepare()
        release.publish(gh, directory, digest)
        self.assertEqual(len(gh.mutations), 3)
        tag, draft, publish = gh.mutations
        self.assertEqual(tag["args"], ["api", "--hostname", "github.com", "--method", "POST",
                                      release.BASE + "git/refs", "--input", "-"])
        self.assertEqual(json.loads(tag["data"]), {"ref": "refs/tags/v" + VERSION, "sha": COMMIT})
        self.assertEqual(draft["args"][11:], sorted(EXPECTED_CANDIDATE))
        self.assertEqual(draft["cwd"], directory / "assets")
        self.assertEqual(publish["args"], ["release", "edit", "v" + VERSION, "--draft=false", "--repo", release.REPO])
        self.assertFalse(gh.draft["draft"])
        self.assertTrue((directory / "publication-started.json").is_file())

    def test_plan_directory_is_literal_when_gh_uploads_assets(self):
        gh, original, digest = self.prepare()
        directory = original.with_name("candidate [review]#approved")
        original.rename(directory)
        release.publish(gh, directory, digest)
        uploaded = gh.mutations[1]
        self.assertEqual(uploaded["cwd"], directory / "assets")
        self.assertEqual(uploaded["args"][11:], sorted(EXPECTED_CANDIDATE))
        self.assertEqual(uploaded["args"][10], str(directory / "release-notes.md"))
        self.assertEqual({asset["name"] for asset in gh.remote_assets}, EXPECTED_CANDIDATE)
        self.assertFalse(gh.draft["draft"])

    def test_upload_failure_keeps_partial_draft_and_blocks_retry(self):
        gh, directory, digest = self.prepare()
        gh.fail_upload = True
        with self.assertRaisesRegex(ValueError, "upload failure"):
            release.publish(gh, directory, digest)
        self.assertTrue(gh.draft["draft"])
        self.assertEqual(len(gh.remote_assets), 1)
        self.assertEqual(len(gh.mutations), 2)
        self.assertTrue((directory / "publication-started.json").is_file())
        with self.assertRaises(ValueError):
            release.publish(gh, directory, digest)
        self.assertEqual(len(gh.mutations), 2)

    def test_remote_assets_must_match_all_names_sizes_digests_and_states(self):
        changes = {
            "missing": lambda assets: assets.pop(),
            "name": lambda assets: assets[0].update(name="unexpected.txt"),
            "duplicate": lambda assets: assets[0].update(name=assets[1]["name"]),
            "size": lambda assets: assets[0].update(size=assets[0]["size"] + 1),
            "digest": lambda assets: assets[0].update(digest="sha256:" + "0" * 64),
            "state": lambda assets: assets[0].update(state="new"),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                gh, directory, digest = self.prepare()
                gh.asset_error = change
                with self.assertRaises(ValueError):
                    release.publish(gh, directory, digest)
                self.assertTrue(gh.draft["draft"])
                self.assertEqual(len(gh.mutations), 2)
        gh, directory, digest = self.prepare()
        gh.created_tag_sha = "b" * 40
        with self.assertRaises(ValueError):
            release.publish(gh, directory, digest)
        self.assertIsNone(gh.draft)
        self.assertEqual(len(gh.mutations), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
