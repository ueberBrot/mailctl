#!/usr/bin/env python3
"""Run offline release-helper checks with Python 3.11 or later.

Run ``python3 tests/release.py`` from the repository root. Every GitHub command
stops at FakeGitHub.call. The fixture programs are bytes and never run.
"""

from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import stat
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
SPEC = importlib.util.spec_from_file_location("mailctl_release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

COMMIT = "a" * 40
VERSION = "0.1.0"
RUN_ID = 1234
ATTEMPT = 2
ARTIFACT_ID = 5678
RELEASE_ID = 9012
LOG_NAMES = {
    "installer-acceptance.log", "installed-state-acceptance.log",
    "installed-process-acceptance.log", "installed-native-acceptance.log",
    "installed-reading-cli-acceptance.log", "installed-reading-mcp-acceptance.log",
    "installed-reading-cli-mcp-acceptance.log", "installed-drafts-cli-acceptance.log",
    "installed-drafts-mcp-acceptance.log", "installed-drafts-cli-mcp-acceptance.log",
}
EXPECTED_CANDIDATE = LOG_NAMES | {
    "SHA256SUMS", "acceptance-evidence.txt", "build-evidence.txt", "dist-manifest.json",
    "install-v0.1.0.sh", "manifest-v0.1.0-aarch64-apple-darwin.txt",
    "mailctl-aarch64-apple-darwin.tar.gz", "mailctl-aarch64-apple-darwin.tar.gz.sha256",
    "mailctl-v0.1.0-aarch64-apple-darwin", "mailctl-mcp-v0.1.0-aarch64-apple-darwin",
}


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


class Candidate:
    """Build the current candidate.sh output without compiling or executing it."""

    def __init__(self):
        self.source = {
            "Cargo.toml": b'[workspace.package]\nversion = "0.1.0"\n',
            "install.sh": (ROOT / "install.sh").read_bytes(),
            "CHANGELOG.md": b"# Changelog\n\n## [0.1.0] - 2026-10-15\n\nInitial release.\n",
        }
        self.binaries = {"mailctl": b"\xcf\xfa\xed\xfe\x00CLI candidate bytes\n",
                         "mailctl-mcp": b"\xcf\xfa\xed\xfe\x00MCP candidate bytes\n"}
        self.files = {}
        receipt = dict(format="1", version=VERSION, target=release.TARGET,
                       commit=COMMIT, compatibility="1")
        for component, binary in release.COMPONENTS.items():
            name = f"{binary}-v{VERSION}-{release.TARGET}"
            self.files[name] = self.binaries[binary]
            receipt.update({component + "_file": name,
                            component + "_sha256": release.sha(self.binaries[binary]),
                            component + "_size": str(len(self.binaries[binary])),
                            component + "_signing": "ad-hoc"})
        self.files[f"manifest-v{VERSION}-{release.TARGET}.txt"] = evidence(receipt)
        self.files[f"install-v{VERSION}.sh"] = self.source["install.sh"]
        build = dict(status="prepared", source="clean", commit=COMMIT,
                     version=VERSION, target=release.TARGET, compatibility="1",
                     dist_version="0.33.0", rustc="rustc 1.98.1 (fixture)",
                     macos="26.0", architecture="arm64", archive_sha256="pending",
                     build_command=f"dist build --artifacts=local --target {release.TARGET} --output-format=json",
                     publication="not-performed", notarization="not-performed")
        self.files["build-evidence.txt"] = evidence(build)
        acceptance = dict(status="passed", topology="cooperative-embedded",
                          credential_source="disposable-apple-keychain",
                          packaged_bin_directory="/Users/runner/work/_temp/mailctl-installed",
                          installer_command="python3 tests/installer.py --suite packaged --artifacts /Users/runner/work/_temp/mailctl-release-candidate --install-to /Users/runner/work/_temp/mailctl-installed ",
                          state_command="cargo test --locked --test administration_process --test state_maintenance ",
                          process_command="cargo test --locked --test mcp_process --test message_process --test attachment_process --test search_process --test discovery_process --test read_contention_process --test draft_process ",
                          native_command="cargo test --locked --test native_credentials -- --ignored --test-threads=1 ",
                          reading_credential_source="disposable-command-helper",
                          reading_tls_source="fixture-ca-via-SSL_CERT_FILE",
                          drafts_credential_source="disposable-command-helper",
                          drafts_tls_source="fixture-ca-via-SSL_CERT_FILE")
        for suite in ("reading", "drafts"):
            for selection in ("cli", "mcp", "cli,mcp"):
                installed = "/Users/runner/work/_temp/mailctl-installed"
                if selection != "cli,mcp":
                    installed += "-" + selection
                acceptance[f"{suite}_components_command_{selection}"] = (
                    "python3 tests/installer.py --artifacts /Users/runner/work/_temp/mailctl-release-candidate "
                    f"--install-only --reuse --components {selection} --install-to {installed} ")
                selected_test = "" if selection == "cli,mcp" else selection + "_ "
                acceptance[f"{suite}_command_{selection}"] = (
                    f"env MAILCTL_PACKAGED_BIN_DIR={installed} cargo test --locked "
                    f"--test packaged_{suite} {selected_test}-- --test-threads=1 ")
        acceptance.update(real_provider="not-qualified", isolation="not-qualified",
                          publication="not-performed")
        # candidate.sh includes these host lines alongside the key/value fields.
        self.files["acceptance-evidence.txt"] = (
            evidence(acceptance) + b"ProductName:\tmacOS\nProductVersion:\t26.0\nBuildVersion:\t25A354\nDarwin arm64\n")
        for name in LOG_NAMES:
            self.files[name] = b"test fixture ... ok\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        self.files["installer-acceptance.log"] = b"Ran 12 tests in 0.123s\n\nOK\n"
        self.archive()

    def archive(self, binaries=None, special_member=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for binary, data in (binaries or self.binaries).items():
                info = tarfile.TarInfo(f"mailctl-{release.TARGET}/{binary}")
                info.mode = 0o755
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if special_member is not None:
                archive.addfile(special_member)
        self.files[release.ARCHIVE] = output.getvalue()
        digest = release.sha(output.getvalue())
        self.files[release.ARCHIVE + ".sha256"] = f"{digest}  {release.ARCHIVE}\n".encode()
        build = release.fields(self.files["build-evidence.txt"])
        build["archive_sha256"] = digest
        self.files["build-evidence.txt"] = evidence(build)
        manifest = {
            "dist_version": "0.33.0",
            "releases": [{"app_name": "mailctl", "app_version": VERSION,
                          "artifacts": [release.ARCHIVE, release.ARCHIVE + ".sha256"]}],
            "artifacts": {
                release.ARCHIVE: {
                    "name": release.ARCHIVE, "kind": "executable-zip",
                    "path": "/Users/runner/work/mailctl/mailctl/target/distrib/" + release.ARCHIVE,
                    "target_triples": [release.TARGET], "checksum": release.ARCHIVE + ".sha256",
                    "checksums": {"sha256": digest},
                    "assets": [{"name": name, "kind": "executable", "path": name}
                               for name in self.binaries]},
                release.ARCHIVE + ".sha256": {
                    "name": release.ARCHIVE + ".sha256", "kind": "checksum",
                    "path": "/Users/runner/work/mailctl/mailctl/target/distrib/" + release.ARCHIVE + ".sha256"},
            },
        }
        self.files["dist-manifest.json"] = release.canonical(manifest)
        self.sums()

    def sums(self):
        self.files["SHA256SUMS"] = "".join(
            f"{release.sha(data)}  {name}\n" for name, data in sorted(self.files.items())
            if name != "SHA256SUMS").encode()

    def zip(self):
        return make_zip((name, data, stat.S_IFREG | 0o644) for name, data in sorted(self.files.items()))


class FakeGitHub(release.GitHub):
    """Override only the external-command boundary; use the real API adapters."""

    def __init__(self, candidate=None, zip_bytes=None):
        self.candidate = candidate or Candidate()
        self.zip_bytes = zip_bytes if zip_bytes is not None else self.candidate.zip()
        self.calls = []
        self.tag = None
        self.draft = None
        self.remote_assets = []
        self.fail_upload = False
        self.asset_error = None
        self.created_tag_sha = COMMIT
        self.workflow = dict(id=99, path=".github/workflows/ci.yml", state="active")
        repository = dict(id=42, full_name=release.REPO)
        self.run = dict(id=RUN_ID, head_sha=COMMIT, head_branch="main", event="push",
                        status="completed", conclusion="success", workflow_id=99,
                        path=".github/workflows/ci.yml", run_attempt=ATTEMPT,
                        repository=repository, head_repository=deepcopy(repository))
        self.attempt = deepcopy(self.run)
        self.jobs = [dict(id=777, name="native-credentials", run_id=RUN_ID,
                          run_attempt=ATTEMPT, head_sha=COMMIT, status="completed",
                          conclusion="success", started_at="2026-10-15T10:00:00Z",
                          completed_at="2026-10-15T10:30:00Z", steps=[
                              dict(name="Record passing candidate acceptance", status="completed",
                                   conclusion="success", number=11,
                                   started_at="2026-10-15T10:28:00Z", completed_at="2026-10-15T10:28:59Z"),
                              dict(name="Keep candidate downloads and acceptance evidence", status="completed",
                                   conclusion="success", number=12,
                                   started_at="2026-10-15T10:29:00Z", completed_at="2026-10-15T10:29:59Z")])]
        self.artifact = dict(id=ARTIFACT_ID, name=release.ARTIFACT, expired=False,
                             size_in_bytes=len(self.zip_bytes), digest="sha256:" + release.sha(self.zip_bytes),
                             created_at="2026-10-15T10:29:30Z", updated_at="2026-10-15T10:29:30Z",
                             expires_at="2099-10-29T10:29:30Z",
                             workflow_run=dict(id=RUN_ID, head_sha=COMMIT, head_branch="main",
                                               repository_id=42, head_repository_id=42))
        self.artifacts = [self.artifact]
        self.main_sha = COMMIT

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
            return b"{}"
        if method != "GET":
            raise AssertionError("Unexpected API mutation: " + repr(args))
        path = urlsplit(endpoint).path
        query = parse_qs(urlsplit(endpoint).query)
        if path == f"actions/artifacts/{ARTIFACT_ID}/zip":
            if output is None:
                raise AssertionError("Download requires a destination")
            output.write(self.zip_bytes)
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
            f"actions/artifacts/{ARTIFACT_ID}": self.artifact,
            f"git/ref/tags/v{VERSION}": self.tag,
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
            if {path.name for path in assets} != EXPECTED_CANDIDATE or len(assets) != 20:
                raise AssertionError("Draft creation must name all 20 assets")
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
            return b""
        if args == ["release", "edit", "v" + VERSION, "--draft=false", "--repo", release.REPO]:
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
                     artifact_association=dict(commit=COMMIT, run_id=RUN_ID, run_attempt=ATTEMPT,
                                               artifact_id=ARTIFACT_ID, artifact_sha256=gh.artifact["digest"]))
        note_path = directory / "notes.json"
        note_path.write_bytes(release.canonical(notes))
        return gh, directory / "plan", note_path

    def prepare(self, gh=None):
        gh, directory, notes = self.case(gh)
        digest = release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_ID, notes, directory)
        return gh, directory, digest

    def rejected(self, gh, message=None):
        gh, directory, notes = self.case(gh)
        with self.assertRaises(ValueError) if message is None else self.assertRaisesRegex(ValueError, message):
            release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_ID, notes, directory)
        self.assertEqual(gh.mutations, [])

    def test_prepare_and_verify_preserve_exact_bytes_without_mutations(self):
        gh, directory, digest = self.prepare()
        plan, actual = release.verify(gh, directory)
        self.assertEqual(actual, digest)
        self.assertEqual((directory / "artifact.zip").read_bytes(), gh.zip_bytes)
        self.assertEqual(set(plan["assets"]), EXPECTED_CANDIDATE)
        self.assertEqual(len(plan["assets"]), 20)
        self.assertEqual(plan["run_attempt"], ATTEMPT)
        for name, data in gh.candidate.files.items():
            self.assertEqual((directory / "candidate" / name).read_bytes(), data)
        for name, data in gh.candidate.source.items():
            self.assertEqual((directory / "source" / name).read_bytes(), data)
        self.assertEqual(gh.mutations, [])
        self.assertTrue(all(call["args"][:5] == ["api", "--hostname", "github.com", "--method", "GET"] for call in gh.calls))

    def test_linked_release_plz_changelog_heading(self):
        candidate = Candidate()
        candidate.source["CHANGELOG.md"] = b"## [0.1.0](https://github.com/ueberBrot/mailctl/compare/v0.0.0...v0.1.0) - 2026-10-15\n\nInitial release.\n"
        self.prepare(FakeGitHub(candidate))

    def test_invalid_or_noncurrent_commit_and_ids(self):
        for commit in ("a" * 39, "A" * 40, "b" * 40):
            with self.subTest(commit=commit):
                gh, directory, notes = self.case()
                with self.assertRaises(ValueError):
                    release.prepare(gh, commit, RUN_ID, ARTIFACT_ID, notes, directory)
                self.assertEqual(gh.mutations, [])
        for run_id, artifact_id in ((0, ARTIFACT_ID), (RUN_ID, -1), (True, ARTIFACT_ID)):
            with self.subTest(run_id=run_id, artifact_id=artifact_id):
                gh, directory, notes = self.case()
                with self.assertRaises(ValueError):
                    release.prepare(gh, COMMIT, run_id, artifact_id, notes, directory)
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
        manifest_name = f"manifest-v{VERSION}-{release.TARGET}.txt"
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
        manifest["artifacts"][release.ARCHIVE]["target_triples"] = ["x86_64-apple-darwin"]
        candidate.files["dist-manifest.json"] = release.canonical(manifest)
        candidate.sums()
        self.rejected(FakeGitHub(candidate))

    def test_source_version_installer_and_changelog(self):
        for version in ("01.0.0", "0.1.0-rc.1", "v0.1.0"):
            candidate = Candidate()
            candidate.source["Cargo.toml"] = f'[workspace.package]\nversion = "{version}"\n'.encode()
            self.rejected(FakeGitHub(candidate))
        candidate = Candidate()
        candidate.files[f"install-v{VERSION}.sh"] += b"# changed\n"
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
                release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_ID, note_path, directory)
            self.assertEqual(gh.mutations, [])
        for field, value in (("commit", "b" * 40), ("run_id", RUN_ID + 1), ("run_attempt", ATTEMPT - 1),
                             ("artifact_id", ARTIFACT_ID + 1), ("artifact_sha256", "sha256:" + "0" * 64)):
            gh, directory, note_path = self.case()
            notes = json.loads(note_path.read_bytes())
            notes["artifact_association"][field] = value
            note_path.write_bytes(release.canonical(notes))
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.prepare(gh, COMMIT, RUN_ID, ARTIFACT_ID, note_path, directory)
            self.assertEqual(gh.mutations, [])

    def test_verify_rejects_local_tampering_and_remote_changes(self):
        for relative in ("artifact.zip", "qualification-notes.json", "release-notes.md", "metadata.json",
                         "source/install.sh", "candidate/installed-state-acceptance.log", "plan.json", "PLAN_SHA256"):
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
        asset = directory / "candidate" / "installer-acceptance.log"
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
                    (directory / "candidate" / "installer-acceptance.log").write_bytes(b"corrupt")
                with self.assertRaises(ValueError):
                    release.publish(gh, directory, digest)
                self.assertEqual(gh.mutations, [])

    def test_publish_creates_exact_tag_then_draft_with_all_assets_then_publishes(self):
        gh, directory, digest = self.prepare()
        release.publish(gh, directory, digest)
        self.assertEqual(len(gh.mutations), 3)
        tag, draft, publish = gh.mutations
        self.assertEqual(tag["args"], ["api", "--hostname", "github.com", "--method", "POST",
                                      release.BASE + "git/refs", "--input", "-"])
        self.assertEqual(json.loads(tag["data"]), {"ref": "refs/tags/v" + VERSION, "sha": COMMIT})
        self.assertEqual(draft["args"][11:], sorted(gh.candidate.files))
        self.assertEqual(draft["cwd"], directory / "candidate")
        self.assertEqual(publish["args"], ["release", "edit", "v" + VERSION, "--draft=false", "--repo", release.REPO])
        self.assertFalse(gh.draft["draft"])
        self.assertTrue((directory / "publication-started.json").is_file())

    def test_plan_directory_is_literal_when_gh_uploads_assets(self):
        gh, original, digest = self.prepare()
        directory = original.with_name("candidate [review]#approved")
        original.rename(directory)
        release.publish(gh, directory, digest)
        uploaded = gh.mutations[1]
        self.assertEqual(uploaded["cwd"], directory / "candidate")
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
