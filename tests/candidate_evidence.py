#!/usr/bin/env python3
"""Run offline candidate-evidence regressions with Python 3.11 or later.

Run ``python3 tests/candidate_evidence.py`` from the repository root. Native
programs and acceptance harnesses are fixture bytes and are never executed.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ci/candidate-jobs.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("candidate_release_fixture", ROOT / "tests/release.py")
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
release = fixtures.release
evidence = release.candidate_evidence
CONTEXT = dict(repository="ueberBrot/mailctl", commit="a" * 40, run_id=1234, run_attempt=2)


def checksums(files):
    return "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                   for name, data in sorted(files.items()) if name != "SHA256SUMS").encode()


class PreparedCandidate:
    """Simulate artifact downloads and isolated acceptance jobs using real CLI calls."""

    def __init__(self, case, directory, target):
        self.case = case
        self.root = directory
        self.target = target
        self.fixture = fixtures.Candidate(target)
        self.proof = json.loads(self.fixture.files["parallel-acceptance.json"])
        self.artifact = self.proof["artifact"]
        self.prepared = {name: self.fixture.files[name] for name in self.proof["build"]["candidate"]
                         if name != "SHA256SUMS"}
        self.prepared["SHA256SUMS"] = checksums(self.prepared)
        self.build = directory / "build"
        self.candidate = self.build / "candidate"
        self.harnesses = self.build / "harnesses"
        self.shards = directory / "shards"
        self.candidate.mkdir(parents=True)
        self.harnesses.mkdir()
        self.shards.mkdir()
        self.put(self.candidate, self.prepared)
        self.put(self.harnesses, {"fixture-driver": b"driver"})
        self.env = dict(os.environ, GITHUB_REPOSITORY=CONTEXT["repository"], GITHUB_SHA=CONTEXT["commit"],
                        GITHUB_RUN_ID="1234", GITHUB_RUN_ATTEMPT="2", MAILCTL_TARGET=target,
                        MAILCTL_BUILD_DIR=str(self.build), MAILCTL_BUILD_ARTIFACT_ID=str(self.artifact["id"]),
                        MAILCTL_BUILD_ARTIFACT_DIGEST="sha256:" + self.artifact["digest"])

    @staticmethod
    def put(directory, files):
        for name, data in files.items():
            (directory / name).write_bytes(data)

    def command(self, *arguments, succeeds=True, overrides=None, message=None):
        result = subprocess.run([sys.executable, "-B", str(HELPER), *map(str, arguments)],
                                cwd=ROOT, env=dict(self.env, **(overrides or {})),
                                capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        if succeeds:
            self.case.assertEqual(result.returncode, 0, output)
        else:
            self.case.assertNotEqual(result.returncode, 0, output)
            if message is not None:
                self.case.assertRegex(output, message)
        return result

    def payload(self, phase):
        receipt = next(shard for shard in self.proof["shards"] if shard["phase"] == phase)
        return {name: receipt["shared"][name].encode() if name in receipt["shared"]
                else self.fixture.files[name] for name in receipt["files"]}

    def record(self, phase, payload=None, succeeds=True):
        worker = self.root / "workers" / phase
        shutil.copytree(self.build, worker)
        for path in worker.rglob("*"):
            if path.is_file():
                path.chmod(0o644)  # Artifact downloads strip executable permissions.
        environment = dict(MAILCTL_BUILD_DIR=str(worker))
        self.command("restore", overrides=environment)
        self.put(worker / "candidate", self.payload(phase) if payload is None else payload)
        execution = next(shard["execution"] for shard in self.proof["shards"] if shard["phase"] == phase)
        build = json.loads((worker / "build.json").read_bytes())
        (worker / "execution.json").write_text(json.dumps(dict(context=CONTEXT, phase=phase, execution=execution,
            build_sha256=evidence.digest(evidence.canonical(build)), artifact=self.artifact)))
        self.command("record", "--phase", phase, "--evidence", self.shards / phase,
                     succeeds=succeeds, overrides=environment)

    def record_all(self, replacements=None, windows_encoding=False):
        # Neither job completion nor artifact directory order is phase order.
        for phase in reversed(evidence.phases(self.target)):
            payload = self.payload(phase)
            payload.update({name: data for name, data in (replacements or {}).items() if name in payload})
            if windows_encoding:
                for name in payload.keys() & evidence.SHARED:
                    payload[name] = b"\xef\xbb\xbf" + payload[name].replace(b"\n", b"\r\n")
            self.record(phase, payload)

    def collect(self, **kwargs):
        return self.command("collect", "--evidence", self.shards, **kwargs)

    def finish(self):
        # The platform recorder adds aggregate qualification text and final sums.
        self.put(self.candidate, {"acceptance-evidence.txt": self.fixture.files["acceptance-evidence.txt"]})
        self.put(self.candidate, {"SHA256SUMS": checksums(self.contents())})

    def contents(self):
        return {path.name: path.read_bytes() for path in self.candidate.iterdir()}


class CandidateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mailctl-evidence-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.serial = 0

    def prepared(self, target=release.MAC, *, seal=True):
        self.serial += 1
        candidate = PreparedCandidate(self, self.directory / str(self.serial), target)
        if seal:
            candidate.command("seal")
        return candidate

    def test_core_proof_binds_candidate_bytes_run_attempt_and_source_artifact(self):
        for target in fixtures.TARGETS:
            candidate = fixtures.Candidate(target)
            proof = json.loads(candidate.files["parallel-acceptance.json"])
            artifact = proof["artifact"]
            evidence.validate(proof, candidate.files, target, fixtures.COMMIT, CONTEXT, artifact)
            for key, value in (("repository", "another/repository"), ("commit", "c" * 40),
                               ("run_id", 1235), ("run_attempt", 3)):
                with self.subTest(target=target, context=key), self.assertRaises(ValueError):
                    evidence.validate(proof, candidate.files, target, fixtures.COMMIT,
                                      dict(CONTEXT, **{key: value}), artifact)
            for wrong in (dict(artifact, id=1), dict(artifact, digest="c" * 64)):
                with self.subTest(target=target, artifact=wrong), self.assertRaises(ValueError):
                    evidence.validate(proof, candidate.files, target, fixtures.COMMIT, CONTEXT, wrong)
            names = [release.archive_name(target), release.binary_name("mailctl", fixtures.VERSION, target),
                     "installed-state-cli-acceptance.log" if target == release.WINDOWS
                     else "installed-state-acceptance.log"]
            if target == release.LINUX:
                names += ["linux-source-evidence.txt", "desktop-source-evidence.txt"]
            if target == release.WINDOWS:
                names += ["windows-source-evidence.txt", "windows-wsl-evidence.txt"]
            for name in names:
                with self.subTest(target=target, changed=name), self.assertRaises(ValueError):
                    evidence.validate(proof, dict(candidate.files, **{name: candidate.files[name] + b"changed"}),
                                      target, fixtures.COMMIT, CONTEXT, artifact)

    def test_cli_roundtrip_preserves_all_platform_candidates_and_source_evidence(self):
        for target in fixtures.TARGETS:
            with self.subTest(target=target):
                candidate = self.prepared(target)
                build = json.loads((candidate.build / "build.json").read_bytes())
                self.assertEqual(build, candidate.proof["build"])
                for path in (*candidate.candidate.iterdir(), *candidate.harnesses.iterdir()):
                    path.chmod(0o644)
                candidate.command("restore")
                executable = [candidate.harnesses / "fixture-driver"] + [candidate.candidate /
                    release.binary_name(binary, fixtures.VERSION, target) for binary in release.COMPONENTS.values()]
                for path in executable:
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755, path.name)
                for name in (release.archive_name(target), "dist-manifest.json", "SHA256SUMS"):
                    self.assertEqual(stat.S_IMODE((candidate.candidate / name).stat().st_mode), 0o644)
                candidate.record_all(windows_encoding=target == release.WINDOWS)
                candidate.collect()
                candidate.finish()
                candidate.command("verify")
                files = candidate.contents()
                expected_phases = ["installer", "state", "process", "native", "reading", "drafts"]
                if target == release.LINUX:
                    expected_phases += ["desktop-credentials", "desktop-reading", "desktop-drafts"]
                elif target == release.WINDOWS:
                    expected_phases += ["wsl"]
                proof = json.loads(files["parallel-acceptance.json"])
                self.assertEqual([shard["phase"] for shard in proof["shards"]], expected_phases)
                self.assertEqual(release.validate_candidate(files, candidate.fixture.source, fixtures.COMMIT, target),
                                 ("0.1.0", "Initial release."))
                self.assertEqual({name: files[name] for name in candidate.prepared if name != "SHA256SUMS"},
                                 {name: data for name, data in candidate.prepared.items() if name != "SHA256SUMS"})
                for name in set(files) - set(candidate.prepared) - {"parallel-acceptance.json"}:
                    expected = candidate.fixture.files[name]
                    if name == "windows-source-evidence.txt":
                        expected = expected.replace(b"\r\n", b"\n")
                    self.assertEqual(files[name], expected, name)
                if target == release.LINUX:
                    for name in ("linux-source-evidence.txt", "desktop-source-evidence.txt"):
                        self.assertEqual(re.findall(rb"^suite=(.+)$", files[name], re.MULTILINE),
                                         [b"credentials", b"reading", b"drafts"])

    def test_seal_rejects_bad_checksums_untracked_files_and_missing_harnesses(self):
        for problem in ("modified", "missing", "untracked", "duplicate-checksum", "no-harness"):
            with self.subTest(problem=problem):
                candidate = self.prepared(seal=False)
                installer = candidate.candidate / "install.sh"
                if problem == "modified":
                    installer.write_bytes(installer.read_bytes() + b"changed")
                elif problem == "missing":
                    installer.unlink()
                elif problem == "untracked":
                    (candidate.candidate / "untracked.txt").write_bytes(b"unexpected")
                elif problem == "duplicate-checksum":
                    manifest = candidate.candidate / "SHA256SUMS"
                    manifest.write_bytes(manifest.read_bytes() * 2)
                else:
                    (candidate.harnesses / "fixture-driver").unlink()
                candidate.command("seal", succeeds=False)
                self.assertFalse((candidate.build / "build.json").exists())

    def test_restore_rejects_modified_and_added_prepared_or_harness_files(self):
        for directory in ("candidate", "harnesses"):
            for problem in ("modified", "untracked", "symlink"):
                with self.subTest(directory=directory, problem=problem):
                    candidate = self.prepared()
                    root = candidate.build / directory
                    name = "install.sh" if directory == "candidate" else "fixture-driver"
                    path = root / name
                    if problem == "modified":
                        path.write_bytes(path.read_bytes() + b"changed")
                    elif problem == "untracked":
                        (root / "extra").write_bytes(b"unexpected")
                    else:
                        outside = candidate.root / "outside"
                        path.rename(outside)
                        path.symlink_to(outside)
                    candidate.command("restore", succeeds=False)

    def test_downloaded_build_rejects_stale_context_and_wrong_target(self):
        candidate = self.prepared()
        for name, value in (("GITHUB_REPOSITORY", "another/repository"), ("GITHUB_SHA", "c" * 40),
                            ("GITHUB_RUN_ID", "1235"), ("GITHUB_RUN_ATTEMPT", "3"),
                            ("MAILCTL_TARGET", release.LINUX)):
            with self.subTest(environment=name):
                candidate.command("restore", succeeds=False, overrides={name: value}, message="another run or attempt")

    def test_record_requires_exact_acceptance_phase_files(self):
        for target, phase in ((release.MAC, "reading"), (release.LINUX, "native"), (release.WINDOWS, "wsl")):
            for problem in ("missing", "unexpected"):
                with self.subTest(target=target, problem=problem):
                    candidate = self.prepared(target)
                    payload = candidate.payload(phase)
                    if problem == "missing":
                        payload.pop(next(iter(payload)))
                    else:
                        payload["unrelated.log"] = b"test result: ok. 1 passed; 0 failed; 0 ignored;\n"
                    candidate.record(phase, payload, succeeds=False)
                    self.assertFalse((candidate.shards / phase).exists())

    def test_executing_worker_records_argv_and_paths_only_after_success(self):
        candidate = self.prepared()
        commands = candidate.root / "commands"
        commands.mkdir()
        bash = commands / "bash"
        bash.write_text("#!/bin/sh\nexit 37\n")
        bash.chmod(0o755)
        paths = dict(MAILCTL_CANDIDATE_DIR=str(candidate.candidate),
                     MAILCTL_HARNESS_DIR=str(candidate.harnesses),
                     MAILCTL_PACKAGED_BIN_DIR=str(candidate.root / "installed"))
        environment = dict(paths, PATH=str(commands) + os.pathsep + os.environ["PATH"])
        candidate.command("run", "--phase", "state", succeeds=False, overrides=environment)
        ledger = candidate.build / "execution.json"
        self.assertFalse(ledger.exists())
        bash.write_text("#!/bin/sh\nexit 0\n")
        candidate.command("run", "--phase", "state", overrides=environment)
        recorded = json.loads(ledger.read_bytes())
        self.assertEqual(recorded["context"], CONTEXT)
        self.assertEqual(recorded["phase"], "state")
        self.assertEqual(recorded["execution"]["argv"], ["bash", str(ROOT / "scripts/ci/candidate.sh"), "state"])
        self.assertEqual(recorded["execution"]["env"], paths)

    def test_unix_collector_records_checksums_for_the_proof_and_all_acceptance_files(self):
        candidate = self.prepared()
        candidate.record_all()
        candidate.collect()
        commands = candidate.root / "commands"
        commands.mkdir()
        version = commands / "sw_vers"
        version.write_text("#!/bin/sh\nprintf '26.0\\n'\n")
        version.chmod(0o755)
        environment = dict(candidate.env, MAILCTL_CANDIDATE_DIR=str(candidate.candidate),
                           MAILCTL_HARNESS_DIR=str(candidate.harnesses),
                           MAILCTL_PACKAGED_BIN_DIR=str(candidate.root / "installed"),
                           PATH=str(commands) + os.pathsep + os.environ["PATH"])
        result = subprocess.run(["bash", str(ROOT / "scripts/ci/candidate.sh"), "record"],
                                env=environment, cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        candidate.command("verify")
        contents = candidate.contents()
        self.assertEqual(release.checksum_lines(contents["SHA256SUMS"]),
                         {name: release.sha(data) for name, data in contents.items() if name != "SHA256SUMS"})
        release.validate_candidate(contents, candidate.fixture.source, fixtures.COMMIT, candidate.target)

    def test_collect_requires_one_shard_per_phase_from_the_same_build_and_artifact(self):
        candidate = self.prepared()
        candidate.record_all()
        installer = candidate.shards / "installer"
        receipt_path = installer / "receipt.json"
        original = receipt_path.read_bytes()
        for problem in ("missing", "duplicate", "artifact-id", "artifact-digest", "attempt", "build", "host"):
            with self.subTest(problem=problem):
                receipt = json.loads(original)
                if problem == "missing":
                    installer.rename(candidate.root / "missing-installer")
                elif problem == "duplicate":
                    shutil.copytree(installer, candidate.shards / "duplicate")
                else:
                    if problem.startswith("artifact-"):
                        receipt["artifact"]["id" if problem == "artifact-id" else "digest"] = (
                            9999 if problem == "artifact-id" else "c" * 64)
                    elif problem == "attempt":
                        receipt["context"]["run_attempt"] = 3
                    elif problem == "build":
                        receipt["build_sha256"] = "c" * 64
                    else:
                        receipt["host"]["machine"] = ""
                    receipt_path.write_text(json.dumps(receipt))
                candidate.collect(succeeds=False)
                self.assertFalse((candidate.candidate / "parallel-acceptance.json").exists())
                if problem == "missing":
                    (candidate.root / "missing-installer").rename(installer)
                elif problem == "duplicate":
                    shutil.rmtree(candidate.shards / "duplicate")
                else:
                    receipt_path.write_bytes(original)

    def test_collect_rejects_changed_or_added_shard_payloads(self):
        candidate = self.prepared(release.LINUX)
        candidate.record_all()
        folder = candidate.shards / "native"
        for name in ("installed-native-acceptance.log", "linux-source-evidence.txt", "unexpected.log"):
            with self.subTest(changed=name):
                path = folder / name
                original = path.read_bytes() if path.exists() else None
                path.write_bytes((original or b"") + b"changed")
                candidate.collect(succeeds=False, message="evidence bytes changed")
                self.assertFalse((candidate.candidate / "parallel-acceptance.json").exists())
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)

    def test_verify_rejects_changed_evidence_reordered_proof_and_wrong_artifact(self):
        candidate = self.prepared(release.LINUX)
        candidate.record_all()
        candidate.collect()
        candidate.finish()
        for name in ("installed-state-acceptance.log", "linux-source-evidence.txt", "desktop-source-evidence.txt"):
            with self.subTest(changed=name):
                path = candidate.candidate / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                candidate.command("verify", succeeds=False)
                path.write_bytes(original)
        proof_path = candidate.candidate / "parallel-acceptance.json"
        original = proof_path.read_bytes()
        proof = json.loads(original)
        proof["shards"].reverse()
        proof_path.write_text(json.dumps(proof))
        candidate.command("verify", succeeds=False, message="out of order")
        proof_path.write_bytes(original)
        for overrides in (dict(MAILCTL_BUILD_ARTIFACT_ID="1"), dict(MAILCTL_BUILD_ARTIFACT_DIGEST="sha256:" + "c" * 64)):
            with self.subTest(artifact=overrides):
                candidate.command("verify", succeeds=False, overrides=overrides, message="artifact identity differs")
        candidate.command("verify")

    def test_release_rejects_empty_zero_or_ignored_tests_despite_valid_proof_and_checksums(self):
        for target in fixtures.TARGETS:
            for result in (b"", b"test result: ok. 0 passed; 0 failed; 0 ignored;\n",
                           b"test result: ok. 2 passed; 0 failed; 1 ignored;\n"):
                with self.subTest(target=target, result=result):
                    candidate = self.prepared(target)
                    candidate.record_all({"installed-reading-cli-acceptance.log" if target != release.LINUX
                                          else "installed-reading-command-cli-acceptance.log": result})
                    candidate.collect()
                    candidate.finish()
                    candidate.command("verify")
                    with self.assertRaisesRegex(ValueError, "Empty acceptance log|Missing passing tests"):
                        release.validate_candidate(candidate.contents(), candidate.fixture.source, fixtures.COMMIT, target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
