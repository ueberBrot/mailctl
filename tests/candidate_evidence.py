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
import textwrap
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

    def stub_commands(self):
        commands = self.root / "commands"
        if commands.exists():
            return commands
        commands.mkdir()
        payloads = self.root / "payloads"
        payloads.mkdir()
        for phase in evidence.phases(self.target):
            folder = payloads / phase
            folder.mkdir()
            self.put(folder, self.payload(phase))
        script = f"#!{sys.executable}\n" + textwrap.dedent("""\
            import hashlib
            import json
            import os
            from pathlib import Path
            import sys

            def hashes(directory):
                return {path.name: dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                       size=path.stat().st_size) for path in directory.iterdir()}

            root = Path(os.environ["MAILCTL_FIXTURE_ROOT"])
            phase = sys.argv[-1]
            if any(Path(arg).name == "desktop-acceptance.sh" for arg in sys.argv[1:]):
                phase = "desktop-" + phase
            paths = {name: os.environ[name] for name in
                     ("MAILCTL_CANDIDATE_DIR", "MAILCTL_HARNESS_DIR", "MAILCTL_PACKAGED_BIN_DIR")}
            candidate = Path(paths["MAILCTL_CANDIDATE_DIR"])
            record = dict(phase=phase, before=hashes(candidate),
                          harnesses=hashes(Path(paths["MAILCTL_HARNESS_DIR"])),
                          execution=dict(argv=[Path(sys.argv[0]).name, *sys.argv[1:]], env=paths))
            with (root / "commands.jsonl").open("a") as trace:
                trace.write(json.dumps(record) + "\\n")
            for path in (root / "payloads" / phase).iterdir():
                (candidate / path.name).write_bytes(path.read_bytes())
            if phase == os.environ.get("MAILCTL_FIXTURE_MUTATE_PHASE"):
                build = Path(os.environ["MAILCTL_BUILD_DIR"])
                changed = {"prepared": build / "candidate" / "install.sh",
                           "harness": build / "harnesses" / "fixture-driver",
                           "phase": candidate / "install.sh"}[os.environ["MAILCTL_FIXTURE_MUTATE"]]
                changed.write_bytes(changed.read_bytes() + b"changed")
            if phase == os.environ.get("MAILCTL_FIXTURE_FAIL_PHASE"):
                sys.exit(37)
            """)
        for name in ("bash", "pwsh"):
            command = commands / name
            command.write_text(script)
            command.chmod(0o755)
        return commands

    def group_worker(self, group):
        commands = self.stub_commands()
        worker = self.root / "group-workers" / group
        shutil.copytree(self.build, worker)
        for path in worker.rglob("*"):
            if path.is_file():
                path.chmod(0o644)
        environment = dict(MAILCTL_BUILD_DIR=str(worker), MAILCTL_CANDIDATE_DIR=str(worker / "candidate"),
                           MAILCTL_HARNESS_DIR=str(worker / "harnesses"),
                           MAILCTL_PACKAGED_BIN_DIR=str(worker / "installed"),
                           MAILCTL_FIXTURE_ROOT=str(self.root),
                           PATH=str(commands) + os.pathsep + os.environ["PATH"])
        self.command("restore", overrides=environment)
        return worker, environment

    def qualify(self, group, environment, **kwargs):
        return self.command("qualify", "--group", group, "--evidence", self.shards / group,
                            overrides=environment, **kwargs)

    def executions(self):
        trace = self.root / "commands.jsonl"
        return [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []

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

    def test_acceptance_groups_preserve_required_platform_phase_membership_and_order(self):
        expected = {
            release.MAC: {"core": ("installer", "state", "process", "native", "drafts"),
                          "reading": ("reading",)},
            release.LINUX: {"core": ("installer", "state", "process", "native", "drafts",
                                     "desktop-credentials", "desktop-drafts"),
                            "reading": ("reading", "desktop-reading")},
            release.WINDOWS: {"core": ("installer", "state", "process", "native"),
                              "content": ("reading", "drafts", "wsl")},
        }
        for target, groups in expected.items():
            with self.subTest(target=target):
                self.assertEqual(evidence.acceptance_groups(target), groups)
        with self.assertRaises(ValueError):
            evidence.acceptance_groups("unsupported-target")

    def test_grouped_cli_roundtrip_isolates_phase_outputs_and_records_actual_commands(self):
        for target in fixtures.TARGETS:
            with self.subTest(target=target):
                candidate = self.prepared(target)
                build = json.loads((candidate.build / "build.json").read_bytes())
                expected_order = []
                for group, phases in reversed(list(evidence.acceptance_groups(target).items())):
                    worker, environment = candidate.group_worker(group)
                    candidate.qualify(group, environment)
                    expected_order.extend(phases)
                    self.assertEqual({path.name for path in (candidate.shards / group).iterdir()}, set(phases))
                    self.assertEqual({path.name: path.read_bytes() for path in (worker / "candidate").iterdir()},
                                     candidate.prepared)
                    self.assertEqual({path.name: path.read_bytes() for path in (worker / "harnesses").iterdir()},
                                     {"fixture-driver": b"driver"})
                    for phase in phases:
                        folder = candidate.shards / group / phase
                        receipt = json.loads((folder / "receipt.json").read_bytes())
                        payload = candidate.payload(phase)
                        self.assertEqual({path.name: path.read_bytes() for path in folder.iterdir()
                                          if path.name != "receipt.json"}, payload)
                        phase_candidate = worker / "phases" / phase / "candidate"
                        self.assertEqual({path.name: path.read_bytes() for path in phase_candidate.iterdir()},
                                         dict(candidate.prepared, **payload))
                        if target == release.WINDOWS:
                            script = ("windows-candidate.ps1" if phase == "installer"
                                      else "windows-packaged-acceptance.ps1")
                            argv = ["pwsh", "-NoProfile", "-File", str(ROOT / "scripts/ci" / script),
                                    "-Phase", phase]
                        else:
                            script = "desktop-acceptance.sh" if phase.startswith("desktop-") else "candidate.sh"
                            argv = ["bash", str(ROOT / "scripts/ci" / script), phase.removeprefix("desktop-")]
                        paths = {name: environment[name] for name in
                                 ("MAILCTL_HARNESS_DIR", "MAILCTL_PACKAGED_BIN_DIR")}
                        paths["MAILCTL_CANDIDATE_DIR"] = str(phase_candidate)
                        self.assertEqual(receipt["execution"], dict(argv=argv, env=paths))
                        self.assertEqual(receipt["phase"], phase)
                        self.assertEqual(receipt["context"], CONTEXT)
                        self.assertEqual(receipt["artifact"], candidate.artifact)
                        self.assertEqual(receipt["build_sha256"], evidence.digest(evidence.canonical(build)))
                        actual = next(record for record in candidate.executions() if record["phase"] == phase)
                        self.assertEqual(receipt["execution"], actual["execution"])
                        self.assertEqual(actual["before"], build["candidate"])
                        self.assertEqual(actual["harnesses"], build["harnesses"])
                self.assertEqual([record["phase"] for record in candidate.executions()], expected_order)
                self.assertEqual(candidate.contents(), candidate.prepared)
                candidate.collect()
                candidate.finish()
                candidate.command("verify")
                files = candidate.contents()
                proof = json.loads(files["parallel-acceptance.json"])
                self.assertEqual([receipt["phase"] for receipt in proof["shards"]], list(evidence.phases(target)))
                release.validate_candidate(files, candidate.fixture.source, fixtures.COMMIT, target)
                for name in set(files) - {"parallel-acceptance.json", "SHA256SUMS"}:
                    expected = candidate.fixture.files[name]
                    if name == "windows-source-evidence.txt":
                        expected = evidence.normalized(expected)
                    self.assertEqual(files[name], expected, name)

    def test_group_failure_stops_before_later_phases_and_records_only_success(self):
        cases = [
            (release.MAC, "core", ("installer", "state", "process", "native", "drafts"), "state"),
            (release.LINUX, "core", ("installer", "state", "process", "native", "drafts",
                                     "desktop-credentials", "desktop-drafts"), "desktop-credentials"),
        ]
        for target, group, phases in ((release.LINUX, "reading", ("reading", "desktop-reading")),
                                      (release.WINDOWS, "content", ("reading", "drafts", "wsl"))):
            cases.extend((target, group, phases, phase) for phase in phases)
        for target, group, phases, failed in cases:
            with self.subTest(target=target, group=group, failed=failed):
                candidate = self.prepared(target)
                worker, environment = candidate.group_worker(group)
                environment["MAILCTL_FIXTURE_FAIL_PHASE"] = failed
                candidate.qualify(group, environment, succeeds=False)
                index = phases.index(failed)
                self.assertEqual([record["phase"] for record in candidate.executions()], list(phases[:index + 1]))
                self.assertEqual({path.name for path in (candidate.shards / group).iterdir()}, set(phases[:index]))
                ledgers = [json.loads(path.read_bytes()) for path in worker.rglob("execution.json")]
                self.assertCountEqual([ledger["phase"] for ledger in ledgers], phases[:index])
                for phase in phases[index + 1:]:
                    self.assertFalse((worker / "phases" / phase).exists())
                self.assertEqual(candidate.contents(), candidate.prepared)
                self.assertEqual({path.name: path.read_bytes() for path in (worker / "candidate").iterdir()},
                                 candidate.prepared)

    def test_group_rejects_modified_prepared_and_harness_bytes_before_execution(self):
        for directory, name in (("candidate", "install.sh"), ("harnesses", "fixture-driver")):
            with self.subTest(directory=directory):
                candidate = self.prepared()
                worker, environment = candidate.group_worker("core")
                path = worker / directory / name
                path.write_bytes(path.read_bytes() + b"changed")
                candidate.qualify("core", environment, succeeds=False)
                self.assertEqual(candidate.executions(), [])
                self.assertFalse((candidate.shards / "core").exists())

    def test_group_rejects_prepared_or_harness_mutation_during_a_successful_command(self):
        for mutation in ("prepared", "harness", "phase"):
            with self.subTest(mutation=mutation):
                candidate = self.prepared()
                worker, environment = candidate.group_worker("core")
                environment.update(MAILCTL_FIXTURE_MUTATE_PHASE="installer", MAILCTL_FIXTURE_MUTATE=mutation)
                candidate.qualify("core", environment, succeeds=False)
                self.assertEqual([record["phase"] for record in candidate.executions()], ["installer"])
                self.assertEqual(list((candidate.shards / "core").rglob("receipt.json")), [])
                self.assertFalse((worker / "phases" / "state").exists())
                self.assertEqual(candidate.contents(), candidate.prepared)

    def test_group_rejects_unknown_platform_groups_without_running_commands(self):
        for target, group in ((release.MAC, "state-native"), (release.LINUX, "desktop-credentials"),
                              (release.WINDOWS, "state-native"), (release.WINDOWS, "reading"),
                              (release.MAC, "drafts"), (release.LINUX, "desktop-reading"),
                              (release.LINUX, "desktop-drafts"), (release.MAC, "unknown")):
            with self.subTest(target=target, group=group):
                candidate = self.prepared(target)
                _, environment = candidate.group_worker(group)
                candidate.qualify(group, environment, succeeds=False)
                self.assertEqual(candidate.executions(), [])
                self.assertFalse((candidate.shards / group).exists())

    def test_group_rejects_stale_output_and_repeated_qualification(self):
        for problem in ("evidence", "working", "repeat"):
            with self.subTest(problem=problem):
                candidate = self.prepared()
                worker, environment = candidate.group_worker("core")
                if problem == "repeat":
                    candidate.qualify("core", environment)
                else:
                    stale = (candidate.shards / "core" if problem == "evidence"
                             else worker / "phases" / "state" / "candidate")
                    stale.mkdir(parents=True)
                    (stale / "stale.log").write_bytes(b"previous attempt")
                before = candidate.executions()
                retained = {path: path.read_bytes() for path in candidate.shards.rglob("*") if path.is_file()}
                candidate.qualify("core", environment, succeeds=False)
                self.assertEqual(candidate.executions(), before)
                self.assertEqual({path: path.read_bytes() for path in candidate.shards.rglob("*") if path.is_file()},
                                 retained)
                self.assertEqual(candidate.contents(), candidate.prepared)

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

    def test_collect_rejects_mixed_or_unexpected_grouped_artifact_nesting(self):
        candidate = self.prepared()
        candidate.record_all()
        flat = candidate.root / "flat-shards"
        candidate.shards.rename(flat)
        candidate.shards.mkdir()
        for group, phases in evidence.acceptance_groups(candidate.target).items():
            folder = candidate.shards / group
            folder.mkdir()
            for phase in phases:
                (flat / phase).rename(folder / phase)
        valid = candidate.root / "valid-grouped-shards"
        shutil.copytree(candidate.shards, valid)
        for problem in ("mixed", "missing", "unexpected", "deep", "symlink", "phase-name", "payload"):
            with self.subTest(problem=problem):
                shutil.rmtree(candidate.shards)
                shutil.copytree(valid, candidate.shards)
                shutil.rmtree(candidate.candidate)
                candidate.candidate.mkdir()
                candidate.put(candidate.candidate, candidate.prepared)
                core = candidate.shards / "core"
                state = core / "state"
                if problem == "mixed":
                    (candidate.shards / "reading" / "reading").rename(candidate.shards / "legacy-reading")
                    (candidate.shards / "reading").rmdir()
                elif problem == "missing":
                    shutil.rmtree(state)
                elif problem == "unexpected":
                    (core / "stale.log").write_bytes(b"previous attempt")
                elif problem == "deep":
                    nested = candidate.root / "nested-state"
                    state.rename(nested)
                    state.mkdir()
                    nested.rename(state / "extra")
                elif problem == "symlink":
                    outside = candidate.root / "outside-state"
                    state.rename(outside)
                    state.symlink_to(outside, target_is_directory=True)
                elif problem == "phase-name":
                    saved = candidate.root / "swapped-state"
                    state.rename(saved)
                    (core / "process").rename(state)
                    saved.rename(core / "process")
                else:
                    log = state / "installed-state-acceptance.log"
                    log.write_bytes(log.read_bytes() + b"changed")
                candidate.collect(succeeds=False)
                self.assertFalse((candidate.candidate / "parallel-acceptance.json").exists())
                self.assertEqual(candidate.contents(), candidate.prepared)

    def test_collect_rejects_missing_reading_and_content_groups_or_their_phase_receipts(self):
        for target, group, phases in ((release.LINUX, "reading", ("reading", "desktop-reading")),
                                      (release.WINDOWS, "content", ("reading", "drafts", "wsl"))):
            candidate = self.prepared(target)
            candidate.record_all()
            flat = candidate.root / "flat-shards"
            candidate.shards.rename(flat)
            candidate.shards.mkdir()
            for name, members in evidence.acceptance_groups(target).items():
                folder = candidate.shards / name
                folder.mkdir()
                for phase in members:
                    (flat / phase).rename(folder / phase)
            for missing in (None, *phases):
                with self.subTest(target=target, group=group, missing=missing):
                    folder = candidate.shards / group
                    path = folder if missing is None else folder / missing
                    saved = candidate.root / "missing-evidence"
                    path.rename(saved)
                    message = ("Missing or duplicate acceptance shard" if missing is None
                               else "Acceptance group has missing or unexpected phases")
                    candidate.collect(succeeds=False, message=message)
                    self.assertEqual(candidate.contents(), candidate.prepared)
                    saved.rename(path)

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
