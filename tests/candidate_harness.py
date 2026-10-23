#!/usr/bin/env python3
"""Exercise portable candidate harness staging with an offline fake compiler."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/ci/candidate-harness.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("candidate_harness", HELPER)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)
UNIX_TARGETS = {
    "administration_process", "state_maintenance", "mcp_process", "message_process",
    "attachment_process", "search_process", "discovery_process", "read_contention_process",
    "draft_process", "native_credentials", "packaged_reading", "packaged_drafts",
}
LINUX_TARGETS = {
    "linux_credentials", "systemd_native", "systemd_credentials", "secret_service_credentials",
}


class PortableHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mailctl-harness-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.cache = self.root / "build-cache"
        self.directory = self.root / "harnesses"
        self.candidate = self.root / "candidate"
        self.installed = self.root / "installed"
        self.launchers = self.root / "bin"
        for directory in (self.cache, self.candidate, self.installed, self.launchers):
            directory.mkdir()
        self.trace = self.root / "runs.jsonl"
        self.compiler_trace = self.root / "compiler.json"
        self.artifacts = self.root / "compiler-artifacts.json"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("MAILCTL_", "CARGO_", "FIXTURE_"))}
        self.env.update(
            PATH=str(self.launchers), CARGO_TARGET_DIR=str(self.cache),
            MAILCTL_TARGET="x86_64-unknown-linux-gnu",
            MAILCTL_CANDIDATE_DIR=str(self.candidate),
            MAILCTL_HARNESS_DIR=str(self.directory),
            MAILCTL_PACKAGED_BIN_DIR=str(self.installed),
            FIXTURE_TRACE=str(self.trace), FIXTURE_COMPILER_TRACE=str(self.compiler_trace),
            FIXTURE_ARTIFACTS=str(self.artifacts),
        )
        self.write_executable(self.launchers / "cargo", '''
import json, os, pathlib, sys
pathlib.Path(os.environ["FIXTURE_COMPILER_TRACE"]).write_text(json.dumps(sys.argv[1:]))
for artifact in json.loads(pathlib.Path(os.environ["FIXTURE_ARTIFACTS"]).read_text()):
    print(json.dumps(artifact))
sys.exit(int(os.environ.get("FIXTURE_COMPILER_EXIT", "0")))
''')
        artifacts = []
        for name in sorted(UNIX_TARGETS | LINUX_TARGETS):
            executable = self.cache / f"built-{name}"
            self.write_executable(executable, f'''
import json, os, pathlib, sys
record = {{"name": {name!r}, "arguments": sys.argv[1:],
          "installed": os.environ.get("MAILCTL_PACKAGED_BIN_DIR")}}
with pathlib.Path(os.environ["FIXTURE_TRACE"]).open("a") as trace:
    trace.write(json.dumps(record) + "\\n")
sys.exit(int(os.environ.get("FIXTURE_HARNESS_EXIT", "0")))
''')
            artifacts.append(self.artifact(name, executable))
            # Cargo's workspace stream may contain identically named targets
            # from other packages. Those executables must never be selected.
            artifacts.append(self.artifact(name, self.cache / "wrong-driver",
                                           ROOT / "tests/process-driver/tests" / f"{name}.rs"))
        self.artifacts.write_text(json.dumps(artifacts))

    @staticmethod
    def write_executable(path, contents):
        path.write_text(f"#!{sys.executable}\n" + contents, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def artifact(name, executable, source=None):
        return {"reason": "compiler-artifact", "executable": str(executable),
                "target": {"name": name, "kind": ["test"],
                           "src_path": str(source or ROOT / "tests" / f"{name}.rs")}}

    def command(self, *arguments, succeeds=True):
        result = subprocess.run([sys.executable, str(HELPER), *arguments], env=self.env,
                                text=True, capture_output=True, timeout=30)
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def prepare(self, target="x86_64-unknown-linux-gnu"):
        self.env["MAILCTL_TARGET"] = target
        self.command("prepare")
        return json.loads((self.directory / harness.MANIFEST).read_text())

    def relocate(self):
        self.prepare()
        downloaded = self.root / "downloaded harnesses"
        self.directory.rename(downloaded)
        self.directory = downloaded
        self.env["MAILCTL_HARNESS_DIR"] = str(downloaded)
        for executable in downloaded.iterdir():
            executable.chmod(0o644)
        shutil.rmtree(self.cache)
        shutil.rmtree(self.launchers)

    def test_linux_stages_only_root_harnesses_and_all_acceptance_targets(self):
        manifest = self.prepare()
        expected = UNIX_TARGETS | LINUX_TARGETS
        self.assertEqual(set(manifest["harnesses"]), expected)
        self.assertEqual(set(path.name for path in self.directory.iterdir()),
                         {harness.MANIFEST} | set(manifest["harnesses"].values()))
        command = json.loads(self.compiler_trace.read_text())
        self.assertEqual(command[:9], ["test", "--locked", "--workspace", "--no-default-features",
                                       "--features", "cli,mcp", "--target",
                                       "x86_64-unknown-linux-gnu", "--test"])
        self.assertEqual(command[-2:], ["--no-run", "--message-format=json"])
        self.assertEqual({command[index + 1] for index, value in enumerate(command)
                          if value == "--test"}, expected)
        self.assertEqual(manifest["build_command"], ["cargo", *command])
        for name, filename in manifest["harnesses"].items():
            self.assertEqual(Path(filename).name, filename)
            staged = self.directory / filename
            self.assertEqual(staged.read_bytes(), (self.cache / f"built-{name}").read_bytes())
            self.assertTrue(os.access(staged, os.X_OK))
        self.assertEqual(list(self.candidate.iterdir()), [])

    def test_macos_omits_linux_only_targets(self):
        manifest = self.prepare("aarch64-apple-darwin")
        self.assertEqual(set(manifest["harnesses"]), UNIX_TARGETS)
        command = json.loads(self.compiler_trace.read_text())
        self.assertIn("aarch64-apple-darwin", command)
        for name in LINUX_TARGETS:
            self.assertNotIn(name, command)

    def test_relocated_artifacts_restore_permissions_without_cargo_or_build_tree(self):
        self.relocate()
        result = self.command("artifacts", "--test", "systemd_native",
                              "--test", "secret_service_credentials")
        artifacts = json.loads(result.stdout)
        self.assertEqual(set(artifacts), {"systemd_native", "secret_service_credentials"})
        for path in artifacts.values():
            self.assertEqual(Path(path).parent, self.directory)
            self.assertTrue(os.access(path, os.X_OK))
        self.assertFalse(self.trace.exists())

    def test_relocated_run_preserves_installed_candidate_filter_flags_and_order(self):
        self.relocate()
        self.command("run", "--test", "packaged_reading", "--test", "packaged_drafts",
                     "cli_", "--", "--nocapture", "--test-threads=1")
        records = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual([record["name"] for record in records],
                         ["packaged_reading", "packaged_drafts"])
        for record in records:
            self.assertEqual(record["installed"], str(self.installed))
            self.assertEqual(record["arguments"], ["cli_", "--nocapture", "--test-threads=1"])

    def test_harness_failure_stops_remaining_targets_and_propagates_exit_status(self):
        self.prepare()
        self.env["FIXTURE_HARNESS_EXIT"] = "19"
        result = self.command("run", "--test", "administration_process", "--test",
                              "state_maintenance", succeeds=False)
        self.assertEqual(result.returncode, 19)
        self.assertEqual(len(self.trace.read_text().splitlines()), 1)

    def test_candidate_bootstrap_state_and_process_work_without_cargo(self):
        self.relocate()
        self.launchers.mkdir()
        for command in ("dirname", "tee"):
            (self.launchers / command).symlink_to(shutil.which(command))
        installer_trace = self.root / "installer.json"
        self.env["FIXTURE_INSTALLER_TRACE"] = str(installer_trace)
        self.write_executable(self.launchers / "python3", '''
import json, os, pathlib, sys
if sys.argv[1] == "tests/installer.py":
    pathlib.Path(os.environ["FIXTURE_INSTALLER_TRACE"]).write_text(json.dumps(sys.argv[2:]))
else:
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
''')
        script = ROOT / "scripts/ci/candidate.sh"
        for phase in ("bootstrap", "state", "process"):
            result = subprocess.run(["/bin/bash", str(script), phase], env=self.env,
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(installer_trace.read_text()),
                         ["--artifacts", str(self.candidate), "--install-only", "--reuse",
                          "--components", "cli,mcp", "--install-to", str(self.installed)])
        self.assertEqual([json.loads(line)["name"] for line in self.trace.read_text().splitlines()],
                         ["administration_process", "state_maintenance", "mcp_process",
                          "message_process", "attachment_process", "search_process",
                          "discovery_process", "read_contention_process", "draft_process"])
        self.assertTrue((self.candidate / "installed-state-acceptance.log").is_file())
        self.assertTrue((self.candidate / "installed-process-acceptance.log").is_file())

    def test_failed_compiler_cannot_publish_or_reuse_successful_manifest(self):
        self.prepare()
        self.env["FIXTURE_COMPILER_EXIT"] = "42"
        self.command("prepare", succeeds=False)
        self.assertFalse((self.directory / harness.MANIFEST).exists())
        self.command("artifacts", "--test", "state_maintenance", succeeds=False)

    def test_missing_or_ambiguous_root_target_rejects_entire_preparation(self):
        original = json.loads(self.artifacts.read_text())
        for artifacts in (original[1:], original + [original[0]]):
            with self.subTest(artifacts=len(artifacts)):
                self.artifacts.write_text(json.dumps(artifacts))
                self.command("prepare", succeeds=False)
                self.assertFalse((self.directory / harness.MANIFEST).exists())
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_staged_run_requires_an_absolute_installed_candidate_directory(self):
        self.prepare()
        for installed in (None, "relative/bin", str(self.root / "missing")):
            with self.subTest(installed=installed):
                if installed is None:
                    self.env.pop("MAILCTL_PACKAGED_BIN_DIR", None)
                else:
                    self.env["MAILCTL_PACKAGED_BIN_DIR"] = installed
                self.command("run", "--test", "state_maintenance", succeeds=False)
                self.assertFalse(self.trace.exists())

    def test_preparation_requires_separate_absolute_harness_tree_outside_cache(self):
        for directory in ("relative", self.cache / "harnesses", self.candidate / "harnesses"):
            with self.subTest(directory=directory):
                self.env["MAILCTL_HARNESS_DIR"] = str(directory)
                self.command("prepare", succeeds=False)
                self.assertFalse(self.compiler_trace.exists())

    def test_artifacts_reject_unsafe_filenames_symlinks_and_wrong_platform(self):
        manifest = self.prepare()
        path = self.directory / harness.MANIFEST
        for filename in ("../outside", str(self.cache / "built-state_maintenance")):
            with self.subTest(filename=filename):
                manifest["harnesses"]["state_maintenance"] = filename
                path.write_text(json.dumps(manifest))
                self.command("artifacts", "--test", "state_maintenance", succeeds=False)
        link = self.directory / "linked-test"
        link.symlink_to(self.cache / "built-state_maintenance")
        manifest["harnesses"]["state_maintenance"] = link.name
        path.write_text(json.dumps(manifest))
        self.command("artifacts", "--test", "state_maintenance", succeeds=False)
        self.env["MAILCTL_TARGET"] = "aarch64-apple-darwin"
        self.command("artifacts", "--test", "packaged_reading", succeeds=False)


if __name__ == "__main__":
    unittest.main()
