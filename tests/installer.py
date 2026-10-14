#!/usr/bin/env python3
"""Exercise the standalone installer using disposable downloads and state.

Run fixture checks with ``python3 tests/installer.py``. Add ``--artifacts DIR``
to qualify real packaged binaries on macOS Apple Silicon. ``--install-to DIR``
leaves a fresh combined installation for the packaged Rust acceptance suites.
Only Python's standard library and the installer's documented system tools are
used; every download is served from a temporary loopback HTTP server.
"""

import argparse
from contextlib import closing
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = "aarch64-apple-darwin"
COMPONENTS = {"cli": "mailctl", "mcp": "mailctl-mcp"}
ARTIFACTS = None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_manifest(directory):
    manifests = list(directory.glob(f"manifest-v*-{TARGET}.txt"))
    if len(manifests) != 1:
        raise AssertionError("artifact directory must contain one candidate manifest")
    return dict(line.split("=", 1) for line in manifests[0].read_text().splitlines())


def tree_bytes(directory):
    """Record user-visible bytes, excluding volatile lock files."""
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file() and not path.name.endswith(".lock")
    }


class DownloadServer:
    def __init__(self, directory):
        self.directory = directory
        self.requests = []
        self.block_path = None
        self.blocked = threading.Event()
        self.release = threading.Event()
        owner = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(owner.directory), **kwargs)

            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.requests.append(self.path)
                if self.path == owner.block_path:
                    owner.blocked.set()
                    if not owner.release.wait(20):
                        return
                try:
                    super().do_GET()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.http.server_port}"
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=5)


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mailctl-installer-")
        self.directory = Path(self.temporary.name).resolve()
        self.home = self.directory / "home with spaces"
        self.home.mkdir(mode=0o700)
        self.downloads = self.directory / "downloads"
        self.downloads.mkdir()
        self.tools = self.directory / "system tools"
        self.tools.mkdir()
        # Fixture scenarios exercise installation semantics independently of the
        # development host. Real artifact checks use the actual native platform.
        uname = self.tools / "uname"
        uname.write_text('#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; *) exit 1;; esac\n')
        uname.chmod(0o755)
        self.env = {
            "HOME": str(self.home),
            "PATH": f"{self.tools}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(self.directory),
            "LC_ALL": "C",
        }
        self.version = "0.1.0"
        self.installer = ROOT / "install.sh"
        self.publish_fixture(self.version)
        self.server = DownloadServer(self.downloads)
        self.bin = self.home / ".cargo" / "bin"

    def tearDown(self):
        self.server.close()
        self.temporary.cleanup()

    def publish_fixture(self, version, commit="a" * 40, compatibility="1"):
        manifest = {
            "format": "1",
            "version": version,
            "target": TARGET,
            "commit": commit,
            "compatibility": compatibility,
        }
        for selection, component in COMPONENTS.items():
            name = f"{component}-v{version}-{TARGET}"
            path = self.downloads / name
            path.write_text(
                f"#!/bin/sh\n"
                f"if [ \"$1\" = --version ]; then printf '%s\\n' '{component} {version}'; exit 0; fi\n"
                "printf '%s\\n' '{\"ok\":true,\"result\":{}}'\n"
            )
            path.chmod(0o755)
            manifest[f"{selection}_file"] = name
            manifest[f"{selection}_sha256"] = digest(path)
            manifest[f"{selection}_size"] = str(path.stat().st_size)
            manifest[f"{selection}_signing"] = "unsigned"
        self.write_manifest(manifest)
        shutil.copy2(ROOT / "install.sh", self.downloads / f"install-v{version}.sh")
        return manifest

    def write_manifest(self, manifest):
        path = self.downloads / f"manifest-v{manifest['version']}-{TARGET}.txt"
        path.write_text("".join(f"{key}={value}\n" for key, value in manifest.items()))
        return path

    def command(self, *args, version=None, env=None, **kwargs):
        command = [
            "/bin/sh", str(self.installer),
            "--version", version or self.version,
            "--base-url", self.server.url,
            *map(str, args),
        ]
        return subprocess.run(command, env=env or self.env, capture_output=True,
                              text=True, timeout=30, **kwargs)

    def successful(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def installed(self, components, directory=None):
        directory = directory or self.bin
        for selection, component in COMPONENTS.items():
            path = directory / component
            self.assertEqual(path.is_file(), selection in components, str(path))
            if selection in components:
                self.assertTrue(os.access(path, os.X_OK), str(path))
                self.assertEqual(path.read_bytes(), (self.downloads /
                    f"{component}-v{self.version}-{TARGET}").read_bytes())

    def test_default_install_is_combined_and_needs_no_rust(self):
        self.assertIsNone(shutil.which("cargo", path=self.env["PATH"]))
        self.assertIsNone(shutil.which("rustup", path=self.env["PATH"]))
        result = self.command()
        self.successful(result)
        self.installed({"cli", "mcp"})
        self.assertIn(str(self.bin), result.stdout + result.stderr)

    def test_each_selection_is_independent_and_addition_preserves_sibling(self):
        for selected in ("cli", "mcp"):
            with self.subTest(selected=selected):
                self.version = "0.1.0"
                self.publish_fixture(self.version)
                directory = self.directory / selected
                self.successful(self.command("--components", selected, "--install-dir", directory))
                self.installed({selected}, directory)
                sibling = "mcp" if selected == "cli" else "cli"
                previous = (directory / COMPONENTS[selected]).read_bytes()
                self.version = "0.2.0"
                candidate = self.publish_fixture(self.version, commit="b" * 40)
                self.successful(self.command("--components", selected, "--install-dir", directory))
                self.installed({selected}, directory)
                self.assertNotEqual((directory / COMPONENTS[selected]).read_bytes(), previous)
                receipt = dict(line.split("=", 1) for line in
                               (directory / ".mailctl-components").read_text().splitlines())
                self.assertEqual(receipt[f"{selected}_version"], self.version)
                self.assertEqual(receipt[f"{selected}_commit"], candidate["commit"])
                self.assertEqual(receipt[f"{selected}_sha256"], candidate[f"{selected}_sha256"])
                self.assertNotIn(f"{sibling}_version", receipt)
                before = (directory / COMPONENTS[selected]).read_bytes()
                self.successful(self.command("--components", sibling, "--install-dir", directory))
                self.installed({"cli", "mcp"}, directory)
                self.assertEqual((directory / COMPONENTS[selected]).read_bytes(), before)
                self.successful(self.command("--uninstall", "--components", selected,
                                             "--install-dir", directory))
                self.installed({sibling}, directory)

    def test_cargo_home_and_explicit_paths_with_spaces_preserve_shared_tools(self):
        cargo = self.directory / "custom cargo home"
        (cargo / "bin").mkdir(parents=True)
        sentinels = {
            cargo / ".crates.toml": b"foreign cargo metadata\n",
            cargo / ".crates2.json": b"foreign cargo metadata JSON\n",
            cargo / "bin" / "rustup": b"unrelated rustup binary\n",
            cargo / "bin" / "cargo": b"unrelated cargo binary\n",
        }
        for path, content in sentinels.items():
            path.write_bytes(content)
        env = dict(self.env, CARGO_HOME=str(cargo))
        self.successful(self.command(env=env))
        self.installed({"cli", "mcp"}, cargo / "bin")
        explicit = self.directory / "explicit application binaries"
        self.successful(self.command("--install-dir", explicit, env=env))
        self.installed({"cli", "mcp"}, explicit)
        self.successful(self.command("--uninstall", env=env))
        self.successful(self.command("--uninstall", "--install-dir", explicit, env=env))
        for path, content in sentinels.items():
            self.assertEqual(path.read_bytes(), content)

    def test_curl_pipeline_installs_the_downloaded_script(self):
        curl = subprocess.run(["/usr/bin/curl", "-fsSL",
            f"{self.server.url}/install-v{self.version}.sh"], capture_output=True,
            check=True, timeout=10, env=self.env)
        result = subprocess.run(["/bin/sh", "-s", "--", "--version", self.version,
            "--base-url", self.server.url], input=curl.stdout, capture_output=True,
            timeout=30, env=self.env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.installed({"cli", "mcp"})

    def test_foreign_files_directories_and_symlinks_are_never_replaced(self):
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                directory = self.directory / kind
                directory.mkdir()
                destination = directory / "mailctl"
                foreign = self.directory / "foreign-owned-file"
                foreign.write_bytes(b"foreign installation\n")
                if kind == "file":
                    destination.write_bytes(foreign.read_bytes())
                elif kind == "directory":
                    destination.mkdir()
                else:
                    destination.symlink_to(foreign)
                self.failed(self.command("--install-dir", directory))
                self.assertEqual(foreign.read_bytes(), b"foreign installation\n")
                self.assertFalse((directory / "mailctl-mcp").exists())
                self.assertEqual(destination.is_symlink(), kind == "symlink")
                if kind == "file":
                    self.assertEqual(destination.read_bytes(), foreign.read_bytes())

    def test_repeat_install_and_uninstall_preserve_application_state(self):
        state = self.home / "Library" / "Application Support" / "mailctl" / "state"
        state.mkdir(parents=True)
        sentinel = state / "history.json"
        sentinel.write_bytes(b"opaque installation history\n")
        self.successful(self.command())
        before = tree_bytes(self.bin)
        self.successful(self.command())
        self.assertEqual(tree_bytes(self.bin), before)
        self.successful(self.command("--uninstall"))
        self.assertFalse((self.bin / "mailctl").exists())
        self.assertFalse((self.bin / "mailctl-mcp").exists())
        self.assertEqual(sentinel.read_bytes(), b"opaque installation history\n")

    def test_checksum_size_missing_download_and_manifest_failures_are_atomic(self):
        self.successful(self.command())
        before = tree_bytes(self.bin)
        for defect in ("checksum", "size", "missing", "schema", "filename", "duplicate"):
            with self.subTest(defect=defect):
                manifest = self.publish_fixture("0.2.0", commit="b" * 40)
                path = self.downloads / manifest["mcp_file"]
                if defect == "checksum":
                    path.write_bytes(path.read_bytes() + b"tampered\n")
                    manifest["mcp_size"] = str(path.stat().st_size)
                elif defect == "size":
                    manifest["mcp_size"] = str(path.stat().st_size + 1)
                elif defect == "missing":
                    path.unlink()
                elif defect == "schema":
                    manifest["compatibility"] = "2"
                elif defect == "filename":
                    manifest["mcp_file"] = "../../foreign"
                self.write_manifest(manifest)
                if defect == "duplicate":
                    with self.write_manifest(manifest).open("a") as output:
                        output.write("version=9.9.9\n")
                self.failed(self.command(version="0.2.0"))
                self.assertEqual(tree_bytes(self.bin), before)

    def test_partial_upgrade_rejects_mixed_versions_or_commits(self):
        self.successful(self.command())
        before = tree_bytes(self.bin)
        self.publish_fixture("0.2.0", commit="b" * 40)
        self.failed(self.command("--components", "cli", version="0.2.0"))
        self.assertEqual(tree_bytes(self.bin), before)
        self.publish_fixture("0.1.0", commit="b" * 40)
        self.failed(self.command("--components", "mcp"))
        self.assertEqual(tree_bytes(self.bin), before)
        self.successful(self.command(version="0.2.0"))
        self.version = "0.2.0"
        self.installed({"cli", "mcp"})

    def test_modified_owned_binary_is_not_overwritten_or_uninstalled(self):
        self.successful(self.command())
        binary = self.bin / "mailctl"
        binary.write_bytes(b"replacement by another installation channel\n")
        before = tree_bytes(self.bin)
        self.failed(self.command())
        self.assertEqual(tree_bytes(self.bin), before)
        self.failed(self.command("--uninstall"))
        self.assertEqual(tree_bytes(self.bin), before)

    def test_interrupted_download_leaves_prior_installation_usable(self):
        self.successful(self.command())
        before = tree_bytes(self.bin)
        manifest = self.publish_fixture("0.2.0", commit="b" * 40)
        self.server.block_path = f"/{manifest['mcp_file']}"
        command = ["/bin/sh", str(ROOT / "install.sh"), "--version", "0.2.0",
                   "--base-url", self.server.url]
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            self.assertTrue(self.server.blocked.wait(10), "download did not start")
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
        finally:
            self.server.release.set()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
        self.assertEqual(tree_bytes(self.bin), before)
        self.successful(self.command(version="0.2.0"))
        self.version = "0.2.0"
        self.installed({"cli", "mcp"})

    def test_replacement_failure_rolls_back_binaries_and_manifest(self):
        self.successful(self.command())
        before = tree_bytes(self.bin)
        self.publish_fixture("0.2.0", commit="b" * 40)
        wrapper = self.tools / "mv"
        wrapper.write_text(
            '#!/bin/sh\ncase "$*" in *download/mailctl-mcp*) exit 70;; esac\n'
            'exec /bin/mv "$@"\n'
        )
        wrapper.chmod(0o755)
        self.failed(self.command(version="0.2.0"))
        self.assertEqual(tree_bytes(self.bin), before)
        wrapper.unlink()
        self.successful(self.command(version="0.2.0"))

    def test_killed_partial_update_is_serialized_and_explicitly_recovered(self):
        self.successful(self.command())
        before = tree_bytes(self.bin)
        self.publish_fixture("0.2.0", commit="b" * 40)
        marker = self.directory / "replacement-held"
        wrapper = self.tools / "mv"
        wrapper.write_text(
            '#!/bin/sh\ncase "$*" in *download/mailctl-mcp*)\n'
            '  : >"$MAILCTL_TEST_REPLACEMENT_MARKER"\n'
            '  while :; do /bin/sleep 1; done;;\nesac\n'
            'exec /bin/mv "$@"\n'
        )
        wrapper.chmod(0o755)
        command = ["/bin/sh", str(ROOT / "install.sh"), "--version", "0.2.0",
                   "--base-url", self.server.url]
        process = subprocess.Popen(command, env=dict(self.env,
            MAILCTL_TEST_REPLACEMENT_MARKER=str(marker)), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while not marker.exists() and time.monotonic() < deadline:
                self.assertIsNone(process.poll(), "installer exited before second replacement")
                time.sleep(0.02)
            self.assertTrue(marker.exists(), "second component replacement did not begin")
            self.assertNotEqual((self.bin / "mailctl").read_bytes(), before["mailctl"])
            self.assertEqual((self.bin / "mailctl-mcp").read_bytes(), before["mailctl-mcp"])
            self.failed(self.command(version="0.2.0"))
            self.failed(self.command("--recover"))
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            wrapper.unlink()
        self.failed(self.command(version="0.2.0"))
        self.successful(self.command("--recover"))
        self.assertEqual(tree_bytes(self.bin), before)
        self.successful(self.command(version="0.2.0"))
        self.version = "0.2.0"
        self.installed({"cli", "mcp"})

    def test_remote_plain_http_and_unknown_options_are_rejected(self):
        for arguments in (("--base-url", "http://example.test/releases"),
                          ("--components", "broker"), ("--unknown",),
                          ("--version", "../../0.1.0")):
            with self.subTest(arguments=arguments):
                self.failed(self.command(*arguments))
                self.assertFalse((self.bin / "mailctl").exists())

    def test_unsupported_platform_is_rejected_before_download_or_install(self):
        (self.tools / "uname").write_text("#!/bin/sh\necho unsupported\n")
        result = self.command()
        self.failed(result)
        self.assertIn("macOS Apple Silicon", result.stderr)
        self.assertFalse(self.bin.exists())
        self.assertEqual(self.server.requests, [])


class PackagedInstallerTest(InstallerTest):
    """Acceptance at the public installed executable boundary."""

    def setUp(self):
        if ARTIFACTS is None:
            self.skipTest("supply --artifacts DIR to qualify packaged binaries")
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            self.fail("packaged candidate acceptance requires macOS Apple Silicon")
        super().setUp()
        shutil.rmtree(self.downloads)
        shutil.copytree(ARTIFACTS, self.downloads)
        self.manifest = read_manifest(self.downloads)
        self.version = self.manifest["version"]
        self.installer = self.downloads / f"install-v{self.version}.sh"
        self.env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        self.config = self.directory / "operator configuration" / "config.toml"

    def test_packaged_dist_archive_matches_installed_bytes(self):
        archive_path = self.downloads / f"mailctl-{TARGET}.tar.gz"
        build = json.loads((self.downloads / "dist-manifest.json").read_text())
        artifact = build["artifacts"][archive_path.name]
        self.assertEqual(digest(archive_path), artifact["checksums"]["sha256"])
        self.assertEqual({asset["name"] for asset in artifact["assets"]
                          if asset["kind"] == "executable"}, set(COMPONENTS.values()))
        self.successful(self.command())
        with tarfile.open(archive_path, "r:gz") as archive:
            for component, binary in COMPONENTS.items():
                member = next(m for m in archive.getmembers() if Path(m.name).name == binary)
                with archive.extractfile(member) as reader:
                    archived = reader.read()
                self.assertEqual(archived, (self.bin / binary).read_bytes())
                self.assertEqual(hashlib.sha256(archived).hexdigest(),
                                 self.manifest[f"{component}_sha256"])

    def test_packaged_adapter_rejects_corrupt_dist_archive(self):
        manifest_path = self.downloads / "dist-manifest.json"
        build = json.loads(manifest_path.read_text())
        for artifact in build["artifacts"].values():
            artifact["path"] = str(self.downloads / artifact["name"])
        manifest_path.write_text(json.dumps(build))
        archive_path = self.downloads / f"mailctl-{TARGET}.tar.gz"
        with archive_path.open("ab") as archive:
            archive.write(b"corruption")
        output = self.directory / "rejected-candidate"
        result = subprocess.run(["python3", str(ROOT / "scripts/prepare-installer.py"),
            "--manifest", str(manifest_path), "--output", str(output), "--allow-dirty"],
            capture_output=True, text=True, timeout=30)
        self.failed(result)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(output.exists())

    def invoke(self, binary, *arguments):
        result = subprocess.run([str(binary), "--config", str(self.config),
                                 "--json", "--log-format", "off", *arguments],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.successful(result)
        envelope = json.loads(result.stdout)
        self.assertTrue(envelope["ok"], result.stdout)
        return envelope["result"]

    def setup_accounts(self, binary):
        for alias in ("work", "personal"):
            self.invoke(binary, "setup", "--alias", alias,
                        "--server", "imap.example.test", "--username", f"{alias}@example.test")
        result = self.invoke(binary, "setup")
        self.assertEqual(result["accounts"], 2)
        return result["installation_id"]

    def discover_mcp(self, binary, while_running=None):
        process = subprocess.Popen([str(binary), "--config", str(self.config),
            "--log-format", "off"], env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        incoming = queue.Queue()

        def read_lines():
            for line in process.stdout:
                incoming.put(line)
            incoming.put(None)

        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()

        def send(message):
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()

        def receive(identifier):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                line = incoming.get(timeout=max(0.1, deadline - time.monotonic()))
                self.assertIsNotNone(line, "MCP closed its protocol stream")
                response = json.loads(line)
                if response.get("id") == identifier:
                    self.assertNotIn("error", response, response)
                    return response["result"]
            self.fail("MCP response deadline")

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "mailctl-installer-acceptance", "version": "1"}}})
            receive(1)
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "email_list_accounts", "arguments": {}}})
            response = receive(2)
            envelope = response["structuredContent"]
            self.assertTrue(envelope["ok"], envelope)
            if while_running is not None:
                while_running()
            return envelope["result"]
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            stderr = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "", stderr)

    def test_packaged_components_setup_two_accounts_and_preserve_shared_state(self):
        for selected in ("cli", "mcp", "cli,mcp"):
            for removed in ("cli", "mcp"):
                with self.subTest(components=selected, removed=removed):
                    scenario = f"{selected} remove {removed}"
                    directory = self.directory / f"installed {scenario}"
                    self.config = self.directory / f"configuration {scenario}" / "config.toml"
                    self.successful(self.command("--components", selected,
                                                 "--install-dir", directory))
                    self.installed(set(selected.split(",")), directory)
                    first = directory / ("mailctl" if "cli" in selected else "mailctl-mcp")
                    installation_id = self.setup_accounts(first)
                    accounts = (self.invoke(first, "account", "list") if first.name == "mailctl"
                                else self.discover_mcp(first))
                    self.assertEqual({account["alias"] for account in accounts["accounts"]},
                                     {"work", "personal"})
                    state_before = tree_bytes(self.config.parent)
                    binaries_before = tree_bytes(directory)
                    self.successful(self.command("--components", selected,
                                                 "--install-dir", directory,
                                                 "--config", self.config))
                    self.installed(set(selected.split(",")), directory)
                    self.assertEqual(tree_bytes(directory), binaries_before)
                    self.assertEqual(tree_bytes(self.config.parent), state_before)
                    self.assertEqual((self.invoke(first, "account", "list")
                                      if first.name == "mailctl" else self.discover_mcp(first)),
                                     accounts)
                    self.successful(self.command("--install-dir", directory,
                                                 "--config", self.config))
                    self.installed({"cli", "mcp"}, directory)
                    self.assertEqual(tree_bytes(self.config.parent), state_before)
                    self.assertEqual(self.invoke(directory / "mailctl", "account", "list"), accounts)
                    self.assertEqual(self.discover_mcp(directory / "mailctl-mcp"), accounts)
                    for component in COMPONENTS.values():
                        self.assertEqual(self.invoke(directory / component, "setup")["installation_id"],
                                         installation_id)
                    self.successful(self.command("--uninstall", "--components", removed,
                                                 "--install-dir", directory))
                    survivor = "mcp" if removed == "cli" else "cli"
                    self.installed({survivor}, directory)
                    binary = directory / COMPONENTS[survivor]
                    self.assertEqual((self.invoke(binary, "account", "list")
                                      if survivor == "cli" else self.discover_mcp(binary)), accounts)
                    self.assertEqual(tree_bytes(self.config.parent), state_before)
                    self.successful(self.command("--uninstall", "--components", survivor,
                                                 "--install-dir", directory))
                    self.installed(set(), directory)
                    self.assertEqual(tree_bytes(self.config.parent), state_before)

    def test_packaged_upgrade_preflight_rejects_unknown_config_and_state(self):
        self.successful(self.command())
        self.setup_accounts(self.bin / "mailctl")
        binaries_before = tree_bytes(self.bin)
        self.failed(self.command("--config", self.directory / "missing-config.toml"))
        self.assertEqual(tree_bytes(self.bin), binaries_before)
        original = self.config.read_bytes()
        self.config.write_bytes(b"unknown_field = true\n" + original)
        rejected_state = tree_bytes(self.config.parent)
        self.failed(self.command("--config", self.config))
        self.assertEqual(tree_bytes(self.bin), binaries_before)
        self.assertEqual(tree_bytes(self.config.parent), rejected_state)
        self.config.write_bytes(original)
        accounts_path = self.config.parent / "state" / "accounts.json"
        accounts = json.loads(accounts_path.read_bytes())
        accounts["future_schema_field"] = True
        accounts_path.write_text(json.dumps(accounts))
        rejected_state = tree_bytes(self.config.parent)
        self.failed(self.command("--config", self.config))
        self.assertEqual(tree_bytes(self.bin), binaries_before)
        self.assertEqual(tree_bytes(self.config.parent), rejected_state)

    def test_packaged_compatible_commit_upgrade_preserves_accounts_and_history(self):
        self.successful(self.command())
        installation_id = self.setup_accounts(self.bin / "mailctl")
        original_config = self.config.read_text()
        keys = re.findall(r'^key = "([a-z0-9-]+)"$', original_config, flags=re.MULTILINE)
        self.assertEqual(len(keys), 2)
        # Enabling a separate draft grant initializes actual SQLite history while
        # preserving the operator's default read-only access grant.
        draft_config = original_config.replace("[[accounts]]\n",
            '[[accounts]]\ndrafts_mailbox = "Drafts"\n')
        self.config.write_text(draft_config + '\n[[grants]]\nname = "writer"\n'
            'profile = "read_and_drafts"\naccounts = ' + json.dumps(keys) +
            '\nmailboxes = ["INBOX", "Drafts"]\n')
        self.invoke(self.bin / "mailctl", "setup")
        accounts = self.invoke(self.bin / "mailctl", "account", "list")
        journal = self.config.parent / "state" / "drafts.sqlite"
        self.assertTrue(journal.is_file(), "draft grant must initialize the real journal")
        state_before = tree_bytes(self.config.parent)
        binaries_before = tree_bytes(self.bin)
        manifest = dict(self.manifest)
        manifest["commit"] = "b" * 40 if manifest["commit"] != "b" * 40 else "c" * 40
        self.write_manifest(manifest)
        self.failed(self.command("--components", "cli", "--config", self.config))
        self.assertEqual(tree_bytes(self.bin), binaries_before)
        self.successful(self.command("--config", self.config))
        self.assertEqual(tree_bytes(self.config.parent), state_before)
        self.assertEqual(self.invoke(self.bin / "mailctl", "account", "list"), accounts)
        self.assertEqual(self.discover_mcp(self.bin / "mailctl-mcp"), accounts)
        self.assertEqual(self.invoke(self.bin / "mailctl-mcp", "setup")["installation_id"],
                         installation_id)
        # A connection context commits but does not close; close it before
        # taking the snapshot so WAL/shared-memory bookkeeping has settled.
        with closing(sqlite3.connect(journal)) as connection:
            with connection:
                connection.execute("ALTER TABLE draft_operations ADD COLUMN future_column TEXT")
        incompatible_state = tree_bytes(self.config.parent)
        binaries_before = tree_bytes(self.bin)
        self.failed(self.command("--config", self.config))
        self.assertEqual(tree_bytes(self.bin), binaries_before)
        after = tree_bytes(self.config.parent)
        # The application's offline verification fences unsupported draft
        # history. This safety marker is allowed; no existing history is reset.
        self.assertEqual(after.pop("state/drafts.suspended"), b"suspended")
        # SQLite may remove an empty WAL and its volatile shared-memory index
        # on the next open/close. Never ignore a WAL containing durable data.
        for snapshot in (after, incompatible_state):
            self.assertEqual(snapshot.pop("state/drafts.sqlite-wal", b""), b"")
            snapshot.pop("state/drafts.sqlite-shm", None)
        self.assertEqual(after, incompatible_state)

    def test_packaged_default_configuration_is_detected_before_replacement(self):
        self.successful(self.command())
        self.config = self.home / "Library" / "Preferences" / \
            "org.ueberbrot.mailctl" / "config.toml"
        # Invoke setup without a path override so this proves the application's
        # native default path agrees with the installer's default preflight.
        for alias in ("work", "personal"):
            result = subprocess.run([str(self.bin / "mailctl"), "--json", "setup",
                "--alias", alias, "--server", "imap.example.test", "--username",
                f"{alias}@example.test"], env=self.env, capture_output=True,
                text=True, timeout=30)
            self.successful(result)
        self.assertTrue(self.config.is_file(), "native default configuration path differs")
        state_before = tree_bytes(self.home)
        self.successful(self.command())
        self.assertEqual(tree_bytes(self.home), state_before)
        original = self.config.read_bytes()
        self.config.write_bytes(b"future_schema_field = true\n" + original)
        before = tree_bytes(self.home)
        self.failed(self.command())
        self.assertEqual(tree_bytes(self.home), before)

    def test_packaged_update_requires_mcp_runtime_to_stop(self):
        self.successful(self.command())
        self.setup_accounts(self.bin / "mailctl")
        text = self.config.read_text().replace("initialization_seconds = 5",
                                               "initialization_seconds = 1")
        self.config.write_text(text)
        self.invoke(self.bin / "mailctl", "setup")
        binaries_before = tree_bytes(self.bin)
        state_before = tree_bytes(self.config.parent)

        def update_while_busy():
            self.failed(self.command("--config", self.config))
            self.assertEqual(tree_bytes(self.bin), binaries_before)
            self.assertEqual(tree_bytes(self.config.parent), state_before)

        self.discover_mcp(self.bin / "mailctl-mcp", while_running=update_while_busy)
        self.successful(self.command("--config", self.config))
        self.assertEqual(tree_bytes(self.config.parent), state_before)

    def test_packaged_source_binary_migration_requires_explicit_ownership_handoff(self):
        self.bin.mkdir(parents=True)
        legacy = self.bin / "mailctl"
        shutil.copy2(self.downloads / self.manifest["cli_file"], legacy)
        legacy.chmod(0o755)
        installation_id = self.setup_accounts(legacy)
        accounts = self.invoke(legacy, "account", "list")
        state_before = tree_bytes(self.config.parent)
        binary_before = legacy.read_bytes()
        self.failed(self.command("--config", self.config))
        self.assertEqual(legacy.read_bytes(), binary_before)
        self.assertEqual(tree_bytes(self.config.parent), state_before)
        legacy.rename(self.directory / "old source-build binary")
        self.successful(self.command("--config", self.config))
        self.assertEqual(self.invoke(self.bin / "mailctl", "account", "list"), accounts)
        self.assertEqual(self.discover_mcp(self.bin / "mailctl-mcp"), accounts)
        self.assertEqual(self.invoke(self.bin / "mailctl", "setup")["installation_id"],
                         installation_id)
        self.assertEqual(tree_bytes(self.config.parent), state_before)


def leave_installed_candidate(artifacts, destination):
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise SystemExit("--install-to must be a missing or empty dedicated directory")
    manifest = read_manifest(artifacts)
    with tempfile.TemporaryDirectory(prefix="mailctl-candidate-install-") as temporary:
        home = Path(temporary) / "home"
        home.mkdir(mode=0o700)
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
        server = DownloadServer(artifacts)
        try:
            subprocess.run(["/bin/sh", str(artifacts / f"install-v{manifest['version']}.sh"), "--version",
                manifest["version"], "--base-url", server.url, "--install-dir",
                str(destination)], env=env, check=True, timeout=60)
        finally:
            server.close()


def main():
    global ARTIFACTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--install-to", type=Path)
    parser.add_argument("--suite", choices=("all", "fixtures", "packaged"), default="all")
    options, unittest_args = parser.parse_known_args()
    if options.artifacts:
        ARTIFACTS = options.artifacts.resolve(strict=True)
    if options.install_to and ARTIFACTS is None:
        parser.error("--install-to requires --artifacts")
    if options.suite == "packaged" and ARTIFACTS is None:
        parser.error("--suite packaged requires --artifacts")
    # Packaged checks complement the fixture suite. Avoid inheriting all fixture
    # cases into the packaged class, whose downloads are immutable candidates.
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in (InstallerTest, PackagedInstallerTest):
        if options.suite == "fixtures" and test_class is PackagedInstallerTest:
            continue
        if options.suite == "packaged" and test_class is InstallerTest:
            continue
        names = [name for name in loader.getTestCaseNames(test_class)
                 if test_class is InstallerTest or name.startswith("test_packaged_")]
        if unittest_args:
            names = [name for name in names if any(pattern in name for pattern in unittest_args)]
        suite.addTests(test_class(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if options.install_to:
        leave_installed_candidate(ARTIFACTS, options.install_to.resolve())


if __name__ == "__main__":
    main()
