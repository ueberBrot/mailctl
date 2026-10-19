#!/usr/bin/env python3
"""Check native candidate evidence and executable admission without a Rust build."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("prepare_installer", ROOT / "scripts/prepare-installer.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
LINUX = "x86_64-unknown-linux-gnu"
MACOS = "aarch64-apple-darwin"
WINDOWS = "x86_64-pc-windows-msvc"


def fields(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def elf(machine=62, loader=b"/lib64/ld-linux-x86-64.so.2\0"):
    identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", identity, 3, machine, 1, 0, 64, 0, 0,
                         64, 56, 1, 0, 0, 0)
    interpreter = struct.pack("<IIQQQQQQ", 3, 4, 120, 0, 0, len(loader), len(loader), 1)
    return header + interpreter + loader


def pe(machine=0x8664, magic=0x20b, characteristics=0x22):
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 64)
    header = struct.pack("<4sHHIIIHH", b"PE\0\0", machine, 1, 0, 0, 0, 112, characteristics)
    return dos + header + struct.pack("<H", magic) + b"\0" * (110 + 40)


class CandidatePreparationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mailctl-prepare-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.destination = self.directory / "candidate"
        self.signing = "NotSigned"

    def manifest(self, target, contents=None):
        windows = target == WINDOWS
        archive = self.directory / (f"mailctl-{target}" + (".zip" if windows else ".tar.gz"))
        if windows:
            with zipfile.ZipFile(archive, "w") as output:
                for binary in prepare.COMPONENTS.values():
                    output.writestr(binary + ".exe", (contents or {}).get(binary, pe()))
        else:
            with tarfile.open(archive, "w:gz") as output:
                for binary in prepare.COMPONENTS.values():
                    data = (contents or {}).get(binary, elf())
                    member = tarfile.TarInfo(f"mailctl-{target}/{binary}")
                    member.size = len(data)
                    member.mode = 0o755
                    output.addfile(member, io.BytesIO(data))
        checksum = self.directory / (archive.name + ".sha256")
        digest = prepare.digest(archive)
        checksum.write_text(f"{digest}  {archive.name}\n")
        manifest = {
            "dist_version": "0.33.0",
            "releases": [{"app_name": "mailctl", "app_version": "0.1.0"}],
            "artifacts": {
                archive.name: {"path": str(archive), "target_triples": [target],
                               "checksum": checksum.name, "checksums": {"sha256": digest},
                               "assets": [{"name": binary, "kind": "executable"}
                                          for binary in prepare.COMPONENTS.values()]},
                checksum.name: {"path": str(checksum)},
            },
        }
        path = self.directory / "dist-build.json"
        path.write_text(json.dumps(manifest))
        return path

    def run_command(self, *arguments):
        if arguments == ("git", "status", "--porcelain"):
            return ""
        if arguments == ("git", "rev-parse", "HEAD"):
            return "a" * 40
        if arguments == ("rustc", "--version"):
            return "rustc 1.98.1"
        if arguments == ("sw_vers", "-productVersion"):
            return "26.0"
        if arguments[:2] == ("/usr/bin/lipo", "-archs"):
            return "arm64"
        if arguments[:3] == ("/usr/bin/codesign", "--verify", "--strict"):
            return ""
        if arguments[:3] == ("pwsh", "-NoProfile", "-File"):
            self.assertEqual(arguments[4:7], ("-Phase", "inspect", "-Binary"))
            return json.dumps(dict(authenticode_status=self.signing, powershell_version="7.4.13",
                                   windows_caption="Microsoft Windows Server 2025 Datacenter"))
        if len(arguments) == 2 and arguments[1] == "--version":
            binary = "mailctl-mcp" if Path(arguments[0]).name.startswith("mailctl-mcp-") else "mailctl"
            return binary + " 0.1.0"
        self.fail(f"unexpected candidate command: {arguments}")

    def qualify(self, target, contents=None):
        manifest = self.manifest(target, contents)
        system, machine = {LINUX: ("Linux", "x86_64"), MACOS: ("Darwin", "arm64"),
                           WINDOWS: ("Windows", "AMD64")}[target]
        with patch.object(prepare.platform, "system", return_value=system), \
                patch.object(prepare.platform, "machine", return_value=machine), \
                patch.object(prepare.platform, "release", return_value=(
                    "2025Server" if target == WINDOWS else "6.8.0-test")), \
                patch.object(prepare.platform, "win32_ver", return_value=("10", "10.0.26100", "", "")), \
                patch.object(prepare.platform, "freedesktop_os_release", create=True,
                             return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                patch.object(prepare.os, "confstr", return_value="glibc 2.39"), \
                patch.object(prepare, "run", side_effect=self.run_command), \
                patch.object(prepare.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 0, stdout="", stderr="Signature=adhoc")):
            prepare.prepare(manifest, self.destination, False, target)
        return fields(self.destination / "build-evidence.txt")

    def test_linux_evidence_records_native_ubuntu_glibc_and_elf(self):
        evidence = self.qualify(LINUX)
        for key, expected in dict(target=LINUX, architecture="x86_64", os_release="ubuntu",
                                  os_version="24.04", kernel="6.8.0-test", libc="glibc 2.39",
                                  elf_class="ELF64", elf_machine="x86_64",
                                  elf_interpreter="/lib64/ld-linux-x86-64.so.2",
                                  publication="not-performed").items():
            self.assertEqual(evidence[key], expected)
        self.assertEqual(evidence["build_command"],
                         f"dist build --artifacts=local --target {LINUX} --output-format=json")
        receipt = fields(self.destination / f"manifest-{LINUX}.txt")
        self.assertEqual(receipt["target"], LINUX)
        for component in prepare.COMPONENTS:
            self.assertEqual(receipt[f"{component}_signing"], "unsigned")
        sums = {name: digest for digest, name in
                (line.split("  ", 1) for line in (self.destination / "SHA256SUMS").read_text().splitlines())}
        self.assertEqual(sums, {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in self.destination.iterdir() if path.name != "SHA256SUMS"})

    def test_macos_receipt_and_evidence_fields_stay_compatible(self):
        evidence = self.qualify(MACOS)
        self.assertEqual(set(evidence), {
            "status", "source", "commit", "version", "target", "compatibility", "dist_version",
            "rustc", "macos", "architecture", "archive_sha256", "build_command", "publication",
            "notarization",
        })
        self.assertEqual(evidence["macos"], "26.0")
        self.assertEqual(evidence["architecture"], "arm64")
        receipt = fields(self.destination / f"manifest-{MACOS}.txt")
        self.assertEqual(len(receipt), 13)
        self.assertEqual(receipt["cli_signing"], "ad-hoc")

    def test_native_target_rejects_cross_preparation_and_musl(self):
        with patch.object(prepare.platform, "system", return_value="Linux"), \
                patch.object(prepare.platform, "machine", return_value="x86_64"), \
                patch.object(prepare.os, "confstr", return_value="glibc 2.39"):
            self.assertEqual(prepare.native_target(), LINUX)
            with self.assertRaisesRegex(ValueError, "native target host"):
                prepare.prepare(self.directory / "unused.json", self.destination, False, MACOS)
        with patch.object(prepare.platform, "system", return_value="Linux"), \
                patch.object(prepare.platform, "machine", return_value="x86_64"), \
                patch.object(prepare.os, "confstr", return_value=None):
            with self.assertRaisesRegex(ValueError, "native macOS Apple Silicon, GNU/Linux x86_64"):
                prepare.native_target()
        with patch.object(prepare.platform, "system", return_value="Windows"), \
                patch.object(prepare.platform, "machine", return_value="AMD64"):
            self.assertEqual(prepare.native_target(), WINDOWS)
        with patch.object(prepare.platform, "system", return_value="Windows"), \
                patch.object(prepare.platform, "machine", return_value="ARM64"):
            with self.assertRaises(ValueError):
                prepare.native_target()
        self.assertFalse(self.destination.exists())

    def test_windows_receipt_uses_native_zip_bytes_and_observed_signing(self):
        evidence = self.qualify(WINDOWS)
        for key, expected in dict(target=WINDOWS, architecture="AMD64", os_release="Windows",
                                  os_version="10.0.26100", pe_machine="x86_64", pe_format="PE32+",
                                  authenticode_status="NotSigned", powershell_version="7.4.13",
                                  windows_caption="Microsoft Windows Server 2025 Datacenter",
                                  publication="not-performed").items():
            self.assertEqual(evidence[key], expected)
        receipt = fields(self.destination / f"manifest-{WINDOWS}.txt")
        self.assertEqual(len(receipt), 13)
        for component, binary in prepare.COMPONENTS.items():
            name = f"{binary}-v0.1.0-{WINDOWS}.exe"
            self.assertEqual(receipt[f"{component}_file"], name)
            self.assertEqual(receipt[f"{component}_signing"], "unsigned")
            self.assertEqual((self.destination / name).read_bytes(), pe())
        self.assertEqual((self.destination / "install.ps1").read_bytes(), (ROOT / "install.ps1").read_bytes())
        self.assertFalse((self.destination / "install.sh").exists())

    def test_invalid_windows_images_cannot_publish_a_candidate(self):
        for invalid in (b"#!/bin/sh\n", elf(), pe(machine=0xaa64), pe(magic=0x10b),
                        pe(characteristics=0x20), pe(characteristics=0x2022), pe()[:100]):
            with self.subTest(binary=invalid):
                with self.assertRaises(ValueError):
                    self.qualify(WINDOWS, {"mailctl-mcp": invalid})
                self.assertFalse(self.destination.exists())

    def test_windows_signing_evidence_must_not_claim_unqualified_signing(self):
        for signing in ("Valid", "HashMismatch", "NotTrusted", "UnknownError"):
            self.signing = signing
            with self.subTest(signing=signing):
                with self.assertRaisesRegex(ValueError, "unqualified Authenticode"):
                    self.qualify(WINDOWS)
                self.assertFalse(self.destination.exists())

    def test_invalid_linux_executables_never_publish_a_partial_candidate(self):
        for invalid in (b"#!/bin/sh\n", elf(machine=183), elf()[:80],
                        elf(loader=b"/lib/ld-musl-x86_64.so.1\0")):
            with self.subTest(binary=invalid):
                with self.assertRaises(ValueError):
                    self.qualify(LINUX, {"mailctl-mcp": invalid})
                self.assertFalse(self.destination.exists())

    def test_components_must_use_the_same_dynamic_loader(self):
        other_glibc = elf(loader=b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\0")
        with self.assertRaisesRegex(ValueError, "interpreters differ"):
            self.qualify(LINUX, {"mailctl-mcp": other_glibc})
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
