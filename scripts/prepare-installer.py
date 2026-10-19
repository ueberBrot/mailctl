#!/usr/bin/env python3
"""Add mailctl's component receipt and signing evidence to dist-built artifacts.

This does not compile, archive, sign or publish. Run dist build first; the
unchanged archive and its checksum remain the authoritative build outputs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
COMPONENTS = {"cli": "mailctl", "mcp": "mailctl-mcp"}
# Bump with the installer's supported epoch when component/state compatibility changes.
COMPATIBILITY = "1"


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_target():
    host = platform.system(), platform.machine()
    if host == ("Darwin", "arm64"):
        return TARGETS[0]
    if host == ("Linux", "x86_64") and (os.confstr("CS_GNU_LIBC_VERSION") or "").startswith("glibc "):
        return TARGETS[1]
    if host[0] == "Windows" and host[1].lower() in ("amd64", "x86_64"):
        return TARGETS[2]
    raise ValueError("candidate evidence requires native macOS Apple Silicon, GNU/Linux x86_64, or Windows x86_64")


def linux_binary(path):
    with path.open("rb") as binary:
        header = binary.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("expected a little-endian ELF64 binary: " + path.name)
        fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
        if fields[1] not in (2, 3) or fields[2:4] != (62, 1) or fields[8:10] != (64, 56):
            raise ValueError("expected an x86_64 ELF executable: " + path.name)
        offset, count = fields[5], fields[10]
        size = path.stat().st_size
        if not 1 <= count <= 128 or offset < 64 or offset + count * 56 > size:
            raise ValueError("invalid ELF program headers: " + path.name)
        binary.seek(offset)
        headers = [struct.unpack("<IIQQQQQQ", binary.read(56)) for _ in range(count)]
        interpreters = [header for header in headers if header[0] == 3]
        if len(interpreters) != 1:
            raise ValueError("GNU/Linux candidate must use a dynamic loader: " + path.name)
        interpreter = interpreters[0]
        offset, length = interpreter[2], interpreter[5]
        if not 2 <= length <= 4096 or offset + length > size:
            raise ValueError("invalid ELF interpreter: " + path.name)
        binary.seek(offset)
        loader = binary.read(length)
        if loader not in (b"/lib64/ld-linux-x86-64.so.2\0",
                          b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\0"):
            raise ValueError("GNU/Linux candidate requires the x86_64 glibc loader: " + path.name)
    return dict(elf_class="ELF64", elf_machine="x86_64", elf_interpreter=loader[:-1].decode())


def windows_binary(path):
    with path.open("rb") as binary:
        header = binary.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError("expected a Windows executable: " + path.name)
        offset = struct.unpack_from("<I", header, 60)[0]
        size = path.stat().st_size
        if not 64 <= offset <= size - 24:
            raise ValueError("invalid PE header offset: " + path.name)
        binary.seek(offset)
        header = binary.read(24)
        signature, machine, sections, _, _, _, optional_size, characteristics = struct.unpack(
            "<4sHHIIIHH", header)
        if (signature != b"PE\0\0" or machine != 0x8664 or not 1 <= sections <= 96
                or optional_size < 112 or not characteristics & 2 or characteristics & 0x2000
                or offset + 24 + optional_size + sections * 40 > size):
            raise ValueError("expected an x86_64 PE executable: " + path.name)
        if binary.read(2) != b"\x0b\x02":
            raise ValueError("expected a PE32+ executable: " + path.name)
    return dict(pe_machine="x86_64", pe_format="PE32+")


def copy_binary(archive, binary, output, windows):
    # Read exact regular members, never extract archive paths to disk.
    if windows:
        members = [member for member in archive.infolist()
                   if Path(member.filename).name == binary + ".exe"]
        if (len(members) != 1 or members[0].is_dir()
                or ((members[0].external_attr >> 16) & 0o170000) not in (0, 0o100000)
                or members[0].external_attr & 0x10):
            raise ValueError("missing or ambiguous binary in dist archive: " + binary)
        reader = archive.open(members[0])
    else:
        members = [member for member in archive.getmembers() if Path(member.name).name == binary]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("missing or ambiguous binary in dist archive: " + binary)
        reader = archive.extractfile(members[0])
    with reader, output.open("wb") as writer:
        shutil.copyfileobj(reader, writer)
    output.chmod(0o755)


def prepare(manifest_path, destination, allow_dirty, target=None):
    native = native_target()
    target = target or native
    if target != native:
        raise ValueError("candidate evidence must be prepared on its native target host")
    if destination.exists() or destination.is_symlink():
        raise ValueError("output directory must not exist")
    source = "dirty" if run("git", "status", "--porcelain") else "clean"
    if source == "dirty" and not allow_dirty:
        raise ValueError("source is dirty; use --allow-dirty only for local testing")
    commit = run("git", "rev-parse", "HEAD")
    manifest = json.loads(manifest_path.read_text())
    if manifest["dist_version"] != "0.33.0":
        raise ValueError("candidate requires pinned cargo-dist 0.33.0")
    releases = manifest["releases"]
    if len(releases) != 1 or releases[0]["app_name"] != "mailctl":
        raise ValueError("dist must distribute only the mailctl package")
    version = releases[0]["app_version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("installer requires a stable release version")
    windows = target == "x86_64-pc-windows-msvc"
    archive_name = "mailctl-" + target + (".zip" if windows else ".tar.gz")
    artifact = manifest["artifacts"][archive_name]
    if artifact["target_triples"] != [target]:
        raise ValueError("unexpected dist target")
    binaries = {a["name"] for a in artifact["assets"] if a["kind"] == "executable"}
    if binaries != set(COMPONENTS.values()):
        raise ValueError("dist must package exactly CLI and MCP")
    archive_path = Path(artifact["path"])
    checksum_path = Path(manifest["artifacts"][artifact["checksum"]]["path"])
    archive_digest = digest(archive_path)
    if (archive_digest != checksum_path.read_text().split()[0]
            or archive_digest != artifact.get("checksums", {}).get("sha256")):
        raise ValueError("dist archive checksum mismatch")
    compatibility = COMPATIBILITY
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mailctl-candidate-", dir=destination.parent) as temporary:
        staging = Path(temporary)
        shutil.copy2(archive_path, staging / archive_name)
        shutil.copy2(checksum_path, staging / checksum_path.name)
        shutil.copy2(manifest_path, staging / "dist-manifest.json")
        installer = "install.ps1" if windows else "install.sh"
        shutil.copy2(ROOT / installer, staging / installer)
        values = {"format": "1", "version": version, "target": target,
                  "commit": commit, "compatibility": compatibility}
        elf = None
        windows_evidence = None
        archive_reader = zipfile.ZipFile if windows else tarfile.open
        with archive_reader(staging / archive_name, "r" if windows else "r:gz") as archive:
            for component, binary in COMPONENTS.items():
                filename = binary + "-v" + version + "-" + target + (".exe" if windows else "")
                output = staging / filename
                copy_binary(archive, binary, output, windows)
                if target == "aarch64-apple-darwin":
                    if run("/usr/bin/lipo", "-archs", str(output)) != "arm64":
                        raise ValueError("unexpected architecture: " + binary)
                elif windows:
                    windows_binary(output)
                else:
                    binary_elf = linux_binary(output)
                    if elf is not None and elf != binary_elf:
                        raise ValueError("component ELF architectures or interpreters differ")
                    elf = binary_elf
                if run(str(output), "--version") != binary + " " + version:
                    raise ValueError("binary version differs from dist manifest")
                if target == "aarch64-apple-darwin":
                    signature = subprocess.run(["/usr/bin/codesign", "-d", "-vvv", str(output)],
                                               capture_output=True, text=True)
                    if signature.returncode == 0 and "Signature=adhoc" in signature.stderr:
                        run("/usr/bin/codesign", "--verify", "--strict", str(output))
                        signing = "ad-hoc"
                    elif signature.returncode != 0 and "code object is not signed at all" in signature.stderr:
                        signing = "unsigned"
                    else:
                        raise ValueError("unqualified signing status: " + signature.stderr)
                elif windows:
                    inspected = json.loads(run("pwsh", "-NoProfile", "-File",
                                               str(ROOT / "scripts/ci/windows-candidate.ps1"),
                                               "-Phase", "inspect", "-Binary", str(output)))
                    if inspected["authenticode_status"] != "NotSigned":
                        raise ValueError("unqualified Authenticode status: " + inspected["authenticode_status"])
                    if windows_evidence is not None and windows_evidence != inspected:
                        raise ValueError("component Windows host or signing evidence differs")
                    windows_evidence = inspected
                    signing = "unsigned"
                else:
                    signing = "unsigned"
                values.update({component + "_file": filename,
                               component + "_sha256": digest(output),
                               component + "_size": str(output.stat().st_size),
                               component + "_signing": signing})
        (staging / ("manifest-" + target + ".txt")).write_text(
            "".join(key + "=" + value + "\n" for key, value in values.items()))
        evidence = dict(status="prepared", source=source, commit=commit, version=version,
                        target=target, compatibility=compatibility,
                        dist_version=manifest["dist_version"], rustc=run("rustc", "--version"))
        if target == "aarch64-apple-darwin":
            evidence["macos"] = run("sw_vers", "-productVersion")
        elif windows:
            evidence.update(os_release="Windows", os_version=platform.win32_ver()[1],
                            windows_release=platform.release(), **windows_binary(output),
                            **windows_evidence)
        else:
            distribution = platform.freedesktop_os_release()
            evidence.update(os_release=distribution["ID"], os_version=distribution["VERSION_ID"],
                            kernel=platform.release(), libc=os.confstr("CS_GNU_LIBC_VERSION"), **elf)
        evidence.update(architecture=platform.machine(), archive_sha256=digest(staging / archive_name),
                        build_command="dist build --artifacts=local --target " + target + " --output-format=json",
                        publication="not-performed", notarization="not-performed")
        (staging / "build-evidence.txt").write_text(
            "".join(key + "=" + value + "\n" for key, value in evidence.items()))
        (staging / "SHA256SUMS").write_text("".join(
            digest(path) + "  " + path.name + "\n" for path in sorted(staging.iterdir())))
        # Refuse to merge this candidate with a previous run's files.
        destination.mkdir()
        for path in staging.iterdir():
            shutil.move(str(path), destination / path.name)
    print("Prepared dist candidate and installer evidence: " + str(destination))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "target/dist-build.json")
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-candidate")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--target", choices=TARGETS,
                        help="target to qualify (default: supported native host)")
    args = parser.parse_args()
    try:
        prepare(args.manifest.resolve(strict=True), args.output.resolve(), args.allow_dirty, args.target)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError,
            tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, "prepare-installer: " + str(error) + "\n")
