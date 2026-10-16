#!/usr/bin/env python3
"""Add mailctl's component receipt and signing evidence to dist-built artifacts.

This does not compile, archive, sign or publish. Run dist build first; the
unchanged archive and its checksum remain the authoritative build outputs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TARGET = "aarch64-apple-darwin"
COMPONENTS = {"cli": "mailctl", "mcp": "mailctl-mcp"}
# Bump with the installer's supported epoch when component/state compatibility changes.
COMPATIBILITY = "1"


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(manifest_path, destination, allow_dirty):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("candidate evidence requires native macOS Apple Silicon")
    if destination.exists() or destination.is_symlink():
        raise ValueError("output directory must not exist")
    source = "dirty" if run("git", "status", "--porcelain") else "clean"
    if source == "dirty" and not allow_dirty:
        raise ValueError("source is dirty; use --allow-dirty only for local testing")
    commit = run("git", "rev-parse", "HEAD")
    manifest = json.loads(manifest_path.read_text())
    releases = manifest["releases"]
    if len(releases) != 1 or releases[0]["app_name"] != "mailctl":
        raise ValueError("dist must distribute only the mailctl package")
    version = releases[0]["app_version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("installer requires a stable release version")
    archive_name = "mailctl-" + TARGET + ".tar.gz"
    artifact = manifest["artifacts"][archive_name]
    if artifact["target_triples"] != [TARGET]:
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
        shutil.copy2(ROOT / "install.sh", staging / "install.sh")
        values = {"format": "1", "version": version, "target": TARGET,
                  "commit": commit, "compatibility": compatibility}
        # Read exact regular members, never extract archive paths to disk.
        with tarfile.open(staging / archive_name, "r:gz") as archive:
            for component, binary in COMPONENTS.items():
                members = [m for m in archive.getmembers() if Path(m.name).name == binary]
                if len(members) != 1 or not members[0].isfile():
                    raise ValueError("missing or ambiguous binary in dist archive: " + binary)
                filename = binary + "-v" + version + "-" + TARGET
                output = staging / filename
                with archive.extractfile(members[0]) as reader, output.open("wb") as writer:
                    shutil.copyfileobj(reader, writer)
                output.chmod(0o755)
                if run("/usr/bin/lipo", "-archs", str(output)) != "arm64":
                    raise ValueError("unexpected architecture: " + binary)
                if run(str(output), "--version") != binary + " " + version:
                    raise ValueError("binary version differs from dist manifest")
                signature = subprocess.run(["/usr/bin/codesign", "-d", "-vvv", str(output)],
                                           capture_output=True, text=True)
                if signature.returncode == 0 and "Signature=adhoc" in signature.stderr:
                    run("/usr/bin/codesign", "--verify", "--strict", str(output))
                    signing = "ad-hoc"
                elif signature.returncode != 0 and "code object is not signed at all" in signature.stderr:
                    signing = "unsigned"
                else:
                    raise ValueError("unqualified signing status: " + signature.stderr)
                values.update({component + "_file": filename,
                               component + "_sha256": digest(output),
                               component + "_size": str(output.stat().st_size),
                               component + "_signing": signing})
        (staging / ("manifest-" + TARGET + ".txt")).write_text(
            "".join(key + "=" + value + "\n" for key, value in values.items()))
        evidence = dict(status="prepared", source=source, commit=commit, version=version,
                        target=TARGET, compatibility=compatibility,
                        dist_version=manifest["dist_version"], rustc=run("rustc", "--version"),
                        macos=run("sw_vers", "-productVersion"), architecture=platform.machine(),
                        archive_sha256=digest(staging / archive_name),
                        build_command="dist build --artifacts=local --target " + TARGET + " --output-format=json",
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
    args = parser.parse_args()
    try:
        prepare(args.manifest.resolve(strict=True), args.output.resolve(), args.allow_dirty)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, "prepare-installer: " + str(error) + "\n")
