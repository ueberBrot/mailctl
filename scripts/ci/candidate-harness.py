#!/usr/bin/env python3
"""Stage and run relocatable native candidate test harnesses without Cargo.

prepare requires MAILCTL_TARGET, MAILCTL_CANDIDATE_DIR and MAILCTL_HARNESS_DIR.
artifacts --test NAME (repeatable) prints a JSON name-to-absolute-path mapping.
run --test NAME (repeatable) [FILTER] -- [LIBTEST FLAGS] runs staged harnesses;
MAILCTL_PACKAGED_BIN_DIR must select the installed release candidate.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "portable-harnesses.json"
COMMON_TESTS = (
    "administration_process", "state_maintenance", "mcp_process",
    "message_process", "attachment_process", "search_process",
    "discovery_process", "read_contention_process", "draft_process",
    "native_credentials", "packaged_reading", "packaged_drafts",
)
LINUX_TESTS = (
    "linux_credentials", "systemd_native", "systemd_credentials",
    "secret_service_credentials",
)


def absolute_directory(name):
    value = os.environ.get(name)
    if not value or not Path(value).is_absolute():
        raise ValueError(f"{name} must be an absolute directory")
    return Path(value).resolve()


def test_targets(target):
    if target == "aarch64-apple-darwin":
        return COMMON_TESTS
    if target == "x86_64-unknown-linux-gnu":
        return COMMON_TESTS + LINUX_TESTS
    raise ValueError(f"Unsupported candidate target: {target}")


def prepare():
    target = os.environ.get("MAILCTL_TARGET", "")
    targets = test_targets(target)
    candidate = absolute_directory("MAILCTL_CANDIDATE_DIR")
    directory = absolute_directory("MAILCTL_HARNESS_DIR")
    caches = [ROOT / "target", ROOT / os.environ.get("CARGO_TARGET_DIR", "target")]
    for cache in caches:
        cache = cache.resolve()
        if directory.is_relative_to(cache) or cache.is_relative_to(directory):
            raise ValueError("MAILCTL_HARNESS_DIR must be outside the Cargo target cache")
    if directory.is_relative_to(candidate) or candidate.is_relative_to(directory):
        raise ValueError("Candidate and harness directories must be separate")
    if not candidate.is_dir():
        raise ValueError("MAILCTL_CANDIDATE_DIR is not a directory")
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / MANIFEST
    # A failed rebuild must never leave a previous successful manifest usable.
    manifest_path.unlink(missing_ok=True)
    command = ["cargo", "test", "--locked", "--workspace", "--no-default-features",
               "--features", "cli,mcp", "--target", target]
    for name in targets:
        command += ["--test", name]
    command += ["--no-run", "--message-format=json"]
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    selected = {}
    for name in targets:
        source = (ROOT / "tests" / f"{name}.rs").resolve()
        matches = []
        for artifact in artifacts:
            built = artifact.get("target", {})
            if (artifact.get("reason") == "compiler-artifact" and artifact.get("executable")
                    and built.get("name") == name and "test" in built.get("kind", [])
                    and Path(built.get("src_path", "")).resolve() == source):
                matches.append(Path(artifact["executable"]))
        if len(matches) != 1:
            raise ValueError(f"Expected one root workspace harness for {name}, got {len(matches)}")
        if not matches[0].is_file():
            raise ValueError(f"Missing compiled harness: {matches[0]}")
        selected[name] = matches[0]
    harnesses = {}
    for name, source in selected.items():
        filename = f"test-{name}"
        destination = directory / filename
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        harnesses[name] = filename
    manifest = {"schema": 1, "target": target, "features": "cli,mcp",
                "build_command": command, "harnesses": harnesses}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def staged_artifacts(names):
    directory = absolute_directory("MAILCTL_HARNESS_DIR")
    manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("features") != "cli,mcp":
        raise ValueError("Unsupported portable harness manifest")
    target = manifest.get("target")
    targets = test_targets(target)
    if os.environ.get("MAILCTL_TARGET", target) != target:
        raise ValueError("Portable harness target does not match MAILCTL_TARGET")
    artifacts = {}
    for name in names:
        filename = manifest.get("harnesses", {}).get(name)
        if name not in targets or not isinstance(filename, str):
            raise ValueError(f"Missing portable harness: {name}")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename):
            raise ValueError(f"Unsafe portable harness filename: {filename}")
        executable = directory / filename
        if executable.is_symlink() or not executable.is_file():
            raise ValueError(f"Missing regular portable harness: {executable}")
        # Artifact downloads retain bytes but strip Unix execute permission.
        executable.chmod(executable.stat().st_mode | 0o111)
        artifacts[name] = str(executable)
    return artifacts


def main():
    arguments = sys.argv[1:]
    flags = []
    if "--" in arguments:
        separator = arguments.index("--")
        arguments, flags = arguments[:separator], arguments[separator + 1:]
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    artifacts = commands.add_parser("artifacts")
    artifacts.add_argument("--test", action="append", required=True)
    run = commands.add_parser("run")
    run.add_argument("--test", action="append", required=True)
    run.add_argument("filter", nargs="?")
    options = parser.parse_args(arguments)
    if flags and options.command != "run":
        parser.error("Libtest flags require run")
    try:
        if options.command == "prepare":
            prepare()
            return 0
        selected = staged_artifacts(options.test)
        if options.command == "artifacts":
            print(json.dumps(selected, sort_keys=True))
            return 0
        installed = absolute_directory("MAILCTL_PACKAGED_BIN_DIR")
        if not installed.is_dir():
            raise ValueError("MAILCTL_PACKAGED_BIN_DIR is not a directory")
        for executable in selected.values():
            command = [executable]
            if options.filter is not None:
                command.append(options.filter)
            result = subprocess.run(command + flags, check=False)
            if result.returncode:
                return result.returncode if result.returncode > 0 else 1
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Candidate harness error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
