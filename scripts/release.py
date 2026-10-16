#!/usr/bin/env python3
"""Preserve, inspect, and explicitly approve one mailctl release candidate.

Requires Python 3.11+ and gh. prepare and verify use only GitHub GET requests.
Downloaded programs and installers are never executed.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import zipfile

try:
    import tomllib
except ModuleNotFoundError:
    sys.exit("release: Python 3.11 or newer is required")


REPO = "ueberBrot/mailctl"
BASE = "repos/" + REPO + "/"
TARGET = "aarch64-apple-darwin"
ARTIFACT = "mailctl-candidate-" + TARGET
ARCHIVE = "mailctl-" + TARGET + ".tar.gz"
COMPONENTS = {"cli": "mailctl", "mcp": "mailctl-mcp"}
LOGS = {"installer-acceptance.log", "installed-state-acceptance.log",
        "installed-process-acceptance.log", "installed-native-acceptance.log"} | {
    f"installed-{suite}-{selection}-acceptance.log"
    for suite in ("reading", "drafts") for selection in ("cli", "mcp", "cli-mcp")}
SOURCE_FILES = ("Cargo.toml", "install.sh", "CHANGELOG.md")
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read(path):
    require(stat.S_ISREG(path.lstat().st_mode), "Expected regular file: " + str(path))
    require(path.stat().st_size <= MAX_FILE, "File exceeds size limit: " + str(path))
    return path.read_bytes()


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def fields(data, *, mixed=False):
    result = {}
    for line in data.decode().splitlines():
        if "=" not in line:
            require(mixed, "Malformed evidence line")
            continue  # sw_vers and uname also occur in acceptance evidence.
        key, value = line.split("=", 1)
        require(key not in result, "Duplicate evidence field: " + key)
        result[key] = value
    return result


def matches(actual, expected, context):
    for key, value in expected.items():
        require(type(actual.get(key)) is type(value) and actual.get(key) == value,
                f"{context}: unexpected {key}")


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "Timestamp requires timezone")
    return result


class GitHub:
    """Keep all external commands at one auditable boundary."""

    def call(self, args, *, data=None, output=None, absent_ok=False, cwd=None):
        env = dict(os.environ, GH_HOST="github.com", GH_PROMPT_DISABLED="1")
        result = subprocess.run(["gh", *args], input=data, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, cwd=cwd, check=False)
        if result.returncode:
            if absent_ok and b"(HTTP 404)" in result.stderr:
                return None
            raise ValueError("gh failed: " + result.stderr.decode(errors="replace").strip())
        return result.stdout

    def get(self, endpoint, *, raw=False, absent_ok=False):
        accept = "application/vnd.github.raw+json" if raw else "application/vnd.github+json"
        result = self.call(["api", "--hostname", "github.com", "--method", "GET",
                            BASE + endpoint, "-H", "Accept: " + accept], absent_ok=absent_ok)
        return result if raw or result is None else parse_json(result)

    def pages(self, endpoint, key):
        values = []
        for page in range(1, 101):
            response = self.get(f"{endpoint}?per_page=100&page={page}")
            entries = response[key] if key else response
            values.extend(entries)
            if (key and len(values) == response["total_count"]) or (not key and len(entries) < 100):
                return values
            require(len(entries) == 100, "Incomplete GitHub pagination")
        raise ValueError("GitHub pagination exceeds limit")

    def download(self, artifact_id, destination):
        with destination.open("xb") as output:
            self.call(["api", "--hostname", "github.com", "--method", "GET",
                       BASE + f"actions/artifacts/{artifact_id}/zip"], output=output)


def metadata(gh, commit, run_id, artifact_id):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Use a full lowercase commit SHA")
    require(type(run_id) is int and run_id > 0 and type(artifact_id) is int and artifact_id > 0,
            "Run and artifact IDs must be positive integers")
    main = gh.get("git/ref/heads/main")
    matches(main["object"], {"type": "commit", "sha": commit}, "current main")
    workflow = gh.get("actions/workflows/ci.yml")
    matches(workflow, {"path": ".github/workflows/ci.yml", "state": "active"}, "workflow")
    run = gh.get(f"actions/runs/{run_id}")
    expected = {"id": run_id, "head_sha": commit, "head_branch": "main", "event": "push",
                "status": "completed", "conclusion": "success", "workflow_id": workflow["id"]}
    matches(run, expected, "CI run")
    require(run["path"] in (".github/workflows/ci.yml", ".github/workflows/ci.yml@main",
                            ".github/workflows/ci.yml@refs/heads/main"), "Unexpected run workflow path")
    matches(run["repository"], {"full_name": REPO}, "run repository")
    matches(run["head_repository"], {"full_name": REPO}, "run head repository")
    attempt_number = run["run_attempt"]
    require(type(attempt_number) is int and attempt_number > 0, "Invalid run attempt")
    attempt = gh.get(f"actions/runs/{run_id}/attempts/{attempt_number}")
    matches(attempt, dict(expected, run_attempt=attempt_number, path=run["path"]), "CI attempt")
    jobs = gh.pages(f"actions/runs/{run_id}/attempts/{attempt_number}/jobs", "jobs")
    candidates = [job for job in jobs if job["name"] == "native-credentials"]
    require(len(candidates) == 1, "Expected exactly one candidate job in this attempt")
    job = candidates[0]
    matches(job, {"run_id": run_id, "head_sha": commit,
                  "status": "completed", "conclusion": "success"}, "candidate job")
    if "run_attempt" in job:
        matches(job, {"run_attempt": attempt_number}, "candidate job attempt")
    for name in ("Record passing candidate acceptance", "Keep candidate downloads and acceptance evidence"):
        steps = [step for step in job["steps"] if step["name"] == name]
        require(len(steps) == 1, "Missing candidate step: " + name)
        matches(steps[0], {"status": "completed", "conclusion": "success"}, name)
    artifact = gh.get(f"actions/artifacts/{artifact_id}")
    matches(artifact, {"id": artifact_id, "name": ARTIFACT, "expired": False}, "artifact")
    matches(artifact["workflow_run"], {"id": run_id, "head_sha": commit, "head_branch": "main",
                                      "repository_id": run["repository"]["id"],
                                      "head_repository_id": run["repository"]["id"]}, "artifact run")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), "Missing artifact SHA256 digest")
    require(timestamp(artifact["expires_at"]) > datetime.now(timezone.utc), "Artifact expired")
    # Artifacts do not carry run_attempt. Bind the ID to this attempt's job window.
    require(timestamp(job["started_at"]) <= timestamp(artifact["created_at"])
            <= timestamp(job["completed_at"]), "Artifact belongs to another attempt")
    upload = next(step for step in job["steps"] if step["name"] == "Keep candidate downloads and acceptance evidence")
    require(timestamp(upload["started_at"]) <= timestamp(artifact["created_at"])
            <= timestamp(upload["completed_at"]), "Artifact is outside this attempt's upload step")
    artifacts = gh.pages(f"actions/runs/{run_id}/artifacts", "artifacts")
    named = [entry for entry in artifacts if entry["name"] == ARTIFACT]
    require(len(named) == 1 and named[0] == artifact, "Ambiguous or mismatched run artifact")
    return dict(workflow=workflow, run=run, attempt=attempt, job=job, artifact=artifact)


def zip_files(path):
    result = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename
            require(name == entry.orig_filename and name and name not in (".", "..") and "/" not in name and "\\" not in name
                    and "\x00" not in name and ":" not in name, "Unsafe ZIP path: " + name)
            require(name not in result, "Duplicate ZIP path: " + name)
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not entry.external_attr & 0x10, "Nonregular ZIP member: " + name)
            total += entry.file_size
            require(entry.file_size <= MAX_FILE and total <= MAX_TOTAL, "ZIP exceeds size limit")
            result[name] = archive.read(entry)
    return result


def candidate_files(version):
    return LOGS | {"SHA256SUMS", "acceptance-evidence.txt", "build-evidence.txt", "dist-manifest.json",
                   f"install-v{version}.sh", ARCHIVE, ARCHIVE + ".sha256",
                   f"manifest-v{version}-{TARGET}.txt"} | {
                       f"{binary}-v{version}-{TARGET}" for binary in COMPONENTS.values()}


def checksum_lines(data):
    result = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        require(match is not None, "Malformed checksum line")
        digest, name = match.groups()
        require(name not in result, "Duplicate checksum: " + name)
        result[name] = digest
    return result


def validate_candidate(files, source, commit):
    version = tomllib.loads(source["Cargo.toml"].decode())["workspace"]["package"]["version"]
    require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version),
            "Source requires a stable release version")
    require(set(files) == candidate_files(version), "Candidate must contain the exact 20 expected files")
    sums = checksum_lines(files["SHA256SUMS"])
    require(sums == {name: sha(data) for name, data in files.items() if name != "SHA256SUMS"},
            "SHA256SUMS must cover all 19 other files with matching hashes")
    common = dict(version=version, target=TARGET, commit=commit, compatibility="1")
    receipt = fields(files[f"manifest-v{version}-{TARGET}.txt"])
    require(set(receipt) == {"format", "version", "target", "commit", "compatibility"} | {
        component + "_" + key for component in COMPONENTS for key in ("file", "size", "sha256", "signing")},
        "Unexpected component manifest fields")
    matches(receipt, dict(common, format="1"), "component manifest")
    build = fields(files["build-evidence.txt"])
    matches(build, dict(common, status="prepared", source="clean", dist_version="0.33.0",
                        architecture="arm64", archive_sha256=sha(files[ARCHIVE]),
                        publication="not-performed", notarization="not-performed",
                        build_command=f"dist build --artifacts=local --target {TARGET} --output-format=json"),
            "build evidence")
    require(build.get("rustc", "").startswith("rustc ") and build.get("macos"), "Missing build host evidence")
    acceptance = fields(files["acceptance-evidence.txt"], mixed=True)
    matches(acceptance, dict(status="passed", topology="cooperative-embedded",
                            credential_source="disposable-apple-keychain",
                            reading_credential_source="disposable-command-helper",
                            reading_tls_source="fixture-ca-via-SSL_CERT_FILE",
                            drafts_credential_source="disposable-command-helper",
                            drafts_tls_source="fixture-ca-via-SSL_CERT_FILE",
                            real_provider="not-qualified", isolation="not-qualified", publication="not-performed"),
            "acceptance evidence")
    commands = {"installer_command", "state_command", "process_command", "native_command"} | {
        f"{suite}{kind}_command_{selection}" for suite in ("reading", "drafts")
        for kind in ("", "_components") for selection in ("cli", "mcp", "cli,mcp")}
    require(all(acceptance.get(name) for name in commands), "Missing acceptance command evidence")
    for name in LOGS:
        require(files[name].strip(), "Empty acceptance log: " + name)
        if name != "installer-acceptance.log":
            results = re.findall(rb"^test result: (.+)$", files[name], re.MULTILINE)
            require(results and all(re.match(rb"ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;", result)
                                    for result in results), "Missing passing tests: " + name)
        else:
            require(re.search(rb"^OK\s*$", files[name], re.MULTILINE), "Missing passing installer tests")
    require(files[f"install-v{version}.sh"] == source["install.sh"], "Installer differs from fixed source commit")
    require(b"compatibility=1" in source["install.sh"], "Source installer compatibility changed")
    manifest = parse_json(files["dist-manifest.json"])
    matches(manifest, {"dist_version": "0.33.0"}, "dist manifest")
    require(len(manifest["releases"]) == 1, "Expected one dist release")
    release = manifest["releases"][0]
    matches(release, {"app_name": "mailctl", "app_version": version}, "dist release")
    require(ARCHIVE in release["artifacts"], "Dist release lacks candidate archive")
    archive = manifest["artifacts"][ARCHIVE]
    matches(archive, {"name": ARCHIVE, "target_triples": [TARGET], "checksum": ARCHIVE + ".sha256"}, "dist archive")
    matches(archive["checksums"], {"sha256": sha(files[ARCHIVE])}, "dist checksum")
    require({asset["name"] for asset in archive["assets"] if asset["kind"] == "executable"}
            == set(COMPONENTS.values()), "Dist executables differ")
    # Runner paths in dist's path fields are historical metadata, never local paths.
    checksum = manifest["artifacts"][ARCHIVE + ".sha256"]
    matches(checksum, {"name": ARCHIVE + ".sha256"}, "dist checksum artifact")
    checksum_text = files[ARCHIVE + ".sha256"].decode().strip().split()
    require(len(checksum_text) in (1, 2) and checksum_text[0] == sha(files[ARCHIVE]), "Archive checksum mismatch")
    if len(checksum_text) == 2:
        require(checksum_text[1].lstrip("*") == ARCHIVE, "Unexpected archive checksum filename")
    binaries = {}
    with tarfile.open(fileobj=io.BytesIO(files[ARCHIVE]), mode="r:gz") as tar:
        names = set()
        total = 0
        for member in tar.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.name,
                    "Unsafe tar member")
            require(member.name not in names and (member.isdir() or member.isfile()), "Duplicate or nonregular tar member")
            names.add(member.name)
            total += member.size
            require(member.size <= MAX_FILE and total <= MAX_TOTAL, "Tar exceeds size limit")
            if path.name in COMPONENTS.values():
                require(member.isfile() and path.name not in binaries, "Ambiguous archive binary")
                binaries[path.name] = tar.extractfile(member).read()
    require(set(binaries) == set(COMPONENTS.values()), "Archive binaries missing")
    for component, binary in COMPONENTS.items():
        name = f"{binary}-v{version}-{TARGET}"
        require(0 < len(files[name]) <= 104857600, "Component size exceeds installer limit")
        matches(receipt, {component + "_file": name, component + "_size": str(len(files[name])),
                          component + "_sha256": sha(files[name])}, "component bytes")
        require(receipt.get(component + "_signing") in ("ad-hoc", "unsigned"), "Unqualified signing evidence")
        require(binaries[binary] == files[name], "Raw binary differs from archive: " + binary)
    changelog = source["CHANGELOG.md"].decode()
    headings = list(re.finditer(r"^## \[?v?" + re.escape(version) +
                               r"\]?(?:\(https://[^\s)]+\))?(?:\s.*)?$", changelog, re.MULTILINE))
    require(len(headings) == 1, "Fixed source requires exactly one changelog entry for the release version")
    section = changelog[headings[0].end():].split("\n## ", 1)[0].strip()
    require(section, "Release changelog entry is empty")
    return version, section


def qualification(data, commit, meta):
    notes = parse_json(data)
    artifact = meta["artifact"]
    matches(notes, {"source_commit": commit}, "qualification source")
    matches(notes["artifact_association"], dict(commit=commit, run_id=meta["run"]["id"],
            run_attempt=meta["run"]["run_attempt"], artifact_id=artifact["id"],
            artifact_sha256=artifact["digest"]), "qualification association")
    for key in ("operator", "association_notes"):
        require(isinstance(notes.get(key), str) and notes[key].strip(), "Missing qualification " + key)
    links = notes.get("accepted_source_evidence")
    require(isinstance(links, list) and links and all(isinstance(link, str) and
            re.fullmatch(r"https://[^\s]+", link) for link in links), "Supply accepted source evidence links")
    return notes


def plan_for(directory, meta, source, files):
    commit = meta["run"]["head_sha"]
    version, changelog = validate_candidate(files, source, commit)
    note_bytes = read(directory / "qualification-notes.json")
    qualification(note_bytes, commit, meta)
    notes = (f"# mailctl {version}\n\n{changelog}\n\n"
             "## Qualification supplied by the operator\n\n"
             "These notes associate accepted source evidence with this artifact. "
             "The release helper does not run live qualification.\n\n```json\n" +
             note_bytes.decode().rstrip() + "\n```\n").encode()
    artifact = meta["artifact"]
    plan = dict(format=1, repository=REPO, commit=commit, version=version, tag="v" + version,
                run_id=meta["run"]["id"], run_attempt=meta["run"]["run_attempt"], artifact_id=artifact["id"],
                artifact_name=artifact["name"], artifact_sha256=artifact["digest"],
                assets={name: dict(size=len(data), sha256=sha(data)) for name, data in sorted(files.items())},
                source={name: sha(data) for name, data in source.items()},
                metadata_sha256=sha(read(directory / "metadata.json")),
                qualification_notes_sha256=sha(note_bytes), release_notes_sha256=sha(notes))
    return plan, notes


def prepare(gh, commit, run_id, artifact_id, qualification_notes, directory):
    require(not directory.exists() and not directory.is_symlink(), "Output directory must not exist")
    meta = metadata(gh, commit, run_id, artifact_id)
    directory.mkdir(parents=True)
    (directory / "metadata.json").write_bytes(canonical(meta))
    gh.download(artifact_id, directory / "artifact.zip")
    require("sha256:" + sha(read(directory / "artifact.zip")) == meta["artifact"]["digest"], "ZIP digest mismatch")
    source = {}
    (directory / "source").mkdir()
    for name in SOURCE_FILES:
        source[name] = gh.get(f"contents/{name}?ref={commit}", raw=True)
        (directory / "source" / name).write_bytes(source[name])
    (directory / "qualification-notes.json").write_bytes(read(qualification_notes))
    files = zip_files(directory / "artifact.zip")
    plan, notes = plan_for(directory, meta, source, files)
    (directory / "candidate").mkdir()
    for name, data in files.items():
        (directory / "candidate" / name).write_bytes(data)
    (directory / "release-notes.md").write_bytes(notes)
    encoded = canonical(plan)
    (directory / "plan.json").write_bytes(encoded)
    (directory / "PLAN_SHA256").write_text(sha(encoded) + "\n")
    return sha(encoded)


def verify(gh, directory):
    require(directory.is_dir() and not directory.is_symlink(), "Expected a plan directory")
    require(not (directory / "publication-started.json").exists(), "Publication already started; use manual recovery")
    encoded = read(directory / "plan.json")
    require(read(directory / "PLAN_SHA256") == (sha(encoded) + "\n").encode(), "Plan digest mismatch")
    plan = parse_json(encoded)
    saved = parse_json(read(directory / "metadata.json"))
    current = metadata(gh, plan["commit"], plan["run_id"], plan["artifact_id"])
    require(current == saved, "Remote metadata changed since preparation")
    require("sha256:" + sha(read(directory / "artifact.zip")) == current["artifact"]["digest"], "ZIP digest mismatch")
    files = zip_files(directory / "artifact.zip")
    source = {}
    require(not (directory / "source").is_symlink() and not (directory / "candidate").is_symlink(), "Unsafe plan directory")
    for name in SOURCE_FILES:
        source[name] = read(directory / "source" / name)
        require(source[name] == gh.get(f"contents/{name}?ref={plan['commit']}", raw=True), "Fixed source changed: " + name)
    require({path.name for path in (directory / "candidate").iterdir()} == set(files), "Local assets differ")
    for name, data in files.items():
        require(read(directory / "candidate" / name) == data, "Local asset changed: " + name)
    expected, notes = plan_for(directory, saved, source, files)
    require(encoded == canonical(expected), "Plan content mismatch")
    require(read(directory / "release-notes.md") == notes, "Release notes changed")
    return plan, sha(encoded)


def publish(gh, directory, approved):
    require(re.fullmatch(r"[0-9a-f]{64}", approved), "Approval requires the exact plan SHA256")
    require(sha(read(directory / "plan.json")) == approved, "Approved digest differs from this plan")
    plan, digest = verify(gh, directory)
    require(digest == approved, "Approved digest changed")
    tag = plan["tag"]
    require(gh.get("git/ref/tags/" + tag, absent_ok=True) is None, "Tag already exists; use manual recovery")
    require(not [release for release in gh.pages("releases", None) if release["tag_name"] == tag],
            "Release already exists; use manual recovery")
    # Exclusive journal: a failed or interrupted attempt cannot be retried automatically.
    with (directory / "publication-started.json").open("xb") as journal:
        journal.write(canonical(dict(plan_sha256=digest, tag=tag, commit=plan["commit"])))
    gh.call(["api", "--hostname", "github.com", "--method", "POST", BASE + "git/refs",
             "--input", "-"], data=canonical(dict(ref="refs/tags/" + tag, sha=plan["commit"])))
    remote_tag = gh.get("git/ref/tags/" + tag)
    matches(remote_tag["object"], {"type": "commit", "sha": plan["commit"]}, "created tag")
    gh.call(["release", "create", tag, "--draft", "--verify-tag", "--repo", REPO,
             "--title", tag, "--notes-file", str(directory / "release-notes.md"),
             *sorted(plan["assets"])], cwd=directory / "candidate")
    releases = [release for release in gh.pages("releases", None) if release["tag_name"] == tag]
    require(len(releases) == 1, "Expected exactly one draft release")
    release = releases[0]
    matches(release, {"tag_name": tag, "draft": True,
                      "body": read(directory / "release-notes.md").decode()}, "draft release")
    assets = gh.pages(f"releases/{release['id']}/assets", None)
    require(len(assets) == len(plan["assets"]), "Remote asset count differs; draft remains unpublished")
    seen = set()
    for asset in assets:
        name = asset["name"]
        require(name in plan["assets"] and name not in seen, "Remote asset names differ; draft remains unpublished")
        seen.add(name)
        expected = plan["assets"][name]
        matches(asset, {"size": expected["size"], "digest": "sha256:" + expected["sha256"],
                       "state": "uploaded"}, "remote asset " + name)
    matches(gh.get("git/ref/tags/" + tag)["object"], {"type": "commit", "sha": plan["commit"]}, "final tag")
    gh.call(["release", "edit", tag, "--draft=false", "--repo", REPO])
    matches(gh.get(f"releases/{release['id']}"), {"tag_name": tag, "draft": False}, "published release")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="Preserve a current-main candidate using GET requests")
    prep.add_argument("--commit", required=True)
    prep.add_argument("--run-id", required=True, type=int)
    prep.add_argument("--artifact-id", required=True, type=int)
    prep.add_argument("--qualification-notes", required=True, type=Path)
    prep.add_argument("--output", required=True, type=Path)
    commands.add_parser("verify", help="Revalidate local files and GitHub metadata using GET requests").add_argument("directory", type=Path)
    pub = commands.add_parser("publish", help="Create a tag and publish only the explicitly approved plan")
    pub.add_argument("directory", type=Path)
    pub.add_argument("--approve", required=True, metavar="PLAN_SHA256")
    args = parser.parse_args()
    gh = GitHub()
    try:
        if args.command == "prepare":
            result = prepare(gh, args.commit, args.run_id, args.artifact_id,
                             args.qualification_notes, args.output.absolute())
        elif args.command == "verify":
            _, result = verify(gh, args.directory.absolute())
        else:
            publish(gh, args.directory.absolute(), args.approve)
            result = "Published approved plan " + args.approve
        print(result)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, "release: " + str(error) + "\n")


if __name__ == "__main__":
    main()
