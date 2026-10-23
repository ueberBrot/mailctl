#!/usr/bin/env python3
"""Gate release-plz from original history and retain dependency release notes.

Requires Python 3.11+. `plan` writes only to its output directory and GitHub
Actions output files. `supplement` is the changelog postprocessor; it never
changes Git history, package versions, or publication state.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


DEPENDENCY_FILES = {"Cargo.toml", "Cargo.lock"}
SUBJECT = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^()\r\n]+)\))?(?P<breaking>!)?: (?P<summary>[^\r\n]+)$", re.I)
BREAKING = re.compile(r"^BREAKING[ -]CHANGE: .+", re.M | re.I)
REVERTED_COMMIT = re.compile(r"^This reverts commit ([0-9a-f]{40,64})[.,]", re.M)
MARKER = re.compile(r"<!-- mailctl-release-commits: ([^\r\n]*?) -->\n?")
SYNTHETIC = "<!-- mailctl-synthetic -->"
BUMP_RANK = {None: -1, "patch": 0, "minor": 1, "major": 2}


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return result.stdout


def paths(root, *args):
    return set(filter(None, git(root, *args).split("\0")))


def blob(root, revision, path):
    result = subprocess.run(["git", "show", f"{revision}:{path}"], cwd=root,
                            capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else ""


def dependency_changes_survive(root, commit, source, changed):
    """Do not describe a reverted dependency fix just because another one remains."""
    def state(revision, path):
        data = tomllib.loads(blob(root, revision, path))
        if path == "Cargo.lock":
            return {(p["name"], p["version"], p.get("source")): p for p in data.get("package", [])}

        def leaves(table, prefix=()):
            for key, value in table.items():
                if isinstance(value, dict):
                    yield from leaves(value, prefix + (key,))
                else:
                    yield prefix + (key,), value
        return dict(leaves(data))

    def runtime_requirements(state):
        return {key: value for key, value in state.items()
                if key[0] in {"dependencies", "build-dependencies"}
                or key[:2] == ("workspace", "dependencies")
                or (key[0] == "target" and len(key) > 2
                    and key[2] in {"dependencies", "build-dependencies"})}

    def survives(before, after, current):
        return any(before.get(key) != value and current.get(key) == value for key, value in after.items()) or any(
            key not in after and key not in current for key in before)

    # A surviving lock package might now be used only by a test dependency. An
    # original runtime requirement change must survive; unrelated manifest edits
    # must not suppress a still-present lockfile security upgrade.
    ordered_paths = sorted(changed, key=lambda path: path != "Cargo.toml")
    for path in ordered_paths:
        before, after, current = (state(revision, path) for revision in (commit + "^", commit, source))
        if path == "Cargo.toml":
            runtime_before, runtime_after, runtime_current = map(runtime_requirements, (before, after, current))
            if runtime_before != runtime_after:
                return survives(runtime_before, runtime_after, runtime_current)
        if survives(before, after, current):
            return True
    return False


def original_history(root, baseline, source):
    history = [(commit, git(root, "show", "--no-patch", "--format=%B", commit).rstrip("\n"))
               for commit in git(root, "rev-list", "--reverse", f"{baseline}..{source}").splitlines()]
    reverted = set()
    # Walk backwards so reverting a revert restores the original commit. Git's
    # explicit revert metadata applies to every file, including a source path
    # subsequently reused by formatting or other maintenance.
    for commit, message in reversed(history):
        if commit not in reverted:
            reverted.update(REVERTED_COMMIT.findall(message))
    return [(commit, message) for commit, message in history if commit not in reverted]


def group_for(message, breaking, config):
    for parser in config["changelog"]["commit_parsers"]:
        if re.search(parser.get("message", r"(?!)"), message):
            if parser.get("skip"):
                if breaking and config["changelog"].get("protect_breaking_commits"):
                    continue
                return None
            return parser.get("group", "other")
    return "other"


def prepare(root, output):
    """Plan eligibility from the released product tag, before crate filtering."""
    if git(root, "status", "--porcelain"):
        raise ValueError("Release preparation requires a clean checkout")
    config_path = root / "release-plz.toml"
    config_text = config_path.read_text()
    config = tomllib.loads(config_text)
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    baseline = "v" + version
    source = git(root, "rev-parse", "HEAD").strip()
    context = dict(format=1, eligible=False, source=source, baseline=baseline,
                   minimum_bump=None, notes=[])
    # An approved release PR has a new manifest version before publication makes
    # its tag. Do not prepare another version while that release is pending.
    tags = git(root, "tag", "--merged", source, "--list", baseline).splitlines()
    if baseline in tags:
        net_paths = paths(root, "diff", "--no-renames", "--name-only", "-z", baseline, source, "--")
        trigger = re.compile(config["workspace"]["release_commits"])
        major = int(version.split(".")[0])
        for commit, message in original_history(root, baseline, source):
            changed = paths(root, "diff-tree", "--root", "--no-commit-id", "--no-renames",
                            "--name-only", "-r", "-z", commit)
            if not trigger.search(message) or not changed.intersection(net_paths):
                continue
            if changed.issubset(DEPENDENCY_FILES) and not dependency_changes_survive(root, commit, source, changed):
                continue
            subject = SUBJECT.fullmatch(message.splitlines()[0])
            fields = subject.groupdict() if subject else {}
            breaking = bool(fields.get("breaking") or BREAKING.search(message))
            kind = (fields.get("type") or "").lower()
            bump = "patch"
            if breaking:
                bump = "major" if major else "minor"
            elif kind == "feat" and (major or config["workspace"].get("features_always_increment_minor", False)):
                bump = "minor"
            if BUMP_RANK[bump] > BUMP_RANK[context["minimum_bump"]]:
                context["minimum_bump"] = bump
            context["eligible"] = True
            if changed.issubset(DEPENDENCY_FILES):
                group = group_for(message, breaking, config)
                if group:
                    context["notes"].append(dict(sha=commit, summary=fields.get("summary", message.splitlines()[0]),
                                                 scope=fields.get("scope"), group=group,
                                                 breaking=breaking, paths=sorted(changed)))
    # Crate filtering can also discard a dependency-only feature or breaking
    # marker. Preserve the original history's minimum increment using a supported
    # release-plz override in a temporary config, not an artificial source commit.
    if context["minimum_bump"] in ("minor", "major"):
        key = "custom_" + context["minimum_bump"] + "_increment_regex"
        if key in config["workspace"] or any(key in p for p in config.get("package", [])):
            raise ValueError("Release preparation must reconcile the existing " + key)
        config_text = config_text.replace("[workspace]\n", f'[workspace]\n{key} = ".*"\n', 1)
    # Eligibility is already decided from complete history. Applying the gate a
    # second time to filtered crate commits would suppress lockfix + docs releases.
    config_text = re.sub(r"(?m)^release_commits\s*=.*$", 'release_commits = ".*"', config_text)
    output.mkdir(parents=True, exist_ok=True)
    (output / "context.json").write_text(json.dumps(context, sort_keys=True) + "\n")
    (output / "release-plz.toml").write_text(config_text)
    return context


def note_line(note):
    summary = re.sub(r"\(#(\d+)\)", r"([#\1](https://github.com/ueberBrot/mailctl/pull/\1))", note["summary"])
    scope = f'*({note["scope"]})* ' if note.get("scope") and note["scope"] != note["group"] else ""
    breaking = "[**breaking**] " if note["breaking"] else ""
    return "- " + scope + breaking + summary


def supplement(text, context):
    """Restore dependency notes omitted by release-plz, deduplicated by SHA."""
    if context.get("format") != 1:
        raise ValueError("Unsupported release preparation context")
    markers = list(MARKER.finditer(text))
    if len(markers) != 1:
        raise ValueError("Expected exactly one release commit metadata marker")
    native_ids = set(markers[0].group(1).split())
    if any(not re.fullmatch(r"[0-9a-f]{7,64}", commit) for commit in native_ids):
        raise ValueError("Invalid release commit metadata")
    text = MARKER.sub("", text)
    missing = {note["sha"]: note for note in context["notes"] if note["sha"] not in native_ids}
    # Use actual commit notes in place of the exact synthetic dependency entry;
    # retain every unrelated entry and every existing section's content.
    dependency_files = {path for note in missing.values() for path in note["paths"]}
    for path in dependency_files:
        text = re.sub(r"(?m)^- " + re.escape(SYNTHETIC) + "update " + re.escape(path)
                      + r" dependencies[ \t]*$\n?", "", text)
    text = text.replace(SYNTHETIC, "")
    if not missing:
        return text
    parts = re.split(r"(?m)^### ([^\n]+)\n", text)
    sections = {parts[i]: parts[i + 1].strip() for i in range(1, len(parts), 2)}
    for note in missing.values():
        title = note["group"][0].upper() + note["group"][1:]
        sections[title] = (sections.get(title, "") + "\n" + note_line(note)).strip()
    result = [parts[0].rstrip()]
    result.extend("### " + title + "\n\n" + body for title, body in sections.items() if body)
    return "\n\n".join(result) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan").add_argument("--output", type=Path, required=True)
    commands.add_parser("supplement")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.command == "plan":
            output = args.output.absolute()
            context = prepare(root, output)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as target:
                    target.write(f'release={str(context["eligible"]).lower()}\nconfig={output / "release-plz.toml"}\n')
            if os.environ.get("GITHUB_ENV"):
                with open(os.environ["GITHUB_ENV"], "a") as target:
                    target.write("MAILCTL_RELEASE_CONTEXT=" + json.dumps(context) + "\n")
            print("Release eligible:", context["eligible"], "since", context["baseline"])
        else:
            context = json.loads(os.environ["MAILCTL_RELEASE_CONTEXT"])
            if git(root, "rev-parse", "HEAD").strip() != context["source"]:
                raise ValueError("Release preparation context does not match the source commit")
            sys.stdout.write(supplement(sys.stdin.read(), context))
    except (ValueError, KeyError, OSError) as error:
        sys.exit("release preparation: " + str(error))


if __name__ == "__main__":
    main()
