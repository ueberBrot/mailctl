#!/usr/bin/env python3
"""Check release policy with disposable Git history and offline release-plz.

Run with Python 3.11 or later. ``--integration`` requires release-plz 0.3.171
on PATH or at MAILCTL_RELEASE_PLZ; without it, unavailable integration checks
are skipped. Cargo resolves only the tiny vendored fixture dependency.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("prepare_release", ROOT / "scripts/prepare-release.py")
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)
RELEASE_PLZ_VERSION = "0.3.171"
RELEASE_PLZ = None
RELEASE_DATE = "2026-10-21"


def run(root, *arguments, env=None, input=None):
    result = subprocess.run([str(argument) for argument in arguments], cwd=root,
                            env=env, input=input, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise AssertionError(f"Command failed ({result.returncode}): {' '.join(map(str, arguments))}\n"
                             + result.stdout + result.stderr)
    return result.stdout


class Repository:
    """A committed product and its published tag, independent of the real repo."""

    def __init__(self, directory, version="0.1.0", cargo=False):
        self.root = directory / "repo"
        self.root.mkdir(parents=True)
        self.output = directory / "preparation"
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT="0", CARGO_NET_OFFLINE="true",
                        CARGO_TARGET_DIR=str(directory / "target"))
        # The configured postprocessor calls python3. Use the interpreter running
        # this suite, including on macOS where /usr/bin/python3 is too old.
        launcher = directory / "bin"
        launcher.mkdir()
        (launcher / "python3").symlink_to(sys.executable)
        self.env["PATH"] = str(launcher) + os.pathsep + self.env.get("PATH", "")
        self.write("Cargo.toml", f'''[workspace]
members = ["."]
[workspace.package]
version = "{version}"
[package]
name = "mailctl"
version.workspace = true
edition = "2024"
publish = false
exclude = ["vendor"]
[dependencies]
tls-fixture = "0.1"
''')
        self.write("src/main.rs", "fn main() {}\n")
        self.write("README.md", "Original documentation.\n")
        self.write("CHANGELOG.md", f"# Changelog\n\n## [{version}] - 2026-10-20\n\nInitial release.\n")
        # Include the real policy and postprocessor in the tagged baseline so
        # their introduction cannot itself make a fixture release eligible.
        self.write("release-plz.toml", (ROOT / "release-plz.toml").read_text())
        self.write("scripts/prepare-release.py", (ROOT / "scripts/prepare-release.py").read_text())
        if cargo:
            self.vendor_dependencies()
            self.command("cargo", "generate-lockfile", "--offline")
            self.lock_version("0.1.0")
        else:
            self.write("Cargo.lock", '''version = 4

[[package]]
name = "mailctl"
version = "''' + version + '''"
dependencies = ["tls-fixture"]

[[package]]
name = "tls-fixture"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "''' + "0" * 64 + '''"
''')
        self.command("git", "init", "--initial-branch=main")
        self.command("git", "config", "user.name", "Release fixture")
        self.command("git", "config", "user.email", "release-fixture@example.invalid")
        self.command("git", "config", "commit.gpgsign", "false")
        self.command("git", "config", "core.hooksPath", str(directory / "no-hooks"))
        self.command("git", "config", "core.autocrlf", "false")
        self.commit("chore: initial release")
        self.command("git", "tag", "v" + version)
        self.command("git", "remote", "add", "origin", "https://github.com/ueberBrot/mailctl")

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def command(self, *arguments):
        return run(self.root, *arguments, env=self.env)

    def commit(self, message, changes=None):
        for name, contents in (changes or {}).items():
            self.write(name, contents)
        self.command("git", "add", ".")
        self.command("git", "commit", "-m", message)
        return self.command("git", "rev-parse", "HEAD").strip()

    def vendor_dependencies(self):
        self.write(".cargo/config.toml", '''[source.crates-io]
replace-with = "fixtures"
[source.fixtures]
directory = "vendor"
''')
        for version in ("0.1.0", "0.1.1"):
            name = "vendor/tls-fixture-" + version
            self.write(name + "/Cargo.toml", f'''[package]
name = "tls-fixture"
version = "{version}"
edition = "2024"
''')
            self.write(name + "/src/lib.rs", "pub fn verify() {}\n")
            self.write(name + "/.cargo-checksum.json", json.dumps({"files": {}, "package": "0" * 64}))

    def lock_version(self, version):
        # Cargo's directory source ignores --precise here. Select the fixture
        # lock entry explicitly, then require Cargo to accept it unchanged.
        lock = self.root / "Cargo.lock"
        lock.write_text(re.sub(r'(name = "tls-fixture"\nversion = ")[^"]+',
                               lambda match: match.group(1) + version, lock.read_text()))
        self.command("cargo", "metadata", "--offline", "--locked", "--format-version", "1")

    def dependency_change(self):
        return (self.root / "Cargo.lock").read_text().replace(
            'name = "tls-fixture"\nversion = "0.1.0"',
            'name = "tls-fixture"\nversion = "0.1.1"')

    def plan(self):
        return preparation.prepare(self.root, self.output)

    def tracked_files(self):
        return {name: (self.root / name).read_bytes() for name in
                self.command("git", "ls-files", "-z").split("\0") if name}

    def version(self):
        return tomllib.loads((self.root / "Cargo.toml").read_text())["workspace"]["package"]["version"]


class RepositoryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mailctl-release-preparation-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.repository_count = 0

    def repository(self, version="0.1.0", cargo=False):
        self.repository_count += 1
        return Repository(self.directory / str(self.repository_count), version, cargo)

    def assert_preparation_keeps_source(self, repository):
        before = repository.tracked_files()
        head = repository.command("git", "rev-parse", "HEAD").strip()
        context = repository.plan()
        self.assertEqual(repository.tracked_files(), before)
        self.assertEqual(repository.command("git", "status", "--porcelain"), "")
        self.assertEqual(context["source"], head)
        self.assertEqual(context["format"], 1)
        self.assertEqual(json.loads((repository.output / "context.json").read_text()), context)
        self.assertTrue((repository.output / "release-plz.toml").is_file())
        return context


class ReleasePreparationTest(RepositoryTest):
    def test_docs_only_do_not_prepare_a_release_or_modify_the_product(self):
        repository = self.repository()
        repository.commit("docs: explain setup (#100)", {"README.md": "Updated documentation.\n"})
        context = self.assert_preparation_keeps_source(repository)
        self.assertFalse(context["eligible"])
        self.assertEqual(context["baseline"], "v0.1.0")
        self.assertIsNone(context["minimum_bump"])
        self.assertEqual(context["notes"], [])

    def test_release_types_accept_optional_scopes(self):
        for message in ("feat: add reader", "feat(cli): add reader", "fix: repair reader",
                        "fix(imap): repair reader", "perf(imap): reduce allocations",
                        "refactor(cli): simplify reading", "revert: restore reading"):
            with self.subTest(message=message):
                repository = self.repository()
                repository.commit(message, {"src/main.rs": "fn main() { println!(\"changed\"); }\n"})
                context = repository.plan()
                self.assertTrue(context["eligible"])
                self.assertEqual(context["notes"], [])

    def test_maintenance_and_conventional_examples_in_docs_do_not_release(self):
        for message in ("docs: update setup\n\nExample commit:\nfix: repair the reader",
                        "test(imap): exercise reading", "style: format sources",
                        "ci: refresh workflow", "chore: clean fixtures", "build: update tools",
                        "build(tooling): update tools", "chore(deps-dev): update tools"):
            with self.subTest(message=message):
                repository = self.repository()
                repository.commit(message, {"README.md": "Updated documentation.\n"})
                self.assertFalse(repository.plan()["eligible"])

    def test_breaking_docs_and_ci_release_with_bang_or_footer(self):
        for message in ("docs!: remove old setup", "ci(publish)!: require a new runner",
                        "docs: change setup\n\nBREAKING CHANGE: use the new setup",
                        "ci: change runner\n\nBREAKING-CHANGE: use the new runner"):
            with self.subTest(message=message):
                repository = self.repository()
                repository.commit(message, {"README.md": "New required setup.\n"})
                context = repository.plan()
                self.assertTrue(context["eligible"])
                self.assertEqual(context["minimum_bump"], "minor")

    def test_dependency_scopes_release_and_retain_authentic_notes(self):
        for kind in ("build", "chore"):
            with self.subTest(kind=kind):
                repository = self.repository()
                sha = repository.commit(f"{kind}(deps): update TLS (#101)",
                                        {"Cargo.lock": repository.dependency_change()})
                context = repository.plan()
                self.assertTrue(context["eligible"])
                self.assertEqual(context["minimum_bump"], "patch")
                self.assertEqual(len(context["notes"]), 1)
                note = context["notes"][0]
                self.assertEqual(note["sha"], sha)
                self.assertEqual(note["summary"], "update TLS (#101)")
                self.assertEqual(note["scope"], "deps")
                self.assertEqual(note["group"], "dependencies")
                self.assertFalse(note["breaking"])
                self.assertEqual(note["paths"], ["Cargo.lock"])

    def test_security_group_precedes_generic_fixes_and_mixed_changes_stay_native(self):
        repository = self.repository()
        sha = repository.commit("fix(security): update certificate verification (#101)",
                                {"Cargo.lock": repository.dependency_change()})
        repository.commit("fix(cli): repair rendering (#102)",
                          {"Cargo.toml": (repository.root / "Cargo.toml").read_text() + "\n# rendering\n",
                           "src/main.rs": "fn main() { println!(\"fixed\"); }\n"})
        context = repository.plan()
        self.assertEqual(context["notes"], [{"sha": sha,
                         "summary": "update certificate verification (#101)", "scope": "security",
                         "group": "security", "breaking": False, "paths": ["Cargo.lock"]}])

    def test_manifest_only_notes_are_retained(self):
        repository = self.repository()
        sha = repository.commit("build(deps): require newer TLS (#103)",
                                {"Cargo.toml": (repository.root / "Cargo.toml").read_text().replace(
                                    'tls-fixture = "0.1"', 'tls-fixture = "0.1.1"')})
        context = repository.plan()
        self.assertTrue(context["eligible"])
        self.assertEqual([(note["sha"], note["paths"]) for note in context["notes"]],
                         [(sha, ["Cargo.toml"])])

    def test_published_commits_are_excluded_from_the_current_release_range(self):
        repository = self.repository()
        repository.commit("fix(security): already published (#99)",
                          {"Cargo.lock": repository.dependency_change()})
        repository.command("git", "tag", "--force", "v0.1.0")
        repository.commit("docs: explain setup", {"README.md": "Updated documentation.\n"})
        context = repository.plan()
        self.assertFalse(context["eligible"])
        self.assertEqual(context["notes"], [])

    def test_reverted_lock_change_does_not_release_even_with_other_net_changes(self):
        repository = self.repository()
        sha = repository.commit("fix(security): update TLS (#101)",
                                {"Cargo.lock": repository.dependency_change()})
        repository.command("git", "revert", "--no-edit", sha)
        repository.commit("docs: explain setup", {"README.md": "Updated documentation.\n"})
        context = repository.plan()
        self.assertFalse(context["eligible"])
        self.assertEqual(context["notes"], [])

    def test_reverted_manifest_and_lock_fix_does_not_release_later_development_updates(self):
        repository = self.repository()
        manifest = (repository.root / "Cargo.toml").read_text()
        lock = (repository.root / "Cargo.lock").read_text()
        sha = repository.commit("fix(security): require verified TLS (#101)", {
            "Cargo.toml": manifest.replace('tls-fixture = "0.1"', 'tls-fixture = "0.1.1"'),
            "Cargo.lock": repository.dependency_change()})
        repository.command("git", "revert", "--no-edit", sha)
        repository.commit("chore(deps-dev): refresh test dependencies (#102)", {
            "Cargo.toml": manifest + '\n[dev-dependencies]\ntest-fixture = "0.1"\n',
            "Cargo.lock": lock + '\n[[package]]\nname = "test-fixture"\nversion = "0.1.0"\n'})
        context = self.assert_preparation_keeps_source(repository)
        self.assertFalse(context["eligible"])
        self.assertIsNone(context["minimum_bump"])
        self.assertEqual(context["notes"], [])

    def test_manifest_ahead_of_published_tag_waits_for_publication(self):
        repository = self.repository()
        repository.commit("chore: prepare mailctl v0.1.1", {
            "Cargo.toml": (repository.root / "Cargo.toml").read_text().replace(
                'version = "0.1.0"', 'version = "0.1.1"')})
        repository.commit("fix: repair reading", {"src/main.rs": "fn main() { println!(\"fixed\"); }\n"})
        context = self.assert_preparation_keeps_source(repository)
        self.assertEqual(context["baseline"], "v0.1.1")
        self.assertFalse(context["eligible"])
        self.assertIsNone(context["minimum_bump"])
        self.assertEqual(context["notes"], [])

    def test_runtime_fix_is_not_retained_by_the_same_package_in_test_dependencies(self):
        repository = self.repository()
        manifest = (repository.root / "Cargo.toml").read_text()
        lock = (repository.root / "Cargo.lock").read_text()
        new_package = lock[lock.index('[[package]]\nname = "tls-fixture"'):].replace(
            'version = "0.1.0"', 'version = "0.2.0"')
        repository.commit("fix(security)!: require new TLS", {
            "Cargo.toml": manifest.replace('tls-fixture = "0.1"', 'tls-fixture = "0.2"'),
            "Cargo.lock": lock.replace('version = "0.1.0"\nsource', 'version = "0.2.0"\nsource')})
        # A manual reversal also needs manifest attribution, rather than merely
        # finding the upgraded package anywhere in the final lockfile.
        repository.commit("chore: restore previous runtime TLS", {"Cargo.toml": manifest, "Cargo.lock": lock})
        repository.commit("chore(deps-dev): exercise new TLS", {
            "Cargo.toml": manifest + '\n[dev-dependencies]\ntest-tls = { package = "tls-fixture", version = "0.2" }\n',
            "Cargo.lock": lock + '\n' + new_package})
        context = repository.plan()
        self.assertFalse(context["eligible"])
        self.assertIsNone(context["minimum_bump"])
        self.assertEqual(context["notes"], [])

    def test_reverting_a_revert_restores_release_eligibility(self):
        repository = self.repository()
        original = repository.commit("fix: repair reading", {"src/main.rs": 'fn main() { println!("fixed"); }\n'})
        repository.command("git", "revert", "--no-edit", original)
        reversal = repository.command("git", "rev-parse", "HEAD").strip()
        repository.command("git", "revert", "--no-edit", reversal)
        context = repository.plan()
        self.assertTrue(context["eligible"])
        self.assertEqual(context["minimum_bump"], "patch")

    def test_reversing_test_dependencies_keeps_a_surviving_lockfile_security_fix(self):
        repository = self.repository()
        manifest = (repository.root / "Cargo.toml").read_text()
        original = repository.commit("fix(security): update TLS with regression coverage", {
            "Cargo.toml": manifest + '\n[dev-dependencies]\ntest-fixture = "0.1"\n',
            "Cargo.lock": repository.dependency_change()})
        repository.commit("test: remove unused fixture dependency", {"Cargo.toml": manifest})
        context = repository.plan()
        self.assertTrue(context["eligible"])
        self.assertEqual(context["minimum_bump"], "patch")
        self.assertEqual([note["sha"] for note in context["notes"]], [original])

    def test_dependency_only_breaking_change_keeps_its_minimum_bump(self):
        for version, message, bump in (
                ("0.1.0", "fix(security)!: require verified TLS (#101)", "minor"),
                ("1.0.0", "feat(deps): expose new TLS support (#101)", "minor"),
                ("1.0.0", "fix(security)!: require verified TLS (#101)", "major"),
                ("0.1.0", "chore: update TLS\n\nBREAKING CHANGE: require verified TLS", "minor")):
            with self.subTest(version=version, message=message):
                repository = self.repository(version)
                repository.commit(message, {"Cargo.lock": repository.dependency_change()})
                context = repository.plan()
                self.assertTrue(context["eligible"])
                self.assertEqual(context["minimum_bump"], bump)
                self.assertEqual(len(context["notes"]), 1)
                self.assertEqual(context["notes"][0]["breaking"], "BREAKING" in message or "!:" in message)


def note(sha="a" * 40, summary="update certificate verification (#101)", **fields):
    return dict(sha=sha, summary=summary, scope="security", group="security",
                breaking=False, paths=["Cargo.lock"]) | fields


def context(*notes):
    return dict(format=1, eligible=True, source="f" * 40, baseline="v0.1.0",
                minimum_bump="patch", notes=list(notes))


def marker(*shas):
    return "<!-- mailctl-release-commits: " + " ".join(shas) + " -->\n"


class ChangelogSupplementTest(unittest.TestCase):
    def test_redundant_scopes_are_omitted_but_other_scopes_and_markers_survive(self):
        for scope, group, title, prefix in (
                ("security", "security", "Security", ""),
                ("drafts", "fixed", "Fixed", "*(drafts)* "),
                ("deps", "dependencies", "Dependencies", "*(deps)* ")):
            for breaking in (False, True):
                with self.subTest(scope=scope, breaking=breaking):
                    rendered = "## [0.1.1] - 2026-10-21\n\n"
                    text = preparation.supplement(rendered + marker(), context(
                        note(scope=scope, group=group, breaking=breaking)))
                    expected = (rendered + "### " + title + "\n\n- " + prefix
                                + ("[**breaking**] " if breaking else "")
                                + "update certificate verification "
                                "([#101](https://github.com/ueberBrot/mailctl/pull/101))\n")
                    self.assertEqual(text, expected)

    def test_native_commit_ids_prevent_duplicate_notes(self):
        rendered = "## [0.1.1] - 2026-10-21\n\n### Security\n\n- Original native note (#101)\n"
        text = preparation.supplement(rendered + marker("a" * 40), context(note()))
        self.assertEqual(text, rendered)
        self.assertNotIn("mailctl-release-commits", text)

    def test_missing_notes_join_existing_sections_and_preserve_unrelated_notes(self):
        rendered = ("## [0.1.1] - 2026-10-21\n\n### Security\n\n- Existing security note\n"
                    "\n### Documentation\n\n- Explain setup (#100)\n")
        text = preparation.supplement(rendered + marker("c" * 40), context(
            note(), note("b" * 40, "prevent downgrade (#102)")))
        self.assertEqual(text.count("### Security"), 1)
        self.assertEqual(text.count("update certificate verification"), 1)
        self.assertEqual(text.count("prevent downgrade"), 1)
        self.assertIn("- Existing security note", text)
        self.assertIn("### Documentation\n\n- Explain setup (#100)", text)
        self.assertIn("[#101](https://github.com/ueberBrot/mailctl/pull/101)", text)
        self.assertNotIn("mailctl-release-commits", text)

    def test_synthetic_dependency_fallbacks_and_empty_sections_are_removed(self):
        for filename in ("Cargo.lock", "Cargo.toml"):
            with self.subTest(filename=filename):
                rendered = ("## [0.1.1] - 2026-10-21\n\n### Dependencies\n\n"
                            f"- <!-- mailctl-synthetic -->update {filename} dependencies\n"
                            "\n### Documentation\n\n- Explain setup\n")
                text = preparation.supplement(rendered + marker(), context(note(paths=[filename])))
                self.assertNotIn(f"- update {filename} dependencies\n", text)
                self.assertNotIn("### Dependencies", text)
                self.assertIn("### Documentation\n\n- Explain setup", text)
                self.assertIn("### Security", text)

    def test_native_fixed_dependency_summary_survives_synthetic_fallback_replacement(self):
        rendered = ("## [0.1.1] - 2026-10-21\n\n### Fixed\n\n"
                    "- update Cargo.lock dependencies\n"
                    "\n### Dependencies\n\n"
                    "- <!-- mailctl-synthetic -->update Cargo.lock dependencies\n")
        text = preparation.supplement(rendered + marker("b" * 40, "0000000"), context(note()))
        self.assertIn("### Fixed\n\n- update Cargo.lock dependencies\n", text)
        self.assertEqual(text.count("- update Cargo.lock dependencies"), 1)
        self.assertNotIn("### Dependencies", text)
        self.assertIn("### Security", text)
        self.assertEqual(text.count("update certificate verification"), 1)
        self.assertIn("[#101](https://github.com/ueberBrot/mailctl/pull/101)", text)
        self.assertNotIn("mailctl-synthetic", text)
        self.assertNotIn("mailctl-release-commits", text)

    def test_unrelated_synthetic_looking_notes_are_preserved(self):
        rendered = ("## [0.1.1] - 2026-10-21\n\n### Other\n\n"
                    "- update Cargo.lock dependencies carefully\n- Unrelated maintenance\n")
        text = preparation.supplement(rendered + marker(), context(note()))
        self.assertIn("- update Cargo.lock dependencies carefully", text)
        self.assertIn("- Unrelated maintenance", text)

    def test_native_and_duplicate_context_shas_restore_only_one_missing_note(self):
        native = note()
        missing = note("b" * 40, "prevent downgrade (#102)", breaking=True)
        rendered = ("## [0.1.1] - 2026-10-21\n\n### Security\n\n"
                    "- update certificate verification (#101)\n")
        text = preparation.supplement(rendered + marker(native["sha"]), context(native, missing, missing))
        self.assertEqual(text.count("update certificate verification"), 1)
        self.assertEqual(text.count("prevent downgrade"), 1)
        self.assertIn("[**breaking**]", text)

    def test_marker_is_removed_without_supplemental_notes(self):
        rendered = "## [0.1.1] - 2026-10-21\n\n### Fixed\n\n- Repair reading\n"
        self.assertEqual(preparation.supplement(rendered + marker(), context()), rendered)

    def test_missing_or_invalid_native_metadata_fails(self):
        for metadata in ("", "<!-- mailctl-release-commits: invalid -->\n",
                         "<!-- mailctl-release-commits: " + "a" * 40 + "\n",
                         marker() + marker()):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValueError):
                    preparation.supplement("## [0.1.1]\n" + metadata, context(note()))


class ReleasePlzIntegrationTest(RepositoryTest):
    @classmethod
    def setUpClass(cls):
        if not RELEASE_PLZ:
            raise unittest.SkipTest("release-plz 0.3.171 unavailable; use --integration to require it")
        version = run(ROOT, RELEASE_PLZ, "--version").strip()
        if version != "release-plz " + RELEASE_PLZ_VERSION:
            raise AssertionError(f"Expected release-plz {RELEASE_PLZ_VERSION}, found {version!r}")

    def update(self, repository):
        context = self.assert_preparation_keeps_source(repository)
        if context["eligible"]:
            env = dict(repository.env, MAILCTL_RELEASE_CONTEXT=json.dumps(context))
            run(repository.root, RELEASE_PLZ, "update", "--config",
                repository.output / "release-plz.toml", "--release-date", RELEASE_DATE, env=env)
        return context

    def release_notes(self, repository, version, previous="0.1.0"):
        changelog = (repository.root / "CHANGELOG.md").read_text()
        heading = re.search(r"(?m)^## \[" + re.escape(version) + r"\].* - " + RELEASE_DATE + "$", changelog)
        self.assertIsNotNone(heading, changelog)
        notes = changelog[heading.start():].split("\n## [" + previous + "]", 1)[0]
        self.assertNotIn("mailctl-release-commits", notes)
        self.assertNotIn("mailctl-synthetic", notes)
        self.assertNotIn("- update Cargo.lock dependencies", notes)
        return notes

    def assert_section_contains(self, notes, section, summary):
        match = re.search(r"(?ms)^### " + re.escape(section) + r"\n(.*?)(?=^### |\Z)", notes)
        self.assertIsNotNone(match, notes)
        self.assertIn(summary, match.group(1))

    def test_docs_and_release_automation_do_not_start_a_release(self):
        for message, path in (("docs: improve README (#100)", "README.md"),
                              ("ci(release): repair release preparation", "scripts/prepare-release.py")):
            with self.subTest(message=message):
                repository = self.repository(cargo=True)
                repository.commit(message, {path: (repository.root / path).read_text() + "\n# Updated guidance.\n"})
                before = repository.tracked_files()
                self.assertFalse(self.update(repository)["eligible"])
                self.assertEqual(repository.version(), "0.1.0")
                self.assertEqual(repository.tracked_files(), before)

    def test_reverted_source_fix_followed_by_style_does_not_release(self):
        repository = self.repository(cargo=True)
        original = repository.commit("fix: repair reading", {"src/main.rs": 'fn main() { println!("fixed"); }\n'})
        repository.command("git", "revert", "--no-edit", original)
        repository.commit("style: format source", {"src/main.rs": "fn main() {\n}\n"})
        before = repository.tracked_files()
        self.assertFalse(self.update(repository)["eligible"])
        self.assertEqual(repository.version(), "0.1.0")
        self.assertEqual(repository.tracked_files(), before)

    def test_native_scopes_omit_section_names_and_preserve_links_and_breaking_markers(self):
        for kind, scope, section, prefix in (
                ("fix", "security", "Security", ""),
                ("fix", "drafts", "Fixed", "*(drafts)* "),
                ("chore", "deps", "Dependencies", "*(deps)* ")):
            for breaking in (False, True):
                with self.subTest(scope=scope, breaking=breaking):
                    repository = self.repository(cargo=True)
                    subject = f"{kind}({scope}){'!' if breaking else ''}: improve reading (#107)"
                    repository.commit(subject, {"src/main.rs": 'fn main() { println!("fixed"); }\n'})
                    context = self.update(repository)
                    self.assertTrue(context["eligible"])
                    self.assertEqual(context["notes"], [])
                    version = "0.2.0" if breaking else "0.1.1"
                    self.assertEqual(repository.version(), version)
                    notes = self.release_notes(repository, version)
                    expected = "- " + prefix + ("[**breaking**] " if breaking else "") + "improve reading"
                    self.assert_section_contains(notes, section, expected)
                    self.assertNotIn("*(security)*", notes)
                    self.assertIn("[#107](https://github.com/ueberBrot/mailctl/pull/107)", notes)
                    self.assertEqual(notes.count("#107"), 1)

    def test_lock_only_security_fix_keeps_authentic_security_note(self):
        repository = self.repository(cargo=True)
        repository.lock_version("0.1.1")
        repository.commit("fix(security): update certificate verification (#101)")
        self.assertTrue(self.update(repository)["eligible"])
        self.assertEqual(repository.version(), "0.1.1")
        notes = self.release_notes(repository, "0.1.1")
        self.assert_section_contains(notes, "Security", "- update certificate verification")
        self.assertNotIn("*(security)*", notes)
        self.assertEqual(notes.count("#101"), 1)
        self.assertIn("https://github.com/ueberBrot/mailctl/pull/101", notes)

    def test_lock_only_security_fix_and_docs_both_reach_the_changelog(self):
        repository = self.repository(cargo=True)
        repository.lock_version("0.1.1")
        repository.commit("fix(security): update certificate verification (#101)")
        repository.commit("docs: improve README (#100)", {"README.md": "Updated documentation.\n"})
        self.assertTrue(self.update(repository)["eligible"])
        self.assertEqual(repository.version(), "0.1.1")
        notes = self.release_notes(repository, "0.1.1")
        self.assert_section_contains(notes, "Security", "update certificate verification")
        self.assert_section_contains(notes, "Documentation", "improve README")
        self.assertEqual(notes.count("#101"), 1)
        self.assertEqual(notes.count("#100"), 1)

    def test_lock_only_security_fix_survives_packaged_routine_commits(self):
        for message, changes, routine_summary in (
                ("style: format source (#104)", {"src/main.rs": "fn main() {\n}\n"}, "format source"),
                ("ci: document fixture checks (#105)", {"README.md": "Run fixture checks.\n"},
                 "document fixture checks")):
            with self.subTest(message=message):
                repository = self.repository(cargo=True)
                repository.lock_version("0.1.1")
                sha = repository.commit("fix(security): update certificate verification (#101)")
                repository.commit(message, changes)
                context = self.update(repository)
                self.assertTrue(context["eligible"])
                self.assertEqual([entry["sha"] for entry in context["notes"]], [sha])
                self.assertEqual(repository.version(), "0.1.1")
                notes = self.release_notes(repository, "0.1.1")
                self.assert_section_contains(notes, "Security", "update certificate verification")
                self.assertEqual(notes.count("#101"), 1)
                self.assertIn("https://github.com/ueberBrot/mailctl/pull/101", notes)
                self.assertNotIn(routine_summary, notes)
                self.assertNotIn("### Other", notes)

    def test_lock_only_breaking_change_bumps_pre_one_minor(self):
        repository = self.repository(cargo=True)
        repository.lock_version("0.1.1")
        repository.commit("fix(security)!: require verified certificates (#102)")
        self.assertEqual(self.update(repository)["minimum_bump"], "minor")
        self.assertEqual(repository.version(), "0.2.0")
        notes = self.release_notes(repository, "0.2.0")
        self.assert_section_contains(notes, "Security", "- [**breaking**] require verified certificates")
        self.assertNotIn("*(security)*", notes)
        self.assertIn("[#102](https://github.com/ueberBrot/mailctl/pull/102)", notes)

    def test_lock_only_feature_bumps_post_one_minor(self):
        repository = self.repository(version="1.0.0", cargo=True)
        repository.lock_version("0.1.1")
        repository.commit("feat(deps): expose new TLS support (#103)")
        self.assertEqual(self.update(repository)["minimum_bump"], "minor")
        self.assertEqual(repository.version(), "1.1.0")
        notes = self.release_notes(repository, "1.1.0", "1.0.0")
        self.assert_section_contains(notes, "Added", "- *(deps)* expose new TLS support")
        self.assertIn("[#103](https://github.com/ueberBrot/mailctl/pull/103)", notes)

    def test_lock_only_breaking_change_bumps_post_one_major(self):
        repository = self.repository(version="1.0.0", cargo=True)
        repository.lock_version("0.1.1")
        repository.commit("fix(security)!: require verified certificates (#102)")
        self.assertEqual(self.update(repository)["minimum_bump"], "major")
        self.assertEqual(repository.version(), "2.0.0")
        notes = self.release_notes(repository, "2.0.0", "1.0.0")
        self.assert_section_contains(notes, "Security", "require verified certificates")
        self.assertIn("[**breaking**]", notes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true", help="require the pinned release-plz CLI")
    arguments, unittest_arguments = parser.parse_known_args()
    RELEASE_PLZ = shutil.which(os.environ.get("MAILCTL_RELEASE_PLZ", "release-plz"))
    if arguments.integration and not RELEASE_PLZ:
        parser.error("--integration requires release-plz 0.3.171 on PATH or at MAILCTL_RELEASE_PLZ")
    unittest.main(argv=[sys.argv[0], *unittest_arguments], verbosity=2)
