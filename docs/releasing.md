# Publish a qualified candidate

Use [scripts/release.py](../scripts/release.py) to preserve and publish one qualified candidate from `ueberBrot/mailctl`.
The helper uses Python 3.11 or newer and an authenticated GitHub CLI (`gh`).
It adds no publishing workflow.
The existing [CI workflow](../.github/workflows/ci.yml) builds candidates with dist 0.33.0.
The [release-plz workflow](../.github/workflows/release-plz.yml) prepares version and changelog changes with release-plz 0.3.171.

A plan records the exact commit, candidate, notes, and release assets.
Its SHA256 digest identifies the bytes that an operator approves.
`prepare` and `verify` use only GitHub GET requests and downloads.
They never execute a downloaded binary or installer.
Only `publish` creates a tag or changes a release.

## Preserve the candidate

Before preparation, merge the release-plz changes and wait for successful push CI on the current `main` commit.
The commit must contain a stable product version and a matching `CHANGELOG.md` entry.
The `native-credentials` job must pass and upload `mailctl-candidate-aarch64-apple-darwin`.
Save the candidate before its 14-day retention period ends.

1. Record the full lowercase SHA of current `main`, its successful CI run ID, and the candidate artifact ID.
2. Make sure that the run uses `.github/workflows/ci.yml`, the `push` event, and the current `main` SHA.
3. Write the qualification notes as JSON with the structure below.
4. Run `prepare` with a new local output directory.
5. Retain that entire directory in durable storage.

Use the actual values in this example.
`accepted_source_evidence` contains links to source evidence that an operator already accepted.
`association_notes` explains why that evidence applies to the exact downloaded candidate.
Include qualification limits and any required human review in those notes.
The helper checks the association fields and preserves the supplied bytes.
The operator must review the evidence and its association.
The helper does not establish live provider or agent harness qualification.

```json
{
  "operator": "Maintainer name",
  "source_commit": "FULL_40_CHARACTER_MAIN_SHA",
  "accepted_source_evidence": [
    "https://github.com/ueberBrot/mailctl/issues/ISSUE_NUMBER#issuecomment-COMMENT_ID"
  ],
  "artifact_association": {
    "commit": "FULL_40_CHARACTER_MAIN_SHA",
    "run_id": 123456,
    "run_attempt": 1,
    "artifact_id": 234567,
    "artifact_sha256": "sha256:FULL_64_CHARACTER_ZIP_SHA256"
  },
  "association_notes": "Explain the accepted source evidence, its limits, and its association with these exact candidate bytes."
}
```

```sh
python3.11 scripts/release.py prepare \
  --commit FULL_40_CHARACTER_MAIN_SHA \
  --run-id 123456 \
  --artifact-id 234567 \
  --qualification-notes /path/to/qualification-notes.json \
  --output /path/to/preserved-candidate
python3.11 scripts/release.py verify /path/to/preserved-candidate
```

Preparation saves the original ZIP, full API metadata, fixed source files, qualification notes, and all 20 candidate files.
It also saves `release-notes.md`, `plan.json`, and `PLAN_SHA256`.
The plan binds every asset name, size, and SHA256 digest.
It also binds the commit, version, run attempt, artifact ID, ZIP digest, source files, and both sets of notes.
If preparation fails, keep its partial output for diagnosis and use a new directory for the next preparation.

Both commands require the candidate artifact to remain available and unexpired on GitHub.
Local preservation protects the bytes from retention loss, but it does not extend publication eligibility.
If the artifact expires or `main` changes, prepare a new candidate from successful current-main CI.

## Review the plan

Read `plan.json`, `release-notes.md`, the qualification notes, and their linked evidence.
Make sure that the notes describe the exact candidate and retain the limits of the source evidence.
CI evidence covers disposable fixtures and records `real_provider=not-qualified` and `isolation=not-qualified`.
It cannot replace the separate source evidence that the operator accepts.

The helper requires exactly the 20 files emitted by [candidate.sh](../scripts/ci/candidate.sh).
`SHA256SUMS` must cover the other 19 files, including all acceptance logs and evidence.
All 20 become release assets without changes.
The helper checks clean build evidence, passing acceptance evidence, component metadata, archive checksums, and archived binary bytes.
It compares the installer, version, and changelog with source files fetched at the fixed commit.
Paths inside the dist manifest refer to the CI runner.
The helper uses recognized artifact basenames and never reads those runner paths.

GitHub artifact metadata does not contain a run attempt.
The helper uses jobs from the exact attempt and places artifact creation inside the successful candidate upload step.
This timestamp association rejects artifacts from earlier attempts.
The saved API metadata remains part of the approved plan.

## Publish after exact approval

Keep publication disabled until the operator explicitly approves the exact digest in `PLAN_SHA256`.
Approval of preparation, documentation, or a different digest does not authorize publication.
After that approval, pass the same digest to `--approve`:

```sh
python3.11 scripts/release.py publish /path/to/preserved-candidate \
  --approve EXACT_APPROVED_PLAN_SHA256
```

Publication repeats all local and remote checks before its first mutation.
It refuses existing tags, existing releases, and an earlier publication journal.
It creates `refs/tags/vVERSION` through the GitHub API with the approved commit SHA.
It creates a draft release with `gh release create --draft --verify-tag` and an explicit list of all 20 assets.
It compares the remote asset names, sizes, upload states, and API SHA256 digests with the plan.
Only after those comparisons pass does it run `gh release edit --draft=false`.

## Recover a partial publication

If publication fails, stop and preserve the plan directory and command output.
The local `publication-started.json` records that a publication attempt began.
A failure can leave only the tag or a draft release with some assets.
The helper leaves a partial draft unpublished and refuses automatic retries.
It never deletes, moves, replaces, or overwrites a tag or asset.

1. Inspect the exact tag target and any release through read-only GitHub views.
2. Compare every remote asset with the approved plan and record missing or mismatched files.
3. Ask the operator to approve a concrete manual recovery before any further mutation.
4. If the final publication request returned an error, inspect the remote draft state before deciding what remains.
5. Retain the original plan and journal as the record of the attempt.

Do not remove the journal to bypass the stop.
A new plan does not authorize changes to existing partial state.
An interrupted request can succeed remotely even when its local command reports failure.

## Test the helper offline

Run the fake GitHub boundary tests and command help before changing this procedure:

```sh
python3.11 tests/release.py
python3.11 scripts/release.py --help
python3.11 scripts/release.py prepare --help
python3.11 scripts/release.py verify --help
python3.11 scripts/release.py publish --help
```

The tests use local ZIP fixtures and simulated `gh` responses.
They perform no network requests, tag creation, release publication, or workflow dispatch.
Update the helper and fixtures together if the candidate format changes.

The GitHub contracts are documented in the official [artifact API](https://docs.github.com/en/rest/actions/artifacts),
[attempt jobs API](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[Git references API](https://docs.github.com/en/rest/git/refs#create-a-reference),
[release asset API](https://docs.github.com/en/rest/releases/assets#list-release-assets), and
[gh release create manual](https://cli.github.com/manual/gh_release_create).
