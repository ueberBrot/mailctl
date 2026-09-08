## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues for `ueberBrot/mailctl`. Before tracker operations, read `docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels. Before triaging or applying triage labels, read `docs/agents/triage-labels.md`.

### Domain docs

Before exploring the codebase or creating or editing `CONTEXT.md` or an ADR, read `docs/agents/domain.md`.

### Testing

Use compile-time fixtures to verify the published type contract. Reserve runtime tests for behavior that can fail at runtime; avoid testing guarantees already enforced by the type system.
