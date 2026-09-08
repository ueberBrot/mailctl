# Domain Docs

How to read and write this repo's domain documentation.

## Before writing domain docs

Before creating or editing `CONTEXT.md` or an ADR, read and apply [writing-for-agents](../../.agents/skills/writing-for-agents/SKILL.md). Use [domain-modeling](../../.agents/skills/domain-modeling/SKILL.md) for glossary and ADR formats and decision criteria.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root for the domain model and glossary.
- **`docs/adr/`** for decisions that touch the area you're about to work in.

If these files don't exist, proceed silently. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms or decisions actually get resolved.

## File structure

This repo uses a single-context layout: `CONTEXT.md` at the repo root and numbered ADRs under `docs/adr/`.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
