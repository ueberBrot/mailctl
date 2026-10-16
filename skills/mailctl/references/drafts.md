# Draft creation and recovery

Read `mailctl guide drafts` or MCP resource `mailctl://guide/drafts` for the save and status recipe.
Use `mailctl schema draft_content` for CLI composition files and `mailctl schema save_draft` for MCP inputs.
Draft creation saves one new unsent message in an approved existing Drafts mailbox.

## Prepare and save one operation

A draft operation identifies one logical creation across retries.
Use existing user authorization when it covers the proposed save.
Otherwise, present the composition and obtain explicit approval before saving it.

1. Discover the approved account's `account_id`, `generation`, `drafts_mailbox`, and `from_identities`.
   The grant must permit draft creation for that account and mailbox.
   If permissions are missing, stop for operator action.
2. Prepare the authorized composition with approved From identity and intended recipients, subject, body, and reply fields.
   Recipients are objects with `address` and optional `name`.
   Reply fields `in_reply_to` and `references` use email Message-ID values, not mailctl references.
3. Generate one operation UUID, the stable unique identifier for this creation.
   Before the first save, persist it and the complete frozen composition in durable caller-owned state.
   Persist the original account UUID, account generation, and exact `drafts_mailbox` name with them.
   If durable retention is unavailable, stop before saving.
4. Save with `email_save_draft` or CLI `draft save`, using the retained identity and composition.
   Pass the account's `generation` as `account_generation` and `drafts_mailbox` as `mailbox`.
   Draft `mailbox` takes the literal name. Search `mailbox` takes a returned reference.
   Retain the receipt and outcome beside the original operation record.

## Resolve the original operation

States `created`, `created_reference_unavailable`, and `duplicate` establish that the draft exists.
A missing message reference does not authorize another creation.
Report the actual state and keep the receipt.

After an interruption, timeout, `operation_in_progress`, or `outcome_unknown`, inspect the original operation with status.
Use `email_draft_status` or CLI `draft status` with the retained account UUID, generation, operation UUID, and mailbox.
Ordinary status reads the journal without contacting the provider.

For an uncertain operation, use status with `reconcile: true` or CLI `--reconcile` within the authorized recovery task.
Reconciliation inspects the original provider target and never creates another draft.
If the outcome remains uncertain, preserve that state and request operator review.
Never replace an uncertain operation with a new UUID, modified composition, current generation, or newly configured mailbox.

For `prepared`, a save can resume with the identical operation identity and frozen composition.
A completed operation replays its recorded outcome.
If the same identity produces a draft-input conflict, recover the original input instead of changing it.
If configuration changes prevent historical access, retain the original record and ask the operator to restore approved access.
