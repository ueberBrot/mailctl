# Preserve email references and draft operation identity

Mailbox, message and attachment references are reusable through CLI, MCP and differently privileged endpoints of the same broker installation. Each dereference uses the caller's current permissions. Independent installations have separate reference identities in version 1; attachment transfer tokens retain the source plan's session binding.

Draft operations retain their original account identity, account generation and target mailbox when configuration changes. Keep historical status available to currently authorized callers; reconcile against the original target only when current permissions allow it. Status and retry requests must identify the original operation independently of a mutable account alias.

This permits handoffs between harnesses without treating references as grants, and prevents account or Drafts-mailbox reconfiguration from redirecting an old operation. Verify cross-endpoint reuse with both allowed and denied callers, and configuration changes with pending and uncertain operations. Retain the source plan's rule that uncertain operations are reconciled without another APPEND.
