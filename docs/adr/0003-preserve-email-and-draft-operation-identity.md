# Preserve email references and draft operation identity

Mailbox, message and attachment references are reusable through CLI commands and MCP sessions using the same installation, including differently scoped access grants. Each dereference uses the caller's effective permissions. Independent installations have separate reference identities in version 1. Attachment transfer tokens remain bound to the issuing session; a CLI export completes its chunk loop within one invocation.

Draft operations retain their original account identity, account generation and target mailbox when configuration changes. Keep historical status available to currently authorized callers; reconcile against the original target only when current permissions allow it. Status and retry requests must identify the original operation independently of a mutable account alias.

This permits handoffs between harnesses without treating references as grants, and prevents account or Drafts-mailbox reconfiguration from redirecting an old operation. Uncertain operations are reconciled without another APPEND.
