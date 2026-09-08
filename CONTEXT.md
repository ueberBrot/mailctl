# Agent Email

Language for email access by agent harnesses and other consuming applications.

## Language

**Email account**:
A configured email identity whose mailboxes are available within operator-approved permissions.
_Avoid_: User, login

**Mailbox**:
A named collection of messages within an email account, such as INBOX or Drafts.
_Avoid_: Email account

**Draft creation**:
Saving a new unsent message in the email account's approved Drafts mailbox. It does not send a message or edit an existing draft.
_Avoid_: Send, draft update

**Draft operation**:
A logical request to create one draft, with an identity and a tracked outcome that persist across retries. An operation may exist before a draft is known to have been created.
_Avoid_: Draft message

**Consuming application**:
An application that uses returned email data for a workflow such as summarization or wiki ingestion.
_Avoid_: Email core

**Agent harness**:
A consuming application that runs an agent and executes its tool calls, such as Claude Code, Codex, or a DeepSeek-based harness.
_Avoid_: Operator

**Operator**:
The person who configures email accounts and grants access to their email operations.
_Avoid_: Agent harness

**Access grant**:
An operator-approved ceiling on the email accounts, mailboxes, and operations available to a consuming application. A caller may narrow that ceiling; a resource reference does not convey it.
_Avoid_: Harness name, resource reference

**Installation**:
The shared identity and history of a configured set of email accounts and draft operations, used by one or more consuming applications. Restarting a consuming application does not create a new installation.
_Avoid_: Process, session, executable

**Account alias**:
A human-facing name for a configured email account. Renaming the alias preserves the account's identity.
_Avoid_: Account identity

**Credential reference**:
The association between an email account and the source of its authentication secret. The reference identifies how to obtain a credential; it is not the secret value.
_Avoid_: Password, account configuration
