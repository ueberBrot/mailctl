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
