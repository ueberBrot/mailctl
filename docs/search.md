# Search messages

Search returns message envelopes from one approved mailbox, newest UID first.
Discover the mailbox with `mailctl mailbox list`, then pass its reference:

```sh
mailctl --json message search --mailbox "$mailbox" --limit 25 \
  --criteria '[{"field":"subject","value":"invoice"},{"field":"forbidden_flag","flag":"seen"}]'
```

MCP clients call `email_search_messages` with the same `mailbox`, `criteria`,
`limit`, and `cursor` fields. Grants without search permission do not expose the
tool. Both executables use the same authorization, query, and continuation logic.

## Criteria

Criteria are an array of AND terms. Omit the array to match every message.
Repeated fields remain separate AND terms; their order does not matter.

| Field | Argument | Meaning |
| --- | --- | --- |
| `received_after` | `date` | INTERNALDATE calendar date on or after this date |
| `received_before` | `date` | INTERNALDATE calendar date before this date |
| `sent_after` | `date` | Date header calendar date on or after this date |
| `sent_before` | `date` | Date header calendar date before this date |
| `from`, `to`, `cc`, `bcc` | `value` | Address-field substring |
| `subject` | `value` | Subject substring |
| `text` | `value` | Message text substring, including headers and body |
| `required_flag` | `flag` | Standard flag must be present |
| `forbidden_flag` | `flag` | Standard flag must be absent |

Dates use `YYYY-MM-DD`. Calendar comparisons ignore the time and time zone;
received and sent dates are separate predicates. Flags are `answered`, `deleted`,
`draft`, `flagged`, `recent`, and `seen`. Contradictory date ranges or flag terms
fail validation. Text retains literal spaces and allows at most 4,096 UTF-8 bytes
per term, with no NUL. A query has at most 32 terms. OR, regex, and raw IMAP
expressions are outside this interface. Text matching follows IMAP server
semantics; a server that rejects a query produces an explicit error.

## Pages and metadata

Results contain `messages`, normalized `criteria`, `account_id`, `generation`,
`mailbox_reference`, `complete`, and `next_cursor`. Each message has an
installation-authenticated `reference`, received date, size, flags, and optional
subject, addresses, sent date, and Message-ID. Optional values report `present`
with a `value`, `missing`, or `malformed`. Message-ID and other headers never
establish message identity.

The first page records an upper UID boundary. Later pages exclude new arrivals
above it, skip deleted messages, and reevaluate predicates against current
mailbox state. A cursor preserves unreturned matches within a partially consumed
UID window. This traversal is live: a flag change can affect a later page, and
messages already passed are not reconsidered.

An empty page can still have `complete: false`. Continue with `next_cursor` until
`complete: true`, retaining the mailbox, criteria, and effective grant:

```sh
mailctl --json message search --mailbox "$mailbox" --cursor "$cursor" \
  --criteria '[{"field":"subject","value":"invoice"},{"field":"forbidden_flag","flag":"seen"}]'
```

The default page size is 50, with a maximum of 200. Each request examines at most
10 UID windows of 1,000 UIDs by default; operator maxima are 100 windows and
10,000 UIDs per window. Grants may narrow these limits. Response, header, wire,
credential, and operation-time limits also apply. Oversized responses fail
explicitly; they are not silently truncated.

References and cursors work across CLI and MCP sessions in the same installation.
Every request rechecks permissions. Changed criteria, grant scope, configuration,
account generation, or UIDVALIDITY invalidate a cursor. Start a new search after
`stale_cursor`. Tokens from another installation, modified tokens, and tokens
used as the wrong resource kind fail authentication. Keep the installation state
directory across restarts.

Search uses read-only mailbox selection and envelope-only FETCH requests. It does
not set seen flags or fetch message bodies to construct the returned envelopes.
