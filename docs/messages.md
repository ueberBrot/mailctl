# Read message text

Use a message reference returned by search:

```sh
mailctl --json message get --message "$message_reference"
```

MCP clients call `email_get_message` with `{"message":"…"}`. The tool is available
under read grants and absent under drafts-only grants. CLI and MCP return the
same result inside their versioned envelope. MCP includes that envelope in both
`structuredContent` and JSON text.

A result contains `account_id`, `generation`, `message_reference`, and `body`.
The body records:

- `text`: selected plain text, or HTML converted to plain text.
- `selected_part` and `source_media_type`: the MIME part and its original type.
- `representation_version`: the selection, decoder, and converter version.
- `converted` and `replacements`: whether HTML conversion or malformed-input
  replacement occurred.
- `truncated`: whether the returned text stops before the available decoded text.
- `empty_reason`: `no_supported_body` when MIME selection finds no eligible body;
  otherwise null. An eligible empty text part retains its part and media type.
- `continuation_available`: currently false. Public text continuation is tracked
  in [issue #13](https://github.com/ueberBrot/mailctl/issues/13). A truncated result
  does not claim to contain the complete body.

References remain usable across CLI processes and MCP sessions in the same
installation. Each read checks the current account and mailbox grants. Sharing a
reference grants no permission. A changed account generation or mailbox
UIDVALIDITY returns `stale_reference`; a vanished message returns
`message_not_found`.

## Selection and limits

Selection excludes attachment-disposition parts and attached messages. Within
alternatives it prefers eligible plain text over HTML. Related content uses its
valid declared root, otherwise its first eligible body. Mixed content uses its
first eligible subtree in wire order. These rules apply recursively.

HTML conversion uses pinned html2text 0.17.1 with no network or file access.
Quotes and inert link text/targets are preserved. Malformed input is decoded
with deterministic replacement. JSON and MCP contain semantic text; human CLI
output currently presents escaped JSON.

An exclusive read-only connection checks UIDVALIDITY and fetches with PEEK.
A short selected body remains readable when unrelated attachments exceed the
wire-fetch budget. Whole-message fetching is used only within its own budget.
Timeout, cancellation, and protocol failure dispose of the connection.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Returned UTF-8 text | 256 KiB | 2 MiB |
| Selected-body or whole-message wire bytes | 2 MiB | 8 MiB |
| Aggregate headers | 64 KiB | 256 KiB |
| MIME depth / parts | 20 / 200 | 40 / 1,000 |

The minimum text page is four bytes, enough for one UTF-8 scalar. Grants can
narrow these limits. Independently, the body route caps decoded text at 8 MiB,
decoding/conversion work at 32 Mi steps, IMAP parser work at 8 Mi steps, response
count at 4,096, total protocol bytes at 16 MiB, frames at 256 KiB, and literals at
64 KiB. Limits produce explicit errors rather than incomplete results marked as
complete. Output envelopes and process-local credential/connection limits also
apply.

## Verification

`tests/message.rs` exercises the application contract with memory and IMAP
adapters. The IMAP body suites cover MIME selection, hostile encodings and HTML,
allocation/work limits, partial PEEK, and connection disposal. GreenMail reads
through the application and compares message contents, identities, and flags
with independent observations, including a message with an oversized attachment.
The dedicated native credential suite checks successful CLI/MCP result parity,
reference handoff, and denied access with no provider connection.
