# Read attachments

List attachments using a message reference returned by search:

```sh
mailctl --json attachment list --message "$message_reference"
mailctl --json attachment get --attachment "$attachment_reference"
```

`attachment list` returns safe display names, media types, declared wire sizes,
transfer availability, and authenticated part references. It reads BODYSTRUCTURE
without downloading payloads. Attached messages remain single attachments;
inline resources and the selected message body are not added to this list.
A declared size describes transfer-encoded bytes, not the decoded file size.

`attachment get` completes the chunk loop in one invocation and returns one
versioned envelope. Its result contains the account UUID/generation, attachment
reference, `bytes_base64`, decoded offset zero, and final integrity metadata.
The whole result must fit the configured envelope limit. Filesystem export under
approved roots is tracked in [issue #14](https://github.com/ueberBrot/mailctl/issues/14).

## MCP chunks

MCP exposes `email_list_attachments` with `{"message":"…"}` and
`email_get_attachment` with either `{"attachment":"…"}` to start or
`{"token":"…"}` to continue. Supply exactly one of those inputs. Both tools
require attachment-reading permission and are absent from drafts-only sessions.
Their schemas are published through MCP tool discovery.

Each chunk contains `bytes_base64` and its `decoded_offset`. Decode each chunk
separately and concatenate the decoded bytes in offset order. The `progress`
field has one of two forms:

```json
{"status":"continue","next_token":"…"}
```

```json
{"status":"complete","total_decoded_bytes":6,"sha256":"…"}
```

Only the final chunk carries the total decoded byte count and SHA-256 digest.
CLI and MCP return the same semantic bytes and integrity result. Small transfers
fit one chunk and have identical normalized results. MCP returns its envelope
in both structured content and JSON text.

## Identity and lifecycle

Attachment references work across authorized CLI processes and MCP sessions in
one installation. A reference conveys no permission. Each operation checks the
current account generation, mailbox scope, and attachment-reading permission;
each provider connection checks UIDVALIDITY before PEEK.

Transfer tokens are single-use and belong to the issuing execution session,
effective grant, resource, offset, and limits. A different process or session
cannot resume one. Altered, replayed, expired, and cross-session tokens return
`transfer_expired`. Changed mailbox identity returns `stale_reference`.

Each process limits transfers per account across its sessions. In-flight work
counts toward that quota. Cancellation, failure, completion, and session exit
release decoder state and the reservation. Expired retained transfers are removed
when admitting or resuming work. A failed continuation cannot be retried with the
same token; start a new transfer from the attachment reference.

## Bounds and verification

| Resource | Default | Maximum |
| --- | ---: | ---: |
| Decoded bytes per transfer | 10 MiB | 32 MiB |
| Encoded wire bytes per transfer | 16 MiB | 64 MiB |
| Decoded chunk | 64 KiB | 256 KiB |
| Transfer lifetime | 5 minutes | 10 minutes |
| Transfers per account per process | 2 | 4 |

Grants can narrow these ceilings. The existing MIME structure, IMAP frame,
parser-work, decoder-work, operation-byte, connection, and deadline limits also
apply. Every reconnect uses normal credential admission; transfers retain no
password or idle connection between chunks. JSON envelope limits apply before
base64 result allocation and before retaining a continuation.

The application contract tests cover exact bytes, digest, authorization, token
binding, quotas, expiry, and mailbox incarnation. Independent transcript tests
verify metadata-only reads and bounded PEEK/decoder behavior. GreenMail compares
retrieved bytes with its synthetic source fixture and checks mailbox contents,
UID identities, and seen/unseen flags independently. Native credential tests
exercise reference handoff and normalized CLI/MCP attachment results.
