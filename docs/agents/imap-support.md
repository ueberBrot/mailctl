# IMAP support

mailctl uses published `async-imap` 0.12.0 with its Tokio runtime and
`imap-proto` 0.17.0 response types. Production, local fixtures, and the optional
GreenMail observer no longer depend on `io-imap`, `imap-codec`, or a Git fork.
TLS remains verified through `tokio-rustls`; implicit TLS and STARTTLS are supported.

## Bounded responses

A transport adapter admits a complete response before the library parses it.
It checks strict CRLF syntax, literal announcements before reading their payload,
protocol nesting, frame bytes, operation bytes, response count, and parser work.
Protocol nesting is limited to 64; the configured MIME depth and part limits also
apply to the decoded structure. The shipped executables reserve 8 MiB stacks for
recursive decoding. Embedded callers must provide equivalent decoding stacks.

If the published response parser panics, the protocol module catches the unwind,
closes the connection, and returns a protocol error. An already dispatched draft
retains an unknown outcome. Rust's panic hook still runs; this recovery requires
unwinding and cannot recover from aborts or stack overflow.

The adapter treats literal payloads as bytes. In LIST mailbox names and supported
FETCH string fields, it converts escaped quoted strings into equivalent standard
IMAP literals. This preserves backslashes and quotes without confusing them with
literal data that contains different bytes. It leaves INTERNALDATE and LIST
delimiters in their required quoted form. Generated responses have the same frame
and work ceilings as received responses.

Partial BODY responses must match the requested UID, section, offset, and byte
count. The original section is checked before the parser can collapse HEADER,
HEADER.FIELDS, and HEADER.FIELDS.NOT into one type. A missing space between an
exact requested partial section and its literal announcement is accepted for
providers that emit `BODY[1]<0>{12}`. Literal payloads never participate in these
syntax checks.

Selected body reads still retrieve bounded headers, MIME structure, and individual
parts independently of attachments. Whole-message reads remain available within
the wire-fetch ceiling. Attachments are streamed in bounded chunks; BINARY,
7BIT, and 8BIT transfer encodings preserve the fetched bytes, while BASE64 and
QUOTED-PRINTABLE use bounded decoders.

## Supported provider syntax

This replacement deliberately changes some pre-release parser behavior:

- Mailbox names must use canonical modified UTF-7. Invalid or lossy names fail;
  they are never substituted with a different mailbox name.
- LIST and FETCH metadata strings must be valid UTF-8 before typed decoding.
  Invalid metadata fails explicitly instead of allowing lossy replacements.
  BODY and attachment payloads may contain arbitrary bytes.
- Status and continuation text must be ASCII. Escaped LIST delimiters are
  unsupported. Both fail explicitly before library parsing.
- Metadata requests use BODYSTRUCTURE. Legacy non-section `BODY (...)` responses
  and MIME forms the published parser cannot represent fail explicitly. For
  example, the parser requires quoted TEXT and MESSAGE media-type tokens to
  recognize their specialized structure forms.
- Unsupported unsolicited extensions, BADCHARSET status codes, and unknown FETCH
  fields fail. Selection requires
  UIDVALIDITY and a tagged READ-ONLY confirmation; read-write selection fails.

Admission charges four passes over original response bytes, plus normalization
expansion. The library-level parser-work default is 16 MiB steps (previously
8 MiB), with a maximum of 64 MiB. Application body reads reserve at least five
times their configured wire-body ceiling, with a 16 MiB minimum. These finite
allowances keep an exact 2 MiB body readable without changing its byte ceiling.

Response errors and resource counters may differ from the former backend. Command
tags and quoting are implementation details. No configuration migration is needed.
Mailbox identities, message UIDs, reference checks, and returned payload bytes
retain their meaning.

## Draft creation

APPEND sends the frozen MIME bytes with the initial Draft flag after one
synchronizing continuation. A definitive rejection is recorded as rejected.
Interrupted or malformed exchanges retain an unknown outcome, including after
cancellation, and never authorize an automatic second APPEND. Read-only
reconciliation still checks the original mailbox incarnation, Message-ID, and
complete MIME hash before reporting a matching draft.
