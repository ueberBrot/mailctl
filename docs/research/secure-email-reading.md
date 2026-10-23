# Safely reading untrusted email

Research checked 2026-10-23. The original probes below predate the hardening
described in the implementation scope.

## Recommendation

Use explicit defenses for HTML extraction, terminal output, and agent actions. Ammonia is a maintained, adopted Rust HTML sanitizer, but its contract is browser HTML/XSS safety. Neither sanitization nor conversion to plain text makes email safe to obey. Anthropic documents hidden instructions in email as a prompt-injection vector and reports that the problem remains unsolved. [Ammonia documentation](https://docs.rs/ammonia/4.2.4/ammonia/), [prompt-injection research](https://www.anthropic.com/research/prompt-injection-defenses).

For mailctl's text output, keep explicit hidden-content and unsafe-link policies in the existing DOM traversal, along with terminal/Unicode handling. Keep `html2text` for conversion. Consider Ammonia when emitting HTML for a browser or when its configurable HTML allowlist serves a specific requirement; adding it before text conversion alone does not solve hidden text or prompt injection. This is a design recommendation based on the evidence below.

## Implementation scope

The shared HTML-to-text extraction removes subtrees with a `hidden` attribute
regardless of its value or common explicit inline hiding declarations
(`display:none`, `visibility:hidden` or `collapse`, `mso-hide:all`, and zero
opacity). Any recognized hiding declaration suppresses its subtree, even if a
later declaration would override it. It also removes executable and other
non-content subtrees and comments. Retained HTML `href`
destinations must be absolute `http:`, `https:`, or `mailto:` URLs; relative URLs
and other schemes are omitted. Conversion executes no scripts and fetches no
remote CSS, assets, or link destinations. It preserves the existing retrieval,
parser-work, input, output, and time bounds and the separation of bodies from
attachment payloads.

This policy does not reproduce browser visibility. It does not guarantee full
CSS cascade or stylesheet handling, arbitrary CSS obfuscation, or visual hiding
tricks. MIME plain text remains data, including commands or instructions.
MCP/JSON preserve returned text; human CLI output filters terminal escape
sequences and escapes other unsafe display controls and selected invisible
formatting characters.

Bodies, subjects, sender fields, link text, filenames, and attachment contents
are untrusted data. They cannot authorize tool use, shell commands, remote
requests, credential access, or draft creation. The consuming application owns
permission checks and confirmation. Preserve apparent commands and instructions
as email data; these transformations offer no prompt-injection guarantee.

The extraction change updates the opaque `representation_version`, invalidating
earlier body continuation cursors with `stale_cursor`. Restart a body read from
its first page after that error. No field schema changes or new safety flags are
expected; existing representation and continuation fields describe the result.
[Reading guide](../../src/frontends/guidance.rs),
[body representation](../../src/imap/body/representation.rs).

## Local evidence before hardening

The dependency is pinned to `html2text =0.17.1`, with default features disabled. Existing body limits and presentation behavior are relevant boundaries. [Cargo.toml](../../Cargo.toml#L56), [body representation](../../src/imap/body/representation.rs#L722), [presentation](../../src/frontends/presentation.rs#L272).

A local compiled probe used the existing dependency artifact and the body path's `config::plain().raw_mode(true).string_from_read(..., 80)` configuration:

- Both `style="display:none"` and the `hidden` attribute left the enclosed `HIDDEN_MARKER` in output: `Hello\n\nHIDDEN_MARKER\n`.
- Script, style, and comment markers disappeared; a `javascript:MARKER` link target survived in text footnotes, and image alt text survived as text.
- Nothing executed or fetched in these probes. These observations establish those fixtures' behavior, not a general security guarantee.

Source inspection also found CLI human-output control filtering, while MCP/JSON preserve data, and guidance that email instructions are data. Transformation choices must account for both interfaces. [Presentation](../../src/frontends/presentation.rs#L272), [MCP serialization](../../src/frontends/mcp.rs#L313), [agent guidance](../../src/frontends/guidance.rs#L65).

## Small crate shortlist

- **Ammonia:** parses HTML fragments with `html5ever` and applies an allowlist to tags, attributes, and URL schemes. Its default policy removes script/style contents and comments, but permits images; defaults are not a no-network or visibility policy. [Crate documentation](https://docs.rs/ammonia/4.2.4/ammonia/), [builder defaults](https://docs.rs/ammonia/4.2.4/ammonia/struct.Builder.html). The release page marks **4.2.4** latest; package records date it **2026-10-17**. This is concrete recent maintenance evidence. That release fixes case-sensitive CSS `url()` filtering; RustSec lists patched ranges `>=4.2.4` and `>=4.1.8, <4.2.0`. The advisory concerns configurations allowing filtered inline styles and describes tracking-pixel injection, not XSS. [Release](https://github.com/rust-ammonia/ammonia/releases/tag/v4.2.4), [package dates](https://docs.rs/crate/ammonia/4.2.4), [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0373.html). Real downstream evidence: `nh3` declares Ammonia in its Cargo manifest; PyPA's `readme_renderer` imports and calls `nh3.clean`. This establishes an actual application dependency chain, without proving a deployed version or deployment count. [nh3 manifest](https://raw.githubusercontent.com/messense/nh3/main/Cargo.toml), [readme_renderer sanitizer](https://raw.githubusercontent.com/pypa/readme_renderer/main/readme_renderer/clean.py).

- **html2text:** keep it as a renderer, with an explicit extraction policy. Its published manifest makes CSS optional; document CSS also needs `use_doc_css()`. Documented hiding support covers `display:none` and zero-height overflow cases, and explicitly stops short of a full browser style system. [Pinned manifest](https://docs.rs/crate/html2text/0.17.1/source/Cargo.toml), [upstream README](https://github.com/jugglerchris/rust-html2text/blob/main/README.md). The directly opened package listing showed **0.17.4 (2026-10-18)** and **0.17.1 (2026-04-19)**; evaluate newer patches separately rather than assuming the local pin is current. [Package/version listing](https://docs.rs/crate/html2text/latest).

- **strip-ansi-escapes:** a focused option for terminal escape sequences. The latest documentation observed is **0.2.1**, published **2025-01-14**; this verifies a release, but does not establish recent active maintenance. [Version listing](https://docs.rs/crate/strip-ansi-escapes/0.2.1), [API](https://docs.rs/strip-ansi-escapes/latest/strip_ansi_escapes/). Its source forwards printable characters and retains only LF in its control-execution handler, so tabs/CR can disappear. It is not a Unicode spoofing filter; do not assume complete C0/C1 or bidi protection from its name. [Implementation](https://docs.rs/strip-ansi-escapes/0.2.1/src/strip_ansi_escapes/lib.rs.html).

Search snippets and some `latest` pages disagreed or were stale. Versions/dates above come from directly visible release/package records; they are observations as of this research date, not guarantees that no newer release exists.

## Practical defense boundaries

1. **Extract deliberately.** Prune explicitly hidden subtrees before removing `style`, `class`, or `hidden` evidence; omit executable/non-content subtrees and comments. Define how alt text and link destinations appear. Allow only intended URL schemes for displayed destinations, and avoid automatic remote-asset fetches or link opening. Removing a hiding attribute alone can expose its text. Full visibility depends on CSS and presentation: even HTML `hidden` can be overridden by CSS, and `visibility:hidden` differs from `display:none`. Treat limited pruning as a useful heuristic, not browser-equivalent visibility. [HTML hidden specification](https://html.spec.whatwg.org/multipage/interaction.html#the-hidden-attribute), [CSS visibility](https://www.w3.org/TR/css-display-3/#visibility), [html2text limits](https://github.com/jugglerchris/rust-html2text/blob/main/README.md).

2. **Protect every displayed field.** Apply a deliberate policy to bodies, headers, filenames, and link labels. Normalize line endings; retain the whitespace needed for readability; escape or remove remaining C0 controls, DEL, and C1 controls after decoding. Handle bidi controls separately, preferably with visible escapes/flags where fidelity matters. Unicode lists `Bidi_Control` separately from control characters, so filtering `char::is_control()` alone misses them. Avoid blanket deletion of all format characters, which can alter legitimate writing. [Terminal control ranges](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html), [Rust control classification](https://doc.rust-lang.org/std/primitive.char.html#method.is_control), [Unicode bidi controls](https://www.unicode.org/Public/UCD/latest/ucd/PropList.txt), [Unicode display/security semantics](https://unicode.org/reports/tr9/).

3. **Keep email as untrusted data.** Do not try to delete every apparent command or instruction: ordinary prose can carry an attack after all markup is gone. Preserve provenance and transformation/truncation indicators; keep returned content out of privileged instructions and shell evaluation. The consuming application's agent harness needs independent permission checks for tool actions, restricted credentials/network access, and approval for sensitive effects. Structured JSON or delimiters help represent data but are not an injection-proof boundary. MCP itself calls for output sanitization, access controls, client validation, and confirmation for sensitive operations. [Prompt-injection research](https://www.anthropic.com/research/prompt-injection-defenses), [MCP security considerations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#security-considerations).

4. **Preserve bounds and ownership.** Any additional DOM/sanitizer pass must retain parser-work, input, output, and time limits; silent fallback to raw HTML on failure would defeat the extraction policy. Harness execution belongs to the consuming application, and mailctl access grants cannot constrain a harness's separately granted shell/filesystem access. [ADR-0004](../adr/0004-read-bodies-independently-of-attachments.md), [ADR-0001](../adr/0001-agent-email-access-boundary.md), [ADR-0006](../adr/0006-make-native-isolation-an-explicit-operator-choice.md).
