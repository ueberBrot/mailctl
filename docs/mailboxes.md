# Discover approved mailboxes

Mailbox discovery lists existing mailboxes in the intersection of an account's
allowlist and the selected access grant. It reports the exact mailbox name,
display label, selectability, server-reported special-use flags, and a reusable
reference. It leaves messages and flags unchanged.

After configuring and provisioning an account, list its approved mailboxes:

```sh
mailctl --account work --json mailbox list --limit 100
```

Select one account with `--account` when the grant allows more than one. MCP
clients call `email_list_mailboxes`; its optional `account` field selects an
alias within the session's account scope. Drafts-only grants do not expose this
tool. Setup and credential administration remain explicit executable subcommands.

## Pages and references

Results contain `account_id`, `generation`, `mailboxes`, `complete`, and
`next_cursor`. Each mailbox contains `reference`, `account_id`, `generation`,
`display_label`, and `metadata` (`name`, `selectable`, and `special_use`).

Mailboxes appear in deterministic identity order. `complete: true` means the
approved inventory is exhausted. Otherwise, pass `next_cursor` to the next
request, retaining the account selection and access grant:

```sh
mailctl --account work --json mailbox list --cursor "$cursor" --limit 100
```

The default page limit is 200; the schema maximum is 1,000. Operator and grant
limits may narrow these values. The inventory contains at most 1,000 entries.
Oversized or malformed inventories fail explicitly. A configured name absent
from the server produces no entry. Selectability and special-use flags come from
the server; an empty flag list does not imply a mailbox role.

Resolve one previously returned reference through either executable:

```sh
mailctl --json mailbox list --reference "$reference"
```

MCP uses the same `reference` field in `email_list_mailboxes`. References identify
resources; every request checks the current account, mailbox, and operation
permissions. The application makes exact-name requests only for authorized
mailboxes. INBOX is case-insensitive; other mailbox identities retain their case.
Mailbox names support Unicode, including names such as `Entwürfe`. Configure
the actual server folder name; special-use attributes such as `\Drafts` are
standardized independently of that name and may be absent. The IMAP route
encodes international names as modified UTF-7. Control characters and LIST
wildcards (`*` and `%`) return an explicit unsupported result.

References remain usable across CLI exits and MCP sessions in one installation.
An alias rename preserves them; an account generation change invalidates them.
Removing mailbox permission denies access, and a missing referenced mailbox
returns `stale_reference`. References from another installation or with altered
payloads fail authentication. A mailbox reference identifies its name within an
account generation; it does not claim to identify a particular mailbox
incarnation after deletion and recreation.

Each cursor binds the account generation, effective scope, configuration,
inventory, and continuation position. Restarting with unchanged state can resume
it. Changed configuration, grants, or inventory return `stale_cursor`; start a
new listing. A cursor and a mailbox reference cannot substitute for each other.
Keep the installation state directory when upgrading or moving executables.

## Application contract and schemas

Rust consumers await `Service::execute` with a validated request context and
`Operation::ListMailboxes`. The same authorization and pagination run with the
in-memory and IMAP mailbox adapters. Configuring an adapter is a trusted
application-composition operation, outside CLI/MCP request inputs.

Generate input and output schemas with:

```sh
cargo run --locked --example discovery-schema
```

CLI JSON and MCP `structuredContent` carry the same versioned envelope. MCP also
returns that envelope as JSON text. Errors use stable codes such as
`permission_denied`, `account_not_allowed`, `mailbox_not_allowed`,
`stale_reference`, `stale_cursor`, and `response_too_large`.
