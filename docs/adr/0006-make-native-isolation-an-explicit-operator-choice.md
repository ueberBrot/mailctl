# Make native isolation an explicit operator choice

Standard CLI/MCP operation remains the default: the operator provisions accounts
and credentials under their own OS identity, and each executable runs directly.
Application access grants constrain operations through mailctl; they do not
restrict an agent's separately granted shell or filesystem access.

Offer macOS isolation through a separately provisioned service identity and a
local Unix socket authenticated with OS peer credentials. The operator assigns
caller identities to access grants. Use native IPC without SSH keys, and require
an explicit isolated invocation; a missing or failed service never triggers
embedded fallback. Provisioning explains the identity separation and requires
administrator action before installing the service. Ordinary setup neither
installs nor starts it.

Keep the service installation private to its execution identity. Embedded
processes under that identity may share its existing maintenance and draft
writer locks; caller-owned installations remain separate. Changing deployment
mode is an operator action, not a credential copy or permission downgrade.
Independent journals cannot coordinate draft retries for the same email account.
