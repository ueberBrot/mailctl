# Share draft coordination across protected endpoints

Allow concurrent callers to use the same email account with different permissions. One broker serves multiple protected listeners, each with an operator-configured grant, and coordinates draft creation through a shared operation journal and one mutation writer per account. Authorization derives from the authenticated endpoint and any permitted narrowing; harness names are descriptive metadata.

This replaces the source plan's one-listener-per-broker rule. Separate draft-capable brokers would compete for its exclusive account writer lock, preventing differently privileged endpoints from creating drafts for the same account. Sharing coordination preserves the existing retry and crash-recovery guarantees across callers.

Verify concurrent requests through differently privileged endpoints: grants remain independent, identical operation IDs and input share one creation, and conflicting input fails before another APPEND. Preserve writer exclusion across broker instances. Endpoint access still depends on the OS boundary described in [ADR-0001](0001-agent-email-access-boundary.md).
