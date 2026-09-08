# Coordinate draft creation across embedded processes

Allow concurrent CLI commands and MCP sessions to use the same email account under different access grants. Processes in one installation share its account registry, reference key, and durable draft journal. Serialize draft dispatch with an OS-backed account writer lock spanning journal recovery, state transition, APPEND, and durable outcome recording; release it after that work rather than reserving the account for a process's lifetime.

Acquire the writer lock before deciding whether an `in_flight` operation has lost its owner. Starting a second process must not recover an operation that another live process is dispatching. A crashed owner releases its OS lock; its unfinished dispatch remains uncertain and is never automatically appended again. SQLite transactions and process-local mutexes alone do not coordinate the network side effect. Status remains journal-only unless reconciliation is explicitly requested; waiting for a writer is bounded.

Use coordinated initialization and maintenance so concurrent startup cannot replace identities, and backup, restore, and migration obtain exclusive access against all active processes. Every caller is authorized before journal existence or input conflicts are exposed. Independent installations have independent journals and cannot safely coordinate draft retries for the same account.

These locks coordinate durable state and draft creation while connections, credential workers, and request admission remain local to each process.
