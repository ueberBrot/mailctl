pub const MCP: &[&[u8]] = &[
    include_bytes!("../fuzz_corpus/envelopes/mcp/accounts.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/mailboxes.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/unknown-tool.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/unknown-field.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/denied-draft.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/invalid-params.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/duplicate-id.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/invalid-version.json"),
    include_bytes!("../fuzz_corpus/envelopes/mcp/batch.json"),
];
