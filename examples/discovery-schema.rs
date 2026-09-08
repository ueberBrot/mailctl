//! Print the versioned discovery contract for consuming applications.
use mailctl::{
    domain::{AccountDiscovery, Capabilities, Envelope, Health, ListAccountsInput, Operation},
    policy::Narrowing,
};
use schemars::schema_for;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schemas = serde_json::json!({
        "envelope": schema_for!(Envelope),
        "account_discovery_envelope": schema_for!(Envelope<AccountDiscovery>),
        "capabilities_envelope": schema_for!(Envelope<Capabilities>),
        "operation": schema_for!(Operation),
        "narrowing": schema_for!(Narrowing),
        "list_accounts_input": schema_for!(ListAccountsInput),
        "account_discovery": schema_for!(AccountDiscovery),
        "capabilities": schema_for!(Capabilities),
        "health": schema_for!(Health),
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &schemas)?;
    Ok(())
}
