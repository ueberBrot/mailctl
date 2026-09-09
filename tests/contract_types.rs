use mailctl::{
    domain::{AccountDiscovery, Capabilities, Envelope, Error, Operation, OperationResult},
    policy::RequestContext,
    service::Service,
};

const _: fn(&Service, &RequestContext, Operation) -> Result<OperationResult, Error> =
    Service::execute;
const _: for<'a> fn(&'a Service, &RequestContext) -> Result<&'a mailctl::config::Limits, Error> =
    Service::limits;
const _: fn(Envelope<AccountDiscovery>) -> Result<AccountDiscovery, Error> = Envelope::into_result;
const _: fn(Envelope<Capabilities>) -> Result<Capabilities, Error> = Envelope::into_result;
const _: fn(OperationResult) = |result| match result {
    OperationResult::Accounts(discovery) => {
        let _: Vec<String> = discovery
            .accounts
            .into_iter()
            .map(|account| account.alias)
            .collect();
        let _: bool = discovery.complete;
    }
    OperationResult::Capabilities(capabilities) => {
        let _: Vec<mailctl::policy::Permission> = capabilities.permissions;
        let _: mailctl::domain::Health = capabilities.health;
        let _: mailctl::domain::ProcessCapacity = capabilities.capacity.per_process;
    }
    OperationResult::Health(health) => {
        let _: Vec<mailctl::domain::AccountHealth> = health.accounts;
    }
    OperationResult::Setup(setup) => {
        let _: String = setup.installation_id;
        let _: String = setup.configuration_revision;
    }
    OperationResult::Cancelled(cancellation) => {
        let _: bool = cancellation.cancelled;
    }
    OperationResult::Credential(status) => {
        let _: String = status.account_id;
        let _: mailctl::domain::SourceAvailability = status.availability;
    }
    OperationResult::Doctor(doctor) => {
        let _: Vec<mailctl::domain::DoctorAccount> = doctor.accounts;
    }
};
