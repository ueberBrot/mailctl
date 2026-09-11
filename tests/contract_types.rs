use mailctl::{
    domain::{AccountDiscovery, Capabilities, Envelope, Error, Operation, OperationResult},
    policy::RequestContext,
    service::Service,
};

const _: fn(&Service, &RequestContext, Operation) = |service, context, operation| {
    fn require_send(_: impl std::future::Future<Output = Result<OperationResult, Error>> + Send) {}
    require_send(service.execute(context, operation));
};
const _: for<'a> fn(&'a Service, &RequestContext) -> Result<&'a mailctl::config::Limits, Error> =
    Service::limits;
const _: fn(Envelope<AccountDiscovery>) -> Result<AccountDiscovery, Error> = Envelope::into_result;
const _: fn(Envelope<Capabilities>) -> Result<Capabilities, Error> = Envelope::into_result;
const _: fn(OperationResult) = |result| match result {
    OperationResult::Message(message) => {
        let _: String = message.account_id;
        let _: u64 = message.generation;
        let _: String = message.message_reference;
        let _: mailctl::domain::BodyText = message.body;
    }
    OperationResult::Messages(search) => {
        let _: Vec<mailctl::domain::MessageEnvelope> = search.messages;
        let _: mailctl::domain::SearchCriteria = search.criteria;
        let _: bool = search.complete;
        let _: Option<String> = search.next_cursor;
    }
    OperationResult::Mailboxes(discovery) => {
        let _: Vec<mailctl::domain::Mailbox> = discovery.mailboxes;
        let _: bool = discovery.complete;
        let _: Option<String> = discovery.next_cursor;
    }
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
