//! Account discovery and access-grant authorization through one application interface.
mod credentials;
#[cfg(any(feature = "cli", feature = "mcp"))]
pub(crate) use credentials::credential_error;
mod attachments;
mod imap;
mod mailboxes;
mod message;
pub(crate) use attachments::TransferSession;
pub use attachments::{AttachmentBackend, AttachmentReader, MemoryAttachments};
pub use message::{BodyBackend, BodyRead, MemoryBodies};
mod requests;
mod search;
mod state;
mod tokens;
use crate::encoding::{OutputBudget, serialized_size};
pub use crate::search::{LocatedMessage, SearchBatch, SearchPosition, SearchRequest};
use crate::{
    config::{AccountConfig, Config},
    domain::{
        Account, AccountDiscovery, AccountHealth, Availability, Capabilities, Capacity, Error,
        ErrorCode, Health, Operation, OperationResult, ProcessCapacity, Setup,
    },
    policy::{Narrowing, Permission, RequestContext},
};
pub use mailboxes::{MailboxBackend, MailboxTarget, MemoryMailboxes};
pub use search::{MemoryMessage, MemoryMessages, SearchBackend};
use state::AccountRegistry;
use uuid::Uuid;

pub struct Service {
    config: Config,
    host: std::sync::Arc<dyn crate::host::HostEnvironment>,
    registry: AccountRegistry,
    context_id: Uuid,
    mailbox_backend: Option<std::sync::Arc<dyn MailboxBackend>>,
    transfers: attachments::Transfers,
    requests: requests::Requests,
    observations: std::sync::Mutex<std::collections::HashMap<String, Availability>>,
    attachment_backend: Option<std::sync::Arc<dyn AttachmentBackend>>,
    body_backend: Option<std::sync::Arc<dyn BodyBackend>>,
    search_backend: Option<std::sync::Arc<dyn SearchBackend>>,
    authentication: credentials::AuthenticationInitialization,
}
impl Service {
    pub fn open(config: Config) -> Result<Self, Error> {
        Self::open_checked(config, || Ok(()))
    }
    pub fn open_checked(
        config: Config,
        confirm_configuration: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let registry = AccountRegistry::open_checked(&config, confirm_configuration)?;
        Ok(Self::build(config, registry))
    }
    pub fn setup(config: Config) -> Result<Setup, Error> {
        Self::maintain(config, || Ok(())).map(|(setup, ())| setup)
    }
    pub fn maintain<T>(
        config: Config,
        update_configuration: impl FnOnce() -> Result<T, Error>,
    ) -> Result<(Setup, T), Error> {
        config.validate()?;
        let (registry, updated) = AccountRegistry::maintain(&config, update_configuration)?;
        Ok((
            Setup {
                installation_id: registry.installation().to_owned(),
                configuration_revision: registry.revision().to_owned(),
                accounts: config.accounts.len(),
                grants: config.grants.len(),
            },
            updated,
        ))
    }
    pub fn in_memory(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let registry = AccountRegistry::in_memory(&config)?;
        Ok(Self::build(config, registry))
    }
    fn build(config: Config, registry: AccountRegistry) -> Self {
        Self {
            config,
            host: std::sync::Arc::new(crate::host::NativeEnvironment),
            registry,
            context_id: Uuid::new_v4(),
            mailbox_backend: None,
            search_backend: None,
            body_backend: None,
            attachment_backend: None,
            transfers: Default::default(),
            requests: Default::default(),
            observations: Default::default(),
            authentication: std::sync::OnceLock::new(),
        }
    }
    /// Select host dependencies during frontend initialization, before operations.
    pub fn with_environment(
        mut self,
        host: std::sync::Arc<dyn crate::host::HostEnvironment>,
    ) -> Self {
        self.host = host;
        self
    }
    pub fn context(
        &self,
        grant_name: &str,
        narrowing: &Narrowing,
    ) -> Result<RequestContext, Error> {
        let grant = self
            .config
            .grants
            .iter()
            .find(|grant| grant.name == grant_name)
            .ok_or_else(denied)?;
        if narrowing.accounts.as_ref().is_some_and(|accounts| {
            accounts.len() > self.config.limits.accounts
                || accounts.iter().any(|account| account.len() > 1024)
        }) {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let account_indices = self
            .config
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, account)| {
                grant.accounts.contains(&account.key)
                    && narrowing
                        .accounts
                        .as_ref()
                        .is_none_or(|selected| selected.contains(&account.alias))
            })
            .map(|(index, _)| index)
            .collect();
        Ok(RequestContext::new(
            self.context_id,
            self.transfers.session(),
            grant_name.into(),
            account_indices,
            grant.profile.permissions(narrowing.read_only),
            grant.limits.envelope_bytes,
        ))
    }
    pub fn limits(&self, context: &RequestContext) -> Result<&crate::config::Limits, Error> {
        Ok(&self.grant(context)?.limits)
    }
    /// Bound the currently implemented discovery envelopes without cloning labels.
    #[cfg(feature = "mcp")]
    pub(crate) fn response_bound(&self, context: &RequestContext) -> Result<usize, Error> {
        let maximum = self
            .limits(context)?
            .envelope_bytes
            .min(context.response_limit());
        if context.permissions().contains(&Permission::SearchMessages) {
            return Ok(maximum);
        }
        let mut size = 2048usize.min(maximum);
        for account in self.visible_accounts(context) {
            // Covers account identity, generation, operation names and envelope
            // fields; capability/health entries are smaller than this discovery entry.
            size = size.saturating_add(512).min(maximum);
            let Ok(alias) = serialized_size(&account.alias, maximum - size) else {
                return Ok(maximum);
            };
            size += alias;
            let Ok(identities) = serialized_size(&account.from_identities, maximum - size) else {
                return Ok(maximum);
            };
            size += identities;
        }
        if context.permissions().contains(&Permission::ListMailboxes) {
            let grant = self.grant(context)?;
            for account in self.visible_accounts(context) {
                let mut entries = account
                    .mailboxes
                    .iter()
                    .filter(|name| {
                        grant.mailboxes.iter().any(|allowed| {
                            crate::domain::mailbox_identity(name)
                                == crate::domain::mailbox_identity(allowed)
                        })
                    })
                    .map(|name| {
                        2048usize
                            .saturating_add(grant.limits.token_bytes)
                            .saturating_add(12 * name.len())
                    })
                    .collect::<Vec<_>>();
                entries.sort_unstable_by(|a, b| b.cmp(a));
                let mailbox_size = entries
                    .into_iter()
                    .take(grant.limits.mailbox_page)
                    .fold(2048usize + grant.limits.token_bytes, usize::saturating_add);
                size = size.max(mailbox_size.min(maximum));
            }
        }
        Ok(size)
    }
    pub async fn execute(
        &self,
        context: &RequestContext,
        operation: Operation,
    ) -> Result<OperationResult, Error> {
        let _reservation = self.requests.reserve(self.limits(context)?)?;
        let transfer = matches!(operation, Operation::GetAttachment(_));
        let execution = self.execute_inner(context, operation);
        // Transfers own the earlier of operation timeout and transfer expiry, including
        // which error to return when both deadlines coincide.
        if transfer {
            execution.await
        } else {
            self.with_deadline(context, execution).await
        }
    }
    async fn with_deadline<T>(
        &self,
        context: &RequestContext,
        execution: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let deadline =
            std::time::Duration::from_secs(self.limits(context)?.operation_seconds as u64);
        tokio::time::timeout(deadline, execution)
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
    }
    async fn execute_inner(
        &self,
        context: &RequestContext,
        operation: Operation,
    ) -> Result<OperationResult, Error> {
        let grant = self.grant(context)?;
        self.registry.check_revision()?;
        let _local = if matches!(
            operation,
            Operation::ListAccounts(_) | Operation::Capabilities | Operation::Health
        ) {
            Some(self.requests.admit("", &grant.limits).await?)
        } else {
            None
        };
        let operations = || {
            [
                ("list_accounts", None),
                ("capabilities", None),
                ("health", None),
                ("list_mailboxes", Some(Permission::ListMailboxes)),
                ("search_messages", Some(Permission::SearchMessages)),
                ("get_message", Some(Permission::ReadMessage)),
                ("list_attachments", Some(Permission::ReadAttachment)),
                ("get_attachment", Some(Permission::ReadAttachment)),
            ]
            .into_iter()
            .filter(|(_, permission)| {
                permission.is_none_or(|permission| context.permissions().contains(&permission))
            })
            .map(|(name, _)| name.to_owned())
            .collect()
        };
        let result = match operation {
            Operation::ListAttachments(input) => {
                OperationResult::Attachments(self.list_attachments(context, input).await?)
            }
            Operation::GetAttachment(input) => {
                OperationResult::Attachment(self.get_attachment(context, input).await?)
            }
            Operation::GetMessage(input) => {
                OperationResult::Message(self.get_message(context, input).await?)
            }
            Operation::SearchMessages(input) => {
                OperationResult::Messages(self.search_messages(context, input).await?)
            }
            Operation::ListMailboxes(input) => {
                OperationResult::Mailboxes(self.list_mailboxes(context, input).await?)
            }
            Operation::ListAccounts(input) => {
                let limit = input.limit.unwrap_or(grant.limits.accounts);
                if limit == 0 || limit > grant.limits.accounts {
                    return Err(Error::new(ErrorCode::InvalidRequest));
                }
                // Count encoded field bytes before cloning operator-controlled labels.
                let mut ordered = self.visible_accounts(context).collect::<Vec<_>>();
                ordered.sort_by_key(|account| self.registry.identity(&account.key).0);
                let complete = ordered.len() <= limit;
                ordered.truncate(limit);
                let mut budget = OutputBudget::new(context.response_limit().saturating_sub(512));
                budget.reserve(32)?;
                for account in &ordered {
                    budget.reserve(256)?;
                    budget.count(&account.alias)?;
                    budget.count(&account.from_identities)?;
                }
                let visible = ordered
                    .into_iter()
                    .map(|account| {
                        let (account_id, generation) = self.registry.identity(&account.key);
                        Account {
                            alias: account.alias.clone(),
                            account_id: account_id.to_owned(),
                            generation,
                            from_identities: account.from_identities.clone(),
                            capabilities: operations(),
                            availability: self.availability(account_id),
                        }
                    })
                    .collect::<Vec<_>>();
                OperationResult::Accounts(AccountDiscovery {
                    accounts: visible,
                    complete,
                })
            }
            Operation::Capabilities => OperationResult::Capabilities(Capabilities {
                operations: operations(),
                permissions: context.permissions().to_vec(),
                health: self.health(context)?,
                capacity: Self::capacity(&grant.limits),
            }),
            Operation::Health => OperationResult::Health(self.health(context)?),
        };
        serialized_size(&result, context.response_limit().saturating_sub(512))?;
        Ok(result)
    }
    fn capacity(limits: &crate::config::Limits) -> Capacity {
        Capacity {
            isolation: None,
            per_process: ProcessCapacity {
                active_requests: limits.active_requests as u64,
                queued_requests: limits.queued_requests as u64,
                buffered_bytes: limits.buffered_bytes as u64,
            },
        }
    }

    fn health(&self, context: &RequestContext) -> Result<Health, Error> {
        let mut budget = OutputBudget::new(context.response_limit().saturating_sub(512));
        budget.reserve(256)?;
        let mut accounts = Vec::new();
        for account in self.visible_accounts(context) {
            budget.reserve(160)?;
            let (account_id, generation) = self.registry.identity(&account.key);
            accounts.push(AccountHealth {
                account_id: account_id.to_owned(),
                generation,
                availability: self.availability(account_id),
            });
        }
        accounts.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        let unavailable = accounts
            .iter()
            .filter(|account| account.availability == Availability::Unavailable)
            .count();
        Ok(Health {
            status: if unavailable == 0 {
                "ready"
            } else if unavailable == accounts.len() {
                "unavailable"
            } else {
                "degraded"
            }
            .into(),
            grant: context.grant_name().into(),
            accounts,
        })
    }
    fn availability(&self, account: &str) -> Availability {
        self.observations
            .lock()
            .unwrap()
            .get(account)
            .copied()
            .unwrap_or(Availability::Unknown)
    }
    fn observed<T>(&self, account: &str, result: Result<T, Error>) -> Result<T, Error> {
        match &result {
            Ok(_) => {
                self.observations
                    .lock()
                    .unwrap()
                    .insert(account.into(), Availability::Available);
            }
            Err(error) => self.observe_failure(account, error),
        }
        result
    }
    fn observe_failure(&self, account: &str, error: &Error) {
        if matches!(
            error.code,
            ErrorCode::ProviderUnavailable
                | ErrorCode::AuthenticationFailed
                | ErrorCode::CredentialUnavailable
                | ErrorCode::TlsFailed
        ) {
            self.observations
                .lock()
                .unwrap()
                .insert(account.into(), Availability::Unavailable);
        }
    }
    fn visible_accounts<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> impl ExactSizeIterator<Item = &'a AccountConfig> {
        context
            .account_indices()
            .iter()
            .map(|&index| &self.config.accounts[index])
    }
    fn grant(&self, context: &RequestContext) -> Result<&crate::config::AccessGrant, Error> {
        if !context.belongs_to(self.context_id) {
            return Err(denied());
        }
        self.config
            .grants
            .iter()
            .find(|grant| grant.name == context.grant_name())
            .ok_or_else(denied)
    }
}
fn denied() -> Error {
    Error::new(ErrorCode::PermissionDenied)
}
