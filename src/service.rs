//! Account discovery and access-grant authorization through one application interface.
mod credentials;
pub(crate) use credentials::credential_error;
mod state;
use crate::encoding::{OutputBudget, serialized_size};
use crate::{
    config::{AccountConfig, Config},
    domain::{
        Account, AccountDiscovery, AccountHealth, Availability, Capabilities, Capacity, Error,
        ErrorCode, Health, Operation, OperationResult, ProcessCapacity, Setup,
    },
    policy::{Narrowing, RequestContext},
};
use state::AccountRegistry;
use uuid::Uuid;

pub struct Service {
    config: Config,
    registry: AccountRegistry,
    context_id: Uuid,
    authentication: tokio::sync::OnceCell<crate::authentication::Runtime>,
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
            registry,
            context_id: Uuid::new_v4(),
            authentication: tokio::sync::OnceCell::new(),
        }
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
        Ok(size)
    }
    pub fn execute(
        &self,
        context: &RequestContext,
        operation: Operation,
    ) -> Result<OperationResult, Error> {
        let grant = self.grant(context)?;
        self.registry.check_revision()?;
        let operations = || {
            vec![
                "list_accounts".to_string(),
                "capabilities".to_string(),
                "health".to_string(),
            ]
        };
        let result = match operation {
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
                            availability: Availability::Unknown,
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
                availability: Availability::Unknown,
            });
        }
        accounts.sort_by(|a, b| a.account_id.cmp(&b.account_id));
        Ok(Health {
            status: "ready".into(),
            grant: context.grant_name().into(),
            accounts,
        })
    }
    fn visible_accounts<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> impl Iterator<Item = &'a AccountConfig> {
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
