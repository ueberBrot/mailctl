//! Authorized mailbox inventories and installation-scoped references.
use super::{Service, tokens::fingerprint};
use crate::domain::mailbox_identity;
use crate::{
    config::{AccountConfig, Limits},
    domain::{Error, ErrorCode, ListMailboxesInput, Mailbox, MailboxDiscovery, MailboxMetadata},
    policy::{Permission, RequestContext},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

pub struct MailboxTarget<'a> {
    pub account_id: &'a str,
    pub generation: u64,
    pub config: &'a AccountConfig,
}

pub trait MailboxBackend: Send + Sync {
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>>;
}

#[derive(Default)]
pub struct MemoryMailboxes(RwLock<BTreeMap<String, Vec<MailboxMetadata>>>);
impl MemoryMailboxes {
    pub fn set(&self, account_key: &str, mailboxes: Vec<MailboxMetadata>) {
        self.0
            .write()
            .unwrap()
            .insert(account_key.into(), mailboxes);
    }
}
impl MailboxBackend for MemoryMailboxes {
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            Ok(self
                .0
                .read()
                .unwrap()
                .get(&target.config.key)
                .into_iter()
                .flatten()
                .filter(|mailbox| {
                    names
                        .iter()
                        .any(|name| mailbox_identity(name) == mailbox_identity(&mailbox.name))
                })
                .cloned()
                .collect())
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference<S = String> {
    pub(super) account: S,
    pub(super) generation: u64,
    pub(super) mailbox: S,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    account: String,
    generation: u64,
    scope: String,
    inventory: String,
    position: usize,
}

impl Service {
    pub(super) fn authorize_mailbox<'a>(
        &'a self,
        context: &'a RequestContext,
        account_id: &str,
        expected_generation: u64,
        mailbox: &str,
    ) -> Result<MailboxTarget<'a>, Error> {
        let grant = self.grant(context)?;
        let (account, id, generation) = self
            .visible_accounts(context)
            .find_map(|account| {
                let (id, generation) = self.registry.identity(&account.key);
                (id == account_id).then_some((account, id, generation))
            })
            .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?;
        if generation != expected_generation {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        let name = mailbox_identity(mailbox);
        if !account
            .mailboxes
            .iter()
            .any(|allowed| mailbox_identity(allowed) == name)
            || !grant
                .mailboxes
                .iter()
                .any(|allowed| mailbox_identity(allowed) == name)
        {
            return Err(Error::new(ErrorCode::MailboxNotAllowed));
        }
        Ok(MailboxTarget {
            config: account,
            account_id: id,
            generation,
        })
    }

    /// Select a provider adapter when composing the application, before accepting requests.
    pub fn with_mailbox_backend(mut self, backend: Arc<dyn MailboxBackend>) -> Self {
        self.mailbox_backend = Some(backend);
        self
    }

    pub(super) async fn list_mailboxes(
        &self,
        context: &RequestContext,
        input: ListMailboxesInput,
    ) -> Result<MailboxDiscovery, Error> {
        let deadline = Duration::from_secs(self.grant(context)?.limits.operation_seconds as u64);
        tokio::time::timeout(deadline, self.list_mailboxes_inner(context, input))
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
    }

    async fn list_mailboxes_inner(
        &self,
        context: &RequestContext,
        input: ListMailboxesInput,
    ) -> Result<MailboxDiscovery, Error> {
        let grant = self.grant(context)?;
        if !context.permissions().contains(&Permission::ListMailboxes) {
            return Err(super::denied());
        }
        let limits = &grant.limits;
        let limit = input.limit.unwrap_or(limits.mailbox_page);
        if limit == 0
            || limit > limits.mailbox_page
            || input.account.as_ref().is_some_and(|a| a.len() > 1024)
        {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let reference: Option<Reference> = input
            .reference
            .as_ref()
            .map(|reference| {
                self.decode(
                    "mb1",
                    reference,
                    limits.token_bytes,
                    ErrorCode::StaleReference,
                )
            })
            .transpose()?;
        let mut accounts = self.visible_accounts(context).filter(|account| {
            input
                .account
                .as_ref()
                .is_none_or(|alias| &account.alias == alias)
                && reference.as_ref().is_none_or(|reference| {
                    self.registry.identity(&account.key).0 == reference.account
                })
        });
        let account = accounts
            .next()
            .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?;
        if accounts.next().is_some() {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let (id, generation) = self.registry.identity(&account.key);
        if let Some(reference) = &reference {
            if reference.generation != generation {
                return Err(Error::new(ErrorCode::StaleReference));
            }
            if !account
                .mailboxes
                .iter()
                .any(|name| mailbox_identity(name) == mailbox_identity(&reference.mailbox))
                || !grant
                    .mailboxes
                    .iter()
                    .any(|name| mailbox_identity(name) == mailbox_identity(&reference.mailbox))
            {
                return Err(Error::new(ErrorCode::MailboxNotAllowed));
            }
        }
        let scope = fingerprint(&(
            self.registry.revision(),
            context.grant_name(),
            context.account_indices(),
            context.permissions(),
            reference.as_ref().map(|reference| &reference.mailbox),
        ))?;
        let cursor: Option<Cursor> = input
            .cursor
            .as_ref()
            .map(|cursor| self.decode("mc1", cursor, limits.token_bytes, ErrorCode::StaleCursor))
            .transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.account != id || cursor.generation != generation || cursor.scope != scope
        }) {
            return Err(Error::new(ErrorCode::StaleCursor));
        }
        let names = account
            .mailboxes
            .iter()
            .filter(|name| {
                reference.as_ref().is_none_or(|reference| {
                    mailbox_identity(name) == mailbox_identity(&reference.mailbox)
                })
            })
            .filter(|name| {
                grant
                    .mailboxes
                    .iter()
                    .any(|allowed| mailbox_identity(allowed) == mailbox_identity(name))
            })
            .map(|name| (mailbox_identity(name), name))
            .collect::<BTreeMap<_, _>>();
        if names.len() > limits.mailbox_inventory {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        // Preserve canonical identity order for provider-row membership checks.
        let names = names.into_values().cloned().collect::<Vec<_>>();
        let rows = if names.is_empty() {
            Vec::new()
        } else {
            let live;
            let backend: &dyn MailboxBackend = match &self.mailbox_backend {
                Some(backend) => backend.as_ref(),
                None => {
                    live = self.imap_backend(account).await?;
                    &live
                }
            };
            backend
                .discover(
                    MailboxTarget {
                        account_id: id,
                        generation,
                        config: account,
                    },
                    &names,
                    limits,
                )
                .await?
        };
        if rows.len() > limits.mailbox_inventory {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let mut inventory = BTreeMap::new();
        for mut row in rows {
            let identity = mailbox_identity(&row.name);
            if row.name.is_empty()
                || row.name.len() > 1024
                || names
                    .binary_search_by(|name| mailbox_identity(name).cmp(identity))
                    .is_err()
                || row.special_use.len() > 16
                || row.special_use.iter().any(|flag| flag.len() > 64)
            {
                return Err(Error::new(ErrorCode::ProviderUnavailable));
            }
            if identity != row.name {
                row.name = identity.to_owned();
            }
            row.special_use.sort_unstable();
            row.special_use.dedup();
            match inventory.entry(row.name.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                Entry::Occupied(entry) if entry.get() != &row => {
                    return Err(Error::new(ErrorCode::ProviderUnavailable));
                }
                Entry::Occupied(_) => {}
            }
        }
        if reference.is_some() && inventory.is_empty() {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        let inventory_hash = fingerprint(&inventory)?;
        let position = cursor.as_ref().map_or(0, |cursor| cursor.position);
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.inventory != inventory_hash || position >= inventory.len())
        {
            return Err(Error::new(ErrorCode::StaleCursor));
        }
        let end = position.saturating_add(limit).min(inventory.len());
        let complete = end == inventory.len();
        let next_cursor = if complete {
            None
        } else {
            Some(self.encode(
                "mc1",
                &Cursor {
                    account: id.into(),
                    generation,
                    scope,
                    inventory: inventory_hash,
                    position: end,
                },
                limits.token_bytes,
            )?)
        };
        let mut budget =
            crate::encoding::OutputBudget::new(context.response_limit().saturating_sub(512));
        budget.reserve(256)?;
        budget.count(&next_cursor)?;
        let mut mailboxes = Vec::new();
        for metadata in inventory.into_values().skip(position).take(limit) {
            budget.reserve(256)?;
            budget.count(&metadata)?;
            budget.count(&metadata.name)?;
            let reference = self.encode(
                "mb1",
                &Reference {
                    account: id,
                    generation,
                    mailbox: metadata.name.as_str(),
                },
                limits.token_bytes,
            )?;
            budget.count(&reference)?;
            mailboxes.push(Mailbox {
                reference,
                account_id: id.into(),
                generation,
                display_label: metadata.name.clone(),
                metadata,
            });
        }
        Ok(MailboxDiscovery {
            account_id: id.into(),
            generation,
            mailboxes,
            complete,
            next_cursor,
        })
    }
}
