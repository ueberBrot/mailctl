//! Authorized mailbox inventories and installation-scoped references.
use super::{Service, tokens::fingerprint};
use crate::domain::mailbox_identity;
use crate::{
    config::{AccountConfig, Limits, MailboxMatcher, MailboxScope},
    domain::{Error, ErrorCode, ListMailboxesInput, Mailbox, MailboxDiscovery, MailboxMetadata},
    policy::{Permission, RequestContext},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy)]
pub struct MailboxTarget<'a> {
    pub account_id: &'a str,
    pub generation: u64,
    pub config: &'a AccountConfig,
}

pub trait MailboxBackend: Send + Sync {
    fn discover_all<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>>;

    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>>;
}

fn validate_metadata(row: &MailboxMetadata) -> Result<(), Error> {
    if (row.name.is_empty() && row.selectable)
        || row.name.len() > 1024
        || row.name.chars().any(char::is_control)
        || row.special_use.len() > 16
        || row.special_use.iter().any(|flag| flag.len() > 64)
    {
        return Err(Error::new(ErrorCode::ProviderUnavailable));
    }
    Ok(())
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

    fn inventory(
        &self,
        target: MailboxTarget<'_>,
        names: Option<&[String]>,
        limits: &Limits,
    ) -> Result<Vec<MailboxMetadata>, Error> {
        let store = self.0.read().unwrap();
        let Some(rows) = store.get(&target.config.key) else {
            return Ok(Vec::new());
        };
        // Wildcard characters require a full provider inventory before exact
        // filtering. Count those raw rows just as the IMAP adapter does.
        let full_inventory =
            names.is_none_or(|names| names.iter().any(|name| name.contains(['*', '%'])));
        if full_inventory && rows.len() > limits.mailbox_inventory {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        if full_inventory {
            let mut seen = BTreeMap::new();
            for row in rows {
                validate_metadata(row)?;
                if row.name.is_empty() {
                    continue;
                }
                let attributes = (
                    row.selectable,
                    row.special_use
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
                );
                match seen.entry(mailbox_identity(&row.name)) {
                    Entry::Vacant(entry) => {
                        entry.insert(attributes);
                    }
                    Entry::Occupied(entry) if entry.get() != &attributes => {
                        return Err(Error::new(ErrorCode::ProviderUnavailable));
                    }
                    Entry::Occupied(_) => {}
                }
            }
        }
        let matcher = MailboxMatcher::new(names);
        let selected = rows
            .iter()
            .filter(|mailbox| matcher.allows(&mailbox.name))
            .take(limits.mailbox_inventory.saturating_add(1))
            .collect::<Vec<_>>();
        drop(matcher);
        if selected.len() > limits.mailbox_inventory {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        selected
            .into_iter()
            .map(|row| {
                validate_metadata(row)?;
                Ok(row.clone())
            })
            .collect()
    }
}
impl MailboxBackend for MemoryMailboxes {
    fn discover_all<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move { self.inventory(target, None, limits) })
    }
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move { self.inventory(target, Some(names), limits) })
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
        let target = self.visible_account_target(context, account_id)?;
        if target.generation != expected_generation {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        Self::authorize_mailbox_scope(grant, target, mailbox)
    }

    pub(super) fn authorize_mailbox_scope<'a>(
        grant: &crate::config::AccessGrant,
        target: MailboxTarget<'a>,
        mailbox: &str,
    ) -> Result<MailboxTarget<'a>, Error> {
        if !target.config.mailboxes.allows(mailbox) || !grant.mailboxes.allows(mailbox) {
            return Err(Error::new(ErrorCode::MailboxNotAllowed));
        }
        Ok(target)
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
        let grant = self.grant(context)?;
        if !context.permissions().contains(&Permission::ListMailboxes) {
            return Err(super::denied());
        }
        let limits = &grant.limits;
        let limit = input.limit.unwrap_or(limits.mailbox_page);
        if limit == 0 || limit > limits.mailbox_page {
            return Err(Error::input_limit("limit", limits.mailbox_page));
        }
        if input.account.as_ref().is_some_and(|a| a.len() > 1024) {
            return Err(Error::invalid_input(
                "account must be an account alias of at most 1024 UTF-8 bytes",
            ));
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
            return Err(Error::invalid_input(
                "Specify account using an alias returned by account discovery, or resolve one mailbox reference",
            ));
        }
        let (id, generation) = self.registry.identity(&account.key);
        if let Some(reference) = &reference {
            self.authorize_mailbox(context, id, reference.generation, &reference.mailbox)?;
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
        let mut effective = account.mailboxes.intersection(&grant.mailboxes);
        if let Some(reference) = &reference {
            effective =
                effective.intersection(&MailboxScope::Only(vec![reference.mailbox.clone()]));
        }
        if matches!(&effective, MailboxScope::Only(names) if names.len() > limits.mailbox_inventory)
        {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let _admission = self.requests.admit(id, limits).await?;
        let rows = if matches!(&effective, MailboxScope::Only(names) if names.is_empty()) {
            Vec::new()
        } else {
            let target = MailboxTarget {
                account_id: id,
                generation,
                config: account,
            };
            let live;
            let backend: &dyn MailboxBackend = match &self.mailbox_backend {
                Some(backend) => backend.as_ref(),
                None => {
                    live = self.imap_backend(target).await?;
                    &live
                }
            };
            let rows = match &effective {
                MailboxScope::All => backend.discover_all(target, limits).await,
                MailboxScope::Only(names) => backend.discover(target, names, limits).await,
            };
            self.observed(id, rows)?
        };
        if rows.len() > limits.mailbox_inventory {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let matcher = MailboxMatcher::new(match &effective {
            MailboxScope::All => None,
            MailboxScope::Only(names) => Some(names),
        });
        let mut inventory = BTreeMap::new();
        for mut row in rows {
            validate_metadata(&row)?;
            if effective.is_all() && row.name.is_empty() && !row.selectable {
                continue;
            }
            let identity = mailbox_identity(&row.name);
            if row.name.is_empty() || !matcher.allows(&row.name) {
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
        drop(matcher);
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
