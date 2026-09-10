//! Authorized mailbox inventories and installation-scoped references.
use super::Service;
use crate::domain::mailbox_identity;
use crate::{
    config::{AccountConfig, Limits},
    domain::{Error, ErrorCode, ListMailboxesInput, Mailbox, MailboxDiscovery, MailboxMetadata},
    policy::{Permission, RequestContext},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Write,
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

/// IMAP inventory adapter sharing the process's bounded credential runtime.
pub struct ImapMailboxes {
    runtime: Arc<crate::authentication::Runtime>,
    sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
}
impl ImapMailboxes {
    pub fn new(
        runtime: Arc<crate::authentication::Runtime>,
        sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
    ) -> Self {
        Self { runtime, sources }
    }
}
impl MailboxBackend for ImapMailboxes {
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            let source = self
                .sources
                .get(&target.config.key)
                .ok_or_else(|| Error::new(ErrorCode::CredentialUnavailable))?
                .clone();
            let account = crate::authentication::Account {
                id: uuid::Uuid::parse_str(target.account_id)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?,
                generation: target.generation,
                config: target.config.clone(),
                source,
            };
            self.runtime
                .discover(&account, names, limits)
                .await
                .map_err(super::credentials::authentication_error)
                .map(|rows| {
                    rows.into_iter()
                        .map(|row| MailboxMetadata {
                            name: row.name,
                            selectable: row.selectable,
                            special_use: row
                                .attributes
                                .into_iter()
                                .filter(|attribute| {
                                    [
                                        "\\All",
                                        "\\Archive",
                                        "\\Drafts",
                                        "\\Flagged",
                                        "\\Junk",
                                        "\\Sent",
                                        "\\Trash",
                                    ]
                                    .iter()
                                    .any(|flag| attribute.eq_ignore_ascii_case(flag))
                                })
                                .collect(),
                        })
                        .collect()
                })
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    pub(super) account: String,
    pub(super) generation: u64,
    pub(super) mailbox: String,
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
                    live = ImapMailboxes::new(
                        self.authentication().await?.clone(),
                        BTreeMap::from([(
                            account.key.clone(),
                            crate::credentials::source_for(&account.credential),
                        )]),
                    );
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
            row.special_use.sort();
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
                    account: id.into(),
                    generation,
                    mailbox: metadata.name.clone(),
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

    pub(super) fn encode(
        &self,
        kind: &str,
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<String, Error> {
        let payload = crate::encoding::serialize_bounded(value, maximum)?;
        let mut token = format!("{kind}.");
        URL_SAFE_NO_PAD.encode_string(payload, &mut token);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.registry.reference_key());
        let tag = hmac::sign(&key, token.as_bytes());
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(tag.as_ref(), &mut token);
        if token.len() > maximum {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        Ok(token)
    }
    pub(super) fn decode<T: DeserializeOwned>(
        &self,
        kind: &str,
        token: &str,
        maximum: usize,
        code: ErrorCode,
    ) -> Result<T, Error> {
        let invalid = || Error::new(code);
        if token.len() > maximum {
            return Err(invalid());
        }
        let (signed, tag) = token.rsplit_once('.').ok_or_else(invalid)?;
        let (version, payload) = signed.split_once('.').ok_or_else(invalid)?;
        if version != kind {
            return Err(invalid());
        }
        let tag = URL_SAFE_NO_PAD.decode(tag).map_err(|_| invalid())?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.registry.reference_key());
        hmac::verify(&key, signed.as_bytes(), &tag).map_err(|_| invalid())?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?;
        serde_json::from_slice(&payload).map_err(|_| invalid())
    }
}
pub(super) fn fingerprint(value: &impl Serialize) -> Result<String, Error> {
    let bytes = crate::encoding::serialize_bounded(value, 4 * 1024 * 1024)?;
    let mut fingerprint = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(fingerprint, "{byte:02x}");
    }
    Ok(fingerprint)
}
