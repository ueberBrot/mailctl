//! Authorized search and exact descending-UID continuation.
use super::{
    MailboxTarget, Service,
    mailboxes::{Reference, fingerprint},
};
use crate::{
    config::Limits,
    domain::{
        Error, ErrorCode, MessageEnvelope, MessageMetadata, MessageSearch, SearchCriteria,
        SearchMessagesInput, mailbox_identity,
    },
    encoding::OutputBudget,
    policy::{Permission, RequestContext},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPosition {
    pub uid_validity: u32,
    pub upper_uid: u32,
    pub next_uid: u32,
}

pub struct SearchRequest<'a> {
    pub mailbox: &'a str,
    pub criteria: &'a SearchCriteria,
    pub position: Option<SearchPosition>,
    pub limit: usize,
    pub response_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct LocatedMessage {
    pub uid: u32,
    pub metadata: MessageMetadata,
}
pub struct SearchBatch {
    pub position: SearchPosition,
    pub messages: Vec<LocatedMessage>,
}

pub trait SearchBackend: Send + Sync {
    fn search<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>>;
}

pub struct ImapMessages {
    runtime: Arc<crate::authentication::Runtime>,
    sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
}
impl ImapMessages {
    pub fn new(
        runtime: Arc<crate::authentication::Runtime>,
        sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
    ) -> Self {
        Self { runtime, sources }
    }
}
impl SearchBackend for ImapMessages {
    fn search<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let source = self
                .sources
                .get(&target.config.key)
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::CredentialUnavailable))?;
            let account = crate::authentication::Account {
                id: uuid::Uuid::parse_str(target.account_id)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?,
                generation: target.generation,
                config: target.config.clone(),
                source,
            };
            let lease = self
                .runtime
                .acquire(&account, limits)
                .await
                .map_err(super::credentials::authentication_error)?;
            lease.search(request, limits).await
        })
    }
}
pub(crate) fn imap_error(error: crate::imap::Error) -> Error {
    super::credentials::authentication_error(crate::authentication::Error::Imap(error))
}

pub(crate) trait SelectedMailbox {
    fn uid_validity(&self) -> u32;
    fn upper_uid(&mut self) -> impl Future<Output = Result<u32, Error>> + Send;
    fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> impl Future<Output = Result<Vec<u32>, Error>> + Send;
    fn fetch(
        &mut self,
        uids: &[u32],
    ) -> impl Future<Output = Result<Vec<LocatedMessage>, Error>> + Send;
}

/// Each resume searches live predicates below the last consumed UID, including a partial window.
pub(crate) async fn page(
    selected: &mut impl SelectedMailbox,
    request: &SearchRequest<'_>,
    limits: &Limits,
) -> Result<SearchBatch, Error> {
    limits.validate()?;
    if request.limit == 0 || request.limit > limits.search_page {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let validity = selected.uid_validity();
    if validity == 0 {
        return Err(Error::new(ErrorCode::ProviderUnavailable));
    }
    let mut position = match request.position {
        Some(position) if position.uid_validity != validity => {
            return Err(Error::new(ErrorCode::StaleCursor));
        }
        Some(position) => position,
        None => {
            let upper_uid = selected.upper_uid().await?;
            SearchPosition {
                uid_validity: validity,
                upper_uid,
                next_uid: upper_uid,
            }
        }
    };
    let mut messages = Vec::new();
    let mut budget = OutputBudget::new(request.response_bytes);
    for _ in 0..limits.search_windows {
        if position.next_uid == 0 || messages.len() == request.limit {
            break;
        }
        let last = position.next_uid;
        let first = last
            .saturating_sub(limits.search_uid_window as u32 - 1)
            .max(1);
        let mut uids = selected.matches(first, last, request.criteria).await?;
        if uids.len() > limits.search_uid_window
            || uids.iter().any(|uid| !(first..=last).contains(uid))
        {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        uids.sort_unstable_by(|a, b| b.cmp(a));
        if uids.windows(2).any(|uids| uids[0] == uids[1]) {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        let remaining = request.limit - messages.len();
        position.next_uid = if uids.len() > remaining {
            uids[remaining - 1] - 1
        } else {
            first - 1
        };
        uids.truncate(remaining);
        if uids.is_empty() {
            continue;
        }
        let mut rows = selected.fetch(&uids).await?;
        rows.sort_unstable_by(|a, b| b.uid.cmp(&a.uid));
        if rows.len() > uids.len()
            || rows.windows(2).any(|rows| rows[0].uid == rows[1].uid)
            || rows
                .iter()
                .any(|row| uids.binary_search_by(|uid| row.uid.cmp(uid)).is_err())
        {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        for row in rows {
            budget.count(&row.metadata)?;
            budget.reserve(1024)?;
            messages.push(row);
        }
    }
    Ok(SearchBatch { position, messages })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    account: String,
    generation: u64,
    mailbox: String,
    scope: String,
    query: String,
    position: SearchPosition,
}
#[derive(Serialize)]
struct MessageReference<'a> {
    account: &'a str,
    generation: u64,
    mailbox: &'a str,
    uid_validity: u32,
    uid: u32,
}

impl Service {
    pub fn with_search_backend(mut self, backend: Arc<dyn SearchBackend>) -> Self {
        self.search_backend = Some(backend);
        self
    }
    pub(super) async fn search_messages(
        &self,
        context: &RequestContext,
        input: SearchMessagesInput,
    ) -> Result<MessageSearch, Error> {
        let deadline = Duration::from_secs(self.grant(context)?.limits.operation_seconds as u64);
        tokio::time::timeout(deadline, self.search_inner(context, input))
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
    }
    async fn search_inner(
        &self,
        context: &RequestContext,
        input: SearchMessagesInput,
    ) -> Result<MessageSearch, Error> {
        let grant = self.grant(context)?;
        if !context.permissions().contains(&Permission::SearchMessages) {
            return Err(super::denied());
        }
        let limits = &grant.limits;
        let limit = input.limit.unwrap_or(limits.search_page);
        if limit == 0 || limit > limits.search_page {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let reference: Reference = self.decode(
            "mb1",
            &input.mailbox,
            limits.token_bytes,
            ErrorCode::StaleReference,
        )?;
        let account = self
            .visible_accounts(context)
            .find(|account| self.registry.identity(&account.key).0 == reference.account)
            .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?;
        let (id, generation) = self.registry.identity(&account.key);
        if generation != reference.generation {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        let name = mailbox_identity(&reference.mailbox);
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
        let scope = fingerprint(&(
            self.registry.revision(),
            context.grant_name(),
            context.account_indices(),
            context.permissions(),
        ))?;
        let query = fingerprint(&input.criteria)?;
        let cursor: Option<Cursor> = input
            .cursor
            .as_ref()
            .map(|cursor| self.decode("sc1", cursor, limits.token_bytes, ErrorCode::StaleCursor))
            .transpose()?;
        if cursor.as_ref().is_some_and(|cursor| {
            cursor.account != id
                || cursor.generation != generation
                || cursor.mailbox != name
                || cursor.scope != scope
                || cursor.query != query
                || cursor.position.next_uid == 0
                || cursor.position.next_uid > cursor.position.upper_uid
        }) {
            return Err(Error::new(ErrorCode::StaleCursor));
        }
        let live;
        let backend: &dyn SearchBackend = match &self.search_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = ImapMessages::new(
                    self.authentication().await?.clone(),
                    BTreeMap::from([(
                        account.key.clone(),
                        crate::credentials::source_for(&account.credential),
                    )]),
                );
                &live
            }
        };
        let batch = backend
            .search(
                MailboxTarget {
                    account_id: id,
                    generation,
                    config: account,
                },
                SearchRequest {
                    mailbox: name,
                    criteria: &input.criteria,
                    position: cursor.map(|cursor| cursor.position),
                    limit,
                    response_bytes: context.response_limit().saturating_sub(2048),
                },
                limits,
            )
            .await?;
        let complete = batch.position.next_uid == 0;
        let next_cursor = if complete {
            None
        } else {
            Some(self.encode(
                "sc1",
                &Cursor {
                    account: id.into(),
                    generation,
                    mailbox: name.into(),
                    scope,
                    query,
                    position: batch.position,
                },
                limits.token_bytes,
            )?)
        };
        let mut budget = OutputBudget::new(context.response_limit().saturating_sub(512));
        budget.count(&input.criteria)?;
        budget.count(&next_cursor)?;
        budget.count(&input.mailbox)?;
        let mut messages = Vec::new();
        for message in batch.messages {
            budget.count(&message.metadata)?;
            let reference = self.encode(
                "ms1",
                &MessageReference {
                    account: id,
                    generation,
                    mailbox: name,
                    uid_validity: batch.position.uid_validity,
                    uid: message.uid,
                },
                limits.token_bytes,
            )?;
            budget.count(&reference)?;
            messages.push(MessageEnvelope {
                reference,
                metadata: message.metadata,
            });
        }
        Ok(MessageSearch {
            account_id: id.into(),
            generation,
            mailbox_reference: input.mailbox,
            criteria: input.criteria,
            messages,
            complete,
            next_cursor,
        })
    }
}

#[derive(Clone)]
pub struct MemoryMessage {
    pub uid: u32,
    pub metadata: MessageMetadata,
    pub bcc: Vec<String>,
    /// Searchable message text, including headers and body.
    pub text: String,
}
struct MemoryMailbox {
    validity: u32,
    messages: BTreeMap<u32, MemoryMessage>,
}
#[derive(Default)]
pub struct MemoryMessages(RwLock<BTreeMap<(String, String), Arc<MemoryMailbox>>>);
impl MemoryMessages {
    pub fn set(
        &self,
        account_key: &str,
        mailbox: &str,
        uid_validity: u32,
        messages: Vec<MemoryMessage>,
    ) {
        self.0.write().unwrap().insert(
            (account_key.into(), mailbox_identity(mailbox).into()),
            Arc::new(MemoryMailbox {
                validity: uid_validity,
                messages: messages
                    .into_iter()
                    .map(|message| (message.uid, message))
                    .collect(),
            }),
        );
    }
}
impl SearchBackend for MemoryMessages {
    fn search<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let mailbox = self
                .0
                .read()
                .unwrap()
                .get(&(
                    target.config.key.clone(),
                    mailbox_identity(request.mailbox).into(),
                ))
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
            page(&mut MemorySelection(mailbox), &request, limits).await
        })
    }
}
struct MemorySelection(Arc<MemoryMailbox>);
impl SelectedMailbox for MemorySelection {
    fn uid_validity(&self) -> u32 {
        self.0.validity
    }
    async fn upper_uid(&mut self) -> Result<u32, Error> {
        Ok(self.0.messages.last_key_value().map_or(0, |(uid, _)| *uid))
    }
    async fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> Result<Vec<u32>, Error> {
        Ok(self
            .0
            .messages
            .range(first..=last)
            .filter(|(_, message)| {
                criteria.predicates().iter().all(|predicate| {
                    use crate::domain::SearchPredicate::*;
                    match predicate {
                        RequiredFlag { flag } => message
                            .metadata
                            .flags
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(flag.imap_name())),
                        ForbiddenFlag { flag } => !message
                            .metadata
                            .flags
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(flag.imap_name())),
                        ReceivedAfter { date } => calendar_date(&message.metadata.received_date)
                            .is_some_and(|value| value >= date.date()),
                        ReceivedBefore { date } => calendar_date(&message.metadata.received_date)
                            .is_some_and(|value| value < date.date()),
                        SentAfter { date } => message
                            .metadata
                            .sent_date
                            .value()
                            .and_then(|value| calendar_date(value))
                            .is_some_and(|value| value >= date.date()),
                        SentBefore { date } => message
                            .metadata
                            .sent_date
                            .value()
                            .and_then(|value| calendar_date(value))
                            .is_some_and(|value| value < date.date()),
                        Subject { value } => message
                            .metadata
                            .subject
                            .value()
                            .is_some_and(|subject| contains(subject, value)),
                        Text { value } => contains(&message.text, value),
                        From { value } => address_match(&message.metadata.from, value),
                        To { value } => address_match(&message.metadata.to, value),
                        Cc { value } => address_match(&message.metadata.cc, value),
                        Bcc { value } => message.bcc.iter().any(|address| contains(address, value)),
                    }
                })
            })
            .map(|(uid, _)| *uid)
            .collect())
    }
    async fn fetch(&mut self, uids: &[u32]) -> Result<Vec<LocatedMessage>, Error> {
        Ok(uids
            .iter()
            .filter_map(|uid| self.0.messages.get(uid))
            .map(|message| LocatedMessage {
                uid: message.uid,
                metadata: message.metadata.clone(),
            })
            .collect())
    }
}
fn calendar_date(value: &str) -> Option<chrono::NaiveDate> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.date_naive())
}
fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}
fn address_match(
    addresses: &crate::domain::Metadata<Vec<crate::domain::MessageAddress>>,
    value: &str,
) -> bool {
    addresses.value().is_some_and(|addresses| {
        addresses.iter().any(|address| {
            contains(&address.address, value)
                || address
                    .name
                    .as_ref()
                    .is_some_and(|name| contains(name, value))
        })
    })
}
