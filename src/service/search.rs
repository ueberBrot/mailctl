//! Authorized search and exact descending-UID continuation.
use super::{MailboxTarget, Service, mailboxes::Reference, tokens::fingerprint};
use crate::search::{SearchBatch, SearchPosition, SearchRequest};
use crate::{
    config::Limits,
    domain::{
        Error, ErrorCode, MessageEnvelope, MessageSearch, SearchMessagesInput, mailbox_identity,
    },
    encoding::OutputBudget,
    policy::{Permission, RequestContext},
};
mod memory;
pub use memory::{MemoryMessage, MemoryMessages};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

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
        let (account, id, generation) = self
            .visible_accounts(context)
            .find_map(|account| {
                let (id, generation) = self.registry.identity(&account.key);
                (id == reference.account).then_some((account, id, generation))
            })
            .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?;
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
