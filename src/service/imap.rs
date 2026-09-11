//! IMAP discovery, search, and body reads share credential resolution.
use super::{MailboxBackend, MailboxTarget, SearchBackend, Service};
use crate::{
    config::{AccountConfig, Limits},
    domain::{BodyText, EmptyBodyReason, Error, ErrorCode, MailboxMetadata},
    search::{SearchBatch, SearchRequest},
};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

impl Service {
    pub(super) async fn imap_backend(&self, account: &AccountConfig) -> Result<ImapBackend, Error> {
        Ok(ImapBackend::new(
            self.authentication().await?.clone(),
            BTreeMap::from([(
                account.key.clone(),
                crate::credentials::source_for(&account.credential),
            )]),
        ))
    }
}

pub struct ImapBackend {
    runtime: Arc<crate::authentication::Runtime>,
    sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
}
impl ImapBackend {
    pub fn new(
        runtime: Arc<crate::authentication::Runtime>,
        sources: BTreeMap<String, Arc<dyn crate::credentials::SecretSource>>,
    ) -> Self {
        Self { runtime, sources }
    }
    fn account(&self, target: MailboxTarget<'_>) -> Result<crate::authentication::Account, Error> {
        let source = self
            .sources
            .get(&target.config.key)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::CredentialUnavailable))?;
        Ok(crate::authentication::Account {
            id: uuid::Uuid::parse_str(target.account_id)
                .map_err(|_| Error::new(ErrorCode::InternalError))?,
            generation: target.generation,
            config: target.config.clone(),
            source,
        })
    }
    async fn acquire(
        &self,
        target: MailboxTarget<'_>,
        limits: &Limits,
    ) -> Result<crate::authentication::Lease, Error> {
        self.runtime
            .acquire(&self.account(target)?, limits)
            .await
            .map_err(super::credentials::authentication_error)
    }
}
impl MailboxBackend for ImapBackend {
    fn discover<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            let account = self.account(target)?;
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

impl SearchBackend for ImapBackend {
    fn search<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(target, limits).await?;
            lease.search(request, limits).await
        })
    }
}
impl super::message::BodyBackend for ImapBackend {
    fn read<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: crate::imap::BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::domain::BodyText, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(target, limits).await?;
            lease
                .read_body(mailbox, request, limits)
                .await
                .map(Into::into)
        })
    }
}
impl From<crate::imap::BodyPage> for BodyText {
    fn from(page: crate::imap::BodyPage) -> Self {
        Self {
            empty_reason: page
                .selected_part
                .is_none()
                .then_some(EmptyBodyReason::NoSupportedBody),
            text: page.text,
            selected_part: page.selected_part,
            source_media_type: page.source_media_type,
            representation_version: page.representation_version.into(),
            converted: page.converted,
            replacements: page.replacements,
            truncated: page.truncated,
            continuation_available: false,
        }
    }
}
