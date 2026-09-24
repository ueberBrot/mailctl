//! IMAP discovery, search, and body reads share credential resolution.
use super::{MailboxBackend, MailboxTarget, SearchBackend, Service};
use crate::{
    config::Limits,
    domain::{BodyText, EmptyBodyReason, Error, ErrorCode, MailboxMetadata},
    search::{SearchBatch, SearchRequest},
};
use std::{future::Future, pin::Pin, sync::Arc};

impl Service {
    pub(super) async fn imap_backend(
        &self,
        target: MailboxTarget<'_>,
    ) -> Result<ImapBackend, Error> {
        Ok(ImapBackend {
            runtime: self
                .authentication()
                .await
                .inspect_err(|error| self.observe_failure(target.account_id, error))?,
            account: Arc::new(crate::authentication::Account {
                id: uuid::Uuid::parse_str(target.account_id)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?,
                generation: target.generation,
                config: target.config.clone(),
                source: self.host.credential_source(&target.config.credential),
            }),
        })
    }
}

pub(super) struct ImapBackend {
    runtime: Arc<crate::authentication::Runtime>,
    account: Arc<crate::authentication::Account>,
}
impl ImapBackend {
    async fn acquire(&self, limits: &Limits) -> Result<crate::authentication::Lease, Error> {
        self.runtime
            .acquire(&self.account, limits)
            .await
            .map_err(super::credentials::authentication_error)
    }
}
impl MailboxBackend for ImapBackend {
    fn discover<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        names: &'a [String],
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MailboxMetadata>, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.runtime
                .discover(&self.account, names, limits)
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
        _: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(limits).await?;
            lease
                .with_connection(async |connection| {
                    connection
                        .search(request, limits, &mut crate::imap::Metrics::default())
                        .await
                })
                .await
        })
    }
}
impl super::message::BodyBackend for ImapBackend {
    fn read<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        request: crate::imap::BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<super::BodyRead, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self.acquire(limits).await?;
            lease
                .with_connection(async |connection| {
                    connection
                        .read_body(
                            mailbox,
                            request,
                            &crate::imap::Limits::body(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map(Into::into)
                .map_err(Into::into)
        })
    }
}
impl From<crate::imap::BodyPage> for super::BodyRead {
    fn from(page: crate::imap::BodyPage) -> Self {
        Self {
            continuation: page.continuation,
            body: BodyText {
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
                next_cursor: None,
            },
        }
    }
}

impl super::AttachmentBackend for ImapBackend {
    fn start(
        &self,
        _: MailboxTarget<'_>,
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        limits: &Limits,
    ) -> Result<Box<dyn super::AttachmentReader>, Error> {
        let decoder = crate::imap::AttachmentDecoder::new(
            mailbox,
            uid,
            validity,
            part,
            &crate::imap::Limits::attachment(limits),
        )
        .map_err(Error::from)?;
        Ok(Box::new(ImapAttachment {
            runtime: self.runtime.clone(),
            account: self.account.clone(),
            decoder,
        }))
    }

    fn list<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        request: crate::imap::AttachmentListRequest,
        limits: &'a Limits,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<crate::imap::AttachmentMetadata>, Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.acquire(limits)
                .await?
                .with_connection(async |connection| {
                    connection
                        .list_attachments(
                            mailbox,
                            request,
                            &crate::imap::Limits::attachment(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(Into::into)
        })
    }
}

struct ImapAttachment {
    runtime: Arc<crate::authentication::Runtime>,
    account: Arc<crate::authentication::Account>,
    decoder: crate::imap::AttachmentDecoder,
}
impl super::AttachmentReader for ImapAttachment {
    fn next<'a>(
        &'a mut self,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AttachmentData, Error>> + Send + 'a>> {
        Box::pin(async move {
            let lease = self
                .runtime
                .acquire(&self.account, limits)
                .await
                .map_err(super::credentials::authentication_error)?;
            lease
                .with_connection(async |connection| {
                    connection
                        .read_attachment(
                            &mut self.decoder,
                            &crate::imap::Limits::attachment(limits),
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(|error| match error {
                    crate::imap::Error::Limit => Error::new(ErrorCode::AttachmentTooLarge),
                    error => error.into(),
                })
        })
    }
}

impl super::DraftBackend for ImapBackend {
    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        mailbox: &'a str,
        limits: &'a Limits,
    ) -> super::DraftPreparation<'a> {
        Box::pin(async move {
            let (lease, validity) = self
                .acquire(limits)
                .await?
                .draft_target(mailbox, &crate::imap::Limits::body(limits))
                .await
                .map_err(|error| match error {
                    crate::imap::Error::UnsafeSelection => {
                        Error::new(ErrorCode::DraftMailboxUnavailable)
                    }
                    error => error.into(),
                })?;
            Ok(Box::new(ImapDraft {
                lease,
                mailbox,
                validity,
            }) as Box<dyn super::DraftAppend>)
        })
    }
}
struct ImapDraft<'a> {
    lease: crate::authentication::Lease,
    mailbox: &'a str,
    validity: u32,
}
impl super::DraftAppend for ImapDraft<'_> {
    fn uid_validity(&self) -> u32 {
        self.validity
    }
    fn append<'a>(
        self: Box<Self>,
        draft: &'a crate::draft::PreparedDraft,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async move {
            self.lease
                .with_connection(async |connection| {
                    let mut bounds = crate::imap::Limits::body(limits);
                    bounds.max_operation_bytes =
                        limits.draft_mime_bytes.saturating_add(1024 * 1024);
                    connection
                        .append_draft(
                            self.mailbox,
                            draft,
                            &bounds,
                            &mut crate::imap::Metrics::default(),
                        )
                        .await
                })
                .await
                .map_err(Into::into)
        })
    }
}
