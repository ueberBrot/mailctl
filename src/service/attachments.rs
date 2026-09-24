//! Attachment access checks precede metadata and transfer work.
use super::{MailboxTarget, Service, tokens::MessageReference};
use crate::{
    config::Limits,
    domain::{self, Error, ErrorCode},
    imap,
    policy::{Permission, RequestContext},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;
mod memory;
mod transfers;
pub use memory::MemoryAttachments;
use transfers::Entry;
pub(crate) use transfers::TransferSession;
pub(super) use transfers::Transfers;

pub trait AttachmentReader: Send {
    fn next<'a>(
        &'a mut self,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<imap::AttachmentData, Error>> + Send + 'a>>;
}

pub trait AttachmentBackend: Send + Sync {
    fn start(
        &self,
        target: MailboxTarget<'_>,
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        limits: &Limits,
    ) -> Result<Box<dyn AttachmentReader>, Error>;

    fn list<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: imap::AttachmentListRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<imap::AttachmentMetadata>, Error>> + Send + 'a>>;
}
impl Service {
    pub fn with_attachment_backend(mut self, backend: Arc<dyn AttachmentBackend>) -> Self {
        self.attachment_backend = Some(backend);
        self
    }
    pub(super) async fn list_attachments(
        &self,
        context: &RequestContext,
        input: domain::ListAttachmentsInput,
    ) -> Result<domain::AttachmentList, Error> {
        let limits = &self.grant(context)?.limits;
        if !context.permissions().contains(&Permission::ReadAttachment) {
            return Err(super::denied());
        }
        let reference: MessageReference = self.decode(
            "ms1",
            &input.message,
            limits.token_bytes,
            ErrorCode::StaleReference,
        )?;
        let name = domain::mailbox_identity(&reference.mailbox);
        let target = self.authorize_message(context, &reference, ErrorCode::StaleReference)?;
        let _admission = self.requests.admit(target.account_id, limits).await?;
        let live;
        let backend = match &self.attachment_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target).await?;
                &live
            }
        };
        let entries = self.observed(
            target.account_id,
            backend
                .list(
                    target,
                    name,
                    imap::AttachmentListRequest::new(reference.uid, reference.uid_validity),
                    limits,
                )
                .await,
        )?;
        if entries.len() > limits.mime_parts {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let mut budget =
            crate::encoding::OutputBudget::new(context.response_limit().saturating_sub(512));
        budget.reserve(256)?;
        budget.count(&input.message)?;
        let attachments = entries
            .into_iter()
            .map(|entry| {
                budget.reserve(128 + limits.token_bytes)?;
                budget.count(&entry.filename)?;
                budget.count(&entry.media_type)?;
                Ok(domain::AttachmentMetadata {
                    reference: self.encode(
                        "at1",
                        &(&reference, &entry.part),
                        limits.token_bytes,
                    )?,
                    display_name: entry.filename,
                    media_type: entry.media_type,
                    declared_size: entry.declared_size,
                    available: entry.available,
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(domain::AttachmentList {
            account_id: reference.account,
            generation: reference.generation,
            message_reference: input.message,
            attachments,
        })
    }
}

fn expired() -> Error {
    Error::new(ErrorCode::TransferExpired)
}
impl Service {
    pub(super) async fn get_attachment(
        &self,
        context: &RequestContext,
        input: domain::GetAttachmentInput,
    ) -> Result<domain::AttachmentChunk, Error> {
        let started = Instant::now();
        let deadline =
            started + Duration::from_secs(self.limits(context)?.operation_seconds as u64);
        tokio::select! {
            biased;
            result = self.get_attachment_inner(context, input, started, deadline) => result,
            () = tokio::time::sleep_until(deadline) => Err(Error::new(ErrorCode::Timeout)),
        }
    }
    async fn get_attachment_inner(
        &self,
        context: &RequestContext,
        input: domain::GetAttachmentInput,
        started: Instant,
        operation_deadline: Instant,
    ) -> Result<domain::AttachmentChunk, Error> {
        let limits = &self.grant(context)?.limits;
        if !context.permissions().contains(&Permission::ReadAttachment) {
            return Err(super::denied());
        }
        let scope = super::tokens::fingerprint(&(
            self.registry.revision(),
            context.grant_name(),
            context.account_indices(),
            context.permissions(),
            limits,
            context.response_limit(),
        ))?;
        let (reservation, mut entry) = match input {
            domain::GetAttachmentInput::Start(input) => {
                let (resource, part): (MessageReference, String) = self.decode(
                    "at1",
                    &input.attachment,
                    limits.token_bytes,
                    ErrorCode::StaleReference,
                )?;
                let target =
                    self.authorize_message(context, &resource, ErrorCode::StaleReference)?;
                let reservation = self.transfers.reserve(
                    context.session_id(),
                    &resource.account,
                    limits,
                    started,
                )?;
                let live;
                let backend = match &self.attachment_backend {
                    Some(backend) => backend.as_ref(),
                    None => {
                        live = self.imap_backend(target).await?;
                        &live
                    }
                };
                let reader = backend.start(
                    target,
                    &resource.mailbox,
                    resource.uid,
                    resource.uid_validity,
                    &part,
                    limits,
                )?;
                (
                    reservation,
                    Entry {
                        resource,
                        reference: input.attachment,
                        scope,
                        offset: 0,
                        reader,
                    },
                )
            }
            domain::GetAttachmentInput::Continue(input) => {
                let (session, id, offset): (Uuid, Uuid, u64) = self.decode(
                    "tx1",
                    &input.token,
                    limits.token_bytes,
                    ErrorCode::TransferExpired,
                )?;
                if session != context.session_id() {
                    return Err(expired());
                }
                self.transfers
                    .checkout(context.session_id(), id, &scope, offset, |entry| {
                        self.authorize_mailbox(
                            context,
                            &entry.resource.account,
                            entry.resource.generation,
                            &entry.resource.mailbox,
                        )
                        .map(|_| ())
                    })?
            }
        };
        let expires = reservation.expires();
        let deadline = operation_deadline.min(expires);
        let page = tokio::select! {
            // Preserve expiry precedence when a nested reader timeout is also ready.
            biased;
            () = tokio::time::sleep_until(deadline) => {
                return Err(if expires <= operation_deadline {
                    expired()
                } else {
                    Error::new(ErrorCode::Timeout)
                });
            }
            page = async {
                let _admission = self.requests.admit(&entry.resource.account, limits).await?;
                self.observed(&entry.resource.account, entry.reader.next(limits).await)
            } => page?,
        };
        if Instant::now() >= expires {
            return Err(expired());
        }
        let next_offset = entry
            .offset
            .checked_add(page.bytes.len() as u64)
            .ok_or_else(|| Error::new(ErrorCode::AttachmentTooLarge))?;
        if page.bytes.len() > limits.attachment_chunk_bytes
            || next_offset > limits.attachment_decoded_bytes as u64
        {
            return Err(Error::new(ErrorCode::AttachmentTooLarge));
        }
        if page.decoded_offset != entry.offset
            || (page.integrity.is_none() && page.bytes.is_empty())
            || page
                .integrity
                .is_some_and(|value| value.total_decoded_bytes != next_offset)
        {
            return Err(Error::new(ErrorCode::InternalError));
        }
        let mut budget =
            crate::encoding::OutputBudget::new(context.response_limit().saturating_sub(512));
        budget.reserve(512 + limits.token_bytes + page.bytes.len().div_ceil(3) * 4)?;
        budget.count(&entry.reference)?;
        let progress = match page.integrity {
            Some(integrity) => domain::AttachmentProgress::Complete {
                total_decoded_bytes: integrity.total_decoded_bytes,
                sha256: crate::encoding::hex(&integrity.sha256),
            },
            None => domain::AttachmentProgress::Continue {
                next_token: self.encode(
                    "tx1",
                    &(context.session_id(), reservation.id(), next_offset),
                    limits.token_bytes,
                )?,
            },
        };
        let result = domain::AttachmentChunk {
            account_id: entry.resource.account.clone(),
            generation: entry.resource.generation,
            attachment_reference: entry.reference.clone(),
            bytes_base64: STANDARD.encode(&page.bytes),
            decoded_offset: entry.offset,
            progress,
        };
        crate::encoding::serialized_size(&result, context.response_limit().saturating_sub(512))?;
        if page.integrity.is_none() {
            entry.offset = next_offset;
            reservation.retain(entry)?;
        }
        Ok(result)
    }
}
