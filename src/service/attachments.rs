//! Attachment access checks precede metadata and transfer work.
use super::{MailboxTarget, Service, tokens::MessageReference};
use crate::{
    config::Limits,
    domain::{self, Error, ErrorCode},
    imap,
    policy::{Permission, RequestContext},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;
mod memory;
pub use memory::MemoryAttachments;

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
        let target =
            self.authorize_mailbox(context, &reference.account, reference.generation, name)?;
        if reference.uid == 0 || reference.uid_validity == 0 {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        let live;
        let backend = match &self.attachment_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target.config).await?;
                &live
            }
        };
        let entries = tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            backend.list(
                target,
                name,
                imap::AttachmentListRequest::new(reference.uid, reference.uid_validity),
                limits,
            ),
        )
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))??;
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
            account_id: reference.account.clone(),
            generation: reference.generation,
            message_reference: input.message,
            attachments,
        })
    }
}

#[derive(Default)]
pub(super) struct Transfers(Arc<Mutex<HashMap<Uuid, Slot>>>);
struct Slot {
    session: Uuid,
    account: String,
    expires: Instant,
    entry: Option<Entry>,
}
struct Entry {
    resource: MessageReference,
    reference: String,
    scope: String,
    offset: u64,
    reader: Box<dyn AttachmentReader>,
}
// A request owns its slot while awaiting provider work. Cancellation drops both
// decoder and reservation; an in-flight transfer still counts toward the quota.
struct Reservation {
    store: Arc<Mutex<HashMap<Uuid, Slot>>>,
    id: Uuid,
    retained: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.retained {
            self.store.lock().unwrap().remove(&self.id);
        }
    }
}
impl Reservation {
    fn retain(mut self, entry: Entry) -> Result<(), Error> {
        let mut store = self.store.lock().unwrap();
        let slot = store.get_mut(&self.id).ok_or_else(expired)?;
        slot.entry = Some(entry);
        self.retained = true;
        Ok(())
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
        let (reservation, mut entry, expires) = match input {
            domain::GetAttachmentInput::Start(input) => {
                let (resource, part): (MessageReference, String) = self.decode(
                    "at1",
                    &input.attachment,
                    limits.token_bytes,
                    ErrorCode::StaleReference,
                )?;
                let target = self.authorize_mailbox(
                    context,
                    &resource.account,
                    resource.generation,
                    &resource.mailbox,
                )?;
                if resource.uid == 0 || resource.uid_validity == 0 {
                    return Err(Error::new(ErrorCode::StaleReference));
                }
                let id = Uuid::new_v4();
                let expires = Instant::now() + Duration::from_secs(limits.transfer_seconds as u64);
                {
                    let mut store = self.transfers.0.lock().unwrap();
                    store.retain(|_, slot| slot.entry.is_none() || slot.expires > Instant::now());
                    if store
                        .values()
                        .filter(|slot| slot.account == resource.account)
                        .count()
                        >= limits.transfers_per_account
                    {
                        return Err(Error::new(ErrorCode::RateLimited));
                    }
                    store.insert(
                        id,
                        Slot {
                            session: context.session_id(),
                            account: resource.account.clone(),
                            expires,
                            entry: None,
                        },
                    );
                }
                let reservation = Reservation {
                    store: self.transfers.0.clone(),
                    id,
                    retained: false,
                };
                let live;
                let backend = match &self.attachment_backend {
                    Some(backend) => backend.as_ref(),
                    None => {
                        live = self.imap_backend(target.config).await?;
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
                    expires,
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
                let mut store = self.transfers.0.lock().unwrap();
                store.retain(|_, slot| slot.entry.is_none() || slot.expires > Instant::now());
                let slot = store.get_mut(&id).ok_or_else(expired)?;
                let entry = slot.entry.as_ref().ok_or_else(expired)?;
                if entry.scope != scope || entry.offset != offset {
                    return Err(expired());
                }
                self.authorize_mailbox(
                    context,
                    &entry.resource.account,
                    entry.resource.generation,
                    &entry.resource.mailbox,
                )?;
                let expires = slot.expires;
                let entry = slot.entry.take().ok_or_else(expired)?;
                (
                    Reservation {
                        store: self.transfers.0.clone(),
                        id,
                        retained: false,
                    },
                    entry,
                    expires,
                )
            }
        };
        let operation_deadline =
            Instant::now() + Duration::from_secs(limits.operation_seconds as u64);
        let deadline = operation_deadline.min(expires);
        let page = tokio::time::timeout_at(deadline, entry.reader.next(limits))
            .await
            .map_err(|_| {
                if expires <= operation_deadline {
                    expired()
                } else {
                    Error::new(ErrorCode::Timeout)
                }
            })??;
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
                sha256: integrity
                    .sha256
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            },
            None => domain::AttachmentProgress::Continue {
                next_token: self.encode(
                    "tx1",
                    &(context.session_id(), reservation.id, next_offset),
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

#[derive(Debug)]
pub(crate) struct TransferSession {
    pub id: Uuid,
    store: std::sync::Weak<Mutex<HashMap<Uuid, Slot>>>,
}
impl Drop for TransferSession {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            store
                .lock()
                .unwrap()
                .retain(|_, slot| slot.session != self.id);
        }
    }
}
impl Transfers {
    pub(super) fn session(&self) -> Arc<TransferSession> {
        Arc::new(TransferSession {
            id: Uuid::new_v4(),
            store: Arc::downgrade(&self.0),
        })
    }
}
