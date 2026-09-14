//! In-memory attachment adapter with live mailbox-incarnation checks.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Clone, Default)]
pub struct MemoryAttachments(Arc<Mutex<BTreeMap<(String, String), Mailbox>>>);
struct Mailbox {
    validity: u32,
    messages: BTreeMap<u32, Vec<(imap::AttachmentMetadata, Vec<u8>)>>,
}
impl MemoryAttachments {
    pub fn set(
        &self,
        account: &str,
        mailbox: &str,
        validity: u32,
        uid: u32,
        attachments: Vec<(imap::AttachmentMetadata, Vec<u8>)>,
    ) {
        let mut store = self.0.lock().unwrap();
        let mailbox = store
            .entry((account.into(), domain::mailbox_identity(mailbox).into()))
            .or_insert_with(|| Mailbox {
                validity,
                messages: BTreeMap::new(),
            });
        if mailbox.validity != validity {
            mailbox.validity = validity;
            mailbox.messages.clear();
        }
        mailbox.messages.insert(uid, attachments);
    }
    fn with<T>(
        &self,
        key: &(String, String),
        uid: u32,
        validity: u32,
        read: impl FnOnce(&[(imap::AttachmentMetadata, Vec<u8>)]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let store = self.0.lock().unwrap();
        let mailbox = store
            .get(key)
            .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
        if mailbox.validity != validity {
            return Err(Error::new(ErrorCode::StaleReference));
        }
        read(
            mailbox
                .messages
                .get(&uid)
                .ok_or_else(|| Error::new(ErrorCode::MessageNotFound))?,
        )
    }
}
impl AttachmentBackend for MemoryAttachments {
    fn list<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: imap::AttachmentListRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<imap::AttachmentMetadata>, Error>> + Send + 'a>>
    {
        Box::pin(async move {
            self.with(
                &(
                    target.config.key.clone(),
                    domain::mailbox_identity(mailbox).into(),
                ),
                request.uid,
                request.uid_validity,
                |entries| {
                    if entries.len() > limits.mime_parts {
                        return Err(Error::new(ErrorCode::ResponseTooLarge));
                    }
                    Ok(entries
                        .iter()
                        .map(|(metadata, _)| metadata.clone())
                        .collect())
                },
            )
        })
    }
    fn start(
        &self,
        target: MailboxTarget<'_>,
        mailbox: &str,
        uid: u32,
        validity: u32,
        part: &str,
        _: &Limits,
    ) -> Result<Box<dyn AttachmentReader>, Error> {
        Ok(Box::new(Reader {
            source: self.clone(),
            key: (
                target.config.key.clone(),
                domain::mailbox_identity(mailbox).into(),
            ),
            uid,
            validity,
            part: part.into(),
            offset: 0,
            digest: Sha256::new(),
        }))
    }
}
struct Reader {
    source: MemoryAttachments,
    key: (String, String),
    uid: u32,
    validity: u32,
    part: String,
    offset: usize,
    digest: Sha256,
}
impl AttachmentReader for Reader {
    fn next<'a>(
        &'a mut self,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<imap::AttachmentData, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.source
                .with(&self.key, self.uid, self.validity, |entries| {
                    let (metadata, bytes) = entries
                        .iter()
                        .find(|(metadata, _)| metadata.part == self.part)
                        .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
                    if !metadata.available {
                        return Err(Error::new(ErrorCode::UnsupportedCapability));
                    }
                    if bytes.len() > limits.attachment_decoded_bytes
                        || bytes.len() > limits.attachment_wire_bytes
                    {
                        return Err(Error::new(ErrorCode::AttachmentTooLarge));
                    }
                    if self.offset > bytes.len() {
                        return Err(Error::new(ErrorCode::StaleReference));
                    }
                    let end = bytes.len().min(self.offset + limits.attachment_chunk_bytes);
                    let page = bytes[self.offset..end].to_vec();
                    self.digest.update(&page);
                    let result = imap::AttachmentData {
                        bytes: page,
                        decoded_offset: self.offset as u64,
                        integrity: (end == bytes.len()).then(|| imap::AttachmentIntegrity {
                            total_decoded_bytes: end as u64,
                            sha256: self.digest.clone().finalize().into(),
                        }),
                    };
                    self.offset = end;
                    Ok(result)
                })
        })
    }
}
