//! Message references are reauthorized before acquiring an exclusive body lease.
use super::{MailboxTarget, Service, tokens::MessageReference};
use crate::{
    config::Limits,
    domain::{BodyText, Error, ErrorCode, GetMessageInput, MessageBody, mailbox_identity},
    imap::{BodyCursor, BodyRequest},
    policy::{Permission, RequestContext},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

/// A bounded backend page with an installation-independent continuation position.
pub struct BodyRead {
    pub body: BodyText,
    pub continuation: Option<BodyCursor>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TextCursor {
    resource: String,
    limits: String,
    position: BodyCursor,
}

pub trait BodyBackend: Send + Sync {
    fn read<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<BodyRead, Error>> + Send + 'a>>;
}

/// Already represented fixture bodies, grouped by the current mailbox incarnation.
#[derive(Default)]
pub struct MemoryBodies(Mutex<BTreeMap<String, BTreeMap<String, MemoryMailbox>>>);
struct MemoryMailbox {
    validity: u32,
    bodies: BTreeMap<u32, MemoryBody>,
}
struct MemoryBody {
    body: BodyText,
    fingerprint: [u8; 32],
}
impl MemoryBodies {
    pub fn set(&self, account: &str, mailbox: &str, validity: u32, uid: u32, body: BodyText) {
        let fingerprint = Sha256::digest(serde_json::to_vec(&body).unwrap()).into();
        let mut mailboxes = self.0.lock().unwrap();
        let mailbox = mailboxes
            .entry(account.into())
            .or_default()
            .entry(mailbox_identity(mailbox).into())
            .or_insert_with(|| MemoryMailbox {
                validity,
                bodies: BTreeMap::new(),
            });
        if mailbox.validity != validity {
            mailbox.validity = validity;
            mailbox.bodies.clear();
        }
        mailbox.bodies.insert(uid, MemoryBody { body, fingerprint });
    }
}
impl BodyBackend for MemoryBodies {
    fn read<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<BodyRead, Error>> + Send + 'a>> {
        Box::pin(async move {
            let mailboxes = self.0.lock().unwrap();
            let mailbox = mailboxes
                .get(&target.config.key)
                .and_then(|mailboxes| mailboxes.get(mailbox_identity(mailbox)))
                .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
            if mailbox.validity != request.uid_validity {
                return Err(Error::new(ErrorCode::StaleReference));
            }
            let MemoryBody { body, fingerprint } = mailbox
                .bodies
                .get(&request.uid)
                .ok_or_else(|| Error::new(ErrorCode::MessageNotFound))?;
            let (range, continuation) = BodyCursor::page(
                request.continuation,
                &body.text,
                *fingerprint,
                limits.text_page_bytes,
            )
            .map_err(|_| Error::new(ErrorCode::StaleCursor))?;
            Ok(BodyRead {
                continuation,
                body: BodyText {
                    truncated: body.truncated || range.end < body.text.len(),
                    text: body.text[range].into(),
                    selected_part: body.selected_part.clone(),
                    source_media_type: body.source_media_type.clone(),
                    representation_version: body.representation_version.clone(),
                    converted: body.converted,
                    replacements: body.replacements,
                    empty_reason: body.empty_reason,
                    continuation_available: false,
                    next_cursor: None,
                },
            })
        })
    }
}

impl Service {
    pub fn with_body_backend(mut self, backend: Arc<dyn BodyBackend>) -> Self {
        self.body_backend = Some(backend);
        self
    }
    pub(super) async fn get_message(
        &self,
        context: &RequestContext,
        input: GetMessageInput,
    ) -> Result<MessageBody, Error> {
        let grant = self.grant(context)?;
        if !context.permissions().contains(&Permission::ReadMessage) {
            return Err(super::denied());
        }
        let limits = &grant.limits;
        let stale = if input.cursor.is_some() {
            ErrorCode::StaleCursor
        } else {
            ErrorCode::StaleReference
        };
        let reference: MessageReference =
            self.decode("ms1", &input.message, limits.token_bytes, stale)?;
        let name = mailbox_identity(&reference.mailbox);
        let target @ MailboxTarget {
            account_id: id,
            generation,
            ..
        } = self.authorize_message(context, &reference, stale)?;

        let resource = super::tokens::fingerprint(&reference)?;
        let limit_fingerprint = super::tokens::fingerprint(limits)?;
        let position = input
            .cursor
            .as_ref()
            .map(|token| {
                let cursor: TextCursor =
                    self.decode("bt1", token, limits.token_bytes, ErrorCode::StaleCursor)?;
                if cursor.resource != resource || cursor.limits != limit_fingerprint {
                    return Err(Error::new(ErrorCode::StaleCursor));
                }
                Ok(cursor.position)
            })
            .transpose()?;
        let live;
        let backend: &dyn BodyBackend = match &self.body_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target).await?;
                &live
            }
        };
        let page = backend
            .read(
                target,
                name,
                BodyRequest {
                    uid: reference.uid,
                    uid_validity: reference.uid_validity,
                    continuation: position,
                },
                limits,
            )
            .await
            .map_err(|error| {
                if input.cursor.is_some()
                    && matches!(
                        error.code,
                        ErrorCode::StaleReference | ErrorCode::MessageNotFound
                    )
                {
                    Error::new(ErrorCode::StaleCursor)
                } else {
                    error
                }
            })?;
        let mut body = page.body;
        body.next_cursor = page
            .continuation
            .map(|position| {
                self.encode(
                    "bt1",
                    &TextCursor {
                        resource,
                        limits: limit_fingerprint,
                        position,
                    },
                    limits.token_bytes,
                )
            })
            .transpose()?;
        body.continuation_available = body.next_cursor.is_some();
        Ok(MessageBody {
            account_id: id.into(),
            generation,
            message_reference: input.message,
            body,
        })
    }
}
