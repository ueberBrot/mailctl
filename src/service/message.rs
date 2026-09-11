//! Message references are reauthorized before acquiring an exclusive body lease.
use super::{MailboxTarget, Service, tokens::MessageReference};
use crate::{
    config::Limits,
    domain::{BodyText, Error, ErrorCode, GetMessageInput, MessageBody, mailbox_identity},
    imap::BodyRequest,
    policy::{Permission, RequestContext},
};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

pub trait BodyBackend: Send + Sync {
    fn read<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<BodyText, Error>> + Send + 'a>>;
}

/// Already represented fixture bodies, grouped by the current mailbox incarnation.
#[derive(Default)]
pub struct MemoryBodies(Mutex<BTreeMap<String, BTreeMap<String, MemoryMailbox>>>);
struct MemoryMailbox {
    validity: u32,
    bodies: BTreeMap<u32, BodyText>,
}
impl MemoryBodies {
    pub fn set(&self, account: &str, mailbox: &str, validity: u32, uid: u32, body: BodyText) {
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
        mailbox.bodies.insert(uid, body);
    }
}
impl BodyBackend for MemoryBodies {
    fn read<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        request: BodyRequest,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<BodyText, Error>> + Send + 'a>> {
        Box::pin(async move {
            let mailboxes = self.0.lock().unwrap();
            let mailbox = mailboxes
                .get(&target.config.key)
                .and_then(|mailboxes| mailboxes.get(mailbox_identity(mailbox)))
                .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
            if mailbox.validity != request.uid_validity {
                return Err(Error::new(ErrorCode::StaleReference));
            }
            let body = mailbox
                .bodies
                .get(&request.uid)
                .ok_or_else(|| Error::new(ErrorCode::MessageNotFound))?;
            let end = body.text.floor_char_boundary(limits.text_page_bytes);
            Ok(BodyText {
                text: body.text[..end].into(),
                truncated: body.truncated || end < body.text.len(),
                selected_part: body.selected_part.clone(),
                source_media_type: body.source_media_type.clone(),
                representation_version: body.representation_version.clone(),
                converted: body.converted,
                replacements: body.replacements,
                empty_reason: body.empty_reason,
                continuation_available: false,
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
        let limits = &self.grant(context)?.limits;
        tokio::time::timeout(
            Duration::from_secs(limits.operation_seconds as u64),
            self.read_message(context, input),
        )
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))?
    }
    async fn read_message(
        &self,
        context: &RequestContext,
        input: GetMessageInput,
    ) -> Result<MessageBody, Error> {
        let grant = self.grant(context)?;
        if !context.permissions().contains(&Permission::ReadMessage) {
            return Err(super::denied());
        }
        let limits = &grant.limits;
        let reference: MessageReference = self.decode(
            "ms1",
            &input.message,
            limits.token_bytes,
            ErrorCode::StaleReference,
        )?;
        let name = mailbox_identity(&reference.mailbox);
        let target @ MailboxTarget {
            config: account,
            account_id: id,
            generation,
        } = self.authorize_mailbox(context, &reference.account, reference.generation, name)?;
        if reference.uid == 0 || reference.uid_validity == 0 {
            return Err(Error::new(ErrorCode::StaleReference));
        }

        let live;
        let backend: &dyn BodyBackend = match &self.body_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(account).await?;
                &live
            }
        };
        let body = backend
            .read(
                target,
                name,
                BodyRequest::new(reference.uid, reference.uid_validity),
                limits,
            )
            .await?;
        Ok(MessageBody {
            account_id: id.into(),
            generation,
            message_reference: input.message,
            body,
        })
    }
}
