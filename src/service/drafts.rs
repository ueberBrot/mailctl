//! Authorized draft preparation and journal-only inspection.
use super::{MailboxTarget, Service};
use crate::{
    config::Limits,
    domain::{
        DraftContent, DraftIdentity, DraftReceipt, DraftState, DraftStatusInput, Error, ErrorCode,
        SaveDraftInput,
    },
    draft_journal::{
        DraftJournalError, DraftOperationState, DraftReconstruction, PersistedDraftOperation,
        PreparedDraftOperation,
    },
    policy::{Permission, RequestContext},
};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
};

/// Verifies that the exact existing target is selectable, without fetching messages.
pub trait DraftTargets: Send + Sync {
    fn inspect<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<u32, Error>> + Send + 'a>>;
}
#[derive(Default)]
pub struct MemoryDraftTargets(RwLock<BTreeMap<(String, String), u32>>);
impl MemoryDraftTargets {
    pub fn set(&self, account: &str, mailbox: &str, uid_validity: u32) {
        self.0.write().unwrap().insert(
            (
                account.into(),
                crate::domain::mailbox_identity(mailbox).into(),
            ),
            uid_validity,
        );
    }
}
impl DraftTargets for MemoryDraftTargets {
    fn inspect<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<u32, Error>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .read()
                .unwrap()
                .get(&(
                    target.config.key.clone(),
                    crate::domain::mailbox_identity(mailbox).into(),
                ))
                .copied()
                .filter(|v| *v != 0)
                .ok_or_else(|| Error::new(ErrorCode::DraftMailboxUnavailable))
        })
    }
}
impl Service {
    pub fn with_draft_targets(mut self, backend: Arc<dyn DraftTargets>) -> Self {
        self.draft_targets = Some(backend);
        self
    }
    fn authorize_draft<'a>(
        &'a self,
        context: &'a RequestContext,
        identity: &DraftIdentity,
        mailbox: &str,
        permission: Permission,
    ) -> Result<MailboxTarget<'a>, Error> {
        let grant = self.grant(context)?;
        if !context.permissions().contains(&permission) {
            return Err(super::denied());
        }
        let requested_account = identity.account_id.to_string();
        let (config, account_id, generation) = self
            .visible_accounts(context)
            .find_map(|account| {
                let (id, generation) = self.registry.identity(&account.key);
                (id == requested_account).then_some((account, id, generation))
            })
            .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?;
        if generation != identity.account_generation {
            return Err(super::denied());
        }
        if identity.operation_id.is_nil() {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        if mailbox.is_empty() || mailbox.len() > 1024 {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let target = Self::authorize_mailbox_scope(
            grant,
            MailboxTarget {
                config,
                account_id,
                generation,
            },
            mailbox,
        )?;
        if target
            .config
            .drafts_mailbox
            .as_deref()
            .map(crate::domain::mailbox_identity)
            != Some(crate::domain::mailbox_identity(mailbox))
        {
            return Err(super::denied());
        }
        Ok(target)
    }
    pub(super) async fn save_draft(
        &self,
        context: &RequestContext,
        input: SaveDraftInput,
    ) -> Result<DraftReceipt, Error> {
        let identity = input.identity();
        let target =
            self.authorize_draft(context, &identity, &input.mailbox, Permission::AppendDraft)?;
        let limits = self.limits(context)?;
        let _admission = self.requests.admit(target.account_id, limits).await?;
        // Ownership covers inspection, target verification and the durable prepare.
        let _writer = self
            .registry
            .draft_writer(identity.account_id, limits.initialization_seconds)
            .await?;
        let mut journal = self.registry.draft_journal()?;
        let prior = authorized_operation(&journal, &identity, &input.mailbox)?;
        let mailbox = crate::domain::mailbox_identity(&input.mailbox);
        let mut content = *input.draft;
        let from = match content.from.take() {
            Some(from) if target.config.from_identities.contains(&from) => from,
            None if target.config.from_identities.len() == 1 => {
                target.config.from_identities[0].clone()
            }
            _ => return Err(Error::new(ErrorCode::InvalidRequest)),
        };
        content.from = Some(from.clone());
        // Bound direct application callers before normalization or hashing.
        validate_size(&content, limits)?;
        content.body = crate::draft::normalize_body(content.body);
        let input_sha256 = hash(&content)?;
        let from_configuration_sha256 = hash(&target.config.from_identities)?;
        let frozen = match &prior {
            Some(prior) => {
                let frozen = prior
                    .operation
                    .reconstruction
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::JournalUnavailable))?;
                if frozen.input_sha256 != input_sha256 {
                    return Err(Error::draft_conflict());
                }
                frozen.clone()
            }
            None => DraftReconstruction {
                uid_validity: 0,
                input_sha256,
                from_configuration_sha256,
                date_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?
                    .as_secs() as i64,
                encoder_version: 1,
            },
        };
        if frozen.encoder_version != 1
            || frozen.from_configuration_sha256 != from_configuration_sha256
        {
            return Err(Error::new(ErrorCode::UnsupportedCapability));
        }
        let mime = crate::draft::PreparedDraft::compose(
            crate::draft::DraftInput {
                from,
                to: content.to,
                cc: content.cc,
                bcc: content.bcc,
                subject: content.subject,
                body: content.body,
                in_reply_to: content.in_reply_to,
                references: content.references,
                message_id: format!(
                    "{}.{}.{}@mailctl.invalid",
                    identity.account_id, identity.account_generation, identity.operation_id
                ),
                date_unix: frozen.date_unix,
            },
            limits.draft_mime_bytes,
        )
        .map_err(Error::from)?;
        if mime.header_bytes() > limits.header_bytes {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        if let Some(prior) = prior {
            if prior.operation.content_sha256 != mime.sha256() {
                return Err(Error::draft_conflict());
            }
            return receipt(prior);
        }
        let live;
        let backend: &dyn DraftTargets = match &self.draft_targets {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target).await?;
                &live
            }
        };
        let validity = self.observed(
            target.account_id,
            backend.inspect(target, mailbox, limits).await,
        )?;
        if validity == 0 {
            return Err(Error::new(ErrorCode::DraftMailboxUnavailable));
        }
        let operation = PreparedDraftOperation {
            identity,
            mailbox_identity: mailbox.into(),
            content_sha256: mime.sha256(),
            reconstruction: Some(DraftReconstruction {
                uid_validity: validity,
                ..frozen
            }),
        };
        receipt(
            journal
                .prepare_with_limit(operation, self.config.limits.journal_records)
                .map_err(journal_error)?,
        )
    }
    pub(super) async fn draft_status(
        &self,
        context: &RequestContext,
        input: DraftStatusInput,
    ) -> Result<DraftReceipt, Error> {
        let identity = input.identity();
        let target = self.authorize_draft(
            context,
            &identity,
            &input.mailbox,
            Permission::InspectDraftOperation,
        )?;
        let _admission = self
            .requests
            .admit(target.account_id, self.limits(context)?)
            .await?;
        let journal = self.registry.draft_journal()?;
        let prior = authorized_operation(&journal, &identity, &input.mailbox)?;
        if input.reconcile {
            return Err(Error::new(ErrorCode::UnsupportedCapability));
        }
        receipt(prior.ok_or_else(|| Error::new(ErrorCode::OperationNotFound))?)
    }
}
// The caller authorizes the requested mailbox before opening the journal. A row
// outside that scope is absent from the authorized lookup; never compare its input.
fn authorized_operation(
    journal: &crate::draft_journal::DraftJournal,
    identity: &DraftIdentity,
    mailbox: &str,
) -> Result<Option<PersistedDraftOperation>, Error> {
    let prior = journal.inspect(identity).map_err(journal_error)?;
    if prior
        .as_ref()
        .is_some_and(|p| p.operation.mailbox_identity != crate::domain::mailbox_identity(mailbox))
    {
        return Err(Error::new(ErrorCode::OperationNotFound));
    }
    Ok(prior)
}
fn validate_size(content: &DraftContent, limits: &Limits) -> Result<(), Error> {
    if content
        .to
        .len()
        .saturating_add(content.cc.len())
        .saturating_add(content.bcc.len())
        > 100
        || content.subject.len() > 8192
        || content.body.len() > limits.draft_mime_bytes
        || content.references.len() > 50
        || content.from.as_ref().is_some_and(|s| s.len() > 254)
        || content
            .to
            .iter()
            .chain(&content.cc)
            .chain(&content.bcc)
            .any(|a| a.address.len() > 254 || a.name.as_ref().is_some_and(|s| s.len() > 1024))
        || content
            .in_reply_to
            .iter()
            .chain(&content.references)
            .any(|s| s.len() > 998)
    {
        return Err(Error::new(ErrorCode::ResponseTooLarge));
    }
    Ok(())
}
fn hash(value: &impl serde::Serialize) -> Result<[u8; 32], Error> {
    crate::encoding::json_sha256(value, usize::MAX)
        .map_err(|_| Error::new(ErrorCode::InvalidRequest))
}
fn receipt(persisted: PersistedDraftOperation) -> Result<DraftReceipt, Error> {
    let operation = persisted.operation;
    let reconstruction = operation
        .reconstruction
        .ok_or_else(|| Error::new(ErrorCode::JournalUnavailable))?;
    let state = match persisted.state {
        DraftOperationState::Prepared => DraftState::Prepared,
        DraftOperationState::InFlight => DraftState::InFlight,
        DraftOperationState::Created { .. } => DraftState::Created,
        DraftOperationState::Rejected => DraftState::Rejected,
        DraftOperationState::OutcomeUnknown => DraftState::OutcomeUnknown,
    };
    Ok(DraftReceipt {
        account_id: operation.identity.account_id,
        account_generation: operation.identity.account_generation,
        operation_id: operation.identity.operation_id,
        mailbox: operation.mailbox_identity,
        uid_validity: reconstruction.uid_validity,
        state,
        dispatched: state != DraftState::Prepared,
        content_sha256: crate::encoding::hex(&operation.content_sha256),
    })
}
fn journal_error(error: DraftJournalError) -> Error {
    match error {
        DraftJournalError::OperationConflict => Error::draft_conflict(),
        DraftJournalError::Full => Error::new(ErrorCode::JournalFull),
        _ => Error::new(ErrorCode::JournalUnavailable),
    }
}
