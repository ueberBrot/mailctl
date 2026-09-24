//! Authorized draft creation and journal-only inspection.
use super::{MailboxTarget, Service};
use crate::{
    config::Limits,
    domain::{
        DraftContent, DraftIdentity, DraftOperationDetails, DraftReceipt, DraftState,
        DraftStatusInput, Error, ErrorCode, SaveDraftInput,
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

pub type DraftPreparation<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn DraftAppend + 'a>, Error>> + Send + 'a>>;

/// Authenticates and verifies the exact existing target before dispatch eligibility.
pub trait DraftBackend: Send + Sync {
    fn prepare<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        limits: &'a Limits,
    ) -> DraftPreparation<'a>;
}
/// Owns the verified target and its connection capacity until APPEND or cancellation.
pub trait DraftAppend: Send {
    fn uid_validity(&self) -> u32;
    fn append<'a>(
        self: Box<Self>,
        draft: &'a crate::draft::PreparedDraft,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a;
}
#[derive(Default)]
pub struct MemoryDrafts(RwLock<BTreeMap<(String, String), u32>>);
impl MemoryDrafts {
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
struct MemoryAppend(u32);
impl DraftAppend for MemoryAppend {
    fn uid_validity(&self) -> u32 {
        self.0
    }
    fn append<'a>(
        self: Box<Self>,
        _: &'a crate::draft::PreparedDraft,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async { Ok(crate::imap::AppendOutcome::Created { uid: None }) })
    }
}
impl DraftBackend for MemoryDrafts {
    fn prepare<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        _: &'a Limits,
    ) -> DraftPreparation<'a> {
        Box::pin(async move {
            let validity = self
                .0
                .read()
                .unwrap()
                .get(&(
                    target.config.key.clone(),
                    crate::domain::mailbox_identity(mailbox).into(),
                ))
                .copied()
                .filter(|v| *v != 0)
                .ok_or_else(|| Error::new(ErrorCode::DraftMailboxUnavailable))?;
            Ok(Box::new(MemoryAppend(validity)) as Box<dyn DraftAppend>)
        })
    }
}
impl Service {
    pub fn with_draft_backend(mut self, backend: Arc<dyn DraftBackend>) -> Self {
        self.draft_backend = Some(backend);
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
        let mut dispatched = None;
        let duration =
            std::time::Duration::from_secs(self.limits(context)?.operation_seconds as u64);
        tokio::time::timeout(
            duration,
            self.save_draft_inner(context, input, &mut dispatched),
        )
        .await
        .unwrap_or_else(|_| {
            Err(if let Some(operation) = dispatched {
                Error::draft_outcome(ErrorCode::OutcomeUnknown, operation)
            } else {
                Error::new(ErrorCode::Timeout)
            })
        })
    }
    async fn save_draft_inner(
        &self,
        context: &RequestContext,
        input: SaveDraftInput,
        dispatched: &mut Option<DraftOperationDetails>,
    ) -> Result<DraftReceipt, Error> {
        let identity = input.identity();
        let target =
            self.authorize_draft(context, &identity, &input.mailbox, Permission::AppendDraft)?;
        let limits = self.limits(context)?;
        let _admission = self.requests.admit(target.account_id, limits).await?;
        // Ownership spans recovery, target verification, APPEND and durable completion.
        let _writer = match self
            .registry
            .draft_writer(identity.account_id, limits.initialization_seconds)
            .await
        {
            Ok(writer) => writer,
            Err(error) if error.code == ErrorCode::RateLimited => {
                let journal = self.registry.draft_journal()?;
                if let Some(prior) = authorized_operation(&journal, &identity, &input.mailbox)?
                    && prior.state == DraftOperationState::InFlight
                {
                    return Err(Error::draft_outcome(
                        ErrorCode::OperationInProgress,
                        operation_details(&prior.operation),
                    ));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let mut journal = self.registry.draft_journal()?;
        let mut prior = authorized_operation(&journal, &identity, &input.mailbox)?;
        if let Some(pending) = &prior
            && pending.state == DraftOperationState::InFlight
        {
            let operation = operation_details(&pending.operation);
            prior = Some(
                journal
                    .record_outcome_unknown(&identity)
                    .map_err(|_| Error::draft_outcome(ErrorCode::OutcomeUnknown, operation))?,
            );
        }
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
        )?;
        if mime.header_bytes() > limits.header_bytes {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let resuming = if let Some(prior) = prior {
            if prior.operation.content_sha256 != mime.sha256() {
                return Err(Error::draft_conflict());
            }
            if prior.state != DraftOperationState::Prepared {
                return self.draft_receipt(prior, limits);
            }
            true
        } else {
            false
        };
        let live;
        let backend: &dyn DraftBackend = match &self.draft_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target).await?;
                &live
            }
        };
        let append = self.observed(
            target.account_id,
            backend.prepare(target, mailbox, limits).await,
        )?;
        let validity = append.uid_validity();
        if validity == 0 || (resuming && validity != frozen.uid_validity) {
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
        let prepared = journal
            .prepare_with_limit(operation, self.config.limits.journal_records)
            .map_err(journal_error)?;
        let dispatch = Dispatch::start(&mut journal, &prepared.operation)?;
        *dispatched = Some(operation_details(&prepared.operation));
        let outcome = append.append(&mime, limits).await;
        let recorded = dispatch.complete(outcome)?;
        self.draft_receipt(recorded, limits)
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
        self.draft_receipt(
            prior.ok_or_else(|| Error::new(ErrorCode::OperationNotFound))?,
            self.limits(context)?,
        )
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
impl Service {
    fn draft_receipt(
        &self,
        persisted: PersistedDraftOperation,
        limits: &Limits,
    ) -> Result<DraftReceipt, Error> {
        let operation = persisted.operation;
        let message_reference = match persisted.state {
            DraftOperationState::Created {
                appended_message: Some(uid),
            } => self
                .encode(
                    "ms1",
                    &super::tokens::MessageReference {
                        account: &operation.identity.account_id.to_string(),
                        generation: operation.identity.account_generation,
                        mailbox: &operation.mailbox_identity,
                        uid_validity: uid.uid_validity,
                        uid: uid.uid,
                    },
                    limits.token_bytes,
                )
                .ok(),
            _ => None,
        };
        let reconstruction = operation
            .reconstruction
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::JournalUnavailable))?;
        let state = match persisted.state {
            DraftOperationState::Prepared => DraftState::Prepared,
            DraftOperationState::InFlight => {
                return Err(Error::draft_outcome(
                    ErrorCode::OperationInProgress,
                    operation_details(&operation),
                ));
            }
            DraftOperationState::Created { .. } if message_reference.is_some() => {
                DraftState::Created
            }
            DraftOperationState::Created { .. } => DraftState::CreatedReferenceUnavailable,
            DraftOperationState::Rejected => DraftState::Rejected,
            DraftOperationState::OutcomeUnknown => {
                return Err(Error::draft_outcome(
                    ErrorCode::OutcomeUnknown,
                    operation_details(&operation),
                ));
            }
        };
        Ok(DraftReceipt {
            account_id: operation.identity.account_id,
            account_generation: operation.identity.account_generation,
            operation_id: operation.identity.operation_id,
            mailbox: operation.mailbox_identity,
            uid_validity: reconstruction.uid_validity,
            state,
            message_reference,
            dispatched: state != DraftState::Prepared,
            content_sha256: crate::encoding::hex(&operation.content_sha256),
        })
    }
}
struct Dispatch<'a> {
    journal: &'a mut crate::draft_journal::DraftJournal,
    operation: &'a PreparedDraftOperation,
    finished: bool,
}
impl<'a> Dispatch<'a> {
    fn start(
        journal: &'a mut crate::draft_journal::DraftJournal,
        operation: &'a PreparedDraftOperation,
    ) -> Result<Self, Error> {
        journal.begin_dispatch(operation).map_err(journal_error)?;
        Ok(Self {
            journal,
            operation,
            finished: false,
        })
    }
    fn complete(
        mut self,
        outcome: Result<crate::imap::AppendOutcome, Error>,
    ) -> Result<PersistedDraftOperation, Error> {
        let identity = &self.operation.identity;
        let recorded = match outcome {
            Ok(crate::imap::AppendOutcome::Created { uid }) => self.journal.record_created(
                identity,
                uid.map(|uid| crate::draft_journal::AppendedMessageIdentity {
                    uid_validity: uid.uid_validity,
                    uid: uid.uid,
                }),
            ),
            Ok(crate::imap::AppendOutcome::Rejected) => self.journal.record_rejected(identity),
            _ => self.journal.record_outcome_unknown(identity),
        }
        .map_err(|_| {
            Error::draft_outcome(ErrorCode::OutcomeUnknown, operation_details(self.operation))
        })?;
        self.finished = true;
        Ok(recorded)
    }
}
impl Drop for Dispatch<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Cancellation is uncertainty. If storage fails, recovery retains in_flight.
            let _ = self
                .journal
                .record_outcome_unknown(&self.operation.identity);
        }
    }
}
fn journal_error(error: DraftJournalError) -> Error {
    match error {
        DraftJournalError::OperationConflict => Error::draft_conflict(),
        DraftJournalError::Full => Error::new(ErrorCode::JournalFull),
        _ => Error::new(ErrorCode::JournalUnavailable),
    }
}

fn operation_details(operation: &PreparedDraftOperation) -> DraftOperationDetails {
    DraftOperationDetails {
        identity: operation.identity.clone(),
        mailbox: operation.mailbox_identity.clone(),
        uid_validity: operation.reconstruction.as_ref().map(|r| r.uid_validity),
    }
}
