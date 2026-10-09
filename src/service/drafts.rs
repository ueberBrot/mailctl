//! Authorized draft creation, durable status, and read-only reconciliation.
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
use uuid::Uuid;

pub type DraftPreparation<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn DraftAppend + 'a>, Error>> + Send + 'a>>;

/// Prepares draft dispatch or independently verifies uncertain creation at its original target.
pub trait DraftBackend: Send + Sync {
    fn prepare<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        limits: &'a Limits,
    ) -> DraftPreparation<'a>;
    fn reconcile<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        expected: &'a crate::draft::DraftVerification,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::draft::DraftEvidence, Error>> + Send + 'a>>;
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
pub struct MemoryDrafts(RwLock<BTreeMap<String, BTreeMap<String, MemoryMailbox>>>);
struct MemoryMailbox {
    validity: u32,
    messages: Vec<MemoryMessage>,
}
struct MemoryMessage {
    message_id: String,
    content_sha256: [u8; 32],
    mime_bytes: usize,
    header_bytes: usize,
}
impl MemoryDrafts {
    pub fn set(&self, account: &str, mailbox: &str, uid_validity: u32) {
        self.0
            .write()
            .unwrap()
            .entry(account.into())
            .or_default()
            .insert(
                crate::domain::mailbox_identity(mailbox).into(),
                MemoryMailbox {
                    validity: uid_validity,
                    messages: Vec::new(),
                },
            );
    }
}
struct MemoryAppend<'a> {
    backend: &'a MemoryDrafts,
    account: &'a str,
    mailbox: &'a str,
    validity: u32,
}
impl DraftAppend for MemoryAppend<'_> {
    fn uid_validity(&self) -> u32 {
        self.validity
    }
    fn append<'a>(
        self: Box<Self>,
        draft: &'a crate::draft::PreparedDraft,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::imap::AppendOutcome, Error>> + Send + 'a>>
    where
        Self: 'a,
    {
        Box::pin(async move {
            let message = mail_parser::MessageParser::default()
                .parse_headers(draft.bytes())
                .ok_or_else(|| Error::new(ErrorCode::InvalidRequest))?;
            let id = message
                .message_id()
                .ok_or_else(|| Error::new(ErrorCode::InvalidRequest))?;
            self.backend
                .0
                .write()
                .unwrap()
                .get_mut(self.account)
                .and_then(|mailboxes| mailboxes.get_mut(self.mailbox))
                .ok_or_else(|| Error::new(ErrorCode::DraftMailboxUnavailable))?
                .messages
                .push(MemoryMessage {
                    message_id: id.into(),
                    content_sha256: draft.sha256(),
                    mime_bytes: draft.bytes().len(),
                    header_bytes: draft.header_bytes(),
                });
            Ok(crate::imap::AppendOutcome::Created { uid: None })
        })
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
            let account = target.config.key.as_str();
            let mailbox = crate::domain::mailbox_identity(mailbox);
            let validity = self
                .0
                .read()
                .unwrap()
                .get(account)
                .and_then(|mailboxes| mailboxes.get(mailbox))
                .map(|m| m.validity)
                .filter(|v| *v != 0)
                .ok_or_else(|| Error::new(ErrorCode::DraftMailboxUnavailable))?;
            Ok(Box::new(MemoryAppend {
                backend: self,
                account,
                mailbox,
                validity,
            }) as Box<dyn DraftAppend>)
        })
    }
    fn reconcile<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        mailbox: &'a str,
        expected: &'a crate::draft::DraftVerification,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<crate::draft::DraftEvidence, Error>> + Send + 'a>> {
        Box::pin(async move {
            use crate::draft::DraftEvidence;
            let state = self.0.read().unwrap();
            let mailbox = state
                .get(&target.config.key)
                .and_then(|mailboxes| mailboxes.get(crate::domain::mailbox_identity(mailbox)))
                .ok_or_else(|| Error::new(ErrorCode::DraftMailboxUnavailable))?;
            if mailbox.validity != expected.uid_validity {
                return Err(Error::new(ErrorCode::StaleReference));
            }
            if mailbox.messages.len() > limits.search_windows * limits.search_uid_window {
                return Err(Error::new(ErrorCode::ResponseTooLarge));
            }
            let mut matches = mailbox
                .messages
                .iter()
                .enumerate()
                .filter(|(_, message)| message.message_id.contains(&expected.message_id));
            let Some((index, message)) = matches.next() else {
                return Ok(DraftEvidence::Absent);
            };
            if matches.next().is_some() {
                return Ok(DraftEvidence::Ambiguous);
            }
            if message.mime_bytes > limits.draft_mime_bytes
                || message.mime_bytes > limits.wire_fetch_bytes
                || message.header_bytes > limits.header_bytes
            {
                return Err(Error::new(ErrorCode::ResponseTooLarge));
            }
            if message.message_id != expected.message_id
                || message.content_sha256 != expected.content_sha256
            {
                return Ok(DraftEvidence::ContentMismatch);
            }
            Ok(DraftEvidence::Verified(
                crate::draft::DraftMessageIdentity {
                    uid_validity: mailbox.validity,
                    uid: index as u32 + 1,
                },
            ))
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
        let mut account_buffer = Uuid::encode_buffer();
        let requested_account: &str = identity
            .account_id
            .hyphenated()
            .encode_lower(&mut account_buffer);
        let target = self.visible_account_target(context, requested_account)?;
        if identity.operation_id.is_nil() {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        if mailbox.is_empty() || mailbox.len() > 1024 {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        if target.generation != identity.account_generation {
            if !grant.historical_drafts.iter().any(|scope| {
                scope.account_id == identity.account_id
                    && scope.account_generation == identity.account_generation
                    && crate::domain::mailbox_identity(&scope.mailbox)
                        == crate::domain::mailbox_identity(mailbox)
            }) {
                return Err(super::denied());
            }
            return Ok(MailboxTarget {
                generation: identity.account_generation,
                ..target
            });
        }
        let target = Self::authorize_mailbox_scope(grant, target, mailbox)?;
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
        let verification_deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(limits.operation_seconds as u64);
        let _admission = self.requests.admit(target.account_id, limits).await?;
        // Ownership spans recovery, target verification, APPEND and durable completion.
        let _writer = match self
            .registry
            .draft_writer(identity.account_id, limits.initialization_seconds)
            .await
        {
            Ok(writer) => writer,
            Err(error) if error.code == ErrorCode::RateLimited => {
                let mut journal = self
                    .registry
                    .wait_for_draft_journal(limits.initialization_seconds)
                    .await?;
                if let Some(prior) = authorized_operation(&mut journal, &identity, &input.mailbox)?
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
        let mut journal = self
            .registry
            .wait_for_draft_journal(limits.initialization_seconds)
            .await?;
        let mut prior = authorized_operation(&mut journal, &identity, &input.mailbox)?;
        if let Some(pending) = &prior
            && pending.state == DraftOperationState::InFlight
        {
            let operation = operation_details(&pending.operation);
            prior = Some(
                journal
                    .access(|journal| journal.record_outcome_unknown(&identity))
                    .map_err(|_| Error::draft_outcome(ErrorCode::OutcomeUnknown, operation))?,
            );
        }
        if prior.is_none()
            && self.registry.identity(&target.config.key).1 != identity.account_generation
        {
            return Err(self.registry.absent_draft());
        }
        if prior.is_none() {
            self.registry.draft_creation_allowed()?;
            journal
                .access(|journal| journal.check_capacity(self.config.limits.journal_records))
                .map_err(journal_error)?;
        }
        let mailbox = crate::domain::mailbox_identity(&input.mailbox);
        let mut content = *input.draft;
        // Hash caller input before resolving a default From identity. Replays must
        // remain inspectable when the operator changes or removes that default.
        validate_size(&content, limits)?;
        content.body = crate::draft::normalize_body(content.body);
        let input_sha256 = hash(&content)?;
        let prior = match prior {
            Some(prior) => {
                let frozen = prior
                    .operation
                    .reconstruction
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::JournalUnavailable))?;
                if frozen.input_sha256 != input_sha256 {
                    return Err(Error::draft_conflict());
                }
                if prior.state != DraftOperationState::Prepared {
                    return self.draft_receipt(prior, limits);
                }
                if !frozen.encoder_is_valid() {
                    return Err(Error::new(ErrorCode::UnsupportedCapability));
                }
                if frozen
                    .fingerprint(&prior.operation.identity, &prior.operation.mailbox_identity)
                    .map_err(journal_error)?
                    != frozen.facts_sha256
                {
                    return Err(Error::draft_conflict());
                }
                Some(prior.operation)
            }
            None => None,
        };
        self.registry.draft_creation_allowed()?;
        // Revisit retained rows before dispatch even if a previous storage failure
        // prevented recording a corruption fence. Status and reads skip this scan.
        let (verified, result, _writer) = tokio::task::spawn_blocking(move || {
            let result = journal.access(|journal| {
                journal.verify_for_dispatch(verification_deadline, Limits::MAXIMUM.journal_records)
            });
            (journal, result, _writer)
        })
        .await
        .map_err(|_| Error::new(ErrorCode::JournalUnavailable))?;
        journal = verified;
        result.map_err(journal_error)?;
        self.registry.draft_creation_allowed()?;
        let frozen = prior
            .as_ref()
            .and_then(|operation| operation.reconstruction.as_ref());
        let from = match (frozen, content.from) {
            (Some(frozen), _) => target
                .config
                .from_identities
                .iter()
                .find(|from| hash(from).ok() == frozen.selected_from_sha256)
                .cloned()
                .ok_or_else(super::denied)?,
            (None, Some(from)) if target.config.from_identities.contains(&from) => from,
            (None, None) if target.config.from_identities.len() == 1 => {
                target.config.from_identities[0].clone()
            }
            _ => return Err(Error::new(ErrorCode::InvalidRequest)),
        };
        let frozen = match frozen {
            Some(frozen) => frozen.clone(),
            None => DraftReconstruction {
                uid_validity: 0,
                input_sha256,
                from_configuration_sha256: hash(&target.config.from_identities)?,
                selected_from_sha256: Some(hash(&from)?),
                date_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Error::new(ErrorCode::InternalError))?
                    .as_secs() as i64,
                encoder: crate::draft::ENCODER.into(),
                facts_sha256: [0; 32],
            },
        };
        let reencoding = frozen.encoder != crate::draft::ENCODER;
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
                message_id: identity.message_id(),
                date_unix: frozen.date_unix,
            },
            limits.draft_mime_bytes,
        )?;
        if mime.header_bytes() > limits.header_bytes {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        if !reencoding
            && prior
                .as_ref()
                .is_some_and(|operation| operation.content_sha256 != mime.sha256())
        {
            return Err(Error::draft_conflict());
        }
        let route = self
            .registry
            .draft_route(target.config, target.generation, mailbox)?;
        let target = MailboxTarget {
            config: &route,
            ..target
        };
        let live;
        let backend: &dyn DraftBackend = match &self.draft_backend {
            Some(backend) => backend.as_ref(),
            None => {
                live = self.imap_backend(target).await?;
                &live
            }
        };
        let append = backend.prepare(target, mailbox, limits).await;
        // Discovery and health describe the current account generation only.
        let append = if self.registry.identity(&target.config.key).1 == target.generation {
            self.observed(target.account_id, append)
        } else {
            append
        }?;
        let validity = append.uid_validity();
        if validity == 0 || (prior.is_some() && validity != frozen.uid_validity) {
            return Err(Error::new(ErrorCode::DraftMailboxUnavailable));
        }
        self.registry.draft_creation_allowed()?;
        let prepared = journal
            .access(|journal| {
                if let Some(prior) = prior.as_ref()
                    && reencoding
                {
                    return journal.reencode_prepared(prior, mime.sha256());
                }
                let mut frozen = DraftReconstruction {
                    uid_validity: validity,
                    ..frozen
                };
                if prior.is_none() {
                    frozen.facts_sha256 = frozen.fingerprint(&identity, mailbox)?;
                }
                journal.prepare_with_limit(
                    PreparedDraftOperation {
                        identity,
                        mailbox_identity: mailbox.into(),
                        content_sha256: mime.sha256(),
                        reconstruction: Some(frozen),
                    },
                    self.config.limits.journal_records,
                )
            })
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
        let mut uncertain_operation = None;
        let duration =
            std::time::Duration::from_secs(self.limits(context)?.operation_seconds as u64);
        tokio::time::timeout(
            duration,
            self.draft_status_inner(context, input, &mut uncertain_operation),
        )
        .await
        .unwrap_or_else(|_| {
            Err(match uncertain_operation {
                Some(operation) => {
                    let mut error = Error::draft_outcome(ErrorCode::OutcomeUnknown, operation);
                    error.message =
                        "Reconciliation deadline exceeded; draft acceptance remains uncertain"
                            .into();
                    error
                }
                None => Error::new(ErrorCode::Timeout),
            })
        })
    }
    async fn draft_status_inner(
        &self,
        context: &RequestContext,
        input: DraftStatusInput,
        uncertain_operation: &mut Option<DraftOperationDetails>,
    ) -> Result<DraftReceipt, Error> {
        let identity = input.identity();
        let target = self.authorize_draft(
            context,
            &identity,
            &input.mailbox,
            Permission::InspectDraftOperation,
        )?;
        if input.reconcile && !context.permissions().contains(&Permission::AppendDraft) {
            return Err(super::denied());
        }
        let limits = self.limits(context)?;
        let _admission = self.requests.admit(target.account_id, limits).await?;
        // Open and close the journal under writer ownership so another process cannot
        // race this connection's final WAL checkpoint with its own reconciliation.
        let _writer = if input.reconcile {
            match self
                .registry
                .draft_writer(identity.account_id, limits.initialization_seconds)
                .await
            {
                Ok(writer) => Some(writer),
                Err(error) if error.code == ErrorCode::RateLimited => {
                    let mut journal = self
                        .registry
                        .wait_for_draft_journal(limits.initialization_seconds)
                        .await?;
                    if let Some(prior) =
                        authorized_operation(&mut journal, &identity, &input.mailbox)?
                        && prior.state == DraftOperationState::InFlight
                    {
                        return self.draft_receipt(prior, limits);
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let mut journal = self
            .registry
            .wait_for_draft_journal(limits.initialization_seconds)
            .await?;
        let mut prior = authorized_operation(&mut journal, &identity, &input.mailbox)?
            .ok_or_else(|| self.registry.absent_draft())?;
        if input.reconcile {
            if prior.state == DraftOperationState::InFlight {
                prior = journal
                    .access(|journal| journal.record_outcome_unknown(&identity))
                    .map_err(|_| {
                        uncertain(
                            &prior.operation,
                            "Draft recovery could not be recorded; acceptance remains uncertain",
                        )
                    })?;
            }
            if prior.state == DraftOperationState::OutcomeUnknown {
                *uncertain_operation = Some(operation_details(&prior.operation));
                return self
                    .reconcile_draft(target, &mut journal, &prior.operation, limits)
                    .await;
            }
        }
        self.draft_receipt(prior, limits)
    }

    async fn reconcile_draft(
        &self,
        target: MailboxTarget<'_>,
        journal: &mut super::state::DraftHistory,
        operation: &PreparedDraftOperation,
        limits: &Limits,
    ) -> Result<DraftReceipt, Error> {
        let identity = &operation.identity;
        let evidence = async {
            let route = self.registry.draft_route(
                target.config,
                target.generation,
                &operation.mailbox_identity,
            )?;
            let target = MailboxTarget {
                config: &route,
                ..target
            };
            let live;
            let backend: &dyn DraftBackend = match &self.draft_backend {
                Some(backend) => backend.as_ref(),
                None => {
                    live = self.imap_backend(target).await?;
                    &live
                }
            };
            let verification = crate::draft::DraftVerification {
                uid_validity: operation
                    .reconstruction
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorCode::JournalUnavailable))?
                    .uid_validity,
                message_id: identity.message_id(),
                content_sha256: operation.content_sha256,
            };
            backend
                .reconcile(target, &operation.mailbox_identity, &verification, limits)
                .await
        }
        .await;
        use crate::draft::DraftEvidence;
        let uid = match evidence {
            Ok(DraftEvidence::Verified(uid)) => Ok(uid),
            Ok(DraftEvidence::Absent) => {
                Err("No matching draft was found; acceptance remains uncertain")
            }
            Ok(DraftEvidence::Ambiguous) => {
                Err("Multiple draft candidates were found; acceptance remains uncertain")
            }
            Ok(DraftEvidence::ContentMismatch) => {
                Err("Draft content could not be verified; acceptance remains uncertain")
            }
            Err(Error {
                code: ErrorCode::ResponseTooLarge | ErrorCode::Timeout,
                ..
            }) => Err("Reconciliation work limit exceeded; draft acceptance remains uncertain"),
            Err(Error {
                code: ErrorCode::StaleReference,
                ..
            }) => {
                Err("The original mailbox incarnation changed; draft acceptance remains uncertain")
            }
            Err(_) => {
                Err("The original draft target could not be verified; acceptance remains uncertain")
            }
        }
        .map_err(|reason| uncertain(operation, reason))?;
        if uid.uid == 0
            || Some(uid.uid_validity) != operation.reconstruction.as_ref().map(|r| r.uid_validity)
        {
            return Err(uncertain(
                operation,
                "Draft identity could not be verified; acceptance remains uncertain",
            ));
        }
        let verified = journal
            .access(|journal| journal.record_duplicate(identity, uid))
            .map_err(|_| {
                uncertain(
                    operation,
                    "Verified draft could not be recorded; acceptance remains uncertain",
                )
            })?;
        self.draft_receipt(verified, limits)
    }
}

fn uncertain(operation: &PreparedDraftOperation, message: &str) -> Error {
    let mut error = Error::draft_outcome(ErrorCode::OutcomeUnknown, operation_details(operation));
    error.message = message.into();
    error
}
// The caller authorizes the requested mailbox before opening the journal. A row
// outside that scope is absent from the authorized lookup; never compare its input.
fn authorized_operation(
    journal: &mut super::state::DraftHistory,
    identity: &DraftIdentity,
    mailbox: &str,
) -> Result<Option<PersistedDraftOperation>, Error> {
    let prior = journal
        .access(|journal| journal.inspect(identity))
        .map_err(journal_error)?;
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
        let mut account_buffer = Uuid::encode_buffer();
        let message_reference = match persisted.state {
            DraftOperationState::Created {
                appended_message: Some(uid),
            }
            | DraftOperationState::Duplicate {
                appended_message: uid,
            } => self
                .encode(
                    "ms",
                    &super::tokens::MessageReference {
                        account: &*operation
                            .identity
                            .account_id
                            .hyphenated()
                            .encode_lower(&mut account_buffer),
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
            DraftOperationState::Duplicate { .. } => DraftState::Duplicate,
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
    journal: &'a mut super::state::DraftHistory,
    operation: &'a PreparedDraftOperation,
    finished: bool,
}
impl<'a> Dispatch<'a> {
    fn start(
        journal: &'a mut super::state::DraftHistory,
        operation: &'a PreparedDraftOperation,
    ) -> Result<Self, Error> {
        journal
            .access(|journal| journal.begin_dispatch(operation))
            .map_err(journal_error)?;
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
        let recorded = self
            .journal
            .access(|journal| match outcome {
                Ok(crate::imap::AppendOutcome::Created { uid }) => {
                    journal.record_created(identity, uid)
                }
                Ok(crate::imap::AppendOutcome::Rejected) => journal.record_rejected(identity),
                _ => journal.record_outcome_unknown(identity),
            })
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
                .access(|journal| journal.record_outcome_unknown(&self.operation.identity));
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
