//! In-memory message adapter for the application search contract.
use super::{MailboxTarget, SearchBackend};
use crate::{
    config::Limits,
    domain::{Error, ErrorCode, MessageMetadata, SearchCriteria, mailbox_identity},
    search::{LocatedMessage, SearchBatch, SearchRequest, SelectedMailbox, page},
};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct MemoryMessage {
    pub uid: u32,
    pub metadata: MessageMetadata,
    pub bcc: Vec<String>,
    /// Searchable message text, including headers and body.
    pub text: String,
}
struct MemoryMailbox {
    validity: u32,
    messages: BTreeMap<u32, MemoryMessage>,
}
#[derive(Default)]
pub struct MemoryMessages(RwLock<BTreeMap<(String, String), Arc<MemoryMailbox>>>);
impl MemoryMessages {
    pub fn set(
        &self,
        account_key: &str,
        mailbox: &str,
        uid_validity: u32,
        messages: Vec<MemoryMessage>,
    ) {
        self.0.write().unwrap().insert(
            (account_key.into(), mailbox_identity(mailbox).into()),
            Arc::new(MemoryMailbox {
                validity: uid_validity,
                messages: messages
                    .into_iter()
                    .map(|message| (message.uid, message))
                    .collect(),
            }),
        );
    }
}
impl SearchBackend for MemoryMessages {
    fn search<'a>(
        &'a self,
        target: MailboxTarget<'a>,
        request: SearchRequest<'a>,
        limits: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<SearchBatch, Error>> + Send + 'a>> {
        Box::pin(async move {
            let mailbox = self
                .0
                .read()
                .unwrap()
                .get(&(
                    target.config.key.clone(),
                    mailbox_identity(request.mailbox).into(),
                ))
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::StaleReference))?;
            page(&mut MemorySelection(mailbox), &request, limits).await
        })
    }
}
struct MemorySelection(Arc<MemoryMailbox>);
impl SelectedMailbox for MemorySelection {
    fn uid_validity(&self) -> u32 {
        self.0.validity
    }
    async fn upper_uid(&mut self) -> Result<u32, Error> {
        Ok(self.0.messages.last_key_value().map_or(0, |(uid, _)| *uid))
    }
    async fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> Result<Vec<u32>, Error> {
        Ok(self
            .0
            .messages
            .range(first..=last)
            .filter(|(_, message)| {
                criteria.predicates().iter().all(|predicate| {
                    use crate::domain::SearchPredicate::*;
                    match predicate {
                        RequiredFlag { flag } => message
                            .metadata
                            .flags
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(flag.imap_name())),
                        ForbiddenFlag { flag } => !message
                            .metadata
                            .flags
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(flag.imap_name())),
                        ReceivedAfter { date } => calendar_date(&message.metadata.received_date)
                            .is_some_and(|value| value >= date.date()),
                        ReceivedBefore { date } => calendar_date(&message.metadata.received_date)
                            .is_some_and(|value| value < date.date()),
                        SentAfter { date } => message
                            .metadata
                            .sent_date
                            .value()
                            .and_then(|value| calendar_date(value))
                            .is_some_and(|value| value >= date.date()),
                        SentBefore { date } => message
                            .metadata
                            .sent_date
                            .value()
                            .and_then(|value| calendar_date(value))
                            .is_some_and(|value| value < date.date()),
                        Subject { value } => message
                            .metadata
                            .subject
                            .value()
                            .is_some_and(|subject| contains(subject, value)),
                        Text { value } => contains(&message.text, value),
                        From { value } => address_match(&message.metadata.from, value),
                        To { value } => address_match(&message.metadata.to, value),
                        Cc { value } => address_match(&message.metadata.cc, value),
                        Bcc { value } => message.bcc.iter().any(|address| contains(address, value)),
                    }
                })
            })
            .map(|(uid, _)| *uid)
            .collect())
    }
    async fn fetch(&mut self, uids: &[u32]) -> Result<Vec<LocatedMessage>, Error> {
        Ok(uids
            .iter()
            .filter_map(|uid| self.0.messages.get(uid))
            .map(|message| LocatedMessage {
                uid: message.uid,
                metadata: message.metadata.clone(),
            })
            .collect())
    }
}
fn calendar_date(value: &str) -> Option<chrono::NaiveDate> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.date_naive())
}
fn contains(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}
fn address_match(
    addresses: &crate::domain::Metadata<Vec<crate::domain::MessageAddress>>,
    value: &str,
) -> bool {
    addresses.value().is_some_and(|addresses| {
        addresses.iter().any(|address| {
            contains(&address.address, value)
                || address
                    .name
                    .as_ref()
                    .is_some_and(|name| contains(name, value))
        })
    })
}
