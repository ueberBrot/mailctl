//! Search windows and envelope reads on one exclusive read-only selection.
use super::{AuthenticatedConnection, Metrics, Projection, wire::Connection};
use crate::{
    domain::{Error, ErrorCode, SearchCriteria},
    search::{LocatedMessage, SearchBatch, SearchRequest, SelectedMailbox, page},
};
use io_imap::{
    rfc3501::{
        fetch::{ImapMessageFetch, ImapMessageFetchOptions},
        logout::ImapLogout,
        search::{ImapMessageSearch, ImapMessageSearchOptions},
    },
    types::search::SearchKey,
};
use std::num::NonZeroU32;

impl AuthenticatedConnection {
    pub(crate) async fn search(
        self,
        request: SearchRequest<'_>,
        limits: &crate::config::Limits,
    ) -> Result<SearchBatch, Error> {
        let mut metrics = Metrics::default();
        self.0
            .resume(&mut metrics)
            .search_messages(request, limits)
            .await
    }
}
impl super::ImapProbe {
    /// Typed traversal through the same selected-mailbox routine used by the application.
    /// `metrics()` retains progress after success, failure, or cancellation.
    pub async fn search_messages(
        &mut self,
        username: &str,
        password: &str,
        request: SearchRequest<'_>,
        limits: &crate::config::Limits,
    ) -> Result<SearchBatch, Error> {
        self.metrics = Metrics::default();
        limits.validate()?;
        super::credentials(username, password).map_err(Error::from)?;
        let deadline = self
            .limits
            .operation_timeout
            .min(std::time::Duration::from_secs(
                limits.operation_seconds as u64,
            ));
        tokio::time::timeout(deadline, async {
            let mut connection = self
                .authenticate(username, password)
                .await
                .map_err(Error::from)?;
            connection.search_messages(request, limits).await
        })
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))?
    }
}
impl Connection<'_> {
    async fn search_messages(
        &mut self,
        request: SearchRequest<'_>,
        limits: &crate::config::Limits,
    ) -> Result<SearchBatch, Error> {
        super::mailbox(request.mailbox).map_err(Error::from)?;
        limits.validate()?;
        self.limit_search(limits);
        let (validity, uid_next) = self
            .examine_selection(request.mailbox)
            .await
            .map_err(Error::from)?;
        let result = page(
            &mut Selection {
                connection: self,
                validity,
                uid_next,
                header_bytes: limits.header_bytes,
            },
            &request,
            limits,
        )
        .await?;
        self.drive(ImapLogout::new()).await.map_err(Error::from)?;
        Ok(result)
    }
}

struct Selection<'a, 'b> {
    connection: &'a mut Connection<'b>,
    validity: u32,
    uid_next: Option<u32>,
    header_bytes: usize,
}
impl SelectedMailbox for Selection<'_, '_> {
    fn uid_validity(&self) -> u32 {
        self.validity
    }
    async fn upper_uid(&mut self) -> Result<u32, Error> {
        if let Some(next) = self.uid_next {
            return Ok(next - 1);
        }
        let uids = self
            .connection
            .drive(ImapMessageSearch::new(
                vec![SearchKey::Uid("*".try_into().unwrap())]
                    .try_into()
                    .unwrap(),
                ImapMessageSearchOptions { uid: true },
            ))
            .await
            .map_err(Error::from)?;
        if uids.len() > 1 {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        Ok(uids.first().map_or(0, |uid| uid.get()))
    }
    async fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> Result<Vec<u32>, Error> {
        let range = (first..=last)
            .try_into()
            .map_err(|_| Error::new(ErrorCode::InvalidRequest))?;
        let mut keys = vec![SearchKey::Uid(range)];
        let mut utf8 = false;
        for predicate in criteria.predicates() {
            keys.push(search_key(predicate, &mut utf8)?);
        }
        let uids = self
            .connection
            .search(keys, utf8)
            .await
            .map_err(Error::from)?;
        Ok(uids.into_iter().map(NonZeroU32::get).collect())
    }
    async fn fetch(&mut self, uids: &[u32]) -> Result<Vec<LocatedMessage>, Error> {
        let mut uids = uids
            .iter()
            .map(|uid| NonZeroU32::new(*uid).ok_or_else(|| Error::new(ErrorCode::InvalidRequest)))
            .collect::<Result<Vec<_>, _>>()?;
        uids.sort_unstable();
        let rows = self
            .connection
            .drive(ImapMessageFetch::new(
                uids.try_into().unwrap(),
                Projection::FIELDS.to_vec().into(),
                ImapMessageFetchOptions {
                    uid: true,
                    ..Default::default()
                },
            ))
            .await
            .map_err(Error::from)?;
        rows.into_values()
            .map(|items| {
                let projection = Projection::parse(items.as_ref()).map_err(Error::from)?;
                projection
                    .check_header_bytes(self.header_bytes)
                    .map_err(Error::from)?;
                Ok(projection.message())
            })
            .collect()
    }
}
fn search_key(
    predicate: &crate::domain::SearchPredicate,
    utf8: &mut bool,
) -> Result<SearchKey<'static>, Error> {
    use crate::domain::{SearchPredicate::*, StandardFlag};
    let date = |value: &crate::domain::SearchDate| {
        value
            .date()
            .try_into()
            .map_err(|_| Error::new(ErrorCode::InvalidRequest))
    };
    let mut text = |value: &String| {
        *utf8 |= !value.is_ascii();
        value
            .clone()
            .try_into()
            .map_err(|_| Error::new(ErrorCode::InvalidRequest))
    };
    Ok(match predicate {
        ReceivedAfter { date: value } => SearchKey::Since(date(value)?),
        ReceivedBefore { date: value } => SearchKey::Before(date(value)?),
        SentAfter { date: value } => SearchKey::SentSince(date(value)?),
        SentBefore { date: value } => SearchKey::SentBefore(date(value)?),
        From { value } => SearchKey::From(text(value)?),
        To { value } => SearchKey::To(text(value)?),
        Cc { value } => SearchKey::Cc(text(value)?),
        Bcc { value } => SearchKey::Bcc(text(value)?),
        Subject { value } => SearchKey::Subject(text(value)?),
        Text { value } => SearchKey::Text(text(value)?),
        RequiredFlag { flag } => match flag {
            StandardFlag::Answered => SearchKey::Answered,
            StandardFlag::Deleted => SearchKey::Deleted,
            StandardFlag::Draft => SearchKey::Draft,
            StandardFlag::Flagged => SearchKey::Flagged,
            StandardFlag::Recent => SearchKey::Recent,
            StandardFlag::Seen => SearchKey::Seen,
        },
        ForbiddenFlag { flag } => match flag {
            StandardFlag::Answered => SearchKey::Unanswered,
            StandardFlag::Deleted => SearchKey::Undeleted,
            StandardFlag::Draft => SearchKey::Undraft,
            StandardFlag::Flagged => SearchKey::Unflagged,
            StandardFlag::Recent => SearchKey::Old,
            StandardFlag::Seen => SearchKey::Unseen,
        },
    })
}
