//! Search windows and envelope reads on one exclusive read-only selection.
use super::{AuthenticatedConnection, Metrics, projection::Projection, wire::Connection};
use super::{
    fetch::Fetch,
    wire::{Kind, SearchTerm},
};
use crate::{
    domain::{Error, ErrorCode, SearchCriteria},
    search::{LocatedMessage, SearchBatch, SearchRequest, SelectedMailbox, page},
};
use std::fmt::Write;

impl AuthenticatedConnection {
    pub async fn search(
        self,
        request: SearchRequest<'_>,
        limits: &crate::config::Limits,
        metrics: &mut Metrics,
    ) -> Result<SearchBatch, Error> {
        let mut connection = self.session.resume(metrics);
        super::mailbox(request.mailbox)?;
        limits.validate()?;
        connection.limit_search(limits);
        let fuzzy = request.fuzzy
            && connection.supports_fuzzy_search()
            && request.criteria.predicates().iter().any(|predicate| {
                matches!(
                    predicate,
                    crate::domain::SearchPredicate::Subject { .. }
                        | crate::domain::SearchPredicate::Text { .. }
                )
            });
        let (validity, uid_next) = connection.examine_selection(request.mailbox).await?;
        let result = page(
            &mut Selection {
                connection: &mut connection,
                validity,
                uid_next,
                header_bytes: limits.header_bytes,
                fuzzy,
            },
            &request,
            limits,
        )
        .await?;
        connection.logout().await?;
        Ok(result)
    }
}

struct Selection<'a, 'b> {
    connection: &'a mut Connection<'b>,
    validity: u32,
    uid_next: Option<u32>,
    header_bytes: usize,
    fuzzy: bool,
}
impl SelectedMailbox for Selection<'_, '_> {
    fn uid_validity(&self) -> u32 {
        self.validity
    }
    fn fuzzy(&self) -> bool {
        self.fuzzy
    }
    async fn upper_uid(&mut self) -> Result<u32, Error> {
        self.connection
            .upper_uid(self.uid_next)
            .await
            .map_err(Error::from)
    }
    async fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> Result<Vec<u32>, Error> {
        let mut keys = vec![SearchTerm::Atom(format!("UID {first}:{last}").into())];
        let mut utf8 = false;
        for predicate in criteria.predicates() {
            keys.push(search_key(predicate, &mut utf8, self.fuzzy));
        }
        Ok(self.connection.search(keys, utf8).await?)
    }
    async fn fetch(&mut self, uids: &[u32]) -> Result<Vec<LocatedMessage>, Error> {
        if uids.is_empty() || uids.contains(&0) {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let mut set = String::with_capacity(uids.len() * 11);
        for uid in uids.iter().rev() {
            if !set.is_empty() {
                set.push(',');
            }
            write!(set, "{uid}").expect("writing a UID to a String");
        }
        let rows = self
            .connection
            .request(
                &format!("UID FETCH {set} ({})", Projection::FIELDS),
                Kind::Projection,
            )
            .await?;
        rows.iter()
            .map(|row| {
                let projection = Projection::parse(Fetch::items(row)?)?;
                projection.check_header_bytes(self.header_bytes)?;
                let message = projection.message();
                if uids.binary_search_by(|uid| message.uid.cmp(uid)).is_err() {
                    return Err(Error::new(ErrorCode::ProviderUnavailable));
                }
                Ok(message)
            })
            .collect()
    }
}

fn search_key<'a>(
    predicate: &'a crate::domain::SearchPredicate,
    utf8: &mut bool,
    fuzzy: bool,
) -> SearchTerm<'a> {
    use crate::domain::{SearchPredicate::*, StandardFlag};
    let date = |keyword: &str, value: &crate::domain::SearchDate| {
        SearchTerm::Atom(format!("{keyword} {}", value.date().format("%d-%b-%Y")).into())
    };
    let mut text = |keyword, value: &'a str| {
        *utf8 |= !value.is_ascii();
        SearchTerm::Text(keyword, value)
    };
    match predicate {
        ReceivedAfter { date: value } => date("SINCE", value),
        ReceivedBefore { date: value } => date("BEFORE", value),
        SentAfter { date: value } => date("SENTSINCE", value),
        SentBefore { date: value } => date("SENTBEFORE", value),
        From { value } => text("FROM", value),
        To { value } => text("TO", value),
        Cc { value } => text("CC", value),
        Bcc { value } => text("BCC", value),
        Subject { value } => text(if fuzzy { "FUZZY SUBJECT" } else { "SUBJECT" }, value),
        Text { value } => text(if fuzzy { "FUZZY TEXT" } else { "TEXT" }, value),
        RequiredFlag { flag } | ForbiddenFlag { flag } => {
            let flag = match (matches!(predicate, ForbiddenFlag { .. }), flag) {
                (false, StandardFlag::Answered) => "ANSWERED",
                (false, StandardFlag::Deleted) => "DELETED",
                (false, StandardFlag::Draft) => "DRAFT",
                (false, StandardFlag::Flagged) => "FLAGGED",
                (false, StandardFlag::Recent) => "RECENT",
                (false, StandardFlag::Seen) => "SEEN",
                (true, StandardFlag::Answered) => "UNANSWERED",
                (true, StandardFlag::Deleted) => "UNDELETED",
                (true, StandardFlag::Draft) => "UNDRAFT",
                (true, StandardFlag::Flagged) => "UNFLAGGED",
                (true, StandardFlag::Recent) => "OLD",
                (true, StandardFlag::Seen) => "UNSEEN",
            };
            SearchTerm::Atom(flag.into())
        }
    }
}
