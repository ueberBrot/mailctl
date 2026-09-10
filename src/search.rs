//! Bounded descending-UID traversal shared by message providers.
use crate::{
    config::Limits,
    domain::{Error, ErrorCode, MessageMetadata, SearchCriteria},
    encoding::OutputBudget,
};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPosition {
    pub uid_validity: u32,
    pub upper_uid: u32,
    pub next_uid: u32,
}

pub struct SearchRequest<'a> {
    pub mailbox: &'a str,
    pub criteria: &'a SearchCriteria,
    pub position: Option<SearchPosition>,
    pub limit: usize,
    pub response_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct LocatedMessage {
    pub uid: u32,
    pub metadata: MessageMetadata,
}
pub struct SearchBatch {
    pub position: SearchPosition,
    pub messages: Vec<LocatedMessage>,
}

pub(crate) trait SelectedMailbox {
    fn uid_validity(&self) -> u32;
    fn upper_uid(&mut self) -> impl Future<Output = Result<u32, Error>> + Send;
    fn matches(
        &mut self,
        first: u32,
        last: u32,
        criteria: &SearchCriteria,
    ) -> impl Future<Output = Result<Vec<u32>, Error>> + Send;
    fn fetch(
        &mut self,
        uids: &[u32],
    ) -> impl Future<Output = Result<Vec<LocatedMessage>, Error>> + Send;
}

/// Each resume searches live predicates below the last consumed UID, including a partial window.
pub(crate) async fn page(
    selected: &mut impl SelectedMailbox,
    request: &SearchRequest<'_>,
    limits: &Limits,
) -> Result<SearchBatch, Error> {
    limits.validate()?;
    if request.limit == 0 || request.limit > limits.search_page {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let validity = selected.uid_validity();
    if validity == 0 {
        return Err(Error::new(ErrorCode::ProviderUnavailable));
    }
    let mut position = match request.position {
        Some(position) if position.uid_validity != validity => {
            return Err(Error::new(ErrorCode::StaleCursor));
        }
        Some(position) => position,
        None => {
            let upper_uid = selected.upper_uid().await?;
            SearchPosition {
                uid_validity: validity,
                upper_uid,
                next_uid: upper_uid,
            }
        }
    };
    let mut messages = Vec::new();
    let mut budget = OutputBudget::new(request.response_bytes);
    for _ in 0..limits.search_windows {
        if position.next_uid == 0 || messages.len() == request.limit {
            break;
        }
        let last = position.next_uid;
        let first = last
            .saturating_sub(limits.search_uid_window as u32 - 1)
            .max(1);
        let mut uids = selected.matches(first, last, request.criteria).await?;
        if uids.len() > limits.search_uid_window
            || uids.iter().any(|uid| !(first..=last).contains(uid))
        {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        uids.sort_unstable_by(|a, b| b.cmp(a));
        if uids.windows(2).any(|uids| uids[0] == uids[1]) {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        let remaining = request.limit - messages.len();
        position.next_uid = if uids.len() > remaining {
            uids[remaining - 1] - 1
        } else {
            first - 1
        };
        uids.truncate(remaining);
        if uids.is_empty() {
            continue;
        }
        let mut rows = selected.fetch(&uids).await?;
        rows.sort_unstable_by_key(|row| std::cmp::Reverse(row.uid));
        if rows.len() > uids.len()
            || rows.windows(2).any(|rows| rows[0].uid == rows[1].uid)
            || rows
                .iter()
                .any(|row| uids.binary_search_by(|uid| row.uid.cmp(uid)).is_err())
        {
            return Err(Error::new(ErrorCode::ProviderUnavailable));
        }
        for row in rows {
            budget.count(&row.metadata)?;
            budget.reserve(1024)?;
            messages.push(row);
        }
    }
    Ok(SearchBatch { position, messages })
}
