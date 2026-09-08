//! In-memory provider adapter for account discovery without provider access.
use crate::domain::Availability;

#[derive(Default)]
pub(crate) struct InMemoryBackend;
impl InMemoryBackend {
    pub(crate) fn availability(&self) -> Availability {
        Availability::Unknown
    }
}
