//! Access-grant authority and request narrowing are independent of provider adapters.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    ReadOnly,
    DraftsOnly,
    ReadAndDrafts,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ListAccounts,
    ListMailboxes,
    SearchMessages,
    ReadMessage,
    ReadAttachment,
    AppendDraft,
    InspectDraftOperation,
}
impl Profile {
    pub fn permissions(self, read_only: bool) -> Vec<Permission> {
        use Permission::*;
        let mut result = vec![ListAccounts];
        if self != Self::DraftsOnly {
            result.extend([ListMailboxes, SearchMessages, ReadMessage, ReadAttachment]);
        }
        if self != Self::ReadOnly && !read_only {
            result.extend([AppendDraft, InspectDraftOperation]);
        }
        result
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Narrowing {
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, deserialize_with = "account_scope::deserialize")]
    #[schemars(schema_with = "account_scope::schema")]
    pub accounts: Option<Vec<String>>,
}
/// Created by the application from a configured access grant.
#[derive(Clone, Debug)]
pub struct RequestContext {
    service_id: Uuid,
    session: std::sync::Arc<crate::service::TransferSession>,
    grant: String,
    // Indices into the immutable configuration of the issuing Service.
    account_indices: Vec<usize>,
    permissions: Vec<Permission>,
    response_limit: usize,
}

impl RequestContext {
    pub(crate) fn new(
        service_id: Uuid,
        session: std::sync::Arc<crate::service::TransferSession>,
        grant: String,
        account_indices: Vec<usize>,
        permissions: Vec<Permission>,
        response_limit: usize,
    ) -> Self {
        Self {
            service_id,
            session,
            grant,
            account_indices,
            permissions,
            response_limit,
        }
    }
    pub fn with_response_limit(mut self, maximum: usize) -> Self {
        self.response_limit = self.response_limit.min(maximum);
        self
    }
    pub(crate) fn session_id(&self) -> Uuid {
        self.session.id
    }
    pub(crate) fn belongs_to(&self, service_id: Uuid) -> bool {
        self.service_id == service_id
    }
    pub(crate) fn grant_name(&self) -> &str {
        &self.grant
    }
    pub(crate) fn account_indices(&self) -> &[usize] {
        &self.account_indices
    }
    pub(crate) fn permissions(&self) -> &[Permission] {
        &self.permissions
    }
    pub(crate) fn response_limit(&self) -> usize {
        self.response_limit
    }
}

mod account_scope {
    use crate::encoding::{BoundedString, BoundedVec};
    use serde::{Deserialize, Deserializer};
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<String>>, D::Error> {
        Option::<BoundedVec<BoundedString<0, 1024>, 256>>::deserialize(deserializer).map(
            |accounts| {
                accounts.map(|accounts| accounts.0.into_iter().map(|alias| alias.0).collect())
            },
        )
    }
    pub(super) fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "anyOf": [
                {"type": "null"},
                {"type": "array", "maxItems":256, "items":{"type":"string", "maxLength":1024, "x-maxUtf8Bytes":1024}}
            ]
        })
    }
}
