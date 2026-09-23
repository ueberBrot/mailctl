//! Caller-retained draft identity, composition, and journal receipts.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftIdentity {
    pub account_id: Uuid,
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub account_generation: u64,
    pub operation_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftAddress {
    #[serde(deserialize_with = "nonempty::<_, 254>")]
    #[schemars(length(min = 1, max = 254), extend("x-maxUtf8Bytes" = 254))]
    pub address: String,
    #[serde(
        default,
        deserialize_with = "super::bounded_optional_string::<_, 1024>"
    )]
    #[schemars(length(min = 1, max = 1024), extend("x-maxUtf8Bytes" = 1024))]
    pub name: Option<String>,
}
impl From<String> for DraftAddress {
    fn from(address: String) -> Self {
        Self {
            address,
            name: None,
        }
    }
}
impl From<&str> for DraftAddress {
    fn from(address: &str) -> Self {
        address.to_owned().into()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftContent {
    #[serde(default, deserialize_with = "super::bounded_optional_string::<_, 254>")]
    #[schemars(length(min = 1, max = 254), extend("x-maxUtf8Bytes" = 254))]
    pub from: Option<String>,
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub to: Vec<DraftAddress>,
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub cc: Vec<DraftAddress>,
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub bcc: Vec<DraftAddress>,
    #[serde(default, deserialize_with = "text::<_, 8192>")]
    #[schemars(length(max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub subject: String,
    #[serde(default, deserialize_with = "text::<_, 8388608>")]
    #[schemars(length(max = 8388608), extend("x-maxUtf8Bytes" = 8388608))]
    pub body: String,
    #[serde(default, deserialize_with = "super::bounded_optional_string::<_, 998>")]
    #[schemars(length(min = 1, max = 998), extend("x-maxUtf8Bytes" = 998))]
    pub in_reply_to: Option<String>,
    #[serde(default, deserialize_with = "references")]
    #[schemars(schema_with = "references_schema")]
    pub references: Vec<String>,
}
fn text<'de, D: serde::Deserializer<'de>, const MAX: usize>(d: D) -> Result<String, D::Error> {
    crate::encoding::BoundedString::<0, MAX>::deserialize(d).map(|s| s.0)
}
fn recipients<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<DraftAddress>, D::Error> {
    crate::encoding::BoundedVec::<DraftAddress, 100>::deserialize(d).map(|v| v.0)
}
fn references<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    crate::encoding::BoundedVec::<crate::encoding::BoundedString<1, 998>, 50>::deserialize(d)
        .map(|v| v.0.into_iter().map(|s| s.0).collect())
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveDraftInput {
    #[serde(deserialize_with = "nonempty::<_, 1024>")]
    #[schemars(length(min = 1, max = 1024), extend("x-maxUtf8Bytes" = 1024))]
    pub mailbox: String,
    pub account_id: Uuid,
    pub account_generation: u64,
    pub operation_id: Uuid,
    pub draft: Box<DraftContent>,
}
impl SaveDraftInput {
    pub fn identity(&self) -> DraftIdentity {
        DraftIdentity {
            account_id: self.account_id,
            account_generation: self.account_generation,
            operation_id: self.operation_id,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftStatusInput {
    #[serde(deserialize_with = "nonempty::<_, 1024>")]
    #[schemars(length(min = 1, max = 1024), extend("x-maxUtf8Bytes" = 1024))]
    pub mailbox: String,
    pub account_id: Uuid,
    pub account_generation: u64,
    pub operation_id: Uuid,
    #[serde(default)]
    pub reconcile: bool,
}
impl DraftStatusInput {
    pub fn identity(&self) -> DraftIdentity {
        DraftIdentity {
            account_id: self.account_id,
            account_generation: self.account_generation,
            operation_id: self.operation_id,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DraftState {
    Prepared,
    InFlight,
    Created,
    Rejected,
    OutcomeUnknown,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftReceipt {
    pub account_id: Uuid,
    pub account_generation: u64,
    pub operation_id: Uuid,
    pub mailbox: String,
    pub uid_validity: u32,
    pub state: DraftState,
    pub dispatched: bool,
    pub content_sha256: String,
}

pub(crate) fn dot_atom(value: &str) -> bool {
    value.split('.').all(|atom| {
        !atom.is_empty()
            && atom
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte))
    })
}

fn nonempty<'de, D: serde::Deserializer<'de>, const MAX: usize>(d: D) -> Result<String, D::Error> {
    crate::encoding::BoundedString::<1, MAX>::deserialize(d).map(|s| s.0)
}

fn references_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "maxItems": 50,
        "items": {
            "type": "string",
            "minLength": 1,
            "maxLength": 998,
            "x-maxUtf8Bytes": 998
        }
    })
}
