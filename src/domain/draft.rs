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

impl DraftIdentity {
    pub(crate) fn message_id(&self) -> String {
        format!(
            "{}.{}.{}@mailctl.invalid",
            self.account_id, self.account_generation, self.operation_id
        )
    }
}

/// Authorized operation and original target, including its incarnation when known.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftOperationDetails {
    pub identity: DraftIdentity,
    pub mailbox: String,
    pub uid_validity: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DraftAddress {
    /// Recipient email address; supply each recipient as an object with this field.
    #[serde(deserialize_with = "nonempty::<_, 254>")]
    #[schemars(length(min = 1, max = 254), extend("x-maxUtf8Bytes" = 254))]
    pub address: String,
    /// Optional recipient display name.
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
    /// Approved from_identities address; omission requires one unambiguous identity.
    #[serde(default, deserialize_with = "super::bounded_optional_string::<_, 254>")]
    #[schemars(length(min = 1, max = 254), extend("x-maxUtf8Bytes" = 254))]
    pub from: Option<String>,
    /// Primary recipients as address/name objects; retain the original list for retries.
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub to: Vec<DraftAddress>,
    /// Copy recipients as address/name objects.
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub cc: Vec<DraftAddress>,
    /// Blind-copy recipients as address/name objects.
    #[serde(default, deserialize_with = "recipients")]
    #[schemars(length(max = 100))]
    pub bcc: Vec<DraftAddress>,
    /// Subject text, unchanged on retry; an empty subject is allowed.
    #[serde(default, deserialize_with = "text::<_, 8192>")]
    #[schemars(length(max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub subject: String,
    /// Plain UTF-8 message text; the encoded draft must fit capabilities.limits.draft_mime_bytes.
    #[serde(default, deserialize_with = "text::<_, 8388608>")]
    #[schemars(length(max = 8388608), extend("x-maxUtf8Bytes" = 8388608))]
    pub body: String,
    /// Original email Message-ID for a reply, rather than a mailctl message reference.
    #[serde(default, deserialize_with = "super::bounded_optional_string::<_, 998>")]
    #[schemars(length(min = 1, max = 998), extend("x-maxUtf8Bytes" = 998))]
    pub in_reply_to: Option<String>,
    /// Email Message-IDs in thread order, retained unchanged on retry.
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
    /// Literal approved drafts_mailbox name from account discovery, not a mailbox reference.
    #[serde(deserialize_with = "nonempty::<_, 1024>")]
    #[schemars(length(min = 1, max = 1024), extend("x-maxUtf8Bytes" = 1024))]
    pub mailbox: String,
    /// Stable account_id UUID from account discovery; retain it across retries.
    pub account_id: Uuid,
    /// Account discovery's generation, retained with the original operation.
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub account_generation: u64,
    /// Caller-generated UUID retained before the first call; reuse for identical retries.
    pub operation_id: Uuid,
    /// Unsent composition retained unchanged for every retry of this operation.
    pub draft: Box<DraftContent>,
}
impl SaveDraftInput {
    pub fn operation_details(&self) -> DraftOperationDetails {
        DraftOperationDetails {
            identity: self.identity(),
            mailbox: self.mailbox.clone(),
            uid_validity: None,
        }
    }
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
    /// Original literal Drafts mailbox name used when saving this operation.
    #[serde(deserialize_with = "nonempty::<_, 1024>")]
    #[schemars(length(min = 1, max = 1024), extend("x-maxUtf8Bytes" = 1024))]
    pub mailbox: String,
    /// Original account UUID retained when saving this operation.
    pub account_id: Uuid,
    /// Original account generation, including after account configuration changes.
    #[schemars(range(min = 1, max = 9223372036854775807u64))]
    pub account_generation: u64,
    /// Original caller-generated operation UUID.
    pub operation_id: Uuid,
    /// Check uncertain creation against the provider and update its journal outcome; never append again.
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
    CreatedReferenceUnavailable,
    Duplicate,
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
    pub message_reference: Option<String>,
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
