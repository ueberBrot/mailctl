//! Selected message text and its representation metadata.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetMessageInput {
    /// A message reference returned by search in this installation.
    #[serde(deserialize_with = "message_reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub message: String,
}
fn message_reference<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    super::bounded_optional_string::<D, 8192>(d)?
        .ok_or_else(|| serde::de::Error::custom("message reference is required"))
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageBody {
    pub account_id: String,
    pub generation: u64,
    pub message_reference: String,
    pub body: BodyText,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyText {
    pub text: String,
    pub selected_part: Option<String>,
    pub source_media_type: Option<String>,
    pub representation_version: String,
    pub converted: bool,
    pub replacements: bool,
    pub truncated: bool,
    pub empty_reason: Option<EmptyBodyReason>,
    /// Public text continuation is not yet implemented.
    pub continuation_available: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmptyBodyReason {
    NoSupportedBody,
}
