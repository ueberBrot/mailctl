//! Selected message text and its representation metadata.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default UTF-8 byte ceiling for each returned text page.
pub const DEFAULT_TEXT_PAGE_BYTES: usize = 8192;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetMessageInput {
    /// A message reference returned by search in this installation.
    #[serde(deserialize_with = "super::reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub message: String,
    /// UTF-8 bytes per text page, from 4 through the effective text_page_bytes ceiling.
    /// Omit to use at most 8192 bytes. Keep this value unchanged for continuation.
    #[serde(default, deserialize_with = "super::page_limit::<_, 2097152>")]
    #[schemars(range(min = 4, max = 2097152))]
    pub max_bytes: Option<usize>,
    /// Authenticated continuation returned by the preceding text page; repeat max_bytes.
    #[serde(
        default,
        deserialize_with = "super::bounded_optional_string::<_, 8192>"
    )]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub cursor: Option<String>,
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
    /// Whether another page of this representation is available.
    pub continuation_available: bool,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmptyBodyReason {
    NoSupportedBody,
}
