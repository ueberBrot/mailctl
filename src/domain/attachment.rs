//! Attachment references and session-local decoded chunks.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportReceipt {
    pub path: std::path::PathBuf,
    pub filesystem: String,
    pub total_decoded_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListAttachmentsInput {
    #[serde(deserialize_with = "super::reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
#[schemars(extend("type" = "object"))]
pub enum GetAttachmentInput {
    Start(AttachmentStart),
    Continue(AttachmentContinuation),
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentStart {
    #[serde(deserialize_with = "super::reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub attachment: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentContinuation {
    #[serde(deserialize_with = "super::reference")]
    #[schemars(length(min = 1, max = 8192), extend("x-maxUtf8Bytes" = 8192))]
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentMetadata {
    pub reference: String,
    pub display_name: Option<String>,
    pub media_type: String,
    /// Transfer-encoded size reported by the provider, not a decoded byte count.
    pub declared_size: Option<u64>,
    pub available: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentList {
    pub account_id: String,
    pub generation: u64,
    pub message_reference: String,
    pub attachments: Vec<AttachmentMetadata>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentChunk {
    pub account_id: String,
    pub generation: u64,
    pub attachment_reference: String,
    pub bytes_base64: String,
    pub decoded_offset: u64,
    pub progress: AttachmentProgress,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachmentProgress {
    Continue {
        next_token: String,
    },
    Complete {
        total_decoded_bytes: u64,
        sha256: String,
    },
}
