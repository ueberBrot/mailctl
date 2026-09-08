//! Domain inputs, discovery results, and safe errors shared by every frontend.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    ProtocolMismatch,
    PermissionDenied,
    AccountNotAllowed,
    MailboxNotAllowed,
    MessageNotFound,
    StaleReference,
    StaleCursor,
    TransferExpired,
    AuthenticationFailed,
    CredentialUnavailable,
    TlsFailed,
    BrokerUnavailable,
    ProviderUnavailable,
    RateLimited,
    Timeout,
    Cancelled,
    ResponseTooLarge,
    AttachmentTooLarge,
    UnsupportedCapability,
    DraftMailboxUnavailable,
    OperationConflict,
    OperationInProgress,
    OutcomeUnknown,
    JournalUnavailable,
    JournalFull,
    ExportFailed,
    InternalError,
    OperationNotFound,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}
impl Error {
    pub fn new(code: ErrorCode) -> Self {
        let message = match code {
            ErrorCode::InvalidRequest => "Invalid request or configuration",
            ErrorCode::ProtocolMismatch => "Unsupported protocol version",
            ErrorCode::PermissionDenied
            | ErrorCode::AccountNotAllowed
            | ErrorCode::MailboxNotAllowed => "Access denied",
            ErrorCode::BrokerUnavailable => "Broker unavailable",
            ErrorCode::RateLimited => "Request capacity exhausted",
            ErrorCode::Timeout => "Request deadline exceeded",
            ErrorCode::ResponseTooLarge => "Result exceeds the configured limit",
            ErrorCode::UnsupportedCapability => "Operation is not supported",
            ErrorCode::Cancelled => "Request cancelled",
            _ => "Operation could not be completed",
        };
        Self {
            code,
            message: message.into(),
            retryable: matches!(
                code,
                ErrorCode::BrokerUnavailable
                    | ErrorCode::ProviderUnavailable
                    | ErrorCode::RateLimited
                    | ErrorCode::Timeout
            ),
        }
    }
    pub fn exit_code(&self) -> u8 {
        match self.code {
            ErrorCode::InvalidRequest | ErrorCode::ProtocolMismatch => 2,
            ErrorCode::PermissionDenied
            | ErrorCode::AccountNotAllowed
            | ErrorCode::MailboxNotAllowed => 3,
            ErrorCode::CredentialUnavailable
            | ErrorCode::AuthenticationFailed
            | ErrorCode::TlsFailed => 4,
            ErrorCode::BrokerUnavailable
            | ErrorCode::ProviderUnavailable
            | ErrorCode::RateLimited
            | ErrorCode::Timeout => 5,
            ErrorCode::MessageNotFound
            | ErrorCode::StaleReference
            | ErrorCode::StaleCursor
            | ErrorCode::TransferExpired
            | ErrorCode::OperationConflict
            | ErrorCode::OperationNotFound => 6,
            ErrorCode::OperationInProgress | ErrorCode::OutcomeUnknown => 7,
            ErrorCode::Cancelled => 130,
            _ => 8,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListAccountsInput {
    pub limit: Option<usize>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(
    tag = "operation",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Operation {
    ListAccounts(ListAccountsInput),
    Capabilities,
    Health,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema_version: u32,
    pub request_id: String,
    #[serde(rename = "ok")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}
impl Envelope {
    pub fn from_result(request_id: String, result: Result<Value, Error>) -> Self {
        match result {
            Ok(result) => Self {
                schema_version: 1,
                request_id,
                success: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                schema_version: 1,
                request_id,
                success: false,
                result: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Unknown,
    Configured,
    Unavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Account {
    pub alias: String,
    pub account_id: String,
    pub generation: u64,
    pub from_identities: Vec<String>,
    pub capabilities: Vec<String>,
    pub availability: Availability,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct AccountDiscovery {
    pub accounts: Vec<Account>,
    pub complete: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Capabilities {
    pub operations: Vec<String>,
    pub permissions: Vec<crate::policy::Permission>,
    pub health: Health,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Health {
    pub status: String,
    pub listener: String,
    pub accounts: Vec<AccountHealth>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct AccountHealth {
    pub account_id: String,
    pub generation: u64,
    pub availability: Availability,
}
