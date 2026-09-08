//! Domain inputs, discovery results, and safe errors shared by every frontend.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub fn setup_required() -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            message: "Configuration is unavailable or invalid; run mailctl setup".into(),
            retryable: false,
        }
    }
    pub fn obsolete_runtime_capacity() -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            message: "Configuration uses removed shared runtime capacity settings; remove runtimes, runtime_slots, and shared permit settings. Limits now apply per process; run mailctl setup to migrate".into(),
            retryable: false,
        }
    }
    pub fn new(code: ErrorCode) -> Self {
        let message = match code {
            ErrorCode::InvalidRequest => "Invalid request or configuration",
            ErrorCode::ProtocolMismatch => "Unsupported protocol version",
            ErrorCode::PermissionDenied
            | ErrorCode::AccountNotAllowed
            | ErrorCode::MailboxNotAllowed => "Access denied",
            ErrorCode::BrokerUnavailable => "Broker unavailable",
            ErrorCode::Timeout => "Request deadline exceeded",
            ErrorCode::ResponseTooLarge => "Result exceeds the configured limit",
            ErrorCode::UnsupportedCapability => "Operation is not supported",
            ErrorCode::Cancelled => "Request cancelled",
            ErrorCode::OperationConflict => {
                "Configuration changed; restart the command or MCP session"
            }
            ErrorCode::RateLimited => {
                "Capacity is busy; retry after active commands or MCP sessions finish"
            }
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
    #[serde(default, deserialize_with = "account_limit")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<usize>,
}
#[derive(Clone, Debug, Serialize, JsonSchema)]
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

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Name {
            ListAccounts,
            Capabilities,
            Health,
        }
        #[derive(Default)]
        enum Input {
            #[default]
            Absent,
            Present(ListAccountsInput),
        }
        impl<'de> Deserialize<'de> for Input {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                ListAccountsInput::deserialize(deserializer).map(Self::Present)
            }
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            operation: Name,
            #[serde(default)]
            input: Input,
        }
        let wire = Wire::deserialize(deserializer)?;
        match (wire.operation, wire.input) {
            (Name::ListAccounts, Input::Present(input)) => Ok(Self::ListAccounts(input)),
            (Name::Capabilities, Input::Absent) => Ok(Self::Capabilities),
            (Name::Health, Input::Absent) => Ok(Self::Health),
            _ => Err(serde::de::Error::custom("invalid operation input")),
        }
    }
}

/// A result envelope has exactly one success result or one failure error.
///
/// ```compile_fail
/// use mailctl::domain::{Envelope, OperationResult};
/// let envelope = Envelope::<OperationResult> { success: true, result: None, error: None };
/// ```
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Envelope<T = OperationResult>(EnvelopeData<T>);

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
enum EnvelopeData<T> {
    Success {
        schema_version: Version1,
        request_id: String,
        ok: True,
        result: T,
    },
    Failure {
        schema_version: Version1,
        request_id: String,
        ok: False,
        error: Error,
    },
}

macro_rules! literal {
    ($name:ident, $type:ty, $value:expr, $json_type:literal) => {
        #[derive(Clone, Copy, Debug)]
        struct $name;
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                $value.serialize(serializer)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                if <$type>::deserialize(deserializer)? == $value { Ok(Self) }
                else { Err(serde::de::Error::custom("invalid envelope discriminator")) }
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static,str> { stringify!($name).into() }
            fn inline_schema() -> bool { true }
            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({"type": $json_type, "const": $value})
            }
        }
    }
}
literal!(Version1, u32, 1u32, "integer");
literal!(True, bool, true, "boolean");
literal!(False, bool, false, "boolean");

impl<T> Envelope<T> {
    pub fn from_result(request_id: String, result: Result<T, Error>) -> Self {
        Self(match result {
            Ok(result) => EnvelopeData::Success {
                schema_version: Version1,
                request_id,
                ok: True,
                result,
            },
            Err(error) => EnvelopeData::Failure {
                schema_version: Version1,
                request_id,
                ok: False,
                error,
            },
        })
    }
    pub fn schema_version(&self) -> u32 {
        1
    }
    pub fn request_id(&self) -> &str {
        match &self.0 {
            EnvelopeData::Success { request_id, .. } | EnvelopeData::Failure { request_id, .. } => {
                request_id
            }
        }
    }
    pub fn is_success(&self) -> bool {
        matches!(self.0, EnvelopeData::Success { .. })
    }
    pub fn result(&self) -> Option<&T> {
        match &self.0 {
            EnvelopeData::Success { result, .. } => Some(result),
            EnvelopeData::Failure { .. } => None,
        }
    }
    pub fn error(&self) -> Option<&Error> {
        match &self.0 {
            EnvelopeData::Failure { error, .. } => Some(error),
            EnvelopeData::Success { .. } => None,
        }
    }
    pub fn into_result(self) -> Result<T, Error> {
        match self.0 {
            EnvelopeData::Success { result, .. } => Ok(result),
            EnvelopeData::Failure { error, .. } => Err(error),
        }
    }
}
fn account_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<usize>, D::Error> {
    let limit = Option::<usize>::deserialize(deserializer)?;
    if limit.is_some_and(|limit| !(1..=256).contains(&limit)) {
        return Err(serde::de::Error::custom("invalid account limit"));
    }
    Ok(limit)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum OperationResult {
    Accounts(AccountDiscovery),
    Capabilities(Capabilities),
    Health(Health),
    Cancelled(Cancellation),
    Setup(Setup),
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cancellation {
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Unknown,
    Configured,
    Unavailable,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub alias: String,
    pub account_id: String,
    pub generation: u64,
    pub from_identities: Vec<String>,
    pub capabilities: Vec<String>,
    pub availability: Availability,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountDiscovery {
    pub accounts: Vec<Account>,
    pub complete: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub operations: Vec<String>,
    pub permissions: Vec<crate::policy::Permission>,
    pub health: Health,
    pub capacity: Capacity,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub status: String,
    pub grant: String,
    pub accounts: Vec<AccountHealth>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountHealth {
    pub account_id: String,
    pub generation: u64,
    pub availability: Availability,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub installation_id: String,
    pub configuration_revision: String,
    pub accounts: usize,
    pub grants: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub per_process: ProcessCapacity,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessCapacity {
    pub active_requests: u64,
    pub queued_requests: u64,
    pub buffered_bytes: u64,
}
