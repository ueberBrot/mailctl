//! Independent command trees sharing startup and operator arguments.
use super::{Executable, diagnostics};
#[cfg(feature = "cli")]
use crate::domain::{
    GetMessageInput, ListAccountsInput, ListMailboxesInput, Operation, SearchCriteria,
    SearchMessagesInput,
};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(super) struct Options {
    /// Use the separately provisioned local service and its operator-assigned access grant.
    #[cfg(target_os = "macos")]
    #[arg(long, global = true, conflicts_with_all = ["config", "grant"])]
    pub isolated: bool,
    #[arg(long, global = true, default_value_os_t = super::configuration::default_path())]
    pub config: PathBuf,
    #[arg(long, global = true)]
    pub grant: Option<String>,
    #[arg(long, global = true)]
    pub read_only: bool,
    #[arg(long = "account", global = true)]
    pub accounts: Vec<String>,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(flatten)]
    pub diagnostics: diagnostics::Options,
}
#[derive(Subcommand)]
enum Administration {
    /// Validate configuration, or add/update one named account without replacing others.
    Setup(Setup),
    #[command(subcommand)]
    Credential(Credential),
    /// Inspect local readiness; authenticate only with --check-account.
    Doctor {
        #[arg(long)]
        check_account: bool,
    },
}
#[derive(Args, Default)]
pub(super) struct Setup {
    #[arg(long)]
    pub alias: Option<String>,
    #[arg(long, requires = "alias")]
    pub server: Option<String>,
    #[arg(long, requires = "alias")]
    pub username: Option<String>,
}
#[derive(Subcommand)]
pub(super) enum Credential {
    Set,
    Delete,
    Status,
}

#[cfg(feature = "cli")]
#[derive(Parser)]
#[command(
    name = "mailctl",
    version,
    about = "Controlled access to configured email accounts."
)]
struct Mailctl {
    #[command(flatten)]
    options: Options,
    #[command(subcommand)]
    command: Email,
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Email {
    #[command(subcommand)]
    Draft(Draft),
    #[command(subcommand)]
    Message(Message),
    #[command(subcommand)]
    Attachment(Attachment),
    #[command(subcommand)]
    Mailbox(Mailbox),
    #[command(subcommand)]
    Account(Account),
    #[command(subcommand)]
    Capability(Capability),
    #[command(flatten)]
    Administration(Administration),
}
#[cfg(feature = "cli")]
#[derive(Args)]
pub(super) struct DraftIdentity {
    #[arg(long)]
    mailbox: String,
    #[arg(long)]
    account_id: uuid::Uuid,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=i64::MAX as u64))]
    account_generation: u64,
    #[arg(long)]
    operation_id: uuid::Uuid,
}
#[cfg(feature = "cli")]
impl DraftIdentity {
    pub(super) fn save(self, draft: crate::domain::DraftContent) -> Operation {
        Operation::SaveDraft(crate::domain::SaveDraftInput {
            mailbox: self.mailbox,
            account_id: self.account_id,
            account_generation: self.account_generation,
            operation_id: self.operation_id,
            draft: Box::new(draft),
        })
    }
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Draft {
    /// Record a prepared, undispatched draft. Retain the identity and original input.
    Save {
        #[command(flatten)]
        identity: DraftIdentity,
        /// JSON composition file with from, to, cc, bcc, subject, body and reply metadata.
        #[arg(long)]
        input: PathBuf,
    },
    /// Inspect durable status without contacting the provider.
    Status {
        #[command(flatten)]
        identity: DraftIdentity,
        /// Request reconciliation (not yet supported).
        #[arg(long)]
        reconcile: bool,
    },
}
#[cfg(feature = "cli")]
pub(super) fn draft_content(
    path: &std::path::Path,
    maximum: usize,
    nesting: usize,
) -> Result<crate::domain::DraftContent, crate::domain::Error> {
    use std::io::Read;
    let invalid = || crate::domain::Error::new(crate::domain::ErrorCode::InvalidRequest);
    let oversized = || crate::domain::Error::new(crate::domain::ErrorCode::ResponseTooLarge);
    if !std::fs::metadata(path).map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let file = std::fs::File::open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    if metadata.len() > maximum as u64 {
        return Err(oversized());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > maximum {
        return Err(oversized());
    }
    crate::encoding::validate_json_bounds(&bytes, nesting, 4096).map_err(|_| invalid())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Attachment {
    /// Save an attachment under a configured export root (embedded macOS only).
    Export {
        #[arg(long)]
        attachment: String,
        #[arg(long)]
        root: PathBuf,
        /// Safe basename; defaults to attachment.bin.
        #[arg(long, default_value = "attachment.bin")]
        name: String,
    },
    /// List attachment metadata without retrieving payloads.
    List {
        #[arg(long)]
        message: String,
    },
    /// Retrieve an attachment in one invocation as a bounded base64 result.
    Get {
        #[arg(long)]
        attachment: String,
    },
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Message {
    /// Read bounded selected text from a reusable message reference.
    Get {
        #[arg(long)]
        message: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Search a mailbox with AND-only criteria and descending-UID continuation.
    Search {
        #[arg(long)]
        mailbox: String,
        /// JSON array of typed predicates; repeated fields remain AND terms.
        #[arg(long, default_value = "[]", value_parser = search_criteria)]
        criteria: SearchCriteria,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=200))]
        limit: Option<u16>,
        #[arg(long)]
        cursor: Option<String>,
    },
}
#[cfg(feature = "cli")]
fn search_criteria(value: &str) -> Result<SearchCriteria, &'static str> {
    if value.len() > 1024 * 1024 {
        return Err("Search criteria exceed the input limit");
    }
    crate::encoding::validate_json_bounds(value.as_bytes(), 32, usize::MAX)
        .map_err(|_| "Invalid search criteria")?;
    serde_json::from_str(value).map_err(|_| "Invalid search criteria")
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Account {
    List {
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
        limit: Option<u16>,
    },
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Mailbox {
    /// List approved mailboxes, or resolve a previously returned reference.
    List {
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: Option<u16>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        reference: Option<String>,
    },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Capability {
    Show,
}

#[cfg(feature = "mcp")]
#[derive(Parser)]
#[command(
    name = "mailctl-mcp",
    version,
    about = "STDIO email tools with shared account setup."
)]
struct Mcp {
    #[command(flatten)]
    options: Options,
    #[arg(long, conflicts_with = "read_only")]
    use_configured_grant: bool,
    #[command(subcommand)]
    administration: Option<Administration>,
}

pub(super) struct Invocation {
    pub options: Options,
    pub action: Action,
}
pub(super) enum Action {
    #[cfg(feature = "cli")]
    DraftSave {
        identity: DraftIdentity,
        input: PathBuf,
    },
    #[cfg(feature = "cli")]
    Export {
        attachment: String,
        root: PathBuf,
        name: String,
    },
    #[cfg(feature = "cli")]
    Email(Operation),
    #[cfg(feature = "mcp")]
    Mcp {
        use_configured_grant: bool,
    },
    Setup(Setup),
    Credential(Credential),
    Doctor {
        check_account: bool,
    },
}
impl From<Administration> for Action {
    fn from(value: Administration) -> Self {
        match value {
            Administration::Setup(args) => Self::Setup(args),
            Administration::Credential(command) => Self::Credential(command),
            Administration::Doctor { check_account } => Self::Doctor { check_account },
        }
    }
}
impl Invocation {
    pub fn command(executable: Executable) -> clap::Command {
        match executable {
            #[cfg(feature = "cli")]
            Executable::Cli => Mailctl::command(),
            #[cfg(feature = "mcp")]
            Executable::Mcp => Mcp::command(),
        }
    }
    pub fn from_matches(
        executable: Executable,
        matches: &clap::ArgMatches,
    ) -> Result<Self, clap::Error> {
        match executable {
            #[cfg(feature = "cli")]
            Executable::Cli => {
                let parsed = Mailctl::from_arg_matches(matches)?;
                let action = match parsed.command {
                    Email::Draft(Draft::Save { identity, input }) => {
                        Action::DraftSave { identity, input }
                    }
                    Email::Draft(Draft::Status {
                        identity,
                        reconcile,
                    }) => Action::Email(Operation::DraftStatus(crate::domain::DraftStatusInput {
                        mailbox: identity.mailbox,
                        account_id: identity.account_id,
                        account_generation: identity.account_generation,
                        operation_id: identity.operation_id,
                        reconcile,
                    })),
                    Email::Attachment(Attachment::Export {
                        attachment,
                        root,
                        name,
                    }) => Action::Export {
                        attachment,
                        root,
                        name,
                    },
                    Email::Attachment(Attachment::List { message }) => Action::Email(
                        Operation::ListAttachments(crate::domain::ListAttachmentsInput { message }),
                    ),
                    Email::Attachment(Attachment::Get { attachment }) => Action::Email(
                        Operation::GetAttachment(crate::domain::GetAttachmentInput::Start(
                            crate::domain::AttachmentStart { attachment },
                        )),
                    ),
                    Email::Message(Message::Get { message, cursor }) => {
                        Action::Email(Operation::GetMessage(GetMessageInput { message, cursor }))
                    }
                    Email::Message(Message::Search {
                        mailbox,
                        criteria,
                        limit,
                        cursor,
                    }) => Action::Email(Operation::SearchMessages(SearchMessagesInput {
                        mailbox,
                        criteria,
                        limit: limit.map(usize::from),
                        cursor,
                    })),
                    Email::Mailbox(Mailbox::List {
                        limit,
                        cursor,
                        reference,
                    }) => Action::Email(Operation::ListMailboxes(ListMailboxesInput {
                        account: None,
                        limit: limit.map(usize::from),
                        cursor,
                        reference,
                    })),
                    Email::Account(Account::List { limit }) => {
                        Action::Email(Operation::ListAccounts(ListAccountsInput {
                            limit: limit.map(usize::from),
                        }))
                    }
                    Email::Capability(Capability::Show) => Action::Email(Operation::Capabilities),
                    Email::Administration(admin) => admin.into(),
                };
                Ok(Self {
                    options: parsed.options,
                    action,
                })
            }
            #[cfg(feature = "mcp")]
            Executable::Mcp => {
                let parsed = Mcp::from_arg_matches(matches)?;
                let action = parsed
                    .administration
                    .map(Action::from)
                    .unwrap_or(Action::Mcp {
                        use_configured_grant: parsed.use_configured_grant,
                    });
                Ok(Self {
                    options: parsed.options,
                    action,
                })
            }
        }
    }
}
