//! Independent command trees sharing startup and operator arguments.
use super::{Executable, diagnostics};
#[cfg(feature = "cli")]
use crate::domain::{
    GetMessageInput, ListAccountsInput, ListMailboxesInput, Operation, SearchCriteria,
    SearchMessagesInput,
};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf};

/// Recover output controls even when another argument cannot be parsed.
pub(super) fn output_options(
    arguments: &[OsString],
    command: &clap::Command,
) -> (bool, diagnostics::Options) {
    use clap::ValueEnum;
    fn value_options(command: &clap::Command, names: &mut Vec<String>) {
        for argument in command.get_arguments() {
            if argument.get_action().takes_values()
                && let Some(name) = argument.get_long()
            {
                names.push(name.into());
            }
        }
        for child in command.get_subcommands() {
            value_options(child, names);
        }
    }
    let mut values = Vec::new();
    value_options(command, &mut values);
    let mut options = diagnostics::Options::default();
    let mut json = false;
    let mut arguments = arguments.iter().skip(1).peekable();
    while let Some(argument) = arguments.next() {
        let Some(text) = argument.to_str() else {
            continue;
        };
        if text == "--" {
            break;
        }
        let Some(option) = text.strip_prefix("--") else {
            continue;
        };
        let (name, attached) = option
            .split_once('=')
            .map_or((option, None), |(name, value)| (name, Some(value)));
        json |= name == "json" && attached.is_none();
        if !values.iter().any(|value| value == name) {
            continue;
        }
        let value = attached.or_else(|| {
            if arguments
                .peek()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with('-'))
            {
                None
            } else {
                arguments.next().and_then(|value| value.to_str())
            }
        });
        let Some(value) = value else { continue };
        match name {
            "log-format" => {
                if let Ok(format) = diagnostics::LogFormat::from_str(value, false) {
                    options.log_format = format;
                }
            }
            "log-level" => {
                if let Ok(level) = diagnostics::LogLevel::from_str(value, false) {
                    options.log_level = level;
                }
            }
            "color" => {
                if let Ok(color) = diagnostics::Color::from_str(value, false) {
                    options.color = color;
                }
            }
            _ => {}
        }
    }
    (json, options)
}

pub(super) fn argument_error(error: &clap::Error, command: &clap::Command) -> crate::domain::Error {
    use clap::error::{ContextKind, ErrorKind};
    fn known_flags(command: &clap::Command, flags: &mut Vec<String>) {
        flags.extend(
            command
                .get_arguments()
                .filter_map(|argument| argument.get_long().map(|name| format!("--{name}"))),
        );
        for child in command.get_subcommands() {
            known_flags(child, flags);
        }
    }
    let mut known = Vec::new();
    known_flags(command, &mut known);
    let flags = error
        .get(ContextKind::InvalidArg)
        .map_or_else(Vec::new, |value| {
            value
                .to_string()
                .split(|character: char| character.is_whitespace() || character == ',')
                .filter(|part| known.iter().any(|flag| flag == part))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
    let target = if flags.is_empty() {
        String::new()
    } else {
        format!(" for {}", flags.join(", "))
    };
    let detail = match error.kind() {
        ErrorKind::MissingRequiredArgument => format!(
            "Missing required argument{}",
            if flags.is_empty() {
                String::new()
            } else {
                format!(": {}", flags.join(", "))
            }
        ),
        ErrorKind::MissingSubcommand => "Choose a command".into(),
        ErrorKind::UnknownArgument => "Unknown option or unexpected argument".into(),
        ErrorKind::InvalidSubcommand => "Unknown command".into(),
        ErrorKind::ArgumentConflict => format!("Conflicting arguments{target}"),
        _ => format!("Invalid argument value{target}"),
    };
    let mut message = format!("{detail}; run this command with --help");
    if flags.iter().any(|flag| flag == "--criteria") {
        message.push_str(" or use schema search_messages for the predicate format");
    }
    crate::domain::Error {
        message,
        ..crate::domain::Error::new(crate::domain::ErrorCode::InvalidRequest)
    }
}

#[derive(Args)]
pub(super) struct Options {
    /// Use the separately provisioned local service and its operator-assigned access grant.
    #[cfg(target_os = "macos")]
    #[arg(long, global = true, conflicts_with_all = ["config", "grant"])]
    pub isolated: bool,
    /// Read this shared account configuration; setup initializes it explicitly.
    #[arg(long, global = true, default_value_os_t = super::configuration::default_path())]
    pub config: PathBuf,
    /// Select an operator-approved access grant; defaults to the configured grant.
    #[arg(long, global = true)]
    pub grant: Option<String>,
    /// Narrow the selected grant to reads; removes draft creation and history access.
    #[arg(long, global = true)]
    pub read_only: bool,
    /// Narrow accounts by exact alias; repeat to select more than one.
    #[arg(long = "account", global = true)]
    pub accounts: Vec<String>,
    /// Write one versioned JSON result to stdout; diagnostics remain on stderr.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(flatten)]
    pub diagnostics: diagnostics::Options,
}
#[derive(Subcommand)]
enum Administration {
    /// Read an offline workflow guide; available before setup.
    Guide {
        #[arg(default_value = "overview", value_parser = clap::builder::PossibleValuesParser::new(super::guidance::topics().iter().copied()))]
        topic: String,
    },
    /// Print a JSON input schema, including search predicates and draft_content.
    Schema {
        /// Core operation name, such as search_messages, get_message, or draft_content.
        operation: String,
    },
    /// Back up, restore, or verify installation history with all runtimes stopped.
    #[command(subcommand, long_about = STATE_RECOVERY_HELP)]
    State(State),
    /// Validate configuration, or add/update one named account without replacing others.
    ///
    /// New installations allow read-only access to every current and future folder.
    /// Existing explicit mailbox restrictions and credential references are preserved.
    /// Set nonempty exact-name mailbox lists in TOML to restrict account or grant scope.
    /// After editing configuration, run setup and restart long-running MCP processes.
    Setup(Setup),
    #[command(subcommand)]
    /// Provision or inspect credentials for one account outside the email tools.
    Credential(Credential),
    /// Inspect local readiness; authenticate only with --check-account.
    Doctor {
        #[arg(long)]
        check_account: bool,
    },
}
const STATE_RECOVERY_HELP: &str = "Back up, restore, or verify installation history.

Stop all CLI commands, MCP sessions, and isolated runtimes using this installation.
Maintenance requires exclusive access; rate_limited means a runtime still holds
its lease. Stop it and retry. Never remove live lock files.

BACKUP AND UPGRADE
  mailctl --config /absolute/config.toml state backup --destination /absolute/new-backup
  mailctl --config /absolute/config.toml state verify
The same commands work with mailctl-mcp. The backup destination must be new and
outside installation state. Keep the complete private snapshot, including its
manifest, unchanged. It preserves the journal, reference key, account history,
configuration, and reconstruction metadata. Back up credentials separately through
their configured source; callers must retain operation identities and draft input.
Run verify before replacing binaries. Unknown schemas and unsupported prepared
encoders fail safely. This unreleased package uses registry schema 2, journal
schema 3, and encoder 2; earlier development formats have no automatic migration.
Preserve incompatible files and use a compatible executable for offline inspection.

RESTORE
  mailctl --config /absolute/config.toml state restore --source /absolute/backup
First preserve the newer or damaged state, including SQLite WAL files, while all
runtimes are stopped. Restore requires the original installation and exact snapshot
configuration. It never recreates lost installation identity. Interrupted restore
keeps creation suspended; investigate the failure and repeat with a valid snapshot.
Successful restore also keeps creation suspended. Reads and known history remain
available; uncertain operations can be reconciled against their original targets.

OFFLINE RECOVERY
Account for every possible post-backup operation using surviving journals, caller
records, and independent provider evidence. Preserve all outcomes, original account
UUIDs and generations, mailbox and UIDVALIDITY, keys, hashes, frozen dates, From
selection, and encoder parameters. Never reconstruct these from current routing.
Any prepared or in_flight record that might have dispatched must become
outcome_unknown before creation resumes. Absence never proves no prior APPEND.
A coherent rollback of all local state cannot be detected without an external
witness. Checksums and successful verification do not prove history is current.

Only after complete, independently supported recovery: run state verify, record
the evidence outside the installation, restore drafts.initialized from ! to 2 if
needed, and durably remove drafts.suspended before restarting. Keep recovery copies.
If completeness cannot be established, keep creation suspended. There is no agent
journal editor or force-retry command. If every suspension write fails and files
are later replaced outside these commands, local state cannot prove that failure.

CAPACITY
journal_full rejects new operations while retaining existing status, reconciliation,
and healthy reads. Raise journal_records through normal exclusive configuration
update; never delete tombstones to free capacity. Investigate journal or writer
storage failures before resuming creation.";

#[derive(Subcommand)]
pub(super) enum State {
    Backup {
        #[arg(long)]
        destination: PathBuf,
    },
    Restore {
        #[arg(long)]
        source: PathBuf,
    },
    Verify,
}
#[derive(Args, Default)]
pub(super) struct Setup {
    /// Create or update this alias; use --account OLD to rename an existing account.
    #[arg(long)]
    pub alias: Option<String>,
    /// IMAP hostname; new accounts use implicit TLS on port 993.
    #[arg(long, requires = "alias")]
    pub server: Option<String>,
    /// IMAP authentication username, usually an email address.
    #[arg(long, requires = "alias")]
    pub username: Option<String>,
}
#[derive(Subcommand)]
pub(super) enum Credential {
    /// Prompt securely in an operator terminal; select --account when needed. Incompatible with --json.
    Set,
    /// Remove the credential from a mutable store for the selected account.
    Delete,
    /// Inspect provisioning and availability without exposing or authenticating the secret.
    Status,
}

#[cfg(feature = "cli")]
#[derive(Parser)]
#[command(
    name = "mailctl",
    version,
    about = "Controlled access to configured email accounts.",
    after_help = "Start with guide for workflows, or schema <operation> for JSON inputs. Both work before setup."
)]
struct Mailctl {
    #[command(flatten)]
    options: Options,
    /// Prompt for session credentials in this foreground invocation; incompatible with JSON.
    #[arg(long, global = true)]
    interactive: bool,
    #[command(subcommand)]
    command: Email,
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Email {
    /// Create unsent drafts and inspect their durable outcomes.
    #[command(subcommand)]
    Draft(Draft),
    /// Search message metadata and read selected body text.
    #[command(subcommand)]
    Message(Message),
    /// List, retrieve, or export attachments.
    #[command(subcommand)]
    Attachment(Attachment),
    /// Discover approved mailbox names and reusable references.
    #[command(subcommand)]
    Mailbox(Mailbox),
    /// Discover approved email accounts and their identities.
    #[command(subcommand)]
    Account(Account),
    /// Inspect effective permissions, limits, and readiness.
    #[command(subcommand)]
    Capability(Capability),
    #[command(flatten)]
    Administration(Administration),
}
#[cfg(feature = "cli")]
#[derive(Args)]
pub(super) struct DraftIdentity {
    /// Exact approved Drafts mailbox name; this is not a mailbox reference.
    #[arg(long)]
    mailbox: String,
    /// Original account UUID returned by account list.
    #[arg(long)]
    account_id: uuid::Uuid,
    /// Original account generation returned by account list.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=i64::MAX as u64))]
    account_generation: u64,
    /// Caller-generated UUID retained with the original composition for safe retries.
    #[arg(long)]
    operation_id: uuid::Uuid,
}
#[cfg(feature = "cli")]
impl DraftIdentity {
    pub(super) fn operation_details(&self) -> crate::domain::DraftOperationDetails {
        crate::domain::DraftOperationDetails {
            mailbox: self.mailbox.clone(),
            uid_validity: None,
            identity: crate::domain::DraftIdentity {
                account_id: self.account_id,
                account_generation: self.account_generation,
                operation_id: self.operation_id,
            },
        }
    }
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
    /// Create one unsent draft. Retain the identity and original input for retries.
    Save {
        #[command(flatten)]
        identity: DraftIdentity,
        /// JSON composition file; use schema draft_content for recipient and body fields.
        #[arg(long)]
        input: PathBuf,
    },
    /// Inspect durable status; optionally verify an uncertain draft with the provider.
    Status {
        #[command(flatten)]
        identity: DraftIdentity,
        /// Verify uncertain creation against the original target without another APPEND.
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
    /// Save an attachment under a configured export root on macOS or Windows.
    Export {
        /// Attachment reference returned by attachment list.
        #[arg(long)]
        attachment: String,
        /// Existing export root approved in configuration.
        #[arg(long)]
        root: PathBuf,
        /// Safe basename; defaults to attachment.bin.
        #[arg(long, default_value = "attachment.bin")]
        name: String,
    },
    /// List attachment metadata without retrieving payloads.
    List {
        /// Message reference returned by message search.
        #[arg(long)]
        message: String,
    },
    /// Retrieve an attachment in one invocation as a bounded base64 result.
    Get {
        /// Attachment reference returned by attachment list.
        #[arg(long)]
        attachment: String,
    },
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Message {
    /// Read bounded selected text from a reusable message reference.
    Get {
        /// Message reference returned by message search; copy it unchanged.
        #[arg(long)]
        message: String,
        /// next_cursor returned by the preceding text page of this same message.
        #[arg(long)]
        cursor: Option<String>,
        /// Maximum UTF-8 bytes in this text page; defaults to at most 8192.
        #[arg(long, value_parser = clap::value_parser!(u32).range(4..=2 * 1024 * 1024))]
        max_bytes: Option<u32>,
    },
    /// Search a mailbox with AND-only criteria and descending-UID continuation.
    #[command(
        after_help = "Example:\n  mailctl message search --mailbox \"$mailbox_reference\" --criteria '[{\"field\":\"subject\",\"value\":\"invoice\"}]' --limit 10 --json\n\nUse a reference returned by mailbox list. Read guide reading for discovery and continuation."
    )]
    Search {
        /// Mailbox reference returned by mailbox list; an exact folder name is insufficient.
        #[arg(long)]
        mailbox: String,
        /// JSON predicates, combined with AND; use schema search_messages for their format.
        #[arg(long, default_value = "[]", value_parser = search_criteria)]
        criteria: SearchCriteria,
        /// Requested page size, up to the effective search_page ceiling.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=200))]
        limit: Option<u16>,
        /// next_cursor from the same mailbox, criteria, and access grant.
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
    /// List authorized aliases, account UUIDs, and generations without authenticating.
    List {
        /// Maximum account rows, up to the effective accounts ceiling.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
        limit: Option<u16>,
    },
}
#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Mailbox {
    /// List approved mailboxes, or resolve a previously returned reference.
    List {
        /// Requested page size, up to the effective mailbox_page ceiling.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: Option<u16>,
        /// next_cursor from discovery under the same scope and inventory.
        #[arg(long)]
        cursor: Option<String>,
        /// Resolve one returned mailbox reference under the current access grant.
        #[arg(long)]
        reference: Option<String>,
    },
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
enum Capability {
    /// Report effective operations, permissions, limits, and readiness.
    Show,
}

#[cfg(feature = "mcp")]
#[derive(Parser)]
#[command(
    name = "mailctl-mcp",
    version,
    about = "STDIO email tools with shared account setup.",
    after_help = "Run without a command to serve MCP over STDIO. Use guide for workflows or schema <operation> for JSON inputs; both work before setup."
)]
struct Mcp {
    #[command(flatten)]
    options: Options,
    /// Enable draft permissions from the selected grant; serving is read-only by default.
    #[arg(long, conflicts_with = "read_only")]
    use_configured_grant: bool,
    #[command(subcommand)]
    administration: Option<Administration>,
}

pub(super) struct Invocation {
    pub options: Options,
    pub action: Action,
    pub interactive: bool,
}
pub(super) enum Action {
    Guide {
        topic: String,
    },
    Schema {
        operation: String,
    },
    State(State),
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
            Administration::Guide { topic } => Self::Guide { topic },
            Administration::Schema { operation } => Self::Schema { operation },
            Administration::State(command) => Self::State(command),
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
                    Email::Message(Message::Get {
                        message,
                        cursor,
                        max_bytes,
                    }) => Action::Email(Operation::GetMessage(GetMessageInput {
                        message,
                        cursor,
                        max_bytes: max_bytes.map(|value| value as usize),
                    })),
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
                    interactive: parsed.interactive,
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
                    interactive: false,
                })
            }
        }
    }
}
