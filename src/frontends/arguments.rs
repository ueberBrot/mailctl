//! Independent command trees sharing startup and operator arguments.
use super::{Executable, diagnostics};
#[cfg(feature = "cli")]
use crate::domain::{
    ListAccountsInput, ListMailboxesInput, Operation, SearchCriteria, SearchMessagesInput,
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
    Message(Message),
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
#[derive(Subcommand)]
enum Message {
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
    crate::encoding::validate_json_depth(value.as_bytes(), 32)
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
