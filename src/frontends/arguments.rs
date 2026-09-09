//! Independent command trees sharing startup and operator arguments.
use super::{Executable, diagnostics};
#[cfg(feature = "cli")]
use crate::domain::{ListAccountsInput, Operation};
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
    Account(Account),
    #[command(subcommand)]
    Capability(Capability),
    #[command(flatten)]
    Administration(Administration),
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
