//! CLI and MCP mapping onto the broker's application contract.
mod mcp;
mod mcp_transport;

use crate::{
    config::Config,
    domain::{Envelope, Error, ErrorCode, ListAccountsInput, Operation},
    ipc::{Broker, Client},
    policy::Narrowing,
};
use clap::{Arg, ArgAction, Command};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

fn command(name: &'static str, description: &'static str) -> Command {
    let base = Command::new(name)
        .version(env!("CARGO_PKG_VERSION"))
        .about(description);
    if name == "maild" {
        return base.arg(Arg::new("config").long("config").required(true));
    }
    if name == "mail-admin" {
        return base;
    }
    let base = base
        .arg(
            Arg::new("endpoint")
                .long("endpoint")
                .global(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("broker-uid")
                .long("broker-uid")
                .global(true)
                .value_parser(clap::value_parser!(u32)),
        )
        .arg(
            Arg::new("read-only")
                .long("read-only")
                .global(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("account")
                .long("account")
                .global(true)
                .action(ArgAction::Append),
        );
    if name == "mail-mcp" {
        return base.arg(
            Arg::new("use-endpoint-grant")
                .long("use-endpoint-grant")
                .conflicts_with("read-only")
                .action(ArgAction::SetTrue),
        );
    }
    base.arg(
        Arg::new("json")
            .long("json")
            .global(true)
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("log-format")
            .long("log-format")
            .global(true)
            .default_value("off")
            .value_parser(["off", "json", "compact"]),
    )
    .subcommand_required(true)
    .subcommand(
        Command::new("account")
            .subcommand_required(true)
            .subcommand(
                Command::new("list").arg(
                    Arg::new("limit")
                        .long("limit")
                        .value_parser(clap::value_parser!(usize)),
                ),
            ),
    )
    .subcommand(
        Command::new("capability")
            .subcommand_required(true)
            .subcommand(Command::new("show")),
    )
    .subcommand(Command::new("doctor"))
}

/// Run a machine-safe executable; all failures use reviewed error categories.
pub fn run(name: &'static str, description: &'static str) {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("{{\"event\":\"panic\",\"code\":\"internal_error\"}}")
    }));
    let args: Vec<_> = std::env::args_os().collect();
    let json = name == "mailctl" && args.iter().any(|arg| arg == "--json");
    let matches = match command(name, description).try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return;
        }
        Err(_) => {
            std::process::exit(
                report(name, json, Err(Error::new(ErrorCode::InvalidRequest))) as i32,
            );
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            std::process::exit(
                report(name, json, Err(Error::new(ErrorCode::InternalError))) as i32,
            );
        }
    };
    let result = runtime.block_on(async {
        if name == "maild" {
            let path = Path::new(
                matches
                    .get_one::<String>("config")
                    .expect("required config"),
            );
            let broker = Broker::bind(read_config(path)?)?;
            broker
                .run(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            return Ok(None);
        }
        if name == "mail-admin" {
            return Err(Error::new(ErrorCode::UnsupportedCapability));
        }
        if name == "mailctl"
            && json
            && matches
                .get_one::<String>("log-format")
                .is_some_and(|v| v == "compact")
        {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let endpoint = matches
            .get_one::<PathBuf>("endpoint")
            .ok_or_else(|| Error::new(ErrorCode::BrokerUnavailable))?;
        let uid = matches
            .get_one::<u32>("broker-uid")
            .copied()
            .unwrap_or_else(default_uid);
        let narrowing = Narrowing {
            read_only: matches.get_flag("read-only")
                || (name == "mail-mcp" && !matches.get_flag("use-endpoint-grant")),
            accounts: matches
                .get_many::<String>("account")
                .map(|values| values.cloned().collect()),
        };
        let mut client = Client::connect(endpoint, uid, narrowing).await?;
        if name == "mail-mcp" {
            mcp::run(client).await?;
            return Ok(None);
        }
        let operation = match matches.subcommand() {
            Some(("account", command)) => {
                let (_, list) = command.subcommand().expect("required subcommand");
                Operation::ListAccounts(ListAccountsInput {
                    limit: list.get_one::<usize>("limit").copied(),
                })
            }
            Some(("capability", _)) => Operation::Capabilities,
            Some(("doctor", _)) => Operation::Health,
            _ => return Err(Error::new(ErrorCode::InvalidRequest)),
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        Ok(Some(client.request(&request_id, operation).await?))
    });
    std::process::exit(report(name, json, result) as i32);
}

fn default_uid() -> u32 {
    #[cfg(unix)]
    {
        rustix::process::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn read_config(path: &Path) -> Result<Config, Error> {
    let invalid = || Error::new(ErrorCode::InvalidRequest);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != default_uid() || metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    let mut text = String::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| invalid())?;
    if text.len() > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    Config::parse(&text)
}

fn report(name: &str, json: bool, result: Result<Option<Envelope>, Error>) -> u8 {
    let envelope = match result {
        Ok(None) => return 0,
        Ok(Some(envelope)) => envelope,
        Err(error) => Envelope::from_result(uuid::Uuid::new_v4().to_string(), Err(error)),
    };
    let code = envelope.error.as_ref().map_or(0, Error::exit_code);
    if name == "mailctl" && json {
        if serde_json::to_writer(std::io::stdout().lock(), &envelope).is_err() {
            return 8;
        }
        if writeln!(std::io::stdout().lock()).is_err() {
            return 8;
        }
    } else if let Some(error) = envelope.error {
        eprintln!(
            "{{\"event\":\"operation_failed\",\"code\":{}}}",
            serde_json::to_string(&error.code).expect("error code")
        );
    } else if let Some(result) = envelope.result {
        let text = serde_json::to_string_pretty(&result).expect("domain result");
        let safe: String = text
            .chars()
            .flat_map(|c| {
                if matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                    format!("\\u{{{:04x}}}", c as u32)
                        .chars()
                        .collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect();
        if writeln!(std::io::stdout().lock(), "{safe}").is_err() {
            return 8;
        }
    }
    code
}
