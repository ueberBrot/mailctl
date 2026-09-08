//! Executable lifecycle and presentation around the embedded application contract.
mod arguments;
mod configuration;
mod diagnostics;
#[cfg(feature = "mcp")]
mod mcp;
#[cfg(feature = "mcp")]
mod mcp_transport;

use crate::{
    domain::{Envelope, Error, ErrorCode, OperationResult},
    service::Service,
};
use arguments::{Action, Invocation};
use clap::FromArgMatches;
use diagnostics::{Color, LogFormat, Options};
use std::{io::Write, process::ExitCode, time::Duration};

#[derive(Clone, Copy)]
pub enum Executable {
    #[cfg(feature = "cli")]
    Cli,
    #[cfg(feature = "mcp")]
    Mcp,
}
impl Executable {
    fn is_mcp(self) -> bool {
        match self {
            #[cfg(feature = "cli")]
            Self::Cli => false,
            #[cfg(feature = "mcp")]
            Self::Mcp => true,
        }
    }
}

pub fn run(executable: Executable) -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    let command = Invocation::command(executable);
    let preliminary = command
        .clone()
        .ignore_errors(true)
        .try_get_matches_from(&arguments)
        .ok();
    let options = preliminary
        .as_ref()
        .and_then(|matches| Options::from_arg_matches(matches).ok())
        .unwrap_or_default();
    let administration = preliminary
        .as_ref()
        .is_some_and(|matches| matches!(matches.subcommand_name(), Some("setup" | "credential")));
    let serving = executable.is_mcp() && !administration;
    let json = !serving
        && preliminary
            .as_ref()
            .is_some_and(|matches| matches.get_flag("json"));
    let initialized = options.initialize(json || serving);
    if initialized.is_err() {
        let _ = Options {
            log_format: LogFormat::Json,
            ..options
        }
        .initialize(true);
    }
    let invocation = command
        .try_get_matches_from(arguments)
        .and_then(|matches| Invocation::from_matches(executable, &matches));
    if let Err(error) = &invocation
        && matches!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
        )
    {
        return ExitCode::from(if error.print().is_ok() { 0 } else { 8 });
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            diagnostics::result("", Some(&Error::new(ErrorCode::InternalError)));
            return ExitCode::from(8);
        }
    };
    let code = runtime.block_on(async {
        let result = match initialized {
            Err(error) => Err(error),
            Ok(()) => match invocation {
                Ok(invocation) => {
                    diagnostics::started();
                    let result = execute(invocation).await;
                    diagnostics::stopped();
                    result
                }
                Err(_) => Err(Error::new(ErrorCode::InvalidRequest)),
            },
        };
        match result {
            Ok(code) => code,
            Err(error) => report(json, options.color, Err(error), None, 30).await,
        }
    });
    // STDIO workers may remain blocked after cancellation; process exit releases their leases.
    runtime.shutdown_timeout(Duration::from_millis(250));
    code.into()
}

async fn execute(invocation: Invocation) -> Result<u8, Error> {
    let Invocation { options, action } = invocation;
    if matches!(action, Action::Credential) {
        return Err(Error::new(ErrorCode::UnsupportedCapability));
    }
    if let Action::Setup(args) = action {
        let json = options.json;
        let color = options.diagnostics.color;
        let setup = tokio::task::spawn_blocking(move || {
            configuration::setup(&options.config, args, &options.accounts, json)
        })
        .await
        .map_err(|_| Error::new(ErrorCode::InternalError))??;
        return Ok(report(json, color, Ok(OperationResult::Setup(setup)), None, 30).await);
    }
    let config = configuration::load(&options.config)?;
    #[cfg(feature = "cli")]
    let deadline = config.limits.operation_seconds;
    let selected = options
        .grant
        .as_deref()
        .unwrap_or(&config.default_grant)
        .to_owned();
    #[allow(unused_mut)]
    let mut narrowing = options.narrowing();
    #[cfg(feature = "mcp")]
    if let Action::Mcp {
        use_configured_grant,
    } = action
    {
        if options.json {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        narrowing.read_only |= !use_configured_grant;
    }
    let shutdown = termination_signal()?;
    tokio::pin!(shutdown);
    let initialization =
        tokio::task::spawn_blocking(move || configuration::open(&options.config, config));
    let service = tokio::select! {
        _ = &mut shutdown => return Err(Error::new(ErrorCode::Cancelled)),
        result = initialization => result.map_err(|_| Error::new(ErrorCode::InternalError))??,
    };
    let context = service.context(&selected, &narrowing)?;
    match action {
        #[cfg(feature = "mcp")]
        Action::Mcp { .. } => {
            tokio::select! {
                _ = &mut shutdown => Err(Error::new(ErrorCode::Cancelled)),
                result = mcp::run(service, context) => result.map(|()| 0),
            }
        }
        #[cfg(feature = "cli")]
        Action::Email(operation) => {
            let result = service.execute(&context, operation);
            Ok(report(
                options.json,
                options.diagnostics.color,
                result,
                Some(service),
                deadline,
            )
            .await)
        }
        Action::Setup(_) | Action::Credential => unreachable!(),
    }
}

fn termination_signal() -> Result<impl Future<Output = ()>, Error> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt =
            signal(SignalKind::interrupt()).map_err(|_| Error::new(ErrorCode::InternalError))?;
        let mut terminate =
            signal(SignalKind::terminate()).map_err(|_| Error::new(ErrorCode::InternalError))?;
        Ok(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

async fn report(
    json: bool,
    color: Color,
    result: Result<OperationResult, Error>,
    owner: Option<Service>,
    seconds: usize,
) -> u8 {
    let envelope = Envelope::from_result(uuid::Uuid::new_v4().to_string(), result);
    diagnostics::result(envelope.request_id(), envelope.error());
    let code = envelope.error().map_or(0, Error::exit_code);
    let output = if json {
        serde_json::to_string(&envelope)
    } else {
        match envelope.result() {
            Some(result) => serde_json::to_string_pretty(result).map(|text| escape_bidi(&text)),
            None => return code,
        }
    };
    let Ok(text) = output else {
        return 8;
    };
    let write = tokio::task::spawn_blocking(move || {
        let _owner = owner;
        writeln!(color.stdout(json), "{text}")
    });
    match tokio::time::timeout(Duration::from_secs(seconds as u64), write).await {
        Ok(Ok(Ok(()))) => code,
        Err(_) => 5,
        _ => 8,
    }
}

fn escape_bidi(text: &str) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => {
                let _ = write!(output, "\\u{{{:04x}}}", character as u32);
            }
            _ => output.push(character),
        }
    }
    output
}
