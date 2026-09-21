//! Executable lifecycle and presentation around the embedded application contract.
mod application;
mod arguments;
mod configuration;
mod credentials;
mod diagnostics;
#[cfg(feature = "mcp")]
mod mcp;
#[cfg(feature = "mcp")]
mod mcp_transport;
mod presentation;

use crate::{
    domain::{Error, ErrorCode, OperationResult},
    policy::Narrowing,
};
use application::Application;
use arguments::{Action, Invocation};
use clap::FromArgMatches;
use diagnostics::{Color, LogFormat, Options, Request};
use std::{io::Write, process::ExitCode, time::Duration};
use tracing::Instrument;

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
    run_with_environment(
        executable,
        std::sync::Arc::new(crate::host::NativeEnvironment),
    )
}

/// Run the shared executable lifecycle with explicitly supplied host dependencies.
pub fn run_with_environment(
    executable: Executable,
    host: std::sync::Arc<dyn crate::host::HostEnvironment>,
) -> ExitCode {
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
    let administration = preliminary.as_ref().is_some_and(|matches| {
        matches!(
            matches.subcommand_name(),
            Some("setup" | "credential" | "doctor")
        )
    });
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
    let request = Request::new();
    let code = runtime.block_on(
        async {
            let result = match initialized {
                Err(error) => Err(error),
                Ok(()) => match invocation {
                    Ok(invocation) => {
                        diagnostics::started();
                        let result = execute(invocation, host, &request).await;
                        diagnostics::stopped();
                        result
                    }
                    Err(_) => Err(Error::new(ErrorCode::InvalidRequest)),
                },
            };
            match result {
                Ok(code) => code,
                Err(error) => report(&request, json, options.color, Err(error), (), 30).await,
            }
        }
        .instrument(request.span()),
    );
    // STDIO workers may remain blocked after cancellation; process exit releases their leases.
    runtime.shutdown_timeout(Duration::from_millis(250));
    code.into()
}

async fn execute(
    invocation: Invocation,
    host: std::sync::Arc<dyn crate::host::HostEnvironment>,
    request: &Request,
) -> Result<u8, Error> {
    let Invocation {
        mut options,
        action,
    } = invocation;
    #[cfg(target_os = "macos")]
    if options.isolated {
        return execute_isolated(options, action, request).await;
    }
    if let Action::Setup(args) = action {
        let json = options.json;
        let color = options.diagnostics.color;
        let span = tracing::Span::current();
        let setup = tokio::task::spawn_blocking(move || {
            span.in_scope(|| configuration::setup(&options.config, args, &options.accounts, json))
        })
        .await
        .map_err(|_| Error::new(ErrorCode::InternalError))??;
        return Ok(report(
            request,
            json,
            color,
            Ok(OperationResult::Setup(setup)),
            (),
            30,
        )
        .await);
    }
    let config = configuration::load(&options.config)?;
    #[cfg(feature = "cli")]
    let export_roots = match action {
        Action::Export { .. } => config.export_roots.clone(),
        _ => Vec::new(),
    };
    let deadline = config.limits.operation_seconds;
    let selected = options
        .grant
        .take()
        .unwrap_or_else(|| config.default_grant.clone());
    let narrowing = invocation_narrowing(&mut options, &action)?;
    let shutdown = termination_signal()?;
    tokio::pin!(shutdown);
    let config_path = options.config.clone();
    let span = tracing::Span::current();
    let initialization = tokio::task::spawn_blocking(move || {
        span.in_scope(|| configuration::open(&config_path, config))
    });
    let service = tokio::select! {
        _ = &mut shutdown => return Err(Error::new(ErrorCode::Cancelled)),
        result = initialization => result.map_err(|_| Error::new(ErrorCode::InternalError))??,
    };
    let service = service.with_environment(host);
    if let Action::Credential(command) = action {
        let (status, service) = tokio::select! {
            _ = &mut shutdown => return Err(Error::new(ErrorCode::Cancelled)),
            result = tokio::time::timeout(
                Duration::from_secs(deadline as u64),
                credentials::execute(
                    service,
                    narrowing.accounts.as_deref().unwrap_or_default(),
                    command,
                    options.json,
                ),
            ) => result.map_err(|_| Error::new(ErrorCode::Timeout))??,
        };
        return Ok(report(
            request,
            options.json,
            options.diagnostics.color,
            Ok(OperationResult::Credential(status)),
            Some(service),
            deadline,
        )
        .await);
    }
    let context = service.context(&selected, &narrowing)?;
    execute_application(
        request,
        options,
        action,
        Application::Embedded {
            service: Box::new(service),
            context,
        },
        #[cfg(feature = "cli")]
        export_roots,
    )
    .await
}

#[cfg(target_os = "macos")]
async fn execute_isolated(
    mut options: arguments::Options,
    action: Action,
    request: &Request,
) -> Result<u8, Error> {
    #[cfg(feature = "cli")]
    if matches!(action, Action::Export { .. }) {
        return Err(Error::new(ErrorCode::UnsupportedCapability));
    }
    if matches!(action, Action::Setup(_) | Action::Credential(_)) {
        return Err(Error::new(ErrorCode::InvalidRequest));
    }
    let narrowing = invocation_narrowing(&mut options, &action)?;
    let shutdown = termination_signal()?;
    tokio::pin!(shutdown);
    let client = tokio::select! {
        _ = &mut shutdown => return Err(Error::new(ErrorCode::Cancelled)),
        result = crate::isolation::Client::connect(narrowing) => result?,
    };
    execute_application(
        request,
        options,
        action,
        Application::Isolated(Box::new(client)),
        #[cfg(feature = "cli")]
        Vec::new(),
    )
    .await
}

fn invocation_narrowing(
    options: &mut arguments::Options,
    _action: &Action,
) -> Result<Narrowing, Error> {
    #[allow(unused_mut, reason = "MCP builds apply additional read-only narrowing")]
    let mut narrowing = Narrowing {
        read_only: options.read_only,
        accounts: (!options.accounts.is_empty()).then(|| std::mem::take(&mut options.accounts)),
    };
    #[cfg(feature = "mcp")]
    if let Action::Mcp {
        use_configured_grant,
    } = _action
    {
        if options.json {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        narrowing.read_only |= !*use_configured_grant;
    }
    Ok(narrowing)
}

async fn execute_application(
    request: &Request,
    options: arguments::Options,
    action: Action,
    application: Application,
    #[cfg(feature = "cli")] export_roots: Vec<std::path::PathBuf>,
) -> Result<u8, Error> {
    let deadline = application.limits()?.operation_seconds;
    let shutdown = termination_signal()?;
    tokio::pin!(shutdown);
    #[cfg(feature = "mcp")]
    if matches!(action, Action::Mcp { .. }) {
        return tokio::select! {
            _ = &mut shutdown => Err(Error::new(ErrorCode::Cancelled)),
            result = mcp::run(application) => result.map(|()| 0),
        };
    }
    #[cfg(feature = "cli")]
    let mut export = match &action {
        Action::Export { root, name, .. } => Some(crate::export::ExportWriter::create(
            &export_roots,
            root,
            name,
            application.limits()?.attachment_decoded_bytes,
        )?),
        _ => None,
    };
    let operation = async {
        match action {
            #[cfg(feature = "cli")]
            Action::Export { attachment, .. } => {
                application
                    .export_attachment(
                        attachment,
                        export.as_mut().expect("export writer initialized"),
                    )
                    .await
            }
            Action::Doctor { check_account } => application.doctor(check_account).await,
            #[cfg(feature = "cli")]
            Action::Email(crate::domain::Operation::GetAttachment(input)) => {
                application.download_attachment(input).await
            }
            #[cfg(feature = "cli")]
            Action::Email(operation) => application.execute(operation).await,
            #[cfg(feature = "mcp")]
            Action::Mcp { .. } => unreachable!(),
            Action::Setup(_) | Action::Credential(_) => unreachable!(),
        }
    };
    let result = tokio::select! {
        _ = &mut shutdown => Err(Error::new(ErrorCode::Cancelled)),
        result = tokio::time::timeout(Duration::from_secs(deadline as u64), operation) =>
            result.map_err(|_| Error::new(ErrorCode::Timeout)).flatten(),
    };
    #[cfg(feature = "cli")]
    let result = export
        .as_mut()
        .map_or(Ok(()), crate::export::ExportWriter::abort)
        .and(result);
    Ok(report(
        request,
        options.json,
        options.diagnostics.color,
        result,
        application,
        deadline,
    )
    .await)
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

async fn report<O: Send + 'static>(
    request: &Request,
    json: bool,
    color: Color,
    result: Result<OperationResult, Error>,
    owner: O,
    seconds: usize,
) -> u8 {
    let envelope = request.envelope(result);
    let error = envelope.error().or_else(|| match envelope.result() {
        Some(OperationResult::Doctor(doctor)) => doctor.accounts.iter().find_map(|account| {
            match &account.authentication.as_ref()?.outcome {
                crate::domain::AuthenticationOutcome::Authenticated => None,
                crate::domain::AuthenticationOutcome::Failed { error } => Some(error),
            }
        }),
        _ => None,
    });
    diagnostics::result(envelope.request_id(), error);
    let code = error.map_or(0, Error::exit_code);
    let output = if json {
        serde_json::to_string(&envelope)
    } else {
        match envelope.result() {
            Some(result) => presentation::human(result),
            None => return code,
        }
    };
    let Ok(text) = output else {
        return 8;
    };
    let write = tokio::task::spawn_blocking(move || {
        let _owner = owner;
        // Terminal filtering strips valid JSON string data such as DELETE.
        if json {
            return writeln!(std::io::stdout().lock(), "{text}");
        }
        let heading = anstyle::Style::new().bold();
        writeln!(color.human_stdout(), "{heading}Result{heading:#}\n{text}")
    });
    match tokio::time::timeout(Duration::from_secs(seconds as u64), write).await {
        Ok(Ok(Ok(()))) => code,
        Err(_) => 5,
        _ => 8,
    }
}
