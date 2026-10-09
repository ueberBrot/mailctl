//! Executable lifecycle and presentation around the embedded application contract.
mod application;
mod arguments;
mod configuration;
mod credentials;
mod diagnostics;
mod guidance;
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
    let (requested_json, options) = arguments::output_options(&arguments, &command);
    let administration = preliminary.as_ref().is_some_and(|matches| {
        matches!(
            matches.subcommand_name(),
            Some("setup" | "credential" | "doctor" | "state" | "guide" | "schema")
        )
    });
    let serving = executable.is_mcp() && !administration;
    let json = !serving && requested_json;
    let initialized = options.initialize(json || serving);
    if initialized.is_err() {
        let _ = Options {
            log_format: LogFormat::Json,
            ..options
        }
        .initialize(true);
    }
    let invocation = command
        .clone()
        .try_get_matches_from(arguments)
        .and_then(|matches| Invocation::from_matches(executable, matches));
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
                    Err(error) => Err(arguments::argument_error(&error, &command)),
                },
            };
            match result {
                Ok(code) => code,
                Err(error) if serving => {
                    diagnostics::result(request.id(), Some(&error));
                    error.exit_code()
                }
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
    match &invocation.action {
        Action::Guide { topic } => {
            let text = guidance::guide(topic)
                .ok_or_else(|| Error::invalid_input("Unknown guide topic; run guide --help"))?;
            return report_guidance(
                request,
                invocation.options.json,
                text.into(),
                serde_json::json!({"topic": topic, "text": text}),
            )
            .await;
        }
        Action::Schema { operation } => {
            let schema = guidance::schema(operation).ok_or_else(|| Error::invalid_input("Unknown input schema; use list_accounts, list_mailboxes, search_messages, get_message, list_attachments, get_attachment, save_draft, draft_status, draft_content, or capabilities"))?;
            let text = serde_json::to_string_pretty(&schema)
                .map_err(|_| Error::new(ErrorCode::InternalError))?;
            return report_guidance(request, invocation.options.json, text, schema).await;
        }
        _ => {}
    }
    if invocation.interactive {
        if invocation.options.json {
            return Err(crate::service::credential_error(
                crate::credentials::SourceError::InteractionRequired,
            ));
        }
        #[cfg(target_os = "macos")]
        if invocation.options.isolated {
            return Err(crate::service::credential_error(
                crate::credentials::SourceError::InteractionRequired,
            ));
        }
        #[cfg(all(any(unix, windows), feature = "cli"))]
        {
            let (host, prompts) = credentials::session::environment(host)
                .map_err(crate::service::credential_error)?;
            return tokio::select! {
                result = execute_inner(invocation, host, request) => result,
                () = prompts => unreachable!(),
            };
        }
        #[cfg(not(all(any(unix, windows), feature = "cli")))]
        return Err(crate::service::credential_error(
            crate::credentials::SourceError::InteractionRequired,
        ));
    }
    execute_inner(invocation, host, request).await
}

async fn execute_inner(
    invocation: Invocation,
    host: std::sync::Arc<dyn crate::host::HostEnvironment>,
    request: &Request,
) -> Result<u8, Error> {
    let Invocation {
        mut options,
        action,
        ..
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
    if let Action::State(command) = action {
        if options.read_only || options.grant.is_some() || !options.accounts.is_empty() {
            return Err(Error::new(ErrorCode::InvalidRequest));
        }
        let path = options.config;
        let result = tokio::task::spawn_blocking(move || {
            let config = configuration::load(&path)?;
            match command {
                arguments::State::Backup { destination } => {
                    crate::service::Service::backup(&config, &destination)
                }
                arguments::State::Restore { source } => {
                    crate::service::Service::restore(&config, &source)
                }
                arguments::State::Verify => crate::service::Service::verify_state(&config),
            }
        })
        .await
        .map_err(|_| Error::new(ErrorCode::InternalError))??;
        return Ok(report(
            request,
            options.json,
            options.diagnostics.color,
            Ok(OperationResult::StateMaintenance(result)),
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
    if matches!(
        action,
        Action::Setup(_) | Action::Credential(_) | Action::State(_)
    ) {
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

#[cfg_attr(
    not(feature = "mcp"),
    allow(
        clippy::unnecessary_wraps,
        reason = "MCP builds can reject invocation options through this shared interface"
    )
)]
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
    #[cfg(feature = "cli")]
    let mut draft_identity = None;
    #[cfg(not(feature = "cli"))]
    let draft_identity: Option<crate::domain::DraftOperationDetails> = None;
    let operation = async {
        match action {
            #[cfg(feature = "cli")]
            Action::DraftSave { identity, input } => {
                let limits = application.limits()?;
                // Charge JSON input/decoding, frozen MIME and the response independently.
                let maximum = (16 * 1024 * 1024)
                    .min(limits.envelope_bytes.saturating_sub(512))
                    .min(
                        limits
                            .buffered_bytes
                            .saturating_sub(limits.envelope_bytes + 2 * limits.draft_mime_bytes)
                            / 4,
                    );
                let nesting = limits.json_nesting;
                let draft = tokio::task::spawn_blocking(move || {
                    arguments::draft_content(&input, maximum, nesting)
                })
                .await
                .map_err(|_| Error::new(ErrorCode::InternalError))??;
                draft_identity = Some(identity.operation_details());
                application.execute(identity.save(draft)).await
            }
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
            Action::Setup(_)
            | Action::Credential(_)
            | Action::State(_)
            | Action::Guide { .. }
            | Action::Schema { .. } => unreachable!(),
        }
    };
    let result = tokio::select! {
        _ = &mut shutdown => Err(ErrorCode::Cancelled),
        result = tokio::time::timeout(Duration::from_secs(deadline as u64), operation) =>
            result.map_err(|_| ErrorCode::Timeout),
    }
    .unwrap_or_else(|code| {
        Err(match draft_identity {
            Some(identity) => Error::draft_outcome(ErrorCode::OutcomeUnknown, identity),
            None => Error::new(code),
        })
    });
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

#[cfg_attr(
    not(any(unix, windows)),
    allow(
        clippy::unnecessary_wraps,
        reason = "Native signal registration can fail through this shared interface"
    )
)]
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
    #[cfg(windows)]
    {
        let mut interrupt =
            tokio::signal::windows::ctrl_c().map_err(|_| Error::new(ErrorCode::InternalError))?;
        // Children can inherit Ctrl+C suppression; restore it after installing the handler.
        #[allow(
            unsafe_code,
            reason = "Restore Windows console signal delivery after registering the native listener"
        )]
        if unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0) } == 0 {
            return Err(Error::new(ErrorCode::InternalError));
        }
        Ok(async move {
            interrupt.recv().await;
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

struct ReportBuffer(Vec<u8>);
enum ReportOutput {
    Json(Vec<u8>),
    Human(String),
}
impl std::io::Write for ReportBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("Output unavailable"))?;
        if needed > self.0.capacity() {
            // A large string arrives in one write. Leave room for the envelope's
            // trailing fields so they do not double that whole allocation.
            // Small escaped writes still grow geometrically.
            let capacity = needed
                .saturating_add(1024)
                .max(self.0.capacity().saturating_mul(2));
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(std::io::Error::other)?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    let human_error = !json && envelope.error().is_some();
    let output = if json {
        // Keep one complete buffer so serializer failures leave stdout untouched.
        let mut output = ReportBuffer(Vec::with_capacity(1024));
        serde_json::to_writer(&mut output, &envelope)
            .ok()
            .map(|()| ReportOutput::Json(output.0))
    } else {
        match envelope.result() {
            Some(result) => presentation::human(result),
            None => presentation::human_error(envelope.error().expect("failure contains an error")),
        }
        .ok()
        .map(ReportOutput::Human)
    };
    let Some(output) = output else {
        return 8;
    };
    let write = tokio::task::spawn_blocking(move || {
        let _owner = owner;
        // Terminal filtering strips valid JSON string data such as DELETE.
        let text = match output {
            ReportOutput::Json(bytes) => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&bytes)?;
                return stdout.write_all(b"\n");
            }
            ReportOutput::Human(text) => text,
        };
        if human_error {
            return writeln!(std::io::stderr().lock(), "{text}");
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

async fn report_guidance(
    request: &Request,
    json: bool,
    text: String,
    result: serde_json::Value,
) -> Result<u8, Error> {
    let text = if json {
        serde_json::to_string(&request.envelope(Ok(result)))
            .map_err(|_| Error::new(ErrorCode::InternalError))?
    } else {
        text
    };
    diagnostics::result(request.id(), None);
    let write = tokio::task::spawn_blocking(move || writeln!(std::io::stdout().lock(), "{text}"));
    tokio::time::timeout(Duration::from_secs(30), write)
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))?
        .map_err(|_| Error::new(ErrorCode::InternalError))?
        .map_err(|_| Error::new(ErrorCode::InternalError))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BodyText, MessageBody};

    #[test]
    fn cli_json_buffers_keep_escaped_pages_with_geometric_growth() {
        let value = serde_json::json!({"text": "\u{1}\"\\é🦀\n".repeat(64 * 1024)});
        let expected = serde_json::to_vec(&value).unwrap();
        let mut output = ReportBuffer(Vec::with_capacity(1024));
        let allocation = allocation_counter::measure(|| {
            serde_json::to_writer(&mut output, &value).unwrap();
        });
        assert_eq!(output.0, expected);
        assert!(
            allocation.bytes_total < expected.len() as u64 * 4,
            "incremental escaped output must not repeatedly reserve its exact next length: {allocation:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_json_serializer_failures_leave_stdout_empty() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "frontends::tests::non_utf8_export_report_fixture",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "serializer failure fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.contains("1 passed; 0 failed"),
            "fixture did not run: {output}"
        );
        assert!(
            !output.contains("\"request_id\""),
            "failed serialization must not emit a partial JSON envelope: {output}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "child fixture for the serializer failure stdout regression"]
    fn non_utf8_export_report_fixture() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = OperationResult::Export(crate::domain::ExportReceipt {
            path: OsString::from_vec(b"/fixture/invalid-\xff".to_vec()).into(),
            filesystem: "fixture".into(),
            total_decoded_bytes: 0,
            sha256: "0".repeat(64),
        });
        assert_eq!(
            runtime.block_on(report(
                &Request::new(),
                true,
                Color::Never,
                Ok(result),
                (),
                30
            )),
            8
        );
    }

    #[test]
    #[ignore = "explicit stdout allocation probe; redirect stdout while running"]
    fn cli_json_reports_allocate_only_the_complete_output_buffer() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut excessive_allocation = Vec::new();
        for size in [64 * 1024, 256 * 1024, 2 * 1024 * 1024] {
            let result = OperationResult::Message(MessageBody {
                account_id: "account".into(),
                generation: 1,
                message_reference: "message".into(),
                body: BodyText {
                    text: "x".repeat(size),
                    selected_part: Some("1".into()),
                    source_media_type: Some("text/plain".into()),
                    converted: false,
                    replacements: false,
                    truncated: false,
                    empty_reason: None,
                    continuation_available: false,
                    next_cursor: None,
                },
            });
            let request = Request::new();
            let mut code = None;
            let started = std::time::Instant::now();
            let allocation = allocation_counter::measure(|| {
                code = Some(runtime.block_on(report(
                    &request,
                    true,
                    Color::Never,
                    Ok(result),
                    (),
                    30,
                )));
            });
            assert_eq!(code, Some(0));
            eprintln!(
                "CLI JSON bytes={size}, elapsed={:?}, {allocation:?}",
                started.elapsed()
            );
            if allocation.bytes_total > size as u64 + 64 * 1024
                || allocation.bytes_max > size as u64 + 64 * 1024
            {
                excessive_allocation.push((size, allocation));
            }
        }
        assert!(
            excessive_allocation.is_empty(),
            "CLI JSON presentation must not repeatedly grow its complete output buffer: {excessive_allocation:?}"
        );
    }
}
