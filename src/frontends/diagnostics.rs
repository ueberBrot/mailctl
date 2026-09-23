//! Reviewed tracing events and independent terminal-output controls.
use crate::domain::{Error, ErrorCode};
use clap::{Args, ValueEnum};
use std::io::IsTerminal;
use tracing_subscriber::{Layer, Registry, layer::SubscriberExt};

const TARGET: &str = "mailctl::diagnostic";

#[derive(Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(super) enum LogFormat {
    #[default]
    Auto,
    Off,
    Json,
    Compact,
}
#[derive(Clone, Copy, Default, ValueEnum)]
pub(super) enum LogLevel {
    Error,
    #[default]
    Warn,
    Info,
    Debug,
    Trace,
}
#[derive(Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(super) enum Color {
    #[default]
    Auto,
    Always,
    Never,
}
#[derive(Clone, Copy, Default, Args)]
#[group(id = "diagnostics")]
pub(super) struct Options {
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub log_format: LogFormat,
    #[arg(long, global = true, value_enum, default_value = "warn")]
    pub log_level: LogLevel,
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub color: Color,
}
impl Options {
    pub fn initialize(self, machine: bool) -> Result<(), Error> {
        let format = match (self.log_format, machine) {
            (LogFormat::Compact, true) => return Err(Error::new(ErrorCode::InvalidRequest)),
            (LogFormat::Auto, true) => LogFormat::Json,
            (LogFormat::Auto, false) => LogFormat::Compact,
            (format, _) => format,
        };
        let layer: Box<dyn Layer<Registry> + Send + Sync> = if format == LogFormat::Compact {
            tracing_subscriber::fmt::layer()
                .compact()
                .without_time()
                .with_target(false)
                .with_ansi(self.color.enabled(std::io::stderr().is_terminal()))
                .with_writer(std::io::stderr)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false)
                .without_time()
                .with_target(false)
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .boxed()
        };
        let level = match self.log_level {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        };
        let filter = tracing_subscriber::filter::filter_fn(move |metadata| {
            metadata.target() == TARGET
                && (metadata.is_span() || (format != LogFormat::Off && *metadata.level() <= level))
        });
        tracing::subscriber::set_global_default(
            Registry::default().with(layer.with_filter(filter)),
        )
        .map_err(|_| Error::new(ErrorCode::InternalError))?;
        std::panic::set_hook(Box::new(|info| {
            // Source location is trusted build metadata. Preserve its useful suffix.
            let location = info
                .location()
                .map(|location| format!("{}:{}", location.file(), location.line()))
                .unwrap_or_default();
            let start = location
                .char_indices()
                .rev()
                .nth(127)
                .map_or(0, |(index, _)| index);
            let location: String = location[start..].escape_default().take(256).collect();
            tracing::error!(target: TARGET, event = "panic", event_id = uuid::Uuid::new_v4().to_string().as_str(), location = location.as_str(), code = "internal_error");
        }));
        Ok(())
    }
}
impl Color {
    fn enabled(self, terminal: bool) -> bool {
        terminal
            && self != Self::Never
            && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
    }
    pub fn human_stdout(self) -> anstream::AutoStream<std::io::Stdout> {
        let choice = if self.enabled(std::io::stdout().is_terminal()) {
            anstream::ColorChoice::Always
        } else {
            anstream::ColorChoice::Never
        };
        anstream::AutoStream::new(std::io::stdout(), choice)
    }
}

/// One correlation identity created before dispatch and retained in the result.
pub(super) struct Request {
    id: String,
}
impl Request {
    pub fn new() -> Self {
        let request = Self {
            id: uuid::Uuid::new_v4().to_string(),
        };
        tracing::info!(target: TARGET, event = "request_started", request_id = request.id.as_str());
        request
    }
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(target: TARGET, "request", request_id = self.id.as_str())
    }
    pub fn envelope<T>(&self, result: Result<T, Error>) -> crate::domain::Envelope<T> {
        crate::domain::Envelope::from_result(self.id.clone(), result)
    }
}

pub(super) fn started() {
    tracing::info!(target: TARGET, event = "process_started");
}
pub(super) fn stopped() {
    tracing::info!(target: TARGET, event = "process_stopped");
}
pub(super) fn result(request_id: &str, error: Option<&Error>) {
    let request_id = uuid::Uuid::parse_str(request_id)
        .map(|id| id.to_string())
        .unwrap_or_default();
    if let Some(error) = error {
        let code = serde_json::to_value(error.code).expect("error code serializes");
        // Public errors can carry caller-controlled text. Only emit reviewed messages.
        let message = [
            Error::setup_required,
            Error::obsolete_runtime_capacity,
            Error::incompatible_schema,
            Error::draft_conflict,
        ]
        .into_iter()
        .map(|known| known())
        .find(|known| known == error)
        .unwrap_or_else(|| Error::new(error.code))
        .message;
        tracing::error!(target: TARGET, event = "operation_failed", request_id = request_id.as_str(), code = code.as_str().expect("error code is a string"), message = message.as_str());
    } else {
        tracing::info!(target: TARGET, event = "operation_completed", request_id = request_id.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_payloads_never_reach_diagnostic_formatting() {
        const CHILD: &str = "MAILCTL_DIAGNOSTIC_FIXTURE";
        if let Ok(level) = std::env::var(CHILD) {
            Options {
                log_format: LogFormat::Json,
                log_level: match level.as_str() {
                    "error" => LogLevel::Error,
                    "warn" => LogLevel::Warn,
                    "info" => LogLevel::Info,
                    "debug" => LogLevel::Debug,
                    _ => LogLevel::Trace,
                },
                color: Color::Always,
            }
            .initialize(true)
            .unwrap();
            struct Private;
            impl std::fmt::Debug for Private {
                fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    panic!("private dependency payload must never be formatted")
                }
            }
            tracing::error!(target: "provider", payload = ?Private);
            tracing::warn!(target: "store", payload = ?Private);
            tracing::info!(target: "command", payload = ?Private);
            tracing::debug!(target: "parser", payload = ?Private);
            tracing::trace!(target: "transport", payload = ?Private);
            let mut error = Error::new(ErrorCode::ProviderUnavailable);
            error.message = "fixture-private-secret\u{1b}]52;c;private\u{7}".repeat(4096);
            result("untrusted-request-secret", Some(&error));
            let _ = std::panic::catch_unwind(|| panic!("fixture-private-panic\u{202e}"));
            return;
        }
        for level in ["error", "warn", "info", "debug", "trace"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "frontends::diagnostics::tests::private_payloads_never_reach_diagnostic_formatting", "--nocapture"])
                .env(CHILD, level).env("RUST_LOG", "trace").env("RUST_BACKTRACE", "full")
                .output().unwrap();
            assert!(output.status.success());
            let diagnostics = String::from_utf8(output.stderr).unwrap();
            assert!(!diagnostics.contains("secret") && !diagnostics.contains("private"));
            let events: Vec<serde_json::Value> = diagnostics
                .lines()
                .map(|line| {
                    assert!(line.len() < 2048);
                    let event: serde_json::Value = serde_json::from_str(line).unwrap();
                    for key in ["request_id", "event_id", "location"] {
                        if let Some(value) = event[key].as_str() {
                            assert!(value.chars().count() <= 256);
                        }
                    }
                    event
                })
                .collect();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["code"], "provider_unavailable");
            assert_eq!(events[1]["event"], "panic");
            assert!(uuid::Uuid::parse_str(events[1]["event_id"].as_str().unwrap()).is_ok());
        }
    }
}
