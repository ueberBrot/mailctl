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
                .with_ansi(self.color.enabled(false, std::io::stderr().is_terminal()))
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
            format != LogFormat::Off && metadata.target() == TARGET && *metadata.level() <= level
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
            let location: String = location
                .chars()
                .rev()
                .take(128)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .flat_map(char::escape_default)
                .collect();
            tracing::error!(target: TARGET, event = "panic", event_id = uuid::Uuid::new_v4().to_string().as_str(), location = location.as_str(), code = "internal_error");
        }));
        Ok(())
    }
}
impl Color {
    fn enabled(self, machine: bool, terminal: bool) -> bool {
        !machine
            && terminal
            && self != Self::Never
            && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
    }
    pub fn stdout(self, machine: bool) -> anstream::AutoStream<std::io::Stdout> {
        let choice = if self.enabled(machine, std::io::stdout().is_terminal()) {
            anstream::ColorChoice::Always
        } else {
            anstream::ColorChoice::Never
        };
        anstream::AutoStream::new(std::io::stdout(), choice)
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
        let message = [Error::setup_required(), Error::obsolete_runtime_capacity()]
            .into_iter()
            .find(|known| known == error)
            .unwrap_or_else(|| Error::new(error.code))
            .message;
        tracing::error!(target: TARGET, event = "operation_failed", request_id = request_id.as_str(), code = code.as_str().expect("error code is a string"), message = message.as_str());
    } else {
        tracing::info!(target: TARGET, event = "operation_completed", request_id = request_id.as_str());
    }
}
