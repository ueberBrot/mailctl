//! Replay synthetic envelopes at the application and SDK STDIO seams.
mod fuzz_support;
mod support;

use mailctl::{
    config::{Config, CredentialSource, Limits},
    credentials::{Availability, Secret, SecretSource, SourceError},
    domain::{Envelope, Error, ErrorCode, Operation},
    host::HostEnvironment,
    service::{
        DraftBackend, DraftPreparation, MailboxTarget, MemoryAttachments, MemoryBodies,
        MemoryMailboxes, MemoryMessages, Service,
    },
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const APPLICATION: &[&[u8]] = &[
    include_bytes!("fuzz_corpus/envelopes/application/accounts.json"),
    include_bytes!("fuzz_corpus/envelopes/application/capabilities.json"),
    include_bytes!("fuzz_corpus/envelopes/application/mailboxes.json"),
    include_bytes!("fuzz_corpus/envelopes/application/unknown-field.json"),
    include_bytes!("fuzz_corpus/envelopes/application/duplicate-operation.json"),
    include_bytes!("fuzz_corpus/envelopes/application/invalid-page.json"),
    include_bytes!("fuzz_corpus/envelopes/application/invalid-reference.json"),
    include_bytes!("fuzz_corpus/envelopes/application/denied-draft.json"),
    include_bytes!("fuzz_corpus/envelopes/application/denied-reconciliation.json"),
    include_bytes!("fuzz_corpus/envelopes/application/null-unit-input.json"),
];

#[derive(Default)]
struct ForbiddenWork(AtomicUsize);

impl HostEnvironment for ForbiddenWork {
    fn credential_source(&self, _: &CredentialSource) -> Arc<dyn SecretSource> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Arc::new(MissingSecret)
    }

    fn tls_roots(&self) -> Result<tokio_rustls::rustls::RootCertStore, SourceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(SourceError::Unavailable)
    }
}

struct MissingSecret;
impl SecretSource for MissingSecret {
    fn availability(&self, _: uuid::Uuid) -> Availability {
        Availability::Missing
    }

    fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
        Err(SourceError::Unavailable)
    }
}

impl DraftBackend for ForbiddenWork {
    fn prepare<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a Limits,
    ) -> DraftPreparation<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(Error::new(ErrorCode::InternalError)) })
    }

    fn reconcile<'a>(
        &'a self,
        _: MailboxTarget<'a>,
        _: &'a str,
        _: &'a mailctl::draft::DraftVerification,
        _: &'a Limits,
    ) -> Pin<Box<dyn Future<Output = Result<mailctl::draft::DraftEvidence, Error>> + Send + 'a>>
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(Error::new(ErrorCode::InternalError)) })
    }
}

fn application() -> (Service, Arc<ForbiddenWork>) {
    let installation = support::Installation::two_accounts();
    let config = Config::parse(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    let forbidden = Arc::new(ForbiddenWork::default());
    let service = Service::in_memory(config)
        .unwrap()
        .with_environment(forbidden.clone())
        .with_mailbox_backend(Arc::new(MemoryMailboxes::default()))
        .with_search_backend(Arc::new(MemoryMessages::default()))
        .with_body_backend(Arc::new(MemoryBodies::default()))
        .with_attachment_backend(Arc::new(MemoryAttachments::default()))
        .with_draft_backend(forbidden.clone());
    (service, forbidden)
}

fn safe_output(bytes: &[u8], case: usize) {
    let text = std::str::from_utf8(bytes).expect("UTF-8 result or diagnostics");
    for private in ["fixture-private-content", "fixture-secret-canary"] {
        assert!(
            !text.contains(private),
            "private input reflected in case {case}"
        );
    }
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\u{202e}'),
        "active terminal controls in case {case}"
    );
}

async fn application_case(service: &Service, input: &[u8], case: usize) -> serde_json::Value {
    assert!(input.len() <= fuzz_support::MAX_INPUT_BYTES);
    let started = Instant::now();
    let mut operation = None;
    let measured = allocation_counter::measure(|| {
        operation = Some(serde_json::from_slice::<Operation>(input));
    });
    assert!(
        measured.bytes_max as usize <= 128 * input.len() + 64 * 1024,
        "application decoding allocation exceeded in case {case}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "decoder stalled in case {case}"
    );
    let context = service.context("default", &Default::default()).unwrap();
    let result = match operation.unwrap() {
        Ok(operation) => {
            tokio::time::timeout(Duration::from_secs(2), service.execute(&context, operation))
                .await
                .unwrap_or_else(|_| panic!("application deadline exceeded in case {case}"))
        }
        Err(_) => Err(Error::new(ErrorCode::InvalidRequest)),
    };
    if let Err(error) = &result {
        assert_eq!(
            error.message,
            Error::new(error.code).message,
            "safe error in case {case}"
        );
        assert!(
            error.draft_operation.is_none(),
            "denied draft identity in case {case}"
        );
    }
    let envelope = Envelope::from_result(format!("envelope-case-{case}"), result);
    let output = serde_json::to_vec(&envelope).unwrap();
    assert!(
        output.len() <= 4096,
        "application output exceeded in case {case}"
    );
    safe_output(&output, case);
    let decoded: Envelope =
        serde_json::from_slice(&output).expect("versioned application envelope");
    assert_eq!(decoded.is_success(), envelope.is_success());
    serde_json::from_slice(&output).unwrap()
}

#[tokio::test]
async fn application_envelope_regressions_preserve_bounds_and_read_only_authority() {
    let (service, forbidden) = application();
    for (case, input) in APPLICATION.iter().enumerate() {
        let envelope = application_case(&service, input, case).await;
        if case < 3 {
            assert_eq!(
                envelope["ok"], true,
                "valid retained application case {case}"
            );
        } else {
            assert_eq!(
                envelope["ok"], false,
                "invalid or denied retained application case {case}"
            );
        }
        if matches!(case, 7 | 8) {
            assert_eq!(envelope["error"]["code"], "permission_denied");
        }
    }
    assert_eq!(
        forbidden.0.load(Ordering::SeqCst),
        0,
        "no credentials, network initialization or draft dispatch"
    );
}

#[tokio::test]
#[ignore = "explicit bounded mutation campaign"]
async fn fuzz_application_envelopes() {
    let campaign = fuzz_support::Campaign::from_env("application-envelopes");
    let (service, forbidden) = application();
    for (case, input) in campaign.cases(APPLICATION) {
        application_case(&service, &input, case).await;
        assert_eq!(
            forbidden.0.load(Ordering::SeqCst),
            0,
            "forbidden work in case {case}"
        );
    }
    campaign.finish();
}

#[cfg(feature = "mcp")]
mod mcp {
    use super::*;
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
    use serde_json::{Value, json};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::{Output, Stdio},
        sync::{atomic::AtomicBool, mpsc},
        thread,
    };

    const MCP: &[&[u8]] = &[
        include_bytes!("fuzz_corpus/envelopes/mcp/accounts.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/mailboxes.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/unknown-tool.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/unknown-field.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/denied-draft.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/invalid-params.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/duplicate-id.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/invalid-version.json"),
        include_bytes!("fuzz_corpus/envelopes/mcp/batch.json"),
    ];
    const INITIALIZE: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"envelope-fixture","version":"1"}}}
"#;
    const INITIALIZED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";

    fn installation() -> (support::Installation, TcpListener) {
        let provider = TcpListener::bind("127.0.0.1:0").unwrap();
        provider.set_nonblocking(true).unwrap();
        let installation = support::Installation::two_accounts();
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        for account in config["accounts"].as_array_mut().unwrap() {
            account["server"] = "localhost".into();
            account.as_table_mut().unwrap().insert(
                "port".into(),
                (provider.local_addr().unwrap().port() as i64).into(),
            );
            account["credential"]["source"] = "session".into();
        }
        // Account and access grant mailbox scopes have no intersection.
        config["grants"][0]["mailboxes"] = toml::Value::Array(vec!["OutsideAccountScope".into()]);
        config.as_table_mut().unwrap().insert(
            "limits".into(),
            toml::Value::Table(toml::map::Map::from_iter([
                ("envelope_bytes".into(), 4096.into()),
                ("buffered_bytes".into(), (1024 * 1024).into()),
                ("operation_seconds".into(), 1.into()),
                ("connection_seconds".into(), 1.into()),
                ("initialization_seconds".into(), 1.into()),
            ])),
        );
        std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
        let mut setup = installation.mcp();
        setup.args(["--json", "setup"]);
        support::assert_success(&support::run_bounded(setup));
        (installation, provider)
    }

    fn capture(
        mut reader: impl Read + Send + 'static,
        limit: usize,
        overflow: Arc<AtomicBool>,
        lines: Option<Arc<AtomicUsize>>,
    ) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let length = reader.read(&mut buffer).expect("read bounded child output");
                if length == 0 {
                    return output;
                }
                let retained = length.min(limit - output.len());
                output.extend_from_slice(&buffer[..retained]);
                if retained < length {
                    overflow.store(true, Ordering::SeqCst);
                }
                if let Some(lines) = &lines {
                    lines.fetch_add(
                        buffer[..length]
                            .iter()
                            .filter(|byte| **byte == b'\n')
                            .count(),
                        Ordering::SeqCst,
                    );
                }
            }
        })
    }

    fn raw_case(installation: &support::Installation, input: &[u8], case: usize) -> Output {
        assert!(input.len() <= fuzz_support::MAX_INPUT_BYTES);
        let mut command = installation.mcp();
        command.args(["--log-format", "json", "--log-level", "trace"]);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start SDK STDIO fixture");
        let overflow = Arc::new(AtomicBool::new(false));
        let lines = Arc::new(AtomicUsize::new(0));
        let stdout = capture(
            child.stdout.take().unwrap(),
            512 * 1024,
            overflow.clone(),
            Some(lines.clone()),
        );
        let stderr = capture(
            child.stderr.take().unwrap(),
            64 * 1024,
            overflow.clone(),
            None,
        );
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let (advance, phases) = mpsc::sync_channel(2);
        let write = thread::spawn(move || {
            let _ = stdin.write_all(INITIALIZE);
            if phases.recv().is_err() {
                return;
            }
            let _ = stdin.write_all(INITIALIZED);
            let _ = stdin.write_all(&input);
            if !input.ends_with(b"\n") {
                let _ = stdin.write_all(b"\n");
            }
            // Keep the transport live until the case responds or the SDK closes it.
            let _ = phases.recv();
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut exceeded = false;
        let mut initialized = false;
        let mut closing = false;
        let status = loop {
            if let Some(status) = child.try_wait().expect("inspect SDK child") {
                break status;
            }
            if overflow.load(Ordering::SeqCst) || Instant::now() >= deadline {
                exceeded = true;
                let _ = child.kill();
                break child.wait().expect("reap bounded SDK child");
            }
            let received = lines.load(Ordering::SeqCst);
            if !initialized && received >= 1 {
                let _ = advance.send(());
                initialized = true;
            }
            if initialized && !closing && received >= 2 {
                let _ = advance.send(());
                closing = true;
            }
            thread::sleep(Duration::from_millis(2));
        };
        drop(advance);
        write.join().expect("join bounded STDIO writer");
        let output = Output {
            status,
            stdout: stdout.join().expect("collect bounded STDIO output"),
            stderr: stderr.join().expect("collect bounded diagnostics"),
        };
        assert!(
            !exceeded,
            "MCP process/output ceiling exceeded in case {case}"
        );
        assert!(
            !overflow.load(Ordering::SeqCst),
            "MCP output ceiling exceeded in case {case}"
        );
        assert!(initialized, "MCP initialization failed before case {case}");
        safe_output(&output.stdout, case);
        safe_output(&output.stderr, case);
        let initialization: Value =
            serde_json::from_slice(output.stdout.split(|byte| *byte == b'\n').next().unwrap())
                .expect("SDK initialization response");
        assert_eq!(
            initialization["id"], 1,
            "initialization response in case {case}"
        );
        assert_eq!(initialization["result"]["protocolVersion"], "2025-11-25");
        for line in output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let frame: Value = serde_json::from_slice(line).expect("SDK JSON-RPC output framing");
            assert_eq!(
                frame["jsonrpc"], "2.0",
                "versioned SDK frame in case {case}"
            );
            if let Some(envelope) = frame["result"].get("structuredContent") {
                let _: Envelope<Value> = serde_json::from_value(envelope.clone())
                    .expect("versioned normalized MCP envelope");
            }
        }
        for line in output
            .stderr
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let _: Value = serde_json::from_slice(line).expect("bounded JSON diagnostics");
        }
        assert!(
            matches!(output.status.code(), Some(0 | 2 | 5 | 8)),
            "MCP crash in case {case}"
        );
        output
    }

    fn no_provider_connections(provider: &TcpListener) {
        assert!(
            matches!(provider.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "envelope reached the provider"
        );
    }

    #[test]
    fn mcp_envelope_regressions_bound_sdk_output_and_never_reach_the_provider() {
        let (installation, provider) = installation();
        for (case, input) in MCP.iter().enumerate() {
            let output = raw_case(&installation, input, case);
            if case < 2 {
                let response: Value = serde_json::from_slice(
                    output
                        .stdout
                        .split(|byte| *byte == b'\n')
                        .nth(1)
                        .expect("retained request response"),
                )
                .unwrap();
                assert_eq!(response["id"], 2);
                assert_eq!(response["result"]["structuredContent"]["ok"], true);
            }
            no_provider_connections(&provider);
        }
        for (case, input) in [
            vec![0xff, b'\n'],
            format!("{}0{}", "[".repeat(65), "]".repeat(65)).into_bytes(),
            format!("[{}]", vec!["0"; 4097].join(",")).into_bytes(),
            vec![b'x'; fuzz_support::MAX_INPUT_BYTES],
        ]
        .iter()
        .enumerate()
        {
            raw_case(&installation, input, MCP.len() + case);
            no_provider_connections(&provider);
        }
    }

    #[tokio::test]
    async fn sdk_client_checks_normalized_error_parity_and_read_only_draft_denial() {
        let (installation, provider) = installation();
        let mut command = tokio::process::Command::new(support::MAILCTL_MCP);
        command
            .arg("--config")
            .arg(installation.config())
            .kill_on_drop(true);
        let transport = TokioChildProcess::new(command).expect("spawn SDK server");
        let client = tokio::time::timeout(Duration::from_secs(10), ().serve(transport))
            .await
            .unwrap()
            .expect("bounded SDK initialization");
        for input in [MCP[0], MCP[1], MCP[3]] {
            let frame: Value = serde_json::from_slice(input).unwrap();
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                client.call_tool(
                    CallToolRequestParams::new(
                        frame["params"]["name"].as_str().unwrap().to_owned(),
                    )
                    .with_arguments(frame["params"]["arguments"].as_object().unwrap().clone()),
                ),
            )
            .await
            .unwrap()
            .expect("bounded SDK tool response");
            let structured = response.structured_content.unwrap();
            let text: Value =
                serde_json::from_str(&response.content[0].as_text().unwrap().text).unwrap();
            assert_eq!(text, structured, "SDK normalized result parity");
            let output = serde_json::to_vec(&structured).unwrap();
            assert!(output.len() <= 4096);
            safe_output(&output, 0);
            let _: Envelope<Value> = serde_json::from_value(structured.clone()).unwrap();
            if input == MCP[3] {
                assert_eq!(structured["error"]["code"], "invalid_request");
            } else {
                assert_eq!(structured["ok"], true);
            }
        }
        let tools = tokio::time::timeout(Duration::from_secs(2), client.list_all_tools())
            .await
            .unwrap()
            .unwrap();
        assert!(tools.iter().all(|tool| tool.name != "email_save_draft"));
        let denied = tokio::time::timeout(
            Duration::from_secs(2),
            client.call_tool(
                CallToolRequestParams::new("email_save_draft")
                    .with_arguments(json!({}).as_object().unwrap().clone()),
            ),
        )
        .await
        .unwrap();
        assert!(denied.is_err(), "unadvertised draft tool must be denied");
        tokio::time::timeout(Duration::from_secs(10), client.cancel())
            .await
            .unwrap()
            .unwrap();
        no_provider_connections(&provider);
    }

    #[test]
    #[ignore = "explicit bounded mutation campaign"]
    fn fuzz_mcp_envelopes() {
        let campaign = fuzz_support::Campaign::from_env("mcp-envelopes");
        let (installation, provider) = installation();
        for (case, input) in campaign.cases(MCP) {
            raw_case(&installation, &input, case);
            no_provider_connections(&provider);
        }
        campaign.finish();
    }
}
