//! STDIO acceptance tests for the standalone MCP component.
#![cfg(feature = "mcp")]

mod support;

use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use support::{Installation, MAILCTL_MCP, assert_success, envelope, run_bounded};

fn setup(installation: &Installation) {
    let output = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&output);
}

type McpClient = rmcp::service::RunningService<rmcp::RoleClient, ()>;

async fn client(installation: &Installation, arguments: &[&str]) -> McpClient {
    let mut command = tokio::process::Command::new(MAILCTL_MCP);
    command
        .arg("--config")
        .arg(installation.config())
        .args(arguments);
    let transport = TokioChildProcess::new(command).expect("start MCP component");
    ().serve(transport).await.expect("negotiate MCP")
}

async fn listed_accounts(installation: &Installation, arguments: &[&str]) -> (McpClient, Value) {
    let client = client(installation, arguments).await;
    let response = client
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await
        .expect("call account discovery tool");
    (
        client,
        response
            .structured_content
            .expect("structured discovery envelope"),
    )
}

#[tokio::test]
async fn default_read_and_drafts_grant_can_discover_capabilities() {
    let installation = Installation::two_accounts();
    let configuration = std::fs::read_to_string(installation.config()).unwrap();
    std::fs::write(
        installation.config(),
        configuration.replace("profile = \"drafts_only\"", "profile = \"read_and_drafts\""),
    )
    .unwrap();
    setup(&installation);
    let client = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    let response = client
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .unwrap();
    let envelope = response.structured_content.unwrap();
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert!(
        envelope["result"]["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("append_draft"))
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_discovery_is_compact_and_output_schemas_validate_wire_results() {
    let installation = Installation::two_accounts();
    let configuration = std::fs::read_to_string(installation.config()).unwrap();
    std::fs::write(
        installation.config(),
        configuration.replace("profile = \"drafts_only\"", "profile = \"read_and_drafts\""),
    )
    .unwrap();
    setup(&installation);
    let client = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 9, "discovery retains every authorized tool");
    let bytes = serde_json::to_vec(&tools).unwrap().len();
    assert!(bytes <= 48 * 1024, "tool discovery uses {bytes} bytes");
    for tool in &tools {
        let schema = serde_json::to_value(tool.output_schema.as_ref().unwrap()).unwrap();
        assert_eq!(schema["type"], "object", "{}", tool.name);
        let validator = jsonschema::validator_for(&schema).expect("self-contained output schema");
        let arguments = match tool.name.as_ref() {
            "email_list_accounts" | "email_capabilities" => None,
            _ => Some(
                json!({"fixture_invalid_argument": true})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        };
        let response = client
            .call_tool(
                CallToolRequestParams::new(tool.name.clone())
                    .with_arguments(arguments.unwrap_or_default()),
            )
            .await
            .unwrap();
        let envelope = support::assert_mcp_envelope(response);
        validator.validate(&envelope).unwrap();
        for (field, invalid) in [
            ("request_id", json!(42)),
            ("ok", json!("true")),
            ("fixture_extra_field", json!(true)),
        ] {
            let mut malformed = envelope.clone();
            malformed[field] = invalid;
            assert!(
                !validator.is_valid(&malformed),
                "{} accepts invalid {field}",
                tool.name
            );
        }
        let malformed = json!({
            "request_id": "fixture",
            "ok": true,
            "result": 42
        });
        assert!(
            !validator.is_valid(&malformed),
            "{} accepts an invalid result",
            tool.name
        );
        if envelope["ok"] == false {
            let mut malformed = envelope.clone();
            malformed["error"]["code"] = json!("fixture_unknown_error");
            assert!(
                !validator.is_valid(&malformed),
                "{} accepts an unknown error code",
                tool.name
            );
            malformed = envelope.clone();
            malformed.as_object_mut().unwrap().remove("error");
            assert!(
                !validator.is_valid(&malformed),
                "{} accepts a missing error",
                tool.name
            );
        }
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_discovery_provides_guides_and_effective_limits() {
    let installation = Installation::two_accounts();
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config["grants"][0].as_table_mut().unwrap().insert(
        "limits".into(),
        toml::Value::Table(toml::map::Map::from_iter([
            ("search_page".into(), 7.into()),
            ("mailbox_page".into(), 11.into()),
            ("text_page_bytes".into(), 4096.into()),
        ])),
    );
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    setup(&installation);
    let client = client(&installation, &[]).await;
    let info = client.peer_info().unwrap();
    assert_eq!(
        info.protocol_version,
        rmcp::model::ProtocolVersion::V_2025_11_25
    );
    assert!(
        info.instructions
            .as_ref()
            .unwrap()
            .contains("mailctl://guide/")
    );
    assert!(info.capabilities.resources.is_some());
    let resources = client.list_all_resources().await.unwrap();
    let uris: Vec<_> = resources
        .iter()
        .map(|resource| resource.uri.as_str())
        .collect();
    assert_eq!(
        uris,
        [
            "mailctl://guide/overview",
            "mailctl://guide/reading",
            "mailctl://guide/attachments",
            "mailctl://guide/drafts",
            "mailctl://guide/errors",
        ]
    );
    for resource in resources {
        let response = client
            .read_resource(rmcp::model::ReadResourceRequestParams::new(resource.uri))
            .await
            .unwrap();
        let text = serde_json::to_value(response).unwrap();
        assert!(text["contents"][0]["text"].as_str().unwrap().len() > 100);
    }
    assert!(
        client
            .read_resource(rmcp::model::ReadResourceRequestParams::new(
                "mailctl://guide/unknown"
            ))
            .await
            .is_err()
    );
    let tools = client.list_all_tools().await.unwrap();
    let response = client
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .unwrap();
    let envelope = response.structured_content.unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["limits"]["search_page"], 7);
    assert_eq!(envelope["result"]["limits"]["mailbox_page"], 11);
    assert_eq!(envelope["result"]["limits"]["text_page_bytes"], 4096);
    assert_eq!(
        envelope["result"]["limits"]["default_text_page_bytes"],
        4096
    );
    for operation in envelope["result"]["operations"].as_array().unwrap() {
        let name = format!("email_{}", operation.as_str().unwrap());
        assert!(tools.iter().any(|tool| tool.name == name));
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_input_errors_provide_safe_repair_guidance() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let client = client(&installation, &[]).await;
    for (name, arguments, expected) in [
        (
            "email_capabilities",
            json!({"fixture-private-field": "fixture-private-value"}),
            "no arguments",
        ),
        (
            "email_get_attachment",
            json!({"attachment": "fixture-private-value", "token": "fixture-private-value"}),
            "either attachment",
        ),
        (
            "email_search_messages",
            json!({"mailbox": "fixture-private-value", "limit": 51}),
            "between 1 and 50",
        ),
        (
            "email_list_mailboxes",
            json!({"limit": 201}),
            "between 1 and 200",
        ),
    ] {
        let response = client
            .call_tool(
                CallToolRequestParams::new(name)
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_eq!(response.is_error, Some(true));
        let envelope = response.structured_content.unwrap();
        assert_eq!(envelope["error"]["code"], "invalid_request");
        assert!(
            envelope["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected)
        );
        assert!(!envelope.to_string().contains("fixture-private"));
    }
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_annotations_distinguish_reads_from_draft_journal_mutation() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let reader = client(&installation, &[]).await;
    for tool in reader.list_all_tools().await.unwrap() {
        assert_eq!(tool.annotations.unwrap().read_only_hint, Some(true));
    }
    reader.cancel().await.unwrap();
    let writer = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    for tool in writer.list_all_tools().await.unwrap() {
        if matches!(
            tool.name.as_ref(),
            "email_save_draft" | "email_draft_status"
        ) {
            let annotations = tool.annotations.unwrap();
            assert_eq!(annotations.read_only_hint, Some(false));
            assert_eq!(annotations.destructive_hint, Some(false));
            if tool.name == "email_save_draft" {
                assert_eq!(annotations.idempotent_hint, Some(true));
            }
        }
    }
    writer.cancel().await.unwrap();
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn large_discovery_matches_cli_in_both_mcp_result_forms() {
    for account_count in [4, 40] {
        let installation = Installation::two_accounts();
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
        let template = config["accounts"][0].clone();
        let mut keys = Vec::new();
        let accounts = (0..account_count)
            .map(|index| {
                let mut account = template.clone();
                let key = format!("account{index}");
                keys.push(toml::Value::String(key.clone()));
                account["key"] = key.clone().into();
                account["alias"] = key.into();
                account["from_identities"] = toml::Value::Array(
                    (0..100)
                        .map(|identity| {
                            let prefix = format!("identity{identity:02}");
                            toml::Value::String(format!(
                                "{prefix}{}",
                                "x".repeat(999 - prefix.len())
                            ))
                        })
                        .collect(),
                );
                account
            })
            .collect();
        config["accounts"] = toml::Value::Array(accounts);
        let mut grant = config["grants"][0].clone();
        grant["accounts"] = toml::Value::Array(keys);
        config["grants"] = toml::Value::Array(vec![grant]);
        config.as_table_mut().unwrap().insert(
            "limits".into(),
            toml::Value::Table(toml::map::Map::from_iter([(
                "accounts".into(),
                toml::Value::Integer(account_count),
            )])),
        );
        let configuration = toml::to_string(&config).unwrap();
        assert!(configuration.len() < 4 * 1024 * 1024);
        std::fs::write(installation.config(), configuration).unwrap();
        setup(&installation);

        // Drain stdout while the process runs: this result is larger than a pipe.
        let cli = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(support::MAILCTL)
                .arg("--config")
                .arg(installation.config())
                .args(["--json", "account", "list"])
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_success(&cli);
        let cli_envelope = envelope(&cli);
        assert!(cli.stdout.len() > 400_000);

        let client = client(&installation, &[]).await;
        let response = client
            .call_tool(CallToolRequestParams::new("email_list_accounts"))
            .await
            .expect("large discovery completes");
        assert_eq!(response.is_error, Some(false), "{account_count} accounts");
        let structured = response.structured_content.unwrap();
        let text: Value =
            serde_json::from_str(&response.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(structured, text);
        assert_eq!(structured["result"], cli_envelope["result"]);
        assert_eq!(
            structured["result"]["accounts"].as_array().unwrap().len(),
            account_count as usize
        );
        client
            .cancel()
            .await
            .expect("close large discovery session");
    }
}

#[tokio::test]
async fn mcp_serves_with_a_small_valid_byte_budget() {
    let installation = Installation::two_accounts();
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.as_table_mut().unwrap().insert(
        "limits".into(),
        toml::Value::Table(toml::map::Map::from_iter([
            ("envelope_bytes".into(), 4096.into()),
            ("buffered_bytes".into(), (1024 * 1024).into()),
        ])),
    );
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    setup(&installation);
    let (client, envelope) = listed_accounts(&installation, &[]).await;
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["accounts"][0]["alias"], "work");
    tokio::time::timeout(Duration::from_secs(30), async {
        for _ in 0..128 {
            assert_eq!(client.list_all_tools().await.unwrap().len(), 7);
            let response = client
                .call_tool(CallToolRequestParams::new("email_list_accounts"))
                .await
                .expect("sequential requests retain their admission slot");
            assert_eq!(response.structured_content.unwrap()["ok"], true);
        }
    })
    .await
    .expect("bounded sequential MCP exchanges complete");
    client.cancel().await.unwrap();
}

#[test]
fn an_mcp_budget_that_cannot_admit_a_frame_has_setup_guidance() {
    let installation = Installation::two_accounts();
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(installation.config()).unwrap()).unwrap();
    config.as_table_mut().unwrap().insert(
        "limits".into(),
        toml::Value::Table(toml::map::Map::from_iter([
            ("envelope_bytes".into(), 1024.into()),
            ("buffered_bytes".into(), (64 * 1024).into()),
        ])),
    );
    std::fs::write(installation.config(), toml::to_string(&config).unwrap()).unwrap();
    setup(&installation);
    let output = run_bounded(installation.mcp());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr).unwrap().contains("setup"));
}

#[tokio::test]
async fn standalone_mcp_negotiates_schemas_and_applies_configured_grant_scope() {
    let installation = Installation::two_accounts();
    setup(&installation);

    let all_client = client(&installation, &["--grant", "all"]).await;
    let tools = all_client.list_all_tools().await.expect("list tools");
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        [
            "email_list_accounts",
            "email_capabilities",
            "email_list_mailboxes",
            "email_search_messages",
            "email_get_message",
            "email_list_attachments",
            "email_get_attachment"
        ]
    );
    let discovery = &tools[0];
    assert!(discovery.input_schema.contains_key("properties"));
    assert!(discovery.input_schema["properties"].get("limit").is_some());
    let output_schema = discovery.output_schema.as_ref().unwrap();
    assert!(
        output_schema.contains_key("$schema") || output_schema.contains_key("$ref"),
        "MCP output schema must be a JSON Schema document"
    );

    let response = all_client
        .call_tool(CallToolRequestParams::new("email_list_accounts"))
        .await
        .expect("call discovery");
    assert_eq!(response.is_error, Some(false));
    let envelope = response.structured_content.unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["accounts"].as_array().unwrap().len(), 2);

    for (name, arguments) in [
        ("email_list_accounts", json!({"limit": 0})),
        ("email_capabilities", json!({"read_only": false})),
        ("email_get_message", json!({})),
        ("email_list_attachments", json!({"message": ""})),
        (
            "email_get_attachment",
            json!({"attachment": "ref", "token": "token"}),
        ),
    ] {
        let invalid = all_client
            .call_tool(
                CallToolRequestParams::new(name)
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await
            .expect("receive application error envelope");
        assert_eq!(invalid.is_error, Some(true), "{name}");
        assert_eq!(
            invalid.structured_content.unwrap()["error"]["code"],
            "invalid_request",
            "{name}"
        );
    }
    all_client.cancel().await.expect("close MCP session");

    let (restricted, envelope) = listed_accounts(&installation, &[]).await;
    assert_eq!(envelope["result"]["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(envelope["result"]["accounts"][0]["alias"], "work");
    restricted.cancel().await.expect("close restricted session");

    let read_only_writer = client(&installation, &["--grant", "writer"]).await;
    let read_only_capabilities = read_only_writer
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("call narrowed capabilities");
    assert_eq!(
        read_only_capabilities.structured_content.unwrap()["result"]["permissions"],
        json!(["list_accounts"]),
        "MCP narrows a configured writer grant unless explicitly opted in"
    );
    read_only_writer
        .cancel()
        .await
        .expect("close narrowed writer session");

    let configured_writer = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    let configured_capabilities = configured_writer
        .call_tool(CallToolRequestParams::new("email_capabilities"))
        .await
        .expect("call configured capabilities");
    assert_eq!(
        configured_capabilities.structured_content.unwrap()["result"]["permissions"],
        json!(["list_accounts", "append_draft", "inspect_draft_operation"])
    );
    configured_writer
        .cancel()
        .await
        .expect("close configured writer session");
}

#[tokio::test]
async fn mcp_hides_administration_tools_and_releases_setup_after_eof() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let client = client(&installation, &[]).await;
    let tools = client.list_all_tools().await.expect("list tools");
    assert!(
        tools
            .iter()
            .all(|tool| !tool.name.contains("credential") && !tool.name.contains("setup"))
    );
    for name in ["email_credential_set", "email_health", "list_accounts"] {
        assert!(
            client
                .call_tool(CallToolRequestParams::new(name))
                .await
                .is_err(),
            "unadvertised operation {name} must not be callable as an MCP tool"
        );
    }

    let busy = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_eq!(busy.status.code(), Some(5));
    assert_eq!(envelope(&busy)["error"]["code"], "rate_limited");

    client.cancel().await.expect("EOF closes MCP session");
    let ready = run_bounded({
        let mut command = installation.mcp();
        command.args(["--json", "setup"]);
        command
    });
    assert_success(&ready);
}

#[test]
fn malformed_stdio_frames_are_not_parsed_or_kept_alive() {
    let installation = Installation::two_accounts();
    setup(&installation);
    for frame in [
        vec![0xff, b'\n'],
        format!("[{}]\n", vec!["0"; 4097].join(",")).into_bytes(),
        format!("{}0{}\n", "[".repeat(65), "]".repeat(65)).into_bytes(),
        vec![b'x'; 65 * 1024],
    ] {
        let mut command = Command::new(MAILCTL_MCP);
        command
            .arg("--config")
            .arg(installation.config())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("start MCP component");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&frame)
            .expect("write malformed frame");
        let output = wait_for_exit(child);
        assert!(
            output.stdout.is_empty(),
            "malformed input must not be reflected to stdout"
        );
    }
}

#[test]
fn mcp_does_not_dispatch_a_tool_before_initialization() {
    let installation = Installation::two_accounts();
    setup(&installation);
    let output = raw_mcp(
        &installation,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"email_list_accounts","arguments":{}}}
"#,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("work") && !stdout.contains("accounts"),
        "a pre-initialization request reached the application: {stdout}"
    );
}

fn raw_mcp(installation: &Installation, frame: &[u8]) -> std::process::Output {
    let mut command = Command::new(MAILCTL_MCP);
    command
        .arg("--config")
        .arg(installation.config())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start MCP component");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(frame)
        .expect("write STDIO frame");
    wait_for_exit(child)
}

fn wait_for_exit(mut child: std::process::Child) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().expect("inspect MCP process").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("MCP process did not exit after EOF");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("collect MCP output")
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_runs_and_exits_while_a_standalone_mcp_session_owns_its_own_lease() {
    use support::MAILCTL;

    let installation = Installation::two_accounts();
    setup(&installation);
    let client = client(&installation, &[]).await;
    let output = run_bounded({
        let mut command = installation.command(MAILCTL);
        command.args(["--json", "account", "list"]);
        command
    });
    assert_success(&output);
    assert_eq!(
        envelope(&output)["result"]["accounts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    client.cancel().await.expect("close MCP session");
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn mailbox_discovery_has_cli_mcp_parity_and_is_hidden_from_drafts_only_grants() {
    let installation = Installation::two_accounts();
    let text = std::fs::read_to_string(installation.config()).unwrap();
    std::fs::write(
        installation.config(),
        text.replace(
            "mailboxes = [\"INBOX\"]",
            "mailboxes = [\"OutsideAccountScope\"]",
        ),
    )
    .unwrap();
    setup(&installation);
    let output = run_bounded({
        let mut command = installation.cli();
        command.args(["--json", "mailbox", "list"]);
        command
    });
    assert_success(&output);
    let cli = envelope(&output);
    assert_eq!(cli["result"]["mailboxes"], json!([]));
    assert_eq!(cli["result"]["complete"], true);
    let reader = client(&installation, &[]).await;
    assert!(
        reader
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|tool| tool.name == "email_list_mailboxes")
    );
    let response = reader
        .call_tool(CallToolRequestParams::new("email_list_mailboxes"))
        .await
        .unwrap();
    let structured = response.structured_content.unwrap();
    assert_eq!(structured["result"], cli["result"]);
    assert_eq!(
        serde_json::from_str::<Value>(&response.content[0].as_text().unwrap().text).unwrap(),
        structured
    );
    reader.cancel().await.unwrap();
    let writer = client(
        &installation,
        &["--grant", "writer", "--use-configured-grant"],
    )
    .await;
    assert!(
        !writer
            .list_all_tools()
            .await
            .unwrap()
            .iter()
            .any(|tool| tool.name == "email_list_mailboxes")
    );
    assert!(
        writer
            .call_tool(CallToolRequestParams::new("email_list_mailboxes"))
            .await
            .is_err()
    );
    writer.cancel().await.unwrap();
}
