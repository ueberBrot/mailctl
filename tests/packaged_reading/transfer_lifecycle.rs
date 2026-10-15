use super::*;
use server::{AttachmentPhase, transfer_lifecycle::TransferStall};
use std::time::Duration;

async fn attachment_reference(fixture: &Fixture, reader: &Reader, message: &str) -> String {
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::List);
    reader
        .call(
            fixture,
            &["attachment", "list", "--message", message],
            "email_list_attachments",
            json!({"message": message}),
        )
        .await["attachments"][0]["reference"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[cfg(feature = "mcp")]
async fn start_transfer(fixture: &Fixture, reader: &Reader, reference: &str) -> Value {
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Start);
    let first = reader
        .call(
            fixture,
            &[],
            "email_get_attachment",
            json!({"attachment": reference}),
        )
        .await;
    assert_eq!(first["attachment_reference"], reference);
    assert_eq!(first["decoded_offset"], 0);
    assert_eq!(first["bytes_base64"], "YWJj");
    assert_eq!(first["progress"]["status"], "continue");
    first["progress"]["next_token"].clone()
}

#[cfg(feature = "mcp")]
async fn finish_transfer(fixture: &Fixture, reader: &Reader, token: &Value) {
    fixture
        .server
        .expect_attachment(USERNAME, PASSWORD, "INBOX", AttachmentPhase::Continue);
    let last = reader
        .call(
            fixture,
            &[],
            "email_get_attachment",
            json!({"token": token}),
        )
        .await;
    assert_eq!(last["decoded_offset"], 3);
    assert_eq!(last["bytes_base64"], "ZGVm");
    assert_eq!(
        last["progress"],
        json!({"status": "complete", "total_decoded_bytes": 6, "sha256": SHA256})
    );
}

async fn complete_transfer(fixture: &Fixture, reader: &Reader, reference: &str) {
    match reader {
        #[cfg(feature = "cli")]
        Reader::Cli => {
            for phase in [AttachmentPhase::Start, AttachmentPhase::Continue] {
                fixture
                    .server
                    .expect_attachment(USERNAME, PASSWORD, "INBOX", phase);
            }
            let result = reader
                .call(
                    fixture,
                    &["attachment", "get", "--attachment", reference],
                    "email_get_attachment",
                    json!({"attachment": reference}),
                )
                .await;
            assert_eq!(result["decoded_offset"], 0);
            assert_eq!(result["bytes_base64"], "YWJjZGVm");
            assert_eq!(
                result["progress"],
                json!({"status": "complete", "total_decoded_bytes": 6, "sha256": SHA256})
            );
        }
        #[cfg(feature = "mcp")]
        Reader::Mcp(_) => {
            let token = start_transfer(fixture, reader, reference).await;
            finish_transfer(fixture, reader, &token).await;
        }
    }
}

#[cfg(feature = "mcp")]
async fn reject_without_provider(fixture: &Fixture, reader: &Reader, input: Value, expected: &str) {
    let accepted = fixture.server.accepted();
    let rejected = reader
        .response(fixture, &[], "email_get_attachment", input)
        .await;
    assert_eq!(rejected["error"]["code"], expected, "{rejected}");
    assert!(rejected.get("result").is_none(), "{rejected}");
    assert_eq!(fixture.server.accepted(), accepted);
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_attachment_quota_preserves_live_tokens_and_expiry_releases_capacity() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut fixture = Fixture::with_limits(
            support::MAILCTL_MCP,
            "attachment_chunk_bytes = 3\ntransfers_per_account = 1\ntransfer_seconds = 1",
        );
        let reader = Reader::start(&fixture, support::MAILCTL_MCP).await;
        let (mailbox, before) = discover_message(&fixture, &reader).await;
        let reference =
            attachment_reference(&fixture, &reader, before["reference"].as_str().unwrap()).await;
        let token = start_transfer(&fixture, &reader, &reference).await;
        reject_without_provider(
            &fixture,
            &reader,
            json!({"attachment": reference}),
            "rate_limited",
        )
        .await;
        // A rejected new transfer must leave the one occupying the slot usable.
        finish_transfer(&fixture, &reader, &token).await;
        let expired = start_transfer(&fixture, &reader, &reference).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        // Start before touching the expired token: capacity must be reclaimed
        // without requiring its owner to issue a cleanup request.
        let fresh = start_transfer(&fixture, &reader, &reference).await;
        reject_without_provider(
            &fixture,
            &reader,
            json!({"token": expired}),
            "transfer_expired",
        )
        .await;
        finish_transfer(&fixture, &reader, &fresh).await;
        assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
        reader.finish().await;
        fixture.server.finish();
    })
    .await
    .expect("standalone MCP attachment quota and expiry deadline");
}

async fn interrupt_attachment_at_its_deadline(executable: &str) {
    for stage in [TransferStall::Authentication, TransferStall::Payload] {
        for (operation, transfer, expected) in [
            (30, 1, &["transfer_expired"][..]),
            // Equal configured durations need not start together: the public
            // operation deadline may precede reservation of the transfer.
            (1, 1, &["transfer_expired", "timeout"][..]),
            (1, 30, &["timeout"][..]),
        ] {
            tokio::time::timeout(Duration::from_secs(30), async {
                let mut fixture = Fixture::with_limits(
                    executable,
                    &format!(
                        "attachment_chunk_bytes = 3\ntransfers_per_account = 1\noperation_seconds = {operation}\ntransfer_seconds = {transfer}\nconnection_seconds = 1\ninitialization_seconds = 1"
                    ),
                );
                let reader = Reader::start(&fixture, executable).await;
                let (mailbox, before) = discover_message(&fixture, &reader).await;
                let reference = attachment_reference(
                    &fixture,
                    &reader,
                    before["reference"].as_str().unwrap(),
                )
                .await;
                fixture.server.expect_transfer_stall(stage);
                let started = std::time::Instant::now();
                let failed = tokio::time::timeout(
                    Duration::from_secs(5),
                    reader.response(
                        &fixture,
                        &["attachment", "get", "--attachment", &reference],
                        "email_get_attachment",
                        json!({"attachment": reference}),
                    ),
                )
                .await
                .expect("the narrower one-second attachment deadline must interrupt provider work");
                assert!(started.elapsed() < Duration::from_secs(5));
                assert!(
                    expected.contains(&failed["error"]["code"].as_str().unwrap()),
                    "{stage:?}, operation={operation}, transfer={transfer}: {failed}"
                );
                assert!(failed.get("result").is_none(), "{failed}");
                assert_eq!(fixture.server.interrupted(), 1);
                // The serial provider cannot accept this successful transfer
                // before observing disposal of the stalled connection. MCP
                // must also release its sole transfer slot while still alive.
                complete_transfer(&fixture, &reader, &reference).await;
                assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
                reader.finish().await;
                fixture.server.finish();
            })
            .await
            .unwrap_or_else(|_| panic!("standalone attachment deadline: {stage:?}, operation={operation}, transfer={transfer}"));
        }
    }
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_attachment_deadlines_dispose_authentication_and_incomplete_fetches() {
    interrupt_attachment_at_its_deadline(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_attachment_deadlines_dispose_authentication_and_incomplete_fetches() {
    interrupt_attachment_at_its_deadline(support::MAILCTL_MCP).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_attachment_cancellation_disposes_transport_and_releases_capacity() {
    use rmcp::{
        model::{CallToolRequest, CallToolRequestParams, ClientRequest},
        service::PeerRequestOptions,
    };

    // None targets a continuation after its EXAMINE command, with decoded bytes
    // already retained from a successful first chunk.
    for stage in [
        Some(TransferStall::Authentication),
        Some(TransferStall::Payload),
        None,
    ] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut fixture = Fixture::with_limits(
                support::MAILCTL_MCP,
                "envelope_bytes = 65536\nattachment_chunk_bytes = 3\ntransfers_per_account = 1",
            );
            let reader = Reader::start(&fixture, support::MAILCTL_MCP).await;
            let (mailbox, before) = discover_message(&fixture, &reader).await;
            let reference =
                attachment_reference(&fixture, &reader, before["reference"].as_str().unwrap())
                    .await;
            let token = if let Some(stage) = stage {
                fixture.server.expect_transfer_stall(stage);
                None
            } else {
                let token = start_transfer(&fixture, &reader, &reference).await;
                fixture.server.expect_attachment(
                    USERNAME,
                    PASSWORD,
                    "INBOX",
                    AttachmentPhase::InterruptedContinuation,
                );
                Some(token)
            };
            let input = token.as_ref().map_or_else(
                || json!({"attachment": reference}),
                |token| json!({"token": token}),
            );
            let client = match &reader {
                Reader::Mcp(client) => client,
                #[cfg(feature = "cli")]
                Reader::Cli => unreachable!("MCP cancellation uses the MCP executable"),
            };
            let request = client
                .send_request_with_option(
                    ClientRequest::CallToolRequest(CallToolRequest::new(
                        CallToolRequestParams::new("email_get_attachment")
                            .with_arguments(input.as_object().unwrap().clone()),
                    )),
                    PeerRequestOptions::no_options(),
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while fixture.server.interrupted() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the actual MCP tool request must reach the provider before cancellation");
            reject_without_provider(
                &fixture,
                &reader,
                json!({"attachment": reference}),
                "rate_limited",
            )
            .await;
            request
                .cancel(Some("packaged attachment acceptance".into()))
                .await
                .unwrap();
            // Keep this session live. The serial provider makes the metadata
            // request a disposal barrier before testing capacity reclamation.
            assert_eq!(search_message(&fixture, &reader, &mailbox).await, before);
            if let Some(token) = token {
                reject_without_provider(
                    &fixture,
                    &reader,
                    json!({"token": token}),
                    "transfer_expired",
                )
                .await;
            }
            complete_transfer(&fixture, &reader, &reference).await;
            reader.finish().await;
            fixture.server.finish();
        })
        .await
        .unwrap_or_else(|_| panic!("standalone MCP attachment cancellation deadline: {stage:?}"));
    }
}
