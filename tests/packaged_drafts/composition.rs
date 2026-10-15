//! Public composition admission, beyond the lower-level schema/encoder suite.
use super::*;
use rusqlite::types::Value as SqlValue;

async fn rejected_before_dispatch(fixture: &Fixture, executable: &str, code: &str) {
    let records = history::rows(fixture);
    let connections = fixture.server.accepted();
    let appends = fixture.server.interrupted();
    assert_eq!(fixture.save(executable).await["error"]["code"], code);
    assert_eq!(
        fixture.status(executable, false).await["error"]["code"],
        "operation_not_found"
    );
    assert_eq!(history::rows(fixture), records);
    assert_eq!(fixture.server.accepted(), connections);
    assert_eq!(fixture.server.interrupted(), appends);
}

async fn public_composition_boundaries(executable: &str) {
    let mut fixture = Fixture::new(executable);
    let original = fixture.input["draft"].clone();
    // These cross the actual CLI file/MCP argument boundary. Individual string
    // and reply-metadata ceilings remain covered by the shared contract suite.
    for (field, value) in [
        ("subject", json!("Synthetic\r\nBcc: injected@example.test")),
        (
            "to",
            json!([{"address":"to@example.test", "name":"Synthetic\nInjected"}]),
        ),
        ("headers", json!({"X-Synthetic":"unsupported"})),
        ("to", json!(vec![json!({"address":"to@example.test"}); 101])),
    ] {
        fixture.input["draft"] = original.clone();
        fixture.input["draft"][field] = value;
        rejected_before_dispatch(&fixture, executable, "invalid_request").await;
    }
    assert!(history::rows(&fixture).is_empty());

    fixture.input["draft"] = original;
    for field in ["to", "cc"] {
        fixture.input["draft"][field] = json!(
            (0..50)
                .map(|index| json!({"address":format!("{field}{index}@example.test")}))
                .collect::<Vec<_>>()
        );
    }
    fixture.input["draft"]["bcc"] = json!([]);
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let created = fixture.save(executable).await;
    assert_eq!(created["result"]["state"], "created");
    let baseline = fixture.server.drafts().pop().unwrap();
    let message = mail_parser::MessageParser::default()
        .parse(&baseline)
        .unwrap();
    for (field, addresses) in [("to", message.to()), ("cc", message.cc())] {
        let actual = addresses.unwrap().as_list().unwrap();
        assert_eq!(actual.len(), 50);
        for (index, address) in actual.iter().enumerate() {
            assert_eq!(
                address.address(),
                Some(format!("{field}{index}@example.test").as_str())
            );
        }
    }
    assert!(message.bcc().is_none());
    assert_eq!(
        message.body_text(0).unwrap().replace("\r\n", "\n"),
        fixture.input["draft"]["body"].as_str().unwrap()
    );
    assert_eq!(history::rows(&fixture).len(), 1);

    // Each array is schema-valid; the total is an independent composition limit.
    fixture.new_operation();
    fixture.input["draft"]["bcc"] = json!([{"address":"hidden@example.test"}]);
    rejected_before_dispatch(&fixture, executable, "response_too_large").await;
    fixture.input["draft"]["bcc"] = json!([]);

    // Freeze the next operation through the existing predispatch SQL fault.
    // Its retained date makes both byte-limit attempts independent of time.
    fixture.sql("CREATE TRIGGER stop_dispatch BEFORE UPDATE ON draft_operations BEGIN SELECT RAISE(ABORT, 'synthetic dispatch failure'); END;");
    fixture.server.expect_draft_target(77);
    assert_eq!(
        fixture.save(executable).await["error"]["code"],
        "journal_unavailable"
    );
    fixture.sql("DROP TRIGGER stop_dispatch");
    let prepared_rows = history::rows(&fixture);
    let prepared = prepared_rows
        .iter()
        .find(|row| matches!(&row[6], SqlValue::Text(state) if state == "prepared"))
        .unwrap();
    let SqlValue::Text(reconstruction) = &prepared[5] else {
        panic!("prepared operation retains frozen reconstruction");
    };
    let reconstruction: Value = serde_json::from_str(reconstruction).unwrap();
    let date = mail_parser::DateTime::from_timestamp(reconstruction["date_unix"].as_i64().unwrap());
    // Measure real MIME at the provider, without the production composer as an
    // oracle. UUIDs have equal width; only the independent Date width may differ.
    let mime_bytes =
        baseline.len() + date.to_rfc822().len() - message.date().unwrap().to_rfc822().len();
    let mut config = fixture.configuration();
    config.limits.draft_mime_bytes = mime_bytes - 1;
    for grant in &mut config.grants {
        grant.limits.draft_mime_bytes = mime_bytes - 1;
    }
    fixture.configure(&config);
    let connections = fixture.server.accepted();
    assert_eq!(
        fixture.save(executable).await["error"]["code"],
        "response_too_large"
    );
    assert_eq!(
        fixture.status(executable, false).await["result"]["state"],
        "prepared"
    );
    assert_eq!(history::rows(&fixture), prepared_rows);
    assert_eq!(prepared_rows.len(), 2);
    assert_eq!(fixture.server.accepted(), connections);
    assert_eq!(fixture.server.interrupted(), 1);

    config.limits.draft_mime_bytes = mime_bytes;
    for grant in &mut config.grants {
        grant.limits.draft_mime_bytes = mime_bytes;
    }
    fixture.configure(&config);
    fixture
        .server
        .expect_append(server::DraftReply::Created(true));
    let exact = fixture.save(executable).await;
    assert_eq!(exact["result"]["state"], "created");
    let drafts = fixture.server.drafts();
    assert_eq!(drafts.len(), 2);
    let bytes = &drafts[1];
    assert_eq!(bytes.len(), config.limits.draft_mime_bytes);
    let message_at_limit = mail_parser::MessageParser::default().parse(bytes).unwrap();
    assert_eq!(message_at_limit.to(), message.to());
    assert_eq!(message_at_limit.cc(), message.cc());
    assert_eq!(message_at_limit.bcc(), message.bcc());
    assert_eq!(message_at_limit.body_text(0), message.body_text(0));
    assert_eq!(
        message_at_limit.message_id(),
        Some(
            format!(
                "{}.1.{}@mailctl.invalid",
                fixture.input["account_id"].as_str().unwrap(),
                fixture.input["operation_id"].as_str().unwrap()
            )
            .as_str()
        )
    );
    assert_eq!(history::rows(&fixture).len(), 2);

    assert_eq!(fixture.server.interrupted(), 2);
    fixture.server.finish();
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn cli_composition_rejection_and_recipient_mime_ceilings_precede_dispatch() {
    public_composition_boundaries(support::MAILCTL).await;
}

#[cfg(feature = "mcp")]
#[tokio::test]
async fn mcp_composition_rejection_and_recipient_mime_ceilings_precede_dispatch() {
    public_composition_boundaries(support::MAILCTL_MCP).await;
}
