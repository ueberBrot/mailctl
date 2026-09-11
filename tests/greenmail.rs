#[test]
fn owned_fixture_authenticates_seeds_resets_and_cleans_up_twice() {
    greenmail_support::run(async {
        for _ in 0..2 {
            let mut fixture = greenmail_support::Fixture::start().await?;
            fixture.verify_folder_path_encoding().await?;
            fixture.purge().await?;
            fixture.verify_empty().await?;
            fixture.reset().await?;
            fixture.delete_user().await?;
            fixture.shutdown().await?;
        }
        Ok(())
    });
}

#[test]
fn imap_discovery_and_search_preserve_mailbox_content_identity_and_flags() {
    greenmail_support::run(async {
        use mailctl::imap::{ImapProbe, Limits, TlsMode, UidWindow};

        let mut fixture = greenmail_support::Fixture::start().await?;
        let content_before = fixture.contents().await?;
        let snapshot_before = fixture.snapshot().await?;
        assert_eq!(snapshot_before.messages.len(), 2);
        assert!(snapshot_before.messages.iter().any(|message| message.seen));
        assert!(snapshot_before.messages.iter().any(|message| !message.seen));

        let mut probe = ImapProbe::new(
            "localhost".to_owned(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            Limits::default(),
        )?;
        let discovery = probe
            .discover(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                &["INBOX".to_owned()],
            )
            .await?;
        assert_eq!(discovery.mailboxes.len(), 1);
        assert_eq!(discovery.mailboxes[0].name, "INBOX");
        assert!(discovery.mailboxes[0].selectable);

        let first = snapshot_before
            .messages
            .first()
            .expect("fixture has messages")
            .uid;
        let last = snapshot_before
            .messages
            .last()
            .expect("fixture has messages")
            .uid;
        let search = probe
            .search(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                "INBOX",
                UidWindow { first, last },
            )
            .await?;
        assert_eq!(search.uid_validity, snapshot_before.uid_validity);
        assert_eq!(search.envelopes.len(), snapshot_before.messages.len());
        for message in &snapshot_before.messages {
            let envelope = search
                .envelopes
                .iter()
                .find(|envelope| envelope.uid == message.uid)
                .expect("search retains observed UID identity");
            assert_eq!(
                envelope.message_id.as_deref(),
                Some(message.message_id.as_str())
            );
            assert_eq!(envelope.subject.as_deref(), Some(message.subject.as_str()));
            assert_eq!(
                envelope
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
                message.seen
            );
        }

        assert_eq!(fixture.snapshot().await?, snapshot_before);
        assert_eq!(fixture.contents().await?, content_before);
        fixture.delete_user().await?;
        fixture.shutdown().await?;
        Ok(())
    });
}

#[test]
fn application_search_pages_and_predicates_preserve_independently_observed_mailbox_state() {
    greenmail_support::run(async {
        use mailctl::{
            authentication::Runtime,
            config::Config,
            credentials::{Availability, Secret, SecretSource, SourceError},
            domain::{ListMailboxesInput, Operation, OperationResult, SearchMessagesInput},
            service::{ImapBackend, Service},
        };
        use std::{collections::BTreeMap, sync::Arc};
        struct FixtureSecret;
        impl SecretSource for FixtureSecret {
            fn availability(&self, _: uuid::Uuid) -> Availability {
                Availability::Available
            }
            fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
                Secret::new(b"disposable-fixture-password".to_vec())
            }
        }
        let mut fixture = greenmail_support::Fixture::start().await?;
        fixture.seed_multipart_with_large_attachment().await?;
        let before = fixture.snapshot().await?;
        let contents = fixture.contents().await?;
        let configuration = Config::parse(&format!(
            r#"
version = 1
default_grant = "reader"
state_dir = {state}
[[accounts]]
key = "fixture"
alias = "fixture"
server = "localhost"
port = {port}
username = "fixture+smoke@example.test"
mailboxes = ["INBOX"]
from_identities = ["fixture"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["fixture"]
mailboxes = ["INBOX"]
"#,
            state = serde_json::to_string(&std::env::temp_dir().join("mailctl-greenmail-search"))?,
            port = fixture.imaps_port()
        ))?;
        let runtime =
            Arc::new(Runtime::new(configuration.limits.clone(), fixture.tls_roots()).unwrap());
        let sources = BTreeMap::from([(
            "fixture".into(),
            Arc::new(FixtureSecret) as Arc<dyn SecretSource>,
        )]);
        let backend = Arc::new(ImapBackend::new(runtime, sources));
        let service = Service::in_memory(configuration)?
            .with_mailbox_backend(backend.clone())
            .with_search_backend(backend.clone())
            .with_body_backend(backend);
        let context = service.context("reader", &Default::default())?;
        let OperationResult::Mailboxes(discovery) = service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput::default()),
            )
            .await?
        else {
            panic!("mailbox discovery")
        };
        let mailbox = discovery.mailboxes[0].reference.clone();
        let mut cursor = None;
        let mut identifiers = Vec::new();
        loop {
            let OperationResult::Messages(page) = service
                .execute(
                    &context,
                    Operation::SearchMessages(SearchMessagesInput {
                        mailbox: mailbox.clone(),
                        criteria: Default::default(),
                        limit: Some(1),
                        cursor,
                    }),
                )
                .await?
            else {
                panic!("search")
            };
            assert_eq!(
                page.messages.len(),
                1,
                "page={page:?}, before={before:?}, returned={identifiers:?}"
            );
            let metadata = &page.messages[0].metadata;
            let id = metadata.message_id.value().unwrap();
            let observed = before
                .messages
                .iter()
                .find(|message| &message.message_id == id)
                .unwrap();
            assert_eq!(metadata.subject.value(), Some(&observed.subject));
            assert_eq!(
                metadata.flags.iter().any(|flag| flag == "\\Seen"),
                observed.seen
            );
            let OperationResult::Message(body) = service
                .execute(
                    &context,
                    Operation::GetMessage(mailctl::domain::GetMessageInput {
                        message: page.messages[0].reference.clone(),
                    }),
                )
                .await?
            else {
                panic!("body")
            };
            let expected = match id.as_str() {
                "<large-attachment-body@example.test>" => "Synthetic multipart body.",
                "<observed-seen@example.test>" => "Synthetic seen message.",
                "<bootstrap-smoke@example.test>" => "Synthetic bootstrap message.",
                _ => panic!("unexpected fixture"),
            };
            assert_eq!(body.body.text, expected);
            assert!(!body.body.truncated);
            identifiers.push(id.clone());
            if page.complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = Some(page.next_cursor.expect("incomplete page keeps its cursor"));
        }
        assert_eq!(
            identifiers,
            before
                .messages
                .iter()
                .rev()
                .map(|message| message.message_id.clone())
                .collect::<Vec<_>>()
        );
        for (field, flag, expected) in [
            ("required_flag", "seen", "<observed-seen@example.test>"),
            ("forbidden_flag", "seen", "<bootstrap-smoke@example.test>"),
        ] {
            let criteria = serde_json::from_value(serde_json::json!([
                {"field":field,"flag":flag}, {"field":"from","value":"sender@example.test"},
                {"field":"text","value":"Synthetic"}, {"field":"received_after","date":"2000-01-01"},
                {"field":"subject","value": if field == "required_flag" { "Observed seen" } else { "Bootstrap smoke" }}
            ]))?;
            let OperationResult::Messages(page) = service
                .execute(
                    &context,
                    Operation::SearchMessages(SearchMessagesInput {
                        mailbox: mailbox.clone(),
                        criteria,
                        limit: None,
                        cursor: None,
                    }),
                )
                .await?
            else {
                panic!("search")
            };
            assert_eq!(page.messages.len(), 1);
            assert_eq!(
                page.messages[0]
                    .metadata
                    .message_id
                    .value()
                    .map(String::as_str),
                Some(expected)
            );
        }
        assert_eq!(fixture.snapshot().await?, before);
        assert_eq!(fixture.contents().await?, contents);
        fixture.delete_user().await?;
        fixture.shutdown().await?;
        Ok(())
    });
}

#[test]
fn imap_body_reads_selected_text_without_downloading_a_large_attachment() {
    greenmail_support::run(async {
        use mailctl::imap::{BodyRequest, ImapProbe, Limits, TlsMode};

        const MULTIPART_MESSAGE_ID: &str = "<large-attachment-body@example.test>";
        // GreenMail 2.1.13 trims selected-part whitespace before serving it.
        // Exact whitespace preservation is covered by the independent transcripts.
        const MULTIPART_BODY: &str = "Synthetic multipart body.";

        let fixture = greenmail_support::Fixture::start().await?;
        fixture.seed_multipart_with_large_attachment().await?;
        let contents_before = fixture.contents().await?;
        let snapshot_before = fixture.snapshot().await?;
        let multipart = contents_before
            .iter()
            .find(|message| message.message_id == MULTIPART_MESSAGE_ID)
            .expect("fixture seeds the multipart message");
        assert!(multipart.mime_message.len() > 2 * 1024 * 1024);
        let multipart_uid = multipart.uid.parse::<u32>()?;
        assert_eq!(snapshot_before.messages.len(), 3);

        let limits = Limits {
            max_text_bytes: 4,
            ..Limits::default()
        };
        let mut probe = ImapProbe::new(
            "localhost".to_owned(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            limits,
        )?;
        let mut continuation = None;
        let mut text = String::new();
        let mut selected_part = None;
        let mut source_media_type = None;
        for _ in 0..16 {
            let mut request = BodyRequest::new(multipart_uid, snapshot_before.uid_validity);
            request.continuation = continuation;
            let page = probe
                .read_body(
                    "fixture+smoke@example.test",
                    "disposable-fixture-password",
                    "INBOX",
                    request,
                )
                .await?;
            assert!(page.metrics.wire_bytes < 64 * 1024);
            assert!(page.metrics.max_literal_bytes < 64 * 1024);
            if let Some(part) = &selected_part {
                assert_eq!(page.selected_part.as_ref(), Some(part));
            } else {
                selected_part = page.selected_part.clone();
            }
            if let Some(media_type) = &source_media_type {
                assert_eq!(page.source_media_type.as_ref(), Some(media_type));
            } else {
                source_media_type = page.source_media_type.clone();
            }
            text.push_str(&page.text);
            continuation = page.continuation;
            if continuation.is_none() {
                break;
            }
        }
        assert_eq!(text, MULTIPART_BODY);
        assert_eq!(selected_part.as_deref(), Some("1.1"));
        assert_eq!(source_media_type.as_deref(), Some("text/plain"));

        let mut probe = ImapProbe::new(
            "localhost".to_owned(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            Limits::default(),
        )?;

        for message in snapshot_before
            .messages
            .iter()
            .filter(|message| message.uid != multipart_uid)
        {
            let page = probe
                .read_body(
                    "fixture+smoke@example.test",
                    "disposable-fixture-password",
                    "INBOX",
                    BodyRequest::new(message.uid, snapshot_before.uid_validity),
                )
                .await?;
            let expected = if message.seen {
                "Synthetic seen message."
            } else {
                "Synthetic bootstrap message."
            };
            assert_eq!(page.text, expected);
            assert!(page.continuation.is_none());
            assert_eq!(page.selected_part.as_deref(), Some("1"));
            assert_eq!(page.source_media_type.as_deref(), Some("text/plain"));
            assert!(page.metrics.wire_bytes < 64 * 1024);
        }

        assert_eq!(fixture.snapshot().await?, snapshot_before);
        assert_eq!(fixture.contents().await?, contents_before);
        fixture.shutdown().await?;
        Ok(())
    });
}

#[test]
fn imap_attachment_listing_and_chunks_preserve_exact_base64_decoded_data() {
    greenmail_support::run(async {
        use mailctl::imap::{
            AttachmentListRequest, AttachmentProgress, AttachmentRequest, Error, ImapProbe, Limits,
            TlsMode,
        };
        use sha2::{Digest, Sha256};
        use std::time::Duration;

        const MULTIPART_MESSAGE_ID: &str = "<large-attachment-body@example.test>";

        let fixture = greenmail_support::Fixture::start().await?;
        fixture.seed_multipart_with_large_attachment().await?;
        let contents_before = fixture.contents().await?;
        let snapshot_before = fixture.snapshot().await?;
        let multipart = contents_before
            .iter()
            .find(|message| message.message_id == MULTIPART_MESSAGE_ID)
            .expect("fixture seeds the multipart message");
        let multipart_uid = multipart.uid.parse::<u32>()?;
        let expected = greenmail_support::large_attachment_bytes();
        let expected_digest: [u8; 32] = Sha256::digest(&expected).into();
        assert!(multipart.mime_message.len() > 2 * 1024 * 1024);
        assert!(
            multipart
                .mime_message
                .contains("Content-Transfer-Encoding: base64")
        );

        let mut probe = ImapProbe::new(
            "localhost".to_owned(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            Limits::default(),
        )?;
        let listed = probe
            .list_attachments(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                "INBOX",
                AttachmentListRequest {
                    uid: multipart_uid,
                    uid_validity: snapshot_before.uid_validity,
                },
            )
            .await?;
        // Listing is a metadata route: its response must not include the multi-megabyte
        // encoded payload that a full message fetch would contain.
        assert!(listed.metrics.wire_bytes < 64 * 1024);
        assert_eq!(listed.attachments.len(), 1);
        let attachment = &listed.attachments[0];
        assert_eq!(attachment.part, "2");
        assert_eq!(attachment.filename.as_deref(), Some("large.bin"));
        assert_eq!(attachment.media_type, "application/octet-stream");
        assert!(attachment.declared_size.is_some());
        assert!(attachment.available);

        // A partial transfer can be explicitly cancelled and frees its session-local state.
        let cancelled = probe
            .read_attachment(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                "INBOX",
                AttachmentRequest::new(
                    multipart_uid,
                    snapshot_before.uid_validity,
                    attachment.part.clone(),
                ),
            )
            .await?;
        let AttachmentProgress::Continue(cancelled) = cancelled.progress else {
            panic!("expected continuation");
        };
        probe.cancel_attachment(cancelled)?;
        assert_eq!(probe.metrics().active_transfers, 0);

        let mut request = AttachmentRequest::new(
            multipart_uid,
            snapshot_before.uid_validity,
            attachment.part.clone(),
        );
        let mut received = Vec::with_capacity(expected.len());
        let mut final_digest = None;
        // The route may fetch a smaller encoded wire slice than the decoded output ceiling;
        // leave room for the pinned 16 KiB wire fetches and base64 expansion.
        for _ in 0..256 {
            let chunk = probe
                .read_attachment(
                    "fixture+smoke@example.test",
                    "disposable-fixture-password",
                    "INBOX",
                    request,
                )
                .await?;
            assert_eq!(chunk.decoded_offset, received.len() as u64);
            assert!(!chunk.bytes.is_empty());
            assert!(chunk.bytes.len() <= Limits::default().max_attachment_chunk_bytes);
            let end = received.len() + chunk.bytes.len();
            assert_eq!(chunk.bytes, expected[received.len()..end]);
            received.extend_from_slice(&chunk.bytes);
            if let AttachmentProgress::Complete(integrity) = chunk.progress {
                assert_eq!(received.len(), expected.len());
                assert_eq!(integrity.total_decoded_bytes, expected.len() as u64);
                assert_eq!(integrity.sha256, expected_digest);
                final_digest = Some(integrity.sha256);
                break;
            }
            let AttachmentProgress::Continue(token) = chunk.progress else {
                unreachable!();
            };
            request = AttachmentRequest::resume(token);
        }
        assert_eq!(received, expected);
        assert_eq!(final_digest, Some(Sha256::digest(&received).into()));
        assert_eq!(probe.metrics().active_transfers, 0);

        // Expired opaque transfers cannot be revived and must release their retained state.
        let mut expiring_probe = ImapProbe::new(
            "localhost".to_owned(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            Limits {
                max_transfer_lifetime: Duration::from_secs(1),
                ..Limits::default()
            },
        )?;
        let incomplete = expiring_probe
            .read_attachment(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                "INBOX",
                AttachmentRequest::new(
                    multipart_uid,
                    snapshot_before.uid_validity,
                    attachment.part.clone(),
                ),
            )
            .await?;
        let AttachmentProgress::Continue(expired) = incomplete.progress else {
            panic!("expected continuation");
        };
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(matches!(
            expiring_probe
                .read_attachment(
                    "fixture+smoke@example.test",
                    "disposable-fixture-password",
                    "INBOX",
                    AttachmentRequest::resume(expired),
                )
                .await,
            Err(Error::TransferExpired)
        ));
        assert_eq!(expiring_probe.metrics().active_transfers, 0);

        // Both the administrative API and a fresh non-mutating IMAP observer must
        // agree that listing/streaming did not alter UIDVALIDITY, UID identity,
        // raw content, or the independent seen/unseen observations.
        assert_eq!(fixture.snapshot().await?, snapshot_before);
        assert_eq!(fixture.contents().await?, contents_before);
        fixture.shutdown().await?;
        Ok(())
    });
}

#[test]
fn imap_append_creates_exact_draft_in_existing_target_without_changing_inbox() {
    greenmail_support::run(async {
        use mailctl::imap::{AppendOutcome, DraftInput, ImapProbe, Limits, PreparedDraft, TlsMode};

        const TARGET: &str = "fixture folder/child";
        const ID: &str = "append-proof@example.test";
        let fixture = greenmail_support::Fixture::start().await?;
        fixture.verify_folder_path_encoding().await?;
        let inbox = fixture.snapshot().await?;
        let inbox_contents = fixture.contents().await?;
        let target = fixture.snapshot_mailbox(TARGET).await?;
        let target_contents = fixture.contents_mailbox(TARGET).await?;
        let draft = PreparedDraft::compose(
            DraftInput {
                from: "sender@example.test".into(),
                to: vec!["recipient@example.test".into()],
                cc: vec!["copy@example.test".into()],
                bcc: vec!["private@example.test".into()],
                subject: "Unsent draft proof".into(),
                body: "Synthetic unsent draft.\nSecond line.".into(),
                message_id: ID.into(),
                date_unix: 1_700_000_000,
                ..DraftInput::default()
            },
            64 * 1024,
        )?;
        let mut probe = ImapProbe::new(
            "localhost".into(),
            fixture.imaps_port(),
            TlsMode::Implicit,
            fixture.tls_roots(),
            Limits::default(),
        )?;
        let result = probe
            .append_draft(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                TARGET,
                &draft,
            )
            .await?;
        let AppendOutcome::Created { uid } = result.outcome else {
            panic!("APPEND was not acknowledged: {:?}", result.outcome);
        };
        let after = fixture.snapshot_mailbox(TARGET).await?;
        assert_eq!(after.uid_validity, target.uid_validity);
        assert_eq!(after.messages.len(), target.messages.len() + 1);
        let observed = after
            .messages
            .iter()
            .find(|message| message.message_id == format!("<{ID}>"))
            .unwrap();
        assert!(observed.draft);
        assert!(!observed.seen);
        if let Some(uid) = uid {
            assert_eq!(uid.uid_validity, after.uid_validity);
            assert_eq!(uid.uid, observed.uid);
        }
        for original in &target.messages {
            assert!(after.messages.contains(original));
        }
        let contents = fixture.contents_mailbox(TARGET).await?;
        assert_eq!(contents.len(), target_contents.len() + 1);
        for original in &target_contents {
            assert!(contents.contains(original));
        }
        let stored = contents
            .iter()
            .find(|message| message.message_id == format!("<{ID}>"))
            .unwrap();
        assert_eq!(stored.mime_message.as_bytes(), draft.bytes());
        let parsed = mail_parser::MessageParser::default()
            .parse(stored.mime_message.as_bytes())
            .unwrap();
        assert_eq!(
            parsed.bcc().unwrap().first().unwrap().address.as_deref(),
            Some("private@example.test")
        );
        assert_eq!(fixture.snapshot().await?, inbox);
        assert_eq!(fixture.contents().await?, inbox_contents);
        fixture.shutdown().await?;
        Ok(())
    });
}

#[test]
fn application_mailbox_discovery_and_reference_reuse_preserve_independently_observed_mail() {
    greenmail_support::run(async {
        use mailctl::{
            authentication::Runtime,
            config::Config,
            credentials::{Availability, Secret, SecretSource, SourceError},
            domain::{ListMailboxesInput, Operation, OperationResult},
            policy::Narrowing,
            service::{ImapBackend, Service},
        };
        use std::{collections::BTreeMap, sync::Arc};
        struct Source;
        impl SecretSource for Source {
            fn availability(&self, _: uuid::Uuid) -> Availability {
                Availability::Available
            }
            fn resolve(&self, _: uuid::Uuid) -> Result<Secret, SourceError> {
                Secret::new(b"disposable-fixture-password".to_vec())
            }
        }
        let fixture = greenmail_support::Fixture::start().await?;
        let contents = fixture.contents().await?;
        let snapshot = fixture.snapshot().await?;
        let config = Config::parse(&format!(
            r#"version = 1
default_grant = "reader"
state_dir = {state}
[[accounts]]
key = "fixture"
alias = "fixture"
server = "localhost"
port = {port}
username = "fixture+smoke@example.test"
mailboxes = ["INBOX"]
from_identities = ["fixture"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["fixture"]
mailboxes = ["INBOX"]
"#,
            state =
                serde_json::to_string(&std::env::temp_dir().join("mailctl-greenmail-application"))?,
            port = fixture.imaps_port()
        ))?;
        let runtime = Arc::new(Runtime::new(config.limits.clone(), fixture.tls_roots()).unwrap());
        let backend = ImapBackend::new(
            runtime,
            BTreeMap::from([("fixture".into(), Arc::new(Source) as Arc<dyn SecretSource>)]),
        );
        let service = Service::in_memory(config)?.with_mailbox_backend(Arc::new(backend));
        let context = service.context("reader", &Narrowing::default())?;
        let OperationResult::Mailboxes(first) = service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput::default()),
            )
            .await?
        else {
            panic!("mailboxes")
        };
        assert!(first.complete);
        assert_eq!(first.mailboxes.len(), 1);
        assert_eq!(first.mailboxes[0].metadata.name, "INBOX");
        let OperationResult::Mailboxes(resolved) = service
            .execute(
                &context,
                Operation::ListMailboxes(ListMailboxesInput {
                    reference: Some(first.mailboxes[0].reference.clone()),
                    ..Default::default()
                }),
            )
            .await?
        else {
            panic!("mailboxes")
        };
        assert_eq!(
            resolved.mailboxes[0].reference,
            first.mailboxes[0].reference
        );
        assert_eq!(fixture.snapshot().await?, snapshot);
        assert_eq!(fixture.contents().await?, contents);
        fixture.shutdown().await?;
        Ok(())
    });
}
