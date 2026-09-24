mod imap_support;
use imap_support::Client;
mod host_support;
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
        use mailctl::imap::{Limits, TlsMode};

        let mut fixture = greenmail_support::Fixture::start().await?;
        let content_before = fixture.contents().await?;
        let snapshot_before = fixture.snapshot().await?;
        assert_eq!(snapshot_before.messages.len(), 2);
        assert!(snapshot_before.messages.iter().any(|message| message.seen));
        assert!(snapshot_before.messages.iter().any(|message| !message.seen));

        let mut probe = Client::new(
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
        assert_eq!(discovery.len(), 1);
        assert_eq!(discovery[0].name, "INBOX");
        assert!(discovery[0].selectable);

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
            .search_window(
                "fixture+smoke@example.test",
                "disposable-fixture-password",
                "INBOX",
                snapshot_before.uid_validity,
                first..=last,
            )
            .await?;
        assert_eq!(search.position.uid_validity, snapshot_before.uid_validity);
        assert_eq!(search.messages.len(), snapshot_before.messages.len());
        for message in &snapshot_before.messages {
            let envelope = search
                .messages
                .iter()
                .find(|envelope| envelope.uid == message.uid)
                .expect("search retains observed UID identity");
            assert_eq!(
                envelope.metadata.message_id.value().map(String::as_str),
                Some(message.message_id.as_str())
            );
            assert_eq!(
                envelope.metadata.subject.value().map(String::as_str),
                Some(message.subject.as_str())
            );
            assert_eq!(
                envelope
                    .metadata
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
            config::Config,
            domain::{ListMailboxesInput, Operation, OperationResult, SearchMessagesInput},
            service::Service,
        };

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
        let service = Service::in_memory(configuration)?.with_environment(host_support::Host::new(
            fixture.tls_roots(),
            b"disposable-fixture-password",
        ));
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
                        cursor: None,
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
            if id == "<large-attachment-body@example.test>" {
                use base64::{Engine, engine::general_purpose::STANDARD};
                use mailctl::domain::{
                    AttachmentContinuation, AttachmentProgress, AttachmentStart,
                    GetAttachmentInput, ListAttachmentsInput,
                };
                let OperationResult::Attachments(list) = service
                    .execute(
                        &context,
                        Operation::ListAttachments(ListAttachmentsInput {
                            message: page.messages[0].reference.clone(),
                        }),
                    )
                    .await?
                else {
                    panic!("attachments")
                };
                assert_eq!(list.attachments.len(), 1);
                let mut input = GetAttachmentInput::Start(AttachmentStart {
                    attachment: list.attachments[0].reference.clone(),
                });
                let mut downloaded = Vec::new();
                loop {
                    let OperationResult::Attachment(chunk) = service
                        .execute(&context, Operation::GetAttachment(input))
                        .await?
                    else {
                        panic!("chunk")
                    };
                    assert_eq!(chunk.decoded_offset, downloaded.len() as u64);
                    downloaded.extend(STANDARD.decode(&chunk.bytes_base64)?);
                    match chunk.progress {
                        AttachmentProgress::Continue { next_token } => {
                            input = GetAttachmentInput::Continue(AttachmentContinuation {
                                token: next_token,
                            })
                        }
                        AttachmentProgress::Complete {
                            total_decoded_bytes,
                            sha256,
                        } => {
                            use sha2::{Digest, Sha256};
                            assert_eq!(total_decoded_bytes, downloaded.len() as u64);
                            assert_eq!(
                                sha256,
                                Sha256::digest(greenmail_support::large_attachment_bytes())
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<String>()
                            );
                            break;
                        }
                    }
                }
                assert_eq!(downloaded, greenmail_support::large_attachment_bytes());
            }

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
        use mailctl::imap::{BodyRequest, Limits, TlsMode};

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
        let mut probe = Client::new(
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

        let mut probe = Client::new(
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
        use mailctl::imap::{AttachmentDecoder, AttachmentListRequest, Limits, TlsMode};
        use sha2::{Digest, Sha256};

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

        let mut probe = Client::new(
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
        assert!(probe.metrics().wire_bytes < 64 * 1024);
        assert_eq!(listed.len(), 1);
        let attachment = &listed[0];
        assert_eq!(attachment.part, "2");
        assert_eq!(attachment.filename.as_deref(), Some("large.bin"));
        assert_eq!(attachment.media_type, "application/octet-stream");
        assert!(attachment.declared_size.is_some());
        assert!(attachment.available);

        let mut decoder = AttachmentDecoder::new(
            "INBOX",
            multipart_uid,
            snapshot_before.uid_validity,
            &attachment.part,
            &Limits::default(),
        )?;
        let mut received = Vec::with_capacity(expected.len());
        let mut final_digest = None;
        // The route may fetch a smaller encoded wire slice than the decoded output ceiling;
        // leave room for the pinned 16 KiB wire fetches and base64 expansion.
        for _ in 0..256 {
            let chunk = probe
                .read_attachment(
                    "fixture+smoke@example.test",
                    "disposable-fixture-password",
                    &mut decoder,
                )
                .await?;
            assert_eq!(chunk.decoded_offset, received.len() as u64);
            assert!(!chunk.bytes.is_empty());
            assert!(chunk.bytes.len() <= Limits::default().max_attachment_chunk_bytes);
            let end = received.len() + chunk.bytes.len();
            assert_eq!(chunk.bytes, expected[received.len()..end]);
            received.extend_from_slice(&chunk.bytes);
            if let Some(integrity) = chunk.integrity {
                assert_eq!(received.len(), expected.len());
                assert_eq!(integrity.total_decoded_bytes, expected.len() as u64);
                assert_eq!(integrity.sha256, expected_digest);
                final_digest = Some(integrity.sha256);
                break;
            };
        }
        assert_eq!(received, expected);
        assert_eq!(final_digest, Some(Sha256::digest(&received).into()));
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
        use mailctl::{
            draft::{DraftInput, PreparedDraft},
            imap::{AppendOutcome, Limits, TlsMode},
        };

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
        let mut probe = Client::new(
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
        let AppendOutcome::Created { uid } = result else {
            panic!("APPEND was not acknowledged: {:?}", result);
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
            config::Config,
            domain::{ListMailboxesInput, Operation, OperationResult},
            policy::Narrowing,
            service::Service,
        };

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
        let service = Service::in_memory(config)?.with_environment(host_support::Host::new(
            fixture.tls_roots(),
            b"disposable-fixture-password",
        ));
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

mod support;
#[test]
fn application_draft_retries_create_one_exact_draft_and_preserve_existing_mail() {
    greenmail_support::run(async {
        use mailctl::{
            config::Config,
            domain::{DraftContent, DraftStatusInput, Operation, OperationResult, SaveDraftInput},
            service::Service,
        };
        const TARGET: &str = "fixture folder/child";
        let fixture = greenmail_support::Fixture::start().await?;
        fixture.verify_folder_path_encoding().await?;
        let inbox = fixture.snapshot().await?;
        let inbox_contents = fixture.contents().await?;
        let target = fixture.snapshot_mailbox(TARGET).await?;
        let target_contents = fixture.contents_mailbox(TARGET).await?;
        let installation = support::Installation::two_accounts();
        let mut config = Config::parse(&std::fs::read_to_string(installation.config())?)?;
        config.accounts[0].server = "localhost".into();
        config.accounts[0].port = fixture.imaps_port();
        config.accounts[0].username = "fixture+smoke@example.test".into();
        config.accounts[0].from_identities = vec!["sender@example.test".into()];
        config.accounts[0].mailboxes = vec!["INBOX".into(), TARGET.into()];
        config.accounts[0].drafts_mailbox = Some(TARGET.into());
        config
            .grants
            .iter_mut()
            .find(|g| g.name == "writer")
            .unwrap()
            .mailboxes = vec![TARGET.into()];
        Service::setup(config.clone())?;
        let service = Service::open(config.clone())?.with_environment(host_support::Host::new(
            fixture.tls_roots(),
            b"disposable-fixture-password",
        ));
        let context = service.context("writer", &Default::default())?;
        let OperationResult::Accounts(accounts) = service
            .execute(&context, Operation::ListAccounts(Default::default()))
            .await?
        else {
            panic!()
        };
        let input = SaveDraftInput {
            mailbox: TARGET.into(),
            account_id: accounts.accounts[0].account_id.parse()?,
            account_generation: accounts.accounts[0].generation,
            operation_id: uuid::Uuid::new_v4(),
            draft: Box::new(DraftContent {
                subject: "Synthetic unsent draft".into(),
                body: "Synthetic draft body.".into(),
                bcc: vec!["hidden@example.test".into()],
                ..Default::default()
            }),
        };
        let prepared = serde_json::to_value(
            service
                .execute(&context, Operation::SaveDraft(input.clone()))
                .await?,
        )?;
        assert!(matches!(
            prepared["state"].as_str(),
            Some("created" | "created_reference_unavailable")
        ));
        assert_eq!(prepared["dispatched"], true);
        let journal = mailctl::draft_journal::DraftJournal::open_existing(
            config.state_dir.join("drafts.sqlite"),
        )?;
        let record = journal.inspect(&input.identity())?.unwrap();
        assert!(matches!(
            record.state,
            mailctl::draft_journal::DraftOperationState::Created { .. }
        ));
        let id = format!(
            "{}.{}.{}@mailctl.invalid",
            input.account_id, input.account_generation, input.operation_id
        );
        let expected = mailctl::draft::PreparedDraft::compose(
            mailctl::draft::DraftInput {
                from: "sender@example.test".into(),
                subject: input.draft.subject.clone(),
                body: input.draft.body.clone(),
                bcc: input.draft.bcc.clone(),
                message_id: id.clone(),
                date_unix: record.operation.reconstruction.unwrap().date_unix,
                ..Default::default()
            },
            config.limits.draft_mime_bytes,
        )?;
        drop(journal);
        drop(service);
        // Restart with no provider credentials: status and identical retry remain local.
        let service = Service::open(config)?;
        let context = service.context("writer", &Default::default())?;
        let status = DraftStatusInput {
            mailbox: TARGET.into(),
            account_id: input.account_id,
            account_generation: input.account_generation,
            operation_id: input.operation_id,
            reconcile: false,
        };
        assert_eq!(
            serde_json::to_value(
                service
                    .execute(&context, Operation::DraftStatus(status))
                    .await?
            )?,
            prepared
        );
        assert_eq!(
            serde_json::to_value(
                service
                    .execute(&context, Operation::SaveDraft(input))
                    .await?
            )?,
            prepared
        );
        assert_eq!(fixture.snapshot().await?, inbox);
        assert_eq!(fixture.contents().await?, inbox_contents);
        let after = fixture.snapshot_mailbox(TARGET).await?;
        assert_eq!(after.messages.len(), target.messages.len() + 1);
        assert_eq!(after.uid_validity, target.uid_validity);
        for original in target.messages {
            assert!(after.messages.contains(&original));
        }
        let observed = after
            .messages
            .iter()
            .find(|m| m.message_id == format!("<{id}>"))
            .unwrap();
        assert!(observed.draft);
        assert!(!observed.seen);
        let contents = fixture.contents_mailbox(TARGET).await?;
        assert_eq!(contents.len(), target_contents.len() + 1);
        for original in target_contents {
            assert!(contents.contains(&original));
        }
        let stored = contents
            .iter()
            .find(|m| m.message_id == format!("<{id}>"))
            .unwrap();
        assert_eq!(stored.mime_message.as_bytes(), expected.bytes());
        drop(service);
        fixture.shutdown().await?;
        Ok(())
    });
}
