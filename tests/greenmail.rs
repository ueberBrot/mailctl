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

        let probe = ImapProbe::new(
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
