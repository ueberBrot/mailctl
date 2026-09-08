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
