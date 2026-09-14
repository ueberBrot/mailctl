fn main() -> std::process::ExitCode {
    mailctl::frontends::run_with_environment(
        mailctl::frontends::Executable::Cli,
        std::sync::Arc::new(mailctl_process_tests::FixtureHost),
    )
}
