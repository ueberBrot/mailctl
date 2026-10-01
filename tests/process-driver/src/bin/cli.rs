fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    #[allow(
        unsafe_code,
        reason = "Reproduce inherited Ctrl+C suppression before entering the production lifecycle"
    )]
    if std::env::var_os("MAILCTL_FIXTURE_IGNORE_CTRL_C").is_some() {
        assert_ne!(
            unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 1) },
            0
        );
    }
    mailctl::frontends::run_with_environment(
        mailctl::frontends::Executable::Cli,
        std::sync::Arc::new(mailctl_process_tests::FixtureHost),
    )
}
