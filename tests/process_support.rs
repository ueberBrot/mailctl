mod support;

use std::{io::Write, process::Command};

#[test]
fn bounded_process_drains_stdout_and_stderr_before_waiting() {
    const CHILD: &str = "MAILCTL_PROCESS_OUTPUT_FIXTURE";
    const BYTES: usize = 256 * 1024;
    if std::env::var_os(CHILD).is_some() {
        std::io::stdout().write_all(&vec![b'X'; BYTES]).unwrap();
        std::io::stderr().write_all(&vec![b'Y'; BYTES]).unwrap();
        return;
    }

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "bounded_process_drains_stdout_and_stderr_before_waiting",
            "--nocapture",
        ])
        .env(CHILD, "1");
    let output = support::run_bounded(command);
    support::assert_success(&output);
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'X').count(),
        BYTES
    );
    assert_eq!(
        output.stderr.iter().filter(|&&byte| byte == b'Y').count(),
        BYTES
    );
}
