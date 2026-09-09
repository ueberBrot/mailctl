#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    mailctl::isolation::run_server()
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("mailctl-isolated: unsupported platform");
    std::process::ExitCode::from(8)
}
