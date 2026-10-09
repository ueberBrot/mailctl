//! Disposable native helper for command-source acceptance; never a production target.
use std::{
    io::{Read, Write},
    time::Duration,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args[1].as_str() {
        "file" => {
            std::io::stdout()
                .write_all(&std::fs::read(&args[2]).unwrap())
                .unwrap();
        }
        "context" => {
            assert_eq!(std::env::vars_os().count(), 0);
            assert_eq!(
                std::env::current_dir().unwrap(),
                std::path::Path::new(&args[2])
            );
            assert_eq!(args[3], "$(touch injected); * $HOME");
            assert_eq!(std::io::stdin().read(&mut [0]).unwrap(), 0);
            #[cfg(unix)]
            if let Some(descriptor) = args.get(4) {
                assert!(std::fs::metadata(format!("/dev/fd/{descriptor}")).is_err());
            }
            print!("disposable-password\r\n");
        }
        "stderr" => {
            std::io::stderr()
                .write_all(&vec![b'x'; args[2].parse().unwrap()])
                .unwrap();
            print!("disposable-password");
        }
        "streams" => {
            let stdout: usize = args[2].parse().unwrap();
            let stderr: usize = args[3].parse().unwrap();
            let mut written_stdout = 0;
            let mut written_stderr = 0;
            while written_stdout < stdout || written_stderr < stderr {
                let count = (stdout - written_stdout).min(1024);
                std::io::stdout().write_all(&vec![b'x'; count]).unwrap();
                written_stdout += count;
                let count = (stderr - written_stderr).min(1024);
                std::io::stderr().write_all(&vec![b'x'; count]).unwrap();
                written_stderr += count;
            }
        }
        "fail" => {
            eprintln!("private-command-error-secret");
            print!("private-command-output-secret");
            std::process::exit(7);
        }
        "hang" => {
            std::thread::sleep(Duration::from_secs(120));
        }
        "descendant" => {
            #[allow(
                clippy::zombie_processes,
                reason = "fixture intentionally leaves descendants for production cleanup"
            )]
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("hang")
                .spawn()
                .unwrap();
            std::fs::write(&args[2], format!("{} {}", std::process::id(), child.id())).unwrap();
            match args.get(3).map(String::as_str) {
                Some("stdout") => std::io::stdout().write_all(&[b'x'; 128]).unwrap(),
                Some("stderr") => std::io::stderr().write_all(&[b'x'; 128]).unwrap(),
                Some("exit") => return,
                _ => (),
            }
            std::io::stdout().flush().unwrap();
            std::io::stderr().flush().unwrap();
            std::thread::sleep(Duration::from_secs(120));
        }
        _ => panic!("unknown fixture mode"),
    }
}
