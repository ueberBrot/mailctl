use crate::Result;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName},
    },
};

pub(crate) const EMAIL: &str = "fixture+smoke@example.test";
pub(crate) const PASSWORD: &str = "disposable-fixture-password";
pub(crate) const MESSAGE_ID: &str = "<bootstrap-smoke@example.test>";
pub(crate) const FOLDER_MESSAGE_ID: &str = "<nested-folder@example.test>";
pub(crate) const BODY: &str = "Synthetic bootstrap message.";
pub(crate) const MESSAGE: &str = "From: sender@example.test\r\nTo: fixture+smoke@example.test\r\nMessage-ID: <bootstrap-smoke@example.test>\r\nSubject: Bootstrap smoke\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic bootstrap message.\r\n";

pub(crate) struct TlsInputs {
    pub keystore: Vec<u8>,
    pub connector: TlsConnector,
}

impl TlsInputs {
    pub async fn prepare() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let dir = directory.path();
        std::fs::write(dir.join("ca.cnf"), include_str!("../../fixtures/ca.cnf"))?;
        std::fs::write(
            dir.join("server.cnf"),
            include_str!("../../fixtures/server.cnf"),
        )?;
        for args in [
            "req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -config ca.cnf",
            "req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config server.cnf",
            "x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 2 -extfile server.cnf -extensions server",
            "pkcs12 -export -inkey server.key -in server.pem -certfile ca.pem -out server.p12 -passout pass:fixture-only",
            "x509 -in ca.pem -outform DER -out ca.der",
        ] {
            openssl(dir, args).await?;
        }
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(std::fs::read(dir.join("ca.der"))?))?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            keystore: std::fs::read(dir.join("server.p12"))?,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

async fn openssl(dir: &Path, args: &str) -> Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("openssl")
            .args(args.split_ascii_whitespace())
            .current_dir(dir)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "OpenSSL fixture preparation timed out")?
    .map_err(|_| "Docker tests require OpenSSL on PATH (see docs/development.md)")?;
    if !result.status.success() {
        return Err("OpenSSL fixture certificate preparation failed".into());
    }
    Ok(())
}

/// A bounded independent protocol observer, never a production email adapter.
struct Wire<S> {
    stream: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    async fn line(&mut self) -> Result<String> {
        let mut bytes = Vec::new();
        (&mut self.stream)
            .take(16 * 1024 + 1)
            .read_until(b'\n', &mut bytes)
            .await?;
        if bytes.len() > 16 * 1024 || !bytes.ends_with(b"\r\n") {
            return Err("Fixture protocol line exceeds bound or ended unexpectedly".into());
        }
        String::from_utf8(bytes).map_err(|_| "Fixture protocol response is not UTF-8".into())
    }

    async fn send(&mut self, text: &str) -> Result<()> {
        self.stream.get_mut().write_all(text.as_bytes()).await?;
        self.stream.get_mut().flush().await?;
        Ok(())
    }

    async fn imap(&mut self, command: &str, accepted: bool) -> Result<Vec<String>> {
        self.send(&format!("a1 {command}\r\n")).await?;
        let mut lines = Vec::new();
        for _ in 0..100 {
            let line = self.line().await?;
            if line.starts_with("a1 ") {
                let status = line.split_whitespace().nth(1);
                if status != Some(if accepted { "OK" } else { "NO" }) {
                    return Err(format!(
                        "Independent IMAP {} returned status {:?}; expected {}",
                        command.split_whitespace().next().unwrap_or("command"),
                        status,
                        if accepted { "OK" } else { "NO" }
                    )
                    .into());
                }
                return Ok(lines);
            }
            lines.push(line);
        }
        Err("Independent IMAP response count exceeded fixture budget".into())
    }

    async fn smtp_reply(&mut self, code: &str) -> Result<()> {
        for _ in 0..100 {
            let line = self.line().await?;
            if !line.starts_with(code) {
                return Err("SMTP fixture seeding failed".into());
            }
            if line.as_bytes().get(3) == Some(&b' ') {
                return Ok(());
            }
        }
        Err("SMTP fixture response count exceeded budget".into())
    }
}

pub(crate) async fn observe(
    port: u16,
    tls: &TlsConnector,
    password: &str,
    expected_login: bool,
    expected_messages: Option<usize>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = tls
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut wire = Wire::new(stream);
        if !wire.line().await?.starts_with("* OK") {
            return Err("IMAP greeting missing".into());
        }
        wire.imap(&format!("LOGIN \"{EMAIL}\" \"{password}\""), expected_login)
            .await?;
        if let Some(count) = expected_messages {
            let lines = wire.imap("EXAMINE INBOX", true).await?;
            if !lines
                .iter()
                .any(|line| line.trim() == format!("* {count} EXISTS"))
                || !lines.iter().any(|line| line.contains("[UIDVALIDITY "))
            {
                return Err("Independent IMAP mailbox count/identity mismatch".into());
            }
            if count > 0 {
                let lines = wire.imap("FETCH 1:* (UID FLAGS)", true).await?;
                if !lines
                    .iter()
                    .any(|line| line.contains("UID ") && line.contains("FLAGS ("))
                    || lines.iter().any(|line| line.contains("\\Seen"))
                {
                    return Err("Synthetic message UID/unseen flag mismatch".into());
                }
            }
        }
        wire.imap("LOGOUT", true).await?;
        Ok(())
    })
    .await
    .map_err(|_| "Independent IMAP/TLS readiness timed out")?
}

pub(crate) async fn seed(port: u16) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut wire = Wire::new(TcpStream::connect(("127.0.0.1", port)).await?);
        wire.smtp_reply("220").await?;
        for (command, code) in [
            ("EHLO localhost\r\n".to_owned(), "250"),
            ("MAIL FROM:<sender@example.test>\r\n".to_owned(), "250"),
            (format!("RCPT TO:<{EMAIL}>\r\n"), "250"),
            ("DATA\r\n".to_owned(), "354"),
            (format!("{MESSAGE}.\r\n"), "250"),
            ("QUIT\r\n".to_owned(), "221"),
        ] {
            wire.send(&command).await?;
            wire.smtp_reply(code).await?;
        }
        Ok(())
    })
    .await
    .map_err(|_| "SMTP fixture seeding timed out")?
}

/// Fixture setup may mutate disposable mailboxes; the independent observer above cannot.
pub(crate) async fn seed_folder(port: u16, tls: &TlsConnector) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = tls
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut wire = Wire::new(stream);
        wire.line().await?;
        wire.imap(&format!("LOGIN \"{EMAIL}\" \"{PASSWORD}\""), true)
            .await?;
        wire.imap("CREATE \"fixture folder/child\"", true).await?;
        let message = MESSAGE.replace(MESSAGE_ID, FOLDER_MESSAGE_ID);
        wire.send(&format!(
            "a1 APPEND \"fixture folder/child\" {{{}}}\r\n",
            message.len()
        ))
        .await?;
        if !wire.line().await?.starts_with('+') {
            return Err("Fixture APPEND continuation missing".into());
        }
        wire.send(&format!("{message}\r\n")).await?;
        if !wire.line().await?.starts_with("a1 OK") {
            return Err("Fixture APPEND failed".into());
        }
        wire.imap("LOGOUT", true).await?;
        Ok(())
    })
    .await
    .map_err(|_| "Folder fixture setup timed out")?
}
