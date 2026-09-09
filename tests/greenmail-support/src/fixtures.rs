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
pub(crate) const SEEN_MESSAGE_ID: &str = "<observed-seen@example.test>";
pub(crate) const MULTIPART_MESSAGE_ID: &str = "<large-attachment-body@example.test>";
pub(crate) const MULTIPART_SUBJECT: &str = "Large attachment body route";
pub(crate) const MULTIPART_BODY: &str = "Synthetic multipart body.\r\n";
pub(crate) const BODY: &str = "Synthetic bootstrap message.";
pub(crate) const SEEN_BODY: &str = "Synthetic seen message.";
pub(crate) const MESSAGE: &str = "From: sender@example.test\r\nTo: fixture+smoke@example.test\r\nMessage-ID: <bootstrap-smoke@example.test>\r\nSubject: Bootstrap smoke\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic bootstrap message.\r\n";
pub(crate) const SEEN_MESSAGE: &str = "From: sender@example.test\r\nTo: fixture+smoke@example.test\r\nMessage-ID: <observed-seen@example.test>\r\nSubject: Observed seen\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSynthetic seen message.\r\n";

pub(crate) struct TlsInputs {
    pub keystore: Vec<u8>,
    pub connector: TlsConnector,
    pub roots: RootCertStore,
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
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        Ok(Self {
            keystore: std::fs::read(dir.join("server.p12"))?,
            connector: TlsConnector::from(Arc::new(config)),
            roots,
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
    .map_err(|_| "Docker tests require OpenSSL on PATH")?;
    if !result.status.success() {
        return Err("OpenSSL fixture certificate preparation failed".into());
    }
    Ok(())
}

/// Bounded protocol exchanges used to seed disposable mailboxes.
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

    async fn imap(&mut self, command: &str) -> Result<()> {
        self.send(&format!("a1 {command}\r\n")).await?;
        for _ in 0..100 {
            let line = self.line().await?;
            if line.starts_with("a1 ") {
                let status = line.split_whitespace().nth(1);
                if status != Some("OK") {
                    return Err(format!(
                        "Fixture IMAP {} returned status {:?}; expected OK",
                        command.split_whitespace().next().unwrap_or("command"),
                        status,
                    )
                    .into());
                }
                return Ok(());
            }
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

pub(crate) async fn seed(port: u16) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut wire = Wire::new(TcpStream::connect(("127.0.0.1", port)).await?);
        wire.smtp_reply("220").await?;
        wire.send("EHLO localhost\r\n").await?;
        wire.smtp_reply("250").await?;
        smtp_message(&mut wire, MESSAGE).await?;
        smtp_message(&mut wire, SEEN_MESSAGE).await?;
        wire.send("QUIT\r\n").await?;
        wire.smtp_reply("221").await?;
        Ok(())
    })
    .await
    .map_err(|_| "SMTP fixture seeding timed out")?
}

/// Seed one multipart message whose attachment exceeds the whole-message route budget.
///
/// This is deliberately opt-in: the default fixture mailbox remains small for suites
/// that only exercise discovery and search.
pub(crate) async fn seed_multipart_with_large_attachment(port: u16) -> Result<()> {
    const ATTACHMENT_BYTES: usize = 2 * 1024 * 1024 + 1;
    const BOUNDARY: &str = "mailctl-large-attachment-boundary";

    let attachment = "A".repeat(76).to_owned() + "\r\n";
    let attachment = attachment.repeat(ATTACHMENT_BYTES.div_ceil(76));
    let message = format!(
        "From: sender@example.test\r\n\
To: {EMAIL}\r\n\
Message-ID: {MULTIPART_MESSAGE_ID}\r\n\
Subject: {MULTIPART_SUBJECT}\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"{BOUNDARY}\"\r\n\
\r\n\
--{BOUNDARY}\r\n\
Content-Type: multipart/alternative; boundary=\"{BOUNDARY}-alternative\"\r\n\
\r\n\
--{BOUNDARY}-alternative\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
{MULTIPART_BODY}\
--{BOUNDARY}-alternative\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Synthetic <strong>HTML</strong> alternative.</p>\r\n\
--{BOUNDARY}-alternative--\r\n\
--{BOUNDARY}\r\n\
Content-Type: application/octet-stream; name=\"large.bin\"\r\n\
Content-Disposition: attachment; filename=\"large.bin\"\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
{attachment}\r\n\
--{BOUNDARY}--\r\n"
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut wire = Wire::new(TcpStream::connect(("127.0.0.1", port)).await?);
        wire.smtp_reply("220").await?;
        wire.send("EHLO localhost\r\n").await?;
        wire.smtp_reply("250").await?;
        smtp_message(&mut wire, &message).await?;
        wire.send("QUIT\r\n").await?;
        wire.smtp_reply("221").await?;
        Ok(())
    })
    .await
    .map_err(|_| "Large multipart SMTP fixture seeding timed out")?
}

/// Fixture setup marks one synthetic message as seen to prove readers preserve both states.
pub(crate) async fn seed_seen(port: u16, tls: &TlsConnector) -> Result<()> {
    let socket = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "Seen-message IMAP connection timed out")??;
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        tls.connect(ServerName::try_from("localhost")?, socket),
    )
    .await
    .map_err(|_| "Seen-message IMAP TLS handshake timed out")??;
    let mut wire = Wire::new(stream);
    tokio::time::timeout(Duration::from_secs(5), wire.line())
        .await
        .map_err(|_| "Seen-message IMAP greeting timed out")??;
    tokio::time::timeout(
        Duration::from_secs(5),
        wire.imap(&format!("LOGIN \"{EMAIL}\" \"{PASSWORD}\"")),
    )
    .await
    .map_err(|_| "Seen-message IMAP login timed out")??;
    tokio::time::timeout(Duration::from_secs(5), wire.imap("SELECT INBOX"))
        .await
        .map_err(|_| "Seen-message mailbox selection timed out")??;
    tokio::time::timeout(
        Duration::from_secs(5),
        wire.imap("UID STORE 2 +FLAGS.SILENT (\\Seen)"),
    )
    .await
    .map_err(|_| "Seen-message flag setup timed out")??;
    tokio::time::timeout(Duration::from_secs(5), wire.imap("LOGOUT"))
        .await
        .map_err(|_| "Seen-message IMAP logout timed out")??;
    Ok(())
}

async fn smtp_message<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    message: &str,
) -> Result<()> {
    for (command, code) in [
        ("MAIL FROM:<sender@example.test>\r\n".to_owned(), "250"),
        (format!("RCPT TO:<{EMAIL}>\r\n"), "250"),
        ("DATA\r\n".to_owned(), "354"),
        (format!("{message}.\r\n"), "250"),
    ] {
        wire.send(&command).await?;
        wire.smtp_reply(code).await?;
    }
    Ok(())
}

/// Fixture setup may mutate disposable mailboxes; the independent observer cannot.
pub(crate) async fn seed_folder(port: u16, tls: &TlsConnector) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = tls
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let mut wire = Wire::new(stream);
        wire.line().await?;
        wire.imap(&format!("LOGIN \"{EMAIL}\" \"{PASSWORD}\""))
            .await?;
        wire.imap("CREATE \"fixture folder/child\"").await?;
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
        wire.imap("LOGOUT").await?;
        Ok(())
    })
    .await
    .map_err(|_| "Folder fixture setup timed out")?
}
