use super::{Error, ImapProbe, Metrics, credentials, mailbox};
use mail_builder::MessageBuilder;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// Plain-text composition for the route proof. Addresses use ASCII addr-spec syntax.
#[derive(Clone, Default)]
pub struct DraftInput {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    /// Message-ID without angle brackets; frozen by the draft operation owner.
    pub message_id: String,
    pub date_unix: i64,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

/// Frozen bounded MIME; composition never contacts a provider.
pub struct PreparedDraft {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    header_bytes: usize,
}
impl PreparedDraft {
    pub fn compose(input: DraftInput, max_mime_bytes: usize) -> Result<Self, Error> {
        if max_mime_bytes == 0 || max_mime_bytes > 8 * 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        if input
            .to
            .len()
            .saturating_add(input.cc.len())
            .saturating_add(input.bcc.len())
            > 100
            || input.subject.len() > 8 * 1024
            || input.body.len() > max_mime_bytes
            || input.references.len() > 50
        {
            return Err(Error::Limit);
        }
        address(&input.from)?;
        for value in input.to.iter().chain(&input.cc).chain(&input.bcc) {
            address(value)?;
        }
        identifier(&input.message_id)?;
        for value in input.in_reply_to.iter().chain(&input.references) {
            identifier(value)?;
        }
        if input.subject.chars().any(char::is_control)
            || !(0..=253_402_300_799).contains(&input.date_unix)
            || input.body.contains('\0')
        {
            return Err(Error::InvalidInput);
        }
        let normalized = input.body.replace("\r\n", "\n").replace('\r', "\n");
        let mut builder = MessageBuilder::new()
            .from(input.from)
            .subject(input.subject)
            .message_id(input.message_id)
            .date(input.date_unix)
            .text_body(normalized);
        if !input.to.is_empty() {
            builder = builder.to(input.to);
        }
        if !input.cc.is_empty() {
            builder = builder.cc(input.cc);
        }
        if !input.bcc.is_empty() {
            builder = builder.bcc(input.bcc);
        }
        if let Some(value) = input.in_reply_to {
            builder = builder.in_reply_to(value);
        }
        if !input.references.is_empty() {
            builder = builder.references(input.references);
        }
        let mut output = BoundedMime {
            bytes: Vec::with_capacity(max_mime_bytes),
            limit: max_mime_bytes,
        };
        builder.write_to(&mut output).map_err(|_| Error::Limit)?;
        let header_bytes = output
            .bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or(Error::Protocol)?
            + 4;
        if header_bytes > 256 * 1024 {
            return Err(Error::Limit);
        }
        let sha256 = Sha256::digest(&output.bytes).into();
        Ok(Self {
            bytes: output.bytes,
            sha256,
            header_bytes,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

fn address(value: &str) -> Result<(), Error> {
    if value.len() > 254 {
        return Err(Error::Limit);
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err(Error::InvalidInput);
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        || domain.is_empty()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn identifier(value: &str) -> Result<(), Error> {
    if value.len() > 998 {
        return Err(Error::Limit);
    }
    let Some((left, right)) = value.split_once('@') else {
        return Err(Error::InvalidInput);
    };
    if left.is_empty()
        || right.is_empty()
        || right.contains('@')
        || !value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>\\\"()[]".contains(&b))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
struct BoundedMime {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedMime {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("MIME limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendUid {
    pub uid_validity: u32,
    pub uid: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Created {
        uid: Option<AppendUid>,
    },
    Rejected,
    /// APPEND may have reached the provider. This outcome never permits automatic retry.
    Unknown,
}
#[derive(Clone, Copy, Debug)]
pub struct AppendResult {
    pub outcome: AppendOutcome,
    pub metrics: Metrics,
}

impl ImapProbe {
    /// Last APPEND acknowledgement, including after dropping a suspended operation.
    pub fn append_outcome(&self) -> Option<AppendOutcome> {
        self.metrics.append_outcome
    }

    /// Append frozen MIME to the caller's exact approved target with the initial Draft flag.
    /// Authentication and validation failures occur before dispatch. Once dispatch starts,
    /// transport failures and cancellation leave an unknown outcome. Connections are dropped
    /// at completion; no cleanup or optional lookup can replace a tagged acknowledgement.
    pub async fn append_draft(
        &mut self,
        user: &str,
        password: &str,
        target: &str,
        draft: &PreparedDraft,
    ) -> Result<AppendResult, Error> {
        self.metrics = Metrics::default();
        credentials(user, password)?;
        mailbox(target)?;
        if draft.header_bytes > self.limits.max_header_bytes {
            return Err(Error::Limit);
        }
        if draft
            .bytes
            .len()
            .saturating_add(target.len())
            .saturating_add(128)
            > self.limits.max_operation_bytes
        {
            return Err(Error::Limit);
        }
        self.metrics.mime_bytes = draft.bytes.len();
        let result = tokio::time::timeout(self.limits.operation_timeout, async {
            let mut conn = self.authenticate(user, password).await?;
            conn.append(target, &draft.bytes).await
        })
        .await
        .unwrap_or(Err(Error::Timeout));
        match self.metrics.append_outcome {
            Some(outcome) => Ok(AppendResult {
                outcome,
                metrics: self.metrics,
            }),
            None => Err(result.err().unwrap_or(Error::Protocol)),
        }
    }
}
