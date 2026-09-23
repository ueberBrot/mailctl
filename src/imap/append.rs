use super::{AuthenticatedConnection, Error, Limits, Metrics, mailbox};
use crate::draft::PreparedDraft;
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
impl AuthenticatedConnection {
    /// Capture the existing target incarnation without reading messages or creating a mailbox.
    pub async fn inspect_draft_target(
        self,
        mailbox: &str,
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<u32, Error> {
        super::mailbox(mailbox)?;
        limits.validate()?;
        let mut connection = self.session.resume(metrics);
        connection.limit_body(limits);
        let (validity, _) = connection.examine_selection(mailbox).await?;
        connection
            .drive(io_imap::rfc3501::logout::ImapLogout::new())
            .await?;
        Ok(validity)
    }

    /// Append frozen MIME with the initial Draft flag. The caller owns authorization
    /// and durable draft coordination. Progress retains the outcome after cancellation.
    pub async fn append_draft(
        self,
        target: &str,
        draft: &PreparedDraft,
        limits: &Limits,
        metrics: &mut Metrics,
    ) -> Result<AppendOutcome, Error> {
        metrics.append_outcome = None;
        metrics.append_wire_bytes = 0;
        metrics.mime_bytes = 0;
        mailbox(target)?;
        limits.validate()?;
        if draft.header_bytes() > limits.max_header_bytes
            || draft
                .bytes()
                .len()
                .saturating_add(target.len())
                .saturating_add(128)
                > limits.max_operation_bytes
        {
            return Err(Error::Limit);
        }
        metrics.mime_bytes = draft.bytes().len();
        let result = tokio::time::timeout(limits.operation_timeout, async {
            let mut conn = self.session.resume(metrics);
            conn.limit_body(limits);
            conn.append(target, draft.bytes()).await
        })
        .await
        .unwrap_or(Err(Error::Timeout));
        metrics
            .append_outcome
            .ok_or_else(|| result.err().unwrap_or(Error::Protocol))
    }
}
