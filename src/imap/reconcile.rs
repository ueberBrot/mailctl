//! Verify uncertain drafts through bounded, read-only provider evidence.
use super::{AuthenticatedConnection, Error, Metrics, fetch::Fetch};
use crate::draft::{DraftEvidence, DraftMessageIdentity, DraftVerification};
use io_imap::types::search::SearchKey;
use sha2::{Digest, Sha256};

impl AuthenticatedConnection {
    pub async fn reconcile_draft(
        self,
        mailbox: &str,
        expected: &DraftVerification,
        limits: &crate::config::Limits,
        metrics: &mut Metrics,
    ) -> Result<DraftEvidence, Error> {
        super::mailbox(mailbox)?;
        limits.validate().map_err(|_| Error::InvalidInput)?;
        if expected.uid_validity == 0 || expected.message_id.len() > 998 {
            return Err(Error::InvalidInput);
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(limits.operation_seconds as u64),
            async {
                let mut connection = self.session.resume(metrics);
                let mut bounds = super::Limits::body(limits);
                bounds.max_response_bytes = bounds.max_response_bytes.min(limits.wire_fetch_bytes);
                bounds.max_literal_bytes = bounds.max_literal_bytes.min(bounds.max_response_bytes);
                bounds.max_operation_bytes = limits.wire_fetch_bytes;
                connection.limit_body(&bounds);
                let (validity, next) = connection.examine_selection(mailbox).await?;
                if validity != expected.uid_validity {
                    return Err(Error::StaleReference);
                }
                let upper = connection.upper_uid(next).await?;
                let mut first = 1u64;
                let mut candidate = None;
                for _ in 0..limits.search_windows {
                    if first > u64::from(upper) {
                        break;
                    }
                    let last = (first + limits.search_uid_window as u64 - 1).min(u64::from(upper));
                    let uids = connection
                        .search(
                            vec![
                                SearchKey::Uid(
                                    (first as u32..=last as u32)
                                        .try_into()
                                        .map_err(|_| Error::InvalidInput)?,
                                ),
                                SearchKey::Header(
                                    "Message-ID".try_into().unwrap(),
                                    expected
                                        .message_id
                                        .clone()
                                        .try_into()
                                        .map_err(|_| Error::InvalidInput)?,
                                ),
                            ],
                            false,
                        )
                        .await?;
                    for uid in uids {
                        if !(first..=last).contains(&u64::from(uid.get())) {
                            return Err(Error::Protocol);
                        }
                        if candidate.replace(uid.get()).is_some() {
                            return Ok(DraftEvidence::Ambiguous);
                        }
                    }
                    first = last + 1;
                }
                // A partial inventory cannot establish uniqueness, even if a candidate exists.
                if first <= u64::from(upper) {
                    return Err(Error::Limit);
                }
                let Some(uid) = candidate else {
                    return Ok(DraftEvidence::Absent);
                };
                let mut hash = Sha256::new();
                let mut offset = 0usize;
                let mut headers = Vec::new();
                let mut headers_complete = false;
                let chunk = bounds.fetch_chunk_bytes()?;
                loop {
                    // One extra byte distinguishes the exact ceiling from a truncated message.
                    let count = (limits.draft_mime_bytes.saturating_sub(offset) + 1).min(chunk);
                    let request = Fetch::Bytes {
                        uid,
                        section: None,
                        offset: offset as u32,
                        count: count as u32,
                    };
                    let fields = request.execute(&mut connection).await?;
                    let bytes = request.data(&fields)?;
                    offset += bytes.len();
                    if offset > limits.draft_mime_bytes {
                        return Err(Error::Limit);
                    }
                    hash.update(bytes);
                    if !headers_complete {
                        for byte in bytes {
                            headers.push(*byte);
                            if headers.len() > limits.header_bytes {
                                return Err(Error::Limit);
                            }
                            if headers.ends_with(b"\r\n\r\n") {
                                headers_complete = true;
                                break;
                            }
                        }
                    }
                    if bytes.len() < count {
                        break;
                    }
                }
                if !headers_complete {
                    return Ok(DraftEvidence::ContentMismatch);
                }
                let parsed = mail_parser::MessageParser::default()
                    .parse_headers(&headers)
                    .ok_or(Error::Protocol)?;
                let ids = parsed
                    .headers()
                    .iter()
                    .filter(|header| header.name == mail_parser::HeaderName::MessageId)
                    .count();
                if ids != 1
                    || parsed.message_id() != Some(expected.message_id.as_str())
                    || <[u8; 32]>::from(hash.finalize()) != expected.content_sha256
                {
                    return Ok(DraftEvidence::ContentMismatch);
                }
                Ok(DraftEvidence::Verified(DraftMessageIdentity {
                    uid_validity: validity,
                    uid,
                }))
            },
        )
        .await
        .unwrap_or(Err(Error::Timeout))
    }
}
