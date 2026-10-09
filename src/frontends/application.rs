//! The frontend uses the same operations in an embedded or isolated installation.
use crate::{
    config::Limits,
    domain::{Error, Operation, OperationResult},
    policy::RequestContext,
    service::Service,
};
#[cfg(feature = "cli")]
use std::ops::ControlFlow;

pub(super) enum Application {
    Embedded {
        service: Box<Service>,
        context: RequestContext,
    },
    #[cfg(target_os = "macos")]
    Isolated(Box<crate::isolation::Client>),
}

impl Application {
    pub fn limits(&self) -> Result<&Limits, Error> {
        match self {
            Self::Embedded { service, context } => service.limits(context),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => Ok(client.limits()),
        }
    }

    #[cfg(feature = "mcp")]
    pub fn response_bound(&self) -> Result<usize, Error> {
        match self {
            Self::Embedded { service, context } => service.response_bound(context),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => Ok(client.response_bound()),
        }
    }

    pub async fn execute(&self, operation: Operation) -> Result<OperationResult, Error> {
        match self {
            Self::Embedded { service, context } => service.execute(context, operation).await,
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => client.execute(operation).await,
        }
    }

    pub async fn doctor(&self, check_account: bool) -> Result<OperationResult, Error> {
        match self {
            Self::Embedded { service, context } => service
                .doctor(context, check_account)
                .await
                .map(OperationResult::Doctor),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => client.doctor(check_account).await,
        }
    }

    #[cfg(feature = "mcp")]
    pub fn with_response_limit(self, maximum: usize) -> Self {
        match self {
            Self::Embedded { service, context } => Self::Embedded {
                service,
                context: context.with_response_limit(maximum),
            },
            #[cfg(target_os = "macos")]
            Self::Isolated(mut client) => {
                client.limit_response(maximum);
                Self::Isolated(client)
            }
        }
    }
}

#[cfg(feature = "cli")]
impl Application {
    pub async fn export_attachment(
        &self,
        attachment: String,
        writer: &mut crate::export::ExportWriter,
    ) -> Result<OperationResult, Error> {
        self.transfer_attachment(
            crate::domain::GetAttachmentInput::Start(crate::domain::AttachmentStart { attachment }),
            |chunk| {
                Ok(match writer.write_chunk(&chunk)? {
                    Some(receipt) => ControlFlow::Break(OperationResult::Export(receipt)),
                    None => ControlFlow::Continue(chunk),
                })
            },
        )
        .await
    }

    pub async fn download_attachment(
        &self,
        input: crate::domain::GetAttachmentInput,
    ) -> Result<OperationResult, Error> {
        use crate::domain::{AttachmentProgress, ErrorCode};
        use base64::{Engine, engine::general_purpose::STANDARD};
        let limits = self.limits()?;
        let mut bytes = Vec::new();
        self.transfer_attachment(input, |mut chunk| {
            if chunk.decoded_offset != bytes.len() as u64 {
                return Err(Error::new(ErrorCode::InternalError));
            }
            let encoded = &chunk.bytes_base64;
            let padding = encoded.len() - encoded.trim_end_matches('=').len();
            let decoded = (encoded.len() / 4 * 3).saturating_sub(padding);
            let total = bytes.len().saturating_add(decoded);
            if total > limits.attachment_decoded_bytes
                || total.div_ceil(3) * 4 + 4096 + chunk.attachment_reference.len()
                    > limits.envelope_bytes
            {
                return Err(Error::new(ErrorCode::ResponseTooLarge));
            }
            let needed = total + 2;
            if bytes.capacity() < needed {
                // Amortize growth across chunks without exceeding the decoded ceiling.
                let capacity = needed
                    .max(bytes.capacity().saturating_mul(2))
                    .min(limits.attachment_decoded_bytes + 2);
                bytes
                    .try_reserve_exact(capacity - bytes.len())
                    .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
            }
            STANDARD
                .decode_vec(encoded, &mut bytes)
                .map_err(|_| Error::new(ErrorCode::InternalError))?;
            if matches!(chunk.progress, AttachmentProgress::Complete { .. }) {
                chunk.bytes_base64 = STANDARD.encode(&bytes);
                chunk.decoded_offset = 0;
                Ok(ControlFlow::Break(OperationResult::Attachment(chunk)))
            } else {
                Ok(ControlFlow::Continue(chunk))
            }
        })
        .await
    }

    async fn transfer_attachment(
        &self,
        mut input: crate::domain::GetAttachmentInput,
        mut consume: impl FnMut(
            crate::domain::AttachmentChunk,
        ) -> Result<
            ControlFlow<OperationResult, crate::domain::AttachmentChunk>,
            Error,
        >,
    ) -> Result<OperationResult, Error> {
        use crate::domain::{
            AttachmentContinuation, AttachmentProgress, ErrorCode, GetAttachmentInput,
        };
        loop {
            let OperationResult::Attachment(chunk) =
                self.execute(Operation::GetAttachment(input)).await?
            else {
                return Err(Error::new(ErrorCode::InternalError));
            };
            let chunk = match consume(chunk)? {
                ControlFlow::Break(result) => return Ok(result),
                ControlFlow::Continue(chunk) => chunk,
            };
            let AttachmentProgress::Continue { next_token } = chunk.progress else {
                return Err(Error::new(ErrorCode::InternalError));
            };
            input = GetAttachmentInput::Continue(AttachmentContinuation { token: next_token });
        }
    }
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::Application;
    use crate::{
        config::Config,
        domain::{
            AttachmentStart, GetAttachmentInput, MessageMetadata, Operation, OperationResult,
        },
        service::{MemoryAttachments, MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use std::sync::Arc;

    async fn download_fixture(bytes: Vec<u8>) -> (Application, GetAttachmentInput) {
        let config = Config::parse(&format!(
            r#"
version = 1
default_grant = "reader"
state_dir = {state}
[limits]
attachment_chunk_bytes = 1024
[[accounts]]
key = "work"
alias = "work"
server = "imap.example.test"
username = "fixture@example.test"
mailboxes = ["INBOX"]
from_identities = ["fixture@example.test"]
[accounts.credential]
source = "session"
[[grants]]
name = "reader"
accounts = ["work"]
"#,
            state =
                serde_json::to_string(&std::env::temp_dir().join("mailctl-download-performance"))
                    .unwrap()
        ))
        .unwrap();
        let mailboxes = Arc::new(MemoryMailboxes::default());
        mailboxes.set(
            "work",
            vec![crate::domain::MailboxMetadata {
                name: "INBOX".into(),
                selectable: true,
                special_use: vec![],
            }],
        );
        let messages = Arc::new(MemoryMessages::default());
        messages.set(
            "work",
            "INBOX",
            77,
            vec![MemoryMessage {
                uid: 4,
                metadata: MessageMetadata {
                    received_date: "2024-02-29T12:00:00+00:00".into(),
                    ..Default::default()
                },
                bcc: vec![],
                text: String::new(),
            }],
        );
        let attachments = Arc::new(MemoryAttachments::default());
        attachments.set(
            "work",
            "INBOX",
            77,
            4,
            vec![(
                crate::imap::AttachmentMetadata {
                    part: "2".into(),
                    filename: None,
                    media_type: "application/octet-stream".into(),
                    declared_size: Some(bytes.len() as u64),
                    available: true,
                },
                bytes,
            )],
        );
        let service = Service::in_memory(config)
            .unwrap()
            .with_mailbox_backend(mailboxes)
            .with_search_backend(messages)
            .with_attachment_backend(attachments);
        let context = service.context("reader", &Default::default()).unwrap();
        let application = Application::Embedded {
            service: Box::new(service),
            context,
        };
        let OperationResult::Mailboxes(page) = application
            .execute(Operation::ListMailboxes(Default::default()))
            .await
            .unwrap()
        else {
            panic!("mailbox fixture");
        };
        let OperationResult::Messages(page) = application
            .execute(
                serde_json::from_value(json!({
                    "operation": "search_messages",
                    "input": {"mailbox": page.mailboxes[0].reference}
                }))
                .unwrap(),
            )
            .await
            .unwrap()
        else {
            panic!("message fixture");
        };
        let OperationResult::Attachments(page) = application
            .execute(
                serde_json::from_value(json!({
                    "operation": "list_attachments",
                    "input": {"message": page.messages[0].reference}
                }))
                .unwrap(),
            )
            .await
            .unwrap()
        else {
            panic!("attachment fixture");
        };
        (
            application,
            GetAttachmentInput::Start(AttachmentStart {
                attachment: page.attachments[0].reference.clone(),
            }),
        )
    }

    #[test]
    fn complete_attachment_download_has_linear_allocation_with_small_chunks() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for size in [64 * 1024, 128 * 1024, 256 * 1024] {
            let expected = vec![0xff; size];
            let (application, input) = runtime.block_on(download_fixture(expected.clone()));
            let mut result = None;
            let allocation = allocation_counter::measure(|| {
                result = Some(
                    runtime
                        .block_on(application.download_attachment(input))
                        .unwrap(),
                );
            });
            let OperationResult::Attachment(chunk) = result.unwrap() else {
                panic!("complete attachment");
            };
            assert_eq!(STANDARD.decode(&chunk.bytes_base64).unwrap(), expected);
            eprintln!("download bytes={size}, {allocation:?}");
            assert!(
                allocation.bytes_total < size as u64 * 64,
                "complete downloads must not reallocate their accumulated contents for every chunk"
            );
        }
    }
}
