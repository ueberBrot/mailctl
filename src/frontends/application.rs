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
            bytes
                .try_reserve_exact(decoded.saturating_add(2))
                .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
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
