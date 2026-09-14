//! The frontend uses the same operations in an embedded or isolated installation.
use crate::{
    config::Limits,
    domain::{Error, Operation, OperationResult},
    policy::RequestContext,
    service::Service,
};

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
    pub async fn download_attachment(
        &self,
        input: crate::domain::GetAttachmentInput,
    ) -> Result<OperationResult, Error> {
        use crate::domain::{
            AttachmentContinuation, AttachmentProgress, ErrorCode, GetAttachmentInput,
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut input = input;
        let mut bytes = Vec::new();
        loop {
            let OperationResult::Attachment(mut chunk) =
                self.execute(Operation::GetAttachment(input)).await?
            else {
                return Err(Error::new(ErrorCode::InternalError));
            };
            if chunk.decoded_offset != bytes.len() as u64 {
                return Err(Error::new(ErrorCode::InternalError));
            }
            let decoded = STANDARD
                .decode(&chunk.bytes_base64)
                .map_err(|_| Error::new(ErrorCode::InternalError))?;
            let next_len = bytes
                .len()
                .checked_add(decoded.len())
                .ok_or_else(|| Error::new(ErrorCode::ResponseTooLarge))?;
            let envelope_bytes = self.limits()?.envelope_bytes;
            if next_len > self.limits()?.attachment_decoded_bytes
                || next_len.div_ceil(3) * 4 + 4096 + chunk.attachment_reference.len()
                    > envelope_bytes
            {
                return Err(Error::new(ErrorCode::ResponseTooLarge));
            }
            bytes.extend_from_slice(&decoded);
            match chunk.progress {
                AttachmentProgress::Continue { next_token } => {
                    input =
                        GetAttachmentInput::Continue(AttachmentContinuation { token: next_token })
                }
                AttachmentProgress::Complete { .. } => {
                    chunk.bytes_base64 = STANDARD.encode(bytes);
                    chunk.decoded_offset = 0;
                    return Ok(OperationResult::Attachment(chunk));
                }
            }
        }
    }
}
