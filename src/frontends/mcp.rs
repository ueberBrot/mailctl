//! MCP tools share normalized envelopes with the CLI.
use super::mcp_transport::{BoundedStdio, Bounds};
use crate::{
    domain::{
        AccountDiscovery, Capabilities, Envelope, Error, ErrorCode, ListAccountsInput, Operation,
    },
    policy::RequestContext as ApplicationContext,
    service::Service,
};
use rmcp::model::ErrorData as McpError;
use rmcp::{RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::{borrow::Cow, time::Duration};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

struct EmailTools {
    service: Service,
    context: ApplicationContext,
    active: Semaphore,
    envelope_limit: usize,
    deadline: Duration,
    shutdown: CancellationToken,
}

fn definitions() -> Vec<Tool> {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    vec![
        Tool::new(
            "email_list_accounts",
            "List authorized email accounts with explicit completion.",
            serde_json::Map::new(),
        )
        .with_input_schema::<ListAccountsInput>()
        .with_output_schema::<Envelope<AccountDiscovery>>(),
        Tool::new(
            "email_capabilities",
            "Show effective permissions and implemented operations.",
            empty.as_object().unwrap().clone(),
        )
        .with_output_schema::<Envelope<Capabilities>>(),
    ]
}

impl ServerHandler for EmailTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new(
                "mailctl-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2025_11_25])
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        if request.is_some_and(|request| request.cursor.is_some()) {
            return Err(McpError::invalid_params("Invalid cursor", None));
        }
        let _active = tokio::select! {
            biased;
            _ = context.ct.cancelled() => return Err(McpError::internal_error("Request cancelled", None)),
            permit = tokio::time::timeout(self.deadline, self.active.acquire()) =>
                permit.map_err(|_| McpError::internal_error("Request timed out", None))?
                    .map_err(|_| McpError::internal_error("Service unavailable", None))?,
        };
        Ok(ListToolsResult {
            tools: definitions(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let admitted = tokio::select! {
            biased;
            _ = context.ct.cancelled() => Err(Error::new(ErrorCode::Cancelled)),
            _ = self.shutdown.cancelled() => Err(Error::new(ErrorCode::Cancelled)),
            permit = tokio::time::timeout(self.deadline, self.active.acquire()) => {
                permit.map_err(|_| Error::new(ErrorCode::Timeout))
                    .and_then(|permit| permit.map_err(|_| Error::new(ErrorCode::Cancelled)))
            },
        };
        let input = request.arguments.unwrap_or_default();
        let operation = match (admitted.as_ref(), request.name.as_ref()) {
            (Err(error), _) => Err(error.clone()),
            (_, "email_list_accounts") => serde_json::from_value(Value::Object(input))
                .map(Operation::ListAccounts)
                .map_err(|_| Error::new(ErrorCode::InvalidRequest)),
            (_, "email_capabilities") => {
                if input.is_empty() {
                    Ok(Operation::Capabilities)
                } else {
                    Err(Error::new(ErrorCode::InvalidRequest))
                }
            }
            _ => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    "Unknown tool",
                    None,
                ));
            }
        };
        // Discovery is bounded, synchronous in-memory work. Future provider
        // operations must propagate this request's deadline/cancellation.
        let result = operation.and_then(|operation| self.service.execute(&self.context, operation));
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OperationConflict)
        {
            self.shutdown.cancel();
        }
        let mut envelope = Envelope::from_result(uuid::Uuid::new_v4().to_string(), result);
        if crate::encoding::serialized_size(&envelope, self.envelope_limit).is_err() {
            envelope = Envelope::from_result(
                envelope.request_id().to_owned(),
                Err(Error::new(ErrorCode::ResponseTooLarge)),
            );
        }
        let success = envelope.is_success();
        let value = serde_json::to_value(envelope)
            .map_err(|_| McpError::internal_error("Result unavailable", None))?;
        let response = if success {
            CallToolResult::structured(value)
        } else {
            CallToolResult::structured_error(value)
        };
        Ok(response.into())
    }
}

pub(super) async fn run(service: Service, context: ApplicationContext) -> Result<(), Error> {
    let limits = service.limits(&context)?;
    let bounds = Bounds::new(limits, service.response_bound(&context)?)?;
    let expires = tokio::time::Instant::now()
        + Duration::from_secs(limits.connection_lifetime_seconds as u64);
    let initialization_expires = expires.min(
        tokio::time::Instant::now() + Duration::from_secs(limits.initialization_seconds as u64),
    );
    let shutdown = CancellationToken::new();
    let _cancel_on_exit = shutdown.clone().drop_guard();
    let handler = EmailTools {
        active: Semaphore::new(limits.active_requests),
        envelope_limit: bounds.envelope,
        deadline: Duration::from_secs(limits.operation_seconds as u64),
        service,
        context: context.with_response_limit(bounds.envelope),
        shutdown: shutdown.clone(),
    };
    let service = tokio::time::timeout_at(
        initialization_expires,
        handler.serve_with_ct(BoundedStdio::new(bounds), shutdown),
    )
    .await
    .map_err(|_| Error::new(ErrorCode::Timeout))?
    .map_err(|_| Error::new(ErrorCode::ProtocolMismatch))?;
    tokio::time::timeout_at(expires, service.waiting())
        .await
        .map_err(|_| Error::new(ErrorCode::Timeout))?
        .map_err(|_| Error::new(ErrorCode::InternalError))
        .map(|_| ())
}
