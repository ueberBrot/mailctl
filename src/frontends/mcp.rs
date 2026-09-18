//! MCP tools share normalized envelopes with the CLI.
use super::application::Application;
use super::mcp_transport::{BoundedStdio, Bounds};
use crate::domain::{
    AccountDiscovery, Capabilities, Envelope, Error, ErrorCode, GetMessageInput, ListAccountsInput,
    ListMailboxesInput, MailboxDiscovery, MessageBody, MessageSearch, Operation, OperationResult,
    SearchMessagesInput,
};
use rmcp::model::ErrorData as McpError;
use rmcp::{RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::{borrow::Cow, time::Duration};
use tokio_util::sync::CancellationToken;

struct EmailTools {
    tools: Vec<Tool>,
    application: Application,
    envelope_limit: usize,
    deadline: Duration,
    shutdown: CancellationToken,
}

fn tool<I: schemars::JsonSchema + 'static, O: schemars::JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    Tool::new(name, description, serde_json::Map::new())
        .with_input_schema::<I>()
        .with_output_schema::<Envelope<O>>()
}

fn definitions(operations: &[String]) -> Vec<Tool> {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    [
        tool::<ListAccountsInput, AccountDiscovery>(
            "email_list_accounts",
            "List authorized email accounts with explicit completion.",
        ),
        Tool::new(
            "email_capabilities",
            "Show effective permissions and implemented operations.",
            empty.as_object().unwrap().clone(),
        )
        .with_output_schema::<Envelope<Capabilities>>(),
        tool::<ListMailboxesInput, MailboxDiscovery>(
            "email_list_mailboxes",
            "List approved mailboxes or resolve a reusable mailbox reference.",
        ),
        tool::<SearchMessagesInput, MessageSearch>(
            "email_search_messages",
            "Search one approved mailbox with AND predicates and bounded descending-UID pages.",
        ),
        tool::<GetMessageInput, MessageBody>(
            "email_get_message",
            "Read or continue bounded selected message text with representation and truncation metadata.",
        ),
        tool::<crate::domain::ListAttachmentsInput, crate::domain::AttachmentList>(
            "email_list_attachments",
            "List attachment metadata and reusable references without retrieving payloads.",
        ),
        tool::<crate::domain::GetAttachmentInput, crate::domain::AttachmentChunk>(
            "email_get_attachment",
            "Retrieve a bounded base64 chunk, or resume a transfer in this session.",
        ),
    ]
    .into_iter()
    .filter(|tool| {
        matches!(tool.name.as_ref(), "email_list_accounts" | "email_capabilities")
            || operations
                .iter()
                .any(|operation| tool.name.strip_prefix("email_") == Some(operation.as_str()))
    })
    .collect()
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
        if context.ct.is_cancelled() || self.shutdown.is_cancelled() {
            return Err(McpError::internal_error("Request cancelled", None));
        }
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let input = request.arguments.unwrap_or_default();
        let operation = match request.name.as_ref() {
            name if self.tools.iter().any(|tool| tool.name == name) => {
                let name = name.strip_prefix("email_").unwrap();
                let mut wire = json!({"operation": name});
                if name != "capabilities" || !input.is_empty() {
                    wire["input"] = Value::Object(input);
                }
                serde_json::from_value(wire).map_err(|_| Error::new(ErrorCode::InvalidRequest))
            }
            _ => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    "Unknown tool",
                    None,
                ));
            }
        };
        let result = match operation {
            Err(error) => Err(error),
            Ok(operation) => tokio::select! {
                biased;
                _ = context.ct.cancelled() => Err(Error::new(ErrorCode::Cancelled)),
                _ = self.shutdown.cancelled() => Err(Error::new(ErrorCode::Cancelled)),
                result = tokio::time::timeout(self.deadline, self.application.execute(operation)) =>
                    result.map_err(|_| Error::new(ErrorCode::Timeout)).flatten(),
            },
        };
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

pub(super) async fn run(application: Application) -> Result<(), Error> {
    let OperationResult::Capabilities(capabilities) =
        application.execute(Operation::Capabilities).await?
    else {
        return Err(Error::new(ErrorCode::InternalError));
    };
    let limits = application.limits()?;
    let bounds = Bounds::new(limits, application.response_bound()?)?;
    let expires = tokio::time::Instant::now()
        + Duration::from_secs(limits.connection_lifetime_seconds as u64);
    let initialization_expires = expires.min(
        tokio::time::Instant::now() + Duration::from_secs(limits.initialization_seconds as u64),
    );
    let shutdown = CancellationToken::new();
    let _cancel_on_exit = shutdown.clone().drop_guard();
    let handler = EmailTools {
        tools: definitions(&capabilities.operations),
        envelope_limit: bounds.envelope,
        deadline: Duration::from_secs(limits.operation_seconds as u64),
        application: application.with_response_limit(bounds.envelope),
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
