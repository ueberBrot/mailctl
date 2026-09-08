//! MCP tools share normalized envelopes with the CLI.
use super::mcp_transport::{BoundedStdio, OUTPUT_LIMIT};
use crate::{
    domain::{Envelope, Error, ErrorCode, ListAccountsInput, Operation},
    ipc::Client,
};
use rmcp::model::ErrorData as McpError;
use rmcp::{RoleServer, ServerHandler, ServiceExt, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::{borrow::Cow, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

struct EmailTools {
    client: Mutex<Client>,
    shutdown: CancellationToken,
}

fn definitions() -> Vec<Tool> {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    vec![
        Tool::new(
            "email_list_accounts",
            "List authorized email accounts with explicit completion.",
            empty.as_object().unwrap().clone(),
        )
        .with_input_schema::<ListAccountsInput>()
        .with_output_schema::<Envelope>(),
        Tool::new(
            "email_capabilities",
            "Show effective permissions and implemented operations.",
            empty.as_object().unwrap().clone(),
        )
        .with_output_schema::<Envelope>(),
    ]
}

impl ServerHandler for EmailTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("mail-mcp", env!("CARGO_PKG_VERSION")))
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2025_11_25])
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        if request.is_some_and(|request| request.cursor.is_some()) {
            return Err(McpError::invalid_params("Invalid cursor", None));
        }
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
        let input = Value::Object(request.arguments.unwrap_or_default());
        let operation = match request.name.as_ref() {
            "email_list_accounts" => serde_json::from_value(input)
                .map(Operation::ListAccounts)
                .map_err(|_| Error::new(ErrorCode::InvalidRequest)),
            "email_capabilities" => {
                if input.as_object().is_some_and(|value| value.is_empty()) {
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
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = match operation {
            Err(error) => Envelope::from_result(request_id, Err(error)),
            Ok(operation) => {
                let mut client = self.client.lock().await;
                let result = tokio::select! {
                    _ = context.ct.cancelled() => Err(Error::new(ErrorCode::Cancelled)),
                    result = client.request(&request_id, operation) => result,
                };
                match result {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        // A lost or cancelled exchange cannot be reused after broker restart.
                        self.shutdown.cancel();
                        Envelope::from_result(request_id, Err(error))
                    }
                }
            }
        };
        if crate::ipc::serialized_size(&envelope, OUTPUT_LIMIT / 4).is_err() {
            envelope = Envelope::from_result(
                envelope.request_id,
                Err(Error::new(ErrorCode::ResponseTooLarge)),
            );
        }
        let success = envelope.success;
        let value = serde_json::to_value(envelope)
            .map_err(|_| McpError::internal_error("Result unavailable", None))?;
        let response = if success {
            CallToolResult::structured(value)
        } else {
            CallToolResult::structured_error(value)
        };
        let response = if crate::ipc::serialized_size(&response, OUTPUT_LIMIT / 2).is_ok() {
            response
        } else {
            CallToolResult::structured_error(json!(Envelope::from_result(
                uuid::Uuid::new_v4().to_string(),
                Err(Error::new(ErrorCode::ResponseTooLarge))
            )))
        };
        Ok(response.into())
    }
}

pub(super) async fn run(client: Client) -> Result<(), Error> {
    let shutdown = CancellationToken::new();
    let handler = EmailTools {
        client: Mutex::new(client),
        shutdown: shutdown.clone(),
    };
    let service = tokio::time::timeout(
        Duration::from_secs(5),
        handler.serve_with_ct(BoundedStdio::new(), shutdown),
    )
    .await
    .map_err(|_| Error::new(ErrorCode::Timeout))?
    .map_err(|_| Error::new(ErrorCode::ProtocolMismatch))?;
    let cancellation = service.cancellation_token();
    let lifetime = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await;
        cancellation.cancel();
    });
    let result = service
        .waiting()
        .await
        .map_err(|_| Error::new(ErrorCode::InternalError));
    lifetime.abort();
    result.map(|_| ())
}
