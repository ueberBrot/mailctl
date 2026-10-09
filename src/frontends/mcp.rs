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
use tracing::Instrument;

mod schema;

struct EmailTools {
    tools: Vec<Tool>,
    application: Application,
    envelope_limit: usize,
    shutdown: CancellationToken,
}

fn tool<I: schemars::JsonSchema + 'static, O: schemars::JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
) -> Tool {
    let journal_mutation = matches!(name, "email_save_draft" | "email_draft_status");
    Tool::new(name, description, serde_json::Map::new())
        .with_input_schema::<I>()
        .with_raw_output_schema(schema::output::<O>())
        .with_annotations(
            ToolAnnotations::new()
                .read_only(!journal_mutation)
                .destructive(false)
                .idempotent(name == "email_save_draft")
                .open_world(!matches!(
                    name,
                    "email_list_accounts" | "email_capabilities"
                )),
        )
}

fn definitions(operations: &[String]) -> Vec<Tool> {
    let empty = json!({"type":"object","properties":{},"additionalProperties":false});
    [
        tool::<crate::domain::SaveDraftInput, crate::domain::DraftReceipt>(
            "email_save_draft", "Create one unsent draft; retain identity and unchanged input before calling, then reuse them on retries. See mailctl://guide/drafts.",
        ),
        tool::<crate::domain::DraftStatusInput, crate::domain::DraftReceipt>(
            "email_draft_status", "Inspect an original draft operation. reconcile checks uncertain creation and updates its journal; never creates another draft. See mailctl://guide/drafts.",
        ),
        tool::<ListAccountsInput, AccountDiscovery>(
            "email_list_accounts",
            "List authorized email accounts with explicit completion.",
        ),
        Tool::new(
            "email_capabilities",
            "Show callable MCP operations, effective permissions, health, and operation limits.",
            empty.as_object().unwrap().clone(),
        )
        .with_raw_output_schema(schema::output::<Capabilities>())
        .with_annotations(ToolAnnotations::new().read_only(true).open_world(false)),
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
            "Read selected message text; max_bytes narrows the page and cursor continues it. Check truncation and continuation metadata. See mailctl://guide/reading.",
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

fn invalid_arguments(name: &str) -> Error {
    Error::invalid_input(match name {
        "email_list_accounts" => {
            "Use an optional limit within capabilities.limits.accounts; match tools/list inputSchema"
        }
        "email_capabilities" => "email_capabilities accepts no arguments; call it with {}",
        "email_list_mailboxes" => {
            "Use an account alias from account discovery and optional reference, limit, cursor; match tools/list inputSchema"
        }
        "email_search_messages" => {
            "Use a mailbox reference, an AND criteria array, optional limit and cursor; retain original criteria when continuing. See mailctl://guide/reading"
        }
        "email_get_message" => {
            "Use a message reference, optional cursor and max_bytes within capabilities.limits.text_page_bytes; match tools/list inputSchema"
        }
        "email_list_attachments" => {
            "Use message with a message reference returned by search; match tools/list inputSchema"
        }
        "email_get_attachment" => {
            "Use either attachment with a returned attachment reference, or token with progress.next_token; never both. See mailctl://guide/attachments"
        }
        "email_save_draft" => {
            "Use account_id and operation_id UUIDs, account_generation, the literal drafts_mailbox name as mailbox, and draft as an object. See mailctl://guide/drafts"
        }
        "email_draft_status" => {
            "Use the original account_id, account_generation, operation_id, mailbox and optional reconcile boolean. See mailctl://guide/drafts"
        }
        _ => "Match tools/list inputSchema; see mailctl://guide/errors",
    })
}

impl ServerHandler for EmailTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .with_server_info(Implementation::new(
            "mailctl-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(super::guidance::instructions())
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
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        if request.is_some_and(|request| request.cursor.is_some()) {
            return Err(McpError::invalid_params("Invalid cursor", None));
        }
        if context.ct.is_cancelled() || self.shutdown.is_cancelled() {
            return Err(McpError::internal_error("Request cancelled", None));
        }
        Ok(ListResourcesResult {
            resources: guide_resources(),
            ..Default::default()
        })
    }
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        if context.ct.is_cancelled() || self.shutdown.is_cancelled() {
            return Err(McpError::internal_error("Request cancelled", None));
        }
        let text = request
            .uri
            .strip_prefix("mailctl://guide/")
            .and_then(super::guidance::guide)
            .ok_or_else(|| McpError::resource_not_found("Unknown usage guide", None))?;
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(text, request.uri).with_mime_type("text/markdown"),
        ])
        .into())
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
                let input =
                    (name != "capabilities" || !input.is_empty()).then_some(Value::Object(input));
                Operation::from_input(name, input)
                    .map_err(|_| invalid_arguments(request.name.as_ref()))
            }
            _ => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    "Unknown tool",
                    None,
                ));
            }
        };
        let diagnostic_request = super::diagnostics::Request::new();
        let mut result = match operation {
            Err(error) => Err(error),
            Ok(operation) => {
                let draft_identity = match &operation {
                    Operation::SaveDraft(input) => Some(input.operation_details()),
                    _ => None,
                };
                // Both application adapters own the operation deadline.
                tokio::select! {
                    biased;
                    _ = context.ct.cancelled() => None,
                    _ = self.shutdown.cancelled() => None,
                    result = self.application.execute(operation).instrument(diagnostic_request.span()) => Some(result),
                }
                .unwrap_or_else(|| Err(match draft_identity {
                    Some(identity) => Error::draft_outcome(ErrorCode::OutcomeUnknown, identity),
                    None => Error::new(ErrorCode::Cancelled),
                }))
            }
        };
        if let Ok(OperationResult::Capabilities(capabilities)) = &mut result {
            capabilities.operations.retain(|operation| {
                self.tools
                    .iter()
                    .any(|tool| tool.name.strip_prefix("email_") == Some(operation.as_str()))
            });
        }
        if result.as_ref().is_err_and(|error| {
            error.code == ErrorCode::OperationConflict
                && error.conflict_kind == Some(crate::domain::ConflictKind::Configuration)
        }) {
            self.shutdown.cancel();
        }
        let mut envelope = diagnostic_request.envelope(result);
        let envelope_bytes = match crate::encoding::serialized_size(&envelope, self.envelope_limit)
        {
            Ok(bytes) => bytes,
            Err(_) => {
                envelope = Envelope::from_result(
                    envelope.request_id().to_owned(),
                    Err(Error::new(ErrorCode::ResponseTooLarge)),
                );
                crate::encoding::serialized_size(&envelope, self.envelope_limit)
                    .map_err(|_| McpError::internal_error("Result unavailable", None))?
            }
        };
        super::diagnostics::result(envelope.request_id(), envelope.error());
        let success = envelope.is_success();
        let value = serde_json::to_value(envelope)
            .map_err(|_| McpError::internal_error("Result unavailable", None))?;
        // Value preserves the envelope's encoded length, including escaped strings.
        // A fixed slice retains that measured bound without geometric String growth.
        let mut encoded = vec![0; envelope_bytes];
        let mut output = encoded.as_mut_slice();
        serde_json::to_writer(&mut output, &value)
            .map_err(|_| McpError::internal_error("Result unavailable", None))?;
        let written = envelope_bytes - output.len();
        encoded.truncate(written);
        let text = String::from_utf8(encoded)
            .map_err(|_| McpError::internal_error("Result unavailable", None))?;
        let mut response = if success {
            CallToolResult::success(vec![ContentBlock::text(text)])
        } else {
            CallToolResult::error(vec![ContentBlock::text(text)])
        };
        response.structured_content = Some(value);
        Ok(response.into())
    }
}

fn guide_resources() -> Vec<Resource> {
    super::guidance::topics()
        .iter()
        .map(|topic| {
            Resource::new(
                format!("mailctl://guide/{topic}"),
                format!("mailctl {topic} guide"),
            )
            .with_description(format!("Read when using mailctl {topic}"))
            .with_mime_type("text/markdown")
        })
        .collect()
}

pub(super) async fn run(application: Application) -> Result<(), Error> {
    let OperationResult::Capabilities(capabilities) = application
        .execute(Operation::Capabilities)
        .await
        .map_err(|error| {
            // Startup must discover the tool surface before negotiating MCP.
            // A ceiling too small for that discovery is an operator setup issue.
            if error.code == ErrorCode::ResponseTooLarge {
                Error::mcp_response_limit_setup_required()
            } else {
                error
            }
        })?
    else {
        return Err(Error::new(ErrorCode::InternalError));
    };
    let limits = application.limits()?;
    let tools = definitions(&capabilities.operations);
    let schema_bytes = crate::encoding::serialized_size(&tools, limits.buffered_bytes)
        .map_err(|_| Error::setup_required())?;
    // Static discovery and guide replies use the transport's control allocation,
    // independent of operation-result ceilings. Measure their encoded sizes too.
    let mut control_bytes = schema_bytes.max(
        crate::encoding::serialized_size(&guide_resources(), limits.buffered_bytes)
            .map_err(|_| Error::setup_required())?,
    );
    control_bytes = control_bytes.max(
        crate::encoding::serialized_size(&super::guidance::instructions(), limits.buffered_bytes)
            .map_err(|_| Error::setup_required())?,
    );
    for topic in super::guidance::topics() {
        let guide = super::guidance::guide(topic).ok_or_else(Error::setup_required)?;
        control_bytes = control_bytes.max(
            crate::encoding::serialized_size(&guide, limits.buffered_bytes)
                .map_err(|_| Error::setup_required())?,
        );
    }
    let bounds = Bounds::new(
        limits,
        application.response_bound()?,
        capabilities.operations.iter().any(|op| op == "save_draft"),
        control_bytes,
    )?;
    let expires = tokio::time::Instant::now()
        + Duration::from_secs(limits.connection_lifetime_seconds as u64);
    let initialization_expires = expires.min(
        tokio::time::Instant::now() + Duration::from_secs(limits.initialization_seconds as u64),
    );
    let shutdown = CancellationToken::new();
    let _cancel_on_exit = shutdown.clone().drop_guard();
    let handler = EmailTools {
        tools,
        envelope_limit: bounds.envelope,
        application: application.with_response_limit(bounds.envelope),
        shutdown: shutdown.clone(),
    };
    let service = tokio::time::timeout_at(
        initialization_expires,
        handler.serve_with_ct(BoundedStdio::new(bounds, shutdown.clone()), shutdown),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        domain::{BodyText, MessageMetadata},
        service::{MemoryBodies, MemoryMailboxes, MemoryMessage, MemoryMessages, Service},
    };
    use std::sync::Arc;

    async fn message_handler(text: String) -> (EmailTools, CallToolRequestParams) {
        let size = text.len();
        let config = Config::parse(&format!(
            r#"
version = 1
default_grant = "reader"
state_dir = {state}
[limits]
text_page_bytes = 2097152
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
            state = serde_json::to_string(&std::env::temp_dir().join("mailctl-mcp-performance"))
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
        let bodies = Arc::new(MemoryBodies::default());
        bodies.set(
            "work",
            "INBOX",
            77,
            4,
            BodyText {
                text,
                selected_part: Some("1".into()),
                source_media_type: Some("text/plain".into()),
                representation_version: "1".into(),
                converted: false,
                replacements: false,
                truncated: false,
                empty_reason: None,
                continuation_available: false,
                next_cursor: None,
            },
        );
        let service = Service::in_memory(config)
            .unwrap()
            .with_mailbox_backend(mailboxes)
            .with_search_backend(messages)
            .with_body_backend(bodies);
        let context = service.context("reader", &Default::default()).unwrap();
        let application = Application::Embedded {
            service: Box::new(service),
            context,
        };
        let OperationResult::Mailboxes(mailboxes) = application
            .execute(Operation::ListMailboxes(Default::default()))
            .await
            .unwrap()
        else {
            panic!("fixture mailbox");
        };
        let OperationResult::Messages(messages) = application
            .execute(
                serde_json::from_value(json!({
                    "operation": "search_messages",
                    "input": {"mailbox": mailboxes.mailboxes[0].reference}
                }))
                .unwrap(),
            )
            .await
            .unwrap()
        else {
            panic!("fixture message");
        };
        let request = CallToolRequestParams::new("email_get_message").with_arguments(
            json!({"message": messages.messages[0].reference, "max_bytes": size})
                .as_object()
                .unwrap()
                .clone(),
        );
        (
            EmailTools {
                tools: definitions(&["get_message".into()]),
                application,
                envelope_limit: 4 * 1024 * 1024,
                shutdown: CancellationToken::new(),
            },
            request,
        )
    }

    #[test]
    fn mcp_message_results_serialize_text_without_geometric_buffer_growth() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut excessive_allocation = Vec::new();
        for size in [64 * 1024, 256 * 1024, 2 * 1024 * 1024] {
            let (handler, request) = runtime.block_on(message_handler("x".repeat(size)));
            let (client_io, server_io) = tokio::io::duplex(8192);
            let (client, server) = runtime
                .block_on(async { tokio::join!(().serve(client_io), handler.serve(server_io)) });
            let client = client.unwrap();
            let server = server.unwrap();
            let context = RequestContext::new(RequestId::Number(1), server.peer().clone());
            let mut response = None;
            let allocation = allocation_counter::measure(|| {
                response = Some(
                    runtime
                        .block_on(server.service().call_tool(request, context))
                        .unwrap(),
                );
            });
            let CallToolResponse::Complete(response) = response.unwrap() else {
                panic!("complete message response");
            };
            assert_eq!(response.is_error, Some(false));
            let structured = response.structured_content.as_ref().unwrap();
            assert_eq!(structured["result"]["body"]["text"], "x".repeat(size));
            assert_eq!(response.content.len(), 1);
            let text = &response.content[0].as_text().unwrap().text;
            assert_eq!(serde_json::from_str::<Value>(text).unwrap(), *structured);
            eprintln!("MCP body bytes={size}, {allocation:?}");
            if allocation.bytes_total > 4 * size as u64 + 64 * 1024 {
                excessive_allocation.push((size, allocation));
            }
            runtime.block_on(async {
                client.cancel().await.unwrap();
                server.cancel().await.unwrap();
            });
        }
        assert!(
            excessive_allocation.is_empty(),
            "MCP results must not repeatedly grow their known-size text buffer: {excessive_allocation:?}"
        );
    }

    #[tokio::test]
    async fn mcp_text_buffers_preserve_escaped_unicode_and_error_envelopes() {
        let expected = "\u{1}\"\\é🦀\n".repeat(1024);
        for limit in [1024, 1024 * 1024] {
            let (mut handler, request) = message_handler(expected.clone()).await;
            handler.envelope_limit = limit;
            let (client_io, server_io) = tokio::io::duplex(8192);
            let (client, server) = tokio::join!(().serve(client_io), handler.serve(server_io));
            let client = client.unwrap();
            let server = server.unwrap();
            let context = RequestContext::new(RequestId::Number(1), server.peer().clone());
            let CallToolResponse::Complete(response) =
                server.service().call_tool(request, context).await.unwrap()
            else {
                panic!("complete message response");
            };
            let structured = response.structured_content.as_ref().unwrap();
            let text = &response.content[0].as_text().unwrap().text;
            assert_eq!(*text, serde_json::to_string(structured).unwrap());
            assert!(text.len() <= limit);
            if limit == 1024 {
                assert_eq!(response.is_error, Some(true));
                assert_eq!(structured["error"]["code"], "response_too_large");
            } else {
                assert_eq!(response.is_error, Some(false));
                assert_eq!(structured["result"]["body"]["text"], expected);
            }
            client.cancel().await.unwrap();
            server.cancel().await.unwrap();
        }
    }
}
