//! A bounded body read owns selection, byte retrieval, representation, and continuation.
mod representation;

use super::{
    Error, ImapProbe, Limits, Metrics, credentials, fetch::Fetch, mailbox, mime::part_name,
    wire::Connection,
};
use io_imap::{
    rfc3501::logout::ImapLogout,
    types::{body::BodyStructure, fetch::Section},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// In-memory continuation for this route proof. Public authenticated tokens belong to
/// the application reading contract. A continuation is revalidated after each fetch.
#[derive(Clone, Debug)]
pub struct BodyCursor {
    fingerprint: [u8; 32],
    offset: usize,
}

#[derive(Clone, Debug)]
pub struct BodyRequest {
    pub uid: u32,
    pub uid_validity: u32,
    pub continuation: Option<BodyCursor>,
}
impl BodyRequest {
    pub fn new(uid: u32, uid_validity: u32) -> Self {
        Self {
            uid,
            uid_validity,
            continuation: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BodyPage {
    pub text: String,
    pub selected_part: Option<String>,
    pub source_media_type: Option<String>,
    pub representation_version: &'static str,
    pub converted: bool,
    pub replacements: bool,
    pub truncated: bool,
    pub continuation: Option<BodyCursor>,
    pub metrics: Metrics,
}

const REPRESENTATION: &str = "mailctl-body-1/mail-parser-0.11.8/html2text-0.17.1";

impl ImapProbe {
    /// Reads one selected body under an exclusive connection lease, checking the
    /// expected UIDVALIDITY before fetching. Cancellation disposes the connection.
    /// Each continuation refetches within the same finite bounds.
    pub async fn read_body(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: BodyRequest,
    ) -> Result<BodyPage, Error> {
        self.metrics = Metrics::default();
        credentials(username, password)?;
        mailbox(name)?;
        if request.uid == 0 || request.uid_validity == 0 {
            return Err(Error::InvalidInput);
        }
        let limits = self.limits.clone();
        let mut context = Sha256::new();
        for value in [self.host.as_str(), username, name, REPRESENTATION] {
            context.update(value.len().to_be_bytes());
            context.update(value.as_bytes());
        }
        context.update(self.port.to_be_bytes());
        context.update(request.uid.to_be_bytes());
        context.update(request.uid_validity.to_be_bytes());
        context.update(format!("{limits:?}").as_bytes());
        tokio::time::timeout(limits.operation_timeout, async {
            let mut conn = self.authenticate(username, password).await?;
            let page = read_selected(&mut conn, name, request, &limits, context).await?;
            drop(conn);
            self.metrics = page.metrics;
            Ok(page)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

impl super::AuthenticatedConnection {
    pub(crate) async fn read_body(
        self,
        name: &str,
        request: BodyRequest,
        limits: &crate::config::Limits,
    ) -> Result<BodyPage, Error> {
        let limits = Limits {
            max_body_wire_bytes: limits.wire_fetch_bytes,
            max_header_bytes: limits.header_bytes,
            max_nesting: limits.mime_depth,
            max_mime_parts: limits.mime_parts,
            max_text_bytes: limits.text_page_bytes,
            max_operation_bytes: 16 * 1024 * 1024,
            max_response_bytes: 256 * 1024,
            max_literal_bytes: 64 * 1024,
            ..Limits::default()
        };
        limits.validate()?;
        let mut metrics = Metrics::default();
        let mut conn = self.0.resume(&mut metrics);
        conn.limit_body(&limits);
        read_selected(&mut conn, name, request, &limits, Sha256::new()).await
    }
}

async fn read_selected(
    conn: &mut Connection<'_>,
    name: &str,
    request: BodyRequest,
    limits: &Limits,
    mut context: Sha256,
) -> Result<BodyPage, Error> {
    mailbox(name)?;
    if request.uid == 0 || request.uid_validity == 0 {
        return Err(Error::InvalidInput);
    }
    if conn.examine(name).await? != request.uid_validity {
        return Err(Error::StaleReference);
    }
    let metadata = Fetch::Metadata { uid: request.uid };
    let fields = metadata.execute(conn).await?;
    let (size, structure) = metadata.metadata(&fields)?;
    // Validate every MIME node, including excluded attachment subtrees.
    let mut related_ids = HashMap::new();
    let needed_headers = representation::related_multipart_headers(structure, limits)?;
    let mut header_bytes = 0;
    let root_headers = headers(
        conn,
        request.uid,
        Section::Header(None),
        limits,
        &mut header_bytes,
    )
    .await?;
    representation::validate_headers(&root_headers, None, limits)?;
    for path in needed_headers {
        let raw = headers(
            conn,
            request.uid,
            Section::Mime(path.clone()),
            limits,
            &mut header_bytes,
        )
        .await?;
        if let Some(id) = representation::validate_headers(&raw, None, limits)? {
            related_ids.insert(path, id);
        }
    }
    let selected = representation::select(structure, limits, &related_ids)?;
    let rendered = if let Some(selected) = &selected {
        if selected.wire_size > limits.max_body_wire_bytes {
            return Err(Error::Limit);
        }
        let single = matches!(structure, BodyStructure::Single { .. });
        if single {
            representation::validate_headers(&root_headers, Some(selected), limits)?;
        }
        let (raw, body_offset) = if single && size as usize <= limits.max_body_wire_bytes {
            let whole = bytes(
                conn,
                request.uid,
                None,
                Some(size as usize),
                limits.max_body_wire_bytes,
                limits,
            )
            .await?;
            if !whole.starts_with(&root_headers)
                || whole.len() - root_headers.len() > selected.wire_size
            {
                return Err(Error::Protocol);
            }
            (whole, root_headers.len())
        } else {
            (
                bytes(
                    conn,
                    request.uid,
                    Some(Section::Part(selected.part.clone())),
                    Some(selected.wire_size),
                    limits.max_body_wire_bytes,
                    limits,
                )
                .await?,
                0,
            )
        };
        let body = &raw[body_offset..];
        context.update(body);
        tokio::task::yield_now().await;
        Some(representation::render(selected, body, limits)?)
    } else {
        None
    };
    conn.drive(ImapLogout::new()).await?;
    let mut metrics = conn.metrics();
    let (text, converted, replacements) = if let Some(rendered) = rendered {
        metrics.decode_steps = rendered.work;
        metrics.decoded_bytes = rendered.text.len();
        (rendered.text, rendered.converted, rendered.replacements)
    } else {
        (String::new(), false, false)
    };
    let selected_part = selected.as_ref().map(|selected| {
        let name = part_name(&selected.part);
        context.update(name.as_bytes());
        context.update(selected.media_type.as_bytes());
        context.update(selected.charset.as_bytes());
        context.update(selected.transfer_encoding.as_bytes());
        name
    });
    context.update(text.as_bytes());
    let fingerprint = context.finalize().into();
    let offset = match request.continuation {
        Some(cursor)
            if cursor.fingerprint == fingerprint
                && text.is_char_boundary(cursor.offset)
                && cursor.offset < text.len() =>
        {
            cursor.offset
        }
        Some(_) => return Err(Error::StaleCursor),
        None => 0,
    };
    let end = text.floor_char_boundary(offset + limits.max_text_bytes);
    let continuation = (end < text.len()).then_some(BodyCursor {
        fingerprint,
        offset: end,
    });
    Ok(BodyPage {
        text: if offset == 0 && end == text.len() {
            text
        } else {
            text[offset..end].to_owned()
        },
        selected_part,
        source_media_type: selected.map(|s| s.media_type),
        representation_version: REPRESENTATION,
        converted,
        replacements,
        truncated: continuation.is_some(),
        continuation,
        metrics,
    })
}

async fn headers(
    conn: &mut Connection<'_>,
    uid: u32,
    section: Section<'static>,
    limits: &Limits,
    used: &mut usize,
) -> Result<Vec<u8>, Error> {
    let remaining = limits
        .max_header_bytes
        .checked_sub(*used)
        .ok_or(Error::Limit)?;
    let mut value = bytes(conn, uid, Some(section), None, remaining, limits).await?;
    *used += value.len();
    if !value.ends_with(b"\r\n") {
        return Err(Error::Protocol);
    }
    // GreenMail omits the empty separator from complete HEADER/MIME sections.
    // The short partial response has already established EOF; normalize only
    // that missing separator, within the shared header budget.
    if !value.ends_with(b"\r\n\r\n") && value != b"\r\n" {
        if *used + 2 > limits.max_header_bytes {
            return Err(Error::Limit);
        }
        value.extend_from_slice(b"\r\n");
        *used += 2;
    }
    Ok(value)
}

async fn bytes(
    conn: &mut Connection<'_>,
    uid: u32,
    section: Option<Section<'static>>,
    expected: Option<usize>,
    budget: usize,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let ceiling = expected.unwrap_or(budget);
    if ceiling > budget {
        return Err(Error::Limit);
    }
    let chunk = (16 * 1024)
        .min(limits.max_literal_bytes)
        .min(limits.max_response_bytes / 2);
    if chunk == 0 {
        return Err(Error::InvalidInput);
    }
    let mut result = Vec::new();
    loop {
        let count = chunk.min(ceiling + 1 - result.len());
        let fetch = Fetch::Bytes {
            uid,
            section: section.clone(),
            offset: result.len() as u32,
            count: count as u32,
        };
        let items = fetch.execute(conn).await?;
        let value = fetch.data(&items)?;
        if value.len() > budget.saturating_sub(result.len()) {
            return Err(Error::Limit);
        }
        result.extend_from_slice(value);
        if result.len() > ceiling {
            return Err(Error::Protocol);
        }
        if value.len() < count {
            // BODYSTRUCTURE size is an admission hint: some servers include
            // MIME headers in it. A short partial response establishes EOF.
            return Ok(result);
        }
    }
}
