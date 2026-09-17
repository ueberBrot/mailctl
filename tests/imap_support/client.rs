use mailctl::{
    config, domain,
    imap::{
        AppendOutcome, AttachmentData, AttachmentDecoder, AttachmentListRequest,
        AttachmentMetadata, AuthenticatedConnection, BodyPage, BodyRequest, Error, ImapEndpoint,
        Limits, Mailbox, Metrics, PreparedDraft, TlsMode,
    },
    service::{SearchBatch, SearchRequest},
};
use tokio_rustls::rustls::RootCertStore;

/// Supplies fixture credentials and observes the same connection operations as the application.
pub struct Client {
    endpoint: ImapEndpoint,
    limits: Limits,
    metrics: Metrics,
}
impl Client {
    pub fn new(
        host: String,
        port: u16,
        mode: TlsMode,
        roots: RootCertStore,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            endpoint: ImapEndpoint::new(host, port, mode, roots, limits.clone())?,
            limits,
            metrics: Metrics::default(),
        })
    }
    pub fn metrics(&self) -> Metrics {
        self.metrics
    }
    pub fn append_outcome(&self) -> Option<AppendOutcome> {
        self.metrics.append_outcome
    }

    async fn run<T, E: From<Error>>(
        &mut self,
        username: &str,
        password: &str,
        operation: impl AsyncFnOnce(AuthenticatedConnection, &Limits, &mut Metrics) -> Result<T, E>,
    ) -> Result<T, E> {
        tokio::time::timeout(self.limits.operation_timeout, async {
            let connection = self
                .endpoint
                .connect_authenticated(username, password, &mut self.metrics)
                .await?;
            operation(connection, &self.limits, &mut self.metrics).await
        })
        .await
        .map_err(|_| E::from(Error::Timeout))?
    }
    pub async fn discover(
        &mut self,
        username: &str,
        password: &str,
        names: &[String],
    ) -> Result<Vec<Mailbox>, Error> {
        self.run(username, password, async |connection, limits, metrics| {
            connection.discover(names, limits, metrics).await
        })
        .await
    }
    pub async fn search_messages(
        &mut self,
        username: &str,
        password: &str,
        request: SearchRequest<'_>,
        limits: &config::Limits,
    ) -> Result<SearchBatch, domain::Error> {
        self.run(username, password, async |connection, _, metrics| {
            connection.search(request, limits, metrics).await
        })
        .await
    }
    pub async fn search_window(
        &mut self,
        username: &str,
        password: &str,
        mailbox: &str,
        validity: u32,
        window: std::ops::RangeInclusive<u32>,
    ) -> Result<SearchBatch, domain::Error> {
        let limits = config::Limits {
            search_uid_window: (window.end() - window.start() + 1) as usize,
            search_windows: 1,
            header_bytes: self.limits.max_header_bytes,
            wire_fetch_bytes: self.limits.max_operation_bytes,
            ..Default::default()
        };
        self.search_messages(
            username,
            password,
            SearchRequest {
                mailbox,
                criteria: &domain::SearchCriteria::default(),
                position: Some(mailctl::service::SearchPosition {
                    uid_validity: validity,
                    upper_uid: *window.end(),
                    next_uid: *window.end(),
                }),
                limit: limits.search_page,
                response_bytes: limits.envelope_bytes,
            },
            &limits,
        )
        .await
    }
    pub async fn read_body(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: BodyRequest,
    ) -> Result<BodyPage, Error> {
        self.run(username, password, async |connection, limits, metrics| {
            connection.read_body(name, request, limits, metrics).await
        })
        .await
    }
    pub async fn list_attachments(
        &mut self,
        username: &str,
        password: &str,
        name: &str,
        request: AttachmentListRequest,
    ) -> Result<Vec<AttachmentMetadata>, Error> {
        self.run(username, password, async |connection, limits, metrics| {
            connection
                .list_attachments(name, request, limits, metrics)
                .await
        })
        .await
    }
    pub async fn read_attachment(
        &mut self,
        username: &str,
        password: &str,
        decoder: &mut AttachmentDecoder,
    ) -> Result<AttachmentData, Error> {
        self.run(username, password, async |connection, limits, metrics| {
            connection.read_attachment(decoder, limits, metrics).await
        })
        .await
    }
    pub async fn append_draft(
        &mut self,
        username: &str,
        password: &str,
        target: &str,
        draft: &PreparedDraft,
    ) -> Result<AppendOutcome, Error> {
        let connection = self
            .endpoint
            .connect_authenticated(username, password, &mut self.metrics)
            .await?;
        connection
            .append_draft(target, draft, &self.limits, &mut self.metrics)
            .await
    }
}
