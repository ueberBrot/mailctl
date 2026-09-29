use crate::{
    config::{CredentialSource, Limits},
    credentials::{Availability, ResolutionLimits, Secret, SecretSource, SourceError},
    host::HostEnvironment,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls::RootCertStore;
use uuid::Uuid;

struct Resolution {
    limits: ResolutionLimits,
    result: oneshot::Sender<Result<Secret, SourceError>>,
}

struct SessionSource(mpsc::Sender<Resolution>);

impl SecretSource for SessionSource {
    fn availability(&self, _: Uuid) -> Availability {
        Availability::Configured
    }

    fn resolve(&self, account: Uuid) -> Result<Secret, SourceError> {
        self.resolve_with_limits(account, &ResolutionLimits::try_from(&Limits::default())?)
    }

    fn resolve_with_limits(
        &self,
        _: Uuid,
        limits: &ResolutionLimits,
    ) -> Result<Secret, SourceError> {
        let (result, response) = oneshot::channel();
        self.0
            .try_send(Resolution {
                limits: *limits,
                result,
            })
            .map_err(|_| SourceError::Unavailable)?;
        response
            .blocking_recv()
            .map_err(|_| SourceError::Unavailable)?
    }
}

struct SessionEnvironment {
    host: Arc<dyn HostEnvironment>,
    source: Arc<SessionSource>,
}

impl HostEnvironment for SessionEnvironment {
    fn credential_source(&self, reference: &CredentialSource) -> Arc<dyn SecretSource> {
        match reference {
            CredentialSource::Session {} => self.source.clone(),
            _ => self.host.credential_source(reference),
        }
    }

    fn tls_roots(&self) -> Result<RootCertStore, SourceError> {
        self.host.tls_roots()
    }
}

pub(in crate::frontends) fn environment(
    host: Arc<dyn HostEnvironment>,
) -> Result<(Arc<dyn HostEnvironment>, impl Future<Output = ()>), SourceError> {
    super::prompt::require_foreground_terminal(&std::io::stdin(), &std::io::stderr())?;
    let (sender, mut receiver) = mpsc::channel::<Resolution>(1);
    let host = Arc::new(SessionEnvironment {
        host,
        source: Arc::new(SessionSource(sender)),
    });
    let prompts = async move {
        while let Some(request) = receiver.recv().await {
            let result = tokio::time::timeout(
                request.limits.timeout(),
                super::prompt(request.limits.secret_bytes()),
            )
            .await
            .unwrap_or(Err(SourceError::Unavailable));
            let _ = request.result.send(result);
        }
        // The invocation owns this future. Dropping it restores the terminal and
        // releases waiting credential workers without retaining a secret cache.
        std::future::pending::<()>().await;
    };
    Ok((host, prompts))
}
