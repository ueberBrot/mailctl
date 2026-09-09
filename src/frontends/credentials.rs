//! Explicit operator credential commands shared by both executables.
use super::arguments::Credential;
#[cfg(not(unix))]
use crate::credentials::Secret;
use crate::{
    credentials::SourceError,
    domain::{CredentialStatus, Error, ErrorCode, Provisioning},
    service::{Service, credential_error},
};

pub(super) async fn execute(
    service: Service,
    selected: &[String],
    command: Credential,
    json: bool,
) -> Result<(CredentialStatus, Service), Error> {
    let (id, source) = service.credential_source(selected)?;
    let mutable = source.mutable_store().is_some();
    let secret = match command {
        Credential::Set => {
            if json {
                return Err(credential_error(SourceError::InteractionRequired));
            }
            if !mutable {
                return Err(credential_error(SourceError::Unavailable));
            }
            Some(
                prompt(service.secret_limit())
                    .await
                    .map_err(credential_error)?,
            )
        }
        Credential::Delete if !mutable => {
            return Err(credential_error(SourceError::Unavailable));
        }
        Credential::Delete | Credential::Status => None,
    };
    // Retain the installation lease until blocking work finishes, even after cancellation.
    tokio::task::spawn_blocking(move || {
        match command {
            Credential::Set => source
                .mutable_store()
                .expect("credential store was validated before prompting")
                .set(id, secret.as_ref().expect("prompt supplied a credential")),
            Credential::Delete => source
                .mutable_store()
                .expect("credential store was validated before deletion")
                .delete(id),
            Credential::Status => Ok(()),
        }
        .map_err(credential_error)?;
        let status = CredentialStatus {
            account_id: id.to_string(),
            availability: source.availability(id),
            provisioning: if mutable {
                Provisioning::Operator
            } else {
                Provisioning::External
            },
        };
        Ok((status, service))
    })
    .await
    .map_err(|_| Error::new(ErrorCode::InternalError))?
}

#[cfg(unix)]
mod prompt;
#[cfg(unix)]
use prompt::prompt;

#[cfg(not(unix))]
async fn prompt(_: usize) -> Result<Secret, SourceError> {
    Err(SourceError::InteractionRequired)
}
