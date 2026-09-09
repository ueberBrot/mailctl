//! Explicit operator credential commands shared by both executables.
use super::arguments::Credential;
#[cfg(not(unix))]
use crate::credentials::Secret;
use crate::{
    credentials::SourceError,
    domain::{CredentialStatus, Error, ErrorCode, Provisioning},
    service::{Service, credential_error, source_availability},
};

pub(super) async fn execute(
    service: Service,
    selected: Vec<String>,
    command: Credential,
    json: bool,
) -> Result<(CredentialStatus, Service), Error> {
    let (id, source) = service.credential_source(&selected)?;
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
    let (result, service) = tokio::task::spawn_blocking(move || {
        let result = match command {
            Credential::Set => source
                .mutable_store()
                .expect("credential store was validated before prompting")
                .set(id, secret.as_ref().expect("prompt supplied a credential"))
                .map_err(credential_error),
            Credential::Delete => source
                .mutable_store()
                .expect("credential store was validated before deletion")
                .delete(id)
                .map_err(credential_error),
            Credential::Status => Ok(()),
        };
        let status = result.map(|()| CredentialStatus {
            account_id: id.to_string(),
            availability: source_availability(source.availability(id)),
            provisioning: if mutable {
                Provisioning::Operator
            } else {
                Provisioning::External
            },
        });
        (status, service)
    })
    .await
    .map_err(|_| Error::new(ErrorCode::InternalError))?;
    result.map(|status| (status, service))
}

#[cfg(unix)]
mod prompt;
#[cfg(unix)]
use prompt::prompt;

#[cfg(not(unix))]
async fn prompt(_: usize) -> Result<Secret, SourceError> {
    Err(SourceError::InteractionRequired)
}
