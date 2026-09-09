//! Authorized diagnostics and stable operator credential references.
use super::Service;
use crate::{
    authentication::{self, Runtime},
    config::{AccountConfig, Topology},
    credentials::{self, SecretSource},
    domain::{
        AuthenticationCheck, AuthenticationOutcome, CredentialFailure, Doctor, DoctorAccount,
        Error, ErrorCode, SourceAvailability,
    },
    encoding::serialized_size,
    policy::{Permission, RequestContext},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_rustls::rustls::RootCertStore;
use uuid::Uuid;

impl Service {
    /// Inspects authorized sources. Authentication requires one selected account
    /// and an explicit request; health and account discovery never authenticate.
    pub async fn doctor(
        &self,
        context: &RequestContext,
        check_account: bool,
    ) -> Result<Doctor, Error> {
        let deadline = Duration::from_secs(self.grant(context)?.limits.operation_seconds as u64);
        tokio::time::timeout(deadline, self.doctor_inner(context, check_account))
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout))?
    }

    async fn doctor_inner(
        &self,
        context: &RequestContext,
        check_account: bool,
    ) -> Result<Doctor, Error> {
        let grant = self.grant(context)?;
        self.registry.check_revision()?;
        if !context.permissions().contains(&Permission::ListAccounts) {
            return Err(Error::new(ErrorCode::PermissionDenied));
        }
        let accounts: Vec<_> = self.visible_accounts(context).collect();
        if check_account && accounts.len() != 1 {
            return Err(if accounts.is_empty() {
                Error::new(ErrorCode::AccountNotAllowed)
            } else {
                select_account()
            });
        }
        let mut result = Doctor {
            status: "ready".into(),
            topology: match self.config.topology {
                Topology::Native => "native",
                Topology::LinuxNativeWsl => "linux_native_wsl",
                Topology::WindowsHostedWsl => "windows_hosted_wsl",
            }
            .into(),
            installation_id: self.registry.installation().to_owned(),
            configuration_revision: self.registry.revision().to_owned(),
            grant: context.grant_name().to_owned(),
            prerequisites: Vec::new(),
            accounts: Vec::with_capacity(accounts.len()),
        };
        match self.config.topology {
            Topology::Native => {}
            Topology::LinuxNativeWsl => result.prerequisites.push(
                "Linux-native WSL requires a Linux executable and a provisioned Linux credential source".into()),
            Topology::WindowsHostedWsl => result.prerequisites.push(
                "Windows-hosted WSL requires Windows executables and the Windows execution identity's credential store".into()),
        }
        // Reserve a fixed upper bound for each safe status before source work.
        if accounts.len().saturating_mul(1024).saturating_add(1024) > context.response_limit() {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        let runtime = self.authentication().await?;
        for configured in accounts {
            let account = self.authentication_account(configured)?;
            if let Some(prerequisite) = account.source.prerequisite()
                && !result
                    .prerequisites
                    .iter()
                    .any(|entry| entry == prerequisite)
            {
                result.prerequisites.push(prerequisite.into());
            }
            let source = runtime
                .inspect_with_limits(
                    account.id,
                    account.generation,
                    account.source.clone(),
                    &grant.limits,
                )
                .await
                .map_err(authentication_error)?;
            if matches!(
                source,
                credentials::Availability::Missing
                    | credentials::Availability::Locked
                    | credentials::Availability::AccessDenied
                    | credentials::Availability::Unavailable
                    | credentials::Availability::InteractionRequired
            ) {
                // Local administration remains usable even when an account's
                // credential source needs attention. This is not authentication.
                result.status = "degraded".into();
            }
            let authentication = if check_account {
                let outcome = match runtime.doctor(&account, &grant.limits).await {
                    Ok(()) => AuthenticationOutcome::Authenticated,
                    Err(error) => {
                        result.status = "degraded".into();
                        AuthenticationOutcome::Failed {
                            error: authentication_error(error),
                        }
                    }
                };
                Some(AuthenticationCheck {
                    checked_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| Error::new(ErrorCode::InternalError))?
                        .as_secs(),
                    outcome,
                })
            } else {
                None
            };
            result.accounts.push(DoctorAccount {
                account_id: account.id.to_string(),
                generation: account.generation,
                source: source_availability(source),
                authentication,
            });
        }
        result
            .accounts
            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
        serialized_size(&result, context.response_limit().saturating_sub(512))?;
        Ok(result)
    }

    async fn authentication(&self) -> Result<&Runtime, Error> {
        self.authentication
            .get_or_try_init(|| async {
                let roots = tokio::task::spawn_blocking(|| -> Result<_, Error> {
                    credentials::prepare_native_access().map_err(credential_error)?;
                    let mut roots = RootCertStore::empty();
                    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
                    Ok(roots)
                })
                .await
                .map_err(|_| Error::new(ErrorCode::InternalError))??;
                Runtime::new(self.config.limits.clone(), roots).map_err(authentication_error)
            })
            .await
    }

    fn authentication_account(
        &self,
        configured: &AccountConfig,
    ) -> Result<authentication::Account, Error> {
        let (id, generation) = self.registry.identity(&configured.key);
        Ok(authentication::Account {
            id: Uuid::parse_str(id).map_err(|_| Error::new(ErrorCode::InternalError))?,
            generation,
            config: configured.clone(),
            source: credentials::source_for(&configured.credential),
        })
    }

    pub(crate) fn credential_source(
        &self,
        selected: &[String],
    ) -> Result<(Uuid, Arc<dyn SecretSource>), Error> {
        self.registry.check_revision()?;
        let account = match selected {
            [] if self.config.accounts.len() == 1 => &self.config.accounts[0],
            [alias] => self
                .config
                .accounts
                .iter()
                .find(|account| account.alias == *alias)
                .ok_or_else(|| Error::new(ErrorCode::AccountNotAllowed))?,
            _ => return Err(select_account()),
        };
        let binding = self.authentication_account(account)?;
        Ok((binding.id, binding.source))
    }

    pub(crate) fn secret_limit(&self) -> usize {
        self.config.limits.secret_bytes
    }
}

fn select_account() -> Error {
    Error {
        message: "Select exactly one email account with --account".into(),
        ..Error::new(ErrorCode::InvalidRequest)
    }
}

pub(crate) fn source_availability(value: credentials::Availability) -> SourceAvailability {
    match value {
        credentials::Availability::Available => SourceAvailability::Available,
        credentials::Availability::Missing => SourceAvailability::Missing,
        credentials::Availability::Locked => SourceAvailability::Locked,
        credentials::Availability::AccessDenied => SourceAvailability::AccessDenied,
        credentials::Availability::Unavailable => SourceAvailability::Unavailable,
        credentials::Availability::Configured => SourceAvailability::Configured,
        credentials::Availability::InteractionRequired => SourceAvailability::InteractionRequired,
        credentials::Availability::Unknown => SourceAvailability::Unknown,
    }
}

pub(crate) fn credential_error(failure: credentials::SourceError) -> Error {
    let failure = match failure {
        credentials::SourceError::Missing => CredentialFailure::Missing,
        credentials::SourceError::Locked => CredentialFailure::Locked,
        credentials::SourceError::AccessDenied => CredentialFailure::AccessDenied,
        credentials::SourceError::Unavailable => CredentialFailure::Unavailable,
        credentials::SourceError::InvalidSecret => CredentialFailure::InvalidSecret,
        credentials::SourceError::InteractionRequired => CredentialFailure::InteractionRequired,
        credentials::SourceError::Internal => CredentialFailure::Internal,
    };
    Error {
        message: match failure {
            CredentialFailure::InteractionRequired => {
                "Credential input or store access requires an operator terminal"
            }
            CredentialFailure::Missing => "No credential is provisioned for this email account",
            CredentialFailure::InvalidSecret => {
                "Credential is empty, invalid, or exceeds the configured limit"
            }
            CredentialFailure::Locked => "Credential store is locked",
            CredentialFailure::AccessDenied => "Credential store denied access",
            CredentialFailure::Unavailable => {
                "Credential source is unavailable; provision it through its configured owner"
            }
            CredentialFailure::Internal => "Credential operation failed",
        }
        .into(),
        credential_failure: Some(failure),
        ..Error::new(ErrorCode::CredentialUnavailable)
    }
}

fn authentication_error(error: authentication::Error) -> Error {
    match error {
        authentication::Error::Source(error) => credential_error(error),
        authentication::Error::RateLimited => Error::new(ErrorCode::RateLimited),
        authentication::Error::Timeout => Error::new(ErrorCode::Timeout),
        authentication::Error::InvalidInput => Error::new(ErrorCode::InvalidRequest),
        authentication::Error::Imap(error) => Error::new(match error {
            crate::imap::Error::Authentication => ErrorCode::AuthenticationFailed,
            crate::imap::Error::Tls => ErrorCode::TlsFailed,
            crate::imap::Error::Timeout => ErrorCode::Timeout,
            crate::imap::Error::Unsupported => ErrorCode::UnsupportedCapability,
            crate::imap::Error::Limit => ErrorCode::ResponseTooLarge,
            crate::imap::Error::InvalidInput => ErrorCode::InvalidRequest,
            _ => ErrorCode::ProviderUnavailable,
        }),
    }
}
