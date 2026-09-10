//! The frontend uses the same operations in an embedded or isolated installation.
use crate::{
    config::Limits,
    domain::{Error, Operation, OperationResult},
    policy::RequestContext,
    service::Service,
};

pub(super) enum Application {
    Embedded {
        service: Box<Service>,
        context: RequestContext,
    },
    #[cfg(target_os = "macos")]
    Isolated(Box<crate::isolation::Client>),
}

impl Application {
    pub fn limits(&self) -> Result<&Limits, Error> {
        match self {
            Self::Embedded { service, context } => service.limits(context),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => Ok(client.limits()),
        }
    }

    #[cfg(feature = "mcp")]
    pub fn response_bound(&self) -> Result<usize, Error> {
        match self {
            Self::Embedded { service, context } => service.response_bound(context),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => Ok(client.response_bound()),
        }
    }

    pub async fn execute(&self, operation: Operation) -> Result<OperationResult, Error> {
        match self {
            Self::Embedded { service, context } => service.execute(context, operation),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => client.execute(operation).await,
        }
    }

    pub async fn doctor(&self, check_account: bool) -> Result<OperationResult, Error> {
        match self {
            Self::Embedded { service, context } => service
                .doctor(context, check_account)
                .await
                .map(OperationResult::Doctor),
            #[cfg(target_os = "macos")]
            Self::Isolated(client) => client.doctor(check_account).await,
        }
    }

    #[cfg(feature = "mcp")]
    pub fn with_response_limit(self, maximum: usize) -> Self {
        match self {
            Self::Embedded { service, context } => Self::Embedded {
                service,
                context: context.with_response_limit(maximum),
            },
            #[cfg(target_os = "macos")]
            Self::Isolated(mut client) => {
                client.limit_response(maximum);
                Self::Isolated(client)
            }
        }
    }
}
