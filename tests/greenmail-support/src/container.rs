use crate::{
    Result,
    api::Api,
    fixtures::{self, BODY, EMAIL, FOLDER_MESSAGE_ID, MESSAGE_ID, PASSWORD, TlsInputs},
};
use std::time::Duration;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};

const IMAGE_TAG: &str =
    "2.1.13@sha256:3df66b7edd01c8a301343ca5e3601d8674760d4708655573560c24745e624fb2";

/// Owns a fresh server. Connections are scoped inside methods and closed before
/// reset/purge. No API or transport handle escapes this exclusive owner.
pub struct Fixture {
    container: ContainerAsync<GenericImage>,
    api: Api,
    tls: tokio_rustls::TlsConnector,
    imaps: u16,
    smtp: u16,
}

impl Fixture {
    /// Prepare test CA/configuration before startup, verify TLS and both login
    /// outcomes independently, then seed synthetic mail after creating the user.
    pub async fn start() -> Result<Self> {
        if std::env::var("TESTCONTAINERS_COMMAND").is_ok_and(|v| v != "remove") {
            return Err(
                "Unset TESTCONTAINERS_COMMAND: Docker tests require remove-on-drop cleanup".into(),
            );
        }
        let tls = TlsInputs::prepare().await?;
        // GreenMail disables authentication when the property EXISTS, even as false.
        // Replace the image defaults and omit greenmail.auth.disabled entirely.
        let opts = "-Dgreenmail.hostname=0.0.0.0 -Dgreenmail.smtp.port=3025 -Dgreenmail.imaps.port=3993 -Dgreenmail.api.port=8080 -Dgreenmail.tls.keystore.file=/tmp/mailctl-server.p12 -Dgreenmail.tls.keystore.password=fixture-only";
        let container = GenericImage::new("greenmail/standalone", IMAGE_TAG)
            .with_env_var("GREENMAIL_OPTS", opts)
            .with_copy_to("/tmp/mailctl-server.p12", tls.keystore)
            .with_mapped_port(0, 3025.tcp())
            .with_mapped_port(0, 3993.tcp())
            .with_mapped_port(0, 8080.tcp())
            .with_host_config_modifier(|host| {
                host.publish_all_ports = Some(false);
                for bindings in host.port_bindings.iter_mut().flat_map(|m| m.values_mut()).flatten() {
                    for binding in bindings {
                        binding.host_ip = Some("127.0.0.1".to_owned());
                    }
                }
            })
            .with_startup_timeout(Duration::from_secs(90))
            .start().await.map_err(|_| "Cannot start pinned GreenMail image; start local Docker and check image access")?;
        let api = Api::new(container.get_host_port_ipv4(8080.tcp()).await?)?;
        let imaps = container.get_host_port_ipv4(3993.tcp()).await?;
        let smtp = container.get_host_port_ipv4(3025.tcp()).await?;
        let fixture = Self {
            container,
            api,
            tls: tls.connector,
            imaps,
            smtp,
        };
        fixture.verify_bindings().await?;
        fixture.initialize().await?;
        Ok(fixture)
    }

    async fn verify_bindings(&self) -> Result<()> {
        let docker = testcontainers::bollard::Docker::connect_with_local_defaults()?;
        let info = docker.inspect_container(self.container.id(), None).await?;
        let ports = info
            .network_settings
            .and_then(|s| s.ports)
            .ok_or("Docker did not report fixture port bindings")?;
        let mut bound = Vec::new();
        for (port, bindings) in ports {
            for binding in bindings.unwrap_or_default() {
                if binding.host_ip.as_deref() != Some("127.0.0.1")
                    || binding
                        .host_port
                        .as_deref()
                        .is_none_or(|p| p == "0" || p.is_empty())
                {
                    return Err(
                        "Docker fixture port is not bound exclusively to random loopback port"
                            .into(),
                    );
                }
                bound.push(port.clone());
            }
        }
        bound.sort();
        if bound != ["3025/tcp", "3993/tcp", "8080/tcp"] {
            return Err("Docker fixture published unexpected ports".into());
        }
        Ok(())
    }

    async fn initialize(&self) -> Result<()> {
        self.api.wait_ready().await?;
        let user = self.api.create_user(EMAIL, PASSWORD).await?;
        if user.email != EMAIL || user.login != EMAIL || self.api.users().await?.len() != 1 {
            return Err("GreenMail user DTO or exclusive account setup mismatch".into());
        }
        fixtures::observe(self.imaps, &self.tls, PASSWORD, true, Some(0)).await?;
        fixtures::observe(self.imaps, &self.tls, "wrong-password", false, None).await?;
        fixtures::seed(self.smtp).await?;
        self.verify_seed().await
    }

    async fn verify_seed(&self) -> Result<()> {
        let messages = self.api.messages(EMAIL, "INBOX").await?;
        if messages.len() != 1
            || messages[0]
                .uid
                .parse::<u64>()
                .ok()
                .is_none_or(|uid| uid == 0)
            || messages[0].message_id != MESSAGE_ID
            || messages[0].subject != "Bootstrap smoke"
            || !messages[0].mime_message.contains(BODY)
        {
            return Err("GreenMail synthetic message content/identity mismatch".into());
        }
        fixtures::observe(self.imaps, &self.tls, PASSWORD, true, Some(1)).await
    }

    pub async fn verify_folder_path_encoding(&self) -> Result<()> {
        fixtures::seed_folder(self.imaps, &self.tls).await?;
        let messages = self.api.messages(EMAIL, "fixture folder/child").await?;
        if messages.len() != 1 || messages[0].message_id != FOLDER_MESSAGE_ID {
            return Err("GreenMail folder path encoding mismatch".into());
        }
        Ok(())
    }

    pub async fn verify_empty(&self) -> Result<()> {
        if !self.api.messages(EMAIL, "INBOX").await?.is_empty() {
            return Err("GreenMail purge retained messages".into());
        }
        fixtures::observe(self.imaps, &self.tls, PASSWORD, true, Some(0)).await
    }

    /// All scoped SMTP and observer connections have closed before this call.
    pub async fn purge(&mut self) -> Result<()> {
        self.api.purge().await
    }

    /// Reset invalidates readiness and users; repeat full authentication and seed checks.
    pub async fn reset(&mut self) -> Result<()> {
        self.api.reset().await?;
        self.initialize().await
    }

    pub async fn delete_user(&mut self) -> Result<()> {
        self.api.delete_user(EMAIL).await?;
        if !self.api.users().await?.is_empty() {
            return Err("GreenMail user cleanup failed".into());
        }
        Ok(())
    }

    /// Explicit deletion; testcontainers remove-on-drop remains the failure fallback.
    pub async fn shutdown(self) -> Result<()> {
        let id = self.container.id().to_owned();
        self.container.rm().await?;
        let docker = testcontainers::bollard::Docker::connect_with_local_defaults()?;
        match docker.inspect_container(&id, None).await {
            Err(testcontainers::bollard::errors::Error::DockerResponseServerError {
                status_code: 404,
                ..
            }) => Ok(()),
            _ => Err("Docker did not confirm fixture container removal".into()),
        }
    }
}
