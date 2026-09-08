use crate::Result;
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::time::Duration;

/// Administrative transport for one exclusively owned loopback fixture.
pub(crate) struct Api {
    base: Url,
    client: Client,
    schema: Value,
}

#[derive(Deserialize)]
pub(crate) struct User {
    pub email: String,
    pub login: String,
}

#[derive(Serialize)]
struct NewUser<'a> {
    email: &'a str,
    login: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Message {
    pub uid: String,
    #[serde(rename = "Message-ID")]
    pub message_id: String,
    pub subject: String,
    pub mime_message: String,
}

#[derive(Deserialize)]
struct Success {
    message: String,
}

impl Api {
    pub fn new(port: u16) -> Result<Self> {
        let mut schema: Value =
            serde_saphyr::from_str(include_str!("../../specs/greenmail-2.1.13.yml"))?;
        // Keep the upstream schema byte-for-byte; apply the documented wire correction.
        schema["components"]["schemas"]["Message"]["properties"]["uid"] =
            serde_json::from_str(include_str!("../../specs/message-uid-schema.json"))?;
        Ok(Self {
            base: Url::parse(&format!("http://127.0.0.1:{port}/api/"))?,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            schema,
        })
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        segments: &[&str],
        input: Option<Value>,
        schema_name: &str,
    ) -> Result<T> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| "invalid fixture URL")?
            .pop_if_empty()
            .extend(segments);
        let mut request = self.client.request(method, url);
        if let Some(input) = input {
            request = request.json(&input);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| "GreenMail API unavailable")?;
        if !response.status().is_success() {
            return Err("GreenMail API returned an unsuccessful status".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err("GreenMail API response exceeded fixture budget".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "GreenMail API returned invalid JSON")?;
        let schema = json!({
            "$ref": format!("#/components/schemas/{schema_name}"),
            "components": self.schema["components"]
        });
        let validator = jsonschema::validator_for(&schema)?;
        if let Some(error) = validator.iter_errors(&value).next() {
            return Err(format!(
                "GreenMail {schema_name} mismatch at {} (schema {})",
                error.instance_path(),
                error.schema_path()
            )
            .into());
        }
        serde_json::from_value(value)
            .map_err(|_| "GreenMail response does not match typed DTO".into())
    }

    pub async fn wait_ready(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let result: Result<Success> = self
                    .request(
                        Method::GET,
                        &["service", "readiness"],
                        None,
                        "SuccessResponse",
                    )
                    .await;
                if let Ok(success) = result
                    && !success.message.is_empty()
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .map_err(|_| "GreenMail administrative readiness timed out")?
    }

    pub async fn create_user(&self, email: &str, password: &str) -> Result<User> {
        self.request(
            Method::POST,
            &["user"],
            Some(serde_json::to_value(NewUser {
                email,
                login: email,
                password,
            })?),
            "User",
        )
        .await
    }

    pub async fn users(&self) -> Result<Vec<User>> {
        self.request(Method::GET, &["user"], None, "Users").await
    }

    pub async fn messages(&self, email: &str, folder: &str) -> Result<Vec<Message>> {
        self.request(
            Method::GET,
            &["user", email, "messages", folder],
            None,
            "Messages",
        )
        .await
    }

    pub async fn delete_user(&self, email: &str) -> Result<()> {
        let _: Success = self
            .request(Method::DELETE, &["user", email], None, "SuccessResponse")
            .await?;
        Ok(())
    }

    pub async fn purge(&self) -> Result<()> {
        self.action("mail", "purge").await
    }
    pub async fn reset(&self) -> Result<()> {
        self.action("service", "reset").await
    }

    async fn action(&self, resource: &str, action: &str) -> Result<()> {
        let _: Success = self
            .request(Method::POST, &[resource, action], None, "SuccessResponse")
            .await?;
        Ok(())
    }
}
