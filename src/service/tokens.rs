//! Installation-authenticated resource references and continuation tokens.
use super::{MailboxTarget, Service};
use crate::{
    domain::{Error, ErrorCode},
    encoding::OutputBudget,
    policy::RequestContext,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MessageReference<S = String> {
    pub account: S,
    pub generation: u64,
    pub mailbox: S,
    pub uid_validity: u32,
    pub uid: u32,
}

impl Service {
    pub(super) fn authorize_message<'a>(
        &'a self,
        context: &'a RequestContext,
        reference: &MessageReference,
        stale: ErrorCode,
    ) -> Result<MailboxTarget<'a>, Error> {
        let target = self
            .authorize_mailbox(
                context,
                &reference.account,
                reference.generation,
                &reference.mailbox,
            )
            .map_err(|error| {
                if error.code == ErrorCode::StaleReference {
                    Error::new(stale)
                } else {
                    error
                }
            })?;
        if reference.uid == 0 || reference.uid_validity == 0 {
            return Err(Error::new(stale));
        }
        Ok(target)
    }

    pub(super) fn encode(
        &self,
        kind: &str,
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<String, Error> {
        let payload = crate::encoding::serialize_bounded(value, maximum)?;
        let mut token = format!("{kind}.");
        URL_SAFE_NO_PAD.encode_string(payload, &mut token);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.registry.reference_key());
        let tag = hmac::sign(&key, token.as_bytes());
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(tag.as_ref(), &mut token);
        if token.len() > maximum {
            return Err(Error::new(ErrorCode::ResponseTooLarge));
        }
        Ok(token)
    }
    pub(super) fn decode<T: DeserializeOwned>(
        &self,
        kind: &str,
        token: &str,
        maximum: usize,
        code: ErrorCode,
    ) -> Result<T, Error> {
        let invalid = || Error::new(code);
        if token.len() > maximum {
            return Err(invalid());
        }
        let (signed, tag) = token.rsplit_once('.').ok_or_else(invalid)?;
        let (version, payload) = signed.split_once('.').ok_or_else(invalid)?;
        if version != kind {
            return Err(invalid());
        }
        let mut signature = [0; 32];
        if URL_SAFE_NO_PAD
            .decode_slice(tag, &mut signature)
            .map_err(|_| invalid())?
            != signature.len()
        {
            return Err(invalid());
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.registry.reference_key());
        hmac::verify(&key, signed.as_bytes(), &signature).map_err(|_| invalid())?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?;
        serde_json::from_slice(&payload).map_err(|_| invalid())
    }
}
pub(super) fn fingerprint(value: &impl Serialize) -> Result<String, Error> {
    let mut writer = Fingerprint {
        digest: Sha256::new(),
        budget: OutputBudget::new(4 * 1024 * 1024),
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| Error::new(ErrorCode::ResponseTooLarge))?;
    Ok(crate::encoding::hex(writer.digest.finalize().as_slice()))
}

struct Fingerprint {
    digest: Sha256,
    budget: OutputBudget,
}
impl std::io::Write for Fingerprint {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.budget
            .reserve(bytes.len())
            .map_err(std::io::Error::other)?;
        self.digest.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
