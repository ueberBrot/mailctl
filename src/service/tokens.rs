//! Installation-authenticated resource references and continuation tokens.
use super::{MailboxTarget, Service};
use crate::{
    domain::{Error, ErrorCode},
    policy::RequestContext,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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
        let length = base64::encoded_len(payload.len(), false)
            .and_then(|length| length.checked_add(kind.len()))
            .and_then(|length| length.checked_add(2 + base64::encoded_len(32, false).unwrap()))
            .filter(|length| *length <= maximum)
            .ok_or_else(|| Error::new(ErrorCode::ResponseTooLarge))?;
        let mut token = String::with_capacity(length);
        token.push_str(kind);
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(payload, &mut token);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.registry.reference_key());
        let tag = hmac::sign(&key, token.as_bytes());
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(tag.as_ref(), &mut token);
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
    crate::encoding::json_sha256(value, 4 * 1024 * 1024).map(|digest| crate::encoding::hex(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encoding_allocates_only_the_payload_and_complete_token() {
        let config = crate::config::Config::parse(&format!(
            "version = 1\nstate_dir = {}\naccounts = []\n[[grants]]\nname = 'default'\naccounts = []\n",
            serde_json::to_string(&std::env::temp_dir().join("mailctl-token-test")).unwrap()
        ))
        .unwrap();
        let service = Service::in_memory(config).unwrap();
        let mut measurements = Vec::new();
        for mailbox in [
            "x".repeat(5),
            "x".repeat(6),
            "x".repeat(7),
            "x".repeat(1024),
            "x".repeat(4096),
            "é\\\"\n".repeat(256),
        ] {
            let reference = MessageReference {
                account: "12345678-9abc-4def-8123-456789abcdef",
                generation: 1,
                mailbox: mailbox.as_str(),
                uid_validity: 77,
                uid: 4,
            };
            let payload = serde_json::to_vec(&reference).unwrap();
            let signed = format!("msg1.{}", URL_SAFE_NO_PAD.encode(&payload));
            let key = hmac::Key::new(hmac::HMAC_SHA256, service.registry.reference_key());
            let tag = hmac::sign(&key, signed.as_bytes());
            let expected = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()));
            let mut token = None;
            let measured = allocation_counter::measure(|| {
                token = Some(service.encode("msg1", &reference, 8192).unwrap());
            });
            assert_eq!(token.as_deref(), Some(expected.as_str()));
            assert_eq!(
                service.encode("msg1", &reference, expected.len()).unwrap(),
                expected
            );
            assert_eq!(
                service
                    .encode("msg1", &reference, expected.len() - 1)
                    .unwrap_err()
                    .code,
                ErrorCode::ResponseTooLarge
            );
            eprintln!(
                "token mailbox={} output={} {measured:?}",
                mailbox.len(),
                expected.len()
            );
            measurements.push((payload.len() + expected.len(), measured));
        }
        for (bytes, measured) in measurements {
            assert_eq!(measured.count_total, 2, "{measured:?}");
            assert_eq!(measured.bytes_total, bytes as u64, "{measured:?}");
        }
    }
}
