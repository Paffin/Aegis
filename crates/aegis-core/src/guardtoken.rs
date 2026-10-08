//! REQ: AGG-05 — proof that Agent Guard is installed on the machine the request comes from.
//!
//! A device has an Ed25519 key pair made by `aegis-guard enroll`; the gateway knows the public keys.
//! The guard signs the device id and the time (and, if it knows it, the conversation); the gateway
//! accepts the token for five minutes. Without a valid token the gateway behaves as if no guard
//! were there (the rules of Stage 1). The spec says «HMAC with the device key»: a signature does the
//! same job without the gateway (and the signed bundle) holding a secret of every device.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const PREFIX: &str = "ag1";

#[derive(Debug, PartialEq, Eq)]
pub enum GuardError {
    Malformed,
    UnknownDevice,
    Expired,
    FromTheFuture,
    Conversation,
    Signature,
}

fn conv_field(conversation: Option<&str>) -> String {
    match conversation {
        None | Some("") => "-".into(),
        Some(c) => Sha256::digest(c.as_bytes())[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    }
}

fn message(id: &str, ts: i64, conv: &str) -> Vec<u8> {
    format!("aegis-guard-v1\n{id}\n{ts}\n{conv}").into_bytes()
}

pub fn valid_device_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// A token for `now`; `conversation` binds it to one conversation (the gateway then requires the same
/// `X-Aegis-Conversation`).
pub fn issue(device_id: &str, key: &SigningKey, now: i64, conversation: Option<&str>) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    let conv = conv_field(conversation);
    let sig = key.sign(&message(device_id, now, &conv));
    format!(
        "{PREFIX}.{device_id}.{now}.{conv}.{}",
        B64.encode(sig.to_bytes())
    )
}

/// The device the token comes from. `device` returns the public key of a device id.
pub fn verify(
    token: &str,
    device: &dyn Fn(&str) -> Option<VerifyingKey>,
    now: i64,
    max_age_secs: i64,
    conversation: Option<&str>,
) -> Result<String, GuardError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    let parts: Vec<&str> = token.split('.').collect();
    let [p, id, ts, conv, sig] = parts.as_slice() else {
        return Err(GuardError::Malformed);
    };
    if *p != PREFIX || !valid_device_id(id) {
        return Err(GuardError::Malformed);
    }
    let ts: i64 = ts.parse().map_err(|_| GuardError::Malformed)?;
    let sig = B64.decode(sig).map_err(|_| GuardError::Malformed)?;
    let sig = Signature::from_slice(&sig).map_err(|_| GuardError::Malformed)?;
    let key = device(id).ok_or(GuardError::UnknownDevice)?;
    key.verify(&message(id, ts, conv), &sig)
        .map_err(|_| GuardError::Signature)?;
    if ts > now + 60 {
        return Err(GuardError::FromTheFuture);
    }
    if now - ts > max_age_secs {
        return Err(GuardError::Expired);
    }
    // a token bound to a conversation is good for that conversation only
    if *conv != "-" && *conv != conv_field(conversation) {
        return Err(GuardError::Conversation);
    }
    Ok((*id).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SigningKey, impl Fn(&str) -> Option<VerifyingKey>) {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let vk = sk.verifying_key();
        (sk, move |id: &str| (id == "laptop-1").then_some(vk))
    }

    // REQ: AGG-05
    #[test]
    fn a_fresh_token_of_a_known_device_is_accepted() {
        let (sk, dev) = keys();
        let t = issue("laptop-1", &sk, 1000, None);
        assert_eq!(verify(&t, &dev, 1000, 300, None), Ok("laptop-1".into()));
        assert_eq!(
            verify(&t, &dev, 1300, 300, None),
            Ok("laptop-1".into()),
            "five minutes still count"
        );
        assert_eq!(verify(&t, &dev, 1301, 300, None), Err(GuardError::Expired));
        assert_eq!(
            verify(&t, &dev, 900, 300, None),
            Err(GuardError::FromTheFuture)
        );
        assert_eq!(
            verify(&t, &dev, 940, 300, None),
            Ok("laptop-1".into()),
            "a minute of clock skew is fine"
        );
    }

    // REQ: AGG-05
    #[test]
    fn forgeries_are_refused() {
        let (sk, dev) = keys();
        let t = issue("laptop-1", &sk, 1000, None);
        // another device name, another time, another key, garbage
        assert_eq!(
            verify(&t.replace("laptop-1", "laptop-2"), &dev, 1000, 300, None),
            Err(GuardError::UnknownDevice)
        );
        assert_eq!(
            verify(&t.replace(".1000.", ".1001."), &dev, 1001, 300, None),
            Err(GuardError::Signature)
        );
        let other = SigningKey::from_bytes(&[8; 32]);
        assert_eq!(
            verify(
                &issue("laptop-1", &other, 1000, None),
                &dev,
                1000,
                300,
                None
            ),
            Err(GuardError::Signature)
        );
        for bad in [
            "",
            "ag1",
            "ag1.a.b.c",
            "xx.laptop-1.1000.-.AAAA",
            "ag1.laptop-1.x.-.AAAA",
            "ag1.laptop-1.1000.-.!!!",
            &"a.".repeat(50),
        ] {
            assert_eq!(
                verify(bad, &dev, 1000, 300, None),
                Err(GuardError::Malformed),
                "{bad}"
            );
        }
    }

    // REQ: AGG-05
    #[test]
    fn a_token_for_one_conversation_is_not_good_for_another() {
        let (sk, dev) = keys();
        let t = issue("laptop-1", &sk, 1000, Some("conv-a"));
        assert!(verify(&t, &dev, 1000, 300, Some("conv-a")).is_ok());
        assert_eq!(
            verify(&t, &dev, 1000, 300, Some("conv-b")),
            Err(GuardError::Conversation)
        );
        assert_eq!(
            verify(&t, &dev, 1000, 300, None),
            Err(GuardError::Conversation)
        );
        // a token without a conversation is good for any
        let any = issue("laptop-1", &sk, 1000, None);
        assert!(verify(&any, &dev, 1000, 300, Some("conv-b")).is_ok());
    }
}
