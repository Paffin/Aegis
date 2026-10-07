//! REQ: PSE-01, PSE-03, PSE-07, CFG-05, SEC-03, ДОП-1.
//!
//! Key derivation and pseudonym identifiers. HMAC-SHA256 is the only
//! primitive used; a GOST provider can implement `Prf` later without
//! touching callers.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Pseudo-random function keyed by a tenant secret.
pub trait Prf: Send + Sync {
    fn mac(&self, parts: &[&[u8]]) -> [u8; 32];
}

pub struct HmacPrf {
    key: Zeroizing<Vec<u8>>,
}

impl HmacPrf {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Zeroizing::new(key.to_vec()),
        }
    }
}

impl Prf for HmacPrf {
    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key length");
        for p in parts {
            // Length prefix keeps `("ab","c")` distinct from `("a","bc")`.
            m.update(&(p.len() as u32).to_be_bytes());
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }
}

/// Keys of one tenant. `k_audit` is a separate key without salt (ADR-08).
pub struct TenantKeys {
    pub tenant: String,
    pub k_t: Box<dyn Prf>,
    pub k_audit: Box<dyn Prf>,
}

impl TenantKeys {
    pub fn from_secrets(tenant: &str, k_t: &[u8], k_audit: &[u8]) -> Self {
        Self {
            tenant: tenant.to_string(),
            k_t: Box::new(HmacPrf::new(k_t)),
            k_audit: Box::new(HmacPrf::new(k_audit)),
        }
    }
}

/// Conversation salt (PSE-03).
#[derive(Clone)]
pub struct Salt(pub [u8; 32]);

/// Where the salt anchor came from. Used for tests and audit only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorSource {
    Header,
    SessionField,
    FirstUserMessage,
}

pub struct SaltInput<'a> {
    pub principal: &'a str,
    /// Value of `X-Aegis-Conversation`.
    pub header: Option<&'a str>,
    /// Session id taken from the request metadata field configured for the client.
    pub session_field: Option<&'a str>,
    /// All content blocks of the first `user` message, canonicalised.
    pub first_user_message: &'a [&'a str],
}

pub fn derive_salt(keys: &TenantKeys, input: &SaltInput<'_>) -> (Salt, AnchorSource) {
    let (anchor, src): (Vec<u8>, AnchorSource) = if let Some(h) = input.header {
        (h.as_bytes().to_vec(), AnchorSource::Header)
    } else if let Some(s) = input.session_field {
        (s.as_bytes().to_vec(), AnchorSource::SessionField)
    } else {
        // SHA-256 of the whole first user message, every block (not only the first).
        let mut h = Sha256::new();
        for b in input.first_user_message {
            h.update((b.len() as u64).to_be_bytes());
            h.update(b.as_bytes());
        }
        (h.finalize().to_vec(), AnchorSource::FirstUserMessage)
    };
    let mac = keys.k_t.mac(&[
        b"conv",
        keys.tenant.as_bytes(),
        input.principal.as_bytes(),
        &anchor,
    ]);
    (Salt(mac), src)
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// First `n` bytes of `bytes` as lowercase base32 without padding. `n = 5` gives 8 chars.
pub fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// PSE-01: `id = base32lower(HMAC(K_t, "aegis/v1" ‖ salt ‖ type ‖ canon(value)))[0..8]`.
pub fn pseudonym_id(keys: &TenantKeys, salt: &Salt, ty: &str, canon: &str) -> String {
    let mac = keys.k_t.mac(&[
        b"aegis/v1",
        keys.tenant.as_bytes(),
        &salt.0,
        ty.as_bytes(),
        canon.as_bytes(),
    ]);
    base32_lower(&mac[..5])
}

/// AUD-02: hash for audit correlation, unsalted, on a separate key.
pub fn audit_hash(keys: &TenantKeys, ty: &str, canon: &str) -> String {
    let mac = keys.k_audit.mac(&[ty.as_bytes(), canon.as_bytes()]);
    mac[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Prefix-preserving permutation of the low `nbits` of `host` (Crypto-PAn, PSE-07).
/// Two inputs that share a prefix of length `k` produce outputs that share a prefix of length `k`.
pub fn pan_bits(keys: &TenantKeys, salt: &Salt, domain: &[u8], value: u128, nbits: u32) -> u128 {
    let mut out: u128 = 0;
    for i in 0..nbits {
        let shift = nbits - 1 - i;
        let bit = (value >> shift) & 1;
        let prefix = if i == 0 { 0 } else { value >> (shift + 1) };
        let mac = keys.k_t.mac(&[
            b"pan",
            &salt.0,
            domain,
            &i.to_be_bytes(),
            &prefix.to_be_bytes(),
        ]);
        let flip = (mac[0] & 1) as u128;
        out = (out << 1) | (bit ^ flip);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> TenantKeys {
        TenantKeys::from_secrets("t1", b"k-tenant", b"k-audit")
    }

    // REQ: PSE-01
    #[test]
    fn id_is_8_chars_base32_and_deterministic() {
        let k = keys();
        let (s, _) = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: Some("c1"),
                session_field: None,
                first_user_message: &[],
            },
        );
        let a = pseudonym_id(&k, &s, "HOST", "prod-db01");
        let b = pseudonym_id(&k, &s, "HOST", "prod-db01");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert!(a.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')));
        assert_ne!(a, pseudonym_id(&k, &s, "HOST", "prod-db02"));
        assert_ne!(a, pseudonym_id(&k, &s, "IP", "prod-db01"));
    }

    // REQ: PSE-03
    #[test]
    fn salt_anchor_levels() {
        let k = keys();
        let hdr = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: Some("c1"),
                session_field: Some("s"),
                first_user_message: &["x"],
            },
        );
        assert_eq!(hdr.1, AnchorSource::Header);
        let ses = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: None,
                session_field: Some("s"),
                first_user_message: &["x"],
            },
        );
        assert_eq!(ses.1, AnchorSource::SessionField);
        let first = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: None,
                session_field: None,
                first_user_message: &["x"],
            },
        );
        assert_eq!(first.1, AnchorSource::FirstUserMessage);
    }

    // REQ: PSE-03 — a templated first block must not make different conversations collide.
    #[test]
    fn first_message_uses_all_blocks() {
        let k = keys();
        let tmpl = "<system-reminder>CLAUDE.md</system-reminder>";
        let a = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: None,
                session_field: None,
                first_user_message: &[tmpl, "fix bug A"],
            },
        );
        let b = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: None,
                session_field: None,
                first_user_message: &[tmpl, "write docs"],
            },
        );
        assert_ne!(a.0 .0, b.0 .0);
    }

    #[test]
    fn salt_differs_between_principals() {
        let k = keys();
        let a = derive_salt(
            &k,
            &SaltInput {
                principal: "u1",
                header: Some("c"),
                session_field: None,
                first_user_message: &[],
            },
        );
        let b = derive_salt(
            &k,
            &SaltInput {
                principal: "u2",
                header: Some("c"),
                session_field: None,
                first_user_message: &[],
            },
        );
        assert_ne!(a.0 .0, b.0 .0);
    }

    // REQ: PSE-07 — prefix preservation.
    #[test]
    fn pan_preserves_prefixes() {
        let k = keys();
        let (s, _) = derive_salt(
            &k,
            &SaltInput {
                principal: "u",
                header: Some("c"),
                session_field: None,
                first_user_message: &[],
            },
        );
        let a = pan_bits(&k, &s, b"d", 0x0022_1215, 24); // .34.18.21
        let b = pan_bits(&k, &s, b"d", 0x0022_1216, 24); // .34.18.22: shares 22+ bits
        let c = pan_bits(&k, &s, b"d", 0x0023_0000, 24);
        assert_eq!(a >> 2, b >> 2, "same /22 prefix must stay equal");
        assert_ne!(a, b);
        assert_ne!(a >> 8, c >> 8, "different /16 stays different");
        // injective on a sample
        let mut seen = std::collections::HashSet::new();
        for v in 0..4096u128 {
            assert!(seen.insert(pan_bits(&k, &s, b"d", v, 24)));
        }
    }

    #[test]
    fn audit_hash_is_unsalted_and_stable() {
        let k = keys();
        assert_eq!(audit_hash(&k, "SECRET", "x"), audit_hash(&k, "SECRET", "x"));
        assert_eq!(audit_hash(&k, "SECRET", "x").len(), 16);
    }
}
