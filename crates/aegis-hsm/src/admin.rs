//! REQ: CFG-07 — put a key object into a token: generated inside it (the key never exists anywhere
//! else) or imported once from the bytes of an existing key (so that pseudonyms and the code index
//! built before the move stay valid). Either way the object is created non-extractable and sensitive,
//! and read back to prove it.

use crate::spec::Pkcs11Spec;
use crate::token::{find_slot, login, op, HsmError, KeyInfo, Pkcs11Key, MIN_KEY_BYTES};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::types::{AuthPin, Ulong};

pub enum Material<'a> {
    /// A new random key of this many bytes, made by the token.
    Generate(usize),
    /// Existing bytes. They pass through this process once and are gone from the token's side of
    /// the wall only in the sense that the token will never give them back.
    Import(&'a [u8]),
}

/// Create the key object the specification names. Refuses to replace an existing one: replacing a
/// key changes every pseudonym and invalidates every code index.
pub fn create_key(
    spec: &Pkcs11Spec,
    pin: &str,
    material: Material<'_>,
) -> Result<KeyInfo, HsmError> {
    let len = match &material {
        Material::Generate(n) => *n,
        Material::Import(b) => b.len(),
    };
    if (len as u64) < MIN_KEY_BYTES || len > 512 {
        return Err(HsmError::Key(format!(
            "длина ключа {len} байт: нужно от {MIN_KEY_BYTES} до 512"
        )));
    }
    let ctx = crate::token::module(&spec.module)?;
    let found = find_slot(&ctx, spec)?;
    let session = ctx.open_rw_session(found.slot).map_err(op)?;
    let pin_secret = AuthPin::new(pin.to_string().into_boxed_str());
    login(&session, &pin_secret)?;

    let mut probe = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::Label(spec.label.as_bytes().to_vec()),
    ];
    if let Some(id) = &spec.id {
        probe.push(Attribute::Id(id.clone()));
    }
    if !session.find_objects(&probe).map_err(op)?.is_empty() {
        return Err(HsmError::Key(format!(
            "объект «{}» уже есть в токене; удалите его вручную, если ключ нужно заменить (это изменит все псевдонимы и сделает индекс кода непригодным)",
            spec.label
        )));
    }

    let mut t = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Label(spec.label.as_bytes().to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Verify(false),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Derive(false),
    ];
    if let Some(id) = &spec.id {
        t.push(Attribute::Id(id.clone()));
    }
    let handle = match material {
        Material::Generate(n) => {
            t.push(Attribute::ValueLen(Ulong::from(n as u64)));
            session
                .generate_key(&Mechanism::GenericSecretKeyGen, &t)
                .map_err(op)?
        }
        Material::Import(bytes) => {
            t.push(Attribute::Value(bytes.to_vec()));
            session.create_object(&t).map_err(op)?
        }
    };

    // Read back what the token made of the template: a token may quietly ignore an attribute.
    let back = session
        .get_attributes(
            handle,
            &[
                AttributeType::Extractable,
                AttributeType::Sensitive,
                AttributeType::Value,
            ],
        )
        .map_err(op)?;
    let mut leaks = back.iter().any(|a| matches!(a, Attribute::Value(_)));
    for a in &back {
        match a {
            Attribute::Extractable(true) => leaks = true,
            Attribute::Sensitive(false) => leaks = true,
            _ => {}
        }
    }
    if leaks {
        let _ = session.destroy_object(handle);
        return Err(HsmError::Key(
            "токен создал извлекаемый ключ (проигнорировал CKA_EXTRACTABLE/CKA_SENSITIVE); объект удалён".into(),
        ));
    }
    drop(session);
    // and open it the way the gateway will
    let key = Pkcs11Key::open_with_pin(spec, Some(pin))?;
    Ok(key.info().clone())
}
