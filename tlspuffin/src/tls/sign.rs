use std::sync::Arc;

use puffin::algebra::error::FnError;
use ring::signature::RsaKeyPair;

use crate::tls::rustls::key::PrivateKey;
use crate::tls::rustls::msgs::enums::SignatureScheme;
use crate::tls::rustls::sign::{EcdsaSigningKey, RsaSigner, SigningKey};

pub fn rsa_sign(
    message: &[u8],
    private_key: &[u8],
    scheme: &SignatureScheme,
) -> Result<Vec<u8>, FnError> {
    let invalid_scheme = !matches!(
        scheme,
        SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512
    );

    if invalid_scheme {
        return Err(FnError::Crypto("Unknown signature scheme".to_string()));
    }

    let key = RsaKeyPair::from_der(private_key)
        .map_err(|_| FnError::Crypto("Failed to parse rsa key.".to_string()))?;

    let signer = RsaSigner::new(
        Arc::new(key),
        *scheme,
        Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
    );
    signer
        .sign(message)
        .map_err(|_err| FnError::Crypto("Failed to sign using RSA key".to_string()))
}

pub fn ecdsa_sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, FnError> {
    let key = EcdsaSigningKey::new(
        &PrivateKey(private_key.to_vec()),
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
    )
    .map_err(|_| FnError::Crypto("Failed to parse ecdsa key.".to_string()))?;

    let signer = key
        .choose_scheme(
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Box::new(ring::test::rand::FixedByteRandom { byte: 43 }),
        )
        .ok_or_else(|| FnError::Crypto("Failed to find signature scheme.".to_string()))?;

    signer
        .sign(message)
        .map_err(|_err| FnError::Crypto("Failed to sign using ECDHE key".to_string()))
}

use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, traits::PrivateKeyParts, traits::PublicKeyParts};
use sha2::{Sha256, Digest};

fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

pub fn rsa_pss_sign_from_mhash(
    mhash: &[u8],
    private_key_der: &[u8],
) -> Result<Vec<u8>, FnError> {
    if mhash.len() != 32 {
        return Err(FnError::Crypto("mhash must be 32 bytes".into()));
    }

    let key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| FnError::Crypto("bad RSA key".into()))?;
    let n = key.n();
    let d = key.d();
    let em_len = (n.bits() + 7) / 8;
    let em_bits = n.bits() - 1;

    let salt = vec![0x2b; 32];

    let mut mprime = Vec::with_capacity(8 + 32 + 32);
    mprime.extend_from_slice(&[0u8; 8]);
    mprime.extend_from_slice(mhash);
    mprime.extend_from_slice(&salt);
    let h: [u8; 32] = Sha256::digest(&mprime).into();

    let ps_len = em_len - 32 - 32 - 2;
    let mut db = vec![0u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(&salt);

    let mask = mgf1_sha256(&h, db.len());
    for i in 0..db.len() { db[i] ^= mask[i]; }
    let drop = 8 * em_len - em_bits;
    db[0] &= 0xff >> drop;

    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);

    use num_bigint_dig::BigUint;
    let m = BigUint::from_bytes_be(&em);
    let s = m.modpow(d, n);

    let mut sig = s.to_bytes_be();
    if sig.len() < em_len {
        let mut padded = vec![0u8; em_len - sig.len()];
        padded.extend_from_slice(&sig);
        sig = padded;
    }
    Ok(sig)
}

