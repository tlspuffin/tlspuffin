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
