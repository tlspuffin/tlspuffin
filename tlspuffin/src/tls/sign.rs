use std::sync::Arc;

use puffin::algebra::error::FnError;
use ring::signature::RsaKeyPair;

use crate::tls::rustls::msgs::enums::SignatureScheme;
use crate::tls::rustls::sign::RsaSigner;

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

/// Signs with ECDSA-P256-SHA256, producing a DER-encoded `ECDSA-Sig-Value` (the same wire format
/// `ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING` produces).
///
/// Uses `p256`/RustCrypto rather than `ring` because `ring`'s `EcdsaKeyPair::sign` is not
/// reproducible even when given a fixed-byte `SecureRandom`: it deliberately mixes the message
/// digest into the nonce "to hedge against faulty RNGs" (see `ring`'s
/// `ec::suite_b::ecdsa::signing::sign`), so the external randomness alone does not pin the nonce.
/// Every other Mapper function in this crate is a pure function of its inputs (`rsa_sign`'s
/// `FixedByteRandom` *does* work there, since RSA-PSS's only randomness is the salt, taken
/// directly from the given RNG with nothing else mixed in) - traces rely on that purity, since the
/// same symbolic term can be evaluated more than once in a trace (e.g. a `CertificateVerify` both
/// sent on the wire and folded into the transcript used to compute `Finished`). A non-deterministic
/// `ecdsa_sign` silently produces two different-but-each-individually-valid signatures for the
/// same input across those two evaluations, so the transcript hash used for `Finished` no longer
/// matches what was actually sent - the handshake fails with "Verify finished error on hashes"
/// before any CertificateVerify-related security check is ever reached. `p256::ecdsa::SigningKey`
/// uses RFC 6979 deterministic nonce derivation (pulled in automatically as the `rfc6979` crate),
/// giving the same signature every time for the same (key, message).
pub fn ecdsa_sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, FnError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey;

    let key = SigningKey::from_pkcs8_der(private_key)
        .map_err(|_| FnError::Crypto("Failed to parse ecdsa key.".to_string()))?;

    let signature: p256::ecdsa::Signature = key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}
