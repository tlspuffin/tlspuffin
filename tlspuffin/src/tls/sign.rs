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

pub fn ecdsa_sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, FnError> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    // Deterministic ECDSA (RFC 6979): nonce k = HMAC(key, msg), so identical (message, key) always
    // yields the identical signature -> term evaluation is reproducible and locate-and-splice is
    // stable. (ring's ECDSA is randomized; the previous FixedByteRandom nonce hack did NOT make it
    // deterministic, which caused the variable-length DER "incompatible indices" splice TermBugs.)
    let key = SigningKey::from_pkcs8_der(private_key)
        .map_err(|_| FnError::Crypto("Failed to parse ecdsa key.".to_string()))?;
    // Signs SHA-256(message), as ECDSA_NISTP256_SHA256; outputs ASN.1 DER (same format as before).
    let sig: Signature = key
        .try_sign(message)
        .map_err(|_| FnError::Crypto("Failed to sign using ECDSA key".to_string()))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod determinism_probe {
    use super::ecdsa_sign;
    use crate::static_certs::RANDOM_EC_PRIVATE_KEY_PKCS8;

    /// Regression: ecdsa_sign must be byte-stable for identical (message, key) (RFC 6979), and sign
    /// arbitrary data. This guards the determinism that locate-and-splice relies on.
    #[test]
    fn ecdsa_sign_is_deterministic_over_arbitrary_data() {
        let key: Vec<u8> = RANDOM_EC_PRIVATE_KEY_PKCS8.1.into();
        for msg in [b"abc".as_slice(), b"a much longer arbitrary message ...", &[0u8; 200]] {
            let s1 = ecdsa_sign(msg, &key).expect("sign1");
            let s2 = ecdsa_sign(msg, &key).expect("sign2");
            assert_eq!(s1, s2, "ecdsa_sign non-deterministic (len {} vs {})", s1.len(), s2.len());
        }
    }
}

#[cfg(test)]
mod rsa_det_probe {
    use super::rsa_sign;
    use crate::static_certs::ALICE_PRIVATE_KEY;
    use crate::tls::rustls::msgs::enums::SignatureScheme;
    #[test]
    fn rsa_pss_sign_same_input_twice() {
        let key: Vec<u8> = ALICE_PRIVATE_KEY.1.into();
        let msg = b"determinism probe message for rsa pss";
        let s1 = rsa_sign(msg, &key, &SignatureScheme::RSA_PSS_SHA256).expect("s1");
        let s2 = rsa_sign(msg, &key, &SignatureScheme::RSA_PSS_SHA256).expect("s2");
        assert_eq!(s1, s2, "RSA-PSS non-deterministic: len {} vs {}", s1.len(), s2.len());
    }
}
