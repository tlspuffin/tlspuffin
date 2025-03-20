use puffin::algebra::error::FnError;
use ring::test::rand::FixedByteRandom;

use super::rustls::suites::SupportedCipherSuite;
use crate::tls::rustls::conn::ConnectionRandoms;
use crate::tls::rustls::kx::{KeyExchange, SupportedKxGroup, ALL_KX_GROUPS};
use crate::tls::rustls::msgs::enums::NamedGroup;
use crate::tls::rustls::msgs::handshake::Random;
use crate::tls::rustls::tls12::ConnectionSecrets;

fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> Result<KeyExchange, FnError> {
    let random = FixedByteRandom { byte: 42 };
    let ours = ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random)
        .map_err(|_err| FnError::Crypto("Failed to generate ephemeral key".to_string()))?;

    let pubkey = ours
        .compute_public_key()
        .map_err(|_err| FnError::Crypto("Failed to compute public key".to_string()))?;

    Ok(KeyExchange {
        skxg,
        privkey: ours,
        pubkey,
    })
}

pub fn deterministic_key_share(group: &NamedGroup) -> Result<Vec<u8>, FnError> {
    if let Some(supported_group) = ALL_KX_GROUPS
        .iter()
        .find(|supported| supported.name == *group)
    {
        Ok(Vec::from(
            deterministic_key_exchange(supported_group)?.pubkey.as_ref(),
        ))
    } else {
        Err(FnError::Crypto("Unable to find named group".to_string()))
    }
}

pub fn tls13_key_exchange(server_key_share: &[u8], group: &NamedGroup) -> Result<Vec<u8>, FnError> {
    // Shared Secret
    let skxg = KeyExchange::choose(*group, &ALL_KX_GROUPS)
        .ok_or_else(|| FnError::Malformed("Failed to choose group in key exchange".to_string()))?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    let shared_secret = kx
        .complete(server_key_share, |secret| Ok(Vec::from(secret)))
        .map_err(|_err| FnError::Crypto("Failed to compute shared secret".to_string()))?;
    Ok(shared_secret)
}

pub fn tls12_key_exchange(group: &NamedGroup) -> Result<KeyExchange, FnError> {
    let skxg = KeyExchange::choose(*group, &ALL_KX_GROUPS)
        .ok_or_else(|| FnError::Malformed("Failed to find key exchange group".to_string()))?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    Ok(kx)
}

pub fn tls12_new_secrets(
    server_random: &Random,
    server_ecdh_pubkey: &[u8],
    group: &NamedGroup,
    client_random: &Random,
    suite: SupportedCipherSuite,
) -> Result<ConnectionSecrets, FnError> {
    let randoms = ConnectionRandoms {
        client: client_random.0,
        server: server_random.0,
    };
    let kx = tls12_key_exchange(group)?;
    let suite = suite
        .tls12()
        .ok_or_else(|| FnError::Malformed("VersionNotCompatibleError".to_string()))?;
    let secrets =
        ConnectionSecrets::from_key_exchange(kx, server_ecdh_pubkey, None, randoms, suite)
            .map_err(|_err| FnError::Crypto("Failed to shared secrets for TLS 1.2".to_string()))?;
    // master_secret is: 01 40 26 dd 53 3c 0a...
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use crate::tls::key_exchange::deterministic_key_exchange;
    use crate::tls::rustls::kx::SECP384R1;

    #[test_log::test]
    fn test_deterministic_key() {
        let a = deterministic_key_exchange(&SECP384R1).unwrap();
        let b = deterministic_key_exchange(&SECP384R1).unwrap();

        assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
    }
}
