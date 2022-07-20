use std::convert::TryInto;

use puffin::algebra::error::FnError;
use ring::test::rand::FixedByteRandom;
use rustls::{
    conn::ConnectionRandoms,
    kx::KeyExchange,
    msgs::{
        enums::NamedGroup,
        handshake::{Random, ServerECDHParams},
    },
    tls12::ConnectionSecrets,
    SupportedKxGroup, ALL_KX_GROUPS,
};

fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> Result<KeyExchange, FnError> {
    let random = FixedByteRandom { byte: 42 };
    let ours = ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random)
        .map_err(|err| FnError::Rustls("Failed to generate ephemeral key".to_string()))?;

    let pubkey = ours
        .compute_public_key()
        .map_err(|err| FnError::Rustls("Failed to compute public key".to_string()))?;

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
        Err(FnError::Rustls("Unable to find named group".to_string()))
    }
}

pub fn tls13_key_exchange(
    server_key_share: &Vec<u8>,
    group: &NamedGroup,
) -> Result<Vec<u8>, FnError> {
    // Shared Secret
    let skxg = KeyExchange::choose(group.clone(), &ALL_KX_GROUPS)
        .ok_or_else(|| FnError::Unknown("Failed to choose group in key exchange".to_string()))?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    let shared_secret = kx
        .complete(server_key_share, |secret| Ok(Vec::from(secret)))
        .map_err(|err| FnError::Rustls("Failed to compute shared secret".to_string()))?;
    Ok(shared_secret)
}

pub fn tls12_key_exchange(group: &NamedGroup) -> Result<KeyExchange, FnError> {
    let skxg = KeyExchange::choose(group.clone(), &ALL_KX_GROUPS)
        .ok_or_else(|| "Failed to find key exchange group".to_string())?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    Ok(kx)
}

pub fn tls12_new_secrets(
    server_random: &Random,
    server_ecdh_pubkey: &Vec<u8>,
    group: &NamedGroup,
) -> Result<ConnectionSecrets, FnError> {
    let suite = &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo https://github.com/tlspuffin/tlspuffin/issues/129

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let server_random = server_random_bytes
        .try_into()
        .map_err(|_| FnError::Unknown("Server random did not have length of 32".to_string()))?;
    let randoms = ConnectionRandoms {
        client: [1; 32], // todo https://github.com/tlspuffin/tlspuffin/issues/129
        server: server_random,
    };
    let kx = tls12_key_exchange(group)?;
    let suite = suite
        .tls12()
        .ok_or_else(|| FnError::Unknown("VersionNotCompatibleError".to_string()))?;
    let secrets =
        ConnectionSecrets::from_key_exchange(kx, &server_ecdh_pubkey, None, randoms, suite)
            .map_err(|err| FnError::Rustls("Failed to shared secrets for TLS 1.2".to_string()))?;
    // master_secret is: 01 40 26 dd 53 3c 0a...
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use rustls::kx_group::SECP384R1;
    use test_log::test;

    use crate::tls::key_exchange::deterministic_key_exchange;

    #[test]
    fn test_deterministic_key() {
        let a = deterministic_key_exchange(&SECP384R1).unwrap();
        let b = deterministic_key_exchange(&SECP384R1).unwrap();

        assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
    }
}
