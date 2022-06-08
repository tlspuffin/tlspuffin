use std::convert::{TryInto};

use ring::test::rand::FixedByteRandom;
use rustls::conn::ConnectionRandoms;
use rustls::kx::KeyExchange;
use rustls::msgs::enums::NamedGroup;
use rustls::msgs::handshake::{Random, ServerECDHParams};
use rustls::tls12::{ConnectionSecrets};
use rustls::{SupportedKxGroup, ALL_KX_GROUPS};

use crate::tls::error::FnError;

fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> Result<KeyExchange, FnError> {
    let random = FixedByteRandom { byte: 42 };
    let ours = ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random)?;

    let pubkey = ours.compute_public_key()?;

    Ok(KeyExchange {
        skxg,
        privkey: ours,
        pubkey,
    })
}

pub fn deterministic_key_share(skxg: &'static SupportedKxGroup) -> Result<Vec<u8>, FnError> {
    Ok(Vec::from(deterministic_key_exchange(skxg)?.pubkey.as_ref()))
}

pub fn tls13_key_exchange(
    server_key_share: &Vec<u8>,
    group: NamedGroup,
) -> Result<Vec<u8>, FnError> {
    // Shared Secret
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS)
        .ok_or_else(|| FnError::Unknown("Failed to choose group in key exchange".to_string()))?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    let shared_secret = kx.complete(server_key_share, |secret| Ok(Vec::from(secret)))?;
    Ok(shared_secret)
}

pub fn tls12_key_exchange(//  server_ecdh_params: &ServerECDHParams,
) -> Result<KeyExchange, FnError> {
    let group = NamedGroup::secp384r1; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let skxg = KeyExchange::choose(group, &ALL_KX_GROUPS)
        .ok_or_else(|| "Failed to find key exchange group".to_string())?;
    let kx: KeyExchange = deterministic_key_exchange(skxg)?;
    //let kxd = tls12::complete_ecdh(kx, &server_ecdh_params.public.0)?;
    Ok(kx)
}

pub fn tls12_new_secrets(
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
) -> Result<ConnectionSecrets, FnError> {
    let suite = &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let server_random = server_random_bytes
        .try_into()
        .map_err(|_| FnError::Unknown("Server random did not have length of 32".to_string()))?;
    let randoms = ConnectionRandoms {
        client: [1; 32], // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
        server: server_random,
    };
    let kx = tls12_key_exchange()?;
    let suite = suite
        .tls12()
        .ok_or_else(|| FnError::Unknown("VersionNotCompatibleError".to_string()))?;
    let secrets = ConnectionSecrets::from_key_exchange(
        kx,
        &server_ecdh_params.public.0,
        None,
        randoms,
        suite,
    )?;
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
