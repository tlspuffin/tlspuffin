use ring::test::rand::FixedByteRandom;
use rustls::kx::KeyExchange;
use rustls::SupportedKxGroup;

use crate::tls::{FnError};

pub fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> Result<KeyExchange, FnError> {
    let random = FixedByteRandom { byte: 42 };
    let ours = ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random)?;

    let pubkey = ours.compute_public_key()?;

    Ok(KeyExchange {
        skxg,
        privkey: ours,
        pubkey,
    })
}
