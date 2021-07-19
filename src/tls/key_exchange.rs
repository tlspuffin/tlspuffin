use ring::test::rand::FixedByteRandom;
use rustls::kx::KeyExchange;
use rustls::SupportedKxGroup;

use crate::tls::error::FnError;

pub fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> Result<KeyExchange, FnError> {
    let random = FixedByteRandom { byte: 42 };  // LH: Why not basing this on the agent name that is performing the key exchange?
    // How key exchanged exposed to the attacker? What happens if the attacker does his own key exchange with others' pub key, do we get the same shared key all the time?
    let ours = ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random)?;

    let pubkey = ours.compute_public_key()?;

    Ok(KeyExchange {
        skxg,
        privkey: ours,
        pubkey,
    })
}
