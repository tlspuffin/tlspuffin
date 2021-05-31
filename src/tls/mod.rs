use ring::digest::Digest;
use rustls::{prf, SupportedKxGroup};
use rustls::kx::KeyExchange;
use ring::test::rand::FixedByteRandom;
use ring::rand::SystemRandom;

pub mod derive;
mod tests;

pub fn client_verify_data(
    master_secret: &[u8],
    hmac_algorithm: ring::hmac::Algorithm,
    handshake_hash: &Digest,
) -> Vec<u8> {
    make_verify_data(
        master_secret,
        hmac_algorithm,
        handshake_hash,
        b"client finished",
    )
}

pub fn make_verify_data(
    master_secret: &[u8],
    hmac_algorithm: ring::hmac::Algorithm,
    handshake_hash: &Digest,
    label: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(12, 0u8);

    prf::prf(
        &mut out,
        hmac_algorithm,
        master_secret,
        label,
        handshake_hash.as_ref(),
    );
    out
}

pub fn deterministic_key_exchange(skxg: &'static SupportedKxGroup) -> KeyExchange {
    let random = FixedByteRandom { byte: 42 };
    //let random = SystemRandom::new();
    let ours =
        ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &random).unwrap();

    let pubkey = ours.compute_public_key().unwrap();

    KeyExchange {
        skxg,
        privkey: ours,
        pubkey,
    }
}
