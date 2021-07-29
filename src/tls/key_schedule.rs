use ring::digest;
use ring::hkdf::Prk;
use rustls::hash_hs::HandshakeHash;
use rustls::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret,
    KeyScheduleTrafficWithClientFinishedPending,
};
use rustls::kx::KeyExchange;
use rustls::msgs::enums::NamedGroup;
use rustls::{SupportedCipherSuite, ALL_KX_GROUPS};
use rustls::NoKeyLog;

use crate::tls::error::FnError;
use crate::tls::key_exchange::{tls12_key_exchange, tls13_key_exchange};

pub fn tls13_handshake_traffic_secret(
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    server: bool,
) -> Result<(&'static SupportedCipherSuite, Prk, KeyScheduleHandshake), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let group = NamedGroup::secp384r1; // todo https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let mut key_schedule = dhe_key_schedule(suite, group, server_key_share, psk)?;

    let server_secret = key_schedule.server_handshake_traffic_secret(
        &server_hello.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    let client_secret = key_schedule.client_handshake_traffic_secret(
        &server_hello.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    Ok((
        suite,
        if server { client_secret } else { server_secret },
        key_schedule,
    ))
}

pub fn tls13_application_traffic_secret(
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    server: bool,
) -> Result<
    (
        &'static SupportedCipherSuite,
        Prk,
        KeyScheduleTrafficWithClientFinishedPending,
    ),
    FnError,
> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45
    let (suite, _key, key_schedule) =
        tls13_handshake_traffic_secret(server_hello, server_key_share, psk, server)?;

    let mut application_key_schedule = key_schedule.into_traffic_with_client_finished_pending();

    let server_secret = application_key_schedule.server_application_traffic_secret(
        &server_finished.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    let client_secret = application_key_schedule.client_application_traffic_secret(
        &server_finished.get_current_hash(),
        &NoKeyLog {},
        client_random,
    );

    Ok((
        suite,
        if server { client_secret } else { server_secret },
        application_key_schedule,
    ))
}

pub fn tls13_derive_psk(
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    client_finished: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    new_ticket_nonce: &Vec<u8>,
) -> Result<(Vec<u8>), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://gitlab.inria.fr/mammann/tlspuffin/-/issues/45

    let (_, _, mut application_key_schedule) = tls13_application_traffic_secret(
        server_hello,
        server_finished,
        server_key_share,
        &None,
        true,
    )?;

    application_key_schedule.exporter_master_secret(
        &server_finished.get_current_hash(), // todo
        &NoKeyLog {},
        client_random,
    );

    let psk = application_key_schedule
        .into_traffic()
        .resumption_master_secret_and_derive_ticket_psk(
            &client_finished.get_current_hash(), // todo
            new_ticket_nonce,
        );

    Ok(psk)
}

pub fn dhe_key_schedule(
    suite: &SupportedCipherSuite,
    group: NamedGroup,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
) -> Result<KeyScheduleHandshake, FnError> {
    // Key Schedule with or without PSK
    let key_schedule = match (server_key_share, psk) {
        (Some(server_key_share), Some(psk)) => {
            let shared_secret = tls13_key_exchange(server_key_share, group)?.shared_secret;
            Ok(KeyScheduleEarly::new(suite.hkdf_algorithm, psk.as_slice())
                .into_handshake(&shared_secret))
        }
        (Some(server_key_share), None) => {
            let shared_secret = tls13_key_exchange(server_key_share, group)?.shared_secret;
            Ok(KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared_secret))
        }
        (None, Some(psk)) => {
            // todo this empty secret is not specified in the RFC 8446
            let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
            Ok(
                KeyScheduleEarly::new(suite.hkdf_algorithm, psk.as_slice()).into_handshake(
                    &zeroes[..suite
                        .hkdf_algorithm
                        .hmac_algorithm()
                        .digest_algorithm()
                        .output_len],
                ),
            )
        }
        (None, None) => Err(FnError::Unknown(
            "Need at least a key share or a psk".to_owned(),
        )),
    };

    key_schedule
}
