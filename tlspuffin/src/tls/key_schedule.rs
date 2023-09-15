use puffin::algebra::error::FnError;
use ring::{digest, hkdf::Prk};

use crate::tls::{
    key_exchange::tls13_key_exchange,
    rustls::{
        hash_hs::HandshakeHash,
        key_log::NoKeyLog,
        msgs::enums::NamedGroup,
        suites::SupportedCipherSuite,
        tls13::key_schedule::{
            KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleHandshakeStart,
            KeySchedulePreHandshake, KeyScheduleTrafficWithClientFinishedPending,
        },
    },
};

pub fn tls13_handshake_traffic_secret(
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    client: bool,
    group: &NamedGroup,
) -> Result<(&'static SupportedCipherSuite, Prk, KeyScheduleHandshake), FnError> {
    let client_random = &[1u8; 32]; // todo see op_random() https://github.com/tlspuffin/tlspuffin/issues/129
    let suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites() https://github.com/tlspuffin/tlspuffin/issues/129
    let key_schedule = dhe_key_schedule(suite, group, server_key_share, psk)?;

    let (hs, client_secret, server_secret) = key_schedule.derive_handshake_secrets(
        &server_hello.get_current_hash_raw(),
        &NoKeyLog {},
        client_random,
    );

    Ok((
        suite,
        if client { client_secret } else { server_secret },
        hs,
    ))
}

pub fn tls13_application_traffic_secret(
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: bool,
) -> Result<
    (
        &'static SupportedCipherSuite,
        Prk,
        KeyScheduleTrafficWithClientFinishedPending,
    ),
    FnError,
> {
    let client_random = &[1u8; 32]; // todo see op_random() https://github.com/tlspuffin/tlspuffin/issues/129
    let (suite, _key, key_schedule) =
        tls13_handshake_traffic_secret(server_hello, server_key_share, psk, client, group)?;

    let (pending, client_secret, server_secret) = key_schedule
        .into_traffic_with_client_finished_pending_raw(
            &server_finished.get_current_hash_raw(),
            &NoKeyLog {},
            client_random,
        );
    Ok((
        suite,
        if client { client_secret } else { server_secret },
        pending,
    ))
}

pub fn tls13_derive_psk(
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    client_finished: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    new_ticket_nonce: &Vec<u8>,
    group: &NamedGroup,
) -> Result<Vec<u8>, FnError> {
    let (_, _, pending) = tls13_application_traffic_secret(
        server_hello,
        server_finished,
        server_key_share,
        &None,
        group,
        true,
    )?;

    let (traffic, _tag, _client_secret) =
        pending.sign_client_finish_raw(&server_finished.get_current_hash_raw());
    let psk = traffic.resumption_master_secret_and_derive_ticket_psk_raw(
        &client_finished.get_current_hash_raw(),
        new_ticket_nonce,
    );

    Ok(psk)
}

pub fn dhe_key_schedule(
    suite: &SupportedCipherSuite,
    group: &NamedGroup,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
) -> Result<KeyScheduleHandshakeStart, FnError> {
    let hkdf_algorithm = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .hkdf_algorithm;

    // Key Schedule with or without PSK
    let key_schedule = match (server_key_share, psk) {
        (Some(server_key_share), Some(psk)) => {
            let shared_secret = tls13_key_exchange(server_key_share, group)?;
            let early = KeyScheduleEarly::new(hkdf_algorithm, psk.as_slice());
            let pre: KeySchedulePreHandshake = early.into();
            Ok(pre.into_handshake(&shared_secret))
        }
        (Some(server_key_share), None) => {
            let shared_secret = tls13_key_exchange(server_key_share, group)?;
            Ok(KeySchedulePreHandshake::new(hkdf_algorithm).into_handshake(&shared_secret))
        }
        (None, Some(psk)) => {
            // Note: his empty secret is not specified in the RFC 8446
            let zeroes = [0u8; digest::MAX_OUTPUT_LEN];
            let early = KeyScheduleEarly::new(hkdf_algorithm, psk.as_slice());
            let pre: KeySchedulePreHandshake = early.into();
            Ok(pre.into_handshake(
                &zeroes[..hkdf_algorithm
                    .hmac_algorithm()
                    .digest_algorithm()
                    .output_len],
            ))
        }
        (None, None) => Err(FnError::Malformed(
            "Need at least a key share or a psk".to_owned(),
        )),
    };

    key_schedule
}
