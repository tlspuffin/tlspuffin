use core::panic;

use puffin::algebra::dynamic_function::TypeShape;
use puffin::trace::Query;
use tlspuffin::test_utils::prelude::*;
use tlspuffin::tls::rustls::msgs::enums::{CipherSuite, NamedGroup};

#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts, filter = all(tls13))]
fn test_group_selection_secp384r1(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    trace.descriptors[0].protocol_config.groups = Some(
        String::from("P-384"), // secp384r1
    );

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_group = ctx_1.find_variable(
        TypeShape::of::<NamedGroup>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_group {
        let group = term.as_any().downcast_ref::<NamedGroup>().unwrap();
        assert_eq!(
            group.get_u16(),
            24 // secp384r1
        );
    } else {
        panic!("no named group");
    }
}

#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts,  filter = tls13)]
fn test_group_selection_secp256r1(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    // Test with secp256r1

    trace.descriptors[0].protocol_config.groups = Some(
        String::from("P-256"), // secp256r1
    );

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_group = ctx_1.find_variable(
        TypeShape::of::<NamedGroup>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_group {
        let group = term.as_any().downcast_ref::<NamedGroup>().unwrap();
        assert_eq!(
            group.get_u16(),
            23 // secp256r1
        );
    } else {
        panic!("no named group");
    }
}

/// Named group of the ECDHE ServerKeyExchange of a TLS 1.2 handshake where both agents are
/// configured with `groups`.
fn server_group_tls12(put: &str, groups: &str) -> u16 {
    use tlspuffin::tls::rustls::msgs::handshake::{KeyExchangeAlgorithm, ServerKeyExchangePayload};
    use tlspuffin::tls::seeds::seed_successful12_forward;

    let runner = default_runner_for(put);
    let mut trace = seed_successful12_forward.build_trace();

    for descriptor in trace.descriptors.iter_mut() {
        descriptor.protocol_config.groups = Some(String::from(groups));
    }

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let server_key_exchange = ctx_1.find_variable(
        TypeShape::of::<ServerKeyExchangePayload>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = server_key_exchange {
        // the payload is only parsed once the key exchange algorithm is known
        let ecdhe = term
            .as_any()
            .downcast_ref::<ServerKeyExchangePayload>()
            .unwrap()
            .unwrap_given_kxa(&KeyExchangeAlgorithm::ECDHE)
            .expect("ServerKeyExchange is not ECDHE");
        ecdhe.params.curve_params.named_group.get_u16()
    } else {
        panic!("no ServerKeyExchange");
    }
}

// ToDo: OpenSSL 1.0.x is not thread-safe without locking callbacks, which the harness does
// not install yet: these tests crash when run in parallel on 1.0.2.
// OpenSSL 1.0.1 has no API to configure groups
#[apply(test_puts, attrs = [ignore], filter = all(tls12, openssl, not(openssl101f)))]
fn test_group_selection_tls12_secp384r1(put: &str) {
    assert_eq!(
        server_group_tls12(put, "P-384"),
        24 // secp384r1
    );
}

// ToDo: OpenSSL 1.0.x is not thread-safe without locking callbacks, which the harness does
// not install yet: these tests crash when run in parallel on 1.0.2.
// OpenSSL 1.0.1 has no API to configure groups
#[apply(test_puts, attrs = [ignore], filter = all(tls12, openssl, not(openssl101f)))]
fn test_group_selection_tls12_secp521r1(put: &str) {
    assert_eq!(
        server_group_tls12(put, "P-521"),
        25 // secp521r1
    );
}

#[apply(test_puts, filter = all(tls13, allow_setting_tls13_ciphers))]
fn test_cipher_selection_tls13_aes_256_gcm_sha384(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    trace.descriptors[0]
        .protocol_config
        .set_cipher_string(String::from("TLS_AES_256_GCM_SHA384"));

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_cipher = ctx_1.find_variable(
        TypeShape::of::<CipherSuite>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_cipher {
        let cipher = term.as_any().downcast_ref::<CipherSuite>().unwrap();
        assert_eq!(*cipher, CipherSuite::TLS13_AES_256_GCM_SHA384);
    } else {
        panic!("no cipher suite");
    }
}

#[apply(test_puts, filter = all(tls13, allow_setting_tls13_ciphers))]
fn test_cipher_selection_tls13_chacha20_poly1305_sha256(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    trace.descriptors[0]
        .protocol_config
        .set_cipher_string(String::from("TLS_CHACHA20_POLY1305_SHA256"));

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_cipher = ctx_1.find_variable(
        TypeShape::of::<CipherSuite>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_cipher {
        let cipher = term.as_any().downcast_ref::<CipherSuite>().unwrap();
        assert_eq!(*cipher, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    } else {
        panic!("no cipher suite");
    }
}

#[apply(test_puts, filter = all(tls12, allow_setting_tls12_ciphers))]
fn test_cipher_selection_tls12_ecdhe_rsa_with_aes_128_gcm_sha256(put: &str) {
    use tlspuffin::tls::seeds::seed_successful12_forward;

    let runner = default_runner_for(put);
    let mut trace = seed_successful12_forward.build_trace();

    trace.descriptors[0]
        .protocol_config
        .set_cipher_string(String::from("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    trace.descriptors[1]
        .protocol_config
        .set_cipher_string(String::from("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_cipher = ctx_1.find_variable(
        TypeShape::of::<CipherSuite>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_cipher {
        let cipher = term.as_any().downcast_ref::<CipherSuite>().unwrap();
        assert_eq!(*cipher, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    } else {
        panic!("no cipher suite");
    }
}

#[apply(test_puts, filter = all(tls12, allow_setting_tls12_ciphers))]
fn test_cipher_selection_tls12_ecdhe_rsa_with_aes_256_gcm_sha384(put: &str) {
    use tlspuffin::tls::seeds::seed_successful12_forward;

    let runner = default_runner_for(put);
    let mut trace = seed_successful12_forward.build_trace();

    trace.descriptors[0]
        .protocol_config
        .set_cipher_string(String::from("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));
    trace.descriptors[1]
        .protocol_config
        .set_cipher_string(String::from("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"));

    let ctx_1 = runner.execute(&trace, &mut 0).unwrap();

    let first_cipher = ctx_1.find_variable(
        TypeShape::of::<CipherSuite>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_cipher {
        let cipher = term.as_any().downcast_ref::<CipherSuite>().unwrap();
        assert_eq!(*cipher, CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    } else {
        panic!("no cipher suite");
    }
}
