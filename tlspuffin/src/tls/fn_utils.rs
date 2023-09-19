#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use std::convert::TryFrom;

use puffin::{
    algebra::error::FnError,
    codec::{Codec, Reader},
};

use crate::tls::{
    key_exchange::{tls12_key_exchange, tls12_new_secrets},
    key_schedule::*,
    rustls::{
        conn::Side,
        hash_hs::HandshakeHash,
        key::Certificate,
        msgs::{
            base::PayloadU8,
            enums::{HandshakeType, NamedGroup},
            handshake::{
                CertificateEntry, CertificateExtension, CertificateExtensions,
                HandshakeMessagePayload, HandshakePayload, Random, ServerECDHParams,
            },
            message::{Message, MessagePayload, OpaqueMessage, PlainMessage},
        },
        tls12,
        tls13::key_schedule::KeyScheduleEarly,
    },
};

// ----
// seed_client_attacker()
// ----

pub fn fn_new_transcript() -> Result<HandshakeHash, FnError> {
    let suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256;

    let transcript = HandshakeHash::new(suite.hash_algorithm());
    Ok(transcript)
}

pub fn fn_append_transcript(
    transcript: &HandshakeHash,
    message: &Message,
) -> Result<HandshakeHash, FnError> {
    let mut new_transcript: HandshakeHash = transcript.clone();
    new_transcript.add_message(message);
    Ok(new_transcript)
}

pub fn fn_decrypt_handshake(
    application_data: &Message,
    server_hello_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
) -> Result<Message, FnError> {
    let (suite, key, _) = tls13_handshake_traffic_secret(
        server_hello_transcript,
        server_key_share,
        psk,
        !*client,
        group,
    )?;
    let decrypter = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_decrypter(&key);
    let message = decrypter
        .decrypt(
            PlainMessage::from(application_data.clone()).into_unencrypted_opaque(),
            *sequence,
        )
        .map_err(|_err| FnError::Crypto("Failed to decrypt it fn_decrypt_handshake".to_string()))?;
    Message::try_from(message)
        .map_err(|_err| FnError::Crypto("Failed to create Message from decrypted data".to_string()))
}

pub fn fn_no_psk() -> Result<Option<Vec<u8>>, FnError> {
    Ok(None)
}

pub fn fn_psk(some: &Vec<u8>) -> Result<Option<Vec<u8>>, FnError> {
    Ok(Some(some.clone()))
}

pub fn fn_decrypt_application(
    application_data: &Message,
    server_hello_transcript: &HandshakeHash,
    server_finished_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
) -> Result<Message, FnError> {
    let (suite, key, _) = tls13_application_traffic_secret(
        server_hello_transcript,
        server_finished_transcript,
        server_key_share,
        psk,
        group,
        !*client,
    )?;
    let decrypter = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_decrypter(&key);
    let message = decrypter
        .decrypt(
            PlainMessage::from(application_data.clone()).into_unencrypted_opaque(),
            *sequence,
        )
        .map_err(|_err| {
            FnError::Crypto("Failed to decrypt it fn_decrypt_application".to_string())
        })?;
    Message::try_from(message)
        .map_err(|_err| FnError::Crypto("Failed to create Message from decrypted data".to_string()))
}

pub fn fn_encrypt_handshake(
    some_message: &Message,
    server_hello: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
) -> Result<OpaqueMessage, FnError> {
    let (suite, key, _) =
        tls13_handshake_traffic_secret(server_hello, server_key_share, psk, *client, group)?;
    let encrypter = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_encrypter(&key);
    let application_data = encrypter
        .encrypt(PlainMessage::from(some_message.clone()).borrow(), *sequence)
        .map_err(|_err| FnError::Crypto("Failed to encrypt it fn_encrypt_handshake".to_string()))?;
    Ok(application_data)
}

pub fn fn_encrypt_application(
    some_message: &Message,
    server_hello_transcript: &HandshakeHash,
    server_finished_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    sequence: &u64,
) -> Result<OpaqueMessage, FnError> {
    let (suite, key, _) = tls13_application_traffic_secret(
        server_hello_transcript,
        server_finished_transcript,
        server_key_share,
        psk,
        group,
        true,
    )?;
    let encrypter = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_encrypter(&key);
    let application_data = encrypter
        .encrypt(PlainMessage::from(some_message.clone()).borrow(), *sequence)
        .map_err(|_err| {
            FnError::Crypto("Failed to encrypt it fn_encrypt_application".to_string())
        })?;
    Ok(application_data)
}

pub fn fn_derive_psk(
    server_hello: &HandshakeHash,
    server_finished: &HandshakeHash,
    client_finished: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    new_ticket_nonce: &Vec<u8>,
    group: &NamedGroup,
) -> Result<Vec<u8>, FnError> {
    let psk = tls13_derive_psk(
        server_hello,
        server_finished,
        client_finished,
        server_key_share,
        new_ticket_nonce,
        group,
    )?;

    Ok(psk)
}

pub fn fn_derive_binder(full_client_hello: &Message, psk: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    let client_hello_payload: HandshakeMessagePayload = match full_client_hello.payload.clone() {
        MessagePayload::Handshake(payload) => Some(payload),
        _ => None,
    }
    .ok_or_else(|| {
        FnError::Unknown("Only can fill binder in HandshakeMessagePayload".to_owned())
    })?;

    let suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256; // todo allow other cipher suites: https://github.com/tlspuffin/tlspuffin/issues/129
    let hkdf_alg = suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .hkdf_algorithm;
    let suite_hash = suite.hash_algorithm();

    let transcript = HandshakeHash::new(suite_hash);

    // RFC: The "pre_shared_key" extension MUST be the last extension in the ClientHello
    // The binder is calculated over the clienthello, but doesn't include itself or its
    // length, or the length of its container.
    let binder_plaintext = client_hello_payload.get_encoding_for_binder_signing();
    let handshake_hash = transcript.get_hash_given(&binder_plaintext);

    // Run a fake key_schedule to simulate what the server will do if it chooses
    // to resume.
    let key_schedule = KeyScheduleEarly::new(hkdf_alg, psk);
    let real_binder = key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);

    Ok(Vec::from(real_binder.as_ref()))
}

pub fn fn_fill_binder(full_client_hello: &Message, binder: &Vec<u8>) -> Result<Message, FnError> {
    match full_client_hello.payload.clone() {
        MessagePayload::Handshake(payload) => match payload.payload {
            HandshakePayload::ClientHello(payload) => {
                let mut new_payload = payload;
                new_payload.set_psk_binder(binder.clone());
                Some(Message {
                    version: full_client_hello.version,
                    payload: MessagePayload::Handshake(HandshakeMessagePayload {
                        typ: HandshakeType::ClientHello,
                        payload: HandshakePayload::ClientHello(new_payload),
                    }),
                })
            }
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        FnError::Malformed("[fn_fill_binder] Could not find ticket in message".to_owned())
    })
}

pub fn fn_get_ticket(new_ticket: &Message) -> Result<Vec<u8>, FnError> {
    match new_ticket.payload.clone() {
        MessagePayload::Handshake(payload) => match payload.payload {
            HandshakePayload::NewSessionTicketTLS13(payload) => Some(payload.ticket.0),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        FnError::Malformed("[fn_get_ticket] Could not find ticket in message".to_owned())
    })
}

pub fn fn_get_ticket_age_add(new_ticket: &Message) -> Result<u64, FnError> {
    match new_ticket.payload.clone() {
        MessagePayload::Handshake(payload) => match payload.payload {
            HandshakePayload::NewSessionTicketTLS13(payload) => Some(payload.age_add as u64),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| FnError::Malformed("Could not find ticket in message".to_owned()))
}

pub fn fn_get_ticket_nonce(new_ticket: &Message) -> Result<Vec<u8>, FnError> {
    match new_ticket.payload.clone() {
        MessagePayload::Handshake(payload) => match payload.payload {
            HandshakePayload::NewSessionTicketTLS13(payload) => Some(payload.nonce.0),
            _ => None,
        },
        _ => None,
    }
    .ok_or_else(|| {
        FnError::Malformed("[fn_get_ticket_nonce] Could not find ticket in message".to_owned())
    })
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_new_transcript12() -> Result<HandshakeHash, FnError> {
    let suite = &tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

    let transcript = HandshakeHash::new(suite.hash_algorithm());
    Ok(transcript)
}

pub fn fn_decode_ecdh_pubkey(data: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    let mut rd = Reader::init(data.as_slice());
    let params = ServerECDHParams::read(&mut rd)
        .ok_or_else(|| FnError::Unknown("Failed to parse ecdh public key".to_string()))?;
    Ok(params.public.0)
}

pub fn fn_new_pubkey12(group: &NamedGroup) -> Result<Vec<u8>, FnError> {
    let kx = tls12_key_exchange(group)?;
    Ok(Vec::from(kx.pubkey.as_ref()))
}

pub fn fn_encode_ec_pubkey12(pubkey: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(pubkey.clone());
    ecpoint.encode(&mut buf);

    Ok(buf)
}

pub fn fn_encrypt12(
    message: &Message,
    server_random: &Random,
    server_ecdh_pubkey: &Vec<u8>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
) -> Result<OpaqueMessage, FnError> {
    let secrets = tls12_new_secrets(server_random, server_ecdh_pubkey, group)?;

    let (_decrypter, encrypter) = secrets.make_cipher_pair(match *client {
        true => Side::Client,
        false => Side::Server,
    });
    let encrypted = encrypter
        .encrypt(PlainMessage::from(message.clone()).borrow(), *sequence)
        .map_err(|_err| FnError::Crypto("Failed to encrypt it fn_encrypt12".to_string()))?;
    Ok(encrypted)
}

pub fn fn_new_certificate() -> Result<Certificate, FnError> {
    let der_cert = hex::decode(
        "308203473082022fa003020102021406f7fb1d20\
    b39f71b9a222e8f03a0ab0a79ec54d300d060\
    92a864886f70d01010b05003033310b30090603550406130241553113301106035504080c0a536f6d652d5374617465\
    310f300d060355040a0c064861636b6572301e170d3231303731393135323135355a170d32323037313931353231353\
    55a3033310b30090603550406130241553113301106035504080c0a536f6d652d5374617465310f300d060355040a0c\
    064861636b657230820122300d06092a864886f70d01010105000382010f003082010a0282010100b7e0f550fa3a22d\
    6dea0278b03e806a561f283e9bfc20c2b6cef8ae0c7c7e665813fda782a7a27745669044fe0e6627ec89fa63914df80\
    17d1a52b85057c318512242ad9416b957d74f06263fab9c75c0cb039c2256a4254b41863fa5d8f73114eaa1ccde793d\
    68ddae7254868d38341768104c9f673262b8bc958cab2a4d763547d744979adfec46497e5b8daf322c5332a86683abc\
    0a034592436c18321720800baac3c555606ecb1c2aa2b279ddf33f653009f6bd41f7e508f5e53613e9543a865934c28\
    8ec9558af93d710b093b5f58e053117d3b5a860e489ee5e9cb46ac76b639533ae06ff2d40f476a7f58a90c139d7c03e\
    17a85ec1426ae1f5b7bbad0203010001a3533051301d0603551d0e04160414f31e256fa78c3cc82c01f1bf46c9b2bfb\
    6b39da7301f0603551d23041830168014f31e256fa78c3cc82c01f1bf46c9b2bfb6b39da7300f0603551d130101ff04\
    0530030101ff300d06092a864886f70d01010b05000382010100aacd9f5f166718736c2290f6dcbec1ff19c2f5ab339\
    0e253fbf6ad3acdcf192a7b8a18f624244b85b68e9bf49dbce18005edb77a271dc6edd7afb427689829f190385b99f4\
    4f58ab901bf269a1b29eb9fc5603dfd67452544ec19fa51c2af29e4ce2667b778262abad12cca57f8c8a6ab1db57309\
    2640eda09ec6a001f48c8fa9996c90f0ae6726b12c69b59e18bc16c9c116a373aabdc4bb62b41c77859d2909eba9936\
    161df1ba38891e9bddec0f196bdcfc9a8801d4e066d4b258a9c072c6f4f13a80da85c75102b7cecae60987997c6b8c3\
    56bef671e44bc3aceb6e15590befb11b76efb6ee89c69820b91e1ba9d11d0324e961e9b0cb98e38ea2414ae94",
    );
    Ok(Certificate(der_cert.map_err(|_err| {
        FnError::Unknown("Failed to load DER certificate".to_string())
    })?))
}

pub fn fn_new_certificates() -> Result<Vec<Certificate>, FnError> {
    Ok(vec![])
}

pub fn fn_append_certificate(
    certs: &Vec<Certificate>,
    cert: &Certificate,
) -> Result<Vec<Certificate>, FnError> {
    let mut new_certs = certs.clone();
    new_certs.push(cert.clone());

    Ok(new_certs)
}

pub fn fn_new_certificate_entries() -> Result<Vec<CertificateEntry>, FnError> {
    Ok(vec![])
}

pub fn fn_append_certificate_entry(
    certs: &Vec<CertificateEntry>,
    cert: &Certificate,
    extensions: &Vec<CertificateExtension>,
) -> Result<Vec<CertificateEntry>, FnError> {
    let mut new_certs = certs.clone();
    new_certs.push(CertificateEntry {
        cert: cert.clone(),
        exts: CertificateExtensions(extensions.clone()),
    });

    Ok(new_certs)
}

pub fn fn_named_group_secp384r1() -> Result<NamedGroup, FnError> {
    Ok(NamedGroup::secp384r1)
}

pub fn fn_named_group_x25519() -> Result<NamedGroup, FnError> {
    Ok(NamedGroup::X25519)
}
