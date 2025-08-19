#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;
use puffin::codec::{Codec, Reader};
use puffin::protocol::{OpaqueProtocolMessageFlight, ProtocolMessageFlight};

use crate::protocol::{MessageFlight, OpaqueMessageFlight};
use crate::tls::key_exchange::{tls12_key_exchange, tls12_new_secrets};
use crate::tls::key_schedule::*;
use crate::tls::rustls::conn::Side;
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key::Certificate;
use crate::tls::rustls::msgs::base::PayloadU8;
use crate::tls::rustls::msgs::enums::{CipherSuite, HandshakeType, NamedGroup};
use crate::tls::rustls::msgs::handshake::{
    CertificateEntries, CertificateEntry, CertificateExtension, CertificateExtensions,
    HandshakeMessagePayload, HandshakePayload, Random, ServerECDHParams,
};
use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage, PlainMessage};
use crate::tls::rustls::suites::SupportedCipherSuite;
use crate::tls::rustls::tls12::{
    self, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use crate::tls::rustls::tls13::key_schedule::KeyScheduleEarly;
use crate::tls::rustls::tls13::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
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

pub fn fn_new_hrr_transcript(original_client_hello: &Message) -> Result<HandshakeHash, FnError> {
    let suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256;

    let mut transcript = HandshakeHash::new(suite.hash_algorithm());
    transcript.add_message(original_client_hello);
    transcript.rollup_for_hrr();
    Ok(transcript)
}

pub fn fn_new_flight() -> Result<MessageFlight, FnError> {
    Ok(MessageFlight::new())
}

pub fn fn_append_flight(flight: &MessageFlight, msg: &Message) -> Result<MessageFlight, FnError> {
    let mut new_flight = flight.clone();
    new_flight.messages.push(msg.clone());
    Ok(new_flight)
}

pub fn fn_new_opaque_flight() -> Result<OpaqueMessageFlight, FnError> {
    Ok(OpaqueMessageFlight::new())
}

pub fn fn_append_opaque_flight(
    flight: &OpaqueMessageFlight,
    msg: &OpaqueMessage,
) -> Result<OpaqueMessageFlight, FnError> {
    let mut new_flight = flight.clone();
    new_flight.messages.push(msg.clone());
    Ok(new_flight)
}

pub fn suite_as_supported_suite(suite: &CipherSuite) -> Result<SupportedCipherSuite, FnError> {
    match suite {
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Ok(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Ok(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        }
        CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(TLS13_AES_128_GCM_SHA256),
        CipherSuite::TLS13_AES_256_GCM_SHA384 => Ok(TLS13_AES_256_GCM_SHA384),
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Ok(TLS13_CHACHA20_POLY1305_SHA256),
        _ => Err(FnError::Crypto("Unsupported ciphersuite".into())),
    }
}

/// Decrypt a whole flight of handshake messages and return a Vec of decrypted messages
pub fn fn_decrypt_handshake_flight(
    flight: &MessageFlight,
    server_hello_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<MessageFlight, FnError> {
    let mut sequence_number = *sequence;

    let mut decrypted_flight = MessageFlight::new();

    for msg in &flight.messages {
        if let MessagePayload::ApplicationData(_) = &msg.payload {
            let decrypted_msg = fn_decrypt_multiple_handshake_messages(
                msg,
                server_hello_transcript,
                server_key_share,
                psk,
                group,
                client,
                &sequence_number,
                client_random,
                suite,
            )?;

            decrypted_flight.messages.extend(decrypted_msg);
            sequence_number += 1;
        }
    }

    Ok(decrypted_flight)
}

pub fn fn_decrypt_handshake_flight_with_secret(
    flight: &MessageFlight,
    server_hello_transcript: &HandshakeHash,
    client: &bool,
    sequence: &u64,
    client_random: &Random,
    suite: &CipherSuite,
    extracted_shared_secret: &Vec<u8>,
) -> Result<MessageFlight, FnError> {
    let mut sequence_number = *sequence;

    let mut decrypted_flight = MessageFlight::new();

    for msg in &flight.messages {
        if let MessagePayload::ApplicationData(_) = &msg.payload {
            let decrypted_msg = fn_decrypt_multiple_handshake_messages_with_secret(
                msg,
                server_hello_transcript,
                client,
                &sequence_number,
                client_random,
                suite,
                extracted_shared_secret,
            )?;

            decrypted_flight.messages.extend(decrypted_msg);
            sequence_number += 1;
        }
    }

    Ok(decrypted_flight)
}

/// Decrypt an Application data message containing multiple handshake messages
/// and return a vec of handshake messages
pub fn fn_decrypt_multiple_handshake_messages(
    application_data: &Message,
    server_hello_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<Message>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let (key, _) = tls13_handshake_traffic_secret(
        server_hello_transcript,
        server_key_share,
        psk,
        !*client,
        group,
        client_random,
        &supported_suite,
    )?;

    let decrypter = supported_suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_decrypter(&key);
    let message = decrypter
        .decrypt(
            PlainMessage::from(application_data.clone()).into_unencrypted_opaque(),
            *sequence,
        )
        .map_err(|_err| FnError::Crypto("Failed to decrypt it fn_decrypt_handshake".to_string()))?;

    let payloads =
        MessagePayload::multiple_new(message.typ, message.version, message.payload).unwrap();

    let messages = payloads
        .into_iter()
        .map(|p| Message {
            version: message.version,
            payload: p,
        })
        .collect();

    Ok(messages)
}

/// Decrypt an Application data message containing multiple handshake messages
/// and return a vec of handshake messages
pub fn fn_decrypt_multiple_handshake_messages_with_secret(
    application_data: &Message,
    server_hello_transcript: &HandshakeHash,
    client: &bool,
    sequence: &u64,
    client_random: &Random,
    suite: &CipherSuite,
    extracted_shared_secret: &Vec<u8>,
) -> Result<Vec<Message>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let (key, _) = tls13_handshake_traffic_secret_from_shared_secret(
        server_hello_transcript,
        client_random,
        !*client,
        &supported_suite,
        extracted_shared_secret,
    )?;

    let decrypter = supported_suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .derive_decrypter(&key);
    let message = decrypter
        .decrypt(
            PlainMessage::from(application_data.clone()).into_unencrypted_opaque(),
            *sequence,
        )
        .map_err(|_err| FnError::Crypto("Failed to decrypt it fn_decrypt_handshake".to_string()))?;

    let payloads =
        MessagePayload::multiple_new(message.typ, message.version, message.payload).unwrap();

    let messages = payloads
        .into_iter()
        .map(|p| Message {
            version: message.version,
            payload: p,
        })
        .collect();

    Ok(messages)
}

pub fn fn_find_server_certificate(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::Certificate {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no server certificate".to_owned()))
}

pub fn fn_find_server_ticket(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::NewSessionTicket {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no server tickets".to_owned()))
}

pub fn fn_find_server_certificate_request(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::CertificateRequest {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no server tickets".to_owned()))
}

pub fn fn_find_encrypted_extensions(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::EncryptedExtensions {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no encrypted extensions".to_owned()))
}

pub fn fn_find_server_certificate_verify(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::CertificateVerify {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no certificate verify".to_owned()))
}

pub fn fn_find_server_finished(flight: &MessageFlight) -> Result<Message, FnError> {
    for msg in &flight.messages {
        if let MessagePayload::Handshake(x) = &msg.payload {
            if x.typ == HandshakeType::Finished {
                return Ok(msg.clone());
            }
        }
    }
    Err(FnError::Malformed("no finished".to_owned()))
}

pub fn fn_no_psk() -> Result<Option<Vec<u8>>, FnError> {
    Ok(None)
}

pub fn fn_psk(some: &Vec<u8>) -> Result<Option<Vec<u8>>, FnError> {
    Ok(Some(some.clone()))
}

/// Decrypt a whole flight of application messages and return a Vec of decrypted messages
pub fn fn_decrypt_application_flight(
    flight: &MessageFlight,
    server_hello_transcript: &HandshakeHash,
    server_finished_transcript: &HandshakeHash,
    server_key_share: &Option<Vec<u8>>,
    psk: &Option<Vec<u8>>,
    group: &NamedGroup,
    client: &bool,
    sequence: &u64,
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<MessageFlight, FnError> {
    let mut sequence_number = *sequence;

    let mut decrypted_flight = MessageFlight::new();

    for msg in &flight.messages {
        if let MessagePayload::ApplicationData(_) = &msg.payload {
            let decrypted_msg = fn_decrypt_application(
                msg,
                server_hello_transcript,
                server_finished_transcript,
                server_key_share,
                psk,
                group,
                client,
                &sequence_number,
                client_random,
                suite,
            )?;

            decrypted_flight.push(decrypted_msg);
            sequence_number += 1;
        }
    }

    Ok(decrypted_flight)
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
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Message, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let (key, _) = tls13_application_traffic_secret(
        server_hello_transcript,
        server_finished_transcript,
        server_key_share,
        psk,
        group,
        !*client,
        client_random,
        &supported_suite,
    )?;
    let decrypter = supported_suite
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
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<OpaqueMessage, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let (key, _) = tls13_handshake_traffic_secret(
        server_hello,
        server_key_share,
        psk,
        *client,
        group,
        client_random,
        &supported_suite,
    )?;
    let encrypter = supported_suite
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
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<OpaqueMessage, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let (key, _) = tls13_application_traffic_secret(
        server_hello_transcript,
        server_finished_transcript,
        server_key_share,
        psk,
        group,
        true,
        client_random,
        &supported_suite,
    )?;
    let encrypter = supported_suite
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
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;
    let psk = tls13_derive_psk(
        server_hello,
        server_finished,
        client_finished,
        server_key_share,
        new_ticket_nonce,
        group,
        client_random,
        &supported_suite,
    )?;

    Ok(psk)
}

pub fn fn_derive_binder(
    full_client_hello: &Message,
    psk: &Vec<u8>,
    suite: &CipherSuite,
) -> Result<Vec<u8>, FnError> {
    let client_hello_payload: HandshakeMessagePayload = match full_client_hello.payload.clone() {
        MessagePayload::Handshake(payload) => Some(payload),
        _ => None,
    }
    .ok_or_else(|| {
        FnError::Malformed("Only can fill binder in HandshakeMessagePayload".to_owned())
    })?;

    let supported_suite = suite_as_supported_suite(suite)?;
    let hkdf_alg = supported_suite
        .tls13()
        .ok_or_else(|| FnError::Crypto("No tls 1.3 suite".to_owned()))?
        .hkdf_algorithm;
    let suite_hash = supported_suite.hash_algorithm();

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
        .ok_or_else(|| FnError::Codec("Failed to parse ecdh public key".to_string()))?;
    Ok(params.public.0)
}

pub fn fn_new_pubkey12(group: &NamedGroup) -> Result<Vec<u8>, FnError> {
    let kx = tls12_key_exchange(group)?;
    Ok(Vec::from(kx.pubkey.as_ref()))
}

pub fn fn_encode_ec_pubkey12(pubkey: &PayloadU8) -> Result<Vec<u8>, FnError> {
    let mut buf = Vec::new();
    let ecpoint = pubkey.clone();
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
    client_random: &Random,
    suite: &CipherSuite,
) -> Result<OpaqueMessage, FnError> {
    let supported_suite = suite_as_supported_suite(suite)?;

    let secrets = tls12_new_secrets(
        server_random,
        server_ecdh_pubkey,
        group,
        client_random,
        supported_suite,
    )?;

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
        FnError::Codec("Failed to load DER certificate".to_string())
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

pub fn fn_certificate_entries_make(
    entries: &Vec<CertificateEntry>,
) -> Result<CertificateEntries, FnError> {
    Ok(CertificateEntries(entries.clone()))
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

pub fn fn_named_group_secp256r1() -> Result<NamedGroup, FnError> {
    Ok(NamedGroup::secp256r1)
}

pub fn fn_named_group_secp384r1() -> Result<NamedGroup, FnError> {
    Ok(NamedGroup::secp384r1)
}

pub fn fn_named_group_x25519() -> Result<NamedGroup, FnError> {
    Ok(NamedGroup::X25519)
}

pub fn fn_u64_to_u32(input: &u64) -> Result<u32, FnError> {
    Ok(*input as u32)
}
