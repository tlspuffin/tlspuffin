use crate::tls::key_exchange::deterministic_key_exchange;
use ring::{hkdf::Prk, hmac, hmac::Key, rand::SystemRandom};
use rustls::cipher::{new_tls12, new_tls13_read, new_tls13_write};
use rustls::conn::{ConnectionRandoms, ConnectionSecrets};
use rustls::hash_hs::HandshakeHash;
use rustls::internal::msgs::base::PayloadU8;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel, ExtensionType};
use rustls::internal::msgs::handshake::{HasServerExtensions, ServerECDHParams};
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::key_schedule::{KeyScheduleHandshake, KeyScheduleNonSecret};
use rustls::kx::KeyExchangeResult;
use rustls::msgs::alert::AlertMessagePayload;
use rustls::suites::Tls12CipherSuite;
use rustls::{
    internal::msgs::{
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        enums::{
            Compression,
            ContentType::{ChangeCipherSpec, Handshake},
            HandshakeType, NamedGroup, ServerNameType,
        },
        handshake::{
            CertificatePayload, ClientExtension, ClientHelloPayload, HandshakeMessagePayload,
            HandshakePayload, HandshakePayload::Certificate, KeyShareEntry, Random,
            ServerExtension, ServerHelloPayload, ServerKeyExchangePayload, ServerName,
            ServerNamePayload, SessionID,
        },
        message::{Message, MessagePayload},
    },
    kx, tls12, CipherSuite, NoKeyLog, ProtocolVersion, SignatureScheme, SupportedCipherSuite,
    ALL_KX_GROUPS,
};
use std::convert::{TryFrom, TryInto};
use HandshakePayload::EncryptedExtensions;

// ----
// Concrete implementations
// ----

// ----
// TLS 1.3 Message constructors (Return type is message)
// ----

pub fn op_alert_close_notify() -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Alert(AlertMessagePayload {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        }),
    }
}

pub fn op_client_hello(
    client_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suites: &Vec<CipherSuite>,
    compression_methods: &Vec<Compression>,
    extensions: &Vec<ClientExtension>,
) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ClientHelloPayload {
                client_version: client_version.clone(),
                random: random.clone(),
                session_id: session_id.clone(),
                cipher_suites: cipher_suites.clone(),
                compression_methods: compression_methods.clone(),
                extensions: extensions.clone(),
            }),
        }),
    }
}

pub fn op_server_hello(
    legacy_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suite: &CipherSuite,
    compression_method: &Compression,
    extensions: &Vec<ServerExtension>,
) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(ServerHelloPayload {
                legacy_version: legacy_version.clone(),
                random: random.clone(),
                session_id: session_id.clone(),
                cipher_suite: cipher_suite.clone(),
                compression_method: compression_method.clone(),
                extensions: extensions.clone(),
            }),
        }),
    }
}

pub fn op_change_cipher_spec() -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    }
}

pub fn op_application_data(data: &Vec<u8>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ApplicationData(Payload::new(data.clone())),
    }
}

// ----
// TLS 1.3 Unused
// ----

pub fn op_encrypted_certificate(server_extensions: &Vec<ServerExtension>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::EncryptedExtensions,
            payload: EncryptedExtensions(server_extensions.clone()),
        }),
    }
}

pub fn op_certificate(certificate: &CertificatePayload) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: Certificate(certificate.clone()),
        }),
    }
}

// ----
// seed_client_attacker()
// ----

pub fn op_finished(verify_data: &Vec<u8>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_3, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(verify_data.clone())),
        }),
    }
}

pub fn op_protocol_version12() -> ProtocolVersion {
    ProtocolVersion::TLSv1_2
}

pub fn op_session_id() -> SessionID {
    SessionID::empty()
}

pub fn op_random() -> Random {
    let random_data: [u8; 32] = [1; 32];
    Random::from(random_data)
}

pub fn op_cipher_suites() -> Vec<CipherSuite> {
    vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
}

pub fn op_compressions() -> Vec<Compression> {
    vec![Compression::Null]
}

fn prepare_key(
    server_public_key: &[u8],
    transcript: &HandshakeHash,
    write: bool,
) -> (&'static SupportedCipherSuite, Prk) {
    let client_random = &[1u8; 32]; // todo see op_random()
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()
    let group = NamedGroup::X25519; // todo
    let mut key_schedule = create_handshake_key_schedule(server_public_key, suite, group);

    let key = if write {
        key_schedule.client_handshake_traffic_secret(
            &transcript.get_current_hash(),
            &NoKeyLog {},
            client_random,
        )
    } else {
        key_schedule.server_handshake_traffic_secret(
            &transcript.get_current_hash(),
            &NoKeyLog {},
            client_random,
        )
    };

    (suite, key)
}

fn create_handshake_key_schedule(
    server_public_key: &[u8],
    suite: &SupportedCipherSuite,
    group: NamedGroup,
) -> KeyScheduleHandshake {
    let skxg = kx::KeyExchange::choose(group, &ALL_KX_GROUPS).unwrap();
    // Shared Secret
    let our_key_share: kx::KeyExchange = deterministic_key_exchange(skxg);
    let shared = our_key_share.complete(server_public_key).unwrap();

    // Key Schedule without PSK
    let key_schedule =
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared.shared_secret);

    key_schedule
}

pub fn op_verify_data(
    server_extensions: &Vec<ServerExtension>,
    verify_transcript: &HandshakeHash,
    client_handshake_traffic_secret_transcript: &HandshakeHash,
) -> Vec<u8> {
    let client_random = &[1u8; 32]; // todo see op_random()
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()

    let group = NamedGroup::X25519; // todo

    let keyshare = get_server_public_key(server_extensions);
    let server_public_key = keyshare.unwrap().payload.0.as_slice();

    let mut key_schedule = create_handshake_key_schedule(server_public_key, suite, group);

    key_schedule.client_handshake_traffic_secret(
        &client_handshake_traffic_secret_transcript.get_current_hash(),
        &NoKeyLog,
        client_random,
    );

    let pending = key_schedule.into_traffic_with_client_finished_pending();

    let bytes = pending.sign_client_finish(&verify_transcript.get_current_hash());
    Vec::from(bytes.as_ref())
}

pub fn op_new_transcript() -> HandshakeHash {
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256;

    let mut transcript = HandshakeHash::new();
    transcript.start_hash(&suite.get_hash());
    transcript
}

pub fn op_append_transcript(transcript: &HandshakeHash, message: &Message) -> HandshakeHash {
    let mut new_transcript: HandshakeHash = transcript.clone();
    new_transcript.add_message(message);

    /*    match &message.payload {
        MessagePayload::Alert(_) => {}
        MessagePayload::Handshake(h) => { println!("add_message() {:?}", h.typ);}
        MessagePayload::ChangeCipherSpec(_) => {}
        MessagePayload::ApplicationData(_) => {}
    }
    println!("add_message() {:?}", &new_transcript.get_current_hash());*/
    new_transcript
}

pub fn op_decrypt(
    application_data: &Message,
    server_extensions: &Vec<ServerExtension>,
    transcript: &HandshakeHash,
    sequence: &u64,
) -> Message {
    let keyshare = get_server_public_key(server_extensions);

    let server_public_key = keyshare.unwrap().payload.0.as_slice();
    let (suite, key) = prepare_key(server_public_key, &transcript, false);
    let decrypter = new_tls13_read(suite, &key);
    let message = decrypter
        .decrypt(OpaqueMessage::from(application_data.clone()), *sequence)
        .unwrap();
    let result = Message::try_from(message.clone()).unwrap();
    return result;
}

pub fn op_encrypt(
    some_message: &Message,
    server_extensions: &Vec<ServerExtension>,
    transcript: &HandshakeHash,
    sequence: &u64,
) -> Message {
    let keyshare = get_server_public_key(server_extensions);

    let server_public_key = keyshare.unwrap().payload.0.as_slice();
    let (suite, key) = prepare_key(server_public_key, &transcript, true);
    let encrypter = new_tls13_write(suite, &key);
    let application_data = encrypter
        .encrypt(
            OpaqueMessage::from(some_message.clone()).borrow(),
            *sequence,
        )
        .unwrap();
    Message::try_from(application_data.clone()).unwrap()
}

pub fn get_server_public_key(server_extensions: &Vec<ServerExtension>) -> Option<&KeyShareEntry> {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .unwrap();

    if let ServerExtension::KeyShare(keyshare) = server_extension {
        Some(keyshare)
    } else {
        None
    }
}

// ----
// Unused
// ----

pub fn op_hmac256_new_key() -> Key {
    // todo maybe we need a context for rng? Maybe also for hs_hash?
    let random = SystemRandom::new();
    let key = hmac::Key::generate(hmac::HMAC_SHA256, &random).unwrap();
    key
}

pub fn op_arbitrary_to_key(key: &Vec<u8>) -> Key {
    Key::new(hmac::HMAC_SHA256, key.as_slice())
}

pub fn op_hmac256(key: &Key, msg: &Vec<u8>) -> Vec<u8> {
    let tag = hmac::sign(&key, msg);
    Vec::from(tag.as_ref())
}

// ----
// TLS 1.2, all used in seed_successful12
// ----

pub fn op_server_certificate(certs: &CertificatePayload) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(certs.clone()),
        }),
    }
}

pub fn op_server_key_exchange(data: &Vec<u8>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Unknown(
                Payload::new(data.clone()),
            )),
        }),
    }
}

pub fn op_server_hello_done() -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerHelloDone,
            payload: HandshakePayload::ServerHelloDone,
        }),
    }
}

pub fn op_client_key_exchange(data: &Vec<u8>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(Payload::new(data.clone())),
        }),
    }
}

pub fn op_change_cipher_spec12() -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    }
}

pub fn op_opaque_handshake_message(data: &Vec<u8>) -> OpaqueMessage {
    OpaqueMessage {
        typ: Handshake,
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: Payload::new(data.clone()),
    }
}

// ----
// seed_client_attacker12()
// ----

pub fn op_cipher_suites12() -> Vec<CipherSuite> {
    vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
}

pub fn op_new_transcript12() -> HandshakeHash {
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

    let mut transcript = HandshakeHash::new();
    transcript.start_hash(&suite.get_hash());
    transcript
}

pub fn op_decode_ecdh_params(data: &Vec<u8>) -> ServerECDHParams {
    let mut rd = Reader::init(data.as_slice());
    ServerECDHParams::read(&mut rd).unwrap()
}

fn new_key_exchange_result(server_ecdh_params: &ServerECDHParams) -> KeyExchangeResult {
    let group = NamedGroup::X25519; // todo
    let skxg = kx::KeyExchange::choose(group, &ALL_KX_GROUPS).unwrap();
    let kx: kx::KeyExchange = deterministic_key_exchange(skxg);
    let kxd = tls12::complete_ecdh(kx, &server_ecdh_params.public.0).unwrap();
    kxd
}

pub fn op_new_pubkey12(server_ecdh_params: &ServerECDHParams) -> Vec<u8> {
    let kxd = new_key_exchange_result(server_ecdh_params);
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.pubkey.as_ref()));
    ecpoint.encode(&mut buf);
    buf
}

fn new_secrets(server_random: &Random, server_ecdh_params: &ServerECDHParams) -> ConnectionSecrets {
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; // todo

    let mut server_random_bytes = vec![0; 32];

    server_random.write_slice(&mut server_random_bytes);

    let randoms = ConnectionRandoms {
        we_are_client: true,
        client: [1; 32], // todo
        server: server_random_bytes.try_into().unwrap(),
    };
    let kxd = new_key_exchange_result(server_ecdh_params);
    let suite12 = Tls12CipherSuite::try_from(suite).unwrap();
    let secrets = ConnectionSecrets::new(&randoms, suite12, &kxd.shared_secret);
    secrets
}

pub fn op_encrypt12(
    message: &Message,
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
    sequence: &u64,
) -> OpaqueMessage {
    let secrets = new_secrets(server_random, server_ecdh_params);

    let (_decrypter, encrypter) = new_tls12(&secrets);
    encrypter
        .encrypt(OpaqueMessage::from(message.clone()).borrow(), *sequence)
        .unwrap()
}

pub fn op_finished12(data: &Vec<u8>) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(data.clone())),
        }),
    }
}

pub fn op_sign_transcript(
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
    transcript: &HandshakeHash,
) -> Vec<u8> {
    let secrets = new_secrets(server_random, server_ecdh_params);

    let vh = transcript.get_current_hash();
    secrets.client_verify_data(&vh)
}
