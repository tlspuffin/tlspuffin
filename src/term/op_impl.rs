use std::collections::HashMap;

use itertools::Itertools;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use ring::{
    hkdf,
    hkdf::{Prk, HKDF_SHA256},
    hmac,
    hmac::Key,
    rand::SystemRandom,
};
use rustls::cipher::{new_tls13_read, new_tls13_write, GcmMessageEncrypter};
use rustls::hash_hs::HandshakeHash;
use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::HasServerExtensions;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::key_schedule::{
    KeySchedule, KeyScheduleEarly, KeyScheduleHandshake, KeyScheduleNonSecret,
};
use rustls::kx_group::X25519;
use rustls::suites::TLS13_AES_128_GCM_SHA256;
use rustls::{
    internal::msgs::{
        base::{Payload, PayloadU16},
        ccs::ChangeCipherSpecPayload,
        enums::{
            Compression,
            ContentType::{ApplicationData, ChangeCipherSpec, Handshake},
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
    kx, CipherSuite, NoKeyLog, ProtocolVersion, SignatureScheme, SupportedCipherSuite,
    ALL_KX_GROUPS,
};
use HandshakePayload::EncryptedExtensions;

use crate::register_fn;
use crate::term::{make_dynamic, DynamicFunction, TypeShape};
use crate::tls::derive::{derive_secret, SecretKind};
use crate::tls::deterministic_key_exchange;
use std::convert::TryFrom;

// ----
// Types
// ----

/// Special type which is used in [`crate::trace::InputAction`]. This is used if an recipe outputs
/// more or less than exactly one message.
#[derive(Clone)]
pub struct MultiMessage {
    pub messages: Vec<Message>,
}

// ----
// Concrete implementations
// ----

// ----
// TLS 1.3 Message constructors (Return type is message)
// ----

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

pub fn op_application_data(data: &Payload) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ApplicationData(data.clone()),
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

fn prepare_read_key(
    server_public_key: &[u8],
    client_hello: &Message,
    server_hello: &Message,
) -> (&'static SupportedCipherSuite, Prk) {
    let client_random = &[1u8; 32]; // todo see op_random()
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256; // todo see op_cipher_suites()

    let group = NamedGroup::X25519;
    let skxg = kx::KeyExchange::choose(group, &ALL_KX_GROUPS).unwrap();

    // generates an ephemeral key: ring::agreement::EphemeralPrivateKey::generate
    //let our_key_share: kx::KeyExchange = kx::KeyExchange::start(skxg).unwrap();

    // always the same value
    let our_key_share: kx::KeyExchange = deterministic_key_exchange(skxg);

    let shared = our_key_share.complete(server_public_key).unwrap();

    let key_log = NoKeyLog {};

    let mut key_schedule =
        KeyScheduleNonSecret::new(suite.hkdf_algorithm).into_handshake(&shared.shared_secret);

    // let master_secret = &[0; 10]; // todo ?
    // let early_key_schedule = KeyScheduleEarly::new(suite.hkdf_algorithm, master_secret);
    // let mut key_schedule = early_key_schedule.into_handshake(shared.shared_secret.as_slice());

    let mut transcript = HandshakeHash::new();
    transcript.start_hash(&suite.get_hash());
    // todo transcript
    transcript.add_message(&client_hello);
    transcript.add_message(&server_hello);
    let hash_at_client_recvd_server_hello = transcript.get_current_hash();
    println!("{:#?}", hash_at_client_recvd_server_hello);

    let write_key = key_schedule.server_handshake_traffic_secret(
        &hash_at_client_recvd_server_hello, // todo ?
        &key_log,
        client_random,
    );

    (suite, write_key)
}

/*pub fn op_encrypt(message: &OpaqueMessage, server_public_key: &[u8], ) -> OpaqueMessage {
    let (suite, key) = prepare_read_key(server_public_key);
    let encrypter = new_tls13_write(suite, &key);
    let seq = 0; // todo ?
    encrypter.encrypt(message.borrow(), seq).unwrap()
}*/

pub fn op_decrypt_after_server_hello(
    application_data: &Message,
    server_extensions: &Vec<ServerExtension>,
    client_hello: &Message,
    server_hello: &Message,
) -> Message {
    let server_extension = server_extensions
        .find_extension(ExtensionType::KeyShare)
        .unwrap();

    if let ServerExtension::KeyShare(ks) = server_extension {
        let server_public_key = ks.payload.0.as_slice();

        let (suite, key) = prepare_read_key(server_public_key, client_hello, server_hello);
        let decrypter = new_tls13_read(suite, &key);
        let seq = 0; // todo ?
        let message = decrypter
            .decrypt(OpaqueMessage::from(application_data.clone()), seq)
            .unwrap();
        Message::try_from(message.clone()).unwrap()
    } else {
        panic!();
    }
}

pub fn op_server_name_extension() -> ClientExtension {
    let dns_name = "maxammann.org";
    ClientExtension::ServerName(vec![ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName((
            PayloadU16(dns_name.to_string().into_bytes()),
            webpki::DnsNameRef::try_from_ascii_str(dns_name)
                .unwrap()
                .to_owned(),
        )),
    }])
}

pub fn op_x25519_support_group_extension() -> ClientExtension {
    ClientExtension::NamedGroups(vec![NamedGroup::X25519])
}

pub fn op_signature_algorithm_extension() -> ClientExtension {
    ClientExtension::SignatureAlgorithms(vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ])
}

pub fn op_key_share_extension() -> ClientExtension {
    //let key = Vec::from(rand::random::<[u8; 32]>()); // 32 byte public key
    //let key = Vec::from([42; 32]); // 32 byte public key
    let our_key_share: kx::KeyExchange = deterministic_key_exchange(&X25519);
    ClientExtension::KeyShare(vec![KeyShareEntry {
        group: NamedGroup::X25519,
        payload: PayloadU16::new(Vec::from(our_key_share.pubkey.as_ref())),
    }])
}

pub fn op_supported_versions_extension() -> ClientExtension {
    ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3])
}

pub fn op_extensions_new() -> Vec<ClientExtension> {
    vec![]
}

pub fn op_extensions_append(
    extensions: &Vec<ClientExtension>,
    extension: &ClientExtension,
) -> Vec<ClientExtension> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());
    new_extensions
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

// https://github.com/ctz/rustls/blob/d03bf27e0b520fe73c901d0027bab12753a42bb6/rustls/src/key_schedule.rs#L164
pub fn op_client_handshake_traffic_secret(secret: &hkdf::Prk, hs_hash: &Vec<u8>) -> Prk {
    let secret: hkdf::Prk = derive_secret(
        secret,
        SecretKind::ClientHandshakeTrafficSecret,
        HKDF_SHA256, // todo make configurable
        hs_hash,
        |okm| okm.into(),
    );

    secret
}

/*pub fn op_random_cipher_suite() -> CipherSuite {
    *vec![
        CipherSuite::TLS13_AES_128_CCM_SHA256,
        CipherSuite::TLS13_AES_128_CCM_8_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    ]
    .choose(&mut rand::thread_rng())
    .unwrap()
}

pub fn op_random_compression() -> Compression {
    *vec![Compression::Null, Compression::Deflate, Compression::LSZ]
        .choose(&mut rand::thread_rng())
        .unwrap()
}

pub fn op_random_extensions() -> Vec<ClientExtension> {
    let server_name: ClientExtension = op_server_name_extension();

    let supported_groups: ClientExtension = op_x25519_support_group_extension();
    let signature_algorithms: ClientExtension = op_signature_algorithm_extension();
    let key_share: ClientExtension = op_key_share_extension();
    let supported_versions: ClientExtension = op_supported_versions_extension();

    vec![
        server_name,
        supported_groups,
        signature_algorithms,
        key_share,
        supported_versions,
    ]
}*/

// ----
// Utils
// ----

pub fn op_concat_messages_2(msg1: &Message, msg2: &Message) -> MultiMessage {
    MultiMessage {
        messages: vec![msg1.clone(), msg2.clone()],
    }
}

pub fn op_concat_messages_3(msg1: &Message, msg2: &Message, msg3: &Message) -> MultiMessage {
    MultiMessage {
        messages: vec![msg1.clone(), msg2.clone(), msg3.clone()],
    }
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

pub fn op_server_key_exchange(ske_payload: &ServerKeyExchangePayload) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ServerKeyExchange,
            payload: HandshakePayload::ServerKeyExchange(ske_payload.clone()),
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

pub fn op_client_key_exchange(data: &Payload) -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(data.clone()),
        }),
    }
}

pub fn op_change_cipher_spec12() -> Message {
    Message {
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    }
}

pub fn op_handshake_finished12(data: &Payload) -> OpaqueMessage {
    OpaqueMessage {
        typ: Handshake,
        version: ProtocolVersion::TLSv1_2, // todo this is not controllable
        payload: data.clone(),
    }
}

// ----
// Attack operations
// ----

// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3449

pub fn op_attack_cve_2021_3449(extensions: &Vec<ClientExtension>) -> Vec<ClientExtension> {
    extensions
        .clone()
        .into_iter()
        .filter(|extension| extension.get_type() != ExtensionType::SignatureAlgorithms)
        .collect_vec()
}

// ----
// Registry
// ----

register_fn!(
    REGISTERED_FN,
    REGISTERED_TYPES,
    op_hmac256_new_key,
    op_arbitrary_to_key,
    op_hmac256,
    op_client_handshake_traffic_secret,
    op_client_hello,
    op_server_hello,
    op_change_cipher_spec,
    op_encrypted_certificate,
    op_certificate,
    op_application_data,
    op_session_id,
    op_protocol_version12,
    op_random,
    op_server_name_extension,
    op_signature_algorithm_extension,
    op_key_share_extension,
    op_supported_versions_extension,
    op_x25519_support_group_extension,
    op_concat_messages_2,
    op_concat_messages_3,
);

// todo it would be possible generate dynamic functions like in criterion_group! macro
// or via a procedural macro.
// https://gitlab.inria.fr/mammann/tlspuffin/-/issues/28
