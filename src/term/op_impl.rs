use ring::{hkdf, hmac};
use ring::hkdf::{HKDF_SHA256, KeyType, Prk};
use ring::hmac::Key;
use ring::rand::SystemRandom;
use rustls::{CipherSuite, ProtocolVersion};
use rustls::internal::msgs::enums::{Compression, HandshakeType};
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::handshake::{ClientExtension, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionID};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;

pub fn op_hmac256_new_key() -> Key {
    // todo maybe we need a context for rng? Maybe also for hs_hash?
    let random = SystemRandom::new();
    let key = hmac::Key::generate(hmac::HMAC_SHA256, &random).unwrap();
    key
}

pub fn op_hmac256(key: &Key, msg: &Vec<u8>) -> Vec<u8> {
    let tag = hmac::sign(&key, msg);
    Vec::from(tag.as_ref())
}

enum SecretKind {
    ResumptionPSKBinderKey,
    ClientEarlyTrafficSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ExporterMasterSecret,
    ResumptionMasterSecret,
    DerivedSecret,
}

impl SecretKind {
    fn to_bytes(&self) -> &'static [u8] {
        match self {
            SecretKind::ResumptionPSKBinderKey => b"res binder",
            SecretKind::ClientEarlyTrafficSecret => b"c e traffic",
            SecretKind::ClientHandshakeTrafficSecret => b"c hs traffic",
            SecretKind::ServerHandshakeTrafficSecret => b"s hs traffic",
            SecretKind::ClientApplicationTrafficSecret => b"c ap traffic",
            SecretKind::ServerApplicationTrafficSecret => b"s ap traffic",
            SecretKind::ExporterMasterSecret => b"exp master",
            SecretKind::ResumptionMasterSecret => b"res master",
            SecretKind::DerivedSecret => b"derived",
        }
    }
}

fn derive_secret<L, F, T>(
    secret: &hkdf::Prk,
    kind: SecretKind,
    algorithm: L,
    context: &Vec<u8>,
    into: F,
) -> T
    where
        L: KeyType,
        F: for<'b> FnOnce(hkdf::Okm<'b, L>) -> T,
{
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let label = kind.to_bytes();
    let output_len = u16::to_be_bytes(algorithm.len() as u16);
    let label_len = u8::to_be_bytes((LABEL_PREFIX.len() + label.len()) as u8);
    let context_len = u8::to_be_bytes(context.len() as u8);

    let info = &[
        &output_len[..],
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
        context,
    ];
    let okm = secret.expand(info, algorithm).unwrap();
    into(okm)
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

pub fn op_client_hello(
    client_version: &ProtocolVersion,
    random: &Random,
    session_id: &SessionID,
    cipher_suites: &Vec<CipherSuite>,
    compression_methods: &Vec<Compression>,
    extensions: &Vec<ClientExtension>,
) -> Message {
    let payload = Handshake(HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: client_version.clone(),
            random: random.clone(),
            session_id: session_id.clone(),
            cipher_suites: cipher_suites.clone(),
            compression_methods: compression_methods.clone(),
            extensions: extensions.clone(),
        }),
    });
    Message {
        typ: RecordHandshake,
        version: ProtocolVersion::TLSv1_2,
        payload,
    }
}
