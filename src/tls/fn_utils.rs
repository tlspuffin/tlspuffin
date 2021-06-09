use std::convert::TryFrom;

use ring::hmac;
use ring::hmac::Key;
use ring::test::rand::FixedByteRandom;
use rustls::cipher::{new_tls12, new_tls13_read, new_tls13_write};
use rustls::hash_hs::HandshakeHash;
use rustls::internal::msgs::base::PayloadU8;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::{Random, ServerECDHParams, ServerExtension};
use rustls::internal::msgs::message::{Message, OpaqueMessage};

use super::error::FnError;

// ----
// seed_client_attacker()
// ----

pub fn fn_new_transcript() -> Result<HandshakeHash, FnError> {
    let suite = &rustls::suites::TLS13_AES_128_GCM_SHA256;

    let mut transcript = HandshakeHash::new();
    transcript.start_hash(&suite.get_hash());
    Ok(transcript)
}

pub fn fn_append_transcript(
    transcript: &HandshakeHash,
    message: &Message,
) -> Result<HandshakeHash, FnError> {
    let mut new_transcript: HandshakeHash = transcript.clone();
    new_transcript.add_message(message);

    /*    match &message.payload {
        MessagePayload::Alert(_) => {}
        MessagePayload::Handshake(h) => { println!("add_message() {:?}", h.typ);}
        MessagePayload::ChangeCipherSpec(_) => {}
        MessagePayload::ApplicationData(_) => {}
    }
    println!("add_message() {:?}", &new_transcript.get_current_hash());*/
    Ok(new_transcript)
}

pub fn fn_decrypt(
    application_data: &Message,
    server_extensions: &Vec<ServerExtension>,
    transcript: &HandshakeHash,
    sequence: &u64,
) -> Result<Message, FnError> {
    let keyshare = super::tls13_get_server_key_share(server_extensions)?;

    let server_public_key = keyshare.payload.0.as_slice();
    let (suite, key) = super::tls13_client_handshake_traffic_secret(server_public_key, &transcript, false)?;
    let decrypter = new_tls13_read(suite, &key);
    let message = decrypter.decrypt(OpaqueMessage::from(application_data.clone()), *sequence)?;
    Ok(Message::try_from(message.clone())?)
}

pub fn fn_encrypt(
    some_message: &Message,
    server_extensions: &Vec<ServerExtension>,
    transcript: &HandshakeHash,
    sequence: &u64,
) -> Result<Message, FnError> {
    let keyshare = super::tls13_get_server_key_share(server_extensions)?;

    let server_public_key = keyshare.payload.0.as_slice();
    let (suite, key) = super::tls13_client_handshake_traffic_secret(server_public_key, &transcript, true)?;
    let encrypter = new_tls13_write(suite, &key);
    let application_data = encrypter.encrypt(
        OpaqueMessage::from(some_message.clone()).borrow(),
        *sequence,
    )?;
    Ok(Message::try_from(application_data.clone())?)
}

// ----
// seed_client_attacker12()
// ----

pub fn fn_new_transcript12() -> Result<HandshakeHash, FnError> {
    let suite = &rustls::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

    let mut transcript = HandshakeHash::new();
    transcript.start_hash(&suite.get_hash());
    Ok(transcript)
}

pub fn fn_decode_ecdh_params(data: &Vec<u8>) -> Result<ServerECDHParams, FnError> {
    let mut rd = Reader::init(data.as_slice());
    ServerECDHParams::read(&mut rd).ok_or(FnError::Message(
        "Failed to create ServerECDHParams".to_string(),
    ))
}

pub fn fn_new_pubkey12(server_ecdh_params: &ServerECDHParams) -> Result<Vec<u8>, FnError> {
    let kxd = super::tls12_key_exchange(server_ecdh_params)?;
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.pubkey.as_ref()));
    ecpoint.encode(&mut buf);
    Ok(buf)
}

pub fn fn_encrypt12(
    message: &Message,
    server_random: &Random,
    server_ecdh_params: &ServerECDHParams,
    sequence: &u64,
) -> Result<OpaqueMessage, FnError> {
    let secrets = super::tls12_new_secrets(server_random, server_ecdh_params)?;

    let (_decrypter, encrypter) = new_tls12(&secrets);
    Ok(encrypter.encrypt(OpaqueMessage::from(message.clone()).borrow(), *sequence)?)
}

// ----
// Unused
// ----

pub fn fn_hmac256_new_key() -> Result<Key, FnError> {
    // todo maybe we need a context for rng? Maybe also for hs_hash?
    let random = FixedByteRandom { byte: 12 };
    Ok(hmac::Key::generate(hmac::HMAC_SHA256, &random)?)
}

pub fn fn_arbitrary_to_key(key: &Vec<u8>) -> Result<Key, FnError> {
    Ok(Key::new(hmac::HMAC_SHA256, key.as_slice()))
}

pub fn fn_hmac256(key: &Key, msg: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    let tag = hmac::sign(&key, msg);
    Ok(Vec::from(tag.as_ref()))
}
