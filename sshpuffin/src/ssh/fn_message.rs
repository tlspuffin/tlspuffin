#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::ssh::message::{
    CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, KexEcdhReplyMessage,
    KexInitMessage, MacAlgorithms, NameList, OnWireData, RawSshMessage, SignatureSchemes,
    SshMessage,
};

pub fn fn_raw_message(message: &RawSshMessage) -> Result<RawSshMessage, FnError> {
    Ok(message.clone())
}

pub fn fn_onwire_message(data: &OnWireData) -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::OnWire(data.clone()))
}

pub fn fn_banner(banner: &String) -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::Banner(banner.clone()))
}

pub fn fn_kex_ecdh_reply(
    public_host_key: &Vec<u8>,
    ephemeral_public_key: &Vec<u8>,
    signature: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhReply(KexEcdhReplyMessage {
        public_host_key: public_host_key.clone(),
        ephemeral_public_key: ephemeral_public_key.clone(),
        signature: signature.clone(),
    }))
}

pub fn fn_kex_init(
    cookie: &[u8; 16],
    kex_algorithms: &KexAlgorithms,
    server_host_key_algorithms: &SignatureSchemes,
    encryption_algorithms_server_to_client: &EncryptionAlgorithms,
    encryption_algorithms_client_to_server: &EncryptionAlgorithms,
    mac_algorithms_client_to_server: &MacAlgorithms,
    mac_algorithms_server_to_client: &MacAlgorithms,
    compression_algorithms_client_to_server: &CompressionAlgorithms,
    compression_algorithms_server_to_client: &CompressionAlgorithms,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexInit(KexInitMessage {
        cookie: *cookie,
        kex_algorithms: kex_algorithms.clone(),
        server_host_key_algorithms: server_host_key_algorithms.clone(),
        encryption_algorithms_server_to_client: encryption_algorithms_server_to_client.clone(),
        encryption_algorithms_client_to_server: encryption_algorithms_client_to_server.clone(),
        mac_algorithms_client_to_server: mac_algorithms_client_to_server.clone(),
        mac_algorithms_server_to_client: mac_algorithms_server_to_client.clone(),
        compression_algorithms_client_to_server: compression_algorithms_client_to_server.clone(),
        compression_algorithms_server_to_client: compression_algorithms_server_to_client.clone(),
        languages_client_to_server: NameList::empty(),
        languages_server_to_client: NameList::empty(),
        first_kex_packet_follows: false,
    }))
}
