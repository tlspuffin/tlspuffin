#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::ssh::message::{
    ChannelCloseMessage, ChannelDataMessage, ChannelEofMessage, ChannelExtendedDataMessage,
    ChannelFailureMessage, ChannelOpenConfirmationMessage, ChannelOpenFailureMessage,
    ChannelOpenMessage, ChannelRequestMessage, ChannelSuccessMessage, ChannelWindowAdjustMessage,
    CompressionAlgorithms, DebugMessage, DisconnectMessage, EncryptionAlgorithms,
    GlobalRequestMessage, IgnoreMessage, KexAlgorithms, KexEcdhInitMessage, KexEcdhReplyMessage,
    KexInitMessage, MacAlgorithms, NameList, OnWireData, RawSshMessage, RequestSuccessMessage,
    ServiceAcceptMessage, ServiceRequestMessage, SignatureSchemes, SshBytes, SshMessage,
    SshPublicKey, SshSignature, UnimplementedMessage, UserAuthBannerMessage,
    UserAuthFailureMessage, UserAuthRequestMessage,
};

pub fn fn_raw_message(message: &RawSshMessage) -> Result<RawSshMessage, FnError> {
    Ok(message.clone())
}

/// Wraps an SshMessage into a properly framed RawSshMessage::Packet.
/// Use this when sending structured messages in InputActions, since InputAction
/// serializes via Codec::encode() which for SshMessage omits the binary packet framing.
pub fn fn_packet(msg: &SshMessage) -> Result<RawSshMessage, FnError> {
    use puffin::protocol::ProtocolMessage;
    Ok(msg.create_opaque())
}

pub fn fn_onwire_message(data: &OnWireData) -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::OnWire(data.clone()))
}

pub fn fn_banner(banner: &String) -> Result<RawSshMessage, FnError> {
    Ok(RawSshMessage::Banner(banner.clone()))
}

// ── Constructor: SshBytes ────────────────────────────────────────────────────

pub fn fn_ssh_bytes(data: &Vec<u8>) -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(data.clone()))
}

pub fn fn_ssh_bytes_empty() -> Result<SshBytes, FnError> {
    Ok(SshBytes::empty())
}

// ── Constructor: SshPublicKey / SshSignature ─────────────────────────────────

pub fn fn_ssh_public_key(
    algorithm: &SshBytes,
    key_data: &SshBytes,
) -> Result<SshPublicKey, FnError> {
    Ok(SshPublicKey {
        algorithm: algorithm.clone(),
        key_data: key_data.clone(),
    })
}

pub fn fn_ssh_signature(
    algorithm: &SshBytes,
    signature_data: &SshBytes,
) -> Result<SshSignature, FnError> {
    Ok(SshSignature {
        algorithm: algorithm.clone(),
        signature_data: signature_data.clone(),
    })
}

// ── Message constructors ─────────────────────────────────────────────────────

pub fn fn_disconnect(
    reason_code: &u32,
    description: &SshBytes,
    language_tag: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Disconnect(DisconnectMessage {
        reason_code: *reason_code,
        description: description.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_ignore(data: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Ignore(IgnoreMessage { data: data.clone() }))
}

pub fn fn_unimplemented(packet_sequence_number: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Unimplemented(UnimplementedMessage {
        packet_sequence_number: *packet_sequence_number,
    }))
}

pub fn fn_debug(
    always_display: &bool,
    message: &SshBytes,
    language_tag: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Debug(DebugMessage {
        always_display: *always_display,
        message: message.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_service_request(service_name: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceRequest(ServiceRequestMessage {
        service_name: service_name.clone(),
    }))
}

pub fn fn_service_accept(service_name: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceAccept(ServiceAcceptMessage {
        service_name: service_name.clone(),
    }))
}

pub fn fn_kex_ecdh_init(ephemeral_public_key: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhInit(KexEcdhInitMessage {
        ephemeral_public_key: ephemeral_public_key.clone(),
    }))
}

pub fn fn_kex_ecdh_reply(
    public_host_key: &SshPublicKey,
    ephemeral_public_key: &SshBytes,
    signature: &SshSignature,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhReply(KexEcdhReplyMessage {
        public_host_key: public_host_key.clone(),
        ephemeral_public_key: ephemeral_public_key.clone(),
        signature: signature.clone(),
    }))
}

pub fn fn_new_keys() -> Result<SshMessage, FnError> {
    Ok(SshMessage::NewKeys)
}

// Shared builder for a fixed aes256-gcm KexInit. `host_key_algos` lets the
// caller restrict the offered host-key algorithms (the server-attacker seed
// offers only rsa-sha2-256 so the negotiated algorithm matches its signature).
fn kexinit_aesgcm(cookie: &[u8; 16], host_key_algos: &[&str]) -> SshMessage {
    use crate::ssh::message::{
        CompressionAlgorithms, EncryptionAlgorithms, KexAlgorithms, MacAlgorithms, NameList,
        SignatureSchemes,
    };
    SshMessage::KexInit(KexInitMessage {
        cookie: *cookie,
        kex_algorithms: KexAlgorithms(NameList::from_strs(&["curve25519-sha256"])),
        server_host_key_algorithms: SignatureSchemes(NameList::from_strs(host_key_algos)),
        encryption_algorithms_client_to_server: EncryptionAlgorithms(NameList::from_strs(&[
            "aes256-gcm@openssh.com",
        ])),
        encryption_algorithms_server_to_client: EncryptionAlgorithms(NameList::from_strs(&[
            "aes256-gcm@openssh.com",
        ])),
        mac_algorithms_client_to_server: MacAlgorithms(NameList::from_strs(&["hmac-sha2-256"])),
        mac_algorithms_server_to_client: MacAlgorithms(NameList::from_strs(&["hmac-sha2-256"])),
        compression_algorithms_client_to_server: CompressionAlgorithms(NameList::from_strs(&[
            "none",
        ])),
        compression_algorithms_server_to_client: CompressionAlgorithms(NameList::from_strs(&[
            "none",
        ])),
        languages_client_to_server: NameList::empty(),
        languages_server_to_client: NameList::empty(),
        first_kex_packet_follows: false,
    })
}

/// A fixed client KexInit that offers ONLY aes256-gcm@openssh.com (plus
/// curve25519-sha256 / rsa-sha2 / none), so that both libssh and wolfSSH
/// negotiate AES-256-GCM. This makes a single seed valid against both
/// implementations (unlike the algorithm-mirroring seeds, which let each PUT
/// pick its own top cipher — chacha20 for libssh, aes-gcm for wolfSSH).
pub fn fn_client_kexinit_aesgcm(cookie: &[u8; 16]) -> Result<SshMessage, FnError> {
    Ok(kexinit_aesgcm(cookie, &["rsa-sha2-512", "rsa-sha2-256"]))
}

/// A fixed SERVER KexInit offering aes256-gcm and ONLY rsa-sha2-256 as the
/// host-key algorithm, so the client negotiates rsa-sha2-256 — matching the
/// rsa-sha2-256 signature the server-attacker seed produces. Used by the
/// fuzzer when it plays the server against a libssh/wolfSSH client.
pub fn fn_server_kexinit_aesgcm(cookie: &[u8; 16]) -> Result<SshMessage, FnError> {
    Ok(kexinit_aesgcm(cookie, &["rsa-sha2-256"]))
}

pub fn fn_user_auth_request(
    user_name: &SshBytes,
    service_name: &SshBytes,
    method_name: &SshBytes,
    method_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthRequest(UserAuthRequestMessage {
        user_name: user_name.clone(),
        service_name: service_name.clone(),
        method_name: method_name.clone(),
        method_data: method_data.clone(),
    }))
}

pub fn fn_user_auth_failure(
    authentications_that_can_continue: &NameList,
    partial_success: &bool,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthFailure(UserAuthFailureMessage {
        authentications_that_can_continue: authentications_that_can_continue.clone(),
        partial_success: *partial_success,
    }))
}

pub fn fn_user_auth_success() -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthSuccess)
}

pub fn fn_user_auth_banner(
    message: &SshBytes,
    language_tag: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthBanner(UserAuthBannerMessage {
        message: message.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_global_request(
    request_name: &SshBytes,
    want_reply: &bool,
    request_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::GlobalRequest(GlobalRequestMessage {
        request_name: request_name.clone(),
        want_reply: *want_reply,
        request_data: request_data.clone(),
    }))
}

pub fn fn_request_success(response_data: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::RequestSuccess(RequestSuccessMessage {
        response_data: response_data.clone(),
    }))
}

pub fn fn_request_failure() -> Result<SshMessage, FnError> {
    Ok(SshMessage::RequestFailure)
}

pub fn fn_channel_open(
    channel_type: &SshBytes,
    sender_channel: &u32,
    initial_window_size: &u32,
    maximum_packet_size: &u32,
    channel_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpen(ChannelOpenMessage {
        channel_type: channel_type.clone(),
        sender_channel: *sender_channel,
        initial_window_size: *initial_window_size,
        maximum_packet_size: *maximum_packet_size,
        channel_data: channel_data.clone(),
    }))
}

pub fn fn_channel_open_confirmation(
    recipient_channel: &u32,
    sender_channel: &u32,
    initial_window_size: &u32,
    maximum_packet_size: &u32,
    channel_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpenConfirmation(
        ChannelOpenConfirmationMessage {
            recipient_channel: *recipient_channel,
            sender_channel: *sender_channel,
            initial_window_size: *initial_window_size,
            maximum_packet_size: *maximum_packet_size,
            channel_data: channel_data.clone(),
        },
    ))
}

pub fn fn_channel_open_failure(
    recipient_channel: &u32,
    reason_code: &u32,
    description: &SshBytes,
    language_tag: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpenFailure(ChannelOpenFailureMessage {
        recipient_channel: *recipient_channel,
        reason_code: *reason_code,
        description: description.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_channel_window_adjust(
    recipient_channel: &u32,
    bytes_to_add: &u32,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelWindowAdjust(
        ChannelWindowAdjustMessage {
            recipient_channel: *recipient_channel,
            bytes_to_add: *bytes_to_add,
        },
    ))
}

pub fn fn_channel_data(recipient_channel: &u32, data: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelData(ChannelDataMessage {
        recipient_channel: *recipient_channel,
        data: data.clone(),
    }))
}

pub fn fn_channel_extended_data(
    recipient_channel: &u32,
    data_type_code: &u32,
    data: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelExtendedData(
        ChannelExtendedDataMessage {
            recipient_channel: *recipient_channel,
            data_type_code: *data_type_code,
            data: data.clone(),
        },
    ))
}

pub fn fn_channel_eof(recipient_channel: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelEof(ChannelEofMessage {
        recipient_channel: *recipient_channel,
    }))
}

pub fn fn_channel_close(recipient_channel: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelClose(ChannelCloseMessage {
        recipient_channel: *recipient_channel,
    }))
}

pub fn fn_channel_request(
    recipient_channel: &u32,
    request_type: &SshBytes,
    want_reply: &bool,
    request_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelRequest(ChannelRequestMessage {
        recipient_channel: *recipient_channel,
        request_type: request_type.clone(),
        want_reply: *want_reply,
        request_data: request_data.clone(),
    }))
}

pub fn fn_channel_success(recipient_channel: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelSuccess(ChannelSuccessMessage {
        recipient_channel: *recipient_channel,
    }))
}

pub fn fn_channel_failure(recipient_channel: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelFailure(ChannelFailureMessage {
        recipient_channel: *recipient_channel,
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
