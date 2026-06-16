#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::ssh::message::{
    ChannelCloseMessage, ChannelDataMessage, ChannelEofMessage, ChannelExtendedDataMessage,
    ChannelFailureMessage, ChannelOpenConfirmationMessage, ChannelOpenFailureMessage,
    ChannelOpenMessage, ChannelRequestMessage, ChannelSuccessMessage, ChannelWindowAdjustMessage,
    CompressionAlgorithms, DebugMessage, DisconnectMessage, EncryptionAlgorithms,
    GlobalRequestMessage, IgnoreMessage, KexAlgorithms, KexEcdhInitMessage, KexEcdhReplyMessage,
    KexInitMessage, MacAlgorithms, NameList, OnWireData, RawSshMessage, RequestSuccessMessage,
    ServiceAcceptMessage, ServiceRequestMessage, SignatureSchemes, SshMessage,
    UnimplementedMessage, UserAuthBannerMessage, UserAuthFailureMessage, UserAuthRequestMessage,
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

pub fn fn_disconnect(
    reason_code: &u32,
    description: &Vec<u8>,
    language_tag: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Disconnect(DisconnectMessage {
        reason_code: *reason_code,
        description: description.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_ignore(data: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Ignore(IgnoreMessage { data: data.clone() }))
}

pub fn fn_unimplemented(packet_sequence_number: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Unimplemented(UnimplementedMessage {
        packet_sequence_number: *packet_sequence_number,
    }))
}

pub fn fn_debug(
    always_display: &bool,
    message: &Vec<u8>,
    language_tag: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Debug(DebugMessage {
        always_display: *always_display,
        message: message.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_service_request(service_name: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceRequest(ServiceRequestMessage {
        service_name: service_name.clone(),
    }))
}

pub fn fn_service_accept(service_name: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceAccept(ServiceAcceptMessage {
        service_name: service_name.clone(),
    }))
}

pub fn fn_kex_ecdh_init(ephemeral_public_key: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhInit(KexEcdhInitMessage {
        ephemeral_public_key: ephemeral_public_key.clone(),
    }))
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

pub fn fn_new_keys() -> Result<SshMessage, FnError> {
    Ok(SshMessage::NewKeys)
}

pub fn fn_user_auth_request(
    user_name: &Vec<u8>,
    service_name: &Vec<u8>,
    method_name: &Vec<u8>,
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
    message: &Vec<u8>,
    language_tag: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthBanner(UserAuthBannerMessage {
        message: message.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_global_request(
    request_name: &Vec<u8>,
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
    channel_type: &Vec<u8>,
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
    description: &Vec<u8>,
    language_tag: &Vec<u8>,
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

pub fn fn_channel_data(recipient_channel: &u32, data: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelData(ChannelDataMessage {
        recipient_channel: *recipient_channel,
        data: data.clone(),
    }))
}

pub fn fn_channel_extended_data(
    recipient_channel: &u32,
    data_type_code: &u32,
    data: &Vec<u8>,
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
    request_type: &Vec<u8>,
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
