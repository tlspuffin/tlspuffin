#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;

use crate::protocol::RawSshMessageFlight;
use crate::ssh::message::{
    AlgoName, ChannelCloseMessage, ChannelDataMessage, ChannelEofMessage,
    ChannelExtendedDataMessage, ChannelFailureMessage, ChannelId, ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage, ChannelOpenMessage, ChannelRequestMessage, ChannelSuccessMessage,
    ChannelWindowAdjustMessage, CompressionAlgorithms, DebugMessage, DisconnectMessage,
    EncryptionAlgorithms, ExtInfoExtension, ExtInfoMessage, GlobalRequestMessage, IgnoreMessage,
    KexAlgorithms, KexEcdhInitMessage, KexEcdhReplyMessage, KexInitMessage, MacAlgorithms,
    NameList, OnWireData, RawMessage, RawSshMessage, RequestSuccessMessage, ServiceAcceptMessage,
    ServiceName, ServiceRequestMessage, SignatureSchemes, SshBytes, SshMessage, SshMsgNumber,
    SshPublicKey, SshPublicKeyBlob, SshSignature, UnimplementedMessage, UserAuthBannerMessage,
    UserAuthFailureMessage, UserAuthRequestMessage, Username,
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

/// Wraps a single raw SSH message into a one-message flight.
///
/// Primarily present so that `RawSshMessageFlight` — the whole-flight
/// agent-output knowledge type queried by the two-party relay seeds
/// (`(agent, n)/RawSshMessageFlight`) — is registered in the signature's type
/// table (`types_by_name`, which is derived solely from function arg/return
/// types). Without it, those query terms execute fine but cannot be
/// *deserialized*: `TypeShape`'s deserializer resolves a type by name against
/// that table and fails, so e.g. `seed_handshake_two_party` round-trips on
/// write but is skipped on load. Registered `[no_gen]` in the signature so it
/// does not enlarge the generation search space.
pub fn fn_raw_message_flight(message: &RawSshMessage) -> Result<RawSshMessageFlight, FnError> {
    Ok(RawSshMessageFlight::from(message.clone()))
}

/// Wrap arbitrary bytes as raw on-wire data. Revives `OnWireData` as a producible
/// term type so the fuzzer can inject unframed byte sequences into the stream.
pub fn fn_onwire_data(data: &Vec<u8>) -> Result<OnWireData, FnError> {
    Ok(OnWireData(data.clone()))
}

// ── Algorithm-negotiation builders ───────────────────────────────────────────
//
// These unfreeze KEXINIT negotiation for the DY mutator. Previously the only
// usable KEXINITs were the two fixed `fn_*_kexinit_aesgcm` (algorithm lists baked
// in), and `fn_kex_init` was dead because its list-typed arguments
// (KexAlgorithms / EncryptionAlgorithms / ...) had no producers. Now an algorithm
// list is built bottom-up from algorithm-name `AlgoName` atoms (fn_algo_*) into a
// `NameList`, then wrapped into the per-field list type. Because `NameList` is the
// shared intermediate, a mutation can splice a single algorithm name, swap a
// whole list across fields (algorithm confusion), reorder/duplicate entries, or
// drop to empty — exercising downgrade and negotiation-handling paths in the PUT.

/// The name-list of `names`: their bytes joined by commas (RFC 4251 §5), so the
/// list's encoding contains every name verbatim.
fn namelist_of(names: &[&AlgoName]) -> NameList {
    NameList::from_raw(
        names
            .iter()
            .map(|n| n.0.as_slice())
            .collect::<Vec<_>>()
            .join(&b","[..]),
    )
}

pub fn fn_namelist_empty() -> Result<NameList, FnError> {
    Ok(NameList::empty())
}
pub fn fn_namelist_1(a: &AlgoName) -> Result<NameList, FnError> {
    Ok(namelist_of(&[a]))
}
pub fn fn_namelist_2(a: &AlgoName, b: &AlgoName) -> Result<NameList, FnError> {
    Ok(namelist_of(&[a, b]))
}
pub fn fn_namelist_3(a: &AlgoName, b: &AlgoName, c: &AlgoName) -> Result<NameList, FnError> {
    Ok(namelist_of(&[a, b, c]))
}
/// A NameList whose wire bytes are exactly `raw` — lets a bit-mutated / observed
/// SshBytes become a (possibly malformed) algorithm list.
pub fn fn_namelist_from_bytes(raw: &SshBytes) -> Result<NameList, FnError> {
    Ok(NameList::from_raw(raw.0.clone()))
}

pub fn fn_kex_algos(list: &NameList) -> Result<KexAlgorithms, FnError> {
    Ok(KexAlgorithms(list.clone()))
}
pub fn fn_enc_algos(list: &NameList) -> Result<EncryptionAlgorithms, FnError> {
    Ok(EncryptionAlgorithms(list.clone()))
}
pub fn fn_mac_algos(list: &NameList) -> Result<MacAlgorithms, FnError> {
    Ok(MacAlgorithms(list.clone()))
}
pub fn fn_sig_schemes(list: &NameList) -> Result<SignatureSchemes, FnError> {
    Ok(SignatureSchemes(list.clone()))
}
pub fn fn_comp_algos(list: &NameList) -> Result<CompressionAlgorithms, FnError> {
    Ok(CompressionAlgorithms(list.clone()))
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

/// A public key of a single-string layout (`string algorithm || string key_data`,
/// e.g. ssh-ed25519), so the encoding contains both arguments. `ssh-rsa` is refused:
/// its blob is two mpints, which `SshPublicKey` stores unprefixed, so the result
/// would not contain `key_data`'s encoding. The RSA host key is `fn_server_rsa_pubkey`.
pub fn fn_ssh_public_key(
    algorithm: &AlgoName,
    key_data: &SshBytes,
) -> Result<SshPublicKey, FnError> {
    if algorithm.0 == b"ssh-rsa" {
        return Err(FnError::Malformed(
            "fn_ssh_public_key: ssh-rsa keys have a two-mpint layout".into(),
        ));
    }
    Ok(SshPublicKey {
        algorithm: SshBytes::new(algorithm.0.clone()),
        key_data: key_data.clone(),
    })
}

pub fn fn_ssh_signature(
    algorithm: &AlgoName,
    signature_data: &SshBytes,
) -> Result<SshSignature, FnError> {
    Ok(SshSignature {
        algorithm: SshBytes::new(algorithm.0.clone()),
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

/// SSH_MSG_EXT_INFO (RFC 8308) carrying a single extension (name, value), e.g.
/// "server-sig-algs". Lets the fuzzer exercise the peer's EXT_INFO parser.
pub fn fn_ext_info(name: &SshBytes, value: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ExtInfo(ExtInfoMessage {
        extensions: vec![ExtInfoExtension {
            name: name.clone(),
            value: value.clone(),
        }],
    }))
}

pub fn fn_unimplemented(packet_sequence_number: &u32) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Unimplemented(UnimplementedMessage {
        packet_sequence_number: *packet_sequence_number,
    }))
}

/// An ARBITRARY SSH message: the type byte `number` followed by `body` verbatim.
/// The general "unknown/malformed message-type" primitive: pointing it at
/// an unassigned number (RFC 4250 §4.1.2) makes the peer treat it as unrecognised,
/// so each stack's RFC 4253 §11.4 handling (reply SSH_MSG_UNIMPLEMENTED vs
/// bare-close) becomes a comparable, fuzzable objective.
pub fn fn_raw_ssh_message(number: &SshMsgNumber, body: &Vec<u8>) -> Result<SshMessage, FnError> {
    Ok(SshMessage::Raw(RawMessage {
        number: number.0,
        body: SshBytes::new(body.clone()),
    }))
}

/// The message number in the low byte of `n`, so the `fn_u32_*` atoms can drive any
/// message type (e.g. the transport messages 1-15) in `fn_raw_ssh_message`.
pub fn fn_msg_number(n: &u32) -> Result<SshMsgNumber, FnError> {
    Ok(SshMsgNumber::new((*n & 0xff) as u8))
}

/// Convenience: a fixed unknown/high-numbered message (type 250 — "reserved for
/// private use", RFC 4251 §7, so unimplemented by both stacks) with an empty body.
/// A deterministic reproducer atom for the item-7 "unknown message" probe.
pub fn fn_msg_unknown_highnumber() -> Result<SshMessage, FnError> {
    Ok(SshMessage::Raw(RawMessage {
        number: 250,
        body: SshBytes::new(Vec::new()),
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

pub fn fn_service_request(service_name: &ServiceName) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceRequest(ServiceRequestMessage {
        service_name: SshBytes::new(service_name.0.clone()),
    }))
}

pub fn fn_service_accept(service_name: &ServiceName) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ServiceAccept(ServiceAcceptMessage {
        service_name: SshBytes::new(service_name.0.clone()),
    }))
}

pub fn fn_kex_ecdh_init(ephemeral_public_key: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhInit(KexEcdhInitMessage {
        ephemeral_public_key: ephemeral_public_key.clone(),
    }))
}

/// Classic modular-DH `SSH_MSG_KEXDH_INIT` (msg 30) carrying `mpint e`. The wire
/// format is identical to KEX_ECDH_INIT (uint32 length + bytes), so it reuses the
/// same message; the distinction is that the negotiated KEX is a
/// `diffie-hellman-group*` method. Pair with an out-of-range `fn_dh_exponent_*`
/// to probe RFC 4253 §8 range validation (issue #1047 item 1).
pub fn fn_kex_dh_init(e: &SshBytes) -> Result<SshMessage, FnError> {
    Ok(SshMessage::KexEcdhInit(KexEcdhInitMessage {
        ephemeral_public_key: e.clone(),
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
    user_name: &Username,
    service_name: &ServiceName,
    method_name: &SshBytes,
    method_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::UserAuthRequest(UserAuthRequestMessage {
        user_name: SshBytes::new(user_name.0.clone()),
        service_name: SshBytes::new(service_name.0.clone()),
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

/// Wrap a `u32` as a `ChannelId` (the type-directed channel-number slot). Lets the
/// fuzzer build any channel id from the existing `fn_u32_*` atoms (including
/// boundary values) while keeping it type-segregated from non-channel u32 fields.
pub fn fn_channel_id(id: &u32) -> Result<ChannelId, FnError> {
    Ok(ChannelId::new(*id))
}

/// The `sender_channel` of a CHANNEL_OPEN or CHANNEL_OPEN_CONFIRMATION: the channel
/// number the PEER chose, which every later message on that channel must address
/// (e.g. read from a client's decrypted CHANNEL_OPEN via `fn_decrypted_message`).
pub fn fn_sender_channel(msg: &SshMessage) -> Result<ChannelId, FnError> {
    match msg {
        SshMessage::ChannelOpen(m) => Ok(ChannelId::new(m.sender_channel)),
        SshMessage::ChannelOpenConfirmation(m) => Ok(ChannelId::new(m.sender_channel)),
        _ => Err(FnError::Malformed(
            "sender_channel: not a CHANNEL_OPEN / CHANNEL_OPEN_CONFIRMATION".into(),
        )),
    }
}

/// The public-key blob a server echoes in SSH_MSG_USERAUTH_PK_OK (RFC 4252 §7:
/// string algorithm, string blob), decoded as `SshMessage::Raw` number 60. Lets a
/// client sign for exactly the key the server said it would accept.
pub fn fn_pk_ok_blob(msg: &SshMessage) -> Result<SshPublicKeyBlob, FnError> {
    let SshMessage::Raw(raw) = msg else {
        return Err(FnError::Malformed(
            "pk_ok_blob: not a raw message 60".into(),
        ));
    };
    if raw.number != 60 {
        return Err(FnError::Malformed(
            "pk_ok_blob: not USERAUTH_PK_OK (60)".into(),
        ));
    }
    let body = &raw.body.0;
    let take = |off: usize| -> Option<(&[u8], usize)> {
        let len = u32::from_be_bytes(body.get(off..off + 4)?.try_into().ok()?) as usize;
        Some((body.get(off + 4..off + 4 + len)?, off + 4 + len))
    };
    let (_alg, off) = take(0).ok_or_else(|| FnError::Malformed("PK_OK: algorithm".into()))?;
    let (blob, _) = take(off).ok_or_else(|| FnError::Malformed("PK_OK: key blob".into()))?;
    Ok(SshPublicKeyBlob::new(blob.to_vec()))
}

/// How much a sender may put in ONE CHANNEL_DATA to this peer right after it
/// opened / confirmed the channel (RFC 4254 §5.1-5.2): the smaller of the window it
/// granted and its maximum packet size.
pub fn fn_channel_send_budget(msg: &SshMessage) -> Result<u32, FnError> {
    match msg {
        SshMessage::ChannelOpen(m) => Ok(m.initial_window_size.min(m.maximum_packet_size)),
        SshMessage::ChannelOpenConfirmation(m) => {
            Ok(m.initial_window_size.min(m.maximum_packet_size))
        }
        _ => Err(FnError::Malformed(
            "send budget: not a CHANNEL_OPEN / CHANNEL_OPEN_CONFIRMATION".into(),
        )),
    }
}

/// The `initial_window_size` the peer granted in a CHANNEL_OPEN or
/// CHANNEL_OPEN_CONFIRMATION (how much data may be sent before a WINDOW_ADJUST).
pub fn fn_initial_window_size(msg: &SshMessage) -> Result<u32, FnError> {
    match msg {
        SshMessage::ChannelOpen(m) => Ok(m.initial_window_size),
        SshMessage::ChannelOpenConfirmation(m) => Ok(m.initial_window_size),
        _ => Err(FnError::Malformed(
            "initial_window_size: not a CHANNEL_OPEN / CHANNEL_OPEN_CONFIRMATION".into(),
        )),
    }
}

/// Channel id 0 — the fixed channel number the honest seeds address.
pub fn fn_channel_id_0() -> Result<ChannelId, FnError> {
    Ok(ChannelId::new(0))
}

pub fn fn_channel_open(
    channel_type: &SshBytes,
    sender_channel: &ChannelId,
    initial_window_size: &u32,
    maximum_packet_size: &u32,
    channel_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpen(ChannelOpenMessage {
        channel_type: channel_type.clone(),
        sender_channel: sender_channel.0,
        initial_window_size: *initial_window_size,
        maximum_packet_size: *maximum_packet_size,
        channel_data: channel_data.clone(),
    }))
}

pub fn fn_channel_open_confirmation(
    recipient_channel: &ChannelId,
    sender_channel: &ChannelId,
    initial_window_size: &u32,
    maximum_packet_size: &u32,
    channel_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpenConfirmation(
        ChannelOpenConfirmationMessage {
            recipient_channel: recipient_channel.0,
            sender_channel: sender_channel.0,
            initial_window_size: *initial_window_size,
            maximum_packet_size: *maximum_packet_size,
            channel_data: channel_data.clone(),
        },
    ))
}

pub fn fn_channel_open_failure(
    recipient_channel: &ChannelId,
    reason_code: &u32,
    description: &SshBytes,
    language_tag: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelOpenFailure(ChannelOpenFailureMessage {
        recipient_channel: recipient_channel.0,
        reason_code: *reason_code,
        description: description.clone(),
        language_tag: language_tag.clone(),
    }))
}

pub fn fn_channel_window_adjust(
    recipient_channel: &ChannelId,
    bytes_to_add: &u32,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelWindowAdjust(
        ChannelWindowAdjustMessage {
            recipient_channel: recipient_channel.0,
            bytes_to_add: *bytes_to_add,
        },
    ))
}

pub fn fn_channel_data(
    recipient_channel: &ChannelId,
    data: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelData(ChannelDataMessage {
        recipient_channel: recipient_channel.0,
        data: data.clone(),
    }))
}

pub fn fn_channel_extended_data(
    recipient_channel: &ChannelId,
    data_type_code: &u32,
    data: &SshBytes,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelExtendedData(
        ChannelExtendedDataMessage {
            recipient_channel: recipient_channel.0,
            data_type_code: *data_type_code,
            data: data.clone(),
        },
    ))
}

pub fn fn_channel_eof(recipient_channel: &ChannelId) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelEof(ChannelEofMessage {
        recipient_channel: recipient_channel.0,
    }))
}

pub fn fn_channel_close(recipient_channel: &ChannelId) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelClose(ChannelCloseMessage {
        recipient_channel: recipient_channel.0,
    }))
}

pub fn fn_channel_request(
    recipient_channel: &ChannelId,
    request_type: &SshBytes,
    want_reply: &bool,
    request_data: &Vec<u8>,
) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelRequest(ChannelRequestMessage {
        recipient_channel: recipient_channel.0,
        request_type: request_type.clone(),
        want_reply: *want_reply,
        request_data: request_data.clone(),
    }))
}

pub fn fn_channel_success(recipient_channel: &ChannelId) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelSuccess(ChannelSuccessMessage {
        recipient_channel: recipient_channel.0,
    }))
}

pub fn fn_channel_failure(recipient_channel: &ChannelId) -> Result<SshMessage, FnError> {
    Ok(SshMessage::ChannelFailure(ChannelFailureMessage {
        recipient_channel: recipient_channel.0,
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
