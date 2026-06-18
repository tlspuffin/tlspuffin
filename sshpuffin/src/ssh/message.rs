use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};
use puffin::error::Error;
use puffin::protocol::{Extractable, OpaqueProtocolMessage, ProtocolMessage, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, dummy_extract_knowledge};

use crate::protocol::SshProtocolTypes;

#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct OnWireData(pub Vec<u8>);

impl Codec for OnWireData {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let data = <Vec<u8> as Codec>::read(reader)?;
        Some(OnWireData(data))
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub enum RawSshMessage {
    #[extractable_no_recursion]
    Banner(String),
    #[extractable_no_recursion]
    Packet(BinaryPacket),
    #[extractable_no_recursion]
    OnWire(OnWireData),
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct BinaryPacket {
    payload: Vec<u8>,
    random_padding: Vec<u8>,
    mac: Vec<u8>,
}

impl BinaryPacket {
    /// Returns the payload bytes (type byte + message fields, without framing or padding).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Codec for BinaryPacket {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let padding_length = self.random_padding.len();
        let payload_length = self.payload.len();
        let packet_length = payload_length + padding_length + 1;
        (packet_length as u32).encode(bytes);
        (padding_length as u8).encode(bytes);
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.random_padding);
        bytes.extend_from_slice(&self.mac);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let packet_length = u32::read(reader)?;
        let padding_length = u8::read(reader)?;
        // Guard against underflow: on encrypted (e.g. AES-GCM) packets the bytes
        // we read as `padding_length` are really ciphertext and can exceed
        // `packet_length`. Treat such frames as unparseable rather than panicking.
        let payload_length = (packet_length as usize)
            .checked_sub(padding_length as usize)
            .and_then(|v| v.checked_sub(1))?;
        let payload = Vec::from(reader.take(payload_length)?);
        let random_padding = Vec::from(reader.take(padding_length as usize)?);
        let mac = Vec::from(reader.take(0_usize)?); // TODO: parse non-zero

        Some(BinaryPacket {
            payload,
            random_padding,
            mac,
        })
    }
}

#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct NameList {
    names: Vec<String>,
}

impl NameList {
    pub fn empty() -> NameList {
        Self { names: vec![] }
    }

    pub fn from_strs(names: &[&str]) -> NameList {
        Self {
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Codec for NameList {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let names = self.names.join(",");
        let names_bytes = names.as_bytes(); // ASCII is valid UTF-8
        (names_bytes.len() as u32).encode(bytes);
        bytes.extend_from_slice(names_bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let length = u32::read(reader)?;
        let names = if length > 0 {
            let names = std::str::from_utf8(reader.take(length as usize)?).ok()?;
            names.split(',').map(str::to_string).collect()
        } else {
            Vec::new()
        };
        Some(NameList { names })
    }
}

// ── SshBytes: u32-length-prefixed byte blob ──────────────────────────────────
//
// This is the standard SSH wire format for strings and opaque byte fields
// (RFC 4251 §5).  Using a named type rather than Vec<u8> lets the DY fuzzer
// extract SshBytes atoms from observed traffic and substitute them into any
// position expecting the same type, enabling cross-field and cross-session
// value reuse.

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct SshBytes(#[extractable_no_recursion] pub Vec<u8>);

impl SshBytes {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self(data.into())
    }
    pub fn empty() -> Self {
        Self(vec![])
    }
}

impl From<Vec<u8>> for SshBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for SshBytes {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

impl Codec for SshBytes {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.0);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let length = u32::read(reader)?;
        Some(SshBytes(Vec::from(reader.take(length as usize)?)))
    }
}

// Keep helpers for the raw-tail fields (method_data, request_data, channel_data)
// that are NOT length-prefixed.
fn encode_ssh_bytes(bytes_value: &[u8], bytes: &mut Vec<u8>) {
    (bytes_value.len() as u32).encode(bytes);
    bytes.extend_from_slice(bytes_value);
}

fn read_ssh_bytes(reader: &mut Reader) -> Option<Vec<u8>> {
    let length = u32::read(reader)?;
    Some(Vec::from(reader.take(length as usize)?))
}

macro_rules! declare_name_list (
  ($name:ident) => {
    #[derive(Debug, Clone, Comparable, PartialEq)]
    pub struct $name(pub NameList);

    impl puffin::codec::Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        NameList::encode(&self.0, bytes);
      }

      fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        Some($name(NameList::read(r)?))
      }
    }
  }
);

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub enum SshMessage {
    Disconnect(DisconnectMessage),
    Ignore(IgnoreMessage),
    Unimplemented(UnimplementedMessage),
    Debug(DebugMessage),
    ServiceRequest(ServiceRequestMessage),
    ServiceAccept(ServiceAcceptMessage),
    KexInit(KexInitMessage),
    KexEcdhInit(KexEcdhInitMessage),
    KexEcdhReply(KexEcdhReplyMessage),
    NewKeys,
    UserAuthRequest(UserAuthRequestMessage),
    UserAuthFailure(UserAuthFailureMessage),
    UserAuthSuccess,
    UserAuthBanner(UserAuthBannerMessage),
    GlobalRequest(GlobalRequestMessage),
    RequestSuccess(RequestSuccessMessage),
    RequestFailure,
    ChannelOpen(ChannelOpenMessage),
    ChannelOpenConfirmation(ChannelOpenConfirmationMessage),
    ChannelOpenFailure(ChannelOpenFailureMessage),
    ChannelWindowAdjust(ChannelWindowAdjustMessage),
    ChannelData(ChannelDataMessage),
    ChannelExtendedData(ChannelExtendedDataMessage),
    ChannelEof(ChannelEofMessage),
    ChannelClose(ChannelCloseMessage),
    ChannelRequest(ChannelRequestMessage),
    ChannelSuccess(ChannelSuccessMessage),
    ChannelFailure(ChannelFailureMessage),
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct DisconnectMessage {
    pub reason_code: u32,
    pub description: SshBytes,
    pub language_tag: SshBytes,
}

impl Codec for DisconnectMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.reason_code.encode(bytes);
        self.description.encode(bytes);
        self.language_tag.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            reason_code: u32::read(reader)?,
            description: SshBytes::read(reader)?,
            language_tag: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct IgnoreMessage {
    pub data: SshBytes,
}

impl Codec for IgnoreMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.data.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            data: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct UnimplementedMessage {
    pub packet_sequence_number: u32,
}

impl Codec for UnimplementedMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.packet_sequence_number.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            packet_sequence_number: u32::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct DebugMessage {
    pub always_display: bool,
    pub message: SshBytes,
    pub language_tag: SshBytes,
}

impl Codec for DebugMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.always_display as u8).encode(bytes);
        self.message.encode(bytes);
        self.language_tag.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            always_display: u8::read(reader)? != 0,
            message: SshBytes::read(reader)?,
            language_tag: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ServiceRequestMessage {
    pub service_name: SshBytes,
}

impl Codec for ServiceRequestMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.service_name.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            service_name: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ServiceAcceptMessage {
    pub service_name: SshBytes,
}

impl Codec for ServiceAcceptMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.service_name.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            service_name: SshBytes::read(reader)?,
        })
    }
}

declare_name_list!(KexAlgorithms);
declare_name_list!(SignatureSchemes);
declare_name_list!(EncryptionAlgorithms);
declare_name_list!(MacAlgorithms);
declare_name_list!(CompressionAlgorithms);

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct KexInitMessage {
    // The cookie is 16 random bytes; it differs on every run and between
    // implementations, so it must not contribute to differential comparison.
    #[comparable_ignore]
    pub cookie: [u8; 16],
    pub kex_algorithms: KexAlgorithms,
    pub server_host_key_algorithms: SignatureSchemes,
    pub encryption_algorithms_server_to_client: EncryptionAlgorithms,
    pub encryption_algorithms_client_to_server: EncryptionAlgorithms,
    pub mac_algorithms_client_to_server: MacAlgorithms,
    pub mac_algorithms_server_to_client: MacAlgorithms,
    pub compression_algorithms_client_to_server: CompressionAlgorithms,
    pub compression_algorithms_server_to_client: CompressionAlgorithms,
    pub languages_client_to_server: NameList,
    pub languages_server_to_client: NameList,
    pub first_kex_packet_follows: bool,
}

impl Codec for KexInitMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.cookie);

        self.kex_algorithms.encode(bytes);
        self.server_host_key_algorithms.encode(bytes);
        self.encryption_algorithms_server_to_client.encode(bytes);
        self.encryption_algorithms_client_to_server.encode(bytes);
        self.mac_algorithms_client_to_server.encode(bytes);
        self.mac_algorithms_server_to_client.encode(bytes);
        self.compression_algorithms_client_to_server.encode(bytes);
        self.compression_algorithms_server_to_client.encode(bytes);
        self.languages_client_to_server.encode(bytes);
        self.languages_server_to_client.encode(bytes);

        (self.first_kex_packet_follows as u8).encode(bytes);
        0u32.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut cookie = [0; 16];
        cookie[..].clone_from_slice(reader.take(16)?);
        let message = KexInitMessage {
            cookie,
            kex_algorithms: KexAlgorithms::read(reader)?,
            server_host_key_algorithms: SignatureSchemes::read(reader)?,
            encryption_algorithms_server_to_client: EncryptionAlgorithms::read(reader)?,
            encryption_algorithms_client_to_server: EncryptionAlgorithms::read(reader)?,
            mac_algorithms_client_to_server: MacAlgorithms::read(reader)?,
            mac_algorithms_server_to_client: MacAlgorithms::read(reader)?,
            compression_algorithms_client_to_server: CompressionAlgorithms::read(reader)?,
            compression_algorithms_server_to_client: CompressionAlgorithms::read(reader)?,
            languages_client_to_server: NameList::read(reader)?,
            languages_server_to_client: NameList::read(reader)?,
            first_kex_packet_follows: u8::read(reader)? != 0,
        };

        u32::read(reader)?; // read reserved
        Some(message)
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct KexEcdhInitMessage {
    // Client ephemeral X25519 key: fresh random per run → ignore in DDYF.
    #[comparable_ignore]
    pub ephemeral_public_key: SshBytes,
}

impl Codec for KexEcdhInitMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ephemeral_public_key.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(KexEcdhInitMessage {
            ephemeral_public_key: SshBytes::read(reader)?,
        })
    }
}

// ── SshPublicKey / SshSignature ───────────────────────────────────────────────
//
// The KEX ECDH reply carries two outer SSH strings that each contain an inner
// structured blob: <algo-name-string><key-or-sig-bytes-string>.  Giving these
// their own types lets the DY fuzzer extract, substitute and compose the
// algorithm name and the raw material independently.

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct SshPublicKey {
    pub algorithm: SshBytes,
    pub key_data: SshBytes,
}

impl Codec for SshPublicKey {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut inner = Vec::new();
        self.algorithm.encode(&mut inner);
        // For RSA ("ssh-rsa") and other multi-field key types, key_data
        // contains the raw remaining inner bytes ([mpint e][mpint n] for RSA),
        // NOT wrapped in an additional SSH string.  We detect this by checking
        // if the key_data starts with what looks like an mpint (i.e., the field
        // does NOT look like a nested SSH string holding the entire remaining
        // blob).  The heuristic: if algorithm is "ssh-rsa", write key_data raw.
        if self.algorithm.0 == b"ssh-rsa" {
            inner.extend_from_slice(&self.key_data.0);
        } else {
            self.key_data.encode(&mut inner);
        }
        (inner.len() as u32).encode(bytes);
        bytes.extend_from_slice(&inner);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let len = u32::read(reader)? as usize;
        let inner = reader.take(len)?;
        let mut r = Reader::init(inner);
        let algorithm = SshBytes::read(&mut r)?;
        // For RSA ("ssh-rsa"): the remaining bytes are raw mpints [e][n], not
        // wrapped in a single SSH string. We store them as-is.
        // For all other key types (ed25519, ecdsa, etc.): the next field is
        // a single SSH string which we read normally.
        let key_data = if algorithm.0 == b"ssh-rsa" {
            SshBytes::new(r.rest().to_vec())
        } else {
            SshBytes::read(&mut r)?
        };
        Some(SshPublicKey { algorithm, key_data })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct SshSignature {
    pub algorithm: SshBytes,
    pub signature_data: SshBytes,
}

impl Codec for SshSignature {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let mut inner = Vec::new();
        self.algorithm.encode(&mut inner);
        self.signature_data.encode(&mut inner);
        (inner.len() as u32).encode(bytes);
        bytes.extend_from_slice(&inner);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let len = u32::read(reader)? as usize;
        let inner = reader.take(len)?;
        let mut r = Reader::init(inner);
        Some(SshSignature {
            algorithm: SshBytes::read(&mut r)?,
            signature_data: SshBytes::read(&mut r)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct KexEcdhReplyMessage {
    // Persistent host key: deterministic (same embedded key across PUTs), so a
    // difference here would be a genuine finding — keep it in the comparison.
    pub public_host_key: SshPublicKey,
    // Server ephemeral X25519 key: fresh random per run → ignore in DDYF.
    #[comparable_ignore]
    pub ephemeral_public_key: SshBytes,
    // Signature over the exchange hash (which includes the random ephemeral
    // key) → differs every run → ignore in DDYF.
    #[comparable_ignore]
    pub signature: SshSignature,
}

impl Codec for KexEcdhReplyMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public_host_key.encode(bytes);
        self.ephemeral_public_key.encode(bytes);
        self.signature.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(KexEcdhReplyMessage {
            public_host_key: SshPublicKey::read(reader)?,
            ephemeral_public_key: SshBytes::read(reader)?,
            signature: SshSignature::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct UserAuthRequestMessage {
    pub user_name: SshBytes,
    pub service_name: SshBytes,
    pub method_name: SshBytes,
    // method_data is NOT a standard ssh-string: it is the raw remainder of the
    // packet whose format depends on the auth method (RFC 4252).
    #[extractable_no_recursion]
    pub method_data: Vec<u8>,
}

impl Codec for UserAuthRequestMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.user_name.encode(bytes);
        self.service_name.encode(bytes);
        self.method_name.encode(bytes);
        bytes.extend_from_slice(&self.method_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            user_name: SshBytes::read(reader)?,
            service_name: SshBytes::read(reader)?,
            method_name: SshBytes::read(reader)?,
            method_data: Vec::from(reader.rest()),
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct UserAuthFailureMessage {
    pub authentications_that_can_continue: NameList,
    pub partial_success: bool,
}

impl Codec for UserAuthFailureMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.authentications_that_can_continue.encode(bytes);
        (self.partial_success as u8).encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            authentications_that_can_continue: NameList::read(reader)?,
            partial_success: u8::read(reader)? != 0,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct UserAuthBannerMessage {
    pub message: SshBytes,
    pub language_tag: SshBytes,
}

impl Codec for UserAuthBannerMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.message.encode(bytes);
        self.language_tag.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            message: SshBytes::read(reader)?,
            language_tag: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct GlobalRequestMessage {
    pub request_name: SshBytes,
    pub want_reply: bool,
    #[extractable_no_recursion]
    pub request_data: Vec<u8>,
}

impl Codec for GlobalRequestMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.request_name.encode(bytes);
        (self.want_reply as u8).encode(bytes);
        bytes.extend_from_slice(&self.request_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            request_name: SshBytes::read(reader)?,
            want_reply: u8::read(reader)? != 0,
            request_data: Vec::from(reader.rest()),
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct RequestSuccessMessage {
    #[extractable_no_recursion]
    pub response_data: Vec<u8>,
}

impl Codec for RequestSuccessMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.response_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let response_data = Vec::from(reader.rest());
        Some(Self { response_data })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelOpenMessage {
    pub channel_type: SshBytes,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
    #[extractable_no_recursion]
    pub channel_data: Vec<u8>,
}

impl Codec for ChannelOpenMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.channel_type.encode(bytes);
        self.sender_channel.encode(bytes);
        self.initial_window_size.encode(bytes);
        self.maximum_packet_size.encode(bytes);
        bytes.extend_from_slice(&self.channel_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            channel_type: SshBytes::read(reader)?,
            sender_channel: u32::read(reader)?,
            initial_window_size: u32::read(reader)?,
            maximum_packet_size: u32::read(reader)?,
            channel_data: Vec::from(reader.rest()),
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelOpenConfirmationMessage {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
    #[extractable_no_recursion]
    pub channel_data: Vec<u8>,
}

impl Codec for ChannelOpenConfirmationMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.sender_channel.encode(bytes);
        self.initial_window_size.encode(bytes);
        self.maximum_packet_size.encode(bytes);
        bytes.extend_from_slice(&self.channel_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let recipient_channel = u32::read(reader)?;
        let sender_channel = u32::read(reader)?;
        let initial_window_size = u32::read(reader)?;
        let maximum_packet_size = u32::read(reader)?;
        let channel_data = Vec::from(reader.rest());
        Some(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            channel_data,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelOpenFailureMessage {
    pub recipient_channel: u32,
    pub reason_code: u32,
    pub description: SshBytes,
    pub language_tag: SshBytes,
}

impl Codec for ChannelOpenFailureMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.reason_code.encode(bytes);
        self.description.encode(bytes);
        self.language_tag.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
            reason_code: u32::read(reader)?,
            description: SshBytes::read(reader)?,
            language_tag: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelWindowAdjustMessage {
    pub recipient_channel: u32,
    pub bytes_to_add: u32,
}

impl Codec for ChannelWindowAdjustMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.bytes_to_add.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
            bytes_to_add: u32::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelDataMessage {
    pub recipient_channel: u32,
    pub data: SshBytes,
}

impl Codec for ChannelDataMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.data.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
            data: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelExtendedDataMessage {
    pub recipient_channel: u32,
    pub data_type_code: u32,
    pub data: SshBytes,
}

impl Codec for ChannelExtendedDataMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.data_type_code.encode(bytes);
        self.data.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
            data_type_code: u32::read(reader)?,
            data: SshBytes::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelEofMessage {
    pub recipient_channel: u32,
}

impl Codec for ChannelEofMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelCloseMessage {
    pub recipient_channel: u32,
}

impl Codec for ChannelCloseMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelRequestMessage {
    pub recipient_channel: u32,
    pub request_type: SshBytes,
    pub want_reply: bool,
    #[extractable_no_recursion]
    pub request_data: Vec<u8>,
}

impl Codec for ChannelRequestMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
        self.request_type.encode(bytes);
        (self.want_reply as u8).encode(bytes);
        bytes.extend_from_slice(&self.request_data);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
            request_type: SshBytes::read(reader)?,
            want_reply: u8::read(reader)? != 0,
            request_data: Vec::from(reader.rest()),
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelSuccessMessage {
    pub recipient_channel: u32,
}

impl Codec for ChannelSuccessMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
        })
    }
}

#[derive(Clone, Debug, Extractable, Comparable, PartialEq)]
#[extractable(SshProtocolTypes)]
pub struct ChannelFailureMessage {
    pub recipient_channel: u32,
}

impl Codec for ChannelFailureMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.recipient_channel.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            recipient_channel: u32::read(reader)?,
        })
    }
}

impl Codec for SshMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            SshMessage::Disconnect(inner) => {
                1u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::Ignore(inner) => {
                2u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::Unimplemented(inner) => {
                3u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::Debug(inner) => {
                4u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ServiceRequest(inner) => {
                5u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ServiceAccept(inner) => {
                6u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::KexInit(inner) => {
                20u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::NewKeys => {
                21u8.encode(bytes);
            }
            SshMessage::KexEcdhInit(inner) => {
                30u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::KexEcdhReply(inner) => {
                31u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::UserAuthRequest(inner) => {
                50u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::UserAuthFailure(inner) => {
                51u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::UserAuthSuccess => {
                52u8.encode(bytes);
            }
            SshMessage::UserAuthBanner(inner) => {
                53u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::GlobalRequest(inner) => {
                80u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::RequestSuccess(inner) => {
                81u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::RequestFailure => {
                82u8.encode(bytes);
            }
            SshMessage::ChannelOpen(inner) => {
                90u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelOpenConfirmation(inner) => {
                91u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelOpenFailure(inner) => {
                92u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelWindowAdjust(inner) => {
                93u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelData(inner) => {
                94u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelExtendedData(inner) => {
                95u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelEof(inner) => {
                96u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelClose(inner) => {
                97u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelRequest(inner) => {
                98u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelSuccess(inner) => {
                99u8.encode(bytes);
                inner.encode(bytes);
            }
            SshMessage::ChannelFailure(inner) => {
                100u8.encode(bytes);
                inner.encode(bytes);
            }
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let typ = u8::read(reader)?;

        match typ {
            1u8 => Some(SshMessage::Disconnect(DisconnectMessage::read(reader)?)),
            2u8 => Some(SshMessage::Ignore(IgnoreMessage::read(reader)?)),
            3u8 => Some(SshMessage::Unimplemented(UnimplementedMessage::read(
                reader,
            )?)),
            4u8 => Some(SshMessage::Debug(DebugMessage::read(reader)?)),
            5u8 => Some(SshMessage::ServiceRequest(ServiceRequestMessage::read(
                reader,
            )?)),
            6u8 => Some(SshMessage::ServiceAccept(ServiceAcceptMessage::read(
                reader,
            )?)),
            20u8 => Some(SshMessage::KexInit(KexInitMessage::read(reader)?)),
            21u8 => Some(SshMessage::NewKeys),
            30u8 => Some(SshMessage::KexEcdhInit(KexEcdhInitMessage::read(reader)?)),
            31u8 => Some(SshMessage::KexEcdhReply(KexEcdhReplyMessage::read(reader)?)),
            50u8 => Some(SshMessage::UserAuthRequest(UserAuthRequestMessage::read(
                reader,
            )?)),
            51u8 => Some(SshMessage::UserAuthFailure(UserAuthFailureMessage::read(
                reader,
            )?)),
            52u8 => Some(SshMessage::UserAuthSuccess),
            53u8 => Some(SshMessage::UserAuthBanner(UserAuthBannerMessage::read(
                reader,
            )?)),
            80u8 => Some(SshMessage::GlobalRequest(GlobalRequestMessage::read(
                reader,
            )?)),
            81u8 => Some(SshMessage::RequestSuccess(RequestSuccessMessage::read(
                reader,
            )?)),
            82u8 => Some(SshMessage::RequestFailure),
            90u8 => Some(SshMessage::ChannelOpen(ChannelOpenMessage::read(reader)?)),
            91u8 => Some(SshMessage::ChannelOpenConfirmation(
                ChannelOpenConfirmationMessage::read(reader)?,
            )),
            92u8 => Some(SshMessage::ChannelOpenFailure(
                ChannelOpenFailureMessage::read(reader)?,
            )),
            93u8 => Some(SshMessage::ChannelWindowAdjust(
                ChannelWindowAdjustMessage::read(reader)?,
            )),
            94u8 => Some(SshMessage::ChannelData(ChannelDataMessage::read(reader)?)),
            95u8 => Some(SshMessage::ChannelExtendedData(
                ChannelExtendedDataMessage::read(reader)?,
            )),
            96u8 => Some(SshMessage::ChannelEof(ChannelEofMessage::read(reader)?)),
            97u8 => Some(SshMessage::ChannelClose(ChannelCloseMessage::read(reader)?)),
            98u8 => Some(SshMessage::ChannelRequest(ChannelRequestMessage::read(
                reader,
            )?)),
            99u8 => Some(SshMessage::ChannelSuccess(ChannelSuccessMessage::read(
                reader,
            )?)),
            100u8 => Some(SshMessage::ChannelFailure(ChannelFailureMessage::read(
                reader,
            )?)),
            _ => None,
        }
    }
}

impl TryFrom<&BinaryPacket> for SshMessage {
    type Error = String;

    fn try_from(packet: &BinaryPacket) -> Result<Self, Self::Error> {
        let mut reader = Reader::init(&packet.payload);
        SshMessage::read(&mut reader).ok_or_else(|| "Can not parse payload".to_string())
    }
}

impl ProtocolMessage<SshProtocolTypes, RawSshMessage> for SshMessage {
    fn create_opaque(&self) -> RawSshMessage {
        let mut payload = Vec::new();
        self.encode(&mut payload);

        let random_padding = Vec::from([0; 7]); // todo: calc proper padding

        RawSshMessage::Packet(BinaryPacket {
            payload,
            random_padding,
            mac: vec![], // todo: calc proper mac
        })
    }

    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self)
    }
}

impl TryFrom<RawSshMessage> for SshMessage {
    type Error = ();

    fn try_from(value: RawSshMessage) -> Result<Self, Self::Error> {
        let message = if let RawSshMessage::Packet(packet) = &value {
            match SshMessage::try_from(packet) {
                Ok(message) => Some(message),
                Err(_) => None,
            }
        } else {
            None
        };
        message.ok_or(())
    }
}

impl OpaqueProtocolMessage<SshProtocolTypes> for RawSshMessage {
    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self)
    }
}

impl Codec for RawSshMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            RawSshMessage::Banner(banner) => {
                bytes.extend_from_slice(banner.as_bytes());
            }
            RawSshMessage::Packet(packet) => packet.encode(bytes),
            RawSshMessage::OnWire(data) => bytes.extend_from_slice(&data.0),
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        // Detect any SSH version banner: starts with "SSH-" and ends with "\n"
        // We peek up to 256 bytes to find the newline, but handle shorter buffers too.
        const MAX_BANNER: usize = 256;
        let peek_len = MAX_BANNER.min(reader.left());
        if peek_len < 4 {
            // Not enough data to determine banner vs packet
            return Some(RawSshMessage::Packet(BinaryPacket::read(reader)?));
        }
        let buf = reader.peek(peek_len)?;

        // Check if data starts with "SSH-"
        if &buf[..4] != b"SSH-" {
            return Some(RawSshMessage::Packet(BinaryPacket::read(reader)?));
        }

        // Find the \n that terminates the banner
        let banner_end = buf.iter().position(|&b| b == b'\n').map(|i| i + 1);

        if let Some(end) = banner_end {
            let banner_bytes = reader.take(end)?;
            let banner = String::from_utf8_lossy(banner_bytes).into_owned();
            Some(RawSshMessage::Banner(banner))
        } else {
            // Banner line not complete yet (no newline found in the buffer)
            // Treat as partial — return None so the deframer waits for more data.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use puffin::codec::Codec;

    use super::*;

    fn nl(items: &[&str]) -> NameList {
        NameList {
            names: items.iter().map(|x| x.to_string()).collect(),
        }
    }

    /// Verify `try_read_bytes` reconstructs each type from its encoded bytes
    /// and that the dynamically-read value re-encodes to the same bytes.
    /// This is the property bit-level mutations (`--with-bit`) rely on.
    #[test]
    fn test_try_read_bytes_roundtrip() {
        // (encoded bytes, TypeId of the source type)
        let cases: Vec<(Vec<u8>, std::any::TypeId)> = vec![
            {
                let v = SshBytes::new(b"hello");
                (v.get_encoding(), std::any::TypeId::of::<SshBytes>())
            },
            {
                let v: u32 = 0xdead_beef;
                (v.get_encoding(), std::any::TypeId::of::<u32>())
            },
            {
                let v: u8 = 42;
                (v.get_encoding(), std::any::TypeId::of::<u8>())
            },
            {
                let v: Vec<u8> = vec![1, 2, 3, 4];
                (v.get_encoding(), std::any::TypeId::of::<Vec<u8>>())
            },
            {
                let v = SshMessage::NewKeys;
                (v.get_encoding(), std::any::TypeId::of::<SshMessage>())
            },
            {
                let v = ChannelEofMessage {
                    recipient_channel: 7,
                };
                (v.get_encoding(), std::any::TypeId::of::<ChannelEofMessage>())
            },
            {
                let v = KexAlgorithms(nl(&["curve25519-sha256"]));
                (v.get_encoding(), std::any::TypeId::of::<KexAlgorithms>())
            },
        ];

        for (bytes, ty) in cases {
            let read = try_read_bytes(&bytes, ty)
                .unwrap_or_else(|e| panic!("try_read_bytes failed for {ty:?}: {e}"));
            // Re-encode the dynamically read value and confirm it matches.
            let mut reencoded = Vec::new();
            read.encode(&mut reencoded);
            assert_eq!(reencoded, bytes, "re-encode mismatch for {ty:?}");
        }
    }

    #[test]
    fn test_all_message_codecs_roundtrip() {
        let samples = vec![
            SshMessage::Disconnect(DisconnectMessage {
                reason_code: 1,
                description: SshBytes::new(b"closed"),
                language_tag: SshBytes::new(b"en"),
            }),
            SshMessage::Ignore(IgnoreMessage {
                data: SshBytes::new(b"noop"),
            }),
            SshMessage::Unimplemented(UnimplementedMessage {
                packet_sequence_number: 42,
            }),
            SshMessage::Debug(DebugMessage {
                always_display: true,
                message: SshBytes::new(b"dbg"),
                language_tag: SshBytes::new(b"en"),
            }),
            SshMessage::ServiceRequest(ServiceRequestMessage {
                service_name: SshBytes::new(b"ssh-userauth"),
            }),
            SshMessage::ServiceAccept(ServiceAcceptMessage {
                service_name: SshBytes::new(b"ssh-userauth"),
            }),
            SshMessage::KexInit(KexInitMessage {
                cookie: [7u8; 16],
                kex_algorithms: KexAlgorithms(nl(&["curve25519-sha256"])),
                server_host_key_algorithms: SignatureSchemes(nl(&["ssh-ed25519"])),
                encryption_algorithms_server_to_client: EncryptionAlgorithms(nl(&[
                    "chacha20-poly1305@openssh.com",
                ])),
                encryption_algorithms_client_to_server: EncryptionAlgorithms(nl(&[
                    "chacha20-poly1305@openssh.com",
                ])),
                mac_algorithms_client_to_server: MacAlgorithms(nl(&["hmac-sha2-256"])),
                mac_algorithms_server_to_client: MacAlgorithms(nl(&["hmac-sha2-256"])),
                compression_algorithms_client_to_server: CompressionAlgorithms(nl(&["none"])),
                compression_algorithms_server_to_client: CompressionAlgorithms(nl(&["none"])),
                languages_client_to_server: nl(&[]),
                languages_server_to_client: nl(&[]),
                first_kex_packet_follows: false,
            }),
            SshMessage::NewKeys,
            SshMessage::KexEcdhInit(KexEcdhInitMessage {
                ephemeral_public_key: SshBytes::new(vec![1, 2, 3]),
            }),
            SshMessage::KexEcdhReply(KexEcdhReplyMessage {
                public_host_key: SshPublicKey {
                    algorithm: SshBytes::new(b"ssh-ed25519".as_ref()),
                    key_data: SshBytes::new(vec![1u8; 32]),
                },
                ephemeral_public_key: SshBytes::new(vec![2u8; 32]),
                signature: SshSignature {
                    algorithm: SshBytes::new(b"ssh-ed25519".as_ref()),
                    signature_data: SshBytes::new(vec![3u8; 64]),
                },
            }),
            SshMessage::UserAuthRequest(UserAuthRequestMessage {
                user_name: SshBytes::new(b"fuzzer".as_ref()),
                service_name: SshBytes::new(b"ssh-connection".as_ref()),
                method_name: SshBytes::new(b"password".as_ref()),
                method_data: vec![0, 0, 0],
            }),
            SshMessage::UserAuthFailure(UserAuthFailureMessage {
                authentications_that_can_continue: nl(&["password"]),
                partial_success: false,
            }),
            SshMessage::UserAuthSuccess,
            SshMessage::UserAuthBanner(UserAuthBannerMessage {
                message: SshBytes::new(b"banner".as_ref()),
                language_tag: SshBytes::new(b"en".as_ref()),
            }),
            SshMessage::GlobalRequest(GlobalRequestMessage {
                request_name: SshBytes::new(b"tcpip-forward".as_ref()),
                want_reply: true,
                request_data: vec![9, 9],
            }),
            SshMessage::RequestSuccess(RequestSuccessMessage {
                response_data: vec![8, 8],
            }),
            SshMessage::RequestFailure,
            SshMessage::ChannelOpen(ChannelOpenMessage {
                channel_type: SshBytes::new(b"session".as_ref()),
                sender_channel: 1,
                initial_window_size: 1024,
                maximum_packet_size: 32768,
                channel_data: vec![],
            }),
            SshMessage::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
                recipient_channel: 1,
                sender_channel: 2,
                initial_window_size: 1024,
                maximum_packet_size: 32768,
                channel_data: vec![],
            }),
            SshMessage::ChannelOpenFailure(ChannelOpenFailureMessage {
                recipient_channel: 1,
                reason_code: 2,
                description: SshBytes::new(b"failed".as_ref()),
                language_tag: SshBytes::new(b"en".as_ref()),
            }),
            SshMessage::ChannelWindowAdjust(ChannelWindowAdjustMessage {
                recipient_channel: 1,
                bytes_to_add: 128,
            }),
            SshMessage::ChannelData(ChannelDataMessage {
                recipient_channel: 1,
                data: SshBytes::new(b"payload".as_ref()),
            }),
            SshMessage::ChannelExtendedData(ChannelExtendedDataMessage {
                recipient_channel: 1,
                data_type_code: 1,
                data: SshBytes::new(b"stderr".as_ref()),
            }),
            SshMessage::ChannelEof(ChannelEofMessage {
                recipient_channel: 1,
            }),
            SshMessage::ChannelClose(ChannelCloseMessage {
                recipient_channel: 1,
            }),
            SshMessage::ChannelRequest(ChannelRequestMessage {
                recipient_channel: 1,
                request_type: SshBytes::new(b"exec".as_ref()),
                want_reply: true,
                request_data: b"id".to_vec(),
            }),
            SshMessage::ChannelSuccess(ChannelSuccessMessage {
                recipient_channel: 1,
            }),
            SshMessage::ChannelFailure(ChannelFailureMessage {
                recipient_channel: 1,
            }),
        ];

        for sample in samples {
            let encoded = sample.get_encoding();
            let decoded = SshMessage::read_bytes(&encoded).expect("decode sample");
            assert_eq!(decoded, sample);
        }
    }
}

atom_extract_knowledge!(SshProtocolTypes, String);
atom_extract_knowledge!(SshProtocolTypes, OnWireData);
// SshBytes derives Extractable directly — no atom_extract_knowledge! needed.
atom_extract_knowledge!(SshProtocolTypes, u8);
atom_extract_knowledge!(SshProtocolTypes, u32);
atom_extract_knowledge!(SshProtocolTypes, u64);
atom_extract_knowledge!(SshProtocolTypes, NameList);
atom_extract_knowledge!(SshProtocolTypes, CompressionAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, EncryptionAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, KexAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, [u8; 16]);
atom_extract_knowledge!(SshProtocolTypes, MacAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, SignatureSchemes);
dummy_extract_knowledge!(SshProtocolTypes, bool);

// ── try_read_bytes: read a bitstring back into a typed EvaluatedTerm ──────────
//
// Required for bit-level mutations (`--with-bit`): the bit-level mutator
// evaluates a sub-term to bytes, mutates those bytes, then must re-read them as
// the sub-term's original type.  Since the target type is only known at runtime
// (via `TypeId`), we dispatch over every type that can appear as a term in the
// SSH signature.  Mirrors tlspuffin's `try_read_bytes`.

use std::any::TypeId;

use puffin::protocol::EvaluatedTerm;

use crate::protocol::{RawSshMessageFlight, SshMessageFlight};

macro_rules! try_read {
    ($bitstring:expr, $ti:expr, $T:ty, $($Ts:ty),+) => {{
        if $ti == TypeId::of::<$T>() {
            <$T>::read_bytes($bitstring)
                .ok_or_else(|| Error::Term(format!(
                    "[try_read_bytes] Failed to read type {:?} from bitstring {:?}",
                    core::any::type_name::<$T>(), $bitstring
                )))
                .map(|v| Box::new(v) as Box<dyn EvaluatedTerm<SshProtocolTypes>>)
        } else {
            try_read!($bitstring, $ti, $($Ts),+)
        }
    }};
    ($bitstring:expr, $ti:expr, $T:ty) => {{
        if $ti == TypeId::of::<$T>() {
            <$T>::read_bytes($bitstring)
                .ok_or_else(|| Error::Term(format!(
                    "[try_read_bytes] Failed to read type {:?} from bitstring {:?}",
                    core::any::type_name::<$T>(), $bitstring
                )))
                .map(|v| Box::new(v) as Box<dyn EvaluatedTerm<SshProtocolTypes>>)
        } else {
            Err(Error::TermBug(format!(
                "[try_read_bytes] No SSH type matches TypeId {:?} for bitstring {:?}",
                $ti, $bitstring
            )))
        }
    }};
}

/// Read a `bitstring` into the `EvaluatedTerm` whose runtime type matches `ty`.
pub fn try_read_bytes(
    bitstring: &[u8],
    ty: TypeId,
) -> Result<Box<dyn EvaluatedTerm<SshProtocolTypes>>, Error> {
    try_read!(
        bitstring,
        ty,
        // Top-level messages / flights
        SshMessage,
        RawSshMessage,
        BinaryPacket,
        OnWireData,
        SshMessageFlight,
        RawSshMessageFlight,
        // Structured byte / key types
        SshBytes,
        SshPublicKey,
        SshSignature,
        // Name lists
        NameList,
        KexAlgorithms,
        SignatureSchemes,
        EncryptionAlgorithms,
        MacAlgorithms,
        CompressionAlgorithms,
        // Per-message payloads
        DisconnectMessage,
        IgnoreMessage,
        UnimplementedMessage,
        DebugMessage,
        ServiceRequestMessage,
        ServiceAcceptMessage,
        KexInitMessage,
        KexEcdhInitMessage,
        KexEcdhReplyMessage,
        UserAuthRequestMessage,
        UserAuthFailureMessage,
        UserAuthBannerMessage,
        GlobalRequestMessage,
        RequestSuccessMessage,
        ChannelOpenMessage,
        ChannelOpenConfirmationMessage,
        ChannelOpenFailureMessage,
        ChannelWindowAdjustMessage,
        ChannelDataMessage,
        ChannelExtendedDataMessage,
        ChannelEofMessage,
        ChannelCloseMessage,
        ChannelRequestMessage,
        ChannelSuccessMessage,
        ChannelFailureMessage,
        // Atoms
        String,
        Vec<u8>,
        u64,
        u32,
        u8,
        [u8; 16],
        bool
    )
}
