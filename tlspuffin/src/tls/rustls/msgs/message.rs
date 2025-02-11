use std::any::TypeId;

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::codec;
use puffin::codec::{Codec, Reader, VecCodecWoSize};
use puffin::error::Error::Term;
use puffin::protocol::{EvaluatedTerm, ProtocolMessage};

use crate::protocol::{MessageFlight, OpaqueMessageFlight, TLSProtocolTypes};
use crate::tls::rustls::error::Error;
use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key::Certificate;
use crate::tls::rustls::msgs::alert::AlertMessagePayload;
use crate::tls::rustls::msgs::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use crate::tls::rustls::msgs::ccs::ChangeCipherSpecPayload;
use crate::tls::rustls::msgs::enums::ContentType::ApplicationData;
use crate::tls::rustls::msgs::enums::ProtocolVersion::TLSv1_3;
use crate::tls::rustls::msgs::enums::{
    AlertDescription, AlertLevel, CipherSuite, Compression, ContentType, HandshakeType, NamedGroup,
    ProtocolVersion, SignatureScheme,
};
use crate::tls::rustls::msgs::handshake::{
    CertReqExtension, CertificateEntries, CertificateEntry, CertificateExtension, CipherSuites,
    ClientExtension, ClientExtensions, Compressions, HandshakeMessagePayload, HelloRetryExtension,
    HelloRetryExtensions, NewSessionTicketExtension, NewSessionTicketExtensions,
    PresharedKeyIdentity, Random, ServerExtension, ServerExtensions, SessionID, VecU16OfPayloadU16,
    VecU16OfPayloadU8,
};
use crate::tls::rustls::msgs::heartbeat::HeartbeatPayload;

#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    // this type is for TLS 1.2 encrypted handshake messages
    TLS12EncryptedHandshake(Payload),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload),
    Heartbeat(HeartbeatPayload),
}

impl codec::CodecP for MessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        MessagePayload::encode(self, bytes);
    }

    fn read(&mut self, _: &mut Reader) -> Result<(), puffin::error::Error> {
        Err(puffin::error::Error::Term(format!(
            "Failed to read for type {:?}",
            std::any::type_name::<MessagePayload>()
        )))
    }
}

impl PartialEq for MessagePayload {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MessagePayload::Alert(_), MessagePayload::Alert(_)) => true,
            (MessagePayload::Handshake(_), MessagePayload::Handshake(_)) => true,
            (
                MessagePayload::TLS12EncryptedHandshake(_),
                MessagePayload::TLS12EncryptedHandshake(_),
            ) => true,
            (MessagePayload::ChangeCipherSpec(_), MessagePayload::ChangeCipherSpec(_)) => true,
            (MessagePayload::ApplicationData(_), MessagePayload::ApplicationData(_)) => true,
            (MessagePayload::Heartbeat(_), MessagePayload::Heartbeat(_)) => true,
            (_, _) => false,
        }
    }
}

impl MessagePayload {
    pub fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::Alert(ref x) => x.encode(bytes),
            Self::Handshake(ref x) => x.encode(bytes),
            Self::TLS12EncryptedHandshake(ref x) => x.encode(bytes),
            Self::ChangeCipherSpec(ref x) => x.encode(bytes),
            Self::ApplicationData(ref x) => x.encode(bytes),
            Self::Heartbeat(ref x) => x.encode(bytes),
        }
    }

    pub fn new(typ: ContentType, vers: ProtocolVersion, payload: Payload) -> Result<Self, Error> {
        let fallback_payload = payload.clone();
        let mut r = Reader::init(&payload.0);
        let parsed = match typ {
            ContentType::ApplicationData => return Ok(Self::ApplicationData(payload)),
            ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
            ContentType::Handshake => {
                HandshakeMessagePayload::read_version(&mut r, vers)
                    .map(MessagePayload::Handshake)
                    // this type is for TLS 1.2 encrypted handshake messages
                    .or(Some(MessagePayload::TLS12EncryptedHandshake(
                        fallback_payload,
                    )))
            }
            ContentType::ChangeCipherSpec => {
                ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
            }
            ContentType::Heartbeat => HeartbeatPayload::read(&mut r).map(MessagePayload::Heartbeat),
            _ => None,
        };

        parsed.ok_or(Error::corrupt_message(typ))
        /*        parsed
        .filter(|_| !r.any_left())
        .ok_or_else(|| Error::corrupt_message(typ))*/
    }

    /// Extract multiple messages payloads from one ApplicationData message
    pub fn multiple_new(
        typ: ContentType,
        vers: ProtocolVersion,
        payload: Payload,
    ) -> Result<Vec<Self>, Error> {
        let fallback_payload = &payload;
        let mut r = Reader::init(&payload.0);
        let mut parsed: Vec<Self> = vec![];
        while r.any_left() {
            let parsed_msg = match typ {
                ContentType::ApplicationData => Some(Self::ApplicationData(payload.clone())),
                ContentType::Alert => AlertMessagePayload::read(&mut r).map(MessagePayload::Alert),
                ContentType::Handshake => {
                    HandshakeMessagePayload::read_version(&mut r, vers)
                        .map(MessagePayload::Handshake)
                        // this type is for TLS 1.2 encrypted handshake messages
                        .or(Some(MessagePayload::TLS12EncryptedHandshake(
                            fallback_payload.clone(),
                        )))
                }
                ContentType::ChangeCipherSpec => {
                    ChangeCipherSpecPayload::read(&mut r).map(MessagePayload::ChangeCipherSpec)
                }
                ContentType::Heartbeat => {
                    HeartbeatPayload::read(&mut r).map(MessagePayload::Heartbeat)
                }
                _ => None,
            };
            if let Some(msg) = parsed_msg {
                parsed.push(msg);
            }
        }

        Ok(parsed)
    }

    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Alert(_) => ContentType::Alert,
            Self::Handshake(_) => ContentType::Handshake,
            Self::TLS12EncryptedHandshake(_) => ContentType::Handshake,
            Self::ChangeCipherSpec(_) => ContentType::ChangeCipherSpec,
            Self::ApplicationData(_) => ContentType::ApplicationData,
            Self::Heartbeat(_) => ContentType::Heartbeat,
        }
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type owns all memory for its interior parts. It is used to read/write from/to I/O
/// buffers as well as for fragmenting, joining and encryption/decryption. It can be converted
/// into a `Message` by decoding the payload.
#[derive(Debug, Clone, Extractable, Comparable, PartialEq)]
#[extractable(TLSProtocolTypes)]
pub struct OpaqueMessage {
    #[extractable_ignore]
    #[comparable_ignore]
    pub typ: ContentType,
    #[extractable_ignore]
    #[comparable_ignore]
    pub version: ProtocolVersion,
    #[extractable_ignore]
    #[comparable_ignore]
    pub payload: Payload,
}

impl codec::VecCodecWoSize for OpaqueMessage {}

impl Codec for OpaqueMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.version.encode(bytes);
        (self.payload.0.len() as u16).encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Self::read(reader).ok()
    }
}

impl OpaqueMessage {
    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;
    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;
    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;

    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        #[cfg(not(feature = "enable-guards"))]
        let typ = ContentType::read(r).unwrap_or(ApplicationData);
        #[cfg(not(feature = "enable-guards"))]
        let version = ProtocolVersion::read(r).unwrap_or(TLSv1_3);

        #[cfg(feature = "enable-guards")]
        let typ = ContentType::read(r).ok_or(MessageError::TooShortForHeader)?;
        #[cfg(feature = "enable-guards")]
        let version = ProtocolVersion::read(r).ok_or(MessageError::TooShortForHeader)?;

        let len = u16::read(r).ok_or(MessageError::TooShortForHeader)?;

        #[cfg(feature = "enable-guards")]
        // Reject undersize messages
        //  implemented per section 5.1 of RFC8446 (TLSv1.3)
        //              per section 6.2.1 of RFC5246 (TLSv1.2)
        if typ != ContentType::ApplicationData && len == 0 {
            return Err(MessageError::IllegalLength);
        }

        #[cfg(feature = "enable-guards")]
        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        #[cfg(feature = "enable-guards")]
        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        #[cfg(feature = "enable-guards")]
        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return Err(MessageError::IllegalProtocolVersion);
            }
            _ => {}
        };

        let mut sub = r.sub(len as usize).ok_or(MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            payload,
        })
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }
}

impl From<Message> for PlainMessage {
    fn from(msg: Message) -> Self {
        let typ = msg.payload.content_type();
        let payload = match msg.payload {
            MessagePayload::ApplicationData(payload) => payload,
            _ => {
                let mut buf = Vec::new();
                msg.payload.encode(&mut buf);
                Payload(buf)
            }
        };

        Self {
            typ,
            version: msg.version,
            payload,
        }
    }
}

/// A decrypted TLS frame
///
/// This type owns all memory for its interior parts. It can be decrypted from an OpaqueMessage
/// or encrypted into an OpaqueMessage, and it is also used for joining and fragmenting.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload,
}

impl PlainMessage {
    pub fn into_unencrypted_opaque(self) -> OpaqueMessage {
        OpaqueMessage {
            version: self.version,
            typ: self.typ,
            payload: self.payload,
        }
    }

    pub fn borrow(&self) -> BorrowedPlainMessage<'_> {
        BorrowedPlainMessage {
            version: self.version,
            typ: self.typ,
            payload: &self.payload.0,
        }
    }
}

/// A message with decoded payload
#[derive(Debug, Clone, Comparable, PartialEq)]
pub struct Message {
    pub version: ProtocolVersion,
    #[comparable_ignore]
    pub payload: MessagePayload,
}

// Make it VecCodecWoSize so that we have `Vec<T>: Codec` for free
impl VecCodecWoSize for Message {}

impl Codec for Message {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Codec::encode(&self.create_opaque(), bytes);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        <OpaqueMessage>::read(reader)
            .ok()
            .and_then(|op| Message::try_from(op).ok())
    }
}

impl Message {
    pub fn is_handshake_type(&self, hstyp: HandshakeType) -> bool {
        // Bit of a layering violation, but OK.
        if let MessagePayload::Handshake(ref hsp) = self.payload {
            hsp.typ == hstyp
        } else {
            false
        }
    }

    pub fn build_alert(level: AlertLevel, desc: AlertDescription) -> Self {
        Self {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level,
                description: desc,
            }),
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::Handshake(HandshakeMessagePayload::build_key_update_notify()),
        }
    }
}

/// Parses a plaintext message into a well-typed [`Message`].
///
/// A [`PlainMessage`] must contain plaintext content. Encrypted content should be stored in an
/// [`OpaqueMessage`] and decrypted before being stored into a [`PlainMessage`].
impl TryFrom<PlainMessage> for Message {
    type Error = Error;

    fn try_from(plain: PlainMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            version: plain.version,
            payload: MessagePayload::new(plain.typ, plain.version, plain.payload)?,
        })
    }
}

impl TryFrom<OpaqueMessage> for Message {
    type Error = Error;

    fn try_from(value: OpaqueMessage) -> Result<Self, Self::Error> {
        Message::try_from(value.into_plain_message())
    }
}

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This type differs from `OpaqueMessage` because it borrows
/// its payload.  You can make a `OpaqueMessage` from an
/// `BorrowMessage`, but this involves a copy.
///
/// This type also cannot decode its internals and
/// cannot be read/encoded; only `OpaqueMessage` can do that.
pub struct BorrowedPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalLength,
    IllegalContentType,
    IllegalProtocolVersion,
}

// Rationale for `any_get_encoding` and `try_read_bytes`:
// 1. Messages of types Vec<Item> will be read and encoded without considering the size of the
//    vector (reading until end of buffer). We consider such messages as "intermediate values",
//    which are not meant to be directly used in struct fields such as
//   `extensions` in `ClientHello`. We use `VecCodecWoSize` for that.
//    In particular, an empty vector yield an empty bitstring and not [0].
// 2. Field elements of struct messages such as `extensions` in `ClientHello` are wrapped into a
//    constructor, whose `Codec` implementation consider the size of the vector, encoded into the
//    appropriate number of bytes. This depends on the field under consideration. For the above
//    example, we shall use `read_vec_u16` and `encode_vec_u16`.

// For all Countable types, we encode list of items of such type by prefixing with the length
// encoded in 2 bytes For each type: whether it produces empty bitstring for empty list ([]), and u8
// or u16 length prefix (8/16)
impl VecCodecWoSize for ClientExtension {} // []/u16
impl VecCodecWoSize for ServerExtension {} // u16    (server has to return at least oen extension it seems)
impl VecCodecWoSize for HelloRetryExtension {} // ?/u16
impl VecCodecWoSize for CertReqExtension {} // u16 -s
impl VecCodecWoSize for CertificateExtension {} // u16 -s
impl VecCodecWoSize for NewSessionTicketExtension {} //u16 -s
impl VecCodecWoSize for Compression {} // u8
impl VecCodecWoSize for Certificate {} // u24, no need?
impl VecCodecWoSize for CertificateEntry {} // u24
impl VecCodecWoSize for CipherSuite {} // u16
impl VecCodecWoSize for PresharedKeyIdentity {} //u16
impl VecCodecWoSize for NamedGroup {} //u16

#[macro_export]
macro_rules! try_read {
  ($bitstring:expr, $ti:expr, $T:ty, $($Ts:ty),+) => {
      {
      if $ti == TypeId::of::<$T>() {
        log::trace!("Type match TypeID {:?}...!", core::any::type_name::<$T>());
        <$T>::read_bytes($bitstring).ok_or(Term(format!(
                "[try_read_bytes] Failed to read to type {:?} the bitstring {:?}",
                core::any::type_name::<$T>(),
                & $bitstring
            )).into()).map(|v| Box::new(v) as Box<dyn EvaluatedTerm<TLSProtocolTypes>>)
      } else {
        try_read!($bitstring, $ti, $($Ts),+)
      }
      }
  };

  ($bitstring:expr, $ti:expr, $T:ty ) => {
      {
        if $ti == TypeId::of::<$T>() {
            log::trace!("Type match TypeID {:?}...!", core::any::type_name::<$T>());
            <$T>::read_bytes($bitstring).ok_or(Term(format!(
                "[try_read_bytes] Failed to read to type {:?} the bitstring {:?}",
                core::any::type_name::<$T>(),
                & $bitstring
            )).into()).map(|v| Box::new(v) as Box<dyn EvaluatedTerm<TLSProtocolTypes>>)
        } else {
                log::error!("Failed to find a suitable type with typeID {:?} to read the bitstring {:?}", $ti, &$bitstring);
                Err(Term(format!(
                    "[try_read_bytes] Failed to find a suitable type with typeID {:?} to read the bitstring {:?}",
                    $ti,
                    &$bitstring
                )).into())
        }
      }
  };
}

/// To `read` an `EvaluatedTerm<PT>` out of a bitstring, we cannot simply use `Codec::read_bytes`
/// since the type of the value to be initialized is not known, we only have the argument `ty` from
/// which we can downcast and then call `read_bytes` on the appropriate type.
/// `try_read_bytes` calls a macro `try_read` that does this.
///  (There is no workaround for the uninitialized value type since we need to make Codec traits
/// into dyn objects, hence it cannot have `Sized` as a supertrait.)
pub fn try_read_bytes(
    bitstring: &[u8],
    ty: TypeId,
) -> Result<Box<dyn EvaluatedTerm<TLSProtocolTypes>>, puffin::error::Error> {
    log::trace!("Trying read...");
    try_read!(
        bitstring,
        ty,
        // We list all the types that have the Codec trait and that can be the type of a rustls
        // message
        // The uni-test `term_zoo::test_term_read_encode` tests this is exhaustive for the TLS
        // signature at least
        Message,
        OpaqueMessage,
        MessageFlight,
        OpaqueMessageFlight,
        Vec<Certificate>,
        Certificate,
        CertificateEntries,
        Vec<CertificateEntry>,
        CertificateEntry,
        ServerExtensions,
        Vec<ServerExtension>,
        ClientExtensions,
        Vec<ClientExtension>,
        ClientExtension,
        ServerExtension,
        HelloRetryExtensions,
        Vec<HelloRetryExtension>,
        HelloRetryExtension,
        Vec<CertReqExtension>,
        CertReqExtension,
        Vec<CertificateExtension>,
        CertificateExtension,
        Vec<NewSessionTicketExtension>,
        NewSessionTicketExtension,
        NewSessionTicketExtensions,
        Random,
        Compressions,
        Vec<Compression>,
        Compression,
        SessionID,
        // HandshakeHash,
        // PrivateKey,
        CipherSuites,
        Vec<CipherSuite>,
        CipherSuite,
        Vec<PresharedKeyIdentity>,
        PresharedKeyIdentity,
        AlertMessagePayload,
        SignatureScheme,
        ProtocolVersion,
        HandshakeHash,
        u64,
        u32,
        // u8,
        // Vec<u64>,
        PayloadU24,
        PayloadU16,
        PayloadU8,
        Vec<PayloadU24>,
        Vec<PayloadU16>,
        Vec<PayloadU8>,
        VecU16OfPayloadU16,
        VecU16OfPayloadU8,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<NamedGroup>,
        Vec<Vec<u8>>,
        bool,
        // Option<Vec<Vec<u8>>>,
        // Result<Option<Vec<u8>>, FnError>,
        // Result<Vec<u8>, FnError>,
        // Result<bool, FnError>,
        // Result<Vec<u8>, FnError>,
        // Result<Vec<Vec<u8>>, FnError>,
        //
        // Message,
        // Result<Message FnError>,
        // MessagePayload,
        // ExtensionType,
        NamedGroup
    )
}
