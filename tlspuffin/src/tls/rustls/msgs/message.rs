use log::{debug, error};
use puffin::algebra::error::FnError;
use puffin::algebra::ConcreteMessage;
use puffin::codec;
use std::any::{Any, type_name, TypeId};
use std::convert::TryFrom;

use puffin::codec::{Codec, Countable, Reader};
use puffin::error::Error::Term;
use puffin::protocol::ProtocolMessage;

use crate::tls::rustls::hash_hs::HandshakeHash;
use crate::tls::rustls::key::{Certificate, PrivateKey};
use crate::tls::rustls::msgs::enums::{ExtensionType, NamedGroup, SignatureScheme};
use crate::tls::rustls::msgs::handshake::{
    CertReqExtension, CertificateEntry, CertificateExtension, ClientExtension, HelloRetryExtension,
    NewSessionTicketExtension, PresharedKeyIdentity, ServerExtension,
};
use crate::tls::rustls::{
    error::Error,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        ccs::ChangeCipherSpecPayload,
        enums::{AlertDescription, AlertLevel, ContentType, HandshakeType, ProtocolVersion},
        handshake::HandshakeMessagePayload,
        heartbeat::HeartbeatPayload,
    },
};
use crate::tls::{
    fn_impl::*,
    rustls::msgs::{
        enums::{CipherSuite, Compression},
        handshake::{Random, SessionID},
    },
};

#[derive(Debug, Clone)]
pub enum MessagePayload {
    Alert(AlertMessagePayload),
    Handshake(HandshakeMessagePayload),
    // this type is for TLS 1.2 encrypted handshake messages
    TLS12EncryptedHandshake(Payload),
    ChangeCipherSpec(ChangeCipherSpecPayload),
    ApplicationData(Payload),
    Heartbeat(HeartbeatPayload),
}

impl codec::Encode for MessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        MessagePayload::encode(self, bytes);
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
#[derive(Clone, Debug)]
pub struct OpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: Payload,
}

impl Codec for OpaqueMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&OpaqueMessage::encode(self.clone()));
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Self::read(reader).ok()
    }
}

impl OpaqueMessage {
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let typ = ContentType::read(r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(r).ok_or(MessageError::TooShortForHeader)?;

        // Reject undersize messages
        //  implemented per section 5.1 of RFC8446 (TLSv1.3)
        //              per section 6.2.1 of RFC5246 (TLSv1.2)
        if typ != ContentType::ApplicationData && len == 0 {
            return Err(MessageError::IllegalLength);
        }

        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

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

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        (self.payload.0.len() as u16).encode(&mut buf);
        self.payload.encode(&mut buf);
        buf
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

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
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
#[derive(Debug, Clone)]
pub struct Message {
    pub version: ProtocolVersion,
    pub payload: MessagePayload,
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

#[macro_export]
macro_rules! try_downcast {
  ($message:expr, $T:ty, $($Ts:ty),+) => {
        $message
        .downcast_ref::<$T>()
        .map(|b| {
            // println!("\n--->> Successfully downcast from {:?}", std::any::type_name::<$T>());
            let b = codec::Encode::get_encoding(b);
            // println!("====>> Successfully encoded\n");
            b
        })
        .or_else(|| {
                // print!("Failed to downcast from {:?}", std::any::type_name::<$T>());
                try_downcast!($message,$($Ts),+)
        })
  };
    ($message:expr, $T:ty ) => {
        $message
        .downcast_ref::<$T>()
        .map(|b| codec::Encode::get_encoding(b))
         .or_else(|| {
                // print!("Failed to downcast from {:?}", std::any::type_name::<$T>());
                $message
                .downcast_ref::<Message>()
                .map(|b| {
                      // println!("\n--->> Successfully downcast from {:?}", std::any::type_name::<Message>());
                      let b = codec::Encode::get_encoding(&b.create_opaque());
                      // println!("====>> Successfully encoded\n");
                      b
                })
        })
  };
}

// For all Countable types, we encode list of items of such type by prefixing with the length
impl Countable for ClientExtension {}
impl Countable for ServerExtension {}
impl Countable for HelloRetryExtension {}
impl Countable for CertReqExtension {}
impl Countable for CertificateExtension {}
impl Countable for NewSessionTicketExtension {}
impl Countable for Compression {}
impl Countable for Certificate {}
impl Countable for CertificateEntry {}
impl Countable for CipherSuite {}
impl Countable for PresharedKeyIdentity {}


// Re-interpret any type of rustls message into bitstrings through successive downcast tries
pub fn any_get_encoding(message: &Box<dyn Any>) -> Result<ConcreteMessage, puffin::error::Error> {
    try_downcast!(
        message,
        // We list all the types that have the Encode trait and that can be the type of a rustls message
        // Using term_zoo.rs integration test `test_term_eval, I am able to measure how many generated terms
        // require each of the encode type below. Can be used to remove non-required ones and possibly
        // to refine the order of them (heuristics to speed up the encoding).
        u64, // 3603 fail
        // u8, // OK
        // Vec<u64>, // OK
        Vec<u8>,         // 2385 Fail
        bool,            // 400 Fail
        Vec<Vec<u8>>,    // Fail 332
        Option<Vec<u8>>, // Fail 542
        // Option<Vec<Vec<u8>>>, // OK
        // Result<Option<Vec<u8>>, FnError>, // OK
        // Result<Vec<u8>, FnError>, // OK
        // Result<bool, FnError>, // OK
        // Result<Vec<u8>, FnError>,
        // Result<Vec<Vec<u8>>, FnError>,
        //
        // Message, // 4185 Fail  TODOOO
        // Result<Message, FnError>,
        // MessagePayload,
        // ExtensionType,
        NamedGroup,           // 407
        Vec<ClientExtension>, //368
        ClientExtension,      // 4067
        Vec<ServerExtension>, // TODO
        ServerExtension,
        Vec<HelloRetryExtension>,
        HelloRetryExtension,
        Vec<CertReqExtension>,
        CertReqExtension,
        Vec<CertificateExtension>,
        CertificateExtension,
        NewSessionTicketExtension,
        Vec<NewSessionTicketExtension>,
        Random,
        Vec<Compression>,
        Compression,
        SessionID,
        Vec<Certificate>,
        Certificate,
        Vec<CertificateEntry>,
        CertificateEntry,
        HandshakeHash,
        PrivateKey,
        Vec<CipherSuite>,
        CipherSuite,
        Vec<PresharedKeyIdentity>,
        PresharedKeyIdentity,
        AlertMessagePayload,
        SignatureScheme, // 800
        OpaqueMessage,   // 337
        ProtocolVersion  // 400
    )
    .ok_or(
        Term(format!(
            "[any_get_encoding] Failed to downcast and then any_encode::get_encoding message {:?}",
            &message
        ))
        .into(),
    )
}

#[macro_export]
macro_rules! try_read {
  ($bitstring:expr, $ti:expr, $T:ty, $($Ts:ty),+) => {
      if $ti == TypeId::of::<$T>() {
        <$T>::read_bytes(& $bitstring).ok_or(Term(format!(
                "[try_read_bytes] Failed to read to type {:?} the bitstring {:?}",
                core::any::type_name::<$T>(),
                & $bitstring
            )).into()).map(|v| Box::new(v) as Box<dyn Any>)
    } else {
        try_read!($bitstring, $ti, $($Ts),+)
    }
  };
    ($bitstring:expr, $ti:expr, $T:ty ) => {
        if $ti == TypeId::of::<$T>() {
            <$T>::read_bytes(& $bitstring).ok_or(Term(format!(
                "[try_read_bytes] Failed to read to type {:?} the bitstring {:?}",
                core::any::type_name::<$T>(),
                & $bitstring
            )).into()).map(|v| Box::new(v) as Box<dyn Any>)
    } else {
            // error!(
            //     "[try_read_bytes] Failed to find a suitable type with typeID {:?} to read the bitstring {:?}",
            //     $ti,
            //     & $bitstring
            // );
           Err(Term(format!(
                "[try_read_bytes] Failed to find a suitable type with typeID {:?} to read the bitstring {:?}",
                $ti,
                & $bitstring
            )).into())
      }
  };
}

pub fn try_read_bytes(bitstring: ConcreteMessage, ty: TypeId) -> Result<Box<dyn Any>, puffin::error::Error> {
    if ty == TypeId::of::<Message>() {
        <OpaqueMessage>::read_bytes(& bitstring).ok_or(Term(format!(
                "[try_read_bytes] Failed to read to type OpaqueMessage (ty was Message though) the bitstring {:?}",
                & bitstring
            )).into()).map(|v| Box::new(Message::try_from(v)) as Box<dyn Any>)
    } else {
        try_read!(
            bitstring,
            ty,
            // We list all the types that have the Codec trait and that can be the type of a rustls message
            ClientExtension,
            Vec<ServerExtension>,
            ServerExtension,
            Vec<HelloRetryExtension>,
            HelloRetryExtension,
            Vec<CertReqExtension>,
            CertReqExtension,
            Vec<CertificateExtension>,
            CertificateExtension,
            NewSessionTicketExtension,
            Vec<NewSessionTicketExtension>,
            Random,
            Vec<Compression>,
            Compression,
            SessionID,
            Vec<Certificate>,
            Certificate,
            Vec<CertificateEntry>,
            CertificateEntry,
            // HandshakeHash,
            // PrivateKey,
            Vec<CipherSuite>,
            CipherSuite,
            Vec<PresharedKeyIdentity>,
            PresharedKeyIdentity,
            AlertMessagePayload,
            SignatureScheme,
            OpaqueMessage,
            ProtocolVersion,
            u64,
            // u8,
            // Vec<u64>,
            Vec<u8>,
            Vec<Vec<u8>>,
            // Option<Vec<Vec<u8>>>,
            // Result<Option<Vec<u8>>, FnError>,
            // Result<Vec<u8>, FnError>,
            // Result<bool, FnError>,
            // Result<Vec<u8>, FnError>,
            // Result<Vec<Vec<u8>>, FnError>,
            //
            // Message,
            // Result<Message, FnError>,
            // MessagePayload,
            // ExtensionType,
            NamedGroup,
            Vec<ClientExtension>
        )
    }
}