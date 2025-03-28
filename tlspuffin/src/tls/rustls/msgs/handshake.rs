use std::{collections, fmt};

use extractable_macro::Extractable;
use puffin::codec::{Codec, Reader};
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, codec};

use crate::protocol::TLSProtocolTypes;
use crate::tls::fn_impl::fn_hello_retry_request_random;
use crate::tls::rustls::msgs::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use crate::tls::rustls::msgs::enums::{
    CertificateStatusType, CipherSuite, ClientCertificateType, Compression, ECCurveType,
    ECPointFormat, ExtensionType, HandshakeType, HashAlgorithm, KeyUpdateRequest, NamedGroup,
    PSKKeyExchangeMode, ProtocolVersion, ServerNameType, SignatureAlgorithm, SignatureScheme,
};
use crate::tls::rustls::{key, rand};

macro_rules! declare_u8_vec (
  ($name:ident, $itemtype:ty) => {
    #[derive(Debug, Clone)]
    pub struct $name(pub Vec<$itemtype>);

    atom_extract_knowledge!(TLSProtocolTypes, $name);

    impl puffin::codec::Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        puffin::codec::encode_vec_u8(bytes, &self.0);
      }

      fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        Some($name(puffin::codec::read_vec_u8::<$itemtype>(r)?))
      }
    }
  }
);

macro_rules! declare_u16_vec (
  ($name:ident, $itemtype:ty) => {
    #[derive(Debug, Clone)]
    pub struct $name(pub Vec<$itemtype>);

    impl Extractable<TLSProtocolTypes> for $name {
        fn extract_knowledge<'a>(
            &'a self,
            knowledges: &mut Vec<Knowledge<'a, TLSProtocolTypes>>,
            matcher: Option<<TLSProtocolTypes as ProtocolTypes>::Matcher>,
            source: &'a Source,
        ) -> Result<(), Error> {
            knowledges.push(Knowledge {
                source,
                matcher,
                data: self,
            });

            for x in &self.0 {
                x.extract_knowledge(knowledges, matcher, source)?;
            }
            Ok(())
        }
    }

    impl puffin::codec::Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        puffin::codec::encode_vec_u16(bytes, &self.0);
      }

      fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        Some($name(puffin::codec::read_vec_u16::<$itemtype>(r)?))
      }
    }
  }
);

macro_rules! declare_u16_vec_empty (
  ($name:ident, $itemtype:ty) => {
    #[derive(Debug, Clone, Extractable)]
    #[extractable(TLSProtocolTypes)]
    pub struct $name(pub Vec<$itemtype>);


    impl puffin::codec::Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
          if !self.0.is_empty() { // for optional fields such as ClientExtensions
            puffin::codec::encode_vec_u16(bytes, &self.0);
          }
      }

      fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        Some($name(puffin::codec::read_vec_u16::<$itemtype>(r)?)) // we still try to read even though we might
          // mis-interpret a ['0'] as being the empty list, which is must however must be serialized as [] (empty bittstring).
          // This is a trade-off we accept to be able to correctly read in most cases (non-empty lists).
          // Moroever, when reading a struct containing $name as a field, we shall first check that there is remaining
          // bytes to read!
      }
    }
  }
);

macro_rules! declare_u24_vec_limited (
  ($name:ident, $itemtype:ty) => {
    #[derive(Debug, Clone)]
    pub struct $name(pub Vec<$itemtype>);

    atom_extract_knowledge!(TLSProtocolTypes, $name);

    impl puffin::codec::Codec for $name {
      fn encode(&self, bytes: &mut Vec<u8>) {
        puffin::codec::encode_vec_u24(bytes, &self.0);
      }

      fn read(r: &mut puffin::codec::Reader) -> Option<Self> {
        Some($name(puffin::codec::read_vec_u24_limited::<$itemtype>(r, 0x10000)?))
      }
    }
  }
);

declare_u16_vec!(VecU16OfPayloadU8, PayloadU8);
declare_u16_vec!(VecU16OfPayloadU16, PayloadU16);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Random(pub [u8; 32]);

static ZERO_RANDOM: Random = Random([0u8; 32]);

impl codec::Codec for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let bytes = r.take(32)?;
        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);

        Some(Self(opaque))
    }
}

impl Random {
    pub fn new() -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        rand::fill_random(&mut data)?;
        Ok(Self(data))
    }

    pub fn write_slice(&self, bytes: &mut [u8]) {
        let buf = self.get_encoding();
        bytes.copy_from_slice(&buf);
    }
}

impl From<[u8; 32]> for Random {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Copy, Clone)]
pub struct SessionID {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SessionID")
            .field(&&self.data[..self.len]) // must be `Sized` to cast to `dyn Debug`
            .finish()
    }
}

impl PartialEq for SessionID {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.data[i] ^ other.data[i]
        }

        diff == 0u8
    }
}

impl codec::Codec for SessionID {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let len = u8::read(r)? as usize;
        if len > 32 {
            return None;
        }

        let bytes = r.take(len)?;
        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);

        Some(Self { data: out, len })
    }
}

impl SessionID {
    pub fn random() -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        rand::fill_random(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    pub fn empty() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct UnknownExtension {
    pub typ: ExtensionType,
    pub payload: Payload,
}

impl UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut codec::Reader) -> Self {
        let payload = Payload::read(r);
        Self { typ, payload }
    }
}

declare_u8_vec!(ECPointFormatList, ECPointFormat);

pub trait SupportedPointFormats {
    fn supported() -> ECPointFormatList;
}

impl SupportedPointFormats for ECPointFormatList {
    fn supported() -> ECPointFormatList {
        ECPointFormatList(vec![ECPointFormat::Uncompressed])
    }
}

declare_u16_vec!(NamedGroups, NamedGroup);

declare_u16_vec!(SupportedSignatureSchemes, SignatureScheme);

pub trait DecomposedSignatureScheme {
    fn sign(&self) -> SignatureAlgorithm;
    fn make(alg: SignatureAlgorithm, hash: HashAlgorithm) -> SignatureScheme;
}

impl DecomposedSignatureScheme for SignatureScheme {
    fn sign(&self) -> SignatureAlgorithm {
        match *self {
            Self::RSA_PKCS1_SHA1
            | Self::RSA_PKCS1_SHA256
            | Self::RSA_PKCS1_SHA384
            | Self::RSA_PKCS1_SHA512
            | Self::RSA_PSS_SHA256
            | Self::RSA_PSS_SHA384
            | Self::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
            Self::ECDSA_NISTP256_SHA256
            | Self::ECDSA_NISTP384_SHA384
            | Self::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }

    fn make(alg: SignatureAlgorithm, hash: HashAlgorithm) -> SignatureScheme {
        use crate::tls::rustls::msgs::enums::HashAlgorithm::{SHA1, SHA256, SHA384, SHA512};
        use crate::tls::rustls::msgs::enums::SignatureAlgorithm::{ECDSA, RSA};

        match (alg, hash) {
            (RSA, SHA1) => Self::RSA_PKCS1_SHA1,
            (RSA, SHA256) => Self::RSA_PKCS1_SHA256,
            (RSA, SHA384) => Self::RSA_PKCS1_SHA384,
            (RSA, SHA512) => Self::RSA_PKCS1_SHA512,
            (ECDSA, SHA256) => Self::ECDSA_NISTP256_SHA256,
            (ECDSA, SHA384) => Self::ECDSA_NISTP384_SHA384,
            (ECDSA, SHA512) => Self::ECDSA_NISTP521_SHA512,
            (_, _) => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ServerNamePayload {
    // Stored twice, bytes so we can round-trip, and DnsName for use
    HostName((PayloadU16, webpki::DnsName)),
    Unknown(Payload),
}

impl ServerNamePayload {
    pub fn new_hostname(hostname: webpki::DnsName) -> Self {
        let raw = {
            let s: &str = hostname.as_ref().into();
            PayloadU16::new(s.as_bytes().into())
        };
        Self::HostName((raw, hostname))
    }

    fn read_hostname(r: &mut codec::Reader) -> Option<Self> {
        let raw = PayloadU16::read(r)?;

        let dns_name = {
            match webpki::DnsNameRef::try_from_ascii(&raw.0) {
                Ok(dns_name) => dns_name.into(),
                Err(_) => {
                    //log::warn!("Illegal SNI hostname received {:?}", raw.0);
                    return None;
                }
            }
        };
        Some(Self::HostName((raw, dns_name)))
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::HostName((ref r, _)) => r.encode(bytes),
            Self::Unknown(ref r) => r.encode(bytes),
        }
    }
}

#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerName {
    #[extractable_ignore]
    pub typ: ServerNameType,
    #[extractable_ignore]
    pub payload: ServerNamePayload,
}

impl codec::Codec for ServerName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r)),
        };

        Some(Self { typ, payload })
    }
}

declare_u16_vec!(ServerNameRequest, ServerName);

pub trait ConvertServerNameList {
    fn has_duplicate_names_for_type(&self) -> bool;
    fn get_single_hostname(&self) -> Option<webpki::DnsNameRef>;
}

impl ConvertServerNameList for ServerNameRequest {
    /// RFC6066: "The ServerNameList MUST NOT contain more than one name of the same name_type."
    fn has_duplicate_names_for_type(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for name in &self.0 {
            if !seen.insert(name.typ.get_u8()) {
                return true;
            }
        }

        false
    }

    fn get_single_hostname(&self) -> Option<webpki::DnsNameRef> {
        fn only_dns_hostnames(name: &ServerName) -> Option<webpki::DnsNameRef> {
            if let ServerNamePayload::HostName((_, ref dns)) = name.payload {
                Some(dns.as_ref())
            } else {
                None
            }
        }

        self.0.iter().filter_map(only_dns_hostnames).next()
    }
}

pub type ProtocolNameList = VecU16OfPayloadU8;

pub trait ConvertProtocolNameList {
    fn from_slices(names: &[&[u8]]) -> Self;
    fn to_slices(&self) -> Vec<&[u8]>;
    fn as_single_slice(&self) -> Option<&[u8]>;
}

impl ConvertProtocolNameList for ProtocolNameList {
    fn from_slices(names: &[&[u8]]) -> Self {
        let mut ret = VecU16OfPayloadU8(Vec::new());

        for name in names {
            ret.0.push(PayloadU8::new(name.to_vec()));
        }

        ret
    }

    fn to_slices(&self) -> Vec<&[u8]> {
        self.0
            .iter()
            .map(|proto| -> &[u8] { &proto.0 })
            .collect::<Vec<&[u8]>>()
    }

    fn as_single_slice(&self) -> Option<&[u8]> {
        if self.0.len() == 1 {
            Some(&self.0[0].0)
        } else {
            None
        }
    }
}

// --- TLS 1.3 Key shares ---
#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub payload: PayloadU16,
}

impl KeyShareEntry {
    pub fn new(group: NamedGroup, payload: &[u8]) -> Self {
        Self {
            group,
            payload: PayloadU16::new(payload.to_vec()),
        }
    }
}

impl codec::Codec for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let group = NamedGroup::read(r)?;
        let payload = PayloadU16::read(r)?;

        Some(Self { group, payload })
    }
}

// --- TLS 1.3 PresharedKey offers ---
#[derive(Clone, Debug)]
pub struct PresharedKeyIdentity {
    pub identity: PayloadU16,
    pub obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity {
    pub fn new(id: Vec<u8>, age: u32) -> Self {
        Self {
            identity: PayloadU16::new(id),
            obfuscated_ticket_age: age,
        }
    }
}

impl codec::Codec for PresharedKeyIdentity {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            identity: PayloadU16::read(r)?,
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

declare_u16_vec!(PresharedKeyIdentities, PresharedKeyIdentity);
pub type PresharedKeyBinder = PayloadU8;
pub type PresharedKeyBinders = VecU16OfPayloadU8;

#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct PresharedKeyOffer {
    #[extractable_ignore]
    pub identities: PresharedKeyIdentities,
    #[extractable_ignore]
    pub binders: PresharedKeyBinders,
}

impl PresharedKeyOffer {
    /// Make a new one with one entry.
    pub fn new(id: PresharedKeyIdentity, binder: Vec<u8>) -> Self {
        Self {
            identities: PresharedKeyIdentities(vec![id]),
            binders: VecU16OfPayloadU8(vec![PresharedKeyBinder::new(binder)]),
        }
    }
}

impl codec::Codec for PresharedKeyOffer {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identities.encode(bytes);
        self.binders.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            identities: PresharedKeyIdentities::read(r)?,
            binders: PresharedKeyBinders::read(r)?,
        })
    }
}

// --- RFC6066 certificate status request ---
type ResponderIDs = VecU16OfPayloadU16;

#[derive(Clone, Debug)]
pub struct OCSPCertificateStatusRequest {
    pub responder_ids: ResponderIDs,
    pub extensions: PayloadU16,
}

impl codec::Codec for OCSPCertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.responder_ids.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            responder_ids: ResponderIDs::read(r)?,
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub enum CertificateStatusRequest {
    OCSP(#[extractable_ignore] OCSPCertificateStatusRequest),
    Unknown(#[extractable_ignore] (CertificateStatusType, Payload)),
}

impl codec::Codec for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::OCSP(ref r) => r.encode(bytes),
            Self::Unknown((typ, payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => {
                let ocsp_req = OCSPCertificateStatusRequest::read(r)?;
                Some(Self::OCSP(ocsp_req))
            }
            _ => {
                let data = Payload::read(r);
                Some(Self::Unknown((typ, data)))
            }
        }
    }
}

impl CertificateStatusRequest {
    pub fn build_ocsp() -> Self {
        let ocsp = OCSPCertificateStatusRequest {
            responder_ids: VecU16OfPayloadU16(Vec::new()),
            extensions: PayloadU16::empty(),
        };
        Self::OCSP(ocsp)
    }
}

// ---
// SCTs

pub type SCTList = VecU16OfPayloadU16;

// ---

declare_u8_vec!(PSKKeyExchangeModes, PSKKeyExchangeMode);
declare_u16_vec!(KeyShareEntries, KeyShareEntry);
declare_u8_vec!(ProtocolVersions, ProtocolVersion);

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub enum ClientExtension {
    ECPointFormats(ECPointFormatList),
    NamedGroups(NamedGroups),
    SignatureAlgorithms(SupportedSignatureSchemes),
    ServerName(ServerNameRequest),
    SessionTicket(ClientSessionTicket),
    Protocols(ProtocolNameList),
    SupportedVersions(ProtocolVersions),
    KeyShare(KeyShareEntries),
    PresharedKeyModes(PSKKeyExchangeModes),
    PresharedKey(PresharedKeyOffer),
    Cookie(PayloadU16),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(CertificateStatusRequest),
    SignedCertificateTimestampRequest,
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    RenegotiationInfo(PayloadU8),
    SignatureAlgorithmsCert(SupportedSignatureSchemes),
    Unknown(UnknownExtension),
}

impl ClientExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            Self::ECPointFormats(_) => ExtensionType::ECPointFormats,
            Self::NamedGroups(_) => ExtensionType::EllipticCurves,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SessionTicket(_) => ExtensionType::SessionTicket,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKeyModes(_) => ExtensionType::PSKKeyExchangeModes,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::ExtendedMasterSecretRequest => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusRequest(_) => ExtensionType::StatusRequest,
            Self::SignedCertificateTimestampRequest => ExtensionType::SCT,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            ClientExtension::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            Self::SignatureAlgorithmsCert(_) => ExtensionType::SignatureAlgorithmsCert,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl codec::Codec for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            Self::ECPointFormats(ref r) => r.encode(&mut sub),
            Self::NamedGroups(ref r) => r.encode(&mut sub),
            Self::SignatureAlgorithms(ref r) => r.encode(&mut sub),
            Self::ServerName(ref r) => r.encode(&mut sub),
            Self::SessionTicket(ClientSessionTicket::Request)
            | Self::ExtendedMasterSecretRequest
            | Self::SignedCertificateTimestampRequest
            | Self::EarlyData => {}
            Self::SessionTicket(ClientSessionTicket::Offer(ref r)) => r.encode(&mut sub),
            Self::Protocols(ref r) => r.encode(&mut sub),
            Self::SupportedVersions(ref r) => r.encode(&mut sub),
            Self::KeyShare(ref r) => r.encode(&mut sub),
            Self::PresharedKeyModes(ref r) => r.encode(&mut sub),
            Self::PresharedKey(ref r) => r.encode(&mut sub),
            Self::Cookie(ref r) => r.encode(&mut sub),
            Self::CertificateStatusRequest(ref r) => r.encode(&mut sub),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                sub.extend_from_slice(r)
            }
            Self::RenegotiationInfo(ref r) => r.encode(&mut sub),
            Self::SignatureAlgorithmsCert(ref r) => r.encode(&mut sub),
            Self::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => {
                Self::ECPointFormats(ECPointFormatList::read(&mut sub)?)
            }
            ExtensionType::EllipticCurves => Self::NamedGroups(NamedGroups::read(&mut sub)?),
            ExtensionType::SignatureAlgorithms => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                Self::SignatureAlgorithms(schemes)
            }
            ExtensionType::ServerName => Self::ServerName(ServerNameRequest::read(&mut sub)?),
            ExtensionType::SessionTicket => {
                if sub.any_left() {
                    let contents = Payload::read(&mut sub);
                    Self::SessionTicket(ClientSessionTicket::Offer(contents))
                } else {
                    Self::SessionTicket(ClientSessionTicket::Request)
                }
            }
            ExtensionType::ALProtocolNegotiation => {
                Self::Protocols(ProtocolNameList::read(&mut sub)?)
            }
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersions::read(&mut sub)?)
            }
            ExtensionType::KeyShare => Self::KeyShare(KeyShareEntries::read(&mut sub)?),
            ExtensionType::PSKKeyExchangeModes => {
                Self::PresharedKeyModes(PSKKeyExchangeModes::read(&mut sub)?)
            }
            ExtensionType::PreSharedKey => Self::PresharedKey(PresharedKeyOffer::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret if !sub.any_left() => {
                Self::ExtendedMasterSecretRequest
            }
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                Self::CertificateStatusRequest(csr)
            }
            ExtensionType::SCT if !sub.any_left() => Self::SignedCertificateTimestampRequest,
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::RenegotiationInfo => {
                let mut content_without_size = sub.rest().to_vec();
                if !content_without_size.is_empty() {
                    content_without_size = content_without_size[1..].to_vec() // because PayloadU8::new adds one byte for the length already
                }
                Self::RenegotiationInfo(PayloadU8::new(content_without_size))
            }
            ExtensionType::SignatureAlgorithmsCert => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                ClientExtension::SignatureAlgorithmsCert(schemes)
            }
            ExtensionType::EarlyData if !sub.any_left() => Self::EarlyData,
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

fn trim_hostname_trailing_dot_for_sni(dns_name: webpki::DnsNameRef) -> webpki::DnsName {
    let dns_name_str: &str = dns_name.into();

    // RFC6066: "The hostname is represented as a byte string using
    // ASCII encoding without a trailing dot"
    if dns_name_str.ends_with('.') {
        let trimmed = &dns_name_str[0..dns_name_str.len() - 1];
        webpki::DnsNameRef::try_from_ascii_str(trimmed)
            .unwrap()
            .to_owned()
    } else {
        dns_name.to_owned()
    }
}

impl ClientExtension {
    /// Make a basic SNI ServerNameRequest quoting `hostname`.
    pub fn make_sni(dns_name: webpki::DnsNameRef) -> Self {
        let name = ServerName {
            typ: ServerNameType::HostName,
            payload: ServerNamePayload::new_hostname(trim_hostname_trailing_dot_for_sni(dns_name)),
        };

        Self::ServerName(ServerNameRequest(vec![name]))
    }
}

#[derive(Clone, Debug, Extractable)]
#[extractable(TLSProtocolTypes)]
pub enum ClientSessionTicket {
    Request,
    Offer(#[extractable_ignore] Payload),
}

#[derive(Clone, Debug)]
pub enum ServerExtension {
    ECPointFormats(ECPointFormatList),
    ServerNameAck,
    SessionTicketAck,
    RenegotiationInfo(PayloadU8),
    Protocols(ProtocolNameList),
    KeyShare(KeyShareEntry),
    PresharedKey(u16),
    ExtendedMasterSecretAck,
    CertificateStatusAck,
    SignedCertificateTimestamp(SCTList),
    SupportedVersions(ProtocolVersion),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    Unknown(UnknownExtension),
}

impl ServerExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            Self::ECPointFormats(_) => ExtensionType::ECPointFormats,
            Self::ServerNameAck => ExtensionType::ServerName,
            Self::SessionTicketAck => ExtensionType::SessionTicket,
            Self::RenegotiationInfo(_) => ExtensionType::RenegotiationInfo,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::ExtendedMasterSecretAck => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusAck => ExtensionType::StatusRequest,
            Self::SignedCertificateTimestamp(_) => ExtensionType::SCT,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl codec::Codec for ServerExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            Self::ECPointFormats(ref r) => r.encode(&mut sub),
            Self::ServerNameAck
            | Self::SessionTicketAck
            | Self::ExtendedMasterSecretAck
            | Self::CertificateStatusAck
            | Self::EarlyData => {}
            Self::RenegotiationInfo(ref r) => r.encode(&mut sub),
            Self::Protocols(ref r) => r.encode(&mut sub),
            Self::KeyShare(ref r) => r.encode(&mut sub),
            Self::PresharedKey(r) => r.encode(&mut sub),
            Self::SignedCertificateTimestamp(ref r) => r.encode(&mut sub),
            Self::SupportedVersions(ref r) => r.encode(&mut sub),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                sub.extend_from_slice(r)
            }
            Self::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => {
                Self::ECPointFormats(ECPointFormatList::read(&mut sub)?)
            }
            ExtensionType::ServerName => Self::ServerNameAck,
            ExtensionType::SessionTicket => Self::SessionTicketAck,
            ExtensionType::StatusRequest => Self::CertificateStatusAck,
            ExtensionType::RenegotiationInfo => Self::RenegotiationInfo(PayloadU8::read(&mut sub)?),
            ExtensionType::ALProtocolNegotiation => {
                Self::Protocols(ProtocolNameList::read(&mut sub)?)
            }
            ExtensionType::KeyShare => Self::KeyShare(KeyShareEntry::read(&mut sub)?),
            ExtensionType::PreSharedKey => Self::PresharedKey(u16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret => Self::ExtendedMasterSecretAck,
            ExtensionType::SCT => {
                let scts = SCTList::read(&mut sub)?;
                Self::SignedCertificateTimestamp(scts)
            }
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData => Self::EarlyData,
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

impl ServerExtension {
    pub fn make_alpn(proto: &[&[u8]]) -> Self {
        Self::Protocols(ProtocolNameList::from_slices(proto))
    }

    pub fn make_empty_renegotiation_info() -> Self {
        let empty = Vec::new();
        Self::RenegotiationInfo(PayloadU8::new(empty))
    }

    pub fn make_sct(sctl: Vec<u8>) -> Self {
        let scts = SCTList::read_bytes(&sctl).expect("invalid SCT list");
        Self::SignedCertificateTimestamp(scts)
    }
}

declare_u16_vec_empty!(ClientExtensions, ClientExtension);
declare_u16_vec!(CipherSuites, CipherSuite);
declare_u8_vec!(Compressions, Compression);

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ClientHelloPayload {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suites: CipherSuites,
    pub compression_methods: Compressions,
    pub extensions: ClientExtensions,
}

impl codec::Codec for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);
        self.extensions.encode(bytes); // will not write anything if the list is empty!
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let mut ret = Self {
            client_version: ProtocolVersion::read(r)?,
            random: Random::read(r)?,
            session_id: SessionID::read(r)?,
            cipher_suites: CipherSuites::read(r)?,
            compression_methods: Compressions::read(r)?,
            extensions: ClientExtensions(Vec::new()),
        };

        if r.any_left() {
            ret.extensions = ClientExtensions::read(r)?;
        }

        if r.any_left() {
            None
        } else {
            Some(ret)
        }
    }
}

impl ClientHelloPayload {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.extensions.0 {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
        self.extensions.0.iter().find(|x| x.get_type() == ext)
    }

    pub fn get_sni_extension(&self) -> Option<&ServerNameRequest> {
        let ext = self.find_extension(ExtensionType::ServerName)?;
        match *ext {
            ClientExtension::ServerName(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureSchemes> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            ClientExtension::SignatureAlgorithms(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_namedgroups_extension(&self) -> Option<&NamedGroups> {
        let ext = self.find_extension(ExtensionType::EllipticCurves)?;
        match *ext {
            ClientExtension::NamedGroups(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ClientExtension::ECPointFormats(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_alpn_extension(&self) -> Option<&ProtocolNameList> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ClientExtension::Protocols(ref req) => Some(req),
            _ => None,
        }
    }

    pub fn get_quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ClientExtension::TransportParameters(ref bytes)
            | ClientExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    pub fn get_ticket_extension(&self) -> Option<&ClientExtension> {
        self.find_extension(ExtensionType::SessionTicket)
    }

    pub fn get_versions_extension(&self) -> Option<&ProtocolVersions> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ClientExtension::SupportedVersions(ref vers) => Some(vers),
            _ => None,
        }
    }

    pub fn get_keyshare_extension(&self) -> Option<&KeyShareEntries> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ClientExtension::KeyShare(ref shares) => Some(shares),
            _ => None,
        }
    }

    pub fn has_keyshare_extension_with_duplicates(&self) -> bool {
        if let Some(entries) = self.get_keyshare_extension() {
            let mut seen = collections::HashSet::new();

            for kse in &entries.0 {
                let grp = kse.group.get_u16();

                if !seen.insert(grp) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_psk(&self) -> Option<&PresharedKeyOffer> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ClientExtension::PresharedKey(ref psk) => Some(psk),
            _ => None,
        }
    }

    pub fn check_psk_ext_is_last(&self) -> bool {
        self.extensions
            .0
            .last()
            .map_or(false, |ext| ext.get_type() == ExtensionType::PreSharedKey)
    }

    pub fn get_psk_modes(&self) -> Option<&PSKKeyExchangeModes> {
        let ext = self.find_extension(ExtensionType::PSKKeyExchangeModes)?;
        match *ext {
            ClientExtension::PresharedKeyModes(ref psk_modes) => Some(psk_modes),
            _ => None,
        }
    }

    pub fn psk_mode_offered(&self, mode: PSKKeyExchangeMode) -> bool {
        self.get_psk_modes()
            .map(|modes| modes.0.contains(&mode))
            .unwrap_or(false)
    }

    pub fn set_psk_binder(&mut self, binder: impl Into<Vec<u8>>) {
        let last_extension = self.extensions.0.last_mut();
        if let Some(ClientExtension::PresharedKey(ref mut offer)) = last_extension {
            offer.binders.0[0] = PresharedKeyBinder::new(binder.into());
        }
    }

    pub fn ems_support_offered(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData).is_some()
    }
}

#[derive(Debug, Clone)]
pub enum HelloRetryExtension {
    KeyShare(NamedGroup),
    Cookie(PayloadU16),
    SupportedVersions(ProtocolVersion),
    Unknown(UnknownExtension),
}

impl HelloRetryExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            HelloRetryExtension::KeyShare(_) => ExtensionType::KeyShare,
            HelloRetryExtension::Cookie(_) => ExtensionType::Cookie,
            HelloRetryExtension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            HelloRetryExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl codec::Codec for HelloRetryExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            HelloRetryExtension::KeyShare(ref r) => r.encode(&mut sub),
            HelloRetryExtension::Cookie(ref r) => r.encode(&mut sub),
            HelloRetryExtension::SupportedVersions(ref r) => r.encode(&mut sub),
            HelloRetryExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::KeyShare => Self::KeyShare(NamedGroup::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersion::read(&mut sub)?)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

declare_u16_vec!(HelloRetryExtensions, HelloRetryExtension);

#[derive(Debug, Clone)]
pub struct HelloRetryRequest {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_methods: Compressions,
    pub extensions: HelloRetryExtensions,
}

impl codec::Codec for HelloRetryRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_methods.encode(bytes);
        // Compression::Null.encode(bytes);
        // if !self.extensions.0.is_empty() {  // TODO: @MAX shouldn't we also accept empty ones?
        //         // lists of extensions, as for CLientHello ClientExtensions?
        self.extensions.encode(bytes);
        // }
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let session_id = SessionID::read(r)?;
        let cipher_suite = CipherSuite::read(r)?;
        let compression_methods = Compressions::read(r)?;
        let extensions = HelloRetryExtensions::read(r)?;
        if compression_methods.0 != vec![Compression::Null] {
            return None;
        }

        Some(Self {
            legacy_version: ProtocolVersion::Unknown(0), /* will be stored by the HandShake
                                                          * message wrapping this payload */
            random: fn_hello_retry_request_random().unwrap(), // same
            session_id,
            cipher_suite,
            compression_methods,
            extensions,
        })
    }
}

impl HelloRetryRequest {
    /// Returns true if there is more than one extension of a given
    /// type.
    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.extensions.0 {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn has_unknown_extension(&self) -> bool {
        self.extensions.0.iter().any(|ext| {
            ext.get_type() != ExtensionType::KeyShare
                && ext.get_type() != ExtensionType::SupportedVersions
                && ext.get_type() != ExtensionType::Cookie
        })
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&HelloRetryExtension> {
        self.extensions.0.iter().find(|x| x.get_type() == ext)
    }

    pub fn get_requested_key_share_group(&self) -> Option<NamedGroup> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            HelloRetryExtension::KeyShare(grp) => Some(grp),
            _ => None,
        }
    }

    pub fn get_cookie(&self) -> Option<&PayloadU16> {
        let ext = self.find_extension(ExtensionType::Cookie)?;
        match *ext {
            HelloRetryExtension::Cookie(ref ck) => Some(ck),
            _ => None,
        }
    }

    pub fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            HelloRetryExtension::SupportedVersions(ver) => Some(ver),
            _ => None,
        }
    }
}

declare_u16_vec_empty!(ServerExtensions, ServerExtension);

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerHelloPayload {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: Compression,
    pub extensions: ServerExtensions,
}

impl codec::Codec for ServerHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.legacy_version.encode(bytes);
        self.random.encode(bytes);

        self.session_id.encode(bytes);
        self.cipher_suite.encode(bytes);
        self.compression_method.encode(bytes);
        self.extensions.encode(bytes);
    }

    // minus version and random, which have already been read.
    fn read(r: &mut codec::Reader) -> Option<Self> {
        let session_id = SessionID::read(r)?;
        let suite = CipherSuite::read(r)?;
        let compression = Compression::read(r)?;
        let extensions = if r.any_left() {
            ServerExtensions::read(r)?
        } else {
            ServerExtensions(vec![])
        };

        let ret = Self {
            legacy_version: ProtocolVersion::Unknown(0),
            random: ZERO_RANDOM,
            session_id,
            cipher_suite: suite,
            compression_method: compression,
            extensions,
        };

        if r.any_left() {
            None
        } else {
            Some(ret)
        }
    }
}

impl HasServerExtensions for ServerHelloPayload {
    fn get_extensions(&self) -> &[ServerExtension] {
        &self.extensions.0
    }
}

impl ServerHelloPayload {
    pub fn get_key_share(&self) -> Option<&KeyShareEntry> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ServerExtension::KeyShare(ref share) => Some(share),
            _ => None,
        }
    }

    pub fn get_psk_index(&self) -> Option<u16> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ServerExtension::PresharedKey(ref index) => Some(*index),
            _ => None,
        }
    }

    pub fn get_ecpoints_extension(&self) -> Option<&ECPointFormatList> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ServerExtension::ECPointFormats(ref fmts) => Some(fmts),
            _ => None,
        }
    }

    pub fn ems_support_acked(&self) -> bool {
        self.find_extension(ExtensionType::ExtendedMasterSecret)
            .is_some()
    }

    pub fn get_sct_list(&self) -> Option<&SCTList> {
        let ext = self.find_extension(ExtensionType::SCT)?;
        match *ext {
            ServerExtension::SignedCertificateTimestamp(ref sctl) => Some(sctl),
            _ => None,
        }
    }

    pub fn get_supported_versions(&self) -> Option<ProtocolVersion> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ServerExtension::SupportedVersions(vers) => Some(vers),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct CertificatePayload(#[extractable_no_recursion] pub Vec<key::Certificate>);

impl codec::Codec for CertificatePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::encode_vec_u24(bytes, &self.0);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        // 64KB of certificates is plenty, 16MB is obviously silly
        Some(CertificatePayload(codec::read_vec_u24_limited(r, 0x10000)?))
    }
}

// TLS1.3 changes the Certificate payload encoding.
// That's annoying. It means the parsing is not
// context-free any more.

#[derive(Debug, Clone)]
pub enum CertificateExtension {
    CertificateStatus(CertificateStatus),
    SignedCertificateTimestamp(SCTList),
    Unknown(UnknownExtension),
}

impl CertificateExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            CertificateExtension::CertificateStatus(_) => ExtensionType::StatusRequest,
            CertificateExtension::SignedCertificateTimestamp(_) => ExtensionType::SCT,
            CertificateExtension::Unknown(ref r) => r.typ,
        }
    }

    pub fn make_sct(sct_list: Vec<u8>) -> Self {
        let sctl = SCTList::read_bytes(&sct_list).expect("invalid SCT list");
        Self::SignedCertificateTimestamp(sctl)
    }

    pub fn get_cert_status(&self) -> Option<&Vec<u8>> {
        match *self {
            CertificateExtension::CertificateStatus(ref cs) => Some(&cs.ocsp_response.0),
            _ => None,
        }
    }

    pub fn get_sct_list(&self) -> Option<&SCTList> {
        match *self {
            CertificateExtension::SignedCertificateTimestamp(ref sctl) => Some(sctl),
            _ => None,
        }
    }
}

impl codec::Codec for CertificateExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            CertificateExtension::CertificateStatus(ref r) => r.encode(&mut sub),
            CertificateExtension::SignedCertificateTimestamp(ref r) => r.encode(&mut sub),
            CertificateExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::StatusRequest => {
                let st = CertificateStatus::read(&mut sub)?;
                Self::CertificateStatus(st)
            }
            ExtensionType::SCT => {
                let scts = SCTList::read(&mut sub)?;
                Self::SignedCertificateTimestamp(scts)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

declare_u16_vec!(CertificateExtensions, CertificateExtension);

#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub cert: key::Certificate,
    pub exts: CertificateExtensions,
}

impl codec::Codec for CertificateEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cert.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            cert: key::Certificate::read(r)?,
            exts: CertificateExtensions::read(r)?,
        })
    }
}

impl CertificateEntry {
    pub fn new(cert: key::Certificate) -> Self {
        Self {
            cert,
            exts: CertificateExtensions(Vec::new()),
        }
    }

    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.exts.0 {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn has_unknown_extension(&self) -> bool {
        self.exts.0.iter().any(|ext| {
            ext.get_type() != ExtensionType::StatusRequest && ext.get_type() != ExtensionType::SCT
        })
    }

    pub fn get_ocsp_response(&self) -> Option<&Vec<u8>> {
        self.exts
            .0
            .iter()
            .find(|ext| ext.get_type() == ExtensionType::StatusRequest)
            .and_then(CertificateExtension::get_cert_status)
    }

    pub fn get_scts(&self) -> Option<&SCTList> {
        self.exts
            .0
            .iter()
            .find(|ext| ext.get_type() == ExtensionType::SCT)
            .and_then(CertificateExtension::get_sct_list)
    }
}

declare_u24_vec_limited!(CertificateEntries, CertificateEntry);
#[derive(Debug, Clone)]
pub struct CertificatePayloadTLS13 {
    pub context: PayloadU8,
    pub entries: CertificateEntries,
}

impl codec::Codec for CertificatePayloadTLS13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.entries.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            context: PayloadU8::read(r)?,
            entries: CertificateEntries::read(r)?,
        })
    }
}

impl CertificatePayloadTLS13 {
    pub fn new(entries: Vec<CertificateEntry>) -> Self {
        Self {
            context: PayloadU8::empty(),
            entries: CertificateEntries(entries),
        }
    }

    pub fn any_entry_has_duplicate_extension(&self) -> bool {
        for entry in &self.entries.0 {
            if entry.has_duplicate_extension() {
                return true;
            }
        }

        false
    }

    pub fn any_entry_has_unknown_extension(&self) -> bool {
        for entry in &self.entries.0 {
            if entry.has_unknown_extension() {
                return true;
            }
        }

        false
    }

    pub fn any_entry_has_extension(&self) -> bool {
        for entry in &self.entries.0 {
            if !entry.exts.0.is_empty() {
                return true;
            }
        }

        false
    }

    pub fn get_end_entity_ocsp(&self) -> Vec<u8> {
        self.entries
            .0
            .first()
            .and_then(CertificateEntry::get_ocsp_response)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_end_entity_scts(&self) -> Option<SCTList> {
        self.entries
            .0
            .first()
            .and_then(CertificateEntry::get_scts)
            .cloned()
    }

    pub fn convert(&self) -> CertificatePayload {
        let mut ret = Vec::new();
        for entry in &self.entries.0 {
            ret.push(entry.cert.clone());
        }
        CertificatePayload(ret)
    }
}

#[derive(Debug)]
pub enum KeyExchangeAlgorithm {
    BulkOnly,
    DH,
    DHE,
    RSA,
    ECDH,
    ECDHE,
}

// We don't support arbitrary curves.  It's a terrible
// idea and unnecessary attack surface.  Please,
// get a grip.
#[derive(Debug, Clone)]
pub struct ECParameters {
    pub curve_type: ECCurveType,
    pub named_group: NamedGroup,
}

impl codec::Codec for ECParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let ct = ECCurveType::read(r)?;
        let grp = NamedGroup::read(r)?;

        Some(Self {
            curve_type: ct,
            named_group: grp,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DigitallySignedStruct {
    pub scheme: SignatureScheme,
    pub sig: PayloadU16,
}

impl DigitallySignedStruct {
    pub fn new(scheme: SignatureScheme, sig: Vec<u8>) -> Self {
        Self {
            scheme,
            sig: PayloadU16::new(sig),
        }
    }
}

impl codec::Codec for DigitallySignedStruct {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.scheme.encode(bytes);
        self.sig.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let scheme = SignatureScheme::read(r)?;
        let sig = PayloadU16::read(r)?;

        Some(Self { scheme, sig })
    }
}

#[derive(Debug)]
pub struct ClientECDHParams {
    pub public: PayloadU8,
}

impl codec::Codec for ClientECDHParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let pb = PayloadU8::read(r)?;
        Some(Self { public: pb })
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerECDHParams {
    #[extractable_ignore]
    pub curve_params: ECParameters,
    #[extractable_ignore]
    pub public: PayloadU8,
}

impl ServerECDHParams {
    pub fn new(named_group: NamedGroup, pubkey: &[u8]) -> Self {
        Self {
            curve_params: ECParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group,
            },
            public: PayloadU8::new(pubkey.to_vec()),
        }
    }
}

impl codec::Codec for ServerECDHParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_params.encode(bytes);
        self.public.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let cp = ECParameters::read(r)?;
        let pb = PayloadU8::read(r)?;

        Some(Self {
            curve_params: cp,
            public: pb,
        })
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct ECDHEServerKeyExchange {
    pub params: ServerECDHParams,
    #[extractable_ignore]
    pub dss: DigitallySignedStruct,
}

impl codec::Codec for ECDHEServerKeyExchange {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let params = ServerECDHParams::read(r)?;
        let dss = DigitallySignedStruct::read(r)?;

        Some(Self { params, dss })
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub enum ServerKeyExchangePayload {
    ECDHE(ECDHEServerKeyExchange),
    Unknown(Payload),
}

impl codec::Codec for ServerKeyExchangePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            ServerKeyExchangePayload::ECDHE(ref x) => x.encode(bytes),
            ServerKeyExchangePayload::Unknown(ref x) => x.encode(bytes),
        }
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        // read as Unknown, fully parse when we know the
        // KeyExchangeAlgorithm
        Some(Self::Unknown(Payload::read(r)))
    }
}

impl ServerKeyExchangePayload {
    pub fn unwrap_given_kxa(&self, kxa: &KeyExchangeAlgorithm) -> Option<ECDHEServerKeyExchange> {
        if let ServerKeyExchangePayload::Unknown(ref unk) = *self {
            let mut rd = codec::Reader::init(&unk.0);

            let result = match *kxa {
                KeyExchangeAlgorithm::ECDHE => ECDHEServerKeyExchange::read(&mut rd),
                _ => None,
            };

            if !rd.any_left() {
                return result;
            };
        }

        None
    }
}

// -- EncryptedExtensions (TLS1.3 only) --
declare_u16_vec!(EncryptedExtensions, ServerExtension);

pub trait HasServerExtensions {
    fn get_extensions(&self) -> &[ServerExtension];

    /// Returns true if there is more than one extension of a given
    /// type.
    fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in self.get_extensions() {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    fn find_extension(&self, ext: ExtensionType) -> Option<&ServerExtension> {
        self.get_extensions().iter().find(|x| x.get_type() == ext)
    }

    fn get_alpn_protocol(&self) -> Option<&[u8]> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ServerExtension::Protocols(ref protos) => protos.as_single_slice(),
            _ => None,
        }
    }

    fn get_quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ServerExtension::TransportParameters(ref bytes)
            | ServerExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData).is_some()
    }
}

impl HasServerExtensions for EncryptedExtensions {
    fn get_extensions(&self) -> &[ServerExtension] {
        &self.0
    }
}

impl HasServerExtensions for Vec<ServerExtension> {
    fn get_extensions(&self) -> &[ServerExtension] {
        self
    }
}

// -- CertificateRequest and sundries --
declare_u8_vec!(ClientCertificateTypes, ClientCertificateType);
pub type DistinguishedName = PayloadU16;
pub type DistinguishedNames = VecU16OfPayloadU16;

#[derive(Debug, Clone)]
pub struct CertificateRequestPayload {
    pub certtypes: ClientCertificateTypes,
    pub sigschemes: SupportedSignatureSchemes,
    pub canames: DistinguishedNames,
}

impl codec::Codec for CertificateRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.certtypes.encode(bytes);
        self.sigschemes.encode(bytes);
        self.canames.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let certtypes = ClientCertificateTypes::read(r)?;
        let sigschemes = SupportedSignatureSchemes::read(r)?;
        let canames = DistinguishedNames::read(r)?;

        Some(Self {
            certtypes,
            sigschemes,
            canames,
        })
    }
}

#[derive(Debug, Clone)]
pub enum CertReqExtension {
    SignatureAlgorithms(SupportedSignatureSchemes),
    AuthorityNames(DistinguishedNames),
    Unknown(UnknownExtension),
}

impl CertReqExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            CertReqExtension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            CertReqExtension::AuthorityNames(_) => ExtensionType::CertificateAuthorities,
            CertReqExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl codec::Codec for CertReqExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            CertReqExtension::SignatureAlgorithms(ref r) => r.encode(&mut sub),
            CertReqExtension::AuthorityNames(ref r) => r.encode(&mut sub),
            CertReqExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::SignatureAlgorithms => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                if schemes.0.is_empty() {
                    return None;
                }
                Self::SignatureAlgorithms(schemes)
            }
            ExtensionType::CertificateAuthorities => {
                let cas = DistinguishedNames::read(&mut sub)?;
                Self::AuthorityNames(cas)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

declare_u16_vec!(CertReqExtensions, CertReqExtension);

#[derive(Debug, Clone)]
pub struct CertificateRequestPayloadTLS13 {
    pub context: PayloadU8,
    pub extensions: CertReqExtensions,
}

impl codec::Codec for CertificateRequestPayloadTLS13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.context.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let context = PayloadU8::read(r)?;
        let extensions = CertReqExtensions::read(r)?;

        Some(Self {
            context,
            extensions,
        })
    }
}

impl CertificateRequestPayloadTLS13 {
    pub fn find_extension(&self, ext: ExtensionType) -> Option<&CertReqExtension> {
        self.extensions.0.iter().find(|x| x.get_type() == ext)
    }

    pub fn get_sigalgs_extension(&self) -> Option<&SupportedSignatureSchemes> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            CertReqExtension::SignatureAlgorithms(ref sa) => Some(sa),
            _ => None,
        }
    }

    pub fn get_authorities_extension(&self) -> Option<&DistinguishedNames> {
        let ext = self.find_extension(ExtensionType::CertificateAuthorities)?;
        match *ext {
            CertReqExtension::AuthorityNames(ref an) => Some(an),
            _ => None,
        }
    }
}

// -- NewSessionTicket --
#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct NewSessionTicketPayload {
    pub lifetime_hint: u32,
    pub ticket: PayloadU16,
}

impl NewSessionTicketPayload {
    pub fn new(lifetime_hint: u32, ticket: Vec<u8>) -> Self {
        Self {
            lifetime_hint,
            ticket: PayloadU16::new(ticket),
        }
    }
}

impl codec::Codec for NewSessionTicketPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime_hint.encode(bytes);
        self.ticket.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let lifetime = u32::read(r)?;
        let ticket = PayloadU16::read(r)?;

        Some(Self {
            lifetime_hint: lifetime,
            ticket,
        })
    }
}

// -- NewSessionTicket electric boogaloo --
#[derive(Debug, Clone)]
pub enum NewSessionTicketExtension {
    EarlyData(u32),
    Unknown(UnknownExtension),
}

impl NewSessionTicketExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            NewSessionTicketExtension::EarlyData(_) => ExtensionType::EarlyData,
            NewSessionTicketExtension::Unknown(ref r) => r.typ,
        }
    }
}

impl codec::Codec for NewSessionTicketExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            NewSessionTicketExtension::EarlyData(r) => r.encode(&mut sub),
            NewSessionTicketExtension::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::EarlyData => Self::EarlyData(u32::read(&mut sub)?),
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}

declare_u16_vec!(NewSessionTicketExtensions, NewSessionTicketExtension);

#[derive(Debug, Clone)]
pub struct NewSessionTicketPayloadTLS13 {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: PayloadU8,
    pub ticket: PayloadU16,
    pub exts: NewSessionTicketExtensions,
}

impl NewSessionTicketPayloadTLS13 {
    pub fn new(lifetime: u32, age_add: u32, nonce: Vec<u8>, ticket: Vec<u8>) -> Self {
        Self {
            lifetime,
            age_add,
            nonce: PayloadU8::new(nonce),
            ticket: PayloadU16::new(ticket),
            exts: NewSessionTicketExtensions(vec![]),
        }
    }

    pub fn has_duplicate_extension(&self) -> bool {
        let mut seen = collections::HashSet::new();

        for ext in &self.exts.0 {
            let typ = ext.get_type().get_u16();

            if seen.contains(&typ) {
                return true;
            }
            seen.insert(typ);
        }

        false
    }

    pub fn find_extension(&self, ext: ExtensionType) -> Option<&NewSessionTicketExtension> {
        self.exts.0.iter().find(|x| x.get_type() == ext)
    }

    pub fn get_max_early_data_size(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionType::EarlyData)?;
        match *ext {
            NewSessionTicketExtension::EarlyData(ref sz) => Some(*sz),
            _ => None,
        }
    }
}

impl codec::Codec for NewSessionTicketPayloadTLS13 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.lifetime.encode(bytes);
        self.age_add.encode(bytes);
        self.nonce.encode(bytes);
        self.ticket.encode(bytes);
        self.exts.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let lifetime = u32::read(r)?;
        let age_add = u32::read(r)?;
        let nonce = PayloadU8::read(r)?;
        let ticket = PayloadU16::read(r)?;
        let exts = NewSessionTicketExtensions::read(r)?;

        Some(Self {
            lifetime,
            age_add,
            nonce,
            ticket,
            exts,
        })
    }
}

// -- RFC6066 certificate status types

/// Only supports OCSP
#[derive(Debug, Clone)]
pub struct CertificateStatus {
    pub ocsp_response: PayloadU24,
}

impl codec::Codec for CertificateStatus {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.ocsp_response.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => Some(Self {
                ocsp_response: PayloadU24::read(r)?,
            }),
            _ => None,
        }
    }
}

impl CertificateStatus {
    pub fn new(ocsp: Vec<u8>) -> Self {
        Self {
            ocsp_response: PayloadU24::new(ocsp),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.ocsp_response.0
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub enum HandshakePayload {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    HelloRetryRequest(#[extractable_ignore] HelloRetryRequest),
    Certificate(CertificatePayload),
    CertificateTLS13(CertificatePayloadTLS13),
    ServerKeyExchange(ServerKeyExchangePayload),
    CertificateRequest(CertificateRequestPayload),
    CertificateRequestTLS13(CertificateRequestPayloadTLS13),
    CertificateVerify(DigitallySignedStruct),
    ServerHelloDone,
    EndOfEarlyData,
    ClientKeyExchange(Payload),
    NewSessionTicket(NewSessionTicketPayload),
    NewSessionTicketTLS13(NewSessionTicketPayloadTLS13),
    EncryptedExtensions(EncryptedExtensions),
    KeyUpdate(KeyUpdateRequest),
    Finished(Payload),
    CertificateStatus(CertificateStatus),
    MessageHash(Payload),
    Unknown(Payload),
}

impl codec::Codec for HandshakePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        use self::HandshakePayload::*;
        match *self {
            HelloRequest | ServerHelloDone | EndOfEarlyData => {}
            ClientHello(ref x) => x.encode(bytes),
            ServerHello(ref x) => x.encode(bytes),
            HelloRetryRequest(ref x) => x.encode(bytes),
            Certificate(ref x) => x.encode(bytes),
            CertificateTLS13(ref x) => x.encode(bytes),
            ServerKeyExchange(ref x) => x.encode(bytes),
            ClientKeyExchange(ref x) => x.encode(bytes),
            CertificateRequest(ref x) => x.encode(bytes),
            CertificateRequestTLS13(ref x) => x.encode(bytes),
            CertificateVerify(ref x) => x.encode(bytes),
            NewSessionTicket(ref x) => x.encode(bytes),
            NewSessionTicketTLS13(ref x) => x.encode(bytes),
            EncryptedExtensions(ref x) => x.encode(bytes),
            KeyUpdate(ref x) => x.encode(bytes),
            Finished(ref x) => x.encode(bytes),
            CertificateStatus(ref x) => x.encode(bytes),
            MessageHash(ref x) => x.encode(bytes),
            Unknown(ref x) => x.encode(bytes),
        }
    }

    fn read(_: &mut Reader) -> Option<Self> {
        None
    }
}

#[derive(Debug, Clone, Extractable)]
#[extractable(TLSProtocolTypes)]
pub struct HandshakeMessagePayload {
    #[extractable_ignore]
    pub typ: HandshakeType,
    pub payload: HandshakePayload,
}

impl codec::Codec for HandshakeMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // encode payload to learn length
        let mut sub: Vec<u8> = Vec::new();
        self.payload.encode(&mut sub);

        // output type, length, and encoded payload
        match self.typ {
            HandshakeType::HelloRetryRequest => HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);
        codec::u24(sub.len() as u32).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Self::read_version(r, ProtocolVersion::TLSv1_2)
    }
}

impl HandshakeMessagePayload {
    pub fn read_version(r: &mut codec::Reader, vers: ProtocolVersion) -> Option<Self> {
        let mut typ = HandshakeType::read(r)?;

        let len = codec::u24::read(r)?.0 as usize;
        let mut sub = r.sub(len)?;

        let payload = match typ {
            HandshakeType::HelloRequest if sub.left() == 0 => HandshakePayload::HelloRequest,
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                let version = ProtocolVersion::read(&mut sub)?;
                let random = Random::read(&mut sub)?;

                if Ok(random) == fn_hello_retry_request_random() {
                    let mut hrr = HelloRetryRequest::read(&mut sub)?;
                    hrr.legacy_version = version;
                    hrr.random = random;
                    typ = HandshakeType::HelloRetryRequest;
                    HandshakePayload::HelloRetryRequest(hrr)
                } else {
                    let mut shp = ServerHelloPayload::read(&mut sub)?;
                    shp.legacy_version = version;
                    shp.random = random;
                    HandshakePayload::ServerHello(shp)
                }
            }
            HandshakeType::Certificate if vers == ProtocolVersion::TLSv1_3 => {
                let p = CertificatePayloadTLS13::read(&mut sub)?;
                HandshakePayload::CertificateTLS13(p)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(CertificatePayload::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                let p = ServerKeyExchangePayload::read(&mut sub)?;
                HandshakePayload::ServerKeyExchange(p)
            }
            HandshakeType::ServerHelloDone => {
                if sub.any_left() {
                    return None;
                }
                HandshakePayload::ServerHelloDone
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(Payload::read(&mut sub))
            }
            HandshakeType::CertificateRequest if vers == ProtocolVersion::TLSv1_3 => {
                let p = CertificateRequestPayloadTLS13::read(&mut sub)?;
                HandshakePayload::CertificateRequestTLS13(p)
            }
            HandshakeType::CertificateRequest => {
                let p = CertificateRequestPayload::read(&mut sub)?;
                HandshakePayload::CertificateRequest(p)
            }
            HandshakeType::CertificateVerify => {
                HandshakePayload::CertificateVerify(DigitallySignedStruct::read(&mut sub)?)
            }
            HandshakeType::NewSessionTicket if vers == ProtocolVersion::TLSv1_3 => {
                let p = NewSessionTicketPayloadTLS13::read(&mut sub)?;
                HandshakePayload::NewSessionTicketTLS13(p)
            }
            HandshakeType::NewSessionTicket => {
                let p = NewSessionTicketPayload::read(&mut sub)?;
                HandshakePayload::NewSessionTicket(p)
            }
            HandshakeType::EncryptedExtensions => {
                HandshakePayload::EncryptedExtensions(EncryptedExtensions::read(&mut sub)?)
            }
            HandshakeType::KeyUpdate => {
                HandshakePayload::KeyUpdate(KeyUpdateRequest::read(&mut sub)?)
            }
            HandshakeType::EndOfEarlyData => {
                if sub.any_left() {
                    return None;
                }
                HandshakePayload::EndOfEarlyData
            }
            HandshakeType::Finished => HandshakePayload::Finished(Payload::read(&mut sub)),
            HandshakeType::CertificateStatus => {
                HandshakePayload::CertificateStatus(CertificateStatus::read(&mut sub)?)
            }
            HandshakeType::MessageHash => {
                // does not appear on the wire
                return None;
            }
            HandshakeType::HelloRetryRequest => {
                // not legal on wire
                return None;
            }
            _ => HandshakePayload::Unknown(Payload::read(&mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(Self { typ, payload })
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            typ: HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(KeyUpdateRequest::UpdateNotRequested),
        }
    }

    pub fn get_encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut ret = self.get_encoding();

        let binder_len = match self.payload {
            HandshakePayload::ClientHello(ref ch) => match ch.extensions.0.last() {
                Some(ClientExtension::PresharedKey(ref offer)) => {
                    let mut binders_encoding = Vec::new();
                    offer.binders.encode(&mut binders_encoding);
                    binders_encoding.len()
                }
                _ => 0,
            },
            _ => 0,
        };

        let ret_len = ret.len() - binder_len;
        ret.truncate(ret_len);
        ret
    }

    pub fn build_handshake_hash(hash: &[u8]) -> Self {
        Self {
            typ: HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.to_vec())),
        }
    }
}
