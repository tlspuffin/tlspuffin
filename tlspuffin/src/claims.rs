use std::fmt::Debug;

use puffin::agent::{AgentName, AgentType, TLSVersion};
use puffin::algebra::dynamic_function::TypeShape;
use puffin::claims::Claim;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};
use smallvec::SmallVec;

use crate::protocol::TLSProtocolTypes;

#[cfg(not(has_instr = "claimer"))]
pub mod dummy_registration {
    #[no_mangle]
    pub extern "C" fn register_claimer(
        _tls_like: *const ::std::os::raw::c_void,
        _claimer: security_claims::claim_t,
        _ctx: *mut ::std::os::raw::c_void,
    ) {
        // NOTE dummy implementation when the C ffi implementation is missing
    }

    #[no_mangle]
    pub extern "C" fn deregister_claimer(
        _tls_like: *const ::std::os::raw::c_void,
    ) -> *mut ::std::os::raw::c_void {
        // NOTE dummy implementation when the C ffi implementation is missing
        ::std::ptr::null_mut()
    }
}

#[derive(Debug, Clone)]
pub struct TlsTranscript(pub [u8; 64], pub i32);

impl codec::Codec for TlsTranscript {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.0);
        b.extend(self.1.to_ne_bytes());
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        let t: [u8; 64] = <[u8; 64]>::try_from(r.take(64)?).ok()?;
        let x = r.take(4)?;
        Some(TlsTranscript(t, i32::from_ne_bytes(x.try_into().unwrap())))
    }
}

#[derive(Debug, Clone)]
pub struct TranscriptClientHello(pub TlsTranscript);
impl Transcript for TranscriptClientHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

impl codec::Codec for TranscriptClientHello {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptClientHello)
    }
}

dummy_extract_knowledge!(TLSProtocolTypes, TranscriptClientHello);

#[derive(Debug, Clone)]
pub struct TranscriptPartialClientHello(pub TlsTranscript);
impl Transcript for TranscriptPartialClientHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

impl codec::Codec for TranscriptPartialClientHello {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptPartialClientHello)
    }
}

dummy_extract_knowledge!(TLSProtocolTypes, TranscriptPartialClientHello);

#[derive(Debug, Clone)]
pub struct TranscriptServerHello(pub TlsTranscript);
impl Transcript for TranscriptServerHello {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

impl codec::Codec for TranscriptServerHello {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptServerHello)
    }
}

dummy_extract_knowledge!(TLSProtocolTypes, TranscriptServerHello);

#[derive(Debug, Clone)]
pub struct TranscriptServerFinished(pub TlsTranscript);
impl Transcript for TranscriptServerFinished {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

impl codec::Codec for TranscriptServerFinished {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptServerFinished)
    }
}

dummy_extract_knowledge!(TLSProtocolTypes, TranscriptServerFinished);

#[derive(Debug, Clone)]
pub struct TranscriptClientFinished(pub TlsTranscript);
impl Transcript for TranscriptClientFinished {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}

impl codec::Codec for TranscriptClientFinished {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptClientFinished)
    }
}

dummy_extract_knowledge!(TLSProtocolTypes, TranscriptClientFinished);

#[derive(Debug, Clone)]
pub struct TranscriptCertificate(pub TlsTranscript);
impl Transcript for TranscriptCertificate {
    fn as_slice(&self) -> &[u8] {
        let transcript = &self.0;
        &transcript.0[..transcript.1 as usize]
    }
}
dummy_extract_knowledge!(TLSProtocolTypes, TranscriptCertificate);

impl codec::Codec for TranscriptCertificate {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.as_slice())
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <TlsTranscript as codec::Codec>::read(r).map(TranscriptCertificate)
    }
}

pub trait Transcript {
    fn as_slice(&self) -> &[u8];
}

#[derive(Debug, Clone)]
pub struct ClientHello;
// We do not expect to encode/read claims!
dummy_extract_knowledge_codec!(TLSProtocolTypes, ClientHello);
#[derive(Debug, Clone)]
pub struct ServerHello;
dummy_extract_knowledge_codec!(TLSProtocolTypes, ServerHello);
#[derive(Debug, Clone)]
pub struct Certificate;
dummy_extract_knowledge_codec!(TLSProtocolTypes, Certificate);
#[derive(Debug, Clone)]
pub struct CertificateVerify;
dummy_extract_knowledge_codec!(TLSProtocolTypes, CertificateVerify);
#[derive(Debug, Clone)]
pub struct Finished {
    pub outbound: bool,

    pub client_random: SmallVec<[u8; 32]>,
    pub server_random: SmallVec<[u8; 32]>,
    pub session_id: SmallVec<[u8; 32]>,

    pub authenticate_peer: bool,
    /// DER encoded certificate. DER works, because:
    ///     DER is a subset of BER providing for exactly one way to encode an ASN.1 value.
    ///     (<https://en.wikipedia.org/wiki/X.690#DER_encoding>)
    pub peer_certificate: SmallVec<[u8; 32]>,

    pub master_secret: SmallVec<[u8; 32]>,

    pub chosen_cipher: u16,
    pub available_ciphers: SmallVec<[u16; 20]>,

    pub signature_algorithm: i32,
    pub peer_signature_algorithm: i32,
    /* TODO: tmp_skey_type peer_tmp_skey_type
                   // TLS 1.2
                   if let Some(server_kex) = claims.iter().find(|(_agent, claim)| {
                       claim.write == 1
                           && claim.server == 1
                           && claim.typ == ClaimType::CLAIM_SERVER_DONE
                   }) {
                       if server_kex.1.tmp_skey_type != client.peer_tmp_skey_type {
                           return Some("Mismatching ephemeral kex method");
                       }
                   } else {
                       return Some("Server Done not found in server claims");
                   }
                   // TLS 1.3
                   if client.tmp_skey_type != server.tmp_skey_type {
                       return Some("Mismatching ephemeral kex method");
                   }
    */
    /* TODO: tmp_skey_group_id
                   // TLS 1.3
                    if client.tmp_skey_group_id != server.tmp_skey_group_id {
                        return Some("Mismatching groups");
                    }
    */
}
dummy_extract_knowledge_codec!(TLSProtocolTypes, Finished);

#[derive(Debug, Clone)]
pub enum ClaimDataTranscript {
    ClientHello(TranscriptClientHello),
    PartialClientHello(TranscriptPartialClientHello),
    ServerHello(TranscriptServerHello),
    Certificate(TranscriptCertificate),
    ServerFinished(TranscriptServerFinished),
    ClientFinished(TranscriptClientFinished),
}

#[derive(Debug, Clone)]
pub enum ClaimDataMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
}

#[derive(Debug, Clone)]
pub enum ClaimData {
    Transcript(ClaimDataTranscript),
    Message(ClaimDataMessage),
}

#[derive(Debug, Clone)]
pub struct TlsClaim {
    pub agent_name: AgentName,
    pub origin: AgentType,
    pub protocol_version: TLSVersion,
    pub data: ClaimData,
}

dummy_codec!(TLSProtocolTypes, TlsClaim);

impl Claim for TlsClaim {
    type PT = TLSProtocolTypes;

    fn agent_name(&self) -> AgentName {
        self.agent_name
    }

    fn id(&self) -> TypeShape<TLSProtocolTypes> {
        type Message = ClaimDataMessage;
        type Transcript = ClaimDataTranscript;
        type Type = TypeShape<TLSProtocolTypes>;
        match &self.data {
            ClaimData::Message(message) => match message {
                Message::ClientHello(_) => Type::of::<ClientHello>(),
                Message::ServerHello(_) => Type::of::<ServerHello>(),
                Message::Certificate(_) => Type::of::<Certificate>(),
                Message::CertificateVerify(_) => Type::of::<CertificateVerify>(),
                Message::Finished(_) => Type::of::<Finished>(),
            },
            ClaimData::Transcript(transcript) => match transcript {
                Transcript::ClientHello(_) => Type::of::<TranscriptClientHello>(),
                Transcript::PartialClientHello(_) => Type::of::<TranscriptPartialClientHello>(),
                Transcript::ServerHello(_) => Type::of::<TranscriptServerHello>(),
                Transcript::ServerFinished(_) => Type::of::<TranscriptServerFinished>(),
                Transcript::ClientFinished(_) => Type::of::<TranscriptClientFinished>(),
                Transcript::Certificate(_) => Type::of::<TranscriptCertificate>(),
            },
        }
    }

    fn inner(&self) -> Box<dyn EvaluatedTerm<TLSProtocolTypes>> {
        type Message = ClaimDataMessage;
        type Transcript = ClaimDataTranscript;
        match &self.data {
            ClaimData::Message(message) => match message {
                Message::ClientHello(claim) => claim.boxed(),
                Message::ServerHello(claim) => claim.boxed(),
                Message::Certificate(claim) => claim.boxed(),
                Message::CertificateVerify(claim) => claim.boxed(),
                Message::Finished(claim) => claim.boxed(),
            },
            ClaimData::Transcript(transcript) => match transcript {
                Transcript::ClientHello(claim) => claim.boxed(),
                Transcript::PartialClientHello(claim) => claim.boxed(),
                Transcript::ServerHello(claim) => claim.boxed(),
                Transcript::ServerFinished(claim) => claim.boxed(),
                Transcript::ClientFinished(claim) => claim.boxed(),
                Transcript::Certificate(claim) => claim.boxed(),
            },
        }
    }
}

impl Extractable<TLSProtocolTypes> for TlsClaim {
    fn extract_knowledge(
        &self,
        _knowledges: &mut Vec<puffin::trace::Knowledge<TLSProtocolTypes>>,
        _matcher: Option<<TLSProtocolTypes as puffin::protocol::ProtocolTypes>::Matcher>,
        _source: &puffin::trace::Source,
    ) -> Result<(), puffin::error::Error> {
        Ok(())
    }
}

pub mod claims_helpers {
    use puffin::agent::TLSVersion;
    use smallvec::SmallVec;

    use crate::claims::{
        ClaimData, ClaimDataMessage, ClaimDataTranscript, Finished, TlsTranscript,
        TranscriptCertificate, TranscriptClientFinished, TranscriptClientHello,
        TranscriptPartialClientHello, TranscriptServerFinished, TranscriptServerHello,
    };

    pub fn to_claim_data(
        protocol_version: TLSVersion,
        claim: security_claims::Claim,
    ) -> Option<ClaimData> {
        match claim.typ {
            // Transcripts
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH => Some(ClaimData::Transcript(
                ClaimDataTranscript::ClientHello(TranscriptClientHello(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_PARTIAL_CH => Some(ClaimData::Transcript(
                ClaimDataTranscript::PartialClientHello(TranscriptPartialClientHello(
                    TlsTranscript(claim.transcript.data, claim.transcript.length),
                )),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SH => Some(ClaimData::Transcript(
                ClaimDataTranscript::ServerHello(TranscriptServerHello(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_SERVER_FIN => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                    TranscriptServerFinished(TlsTranscript(
                        claim.transcript.data,
                        claim.transcript.length,
                    )),
                )))
            }
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CLIENT_FIN => {
                Some(ClaimData::Transcript(ClaimDataTranscript::ClientFinished(
                    TranscriptClientFinished(TlsTranscript(
                        claim.transcript.data,
                        claim.transcript.length,
                    )),
                )))
            }
            security_claims::ClaimType::CLAIM_TRANSCRIPT_CH_CERT => Some(ClaimData::Transcript(
                ClaimDataTranscript::Certificate(TranscriptCertificate(TlsTranscript(
                    claim.transcript.data,
                    claim.transcript.length,
                ))),
            )),
            // Messages
            // Transcripts in these messages are not up-to-date. They get updated after the Message
            // has been processed
            security_claims::ClaimType::CLAIM_FINISHED => {
                Some(ClaimData::Message(ClaimDataMessage::Finished(Finished {
                    outbound: claim.write > 0,
                    client_random: SmallVec::from(claim.client_random.data),
                    server_random: SmallVec::from(claim.server_random.data),
                    session_id: SmallVec::from_slice(
                        &claim.session_id.data[..claim.session_id.length as usize],
                    ),
                    authenticate_peer: false,             // FIXME
                    peer_certificate: Default::default(), // FIXME
                    master_secret: match protocol_version {
                        TLSVersion::V1_3 => SmallVec::from_slice(&claim.master_secret.secret),
                        TLSVersion::V1_2 => SmallVec::from_slice(&claim.master_secret_12.secret),
                    },
                    chosen_cipher: claim.chosen_cipher.data,
                    available_ciphers: SmallVec::from_iter(
                        claim.available_ciphers.ciphers[..claim.available_ciphers.length as usize]
                            .iter()
                            .map(|cipher| cipher.data),
                    ),
                    signature_algorithm: claim.signature_algorithm,
                    peer_signature_algorithm: claim.peer_signature_algorithm,
                })))
            }
            security_claims::ClaimType::CLAIM_CLIENT_HELLO => None,
            security_claims::ClaimType::CLAIM_CCS => None,
            security_claims::ClaimType::CLAIM_END_OF_EARLY_DATA => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE => None,
            security_claims::ClaimType::CLAIM_KEY_EXCHANGE => None,
            // FIXME it is weird that this returns the correct transcript
            security_claims::ClaimType::CLAIM_CERTIFICATE_VERIFY => {
                if claim.write == 0 {
                    Some(ClaimData::Transcript(ClaimDataTranscript::ServerFinished(
                        TranscriptServerFinished(TlsTranscript(
                            claim.transcript.data,
                            claim.transcript.length,
                        )),
                    )))
                } else {
                    None
                }
            }
            security_claims::ClaimType::CLAIM_KEY_UPDATE => None,
            security_claims::ClaimType::CLAIM_HELLO_REQUEST => None,
            security_claims::ClaimType::CLAIM_SERVER_HELLO => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE_REQUEST => None,
            security_claims::ClaimType::CLAIM_SERVER_DONE => None,
            security_claims::ClaimType::CLAIM_SESSION_TICKET => None,
            security_claims::ClaimType::CLAIM_CERTIFICATE_STATUS => None,
            security_claims::ClaimType::CLAIM_EARLY_DATA => None,
            security_claims::ClaimType::CLAIM_ENCRYPTED_EXTENSIONS => None,
            _ => None,
        }
    }
}
