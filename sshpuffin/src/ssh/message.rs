use comparable::Comparable;
use puffin::codec::{Codec, Reader};
use puffin::error::Error;
use puffin::protocol::{Extractable, OpaqueProtocolMessage, ProtocolMessage, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, dummy_extract_knowledge};

use crate::protocol::SshProtocolTypes;
use crate::query::SshQueryMatcher;

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

#[derive(Clone, Debug, Comparable, PartialEq)]
pub enum RawSshMessage {
    Banner(String),
    Packet(BinaryPacket),
    OnWire(OnWireData),
}

#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct BinaryPacket {
    payload: Vec<u8>,
    random_padding: Vec<u8>,
    mac: Vec<u8>,
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
        let payload_length = packet_length as usize - padding_length as usize - 1;
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

#[derive(Clone, Debug, Comparable, PartialEq)]
pub enum SshMessage {
    KexInit(KexInitMessage),
    KexEcdhInit(KexEcdhInitMessage),
    KexEcdhReply(KexEcdhReplyMessage),
    NewKeys,
}

declare_name_list!(KexAlgorithms);
declare_name_list!(SignatureSchemes);
declare_name_list!(EncryptionAlgorithms);
declare_name_list!(MacAlgorithms);
declare_name_list!(CompressionAlgorithms);

#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct KexInitMessage {
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
#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct KexEcdhInitMessage {
    pub ephemeral_public_key: Vec<u8>,
}

impl Codec for KexEcdhInitMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.ephemeral_public_key.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.ephemeral_public_key);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let length = u32::read(reader)?;
        let ephemeral_public_key = Vec::from(reader.take(length as usize)?);
        Some(KexEcdhInitMessage {
            ephemeral_public_key,
        })
    }
}

#[derive(Clone, Debug, Comparable, PartialEq)]
pub struct KexEcdhReplyMessage {
    pub public_host_key: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Codec for KexEcdhReplyMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.public_host_key.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.public_host_key);
        (self.ephemeral_public_key.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.ephemeral_public_key);
        (self.signature.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.signature);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let length = u32::read(reader)?;
        let public_host_key = Vec::from(reader.take(length as usize)?);
        let length = u32::read(reader)?;
        let ephemeral_public_key = Vec::from(reader.take(length as usize)?);
        let length = u32::read(reader)?;
        let signature = Vec::from(reader.take(length as usize)?);
        Some(KexEcdhReplyMessage {
            public_host_key,
            ephemeral_public_key,
            signature,
        })
    }
}

impl Codec for SshMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
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
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let typ = u8::read(reader)?;

        match typ {
            20u8 => Some(SshMessage::KexInit(KexInitMessage::read(reader)?)),
            21u8 => Some(SshMessage::NewKeys),
            30u8 => Some(SshMessage::KexEcdhInit(KexEcdhInitMessage::read(reader)?)),
            31u8 => Some(SshMessage::KexEcdhReply(KexEcdhReplyMessage::read(reader)?)),
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

impl Extractable<SshProtocolTypes> for SshMessage {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshProtocolTypes>>,
        matcher: Option<SshQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        match &self {
            SshMessage::KexInit(KexInitMessage {
                cookie,
                kex_algorithms,
                server_host_key_algorithms,
                encryption_algorithms_server_to_client,
                encryption_algorithms_client_to_server,
                mac_algorithms_client_to_server,
                mac_algorithms_server_to_client,
                compression_algorithms_client_to_server,
                compression_algorithms_server_to_client,
                languages_client_to_server,
                languages_server_to_client,
                first_kex_packet_follows,
            }) => {
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: cookie,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: kex_algorithms,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: server_host_key_algorithms,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: encryption_algorithms_server_to_client,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: encryption_algorithms_client_to_server,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: mac_algorithms_client_to_server,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: mac_algorithms_server_to_client,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: compression_algorithms_client_to_server,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: compression_algorithms_server_to_client,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: languages_client_to_server,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: languages_server_to_client,
                });
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: first_kex_packet_follows,
                });
            }
            SshMessage::KexEcdhInit(KexEcdhInitMessage {
                ephemeral_public_key,
            }) => {
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: ephemeral_public_key,
                });
            }
            SshMessage::KexEcdhReply(KexEcdhReplyMessage {
                public_host_key,
                ephemeral_public_key,
                signature,
            }) => {
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: public_host_key,
                });

                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: ephemeral_public_key,
                });

                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: signature,
                });
            }

            SshMessage::NewKeys => {}
        };

        Ok(())
    }
}

impl OpaqueProtocolMessage<SshProtocolTypes> for RawSshMessage {
    fn debug(&self, info: &str) {
        log::debug!("{}: {:?}", info, self)
    }
}

dummy_extract_knowledge!(SshProtocolTypes, Vec<u8>);

impl Extractable<SshProtocolTypes> for RawSshMessage {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, SshProtocolTypes>>,
        matcher: Option<SshQueryMatcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        match &self {
            RawSshMessage::Banner(banner) => {
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: banner,
                });
            }
            RawSshMessage::Packet(_) => {}
            RawSshMessage::OnWire(onwire) => {
                knowledges.push(Knowledge {
                    source,
                    matcher,
                    data: onwire,
                });
            }
        };
        Ok(())
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
        let banner = "SSH-2.0-libssh_0.10.4\r\n"; // FIXME: hardcoded version of libssh
        let banner_bytes = banner.as_bytes();

        let is_banner = if let Some(received) = reader.peek(banner_bytes.len()) {
            received == banner_bytes
        } else {
            false
        };

        if is_banner {
            reader.take(banner_bytes.len())?;
            Some(RawSshMessage::Banner(banner.to_string()))
        } else {
            Some(RawSshMessage::Packet(BinaryPacket::read(reader)?))
        }
    }
}

atom_extract_knowledge!(SshProtocolTypes, String);
atom_extract_knowledge!(SshProtocolTypes, OnWireData);
atom_extract_knowledge!(SshProtocolTypes, u8);
atom_extract_knowledge!(SshProtocolTypes, u64);
atom_extract_knowledge!(SshProtocolTypes, NameList);
atom_extract_knowledge!(SshProtocolTypes, CompressionAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, EncryptionAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, KexAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, [u8; 16]);
atom_extract_knowledge!(SshProtocolTypes, MacAlgorithms);
atom_extract_knowledge!(SshProtocolTypes, SignatureSchemes);
dummy_extract_knowledge!(SshProtocolTypes, bool);
