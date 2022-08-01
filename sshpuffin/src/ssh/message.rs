use std::io::Read;

use futures::AsyncWriteExt;
use log::debug;
use puffin::{
    codec::{Codec, Reader},
    error::Error,
    protocol::{Message, MessageDeframer, OpaqueMessage},
};

#[derive(Clone, Debug)]
pub enum RawMessage {
    Banner(String),
    Packet(BinaryPacket),
}

#[derive(Clone, Debug)]
pub struct BinaryPacket {
    payload: Vec<u8>,
    random_padding: Vec<u8>,
    mac: Vec<u8>,
}

impl Codec for BinaryPacket {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.payload.len() as u32).encode(bytes);
        (self.random_padding.len() as u8).encode(bytes);
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.random_padding);
        bytes.extend_from_slice(&self.mac);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let packet_length = u32::read(reader)?;
        let padding_length = u8::read(reader)?;
        let payload = Vec::from(reader.take(packet_length as usize - padding_length as usize - 1)?);
        let random_padding = Vec::from(reader.take(padding_length as usize)?);
        let mac = Vec::from(reader.take(0 as usize)?); // TODO: parse non-zero

        Some(BinaryPacket {
            payload,
            random_padding,
            mac,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NameList {
    names: Vec<u8>,
}

impl Codec for NameList {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.names.len() as u32).encode(bytes);
        bytes.extend_from_slice(&self.names);
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let length = u32::read(reader)?;
        let names = Vec::from(reader.take(length as usize)?);
        Some(NameList { names })
    }
}

#[derive(Clone, Debug)]
pub enum SshMessage {
    KexInit(KexInitMessage),
    KexEcdhInit(KexEcdhInitMessage),
    KexEcdhReply(KexEcdhReplyMessage),
}

#[derive(Clone, Debug)]
pub struct KexInitMessage {
    pub cookie: [u8; 16],
    pub kex_algorithms: NameList,
    pub server_host_key_algorithms: NameList,
    pub encryption_algorithms_server_to_client: NameList,
    pub encryption_algorithms_client_to_server: NameList,
    pub mac_algorithms_client_to_server: NameList,
    pub mac_algorithms_server_to_client: NameList,
    pub compression_algorithms_client_to_server: NameList,
    pub compression_algorithms_server_to_client: NameList,
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
        Some(KexInitMessage {
            cookie,
            kex_algorithms: NameList::read(reader)?,
            server_host_key_algorithms: NameList::read(reader)?,
            encryption_algorithms_server_to_client: NameList::read(reader)?,
            encryption_algorithms_client_to_server: NameList::read(reader)?,
            mac_algorithms_client_to_server: NameList::read(reader)?,
            mac_algorithms_server_to_client: NameList::read(reader)?,
            compression_algorithms_client_to_server: NameList::read(reader)?,
            compression_algorithms_server_to_client: NameList::read(reader)?,
            languages_client_to_server: NameList::read(reader)?,
            languages_server_to_client: NameList::read(reader)?,
            first_kex_packet_follows: u8::read(reader)? != 0,
        })
    }
}
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
            30u8 => Some(SshMessage::KexEcdhInit(KexEcdhInitMessage::read(reader)?)),
            31u8 => Some(SshMessage::KexEcdhReply(KexEcdhReplyMessage::read(reader)?)),
            _ => None,
        }
    }
}

impl TryFrom<&RawMessage> for SshMessage {
    type Error = String;

    fn try_from(value: &RawMessage) -> Result<Self, Self::Error> {
        match value {
            RawMessage::Banner(_) => Err("Can not parse on banner".to_string()),
            RawMessage::Packet(packet) => {
                let mut reader = Reader::init(&packet.payload);
                SshMessage::read(&mut reader).ok_or_else(|| "Can not parse payload".to_string())
            }
        }
    }
}
impl Message<RawMessage> for SshMessage {
    fn create_opaque(&self) -> RawMessage {
        todo!()
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self)
    }
}

impl OpaqueMessage<SshMessage> for RawMessage {
    fn encode(&self) -> Vec<u8> {
        todo!() // TODO: replace with codec
    }

    fn into_message(self) -> Result<SshMessage, Error> {
        todo!() // FIXME: does not necessarily make sense
    }

    fn debug(&self, info: &str) {
        debug!("{}: {:?}", info, self)
    }
}

impl Codec for RawMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            RawMessage::Banner(banner) => {
                bytes.extend_from_slice(banner.as_bytes());
            }
            RawMessage::Packet(_) => {}
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let banner = "SSH-2.0-libssh_0.10.90\r\n";
        let banner_bytes = banner.as_bytes();

        let is_banner = reader.peek(banner_bytes.len())? == banner_bytes;

        if is_banner {
            reader.take(banner_bytes.len())?;
            Some(RawMessage::Banner(banner.to_string()))
        } else {
            Some(RawMessage::Packet(BinaryPacket::read(reader)?))
        }
    }
}
