use std::any::Any;

use rand;
use rand::random;
use rand::seq::SliceRandom;
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::{Compression, NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{ClientExtension, KeyShareEntry, Random, SessionID};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};

use crate::agent::{NO_AGENT, AgentName};

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct Metadata {
    owner: AgentName,
}

// VariableData trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny {
    fn get_metadata(&self) -> &Metadata;
    fn get_owner(&self) -> AgentName {
        self.get_metadata().owner
    }

    fn random_value() -> Self
        where
            Self: Sized;
}

// ClientVersion

pub struct ClientVersionData {
    metadata: Metadata,
    pub data: ProtocolVersion,
}

impl VariableData for ClientVersionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        ClientVersionData {
            metadata: Metadata { owner: NO_AGENT },
            data: ProtocolVersion::TLSv1_3,
        }
    }
}

// Random

pub struct RandomData {
    pub metadata: Metadata,
    pub data: Random,
}

impl VariableData for RandomData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        let random_data: [u8; 32] = random();
        RandomData {
            metadata: Metadata { owner: NO_AGENT },
            data: Random::from_slice(&random_data),
        }
    }
}

// SessionId

pub struct SessionIDData {
    pub metadata: Metadata,
    pub data: SessionID,
}

impl VariableData for SessionIDData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        let random_data: [u8; 32] = random();
        SessionIDData {
            metadata: Metadata { owner: NO_AGENT },
            data: SessionID::new(&random_data),
        }
    }
}

// CipherSuite

pub struct CipherSuiteData {
    pub metadata: Metadata,
    pub data: CipherSuite,
}

impl VariableData for CipherSuiteData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        CipherSuiteData {
            metadata: Metadata { owner: NO_AGENT },
            data: *vec![
                CipherSuite::TLS13_AES_128_CCM_SHA256,
                CipherSuite::TLS13_AES_128_CCM_8_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            ]
                .choose(&mut rand::thread_rng())
                .unwrap(),
        }
    }
}

// Compression

pub struct CompressionData {
    pub metadata: Metadata,
    pub data: Compression,
}

impl VariableData for CompressionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        CompressionData {
            metadata: Metadata { owner: NO_AGENT },
            data: *vec![Compression::Null, Compression::Deflate, Compression::LSZ]
                .choose(&mut rand::thread_rng())
                .unwrap(),
        }
    }
}

// Compression

pub struct ExtensionData {
    pub metadata: Metadata,
    pub data: ClientExtension,
}

impl ExtensionData {
    pub fn server_name(dns_name: &str) -> ClientExtension {
        ClientExtension::ServerName(vec![ServerName {
            typ: ServerNameType::HostName,
            payload: ServerNamePayload::HostName(
                webpki::DNSNameRef::try_from_ascii_str(dns_name)
                    .unwrap()
                    .to_owned(),
            ),
        }])
    }

    pub fn supported_groups() -> ClientExtension {
        ClientExtension::NamedGroups(vec![NamedGroup::X25519])
    }

    pub fn signature_algorithms() -> ClientExtension {
        ClientExtension::SignatureAlgorithms(vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256
        ])
    }

    pub fn key_share() -> ClientExtension {
        let key = Vec::from(rand::random::<[u8; 32]>()); // 32 byte public key
        ClientExtension::KeyShare(vec![KeyShareEntry {
            group: NamedGroup::X25519,
            payload: PayloadU16::new(key),
        }])
    }

    pub fn supported_versions() -> ClientExtension {
        ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3])
    }

    pub fn static_extension(extension: ClientExtension) -> Self {
        ExtensionData {
            metadata: Metadata { owner: NO_AGENT },
            data: extension,
        }
    }
}

impl VariableData for ExtensionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
        where
            Self: Sized,
    {
        let server_name: ClientExtension = Self::server_name("maxammann.org");

        let supported_groups: ClientExtension = Self::supported_groups();
        let signature_algorithms: ClientExtension = Self::signature_algorithms();
        let key_share: ClientExtension = Self::key_share();
        let supported_versions: ClientExtension = Self::supported_versions();

        ExtensionData {
            metadata: Metadata { owner: NO_AGENT },
            data: vec![
                server_name,
                supported_groups,
                signature_algorithms,
                key_share,
                supported_versions,
            ]
                .choose(&mut rand::thread_rng())
                .unwrap()
                .clone(), // avoid clone
        }
    }
}
