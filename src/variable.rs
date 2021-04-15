use crate::agent::{Agent, NO_AGENT};
use rand;
use rand::seq::SliceRandom;
use rustls::internal::msgs::enums::{Compression, ServerNameType, NamedGroup};
use rustls::internal::msgs::handshake::{ClientExtension, Random, SessionID, KeyShareEntry};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use std::any::Any;
use rustls::internal::msgs::base::PayloadU16;
use rand::random;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct Metadata {
    owner: &'static Agent,
}

// VariableData trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny {
    fn get_metadata(&self) -> &Metadata;
    fn get_owner(&self) -> &Agent {
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
            metadata: Metadata { owner: &NO_AGENT },
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
            metadata: Metadata { owner: &NO_AGENT },
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
            metadata: Metadata { owner: &NO_AGENT },
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
            metadata: Metadata { owner: &NO_AGENT },
            data: *vec![
                CipherSuite::TLS13_AES_128_CCM_SHA256,
                CipherSuite::TLS13_AES_128_CCM_8_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
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
            metadata: Metadata { owner: &NO_AGENT },
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

impl VariableData for ExtensionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn random_value() -> Self
    where
        Self: Sized,
    {
        let server_name: ClientExtension =
            ClientExtension::ServerName(vec![ServerName {
                typ: ServerNameType::HostName,
                payload: ServerNamePayload::HostName(
                    webpki::DNSNameRef::try_from_ascii_str("maxammann.org")
                        .unwrap()
                        .to_owned(),
                ),
            }]);

        let supported_groups: ClientExtension =
            ClientExtension::NamedGroups(vec![NamedGroup::X25519]);
        let signature_algorithms: ClientExtension =
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ED25519]);

        let key = Vec::from(rand::random::<[u8; 32]>()); // 32 byte public key
        let key_share: ClientExtension =
            ClientExtension::KeyShare(vec![KeyShareEntry {
                group: NamedGroup::X25519,
                payload: PayloadU16::new(key)
            }]);

        let supported_versions: ClientExtension =
            ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]);
        ExtensionData {
            metadata: Metadata { owner: &NO_AGENT },
            data: vec![server_name, supported_groups, signature_algorithms, key_share, supported_versions]
                .choose(&mut rand::thread_rng())
                .unwrap()
                .clone(), // avoid clone
        }
    }
}
