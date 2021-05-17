use std::any::{Any, TypeId};

use dyn_clone::DynClone;
use rand;
use rand::random;
use rand::seq::SliceRandom;
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::enums::{Compression, NamedGroup, ServerNameType};
use rustls::internal::msgs::handshake::{
    ClientExtension, KeyShareEntry, Random, ServerExtension, SessionID,
};
use rustls::internal::msgs::handshake::{ServerName, ServerNamePayload};

use crate::agent::AgentName;
use crate::term::Variable;

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
pub struct Metadata {
    pub owner: AgentName,
}

// VariableData trait should include AsAny so that `as_any` is in its vtable.
pub trait VariableData: Any + AsAny + DynClone {
    fn get_metadata(&self) -> &Metadata;
    fn get_owner(&self) -> AgentName {
        self.get_metadata().owner
    }
    fn get_data(&self) -> &dyn Any;

    fn get_type_id(&self) -> TypeId {
        self.get_data().type_id()
    }

    fn random_value(agent: AgentName) -> Self
        where
            Self: Sized;

    fn clone_data(&self) -> Box<dyn Any>;
}

dyn_clone::clone_trait_object!(VariableData);

// Client/Server Version
#[derive(Clone)]
pub struct VersionData {
    pub metadata: Metadata,
    pub data: ProtocolVersion,
}

impl VariableData for VersionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        VersionData {
            metadata: Metadata { owner },
            data: ProtocolVersion::TLSv1_3,
        }
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// Random
#[derive(Clone)]
pub struct RandomData {
    pub metadata: Metadata,
    pub data: Random,
}

impl VariableData for RandomData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        let random_data: [u8; 32] = random();
        RandomData {
            metadata: Metadata { owner },
            data: Random::from_slice(&random_data),
        }
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// AgreedCipherSuite
#[derive(Clone)]
pub struct AgreedCipherSuiteData {
    pub metadata: Metadata,
    pub data: CipherSuite,
}

impl VariableData for AgreedCipherSuiteData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        todo!()
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// AgreedCompression
#[derive(Clone)]
pub struct AgreedCompressionData {
    pub metadata: Metadata,
    pub data: Compression,
}

impl VariableData for AgreedCompressionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        todo!()
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// SessionId
#[derive(Clone)]
pub struct SessionIDData {
    pub metadata: Metadata,
    pub data: SessionID,
}

impl VariableData for SessionIDData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        let random_data: [u8; 32] = random();
        SessionIDData {
            metadata: Metadata { owner },
            data: SessionID::new(&random_data),
        }
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// CipherSuite
#[derive(Clone)]
pub struct CipherSuiteData {
    pub metadata: Metadata,
    pub data: CipherSuite,
}

impl CipherSuiteData {
    pub fn static_extension(owner: AgentName, cipher_suite: CipherSuite) -> Self {
        Self {
            metadata: Metadata { owner },
            data: cipher_suite,
        }
    }
}

impl VariableData for CipherSuiteData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        CipherSuiteData {
            metadata: Metadata { owner },
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

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// Compression
#[derive(Clone)]
pub struct CompressionData {
    pub metadata: Metadata,
    pub data: Compression,
}

impl CompressionData {
    pub fn static_extension(owner: AgentName, compression: Compression) -> Self {
        Self {
            metadata: Metadata { owner },
            data: compression,
        }
    }
}

impl VariableData for CompressionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        CompressionData {
            metadata: Metadata { owner },
            data: *vec![Compression::Null, Compression::Deflate, Compression::LSZ]
                .choose(&mut rand::thread_rng())
                .unwrap(),
        }
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// Client Extensions
#[derive(Clone)]
pub struct ClientExtensionData {
    pub metadata: Metadata,
    pub data: ClientExtension,
}

impl ClientExtensionData {
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
            SignatureScheme::RSA_PSS_SHA256,
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

    pub fn static_extension(owner: AgentName, extension: ClientExtension) -> Self {
        Self {
            metadata: Metadata { owner },
            data: extension,
        }
    }
}

impl VariableData for ClientExtensionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        let server_name: ClientExtension = Self::server_name("maxammann.org");

        let supported_groups: ClientExtension = Self::supported_groups();
        let signature_algorithms: ClientExtension = Self::signature_algorithms();
        let key_share: ClientExtension = Self::key_share();
        let supported_versions: ClientExtension = Self::supported_versions();

        ClientExtensionData {
            metadata: Metadata { owner },
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

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}

// Server Extensions
#[derive(Clone)]
pub struct ServerExtensionData {
    pub metadata: Metadata,
    pub data: ServerExtension,
}

impl ServerExtensionData {
    pub fn static_extension(owner: AgentName, extension: ServerExtension) -> Self {
        Self {
            metadata: Metadata { owner },
            data: extension,
        }
    }
}

impl VariableData for ServerExtensionData {
    fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn get_data(&self) -> &dyn Any {
        self.data.as_any()
    }

    fn random_value(owner: AgentName) -> Self
        where
            Self: Sized,
    {
        todo!()
    }

    fn clone_data(&self) -> Box<dyn Any> {
        Box::new(self.data.clone())
    }
}
