#[cfg(test)]
pub mod tests {
    use crate::tls::key_exchange::deterministic_key_exchange;
    use rustls::kx_group::X25519;
    use test_env_log::test;
    use rustls::msgs::handshake::ClientExtension;
    use crate::tls::fn_extensions::fn_server_name_extension;

    #[test]
    fn test_deterministic_key() {
        let a = deterministic_key_exchange(&X25519).unwrap();
        let b = deterministic_key_exchange(&X25519).unwrap();

        assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
    }

    #[test]
    fn test_all_extensions_implemented() {

    }

    fn all_extensions_implemented(client_extension: ClientExtension) {
/*        match client_extension {
            ClientExtension::ECPointFormats(_) => {}
            ClientExtension::NamedGroups(_) => {}
            ClientExtension::SignatureAlgorithms(_) => {}
            ClientExtension::ServerName(_) => fn_server_name_extension,
            ClientExtension::SessionTicketRequest => {}
            ClientExtension::SessionTicketOffer(_) => {}
            ClientExtension::Protocols(_) => {}
            ClientExtension::SupportedVersions(_) => {}
            ClientExtension::KeyShare(_) => {}
            ClientExtension::PresharedKeyModes(_) => {}
            ClientExtension::PresharedKey(_) => {}
            ClientExtension::Cookie(_) => {}
            ClientExtension::ExtendedMasterSecretRequest => {}
            ClientExtension::CertificateStatusRequest(_) => {}
            ClientExtension::SignedCertificateTimestampRequest => {}
            ClientExtension::TransportParameters(_) => {}
            ClientExtension::TransportParametersDraft(_) => {}
            ClientExtension::EarlyData => {}
            ClientExtension::RenegotiationInfo(_) => {}
            ClientExtension::SignatureAlgorithmsCert(_) => {}
            ClientExtension::Unknown(_) => {}
        }*/
    }
}
