#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

//! Extensions according to IANA:
//! <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>
//!
//! In the source code all IDs are available, but implementations are missing.

use puffin::algebra::error::FnError;
use webpki::DnsNameRef;

use crate::nyi_fn;
use crate::tls::fn_impl::fn_get_ticket_age_add;
use crate::tls::fn_utils::fn_get_ticket;
use crate::tls::key_exchange::deterministic_key_share;
use crate::tls::rustls::msgs::base::{Payload, PayloadU16, PayloadU24, PayloadU8};
use crate::tls::rustls::msgs::enums::*;
use crate::tls::rustls::msgs::handshake::*;
use crate::tls::rustls::msgs::message::Message;
use crate::tls::rustls::x509;

pub fn fn_client_extensions_new() -> Result<Vec<ClientExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_client_extensions_append(
    extensions: &Vec<ClientExtension>,
    extension: &ClientExtension,
) -> Result<Vec<ClientExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_client_extensions_make(
    extensions: &Vec<ClientExtension>,
) -> Result<ClientExtensions, FnError> {
    Ok(ClientExtensions(extensions.clone()))
}

pub fn fn_server_extensions_new() -> Result<Vec<ServerExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_server_extensions_make(
    extensions: &Vec<ServerExtension>,
) -> Result<ServerExtensions, FnError> {
    Ok(ServerExtensions(extensions.clone()))
}

pub fn fn_server_extensions_append(
    extensions: &Vec<ServerExtension>,
    extension: &ServerExtension,
) -> Result<Vec<ServerExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_hello_retry_extensions_make(
    extensions: &Vec<HelloRetryExtension>,
) -> Result<HelloRetryExtensions, FnError> {
    Ok(HelloRetryExtensions(extensions.clone()))
}
pub fn fn_hello_retry_extensions_new() -> Result<Vec<HelloRetryExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_hello_retry_extensions_append(
    extensions: &Vec<HelloRetryExtension>,
    extension: &HelloRetryExtension,
) -> Result<Vec<HelloRetryExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_cert_req_extensions_new() -> Result<Vec<CertReqExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_cert_req_extensions_append(
    extensions: &Vec<CertReqExtension>,
    extension: &CertReqExtension,
) -> Result<Vec<CertReqExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_cert_extensions_new() -> Result<Vec<CertificateExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_cert_extensions_append(
    extensions: &Vec<CertificateExtension>,
    extension: &CertificateExtension,
) -> Result<Vec<CertificateExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

pub fn fn_cert_extensions_make(
    extensions: &Vec<CertificateExtension>,
) -> Result<CertificateExtensions, FnError> {
    Ok(CertificateExtensions(extensions.clone()))
}

pub fn fn_new_session_ticket_extensions_new() -> Result<Vec<NewSessionTicketExtension>, FnError> {
    Ok(vec![])
}

pub fn fn_new_session_ticket_extensions_append(
    extensions: &Vec<NewSessionTicketExtension>,
    extension: &NewSessionTicketExtension,
) -> Result<Vec<NewSessionTicketExtension>, FnError> {
    let mut new_extensions = extensions.clone();
    new_extensions.push(extension.clone());

    Ok(new_extensions)
}

// todo ServerExtensions
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo CertReqExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo NewSessionTicketExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

// todo Unknown Extensions for
//      ClientExtension, ServerExtension, HelloRetryExtension, NewSessionTicketExtension
//      https://gitlab.inria.fr/mammann/tlspuffin/-/issues/57

//
// Actual extensions
//

/// ServerName => 0x0000,
pub fn fn_server_name_entry() -> Result<ServerName, FnError> {
    let dns_name = "inria.fr";
    Ok(ServerName {
        typ: ServerNameType::HostName,
        payload: ServerNamePayload::HostName((
            PayloadU16(dns_name.to_string().into_bytes()),
            DnsNameRef::try_from_ascii_str(dns_name)
                .map_err(|err| FnError::Codec(err.to_string()))?
                .to_owned(),
        )),
    })
}
pub fn fn_server_names_new() -> Result<Vec<ServerName>, FnError> {
    Ok(vec![])
}
pub fn fn_server_names_append(
    names: &Vec<ServerName>,
    name: &ServerName,
) -> Result<Vec<ServerName>, FnError> {
    let mut new_names = names.clone();
    new_names.push(name.clone());
    Ok(new_names)
}
pub fn fn_server_names_make(
    names: &Vec<ServerName>,
) -> Result<ServerNameRequest, FnError> {
    Ok(ServerNameRequest(names.clone()))
}
pub fn fn_server_name_extension(
    request: &ServerNameRequest,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::ServerName(request.clone()))
}
pub fn fn_server_name_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::ServerNameAck)
}
nyi_fn! {
    /// MaxFragmentLength => 0x0001,
}
nyi_fn! {
    /// ClientCertificateUrl => 0x0002,
}
nyi_fn! {
    /// TrustedCAKeys => 0x0003,
}
nyi_fn! {
    /// TruncatedHMAC => 0x0004,
}
/// StatusRequest => 0x0005,
pub fn fn_status_request_extension(
    responder_ids: &VecU16OfPayloadU16,
    extensions: &PayloadU16,
) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::OCSP(OCSPCertificateStatusRequest {
            responder_ids: responder_ids.clone(),
            extensions: extensions.clone(),
        }),
    ))
}
pub fn fn_status_request_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::CertificateStatusAck)
}

pub fn fn_status_request_certificate_extension(
    ocsp_response: &PayloadU24,
) -> Result<CertificateExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(CertificateExtension::CertificateStatus(CertificateStatus {
        ocsp_response: ocsp_response.clone(),
    }))
}
nyi_fn! {
    /// UserMapping => 0x0006,
}
nyi_fn! {
    /// ClientAuthz => 0x0007,
}
nyi_fn! {
    /// ServerAuthz => 0x0008,
}
nyi_fn! {
    /// CertificateType => 0x0009,
}
/// EllipticCurves => 0x000a,
pub fn fn_support_group_extension_make(
    groups: &Vec<NamedGroup>,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::NamedGroups(NamedGroups(groups.clone())))
}

pub fn fn_support_group_extension_new() -> Result<Vec<NamedGroup>, FnError> {
    Ok(vec![])
}

pub fn fn_support_group_extension_append(
    groups: &Vec<NamedGroup>,
    group: &NamedGroup,
) -> Result<Vec<NamedGroup>, FnError> {
    let mut new_groups = groups.clone();
    new_groups.push(group.clone());

    Ok(new_groups)
}

// ECPointFormats => 0x000b,
pub fn fn_ec_point_format_uncompressed() -> Result<ECPointFormat, FnError> {
    Ok(ECPointFormat::Uncompressed)
}
pub fn fn_ec_point_formats_new() -> Result<Vec<ECPointFormat>, FnError> {
    Ok(vec![])
}
pub fn fn_ec_point_formats_append(
    formats: &Vec<ECPointFormat>,
    format: &ECPointFormat,
) -> Result<Vec<ECPointFormat>, FnError> {
    let mut new_formats = formats.clone();
    new_formats.push(format.clone());
    Ok(new_formats)
}
pub fn fn_ec_point_formats_make(
    formats: &Vec<ECPointFormat>,
) -> Result<ECPointFormatList, FnError> {
    Ok(ECPointFormatList(formats.clone()))
}
pub fn fn_ec_point_formats_extension(
    list: &ECPointFormatList,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::ECPointFormats(list.clone()))
}
pub fn fn_ec_point_formats_server_extension(
    list: &ECPointFormatList,
) -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::ECPointFormats(list.clone()))
}
nyi_fn! {
    /// SRP => 0x000c,
}
/// SignatureAlgorithms => 0x000d,
pub fn fn_signature_schemes_new() -> Result<Vec<SignatureScheme>, FnError> {
    Ok(vec![])
}
pub fn fn_signature_schemes_append(
    schemes: &Vec<SignatureScheme>,
    scheme: &SignatureScheme,
) -> Result<Vec<SignatureScheme>, FnError> {
    let mut new_schemes = schemes.clone();
    new_schemes.push(*scheme);
    Ok(new_schemes)
}
pub fn fn_signature_schemes_make(
    schemes: &Vec<SignatureScheme>,
) -> Result<SupportedSignatureSchemes, FnError> {
    Ok(SupportedSignatureSchemes(schemes.clone()))
}
pub fn fn_signature_algorithm_extension(
    schemes: &SupportedSignatureSchemes,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignatureAlgorithms(schemes.clone()))
}
pub fn fn_signature_algorithm_cert_req_extension(
    schemes: &SupportedSignatureSchemes,
) -> Result<CertReqExtension, FnError> {
    Ok(CertReqExtension::SignatureAlgorithms(schemes.clone()))
}
nyi_fn! {
    /// UseSRTP => 0x000e,
}
nyi_fn! {
    /// Heartbeat => 0x000f,
}
/// ALProtocolNegotiation => 0x0010,
pub fn fn_empty_vec_of_vec() -> Result<Vec<Vec<u8>>, FnError> {
    Ok(vec![])
}
pub fn fn_append_vec(vec_of_vec: &Vec<Vec<u8>>, data: &Vec<u8>) -> Result<Vec<Vec<u8>>, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    let mut new = vec_of_vec.clone();
    new.push(data.clone());
    Ok(new)
}
pub fn fn_al_protocol_negotiation(
    protocol_name_list: &VecU16OfPayloadU8,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::Protocols(protocol_name_list.clone()))
}
pub fn fn_al_protocol_server_negotiation(
    protocol_name_list: &VecU16OfPayloadU8,
) -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::Protocols(protocol_name_list.clone()))
}
nyi_fn! {
    /// status_request_v2 => 0x0011
}
/// SCT => 0x0012,
pub fn fn_signed_certificate_timestamp_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignedCertificateTimestampRequest)
}
pub fn fn_signed_certificate_timestamp_server_extension() -> Result<ServerExtension, FnError> {
    // todo unclear where what to put here
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ServerExtension::SignedCertificateTimestamp(
        VecU16OfPayloadU16(vec![PayloadU16::new(Vec::from([42u8; 128]))]),
    ))
}
pub fn fn_signed_certificate_timestamp_certificate_extension(
) -> Result<CertificateExtension, FnError> {
    // todo unclear where what to put here
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(CertificateExtension::SignedCertificateTimestamp(
        VecU16OfPayloadU16(vec![PayloadU16::new(Vec::from([42u8; 128]))]),
    ))
}
nyi_fn! {
    /// client_certificate_type => 0x0013,
}
nyi_fn! {
    /// server_certificate_type => 0x0014,
}
nyi_fn! {
    /// Padding => 0x0015,
}
nyi_fn! {
    /// encrypt_then_mac => 0x0016,
}
/// ExtendedMasterSecret => 0x0017,
pub fn fn_extended_master_secret_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::ExtendedMasterSecretRequest)
}
pub fn fn_extended_master_secret_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::ExtendedMasterSecretAck)
}
nyi_fn! {
    /// token_binding => 0x0018,
}
nyi_fn! {
    /// cached_info => 0x0019,
}
nyi_fn! {
    /// tls_lts => 0x001A,
}
nyi_fn! {
    /// compress_certificate => 0x001B,
}
nyi_fn! {
    /// record_size_limit => 0x001C,
}
nyi_fn! {
    /// pwd_protect => 0x001D,
}
nyi_fn! {
    /// pwd_clear => 0x001E,
}
nyi_fn! {
    /// password_salt => 0x001F,
}
nyi_fn! {
    /// ticket_pinning => 0x0020,
}
nyi_fn! {
    /// tls_cert_with_extern_psk => 0x0021,
}
nyi_fn! {
    /// delegated_credentials => 0x0022,
}
/// SessionTicket => 0x0023,
pub fn fn_session_ticket_request_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SessionTicket(ClientSessionTicket::Request))
}
pub fn fn_session_ticket_offer_extension(ticket: &Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
        Payload::new(ticket.clone()),
    )))
}
pub fn fn_session_ticket_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::ServerNameAck)
}
nyi_fn! {
    /// TLMSP => 0x0024,
}
nyi_fn! {
    /// TLMSP_proxying => 0x0025,
}
nyi_fn! {
    /// TLMSP_delegate => 0x0026,
}
nyi_fn! {
    /// supported_ekt_ciphers => 0x0027,
}
/// PreSharedKey => 0x0029,
pub fn fn_new_preshared_key_identity(
    identity: &PayloadU16,
) -> Result<PresharedKeyIdentity, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(PresharedKeyIdentity {
        identity: identity.clone(),
        obfuscated_ticket_age: 10,
    })
}
pub fn fn_empty_preshared_keys_identity_vec() -> Result<Vec<PresharedKeyIdentity>, FnError> {
    Ok(vec![])
}
pub fn fn_append_preshared_keys_identity(
    identities: &Vec<PresharedKeyIdentity>,
    identify: &PresharedKeyIdentity,
) -> Result<Vec<PresharedKeyIdentity>, FnError> {
    let mut new = identities.clone();
    new.push(identify.clone());
    Ok(new)
}

pub fn fn_preshared_keys_extension_empty_binder(
    new_ticket: &Message,
) -> Result<ClientExtension, FnError> {
    let ticket: Vec<u8> = fn_get_ticket(new_ticket)?;
    let age_add: u64 = fn_get_ticket_age_add(new_ticket)?;

    let ticket_age_millis: u32 = 100; // 100ms since receiving NewSessionTicket
    let obfuscated_ticket_age = ticket_age_millis.wrapping_add(age_add as u32);

    let resuming_suite = &crate::tls::rustls::tls13::TLS13_AES_128_GCM_SHA256; // todo allow other cipher suites
    let binder_len = resuming_suite.hash_algorithm().output_len;
    let binder = vec![0u8; binder_len];

    let psk_identity = PresharedKeyIdentity::new(ticket, obfuscated_ticket_age);

    Ok(ClientExtension::PresharedKey(PresharedKeyOffer::new(
        psk_identity,
        binder,
    )))
}

pub fn fn_preshared_keys_server_extension(identities: &u16) -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::PresharedKey(*identities))
}
/// EarlyData => 0x002a,
pub fn fn_early_data_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::EarlyData)
}
pub fn fn_early_data_new_session_ticket_extension(
    early_data: &u32,
) -> Result<NewSessionTicketExtension, FnError> {
    Ok(NewSessionTicketExtension::EarlyData(*early_data))
}
pub fn fn_early_data_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::EarlyData)
}
/// SupportedVersions => 0x002b,
pub fn fn_supported_versions12_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SupportedVersions(ProtocolVersions(vec![
        ProtocolVersion::TLSv1_2,
    ])))
}
pub fn fn_supported_versions13_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SupportedVersions(ProtocolVersions(vec![
        ProtocolVersion::TLSv1_3,
    ])))
}
pub fn fn_supported_versions12_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::SupportedVersions(
        ProtocolVersion::TLSv1_2,
    ))
}
pub fn fn_supported_versions13_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::SupportedVersions(
        ProtocolVersion::TLSv1_3,
    ))
}

pub fn fn_supported_versions12_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_2))
}
pub fn fn_supported_versions13_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3))
}
/// Cookie => 0x002c,
pub fn fn_cookie_extension(cookie: &PayloadU16) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::Cookie(cookie.clone()))
}

pub fn fn_cookie_hello_retry_extension(
    cookie: &PayloadU16,
) -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::Cookie(cookie.clone()))
}
/// PSKKeyExchangeModes => 0x002d,
pub fn fn_psk_exchange_mode_dhe_ke() -> Result<PSKKeyExchangeMode, FnError> {
    Ok(PSKKeyExchangeMode::PSK_DHE_KE)
}
pub fn fn_psk_exchange_mode_ke() -> Result<PSKKeyExchangeMode, FnError> {
    Ok(PSKKeyExchangeMode::PSK_KE)
}
pub fn fn_psk_exchange_modes_new() -> Result<Vec<PSKKeyExchangeMode>, FnError> {
    Ok(vec![])
}
pub fn fn_psk_exchange_modes_append(
    modes: &Vec<PSKKeyExchangeMode>,
    mode: &PSKKeyExchangeMode,
) -> Result<Vec<PSKKeyExchangeMode>, FnError> {
    let mut new_modes = modes.clone();
    new_modes.push(*mode);
    Ok(new_modes)
}
pub fn fn_psk_exchange_modes_make(
    modes: &Vec<PSKKeyExchangeMode>,
) -> Result<PSKKeyExchangeModes, FnError> {
    Ok(PSKKeyExchangeModes(modes.clone()))
}
pub fn fn_psk_exchange_modes_extension(
    modes: &PSKKeyExchangeModes,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::PresharedKeyModes(modes.clone()))
}
nyi_fn! {
    /// TicketEarlyDataInfo => 0x002e,
}
/// CertificateAuthorities => 0x002f,
pub fn fn_certificate_authorities_extension() -> Result<CertReqExtension, FnError> {
    let mut r = VecU16OfPayloadU16(Vec::new());

    let subject = "inria.fr";
    let mut name = Vec::new();
    name.extend_from_slice(subject.as_bytes());
    x509::wrap_in_sequence(&mut name);
    r.0.push(DistinguishedName::new(name));

    Ok(CertReqExtension::AuthorityNames(r))
}
nyi_fn! {
    /// OIDFilters => 0x0030,
}
nyi_fn! {
    /// PostHandshakeAuth => 0x0031,
}
/// SignatureAlgorithmsCert => 0x0032,
pub fn fn_signature_algorithm_cert_extension(
    schemes: &SupportedSignatureSchemes,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::SignatureAlgorithmsCert(schemes.clone()))
}
/// KeyShare => 0x0033,
pub fn fn_key_share_entry(
    group: &NamedGroup,
    key_share: &PayloadU16,
) -> Result<KeyShareEntry, FnError> {
    Ok(KeyShareEntry {
        group: *group,
        payload: key_share.clone(),
    })
}
pub fn fn_key_share_entry_deterministic(group: &NamedGroup) -> Result<KeyShareEntry, FnError> {
    fn_key_share_entry(group, &PayloadU16::new(deterministic_key_share(group)?))
}
pub fn fn_key_share_entries_new() -> Result<Vec<KeyShareEntry>, FnError> {
    Ok(vec![])
}
pub fn fn_key_share_entries_append(
    entries: &Vec<KeyShareEntry>,
    entry: &KeyShareEntry,
) -> Result<Vec<KeyShareEntry>, FnError> {
    let mut new_entries = entries.clone();
    new_entries.push(entry.clone());
    Ok(new_entries)
}
pub fn fn_key_share_entries_make(
    entries: &Vec<KeyShareEntry>,
) -> Result<KeyShareEntries, FnError> {
    Ok(KeyShareEntries(entries.clone()))
}
pub fn fn_key_share_extension(
    entries: &KeyShareEntries,
) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::KeyShare(entries.clone()))
}
pub fn fn_key_share_deterministic_server_extension(
    group: &NamedGroup,
) -> Result<ServerExtension, FnError> {
    fn_key_share_server_extension(group, &PayloadU16::new(deterministic_key_share(group)?))
}
pub fn fn_key_share_server_extension(
    group: &NamedGroup,
    key_share: &PayloadU16,
) -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::KeyShare(KeyShareEntry {
        group: *group,
        payload: key_share.clone(),
    }))
}
pub fn fn_key_share_hello_retry_extension(
    group: &NamedGroup,
) -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::KeyShare(*group))
}
nyi_fn! {
    /// transparency_info => 0x0034,
}
nyi_fn! {
    /// connection_id => 0x0035,
}
nyi_fn! {
    /// external_id_hash => 0x0037,
}
nyi_fn! {
    /// external_session_id => 0x0038,
}
/// TransportParameters/quic_transport_parameters => 0x0039,
pub fn fn_transport_parameters_extension(parameters: &Vec<u8>) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ClientExtension::TransportParameters(parameters.clone()))
}
pub fn fn_transport_parameters_server_extension(
    parameters: &Vec<u8>,
) -> Result<ServerExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ServerExtension::TransportParameters(parameters.clone()))
}
nyi_fn! {
    /// NextProtocolNegotiation => 0x3374,
}
nyi_fn! {
    /// ChannelId => 0x754f,
}

/// RenegotiationInfo => 0xff01,
pub fn fn_renegotiation_info_extension(data: &PayloadU8) -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::RenegotiationInfo(data.clone()))
}

pub fn fn_renegotiation_info_server_extension(
    data: &PayloadU8,
) -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::RenegotiationInfo(data.clone()))
}
/// TransportParametersDraft => 0xffa5
pub fn fn_transport_parameters_draft_extension(
    parameters: &Vec<u8>,
) -> Result<ClientExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ClientExtension::TransportParametersDraft(
        parameters.clone(),
    ))
}
pub fn fn_transport_parameters_draft_server_extension(
    parameters: &Vec<u8>,
) -> Result<ServerExtension, FnError> {
    // todo unclear where the arguments come from here, needs manual trace implementation
    //      https://github.com/tlspuffin/tlspuffin/issues/155
    Ok(ServerExtension::TransportParametersDraft(
        parameters.clone(),
    ))
}
// Unknown extensions

pub fn fn_unknown_client_extension() -> Result<ClientExtension, FnError> {
    Ok(ClientExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_server_extension() -> Result<ServerExtension, FnError> {
    Ok(ServerExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_hello_retry_extension() -> Result<HelloRetryExtension, FnError> {
    Ok(HelloRetryExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_cert_request_extension() -> Result<CertReqExtension, FnError> {
    Ok(CertReqExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_new_session_ticket_extension() -> Result<NewSessionTicketExtension, FnError> {
    Ok(NewSessionTicketExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}

pub fn fn_unknown_certificate_extension() -> Result<CertificateExtension, FnError> {
    Ok(CertificateExtension::Unknown(UnknownExtension {
        typ: ExtensionType::Unknown(0xFFFF),
        payload: Payload::new([42; 10]),
    }))
}
