use wolfssl_sys::wolfSSL_write;

#[cfg(feature = "wolfSSL")] // [TODO:WolfSSL]
pub fn create_wolfssl_server(
    stream: MemoryStream,
    cert: &X509Ref,
    key: &PKeyRef<Private>,
    tls_version: &TLSVersion,
) -> Result<SslStream<MemoryStream>, ErrorStack> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls())?;
    ctx_builder.set_certificate(cert)?;
    ctx_builder.set_private_key(key)?;

    #[cfg(feature = "openssl111")]
    ctx_builder.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);

    #[cfg(feature = "openssl111")]
    ctx_builder.set_options(SslOptions::ALLOW_NO_DHE_KEX);

    set_max_protocol_version(&mut ctx_builder, tls_version)?;

    #[cfg(any(feature = "openssl101f", feature = "openssl102u"))]
    {
        ctx_builder.set_tmp_ecdh(openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1).as_ref().unwrap())?;
        // TODO: https://github.com/sfackler/rust-openssl/issues/1529 use callback after fix
        //ctx_builder.set_tmp_ecdh_callback(|_, _, _| {
        //   openssl::ec::EcKey::from_curve_name(openssl::nid::Nid::SECP384R1)
        //});
    }

    #[cfg(any(feature = "openssl101f", feature = "openssl102u"))]
    {
        ctx_builder.set_tmp_rsa(openssl::rsa::Rsa::generate(512).as_ref().unwrap())?;
        // TODO: https://github.com/sfackler/rust-openssl/issues/1529 use callback use callback after fix
        //ctx_builder.set_tmp_rsa_callback(|_, is_export, keylength| openssl::rsa::Rsa::generate(keylength));
    }

    // Allow EXPORT in server
    ctx_builder.set_cipher_list("ALL:EXPORT:!LOW:!aNULL:!eNULL:!SSLv2")?;

    let mut ssl = Ssl::new(&ctx_builder.build())?;

    ssl.set_accept_state();
    SslStream::new(ssl, stream)
}