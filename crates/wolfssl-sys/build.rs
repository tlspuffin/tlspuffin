use std::{
    collections::HashSet,
    env,
    fs::{canonicalize, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

use autotools::Config;

#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

const REF: &str = if cfg!(feature = "vendored-wolfssl540") {
    "v5.4.0-stable"
} else if cfg!(feature = "vendored-wolfssl530") {
    "v5.3.0-stable"
} else if cfg!(feature = "vendored-wolfssl520") {
    "v5.2.0-stable"
} else if cfg!(feature = "vendored-wolfssl510") {
    "v5.1.0-stable"
} else if cfg!(feature = "vendored-wolfssl430") {
    "v4.3.0-stable"
} else {
    "master"
};

fn clone_wolfssl(dest: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://github.com/wolfSSL/wolfssl.git")
        .arg(dest)
        .status()?;

    Ok(())
}

pub fn insert_claim_interface(additional_headers: &PathBuf) -> std::io::Result<()> {
    let interface = security_claims::CLAIM_INTERFACE_H;

    let path = additional_headers.join("claim-interface.h");

    let mut file = File::create(path)?;
    file.write_all(interface.as_bytes())?;

    Ok(())
}

fn build_wolfssl(dest: &str) -> PathBuf {
    let cc = "clang".to_owned();

    let mut config = Config::new(dest);

    config
        .reconf("-ivf")
        .enable_static()
        .disable_shared()
        .enable("debug", None)
        .enable("opensslall", None)
        .enable("opensslextra", None)
        .enable("context-extra-user-data", None)
        //.enable("all", None) // FIXME: Do not use this as its non-default
        //.enable("opensslcoexist", None) // FIXME: not needed
        .enable("keygen", None) // Support for RSA certs
        .enable("certgen", None) // Support x509 decoding
        .enable("tls13", None)
        .enable("dtls", None)
        .enable("dtls-mtu", None)
        .disable("sha3", None)
        .enable("curve25519", None)
        .enable("secure-renegotiation", None)
        .enable("postauth", None) // FIXME; else the session resumption crashes? SEGV?
        .enable("psk", None) // FIXME: Only 4.3.0
        .cflag("-DHAVE_EX_DATA") // FIXME: Only 4.3.0
        .cflag("-DWOLFSSL_CALLBACKS") // FIXME: Elso some msg callbacks are not called
        //FIXME broken: .cflag("-DHAVE_EX_DATA_CLEANUP_HOOKS") // Required for cleanup of ex data
        //.cflag("-g")// FIXME: Reenable?
        .cflag("-fPIC");

    if !(cfg!(feature = "m1")) { // only enabled when Mac M1 chip-specific build is not used
        config
            .enable("aesni", None)
            .enable("sp", None) // FIXME: Fixes a memory leak?
            .enable("sp-asm", None)
            .enable("intelasm", None);
    }

    if cfg!(feature = "sancov") {
        config.cflag("-fsanitize-coverage=trace-pc-guard");
    }

    if cfg!(feature = "asan") {
        config
            .cflag("-fsanitize=address")
            .cflag("-shared-libsan");
    }

    if cfg!(feature = "asan") && cfg!(not(feature = "m1")){
        config
            .cflag("-Wl,-rpath=/usr/lib/clang/10/lib/linux/"); // We need to tell the library where ASAN is, else the tests fail within wolfSSL
        println!("cargo:rustc-link-lib=asan");
    }

    if cfg!(feature = "additional-headers") {
        let additional_headers = PathBuf::from(dest).join("additional_headers");

        std::fs::create_dir_all(&additional_headers).unwrap();
        insert_claim_interface(&additional_headers).unwrap();
        // Make additional headers available
        config.cflag(
            format!(
                " -I{}",
                canonicalize(&additional_headers).unwrap().to_str().unwrap()
            )
            .as_str(),
        );
    }

    config.env("CC", cc).build()
}

fn main() -> std::io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    clone_wolfssl(&out_dir)?;
    let dst = build_wolfssl(&out_dir);

    // Block some macros:https://github.com/rust-lang/rust-bindgen/issues/687
    let mut ignored_macros = HashSet::new();
    for i in &[
        "IPPORT_RESERVED",
        "EVP_PKEY_DH",
        "BIO_CLOSE",
        "BIO_NOCLOSE",
        "CRYPTO_LOCK",
        "ASN1_STRFLGS_ESC_MSB",
        "SSL_MODE_RELEASE_BUFFERS",
        // Woflss 4.3.0
        "GEN_IPADD",
        "EVP_PKEY_RSA",
    ] {
        ignored_macros.insert(i.to_string());
    }
    let ignored_macros = IgnoreMacros(ignored_macros);

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .header(format!("{}/wolfssl/internal.h", out_dir))
        .clang_arg(format!("-I{}/include/", out_dir))
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Linking Time!
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!(
        "cargo:rustc-link-search=native={}",
        format!("{}/lib/", out_dir)
    );
    println!("cargo:include={}", out_dir);
    println!("cargo:rerun-if-changed=wrapper.h");

    Ok(())
}
