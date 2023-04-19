use std::{
    collections::HashSet,
    env,
    fs::{canonicalize, File},
    io,
    io::{ErrorKind, Write},
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
} else if cfg!(feature = "vendored-master") {
    "master"
} else {
    "master"
};

fn patch_wolfssl(source_dir: &PathBuf, out_dir: &str, patch: &str) -> std::io::Result<()> {
    let status = Command::new("git")
        .current_dir(out_dir)
        .arg("am")
        .arg(source_dir.join("patches").join(patch).to_str().unwrap())
        .status()?;

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

    Ok(())
}

fn clone_wolfssl(dest: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    let status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://github.com/wolfSSL/wolfssl.git")
        .arg(dest)
        .status()?;

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

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
        .enable("keygen", None) // Support for RSA certs
        .enable("certgen", None) // Support x509 decoding
        .enable("tls13", None)
        .enable("dtls", None)
        .enable("sp", None)
        .enable("dtls-mtu", None)
        .disable("sha3", None)
        .enable("curve25519", None)
        .enable("secure-renegotiation", None)
        .enable("psk", None) // FIXME: Only 4.3.0
        .disable("examples", None) // Speedup
        .cflag("-DHAVE_EX_DATA") // FIXME: Only 4.3.0
        .cflag("-DWOLFSSL_CALLBACKS") // FIXME: Elso some msg callbacks are not called
        //FIXME broken: .cflag("-DHAVE_EX_DATA_CLEANUP_HOOKS") // Required for cleanup of ex data
        .cflag("-g")
        .cflag("-fPIC");

    #[cfg(target_arch = "x86_64")]
    {
        config
            .enable("intelasm", None)
            .enable("sp-asm", None)
            .enable("aesni", None);
    }

    #[cfg(not(feature = "wolfssl-disable-postauth"))]
    {
        config.enable("postauth", None);
    }

    #[cfg(feature = "wolfssl-disable-postauth")]
    {
        config.disable("postauth", None);
    }

    if cfg!(feature = "sancov") {
        config.cflag("-fsanitize-coverage=trace-pc-guard");
    }

    if cfg!(feature = "asan") {
        let output = Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to clang to get resource dir");
        let clang: &str = std::str::from_utf8(&output.stdout).unwrap().trim();

        config
            .cflag("-fsanitize=address")
            .cflag("-shared-libsan")
            .cflag(format!("-Wl,-rpath={}/lib/linux/", clang)); // We need to tell the library where ASAN is, else the tests fail within wolfSSL
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
    let _source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = env::var("OUT_DIR").unwrap();
    clone_wolfssl(&out_dir)?;

    #[cfg(feature = "fix-CVE-2022-25640")]
    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-25640.patch").unwrap();
    #[cfg(feature = "fix-CVE-2022-25638")]
    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-25638.patch").unwrap();
    #[cfg(feature = "fix-CVE-2022-39173")]
    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-39173.patch").unwrap();
    #[cfg(feature = "fix-CVE-2022-42905")]
    patch_wolfssl(&source_dir, &out_dir, "fix-CVE-2022-42905.patch").unwrap();

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
