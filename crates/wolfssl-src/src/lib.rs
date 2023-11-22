use std::{
    collections::HashSet,
    env,
    fs::{canonicalize, File},
    io,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::Command,
};

use autotools::Config;

pub struct WolfSSLOptions {
    pub fix_cve_2022_25638: bool,
    pub fix_cve_2022_25640: bool,
    pub fix_cve_2022_39173: bool,
    pub fix_cve_2022_42905: bool,
    pub wolfssl_disable_postauth: bool,

    pub asan: bool,
    pub sancov: bool,

    pub gcov_analysis: bool,
    pub llvm_cov_analysis: bool,

    pub git_ref: String,
    pub out_dir: PathBuf,
    pub source_dir: PathBuf,
}

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

fn patch_wolfssl<P: AsRef<Path>>(
    source_dir: &PathBuf,
    out_dir: P,
    patch: &str,
) -> std::io::Result<()> {
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

fn clone_wolfssl<P: AsRef<Path>>(dest: &P, options: &WolfSSLOptions) -> std::io::Result<()> {
    //return Ok(());
    std::fs::remove_dir_all(dest)?;
    let status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(&options.git_ref)
        .arg("https://github.com/wolfSSL/wolfssl.git")
        .arg(dest.as_ref().to_str().unwrap())
        .status()?;

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

    Ok(())
}

fn build_wolfssl<P: AsRef<Path>>(dest: &P, options: &WolfSSLOptions) -> PathBuf {
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
        // TODO .disable("examples", None) // Speedup
        .cflag("-DHAVE_EX_DATA") // FIXME: Only 4.3.0
        .cflag("-DWOLFSSL_CALLBACKS") // FIXME: Elso some msg callbacks are not called
        //FIXME broken: .cflag("-DHAVE_EX_DATA_CLEANUP_HOOKS") // Required for cleanup of ex data
        .cflag("-g")
        .cflag("-fPIC");
    //.cflag("-DWC_RNG_SEED_CB") // FIXME: makes test test_seed_cve_2022_38153 fail, but should be used when evaluating coverage to get same coverage than other fuzzers which use this flag to disable determinism
    //.cflag("-DWOLFSSL_GENSEED_FORTEST"); // FIXME: makes test test_seed_cve_2022_38153 fail, but should be used when evaluating coverage to get same coverage than other fuzzers which use this flag to disable determinism

    #[cfg(target_arch = "x86_64")]
    {
        config
            .enable("intelasm", None)
            .enable("sp-asm", None)
            .enable("aesni", None);
    }

    if options.wolfssl_disable_postauth {
        config.disable("postauth", None);
    } else {
        config.enable("postauth", None);
    }

    if options.gcov_analysis {
        config.cflag("-ftest-coverage").cflag("-fprofile-arcs");
    }

    if options.llvm_cov_analysis {
        config
            .cflag("-fprofile-instr-generate")
            .cflag("-fcoverage-mapping");
    }

    if options.asan {
        let output = Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to clang to get resource dir");
        let clang: &str = std::str::from_utf8(&output.stdout).unwrap().trim();

        // Important: Make sure to pass these flags to the linker invoked by rustc!
        config
            .cflag("-fsanitize=address")
            .cflag("-shared-libsan")
            .cflag(format!("-Wl,-rpath={}/lib/linux/", clang)); // We need to tell the library where ASAN is, else the tests fail within wolfSSL
    }

    config.env("CC", cc).build()
}

pub fn build(options: &WolfSSLOptions) -> std::io::Result<()> {
    let out_dir = &options.out_dir.canonicalize().unwrap();
    clone_wolfssl(out_dir, options)?;

    if options.fix_cve_2022_25640 {
        patch_wolfssl(&options.source_dir, out_dir, "fix-CVE-2022-25640.patch").unwrap();
    }

    if options.fix_cve_2022_25638 {
        patch_wolfssl(&options.source_dir, out_dir, "fix-CVE-2022-25638.patch").unwrap();
    }

    if options.fix_cve_2022_39173 {
        patch_wolfssl(&options.source_dir, out_dir, "fix-CVE-2022-39173.patch").unwrap();
    }

    if options.fix_cve_2022_42905 {
        patch_wolfssl(&options.source_dir, out_dir, "fix-CVE-2022-42905.patch").unwrap();
    }

    let dst = build_wolfssl(&out_dir, options);

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
        .size_t_is_usize(false)
        .header(format!("{}/wrapper.h", options.source_dir.display()))
        .header(format!("{}/wolfssl/internal.h", out_dir.display()))
        .clang_arg(format!("-I{}/include/", out_dir.display()))
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
