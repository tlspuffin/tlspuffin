#[cfg(not(any(
    feature = "wolfssl540",
    feature = "wolfssl530",
    feature = "wolfssl520",
    feature = "wolfssl510",
    feature = "wolfssl430",
    feature = "wolfssl552",
    feature = "wolfssl572",
    feature = "master",
)))]
compile_error!(concat!(
    "You need to select one feature in [",
    "'wolfssl430', ",
    "'wolfssl510', ",
    "'wolfssl520', ",
    "'wolfssl530', ",
    "'wolfssl540', ",
    "'wolfssl552', ",
    "'wolfssl572', ",
    "'master'",
    "]"
));

#[cfg(any(
    all(feature = "wolfssl430", feature = "wolfssl510"),
    all(feature = "wolfssl430", feature = "wolfssl520"),
    all(feature = "wolfssl430", feature = "wolfssl530"),
    all(feature = "wolfssl430", feature = "wolfssl540"),
    all(feature = "wolfssl430", feature = "master"),
    all(feature = "wolfssl510", feature = "wolfssl520"),
    all(feature = "wolfssl510", feature = "wolfssl530"),
    all(feature = "wolfssl510", feature = "wolfssl540"),
    all(feature = "wolfssl510", feature = "master"),
    all(feature = "wolfssl520", feature = "wolfssl530"),
    all(feature = "wolfssl520", feature = "wolfssl540"),
    all(feature = "wolfssl520", feature = "master"),
    all(feature = "wolfssl530", feature = "wolfssl540"),
    all(feature = "wolfssl530", feature = "master"),
    all(feature = "wolfssl540", feature = "master"),
))]
compile_error!(concat!(
    "Incompatible features requested. Only one of [",
    "'wolfssl430', ",
    "'wolfssl510', ",
    "'wolfssl520', ",
    "'wolfssl530', ",
    "'wolfssl540', ",
    "'master'",
    "] can be enabled at the same time."
));

use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use wolfssl_src::{build, WolfSSLOptions};

const PRESET: &str = if cfg!(feature = "wolfssl540") {
    "wolfssl540"
} else if cfg!(feature = "wolfssl530") {
    "wolfssl530"
} else if cfg!(feature = "wolfssl520") {
    "wolfssl520"
} else if cfg!(feature = "wolfssl510") {
    "wolfssl510"
} else if cfg!(feature = "wolfssl430") {
    "wolfssl430"
} else if cfg!(feature = "wolfssl552") {
    "wolfssl552"
} else if cfg!(feature = "wolfssl572") {
    "wolfssl572"
} else if cfg!(feature = "master") {
    "wolfsslmaster"
} else {
    panic!("Unknown version of WolfSSL requested!")
};

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

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let wolfssl = build(&WolfSSLOptions {
        fix: vec![
            #[cfg(feature = "fix-CVE-2022-25638")]
            "CVE-2022-25638".to_string(),
            #[cfg(feature = "fix-CVE-2022-25640")]
            "CVE-2022-25640".to_string(),
            #[cfg(feature = "fix-CVE-2022-39173")]
            "CVE-2022-39173".to_string(),
            #[cfg(feature = "fix-CVE-2022-42905")]
            "CVE-2022-42905".to_string(),
        ],
        postauth: (!cfg!(feature = "wolfssl-disable-postauth")),
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        gcov: cfg!(feature = "gcov"),
        llvm_cov: cfg!(feature = "llvm_cov"),
        preset: String::from(PRESET),
    });

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
        .header(format!("{}/wrapper.h", env!("CARGO_MANIFEST_DIR")))
        .header(format!("{}/wolfssl/internal.h", wolfssl.src_dir().display()))
        .clang_arg(format!("-I{}", wolfssl.inc_dir().display()))
        .clang_arg("-U__STDC_HOSTED__") // The stdatomic.h header is empty without this flag
        .parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    wolfssl.print_cargo_metadata();
}
