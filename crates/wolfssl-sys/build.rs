#[cfg(not(any(
    feature = "wolfssl540",
    feature = "wolfssl530",
    feature = "wolfssl520",
    feature = "wolfssl510",
    feature = "wolfssl430",
    feature = "master",
)))]
compile_error!(concat!(
    "You need to select one feature in [",
    "'wolfssl430', ",
    "'wolfssl510', ",
    "'wolfssl520', ",
    "'wolfssl530', ",
    "'wolfssl540', ",
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

use std::env;
use std::path::PathBuf;

use wolfssl_src::{build, WolfSSLOptions};

const REF: &str = if cfg!(feature = "wolfssl540") {
    "v5.4.0-stable"
} else if cfg!(feature = "wolfssl530") {
    "v5.3.0-stable"
} else if cfg!(feature = "wolfssl520") {
    "v5.2.0-stable"
} else if cfg!(feature = "wolfssl510") {
    "v5.1.0-stable"
} else if cfg!(feature = "wolfssl430") {
    "v4.3.0-stable"
} else if cfg!(feature = "master") {
    "master"
} else {
    panic!("Unknown version of WolfSSL requested!")
};

fn main() {
    let source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../wolfssl-src");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    build(&WolfSSLOptions {
        fix_cve_2022_25638: cfg!(feature = "fix-CVE-2022-25638"),
        fix_cve_2022_25640: cfg!(feature = "fix-CVE-2022-25640"),
        fix_cve_2022_39173: cfg!(feature = "fix-CVE-2022-39173"),
        fix_cve_2022_42905: cfg!(feature = "fix-CVE-2022-42905"),
        wolfssl_disable_postauth: cfg!(feature = "wolfssl-disable-postauth"),
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        gcov: cfg!(feature = "gcov"),
        llvm_cov: cfg!(feature = "llvm_cov"),
        git_ref: REF.to_string(),
        out_dir: out_dir.clone(),
        source_dir: source_dir.clone(),
    })
    .unwrap();

    // Linking Time!
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!("cargo:rustc-link-search=native={}/lib/", out_dir.display());
    println!("cargo:include={}", out_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("wrapper.h").display()
    );
}
