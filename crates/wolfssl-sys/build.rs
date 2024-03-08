#[cfg(not(any(
    feature = "vendored-wolfssl540",
    feature = "vendored-wolfssl530",
    feature = "vendored-wolfssl520",
    feature = "vendored-wolfssl510",
    feature = "vendored-wolfssl430",
    feature = "vendored-master",
)))]
compile_error!(concat!(
    "You need to select one feature in [",
    "'vendored-wolfssl430', ",
    "'vendored-wolfssl510', ",
    "'vendored-wolfssl520', ",
    "'vendored-wolfssl530', ",
    "'vendored-wolfssl540', ",
    "'vendored-master'",
    "]"
));

#[cfg(any(
    all(feature = "vendored-wolfssl430", feature = "vendored-wolfssl510"),
    all(feature = "vendored-wolfssl430", feature = "vendored-wolfssl520"),
    all(feature = "vendored-wolfssl430", feature = "vendored-wolfssl530"),
    all(feature = "vendored-wolfssl430", feature = "vendored-wolfssl540"),
    all(feature = "vendored-wolfssl430", feature = "vendored-master"),
    all(feature = "vendored-wolfssl510", feature = "vendored-wolfssl520"),
    all(feature = "vendored-wolfssl510", feature = "vendored-wolfssl530"),
    all(feature = "vendored-wolfssl510", feature = "vendored-wolfssl540"),
    all(feature = "vendored-wolfssl510", feature = "vendored-master"),
    all(feature = "vendored-wolfssl520", feature = "vendored-wolfssl530"),
    all(feature = "vendored-wolfssl520", feature = "vendored-wolfssl540"),
    all(feature = "vendored-wolfssl520", feature = "vendored-master"),
    all(feature = "vendored-wolfssl530", feature = "vendored-wolfssl540"),
    all(feature = "vendored-wolfssl530", feature = "vendored-master"),
    all(feature = "vendored-wolfssl540", feature = "vendored-master"),
))]
compile_error!(concat!(
    "Incompatible features requested. Only one of [",
    "'vendored-wolfssl430', ",
    "'vendored-wolfssl510', ",
    "'vendored-wolfssl520', ",
    "'vendored-wolfssl530', ",
    "'vendored-wolfssl540', ",
    "'vendored-master'",
    "] can be enabled at the same time."
));

use std::{env, path::PathBuf};

use wolfssl_src::{build, WolfSSLOptions};

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
        gcov_analysis: cfg!(feature = "gcov_analysis"),
        llvm_cov_analysis: cfg!(feature = "llvm_cov_analysis"),
        git_ref: REF.to_string(),
        out_dir: out_dir.clone(),
        source_dir: source_dir.clone(),
    })
    .unwrap();

    // Linking Time!
    println!("cargo:rustc-link-lib=static=wolfssl");
    println!(
        "cargo:rustc-link-search=native={}",
        format!("{}/lib/", out_dir.display())
    );
    println!("cargo:include={}", out_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("wrapper.h").display()
    );
}
