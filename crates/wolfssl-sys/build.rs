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
} else if cfg!(feature = "vendored-wolfssl563") {
    "v5.6.3-stable"
} else if cfg!(feature = "vendored-master") {
    "master"
} else {
    "master"
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
