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
    "master"
};

fn main() {
    build(&WolfSSLOptions {
        fix_cve_2022_25638: cfg!(feature = "fix-CVE-2022-25638"),
        fix_cve_2022_25640: cfg!(feature = "fix-CVE-2022-25640"),
        fix_cve_2022_39173: cfg!(feature = "fix-CVE-2022-39173"),
        fix_cve_2022_42905: cfg!(feature = "fix-CVE-2022-42905"),
        wolfssl_disable_postauth: cfg!(feature = "wolfssl-disable-postauth"),
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        git_ref: REF.to_string(),
        out_dir: PathBuf::from(env::var("OUT_DIR").unwrap()),
        source_dir: PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../wolfssl-src"),
    })
    .unwrap();
}
