use std::{env, path::PathBuf};

use wolfssl_src::{build, WolfSSLOptions};

fn main() {
    let out_dir = PathBuf::from("out_dir");

    env::set_var("TARGET", "aarch64-apple-darwin");
    env::set_var("HOST", "aarch64-apple-darwin");
    env::set_var("OPT_LEVEL", "3");
    env::set_var(
        "OUT_DIR",
        &out_dir.canonicalize().unwrap().display().to_string(),
    );

    build(&WolfSSLOptions {
        fix_cve_2022_25638: false,
        fix_cve_2022_25640: false,
        fix_cve_2022_39173: false,
        fix_cve_2022_42905: false,
        wolfssl_disable_postauth: false,
        gcov_analysis: false,
        llvm_cov_analysis: false,
        asan: false,
        sancov: true,
        git_ref: "v5.4.0-stable".to_string(),
        out_dir,
        source_dir: PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()),
    })
    .unwrap();
}
