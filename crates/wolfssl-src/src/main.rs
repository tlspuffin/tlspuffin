use std::env;
use std::path::PathBuf;

use wolfssl_src::{build, WolfSSLOptions};

fn main() {
    let out_dir = PathBuf::from("out_dir");

    env::set_var("TARGET", "aarch64-apple-darwin");
    env::set_var("HOST", "aarch64-apple-darwin");
    env::set_var("OPT_LEVEL", "3");
    env::set_var(
        "OUT_DIR",
        out_dir.canonicalize().unwrap().display().to_string(),
    );

    build(&WolfSSLOptions {
        preset: String::from("wolfssl540"),
        gcov: false,
        llvm_cov: false,
        asan: false,
        sancov: true,
        postauth: true,
        fix: vec![],
    });
}
