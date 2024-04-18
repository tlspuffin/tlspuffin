use std::{env, path::PathBuf};

use boringssl_src::{build, BoringSSLOptions, GitRef};

fn main() {
    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("out");

    env::set_var(
        "OUT_DIR",
        &out_dir.canonicalize().unwrap().display().to_string(),
    );

    build(&BoringSSLOptions {
        gcov_analysis: false,
        llvm_cov_analysis: false,
        deterministic: false,
        asan: false,
        sancov: true,
        git_ref: GitRef::Branch("master".to_string()),
        git_repo: "https://github.com/google/boringssl".into(),
        out_dir,
        source_dir: PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("boringssl"),
    })
    .unwrap();
}
