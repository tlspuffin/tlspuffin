use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if cfg!(feature = "asan") {
        let output = Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to clang to get resource dir");
        let clang: &str = std::str::from_utf8(&output.stdout).unwrap().trim();

        println!("cargo:rustc-link-arg=-Wl,-rpath={}/lib/linux/", clang);
        println!("cargo:rustc-link-arg=-fsanitize=address");
        println!("cargo:rustc-link-arg=-shared-libasan");
    }

    if cfg!(feature = "gcov_analysis") {
        println!("cargo:rustc-link-arg=-ftest-coverage");
        println!("cargo:rustc-link-arg=-fprofile-arcs");
    }

    if cfg!(feature = "llvm_cov_analysis") {
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-fcoverage-mapping");
    }

    #[cfg(feature = "cputopenssl")]
    {
        fn openssl_config() -> (PathBuf, PathBuf) {
            if env::var("OSSL_DIR").is_ok() {
                let ossl_dir = PathBuf::from(env::var("OSSL_DIR").unwrap());
                let ossl_lib = ossl_dir.join("");
                let ossl_inc = ossl_dir.join("include");

                return (ossl_lib, ossl_inc);
            }

            if env::var("OSSL_VERSION").is_ok() {
                // TODO build OpenSSL from sources
                //
                //     If no pre-built OpenSSL is provided through the OSSL_DIR
                //     env variable then we build it from sources using the
                //     provided OSSL_VERSION.
                //
                //     This variable should contain a valid reference to a git
                //     branch or tag in the OpenSSL repository.
                let _ = env::var("OSSL_VERSION").unwrap();
            }

            panic!("native dependency not found: need either OSSL_DIR or OSSL_VERSION environment variable");
        }

        let (libdir, incdir) = openssl_config();

        cputopenssl::build(
            libdir.to_string_lossy().into(),
            incdir.to_string_lossy().into(),
        );
    }
}
