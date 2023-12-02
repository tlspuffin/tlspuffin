use std::env;
use std::path::PathBuf;
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
        println!("cargo:rerun-if-env-changed=VENDOR_DIR");
        println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
        println!("cargo:rerun-if-env-changed=OPENSSL_VERSION");

        fn openssl_prefix() -> PathBuf {
            if env::var("OPENSSL_DIR").is_ok() {
                return PathBuf::from(env::var("OPENSSL_DIR").unwrap());
            }

            if env::var("OPENSSL_VERSION").is_ok() {
                let version = env::var("OPENSSL_VERSION").unwrap();
                let vendor_dir = PathBuf::from(
                    env::var("VENDOR_DIR")
                        .unwrap_or(concat!(env!("CARGO_MANIFEST_DIR"), "/../vendor").to_string()),
                );

                return cputopenssl::build_vendor(vendor_dir, &version);
            }

            panic!("native dependency not found: need either OPENSSL_DIR or OPENSSL_VERSION environment variable");
        }

        let cbindings_include = PathBuf::from(env::var("DEP_TLSPUFFIN_CBINDINGS_INCLUDE").unwrap());

        cputopenssl::build(openssl_prefix(), cbindings_include);
    }
}
