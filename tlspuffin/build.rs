use std::path::{Path, PathBuf};

use puffin_build::harness::{Harness, Put};
use puffin_build::{harness, library, vendor_dir};

#[cfg(any(
    all(feature = "openssl_binding", feature = "wolfssl_binding"),
    all(feature = "openssl_binding", feature = "boringssl_binding"),
    all(feature = "wolfssl_binding", feature = "boringssl_binding")
))]
compile_error!("Selecting multiple Rust PUT is currently not supported: openssl/libressl, wolfssl and boringssl feature flags are mutually exclusive.");

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let bindings_path = PathBuf::from(&out_dir).join("bindings.rs");
    bindgen::Builder::default()
        .ctypes_prefix("::libc")
        .clang_arg(format!(
            "-I{project_dir}/puffin/include",
            project_dir = puffin_build::puffin::project_dir().display()
        ))
        .allowlist_file(".*/puffin/[^/]+\\.h")
        .allowlist_recursively(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .rustified_enum(".*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_eq(true)
        .derive_default(true)
        .derive_partialeq(false)
        .impl_partialeq(false)
        .impl_debug(true)
        .no_copy("^TLS_AGENT_DESCRIPTOR$")
        .blocklist_type("Claim")
        .header("include/puffin/tls.h")
        .generate()
        .expect("Unable to generate Rust bindings for tlspuffin harness")
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!(
        "cargo:rustc-env=RUST_BINDINGS_FILE={}",
        bindings_path.to_string_lossy()
    );

    let out_dir = Path::new(&std::env::var("OUT_DIR").unwrap()).join("harness_bundle");
    let puts: Vec<Put> = vendor_dir::from_env()
        .all()
        .iter()
        .filter_map(harness)
        .collect();

    let bundle = harness::bundle(puts).build(out_dir);
    bundle.print_cargo_metadata();

    // Compile the deterministic RNG shim for OpenSSL bindings (but NOT LibreSSL,
    // which provides its own RNG shim via the patched arc4random.c).
    // This is needed because the openssl-sys crate no longer uses our patched openssl-src
    // (version mismatch: local is 111.x, openssl-sys now requires 300.x), so
    // build_prng_interface() in openssl-src is never called.
    if cfg!(feature = "openssl_binding") && !cfg!(feature = "libressl_binding") {
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let c_file = manifest_dir
            .join("../crates/openssl-src-111/src/deterministic_rand.c")
            .canonicalize()
            .expect("deterministic_rand.c not found");

        println!("cargo:rerun-if-changed={}", c_file.display());

        let mut builder = cc::Build::new();
        if let Ok(include) = std::env::var("DEP_OPENSSL_INCLUDE") {
            builder.include(&include);
        }
        if cfg!(feature = "deterministic") {
            builder.define("USE_CUSTOM_PRNG", "1");
        }
        builder.file(&c_file);
        builder.compile("tlspuffin_openssl_prng_interface");
    }
}

fn harness(library: &library::Library) -> Option<Put> {
    let out_dir =
        Path::new(&std::env::var("OUT_DIR").unwrap()).join(format!("harness_{}", library.id()));

    let rust_put_name = std::env::var("DEP_BORING_ROOT")
        .or(std::env::var("DEP_OPENSSL_ROOT"))
        .or(std::env::var("DEP_WOLFSSL_ROOT"))
        .map(|libroot| {
            std::path::Path::new(&libroot)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .ok();

    let kind = if cfg!(feature = "rust-put") && Some(&library.name()) == rust_put_name.as_ref() {
        harness::Kind::Rust
    } else {
        if !cfg!(feature = "cputs") {
            return None;
        }

        harness::Kind::C
    };

    Harness::harness_for("tls", library.clone(), kind).map(|harness| harness.wrap(out_dir).unwrap())
}
