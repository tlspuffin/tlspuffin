use std::path::{Path, PathBuf};

use puffin_build::harness::{Harness, Put};
use puffin_build::{harness, library, vendor_dir};

#[cfg(any(
    all(feature = "openssl-binding", feature = "wolfssl-binding"),
    all(feature = "openssl-binding", feature = "boringssl-binding"),
    all(feature = "wolfssl-binding", feature = "boringssl-binding")
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
        .derive_partialeq(true)
        .impl_partialeq(true)
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
