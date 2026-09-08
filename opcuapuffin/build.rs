// open62541 is patched and generated thanks to puffin-build.
// Here, generate the file bindings.rs from open62541 according to the configuration

use std::env;
use std::path::{Path, PathBuf};

use puffin_build::harness::{Harness, Put};
use puffin_build::library::Library;
use puffin_build::{harness, vendor_dir};

fn main() {
    /* Recompile when the C harness sources change. Without this, editing the harness .c/.h files
     * does NOT trigger a rebuild (cargo only tracks build.rs itself and Rust sources), so a
     * changed harness would be silently linked from the stale cmake output. Watch the whole
     * harness tree. */
    println!("cargo:rerun-if-changed=harness");

    /* binding for include/puffin/opcua.h */

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is required!"));
    let bindings_path = out_dir.join("bindings.rs");

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
        .header("include/puffin/opcua.h")
        .generate()
        .expect("Unable to generate Rust bindings for C harness")
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings for C harness!");

    println!(
        "cargo:rustc-env=RUST_BINDINGS_FILE={}",
        bindings_path.to_string_lossy()
    );

    /* build bundle by filtering the libraries found in vendor/ */

    let out_dir = Path::new(&std::env::var("OUT_DIR").unwrap()).join("harness_bundle");
    let puts: Vec<Put> = vendor_dir::from_env()
        .all()
        .iter()
        .filter_map(compile_opcua_harness)
        .collect();
    let bundle = harness::bundle(puts).build(out_dir);
    bundle.print_cargo_metadata();
}

fn compile_opcua_harness(library: &Library) -> Option<Put> {
    let has_gcov = library
        .metadata()
        .instrumentation
        .iter()
        .any(|i| i == "gcov");
    if cfg!(feature = "gcov") != has_gcov {
        return None;
    }

    let out_dir =
        Path::new(&std::env::var("OUT_DIR").unwrap()).join(format!("harness_{}", library.id()));
    Harness::harness_for("opcua", library.clone(), harness::Kind::C)
        .map(|harness| harness.wrap(out_dir).unwrap())
}
