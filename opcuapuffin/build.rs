// open62541 is patched and generated thanks to puffin-build.
// Here, generate the file bindings.rs from open62541 according to the configuration

use std::env;
use std::path::{Path, PathBuf};

use puffin_build::harness::{Harness, Put};
use puffin_build::library::Library;
use puffin_build::{harness, vendor_dir};

fn main() {

    /* binding for include/puffin/opcua.h */

    let out_dir =  PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is required!"));
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

        /* binding for open62541 */
        // Taken from open62541-sys / build.rs

        let out_bindings_rs = out_dir.join("open62541_bindings.rs");

        let builder = bindgen::Builder::default()
            .ctypes_prefix("::libc")

            // Include our wrapper functions.
            .allowlist_function("(__)?RS_.*")
            .allowlist_function("(__)?UA_.*")
            // Include our wrapper types.
            .allowlist_type("(__)?RS_.*")
            .allowlist_type("(__)?UA_.*")
            // Include our wrapper vars.
            .allowlist_var("(__)?RS_.*")
            .allowlist_var("(__)?UA_.*")
            // Explicitly set C99 standard to force Windows variants of `vsnprintf()` to conform to this
            // standard. This also matches the expected (or supported) C standard of `open62541` itself.
            .clang_arg("-std=c99")
            .clang_arg(format!(
                "-I{project_dir}/vendor/open62541/include",
                project_dir = puffin_build::puffin::project_dir().display()
            ))
            .default_enum_style(bindgen::EnumVariation::NewType {
                is_bitfield: false,
                is_global: false,
            })
            // Do not derive `Copy` because most of the data types are not copy-safe (they own memory by
            // pointers and need to be cloned manually to duplicate that memory).
            .derive_copy(false)
            // We want to initialize some types statically. This is used in `open62541`, we require that
            // as well to mirror some of the functionality.
            .derive_default(true)
            // The auto-derived comments are not particularly useful because they often do not match the
            // declaration they belong to.
            .generate_comments(false)
            .header("harness/open62541/include/wrapper.h")
            // Activate parse callbacks. This causes cargo to invalidate the generated bindings when any
            // of the included files change. It also enables us to rename items in the final bindings.
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            // We may use `core` instead of `std`. This might be useful for `no_std` environments.
            .use_core();
            // Wrap static functions. These are used in several places for inline helpers and we want to
            // preserve those in the generated bindings. This outputs `extern.c` which we compile below.
            //.wrap_static_fns(true)
            // Make sure to specify the location of the resulting `extern.c`. By default `bindgen` would
            // place it in the temporary directory.
            //.wrap_static_fns_path("harness/open62541/src/extern.c);

        builder.generate()
            .expect("Unable to generate Rust bindings for open62541_sys")
            .write_to_file(&out_bindings_rs)
            .expect("Couldn't write bindings for open62541_sys!");


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
    let out_dir = 
        Path::new(&std::env::var("OUT_DIR").unwrap())
        .join(format!("harness_{}", library.id()));
    Harness::harness_for("opcua", library.clone(), harness::Kind::C).
        map(|harness| harness.wrap(out_dir).unwrap())
}