extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;

fn main() {
    println!("cargo:rerun-if-changed=claim-interface.h");
    let bindings = bindgen::Builder::default()
        .header("claim-interface.h")
        // We have full control over enums: https://github.com/rust-lang/rust-bindgen/issues/758
        .rustified_enum(".*")
        .derive_copy(true)
        .derive_debug(true)
        .impl_debug(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("claim-interface.rs"))
        .expect("Couldn't write bindings!");
}
