extern crate bindgen;

use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{DeriveInfo, ParseCallbacks, TypeKind};

#[derive(Debug)]
struct MyParseCallbacks;

impl ParseCallbacks for MyParseCallbacks {
    fn add_derives(&self, info: &DeriveInfo<'_>) -> Vec<String> {
        let mut derives = vec![];

        if let TypeKind::Enum = info.kind {
            derives.push("comparable::Comparable".into());
        }
        derives
    }
}

fn main() {
    println!("cargo:rerun-if-changed=claim-interface.h");
    let bindings = bindgen::Builder::default()
        .header("claim-interface.h")
        // We have full control over enums: https://github.com/rust-lang/rust-bindgen/issues/758
        .rustified_enum(".*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_eq(true)
        .derive_default(true)
        .impl_debug(true)
        .parse_callbacks(Box::new(MyParseCallbacks {}))
        .impl_partialeq(false)
        .derive_partialeq(false)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("claim-interface.rs"))
        .expect("Couldn't write bindings!");
}
