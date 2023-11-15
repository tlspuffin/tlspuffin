use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let header = "src/put.h";

    println!("cargo:rerun-if-changed={}", header);

    let bindings_path = Path::new(&out_dir).join("bindings.rs");
    bindgen::Builder::default()
        .header(header)
        .no_copy("^AGENT_DESCRIPTOR$")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings for cput")
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!(
        "cargo:rustc-env=CPUT_BINDINGS_FILE={}",
        bindings_path.to_string_lossy()
    );

    let dst_dir = PathBuf::from(out_dir);
    let inc_dir = dst_dir.join("include/tlspuffin");

    fs::create_dir_all(inc_dir.clone()).unwrap();
    fs::copy("src/put.h", inc_dir.join("put.h")).unwrap();

    println!("cargo:root={}", dst_dir.to_str().unwrap());
    println!("cargo:include={}/include", dst_dir.to_str().unwrap());
}
