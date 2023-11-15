use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    println!("cargo:rerun-if-changed=src/put.h");

    let bindings_path = Path::new(&out_dir).join("bindings.rs");
    bindgen::Builder::default()
        .header("src/put.h")
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
    let bld_dir = dst_dir.join("build");
    let inc_dir = dst_dir.join("include/tlspuffin");

    fs::create_dir_all(&bld_dir).unwrap();
    fs::create_dir_all(&inc_dir).unwrap();

    cc::Build::new()
        .out_dir(&bld_dir)
        .include(&inc_dir)
        .file("src/put.c")
        .compile("tlspuffin-cbindings");

    fs::copy("src/put.h", inc_dir.join("put.h")).unwrap();

    println!("cargo:root={}", dst_dir.to_str().unwrap());
    println!("cargo:include={}/include", dst_dir.to_str().unwrap());
}
