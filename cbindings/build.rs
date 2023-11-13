use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let header = "src/put.h";

    let bindings_path = Path::new(&out_dir).join("bindings.rs");
    bindgen::Builder::default()
        .header(header)
        .no_copy("^AGENT_DESCRIPTOR$")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings for cput")
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed={}", header);
    println!(
        "cargo:rustc-env=CPUT_BINDINGS_FILE={}",
        bindings_path.to_string_lossy()
    );
}
