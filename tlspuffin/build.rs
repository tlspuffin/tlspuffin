use std::env;
use std::path::Path;
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

    if cfg!(feature = "cput") {
        let out_dir = env::var("OUT_DIR").unwrap();
        let cput_header = "src/cput_openssl/put.h";
        let cput_source = "src/cput_openssl/put.c";

        cc::Build::new()
            .include(cput_header)
            .file(cput_source)
            .compile("cput");

        let bindings_path = Path::new(&out_dir).join("bindings.rs");
        bindgen::Builder::default()
            .header(cput_header)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings for cput")
            .write_to_file(&bindings_path)
            .expect("Couldn't write bindings!");

        println!("cargo:rerun-if-changed={}", cput_source);
        println!("cargo:rerun-if-changed={}", cput_header);
        println!(
            "cargo:rustc-env=CPUT_BINDINGS_FILE={}",
            bindings_path.to_string_lossy()
        );
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=cput");
        println!("cargo:rustc-link-search=native=openssl_build/openssl");
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }
}
