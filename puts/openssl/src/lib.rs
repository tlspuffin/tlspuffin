use std::env;

pub fn build(ossl_libdir: String, ossl_incdir: String) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let cbindings_include = env::var("DEP_TLSPUFFIN_CBINDINGS_INCLUDE").unwrap();
    let cput_source = concat!(env!("CARGO_MANIFEST_DIR"), "/src/put.c");

    println!("cargo:rerun-if-changed={}", cput_source);

    cc::Build::new()
        .include(ossl_incdir)
        .include(cbindings_include)
        .file(cput_source)
        .compile("cputopenssl");

    println!("cargo:rustc-link-search=native={}", ossl_libdir);
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=cputopenssl");
}
