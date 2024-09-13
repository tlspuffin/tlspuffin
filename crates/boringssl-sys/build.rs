use std::env;
use std::path::PathBuf;

use boringssl_src::{build, BoringSSLOptions};

const PRESET: &str = if cfg!(feature = "boringssl202403") {
    "boringssl202403"
} else if cfg!(feature = "boringssl202311") {
    "boringssl202311"
} else if cfg!(feature = "boringsslmaster") {
    "boringsslmaster"
} else {
    panic!("Unknown version of BoringSSL requested!")
};

fn main() {
    let boringssl = build(&BoringSSLOptions {
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        gcov: cfg!(feature = "gcov"),
        llvm_cov: cfg!(feature = "llvm_cov"),
        preset: String::from(PRESET),
    });

    if cfg!(feature = "gcov") {
        let clang_output = std::process::Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to use clang to get resource dir");
        let clang_resource_dir: &str = std::str::from_utf8(&clang_output.stdout).unwrap().trim();
        println!("cargo:rustc-link-search={}/lib/linux/", clang_resource_dir);
        println!("cargo:rustc-link-lib=static=clang_rt.profile-x86_64");
    }

    let bindings_out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut builder = bindgen::Builder::default()
        .ctypes_prefix("::libc")
        .raw_line("use libc::*;")
        .allowlist_file(".*/openssl/[^/]+\\.h")
        .allowlist_recursively(false)
        .blocklist_function("BIO_vprintf")
        .blocklist_function("BIO_vsnprintf")
        .blocklist_function("OPENSSL_vasprintf")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .clang_arg("-I")
        .clang_arg(boringssl.inc_dir().display().to_string());

    if cfg!(feature = "deterministic") {
        // Exposes RAND_reset_for_fuzzing
        builder = builder.clang_arg("-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE=1");
    }

    let headers = [
        "aes.h",
        "asn1_mac.h",
        "asn1t.h",
        "blake2.h",
        "blowfish.h",
        "cast.h",
        "chacha.h",
        "cmac.h",
        "cpu.h",
        "curve25519.h",
        "des.h",
        "dtls1.h",
        "hkdf.h",
        "hmac.h",
        "hrss.h",
        "md4.h",
        "md5.h",
        "obj_mac.h",
        "objects.h",
        "opensslv.h",
        "ossl_typ.h",
        "pkcs12.h",
        "poly1305.h",
        "rand.h",
        "rc4.h",
        "ripemd.h",
        "siphash.h",
        "srtp.h",
        "trust_token.h",
        "x509v3.h",
        "ssl.h",
    ];
    for header in &headers {
        builder = builder.header(
            boringssl
                .inc_dir()
                .join("openssl")
                .join(header)
                .to_str()
                .unwrap(),
        );
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings
        .write_to_file(bindings_out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    boringssl.print_cargo_metadata();
    println!("cargo:rustc-link-lib=stdc++");
}
