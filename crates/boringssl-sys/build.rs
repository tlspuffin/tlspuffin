use std::{env, path::PathBuf};

use boringssl_src::{build, BoringSSLOptions, GitRef};

fn main() {
    let git_ref: GitRef = if cfg!(feature = "boring-2023-11-18") {
        GitRef::Commit(String::from("698aa894c96412d4df20e2bb031d9eb9c9d5919a"))
    } else if cfg!(feature = "boring-2024-03-22") {
        GitRef::Commit(String::from("368d0d87d0bd00f8227f74ce18e8e4384eaf6afa"))
    } else {
        GitRef::Branch(String::from("master"))
    };

    let repo = "https://github.com/google/boringssl.git".into();
    let source_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("boringssl");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("boring");
    build(&BoringSSLOptions {
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        gcov: cfg!(feature = "gcov"),
        llvm_cov: cfg!(feature = "llvm_cov"),
        deterministic: cfg!(feature = "deterministic"),
        git_repo: repo,
        git_ref,
        out_dir: out_dir.clone(),
        source_dir,
    })
    .unwrap();

    // Linking Time!
    // The parameters to link BoringSSL are inspired from
    // https://github.com/cloudflare/boring/blob/master/boring-sys/build/main.rs
    println!("cargo:rustc-link-search={}/lib", out_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=stdc++");

    if cfg!(feature = "gcov") {
        let clang_output = std::process::Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to use clang to get resource dir");
        let clang_resource_dir: &str = std::str::from_utf8(&clang_output.stdout).unwrap().trim();
        println!("cargo:rustc-link-search={}/lib/linux/", clang_resource_dir);
        println!("cargo:rustc-link-lib=static=clang_rt.profile-x86_64");
    }

    let include_path = out_dir.join("include");

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
        .clang_arg(include_path.display().to_string());

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
        builder = builder.header(include_path.join("openssl").join(header).to_str().unwrap());
    }

    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings
        .write_to_file(bindings_out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
