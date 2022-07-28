use std::{
    collections::HashSet,
    env,
    fs::{canonicalize, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

use cmake::Config;

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

const REF: &str = if cfg!(feature = "vendored-libssh096") {
    "libssh-0.9.6"
} else {
    "master"
};

fn clone(dest: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://git.libssh.org/projects/libssh.git")
        .arg(dest)
        .status()?;

    Ok(())
}

fn build(source_dir: &str) -> PathBuf {
    let cc = "clang".to_owned();

    let mut config = Config::new(source_dir);
    let config = config
        .define("CMAKE_C_COMPILER", cc)
        .define("WITH_GSSAPI", "OFF")
        .define("BUILD_STATIC_LIB", "ON");

    if cfg!(feature = "sancov") {
        config.cflag("-fsanitize-coverage=trace-pc-guard");
    }

    if cfg!(feature = "asan") {
        config.cflag("-fsanitize=address").cflag("-shared-libsan");
        println!("cargo:rustc-link-lib=asan");
    }

    config.build()
}

fn main() -> std::io::Result<()> {
    // Get the build directory
    let out_dir = env::var("OUT_DIR").unwrap();
    clone(&out_dir)?;
    // Configure and build
    let dst = build(&out_dir);

    // We want to block some macros as they are incorrectly creating duplicate values
    // https://github.com/rust-lang/rust-bindgen/issues/687
    let mut hash_ignored_macros = HashSet::new();
    for i in &["IPPORT_RESERVED"] {
        hash_ignored_macros.insert(i.to_string());
    }
    let ignored_macros = IgnoreMacros(hash_ignored_macros);

    // Build the Rust binding
    let bindings = bindgen::Builder::default()
        .header(format!("{}/include/libssh/libssh.h", out_dir))
        .header(format!("{}/include/libssh/server.h", out_dir))
        .clang_arg(format!("-I{}/include/", out_dir))
        .parse_callbacks(Box::new(ignored_macros))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(PathBuf::from(&out_dir).join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link
    println!("cargo:rustc-link-lib=static=crypto");
    //println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=ssh");
    println!(
        "cargo:rustc-link-search=native={}",
        format!("{}/build/src/", out_dir)
    );

    println!("cargo:include={}", out_dir);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}
