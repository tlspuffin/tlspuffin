use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};

use puffin_build::vendor;

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

const PRESET: &str = if cfg!(feature = "libssh0104") {
    "libssh0104"
} else if cfg!(feature = "libsshmaster") {
    "libsshmaster"
} else {
    panic!("Unknown version of libssh requested!")
};

pub struct LibSSHOptions {
    pub preset: String,

    pub asan: bool,
    pub sancov: bool,
    pub gcov: bool,
    pub llvm_cov: bool,
}

pub struct Artifacts {
    src_dir: PathBuf,
    inc_dir: PathBuf,
    lib_dir: PathBuf,
    libs: Vec<String>,
}

impl Artifacts {
    pub fn src_dir(&self) -> &Path {
        &self.src_dir
    }

    pub fn inc_dir(&self) -> &Path {
        &self.inc_dir
    }

    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    pub fn libs(&self) -> &[String] {
        &self.libs
    }

    pub fn print_cargo_metadata(&self) {
        println!("cargo:rustc-link-search=native={}", self.lib_dir.display());
        for lib in self.libs.iter() {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
        println!("cargo:include={}", self.inc_dir.display());
        println!("cargo:lib={}", self.lib_dir.display());

        println!("cargo:rerun-if-changed={}", self.lib_dir.display());
        println!("cargo:rerun-if-changed={}", self.inc_dir.display());
    }
}

fn build(options: &LibSSHOptions) -> Artifacts {
    let suffix = if options.asan { "-asan" } else { "" };
    let name = format!("{}{suffix}", options.preset);

    let mut config = vendor::Config::preset("libssh", &options.preset)
        .unwrap_or_else(|| panic!("missing preset libssh:{}", options.preset));

    config.option("sancov", options.sancov);
    config.option("asan", options.asan);
    config.option("gcov", options.gcov);
    config.option("llvm_cov", options.llvm_cov);

    let prefix = vendor::dir()
        .lock(&name)
        .and_then(|config_dir| {
            if let Some(old_config) = config_dir.config()? {
                if old_config == config {
                    return Ok(config_dir.path().to_path_buf());
                }

                eprintln!("found incompatible config '{name}' in VENDOR_DIR, rebuilding...");
            }

            config_dir.make(config)
        })
        .unwrap();

    Artifacts {
        src_dir: prefix.join("src").join("vendor"),
        lib_dir: prefix.join("lib"),
        inc_dir: prefix.join("include"),
        libs: vec!["ssh".to_string()],
    }
}

fn main() {
    let libssh = build(&LibSSHOptions {
        asan: cfg!(feature = "asan"),
        sancov: cfg!(feature = "sancov"),
        gcov: cfg!(feature = "gcov"),
        llvm_cov: cfg!(feature = "llvm_cov"),
        preset: String::from(PRESET),
    });

    // We want to ignore some macros because of duplicates:
    // https://github.com/rust-lang/rust-bindgen/issues/687
    let mut ignored_macros = HashSet::new();
    for i in &["IPPORT_RESERVED"] {
        ignored_macros.insert(i.to_string());
    }
    let ignored_macros = IgnoreMacros(ignored_macros);

    // Build the Rust binding
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", libssh.inc_dir().display().to_string()))
        .clang_arg(format!(
            "-I{}/include",
            libssh.src_dir().display().to_string()
        ))
        .clang_arg("-DHAVE_LIBCRYPTO".to_string())
        .clang_arg("-DHAVE_COMPILER__FUNC__=1".to_string())
        .clang_arg("-DHAVE_STRTOULL".to_string())
        .rustified_enum("ssh_auth_state_e")
        .rustified_enum("ssh_session_state_e")
        .rustified_enum("ssh_options_e")
        .rustified_enum("ssh_bind_options_e")
        .rustified_enum("ssh_requests_e")
        .parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt)
        .generate()
        .expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("Couldn't write bindings!");

    libssh.print_cargo_metadata();
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=z");
}
