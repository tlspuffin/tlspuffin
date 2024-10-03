use std::path::{Path, PathBuf};

use puffin_build::vendor;

pub struct BoringSSLOptions {
    pub preset: String,

    pub asan: bool,
    pub sancov: bool,
    pub gcov: bool,
    pub llvm_cov: bool,
}

pub struct Artifacts {
    root_dir: PathBuf,
    src_dir: PathBuf,
    inc_dir: PathBuf,
    lib_dir: PathBuf,
    libs: Vec<String>,
}

impl Artifacts {
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

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
        println!("cargo:root={}", self.root_dir.display());

        println!("cargo:rerun-if-changed={}", self.lib_dir.display());
        println!("cargo:rerun-if-changed={}", self.inc_dir.display());
    }
}

pub fn build(options: &BoringSSLOptions) -> Artifacts {
    let suffix = if options.asan { "-asan" } else { "" };
    let name = format!("{}{suffix}", options.preset);

    let mut config = vendor::Config::preset("boringssl", &options.preset)
        .unwrap_or_else(|| panic!("missing preset boringssl:{}", options.preset));

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
        root_dir: prefix.clone(),
        src_dir: prefix.join("src").join("vendor"),
        lib_dir: prefix.join("lib"),
        inc_dir: prefix.join("include"),
        libs: vec!["crypto".to_string(), "ssl".to_string()],
    }
}
