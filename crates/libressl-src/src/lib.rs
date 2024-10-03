use std::env;
use std::path::{Path, PathBuf};

use puffin_build::vendor;

const PRESET: &str = if cfg!(feature = "libressl333") {
    "libressl333"
} else {
    panic!("Missing LibreSSL version. Use --features=[libresslxxxx] to set the version.");
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub struct Build {
    out_dir: Option<PathBuf>,
    target: Option<String>,
    host: Option<String>,
}

pub struct Artifacts {
    include_dir: PathBuf,
    lib_dir: PathBuf,
    libs: Vec<String>,
}

impl Build {
    pub fn new() -> Build {
        Build {
            out_dir: env::var_os("OUT_DIR").map(|s| PathBuf::from(s).join("libressl-build")),
            target: env::var("TARGET").ok(),
            host: env::var("HOST").ok(),
        }
    }

    pub fn out_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Build {
        self.out_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn target(&mut self, target: &str) -> &mut Build {
        self.target = Some(target.to_string());
        self
    }

    pub fn host(&mut self, host: &str) -> &mut Build {
        self.host = Some(host.to_string());
        self
    }

    pub fn build(&mut self) -> Artifacts {
        let suffix = if cfg!(feature = "asan") { "-asan" } else { "" };
        let name = format!("{PRESET}{suffix}");

        let mut config = vendor::Config::preset("libressl", PRESET)
            .unwrap_or_else(|| panic!("missing preset libressl:{PRESET}"));

        config.option("sancov", cfg!(feature = "sancov"));
        config.option("asan", cfg!(feature = "asan"));
        config.option("gcov", cfg!(feature = "gcov"));
        config.option("llvm_cov", cfg!(feature = "llvm_cov"));

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

        let libressl = Artifacts {
            lib_dir: prefix.join("lib"),
            include_dir: prefix.join("include"),
            libs: vec!["tls".to_string(), "ssl".to_string(), "crypto".to_string()],
        };

        println!("cargo:rerun-if-changed={}", libressl.lib_dir.display());
        println!("cargo:rerun-if-changed={}", libressl.include_dir.display());

        libressl
    }
}

impl Default for Build {
    fn default() -> Self {
        Self::new()
    }
}

impl Artifacts {
    pub fn include_dir(&self) -> &Path {
        &self.include_dir
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
        println!("cargo:include={}", self.include_dir.display());
        println!("cargo:lib={}", self.lib_dir.display());

        println!("cargo:rerun-if-changed={}", self.lib_dir.display());
        println!("cargo:rerun-if-changed={}", self.include_dir.display());
    }
}
