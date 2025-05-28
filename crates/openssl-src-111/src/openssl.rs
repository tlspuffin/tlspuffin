extern crate cc;

use std::env;
use std::fs::canonicalize;
use std::path::{Path, PathBuf};

use puffin_build::{library, vendor_dir};

const PRESET: &str = if cfg!(feature = "openssl101f") {
    "openssl101f"
} else if cfg!(feature = "openssl102u") {
    "openssl102u"
} else if cfg!(feature = "openssl111k") {
    "openssl111k"
} else if cfg!(feature = "openssl111j") {
    "openssl111j"
} else if cfg!(feature = "openssl111u") {
    "openssl111u"
} else if cfg!(feature = "openssl312") {
    "openssl312"
} else {
    panic!("Missing OpenSSL version. Use --features=[opensslxxxx] to set the version.");
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
    bin_dir: PathBuf,
    libs: Vec<String>,
    target: String,
}

impl Build {
    pub fn new() -> Build {
        Build {
            out_dir: env::var_os("OUT_DIR").map(|s| PathBuf::from(s).join("openssl-build")),
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

    pub fn build_prng_interface(openssl: &Artifacts) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let file = root.join("src").join("deterministic_rand.c");
        let buf = canonicalize(file).unwrap();
        let deterministic_rand = buf.to_str().unwrap();

        println!("cargo:rerun-if-changed={}", deterministic_rand);

        let mut builder = cc::Build::new();

        builder
            .file(deterministic_rand)
            .include(&openssl.include_dir);

        #[cfg(feature = "no-rand")]
        builder.define("USE_CUSTOM_PRNG", "1");

        builder.compile("openssl_prng_interface");
    }

    pub fn build(&mut self) -> Artifacts {
        let target = &self.target.as_ref().expect("TARGET dir not set")[..];

        let suffix = if cfg!(feature = "asan") { "-asan" } else { "" };
        let name = format!("{PRESET}{suffix}");

        let mut config = library::Config::preset("openssl", PRESET).unwrap();

        config.option("sancov", cfg!(feature = "sancov"));
        config.option("asan", cfg!(feature = "asan"));
        config.option("gcov", cfg!(feature = "gcov"));
        config.option("llvm_cov", cfg!(feature = "llvm_cov"));

        let prefix = vendor_dir::from_env()
            .library_dir(&name)
            .and_then(|dir| dir.make(config, false))
            .unwrap();

        let openssl = Artifacts {
            lib_dir: prefix.join("lib"),
            bin_dir: prefix.join("bin"),
            include_dir: prefix.join("include"),
            libs: vec!["ssl".to_string(), "crypto".to_string()],
            target: target.to_string(),
        };

        Self::build_prng_interface(&openssl);

        println!("cargo:rerun-if-changed={}", openssl.lib_dir.display());
        println!("cargo:rerun-if-changed={}", openssl.include_dir.display());

        openssl
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

    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    pub fn libs(&self) -> &[String] {
        &self.libs
    }

    pub fn target(&mut self) -> String {
        self.target.clone()
    }

    pub fn print_cargo_metadata(&self) {
        println!("cargo:rustc-link-search=native={}", self.lib_dir.display());
        for lib in self.libs.iter() {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
        println!("cargo:include={}", self.include_dir.display());
        println!("cargo:lib={}", self.lib_dir.display());
    }
}
