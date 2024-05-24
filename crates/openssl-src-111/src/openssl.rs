extern crate cc;

use std::{
    env,
    fs::canonicalize,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const MK_VENDOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/mk_vendor");

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

    pub fn build_deterministic_rand(openssl: &Artifacts) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let file = root.join("src").join("deterministic_rand.c");
        let buf = canonicalize(file).unwrap();
        let deterministic_rand = buf.to_str().unwrap();

        println!("cargo:rerun-if-changed={}", deterministic_rand);

        cc::Build::new()
            .file(deterministic_rand)
            .include(&openssl.include_dir)
            .compile("deterministic_rand");
    }

    pub fn build(&mut self) -> Artifacts {
        let target = &self.target.as_ref().expect("TARGET dir not set")[..];

        let mut mk_vendor_config: Vec<String> = vec![];
        mk_vendor_config.push(format!("openssl:{}", PRESET));

        let options: Vec<&str> = vec![
            #[cfg(feature = "asan")]
            "asan",
            #[cfg(feature = "sancov")]
            "sancov",
            #[cfg(feature = "gcov_analysis")]
            "gcov",
            #[cfg(feature = "llvm_cov_analysis")]
            "llvm_cov",
        ];

        mk_vendor_config.push(format!("--options={}", options.join(",")));

        let suffix = if !options.is_empty() {
            format!("-{}", options.join("-"))
        } else {
            "".to_string()
        };
        mk_vendor_config.push(format!("--name={}{}", PRESET, suffix));

        let mut build_cmd = Command::new(MK_VENDOR);
        build_cmd.arg("make");
        build_cmd.args(&mk_vendor_config);

        self.run_command(build_cmd, format!("Building OpenSSL {}", PRESET));

        let mut locate_cmd = Command::new(MK_VENDOR);
        locate_cmd.arg("locate");
        locate_cmd.args(&mk_vendor_config);

        let res = self.run_command(
            locate_cmd,
            format!("Getting install prefix for OpenSSL {}", PRESET),
        );
        let prefix = PathBuf::from(String::from_utf8_lossy(&res.stdout).into_owned().trim());

        let openssl = Artifacts {
            lib_dir: prefix.join("lib"),
            bin_dir: prefix.join("bin"),
            include_dir: prefix.join("include"),
            libs: vec!["ssl".to_string(), "crypto".to_string()],
            target: target.to_string(),
        };

        if cfg!(feature = "no-rand") {
            Self::build_deterministic_rand(&openssl);
        }

        println!("cargo:rerun-if-changed={}", openssl.lib_dir.display());
        println!("cargo:rerun-if-changed={}", openssl.include_dir.display());

        openssl
    }

    fn run_command(&self, mut command: Command, desc: impl AsRef<str>) -> Output {
        println!("running {:?}", command);
        let res = command.output().unwrap();

        println!(
            concat!(
                "\n\n\n",
                "{}:\n",
                "    Command: {:?}\n",
                "    Exit status: {}\n",
                "    ===== stdout =====\n{}\n",
                "    ===== stderr =====\n{}\n",
                "\n\n"
            ),
            desc.as_ref(),
            command,
            res.status,
            String::from_utf8_lossy(&res.stdout).into_owned().trim(),
            String::from_utf8_lossy(&res.stderr).into_owned().trim()
        );

        if !res.status.success() {
            panic!("Command failed. Cannot build OpenSSL vendor library.");
        }

        res
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
