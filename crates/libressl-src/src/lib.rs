extern crate autotools;

use std::{
    env, fs,
    fs::{canonicalize, File},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const REF: &str = if cfg!(feature = "libressl333") {
    "fuzz-v3.3.3"
} else if cfg!(feature = "libresslmaster") {
    "master"
} else {
    panic!("Unknown version of LibreSSL requested!")
};

fn clone(dest: &PathBuf) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://github.com/tlspuffin/libressl.git")
        .arg(dest)
        .status()?;

    Ok(())
}

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

    pub fn insert_claim_interface(additional_headers: &PathBuf) -> std::io::Result<()> {
        let interface = security_claims::CLAIM_INTERFACE_H;

        let path = additional_headers.join("claim-interface.h");

        let mut file = File::create(path)?;
        file.write_all(interface.as_bytes())?;

        Ok(())
    }

    pub fn build(&mut self) -> Artifacts {
        if cfg!(feature = "asan") {
            panic!("ASAN not yet supported");
        }

        let target = &self.target.as_ref().expect("TARGET dir not set")[..];
        let host = &self.host.as_ref().expect("HOST dir not set")[..];
        let out_dir = self.out_dir.as_ref().expect("OUT_DIR not set");
        let build_dir = out_dir.join("build");
        let install_dir = out_dir.clone(); // out_dir.join("install");

        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).unwrap();
        }
        if install_dir.exists() {
            fs::remove_dir_all(&install_dir).unwrap();
        }

        let additional_headers = out_dir.join("additional_headers");

        fs::create_dir_all(&additional_headers).unwrap();
        Self::insert_claim_interface(&additional_headers).unwrap();

        let inner_dir = build_dir.join("src");
        fs::create_dir_all(&inner_dir).unwrap();
        clone(&inner_dir).unwrap();

        let _ = host;

        // out_dir defaults to $OUT_DIR/libressl-build
        // install_dir = out_dir
        // build_dir = out_dir/build
        // inner_dir = build_dir/src
        // On Linux, source_dir() == "/usr/locde/libressl"

        // see https://stackoverflow.com/a/33279062/272427
        let mut touch = Command::new("touch");
        touch.current_dir(&inner_dir);
        touch.args(vec![
            "aclocal.m4",
            "configure",
            "Makefile.am",
            "Makefile.in",
        ]);
        self.run_command(touch, "touching ./configure etc for LibreSSL");

        use autotools::Config;
        let mut cfg = Config::new(&inner_dir);
        cfg.disable_shared();

        let mut cc = "clang".to_owned();

        // Make additional headers available
        cc.push_str(
            format!(
                " -I{}",
                canonicalize(&additional_headers).unwrap().to_str().unwrap()
            )
            .as_str(),
        );

        if cfg!(feature = "sancov") {
            cc.push_str(" -fsanitize-coverage=trace-pc-guard");
        }

        cfg.env("CC", cc);

        cfg.out_dir(&install_dir);
        if target.starts_with("i686-unknown-linux") {
            cfg.config_option("host", Some(target));
        }
        cfg.cflag("-v"); // JIMP
        let dst = cfg.build();
        assert_eq!(dst, install_dir);

        fs::remove_dir_all(&inner_dir).unwrap();

        let libs = if target.contains("msvc") {
            vec![
                "libtls".to_string(),
                "libssl".to_string(),
                "libcrypto".to_string(),
            ]
        } else {
            vec!["tls".to_string(), "ssl".to_string(), "crypto".to_string()]
        };

        Artifacts {
            lib_dir: install_dir.join("lib"),
            include_dir: install_dir.join("include"),
            libs,
        }
    }

    #[allow(dead_code)]
    fn run_command(&self, mut command: Command, desc: &str) {
        println!("running {:?}", command);
        let status = command.status().unwrap();
        if !status.success() {
            panic!(
                "


Error {}:
    Command: {:?}
    Exit status: {}


    ",
                desc, command, status
            );
        }
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
    }
}
