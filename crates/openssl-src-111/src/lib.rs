extern crate bindgen;
extern crate cc;

use std::{
    env, fs,
    fs::{canonicalize, File},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const REF: &str = if cfg!(feature = "openssl101f") {
    "OpenSSL_1_0_1f"
} else if cfg!(feature = "openssl102u") {
    "OpenSSL_1_0_2u"
} else if cfg!(feature = "openssl111k") {
    "fuzz-OpenSSL_1_1_1k"
} else if cfg!(feature = "openssl111j") {
    "fuzz-OpenSSL_1_1_1j"
} else if cfg!(feature = "openssl111u") {
    "fuzz-OpenSSL_1_1_1u"
} else if cfg!(feature = "openssl312") {
    "fuzz-OpenSSL_3_1_2"
} else {
    "master"
};

#[cfg(not(any(
    feature = "openssl101f",
    feature = "openssl102u",
    feature = "openssl111k",
    feature = "openssl111j",
    feature = "openssl111u",
    feature = "openssl312"
)))]
compile_error!("You need to choose an OpenSSL version!");

fn clone_repo(dest: &str) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest)?;
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(REF)
        .arg("https://github.com/tlspuffin/openssl")
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

    fn cmd_make(&self) -> Command {
        Command::new("make")
    }

    pub fn build_deterministic_rand(install_dir: &PathBuf) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let file = root.join("src").join("deterministic_rand.c");
        let buf = canonicalize(&file).unwrap();
        let deterministic_rand = buf.to_str().unwrap();

        println!("cargo:rerun-if-changed={}", deterministic_rand);

        cc::Build::new()
            .file(deterministic_rand)
            .include(install_dir.join("include"))
            .compile("deterministic_rand");
    }

    pub fn insert_claim_interface(additional_headers: &PathBuf) -> std::io::Result<()> {
        let interface = security_claims::CLAIM_INTERFACE_H;

        let path = additional_headers.join("claim-interface.h");

        let mut file = File::create(path)?;
        file.write_all(interface.as_bytes())?;

        Ok(())
    }

    pub fn build(&mut self) -> Artifacts {
        let target = &self.target.as_ref().expect("TARGET dir not set")[..];
        let host = &self.host.as_ref().expect("HOST dir not set")[..];
        let out_dir = self.out_dir.as_ref().expect("OUT_DIR not set");
        let build_dir = out_dir.join("build");
        let install_dir = out_dir.join("install");
        let additional_headers = out_dir.join("additional_headers");
        fs::create_dir_all(&additional_headers).unwrap();
        Self::insert_claim_interface(&additional_headers).unwrap();

        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).unwrap();
        }
        if install_dir.exists() {
            fs::remove_dir_all(&install_dir).unwrap();
        }

        let inner_dir = build_dir.join("src");
        fs::create_dir_all(&inner_dir).unwrap();

        clone_repo(&inner_dir.to_str().unwrap()).unwrap();

        let perl_program =
            env::var("OPENSSL_SRC_PERL").unwrap_or(env::var("PERL").unwrap_or("perl".to_string()));
        let mut configure = Command::new(perl_program);
        configure.arg("./Configure");

        configure.arg(&format!("--prefix={}", install_dir.display()));
        configure.arg(&format!("--libdir={}/lib", install_dir.display()));

        configure
            // No shared objects, we just want static libraries
            .arg("no-dso")
            .arg("no-shared");
        // No need to build tests, we won't run them anyway
        // TODO .arg("no-unit-test")
        // Nothing related to zlib please
        // TODO .arg("no-comp")
        // TODO .arg("no-zlib")
        // TODO .arg("no-zlib-dynamic")

        // TODO: does only work when combinded with rand.patch?
        //configure.arg("--with-rand-seed=none");

        if cfg!(feature = "weak-crypto") {
            // TODO configure.arg("enable-md2").arg("enable-rc5").arg("enable-weak-ssl-ciphers");
        } else {
            // TODO configure.arg("no-md2").arg("no-rc5").arg("no-weak-ssl-ciphers");
        }

        if cfg!(not(feature = "seed")) {
            // TODO configure.arg("no-seed");
        }

        let os = match target {
            "aarch64-apple-darwin" => "darwin64-arm64-cc",
            "x86_64-apple-darwin" => "darwin64-x86_64-cc",
            "x86_64-unknown-linux-gnu" => "linux-x86_64",
            _ => panic!("don't know how to configure OpenSSL for {}", target),
        };
        configure.arg(os);

        if cfg!(feature = "no-rand") {
            // TODO configure.arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION");
        }

        let mut cc = "clang".to_owned();
        let mut cflags = "".to_owned();

        configure.arg("-fPIE"); // -fPIC was previously added through Cargo flags
        cflags.push_str(" -g ");

        if cfg!(feature = "sancov") {
            cflags.push_str(" -fsanitize-coverage=trace-pc-guard ");
        }

        if cfg!(feature = "gcov_analysis") {
            cflags.push_str(" -ftest-coverage -fprofile-arcs -O0 ");
        }

        if cfg!(feature = "llvm_cov_analysis") {
            cflags.push_str(" -fprofile-instr-generate -fcoverage-mapping -O0 ");
        }

        // Make additional headers available
        cflags.push_str(
            format!(
                " -I{}",
                canonicalize(&additional_headers).unwrap().to_str().unwrap()
            )
            .as_str(),
        );

        if cfg!(feature = "asan") {
            // Disable freelists as they may interfere with malloc
            configure.arg("-DOPENSSL_NO_BUF_FREELISTS");

            //configure.arg("enable-asan"); // If compiled with clang this implies "-static-libasan"
            // Important: Make sure to pass these flags to the linker invoked by rustc!
            cflags.push_str(" -fsanitize=address -shared-libsan");
        }

        configure.env("CFLAGS", cflags);
        configure.env("CC", cc);

        // And finally, run the perl configure script!
        configure.current_dir(&inner_dir);
        self.run_command(configure, "configuring OpenSSL build");

        let mut depend = self.cmd_make();
        depend.arg("depend").current_dir(&inner_dir);
        self.run_command(depend, "building OpenSSL dependencies");

        let mut build = self.cmd_make();
        build.current_dir(&inner_dir);

        #[cfg(feature = "openssl101f")]
        build.arg("-j1");
        #[cfg(not(feature = "openssl101f"))]
        build.arg("-j32");

        self.run_command(build, "building OpenSSL");

        let mut install = self.cmd_make();
        install.arg("install_sw").current_dir(&inner_dir);

        self.run_command(install, "installing OpenSSL");

        let libs = vec!["ssl".to_string(), "crypto".to_string()];

        if cfg!(feature = "no-rand") {
            Self::build_deterministic_rand(&install_dir);
        }

        Artifacts {
            lib_dir: install_dir.join("lib"),
            bin_dir: install_dir.join("bin"),
            include_dir: install_dir.join("include"),
            libs: libs,
            target: target.to_string(),
        }
    }

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
