use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};

use cmake::Config;

pub struct BoringSSLOptions {
    pub asan: bool,
    pub sancov: bool,
    pub deterministic: bool,

    pub gcov: bool,
    pub llvm_cov: bool,

    pub git_repo: String,
    pub git_ref: GitRef,
    pub out_dir: PathBuf,
    pub source_dir: PathBuf,
}

pub enum GitRef {
    Branch(String),
    Commit(String),
}

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

fn patch_boringssl<P: AsRef<Path>>(out_dir: P, patch: &str) -> std::io::Result<()> {
    let patch_path = Path::new("../boringssl-src/patches").join(patch);
    let status = Command::new("git")
        .current_dir(out_dir)
        .arg("apply")
        .arg(fs::canonicalize(patch_path).unwrap().to_str().unwrap())
        .status()
        .unwrap();

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

    Ok(())
}

fn clone_boringssl<P: AsRef<Path>>(dest: &P, options: &BoringSSLOptions) -> std::io::Result<()> {
    std::fs::remove_dir_all(dest).unwrap_or(());
    let status = match &options.git_ref {
        GitRef::Branch(branch_name) => Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--branch")
            .arg(&branch_name)
            .arg(&options.git_repo)
            .arg(dest.as_ref().to_str().unwrap())
            .status()?,
        GitRef::Commit(commit_id) => {
            Command::new("git")
                .arg("clone")
                .arg("--filter=tree:0")
                .arg(&options.git_repo)
                .arg(dest.as_ref().to_str().unwrap())
                .status()?;
            Command::new("git")
                .current_dir(dest.as_ref().to_str().unwrap())
                .arg("checkout")
                .arg(commit_id)
                .status()?
        }
    };

    if !status.success() {
        return Err(io::Error::from(ErrorKind::Other));
    }

    Ok(())
}

fn build_boringssl<P: AsRef<Path>>(dest: &P, options: &BoringSSLOptions) -> PathBuf {
    // BoringSSL is written in C and C++, so all flags have to be given with
    // cflags and cxxflags
    let mut boring_conf = Config::new(&options.source_dir);
    boring_conf
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("CMAKE_INSTALL_PREFIX", dest.as_ref().to_str().unwrap())
        .define("CMAKE_C_COMPILER", "clang")
        .define("CMAKE_CXX_COMPILER", "clang++")
        .pic(true)
        .cflag("-g")
        .cxxflag("-g")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("OPENSSL_NO_BUF_FREELISTS", "1");

    if env::var("TARGET") == Ok("aarch64-apple-darwin".into()) {
        // We rely on llvm installed with homebrew on Mac OS X since Xcode does not ship llvm with
        // libfuzzer!
        boring_conf
            .define("CMAKE_C_COMPILER", "/opt/homebrew/opt/llvm/bin/clang")
            .define("CMAKE_CXX_COMPILER", "/opt/homebrew/opt/llvm/bin/clang++");
    }

    if options.deterministic {
        // FUZZ flag will enable deterministic mode in BoringSSL along with
        // disabling all encryption. To prevent BoringSSL from disabling encryption
        // we also pass the NO_FUZZER_MODE flag
        // See https://github.com/google/boringssl/blob/master/FUZZING.md for details
        boring_conf.define("FUZZ", "1");
        boring_conf.define("NO_FUZZER_MODE", "1");
    }

    if options.sancov {
        boring_conf
            .cflag("-fsanitize-coverage=trace-pc-guard")
            .cxxflag("-fsanitize-coverage=trace-pc-guard");
    }

    if options.gcov {
        boring_conf
            .cflag("-ftest-coverage")
            .cflag("-fprofile-arcs")
            .cxxflag("-ftest-coverage")
            .cxxflag("-fprofile-arcs");
    }

    if options.llvm_cov {
        boring_conf
            .cflag("-fprofile-instr-generate")
            .cflag("-fcoverage-mapping")
            .cxxflag("-fprofile-instr-generate")
            .cxxflag("-fcoverage-mapping");
    }

    if options.asan {
        let output = Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to clang to get resource dir");
        let clang: &str = std::str::from_utf8(&output.stdout).unwrap().trim();

        // Important: Make sure to pass these flags to the linker invoked by rustc!
        boring_conf
            .cflag("-fsanitize=address")
            .cflag("-shared-libsan")
            .cflag("-Wno-unused-command-line-argument")
            .cflag(format!("-Wl,-rpath={}/lib/linux/", clang))
            .cxxflag("-fsanitize=address")
            .cxxflag("-shared-libsan")
            .cxxflag("-Wno-unused-command-line-argument")
            .cxxflag(format!("-Wl,-rpath={}/lib/linux/", clang));
    }

    boring_conf.build_target("ssl;crypto");
    boring_conf.build();

    Command::new(PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/install"
    )))
    .arg(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("boringssl"))
    .arg(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("build"))
    .arg(dest.as_ref().to_str().unwrap())
    .status()
    .expect("failed install step for boringssl");

    dest.as_ref().to_owned()
}

pub fn build(options: &BoringSSLOptions) -> std::io::Result<()> {
    clone_boringssl(&options.source_dir, options).unwrap();

    // Patching CMakeList.txt to disable ASAN when using the fuzzer mode
    let _ = patch_boringssl(&options.source_dir, "no_asan.patch").unwrap();
    let _ = patch_boringssl(&options.source_dir, "extract_transcript.patch").unwrap();

    if options.deterministic {
        // Patching boringssl to reset the DRBG
        let _ = patch_boringssl(&options.source_dir, "reset_drbg.patch").unwrap();
    }

    let _ = build_boringssl(&options.out_dir, options);

    Ok(())
}
