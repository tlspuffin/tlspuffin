use std::{
    collections::HashSet,
    io,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
};

use cmake::Config;

pub struct BoringSSLOptions {
    pub asan: bool,
    pub sancov: bool,
    pub deterministic: bool,

    pub gcov_analysis: bool,
    pub llvm_cov_analysis: bool,

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

fn _patch_boringssl<P: AsRef<Path>>(
    source_dir: &PathBuf,
    out_dir: P,
    patch: &str,
) -> std::io::Result<()> {
    let status = Command::new("git")
        .current_dir(out_dir)
        .arg("am")
        .arg(source_dir.join("patches").join(patch).to_str().unwrap())
        .status()?;

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
            .arg("https://github.com/google/boringssl.git")
            .arg(dest.as_ref().to_str().unwrap())
            .status()?,
        GitRef::Commit(commit_id) => {
            Command::new("git")
                .arg("clone")
                .arg("https://github.com/google/boringssl.git")
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
        .cxxflag("-g");

    if options.deterministic {
        boring_conf
            .define("FUZZ", "1")
            .define("NO_FUZZER_MODE", "1");
    }

    if options.sancov {
        boring_conf
            .cflag("-fsanitize-coverage=trace-pc-guard")
            .cxxflag("-fsanitize-coverage=trace-pc-guard");
    }

    if options.gcov_analysis {
        boring_conf
            .cflag("-ftest-coverage")
            .cflag("-fprofile-arcs")
            .cxxflag("-ftest-coverage")
            .cxxflag("-fprofile-arcs");
    }

    if options.llvm_cov_analysis {
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
            .cxxflag(format!("-Wl,-rpath={}/lib/linux/", clang))
            .define("OPENSSL_NO_BUF_FREELISTS", "1")
            .define("OPENSSL_NO_ASM", "1");
    }

    boring_conf.build();
    dest.as_ref().to_owned()
}

pub fn build(options: &BoringSSLOptions) -> std::io::Result<()> {
    clone_boringssl(&options.source_dir, options)?;

    let _ = build_boringssl(&options.out_dir, options);

    Ok(())
}
