use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub src_dir: PathBuf,
    pub bld_dir: PathBuf,
    pub out_dir: PathBuf,
    pub cfg_args: Vec<String>, // TODO: use OsString instead of String for CLI args
}

impl Config {
    pub fn build(&self) -> io::Result<()> {
        let mut configure_cmd = std::process::Command::new("cmake");

        configure_cmd.arg(format!(
            "-DPUFFIN_VERSION:STRING={}",
            crate::puffin::version()
        ));

        configure_cmd.arg(format!(
            "-DCMAKE_INSTALL_PREFIX:PATH={}",
            self.out_dir.display()
        ));

        configure_cmd.arg(String::from("-DCMAKE_C_COMPILER=clang"));
        configure_cmd.arg(String::from("-DCMAKE_CXX_COMPILER=clang++"));

        if let Some("release") = std::env::var("PROFILE").ok().as_deref() {
            configure_cmd.arg(String::from("-DCMAKE_BUILD_TYPE=Release"));
        } else {
            configure_cmd.arg(String::from("-DCMAKE_BUILD_TYPE=Debug"));
        }

        configure_cmd.arg(format!("-B{}", self.bld_dir.display()));
        configure_cmd.arg(format!("-S{}", self.src_dir.display()));
        for arg in self.cfg_args.iter() {
            configure_cmd.arg(arg);
        }

        configure_cmd
            .status()?
            .success()
            .then_some(())
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("failed cmake configure: config={:?}", self),
            ))?;

        let mut build_cmd = std::process::Command::new("cmake");

        build_cmd.arg("--build").arg(&self.bld_dir);
        build_cmd.arg("--target").arg("install");

        build_cmd
            .status()?
            .success()
            .then_some(())
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                format!("failed cmake build: config={:?}", self),
            ))
    }
}

pub fn command(name: impl AsRef<str>, out_dir: impl AsRef<Path>) -> Config {
    const COMMAND_RUNNER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/cmake");

    Config {
        src_dir: PathBuf::from(COMMAND_RUNNER_DIR),
        bld_dir: out_dir.as_ref().join("build"),
        out_dir: out_dir.as_ref().to_path_buf(),
        cfg_args: vec![format!("-DCOMMAND={}", name.as_ref())],
    }
}
