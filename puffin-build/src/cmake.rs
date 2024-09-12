use std::io;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug)]
pub struct Config {
    pub src_dir: PathBuf,
    pub bld_dir: PathBuf,
    pub out_dir: PathBuf,
    pub cfg_args: Vec<String>,
}

impl Config {
    pub fn build(&self) -> io::Result<()> {
        let mut configure_cmd = Command::new("cmake");

        configure_cmd.arg(format!(
            "-DCMAKE_INSTALL_PREFIX:PATH={}",
            self.out_dir.display()
        ));

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

        let mut build_cmd = Command::new("cmake");

        build_cmd.arg("--build").arg(&self.bld_dir);
        build_cmd.arg("--target").arg("vendor");

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
