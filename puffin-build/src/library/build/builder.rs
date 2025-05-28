use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Options;
use crate::error::{Error, Result};
use crate::utils::cmake;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Builder {
    BuiltIn { name: String },
    CMake { path: PathBuf },
}

impl Builder {
    pub fn build(
        &self,
        sources: impl AsRef<Path>,
        out_dir: impl AsRef<Path>,
        version: impl AsRef<str>,
        options: impl AsRef<Options>,
        cput: bool,
    ) -> Result<()> {
        match self {
            Self::BuiltIn { .. } | Self::CMake { .. } => {
                let mut cmake_conf = match self {
                    Self::BuiltIn { .. } => cmake::command("builder", out_dir),
                    Self::CMake { path, .. } => cmake::Config {
                        src_dir: path.clone(),
                        out_dir: out_dir.as_ref().to_path_buf(),
                        bld_dir: out_dir.as_ref().join("build"),
                        cfg_args: vec![],
                    },
                };

                if let Self::BuiltIn { name, .. } = self {
                    cmake_conf.cfg_args.push(format!("-DBUILDER={}", name));
                }

                cmake_conf
                    .cfg_args
                    .push(format!("-DSOURCES={}", sources.as_ref().display()));
                cmake_conf
                    .cfg_args
                    .push(format!("-DVENDOR_VERSION={}", version.as_ref()));

                cmake_conf
                    .cfg_args
                    .push(format!("-DCPUT={}", if cput { "1" } else { "0" }));

                for (name, value) in options.as_ref().into_iter() {
                    cmake_conf
                        .cfg_args
                        .push(format!("-D{}={}", name, value.to_cmake_value()));
                }

                cmake_conf.build()
            }
        }
        .map_err(|e| Error::LibraryBuilderFailed {
            builder: self.clone(),
            sources: sources.as_ref().to_path_buf(),
            options: options.as_ref().clone(),
            reason: e,
        })
    }
}
