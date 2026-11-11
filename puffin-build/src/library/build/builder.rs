use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Options;
use crate::catalogue::{self, BuildPlan, Catalogue};
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
        let failed = |reason: io::Error| Error::LibraryBuilderFailed {
            builder: self.clone(),
            sources: sources.as_ref().to_path_buf(),
            options: options.as_ref().clone(),
            reason,
        };

        // known vulnerabilities and fix patches come from the vendor's catalogue
        let plan = match self {
            Self::BuiltIn { name } => catalogue_plan(name, version.as_ref(), options.as_ref())
                .map_err(|e| failed(io::Error::other(e)))?,
            Self::CMake { .. } => None,
        };

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

                    // the patches of presets.toml for this version (instrumentation, build fixes)
                    let library_patches = super::presets::load(name)
                        .map(|p| {
                            p.patches_for(&catalogue::vendors_dir().join(name), version.as_ref())
                        })
                        .unwrap_or_default();
                    if !library_patches.is_empty() {
                        cmake_conf.cfg_args.push(format!(
                            "-DLIBRARY_PATCHES={}",
                            library_patches
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        ));
                    }

                    if let Some(plan) = plan {
                        let join = |items: Vec<String>| items.join(",");
                        cmake_conf.cfg_args.push("-DCATALOGUE=ON".into());
                        cmake_conf
                            .cfg_args
                            .push(format!("-DCATALOGUE_KNOWN={}", join(plan.known)));
                        cmake_conf
                            .cfg_args
                            .push(format!("-DCATALOGUE_FIXED={}", join(plan.fixed)));
                        cmake_conf.cfg_args.push(format!(
                            "-DCATALOGUE_PATCHES={}",
                            join(
                                plan.patches
                                    .iter()
                                    .map(|p| p.display().to_string())
                                    .collect()
                            )
                        ));
                    }
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
        .map_err(failed)
    }
}

/// The catalogue plan of a build of the builtin vendor `vendor`, or `None` when the vendor has no
/// catalogue file.
pub fn catalogue_plan(
    vendor: &str,
    version: &str,
    options: &Options,
) -> std::result::Result<Option<BuildPlan>, String> {
    if !catalogue::vendors_dir()
        .join(vendor)
        .join(catalogue::FILE_NAME)
        .exists()
    {
        return Ok(None);
    }

    let catalogue = Catalogue::load(vendor).map_err(|e| e.to_string())?;
    catalogue
        .plan(version, &options.booleans(), &options.fix())
        .map(Some)
}
