use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use derive_more::derive::Display;
use itertools::Itertools;

use crate::error::{Error, Result};
use crate::library::Library;
use crate::puffin;
use crate::utils::cmake;

mod bundle;
mod put;

pub use bundle::{Bundle, BundleBuilder};
pub use put::Put;

pub fn bundle(puts: Vec<Put>) -> BundleBuilder {
    BundleBuilder::new(puts)
}

#[derive(Debug, Clone)]
pub struct Harness {
    library: Library,
    kind: Kind,
    path: PathBuf,
}

#[derive(Debug, Clone, Display)]
pub enum Kind {
    Rust,
    C,
}

impl Harness {
    pub fn harness_for(
        protocol: impl AsRef<str>,
        library: impl Into<Library>,
        kind: Kind,
    ) -> Option<Self> {
        let library = library.into();
        let harness_dir = match kind {
            Kind::Rust => puffin::project_dir().join(format!(
                "{protocol}puffin/src/rust_put/{vendor}",
                protocol = protocol.as_ref(),
                vendor = library.metadata().vendor
            )),
            Kind::C => puffin::project_dir().join(format!(
                "{protocol}puffin/harness/{vendor}",
                protocol = protocol.as_ref(),
                vendor = library.metadata().vendor
            )),
        };

        harness_dir.exists().then_some(Harness {
            library,
            kind,
            path: harness_dir,
        })
    }

    pub fn wrap(&self, out_dir: impl AsRef<Path>) -> Result<Put> {
        let objects = match self.kind {
            Kind::Rust => vec![],
            Kind::C => {
                let mut cmake_conf = cmake::command("harness", &out_dir);
                let mut cflags: Vec<String> = vec![
                    format!("-DPUT_ID={id}", id = self.library.id()),
                    format!("-DREGISTER={id}", id = self.library.id()),
                ];

                if self
                    .library
                    .metadata()
                    .instrumentation
                    .contains(&String::from("claimer"))
                {
                    cflags.push("-DHAS_CLAIMS".into());
                }

                if self
                    .library
                    .metadata()
                    .instrumentation
                    .contains(&String::from("sancov"))
                {
                    cflags.push("-fsanitize-coverage=trace-pc-guard".into());
                }

                cmake_conf
                    .cfg_args
                    .push(format!("-DHARNESS={}", self.path.display()));

                cmake_conf.cfg_args.push(format!(
                    "-DINCLUDE_DIRS={}",
                    self.library
                        .include_dirs()
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .join(",")
                ));

                cmake_conf.cfg_args.push(format!(
                    "-DLINK_LIBRARIES={}",
                    self.library
                        .link_libraries()
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .join(",")
                ));

                cmake_conf
                    .cfg_args
                    .push(format!("-DPUT_ID={id}", id = self.library.id()));

                cmake_conf.cfg_args.push(format!(
                    "-DCMAKE_C_FLAGS='{cflags}'",
                    cflags = cflags.join(" ")
                ));

                cmake_conf.build().map_err(|e| Error::HarnessFailed {
                    harness: Box::new(self.clone()),
                    reason: e,
                })?;

                std::fs::read_dir(&out_dir)
                    .map(|read_dir| {
                        read_dir
                            .filter_map(|x| x.ok())
                            .map(|x| x.path())
                            .filter(|path| path.extension() == Some(OsStr::new("o")))
                            .collect()
                    })
                    .unwrap_or_default()
            }
        };

        Ok(Put::new(self.library.clone(), self.clone(), objects))
    }
}
