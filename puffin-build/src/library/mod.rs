mod build;
mod metadata;

use std::ffi::OsStr;
use std::path::PathBuf;

pub use build::{Builder, Config, Options, Sources};
pub use metadata::Metadata;

use crate::utils::make_rust_identifier;
use crate::vendor_dir::VendorDir;

#[derive(Debug, Clone)]
pub struct Library {
    name: String,
    config: Config,
    metadata: Metadata,
    vendor_dir: VendorDir,
}

impl Library {
    pub fn new(
        name: impl Into<String>,
        config: impl Into<Config>,
        metadata: impl Into<Metadata>,
        vendor_dir: VendorDir,
    ) -> Self {
        Self {
            name: name.into(),
            config: config.into(),
            metadata: metadata.into(),
            vendor_dir,
        }
    }

    pub fn id(&self) -> String {
        make_rust_identifier(self.name())
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn path(&self) -> PathBuf {
        self.vendor_dir.path_for(&self.name)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn include_dirs(&self) -> Vec<PathBuf> {
        vec![self.path().join("include")]
    }

    pub fn link_libraries(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.path().join("lib"))
            .map(|read_dir| {
                read_dir
                    .filter_map(|x| x.ok())
                    .map(|x| x.path())
                    .filter(|path| path.extension() == Some(OsStr::new("a")))
                    .collect()
            })
            .unwrap_or_default()
    }
}
