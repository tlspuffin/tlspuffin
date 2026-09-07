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
        let mut dirs = vec![self.path().join("include")];
        let vendor_src = self.path().join("src").join("vendor");
        if vendor_src.exists() {
            // The vendor source root itself (for files that use relative includes)
            dirs.push(vendor_src.clone());
            // The include subdirectory (for internal library headers like libssh/libcrypto.h)
            let vendor_src_include = vendor_src.join("include");
            if vendor_src_include.exists() {
                dirs.push(vendor_src_include);
            }
        }
        // vendor-build contains generated headers (e.g. config.h) needed by
        // harnesses that use the vendored library's internal API.
        // Also parse CMakeCache.txt to find OpenSSL include dirs (used by
        // libssh's internal headers).
        let vendor_build = self.path().join("src").join("vendor-build");
        if vendor_build.exists() {
            dirs.push(vendor_build.clone());
            // Parse CMakeCache.txt for OPENSSL_INCLUDE_DIR
            let cmake_cache = vendor_build.join("CMakeCache.txt");
            if let Ok(content) = std::fs::read_to_string(&cmake_cache) {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("OPENSSL_INCLUDE_DIR:PATH=") {
                        let p = PathBuf::from(rest.trim());
                        if p.exists() {
                            dirs.push(p);
                        }
                    }
                }
            }
        }
        dirs
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
