use std::io;
use std::path::PathBuf;

use derive_more::From;

use crate::harness::Harness;
use crate::library::{Builder, Options, Sources};
use crate::vendor_dir::VendorDir;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    // -- Vendor Dir
    VendorDirUnavailable {
        dir: VendorDir,
        reason: io::Error,
    },

    // -- Library
    SourcesDownloadFailed {
        sources: Sources,
        reason: io::Error,
    },

    LibraryBuilderFailed {
        builder: Builder,
        sources: PathBuf,
        options: Options,
        reason: io::Error,
    },

    // -- Harness
    HarnessFailed {
        harness: Box<Harness>,
        reason: io::Error,
    },

    // -- Other
    DeserializationFailed {
        reason: toml::de::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
