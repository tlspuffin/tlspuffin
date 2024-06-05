use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::utils::git;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Sources {
    Git {
        #[serde(flatten)]
        tree: git::Tree,
        version: String,
    },
    Url {
        url: String,
        hash: Option<String>,
        version: String,
    },
}

impl Sources {
    pub fn download(&self, dest_dir: impl AsRef<Path>) -> Result<PathBuf> {
        std::fs::create_dir_all(&dest_dir).map_err(|e| Error::SourcesDownloadFailed {
            sources: self.clone(),
            reason: e,
        })?;

        match self {
            Sources::Git { tree, .. } => git::archive(tree.clone()).to_dir(dest_dir),
            Sources::Url { .. } => todo!(),
        }
        .map_err(|e| Error::SourcesDownloadFailed {
            sources: self.clone(),
            reason: e,
        })
    }

    pub fn version(&self) -> String {
        match self {
            Sources::Git { version, .. } | Sources::Url { version, .. } => version.clone(),
        }
    }
}

impl AsRef<Sources> for Sources {
    fn as_ref(&self) -> &Sources {
        self
    }
}
