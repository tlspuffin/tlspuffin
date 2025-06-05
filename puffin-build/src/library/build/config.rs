use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::builder::Builder;
use super::options::Options;
use super::sources::Sources;
use crate::error::Result;
use crate::utils::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    builder: Builder,
    sources: Sources,

    #[serde(default)]
    #[serde(flatten)]
    options: Options,
}

impl Config {
    pub fn new(
        sources: impl Into<Sources>,
        builder: impl Into<Builder>,
        options: impl Into<Options>,
    ) -> Self {
        Self {
            builder: builder.into(),
            sources: sources.into(),
            options: options.into(),
        }
    }

    pub fn preset(vendor: impl AsRef<str>, name: impl AsRef<str>) -> Option<Config> {
        // TODO gracefully handle error cases rather than using `unwrap`

        // FIXME don't use harcoded path to configuration files (CARGO_MANIFEST_DIR, ...)
        let configs_str = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("vendors")
                .join(vendor.as_ref())
                .join("presets.toml"),
        )
        .unwrap();

        toml::from_str::<HashMap<String, Config>>(&configs_str)
            .unwrap()
            .get(name.as_ref())
            .cloned()
    }

    pub fn build(&self, out_dir: impl AsRef<Path>, cput: bool) -> Result<()> {
        let sources_dir = out_dir.as_ref().join("src");
        let sources = self.sources.download(sources_dir)?;
        self.builder.build(
            sources,
            out_dir,
            self.sources.version(),
            &self.options,
            cput,
        )
    }

    pub fn option(&mut self, name: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.options.insert(name, value);
        self
    }
}

impl AsRef<Config> for Config {
    fn as_ref(&self) -> &Config {
        self
    }
}
