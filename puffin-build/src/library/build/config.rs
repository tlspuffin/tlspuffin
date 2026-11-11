use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::builder::Builder;
use super::options::Options;
use super::sources::Sources;
use crate::catalogue::{self, Catalogue, Derived, LibraryState, Spec};
use crate::error::Result;
use crate::utils::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    builder: Builder,
    sources: Sources,

    /// For a vendor name derived from the catalogue: how it was derived (its fix list is in the
    /// options)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    derived: Option<Derived>,

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
            derived: None,
            options: options.into(),
        }
    }

    /// The configuration of the name of a build: a preset of `vendors/<vendor>/presets.toml` as it
    /// is, or any other name of a build (`5.4.0,asan,only-BUF`, `wolfssl540-asan-only-…`, `<ID>`:
    /// see [`catalogue::spec`]): the preset it uses, with the build's options and fix list.
    pub fn resolve(vendor: &str, name: &str) -> std::result::Result<Config, String> {
        Config::resolve_named(vendor, name).map(|(config, _)| config)
    }

    /// [`Config::resolve`], with the name of the build: its library directory and PUT (a preset's
    /// name, or the slug of the build).
    pub fn resolve_named(
        vendor: &str,
        name: &str,
    ) -> std::result::Result<(Config, String), String> {
        if let Some(config) = Config::preset(vendor, name) {
            return Ok((config, name.to_string()));
        }
        let spec = catalogue::resolve_name(vendor, name)?;
        Ok((Config::of_spec(vendor, &spec)?, spec.slug))
    }

    /// The configuration of a resolved name: its preset's, with the options that differ and the
    /// fix list.
    pub fn of_spec(vendor: &str, spec: &Spec) -> std::result::Result<Config, String> {
        let mut config = Config::preset(vendor, &spec.preset)
            .ok_or_else(|| format!("preset '{}' not found", spec.preset))?;
        for (option, on) in &spec.changes {
            config.options.insert(option.as_str(), *on);
        }
        let mut fix = spec.info.fix.clone();
        let mut preset_fix = config.options.fix();
        fix.sort();
        preset_fix.sort();
        if spec.derived.is_some() || fix != preset_fix {
            config.options.insert("fix", spec.info.fix.clone());
        }
        config.derived = spec.derived.clone();
        Ok(config)
    }

    pub fn derived(&self) -> Option<&Derived> {
        self.derived.as_ref()
    }

    pub fn preset(vendor: impl AsRef<str>, name: impl AsRef<str>) -> Option<Config> {
        // TODO gracefully handle error cases rather than using `unwrap`
        let configs_str = fs::read_to_string(
            catalogue::vendors_dir()
                .join(vendor.as_ref())
                .join("presets.toml"),
        )
        .ok()?;

        toml::from_str::<HashMap<String, Config>>(&configs_str)
            .ok()?
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

    /// The state of every catalogue entry in a build of this configuration (`None` for vendors
    /// without catalogue).
    pub fn catalogue_state(&self) -> std::result::Result<Option<LibraryState>, String> {
        let Builder::BuiltIn { name } = &self.builder else {
            return Ok(None);
        };
        let version = self.sources.version();
        let Some(plan) = super::builder::catalogue_plan(name, &version, &self.options)? else {
            return Ok(None);
        };
        let catalogue = Catalogue::load(name).map_err(|e| e.to_string())?;
        let mut state = catalogue.library_state(&version, &plan);
        state.derived = self.derived.clone();
        Ok(Some(state))
    }

    pub fn builder(&self) -> &Builder {
        &self.builder
    }

    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    pub fn option(&mut self, name: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.options.insert(name, value);
        self
    }
}
