use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::builder::Builder;
use super::options::Options;
use super::sources::Sources;
use crate::catalogue::{self, Catalogue, Derived, LibraryState, VendorContext};
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

    /// The configuration of a vendor name: a preset of `vendors/<vendor>/presets.toml`, or a name
    /// derived from the vendor's catalogue (see [`Catalogue::derive`]): `<ID>`,
    /// `<preset>-only-<ID>`, `<preset>-fix-<ID>+<ID>`, `<preset>-fix-all`. A derived name is
    /// resolved to its base preset with an explicit fix list.
    pub fn resolve(vendor: &str, name: &str) -> std::result::Result<Config, String> {
        if let Some(config) = Config::preset(vendor, name) {
            return Ok(config);
        }

        let dir = catalogue::vendors_dir().join(vendor);
        if !dir.join("presets.toml").exists() {
            return Err(format!("unknown vendor '{vendor}'"));
        }
        let context = VendorContext::load(vendor, &dir).map_err(|e| e.to_string())?;
        let catalogue = Catalogue::load(vendor).map_err(|e| e.to_string())?;
        let derivation = catalogue.derive(name, &context)?.ok_or_else(|| {
            format!(
                "'{name}' is neither a preset of {vendor} nor a name derived from its catalogue"
            )
        })?;

        let mut config = Config::preset(vendor, &derivation.derived.base)
            .ok_or_else(|| format!("preset '{}' not found", derivation.derived.base))?;
        config.options.insert("fix", derivation.fix);
        if derivation.force_asan {
            config.options.insert("asan", true);
        }
        config.derived = Some(derivation.derived);
        Ok(config)
    }

    pub fn derived(&self) -> Option<&Derived> {
        self.derived.as_ref()
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
