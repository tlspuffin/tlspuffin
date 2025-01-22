use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub vendor: String,
    pub version: String,
    pub instrumentation: Vec<String>,
    pub known_vulnerabilities: Vec<String>,
    pub fixed_vulnerabilities: Vec<String>,
    pub capabilities: Vec<String>,
}

impl Metadata {
    pub fn full_version(&self) -> String {
        format!("{} {}", self.vendor, self.version)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("failed Metadata serialization")
    }

    pub fn from_toml(toml_str: impl AsRef<str>) -> Result<Self> {
        toml::from_str(toml_str.as_ref()).map_err(|e| Error::DeserializationFailed { reason: e })
    }
}
