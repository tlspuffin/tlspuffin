use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::utils::Value;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Options(HashMap<String, Value>);

impl Options {
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.0.insert(name.into(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Value> {
        self.0.remove(name)
    }

    /// The boolean options (CMake `option()`s of the builders).
    pub fn booleans(&self) -> std::collections::BTreeMap<String, bool> {
        self.0
            .iter()
            .filter_map(|(name, value)| match value {
                Value::Boolean(b) => Some((name.clone(), *b)),
                _ => None,
            })
            .collect()
    }

    /// The ids of the `fix` option (the known vulnerabilities to patch).
    pub fn fix(&self) -> Vec<String> {
        match self.0.get("fix") {
            Some(Value::Array(ids)) => ids
                .iter()
                .map(|id| match id {
                    Value::String(s) => s.clone(),
                    other => other.to_cmake_value(),
                })
                .collect(),
            Some(Value::String(s)) => s.split(',').map(String::from).collect(),
            _ => vec![],
        }
    }
}

impl<'a> IntoIterator for &'a Options {
    type IntoIter = std::collections::hash_map::Iter<'a, String, Value>;
    type Item = (&'a String, &'a Value);

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<Options> for Options {
    fn as_ref(&self) -> &Options {
        self
    }
}
