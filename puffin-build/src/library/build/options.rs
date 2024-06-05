use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::utils::Value;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Options(HashMap<String, Value>);

impl Options {
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.0.insert(name.into(), value.into());
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
