use itertools::Itertools;
use serde::{Deserialize, Serialize};

pub type Array = Vec<Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    String(String),
    Array(Array),
}

impl Value {
    pub fn to_cmake_value(&self) -> String {
        match self {
            Value::Boolean(b) => b.to_string().to_uppercase(),
            Value::Integer(i) => i.to_string(),
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().map(Value::to_cmake_value).join(","),
        }
    }
}

impl From<Array> for Value {
    fn from(value: Array) -> Self {
        Self::Array(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Vec<String>> for Value {
    fn from(value: Vec<String>) -> Self {
        Self::Array(value.into_iter().map(Value::from).collect())
    }
}
