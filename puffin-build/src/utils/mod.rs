pub mod clang;
pub mod cmake;
pub mod git;
pub mod value;

pub use value::Value;

pub fn make_rust_identifier(s: impl AsRef<str>) -> String {
    s.as_ref()
        .replace(|c: char| !c.is_alphanumeric() && c != '_', "_")
        .replace("__", "_")
        .trim()
        .to_string()
}
