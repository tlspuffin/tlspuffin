//! Library versions and version ranges, as used by the vulnerability catalogue.
//!
//! A version is a dotted list of numbers, optionally followed by
//! - letters: a patch release after the plain version (OpenSSL: `1.0.1` < `1.0.1a` < `1.0.1f` <
//!   `1.0.1g`, and `0.9.8z` < `0.9.8za`);
//! - `-<text>`: a pre-release, before the plain version (`3.0.0-alpha1` < `3.0.0`);
//! - `+<text>`: build metadata, not compared (BoringSSL's commits: `1.1.1g+git.368d0d87d0bd` =
//!   `1.1.1g`).
//!
//! Missing numbers count as zero (`5.4` = `5.4.0`). A version that does not start with a digit
//! (`master`, `main`, a name without numbers) is a development head: newer than every release; one
//! that has numbers (`v5.4.0`) is refused.
//!
//! A range is a list of alternatives separated by `||`, each a list of comparisons separated by `,`
//! that must all hold: `">= 1.0.0, < 1.0.0p || >= 1.0.1, < 1.0.1k"`. Comparisons: `<`, `<=`, `>`,
//! `>=`, `=`.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct Version {
    text: String,
    key: Key,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    // NOTE variant order matters: every release is older than a development head
    Release(Vec<u64>, Suffix),
    Head,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Suffix {
    Pre(String),
    None,
    Letters(String),
}

impl Suffix {
    fn rank(&self) -> u8 {
        match self {
            Suffix::Pre(_) => 0,
            Suffix::None => 1,
            Suffix::Letters(_) => 2,
        }
    }
}

impl Ord for Suffix {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Suffix::Pre(a), Suffix::Pre(b)) => a.cmp(b),
            // `z` < `za`: shorter first, then alphabetical
            (Suffix::Letters(a), Suffix::Letters(b)) => (a.len(), a).cmp(&(b.len(), b)),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

impl PartialOrd for Suffix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Version {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_head(&self) -> bool {
        self.key == Key::Head
    }
}

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        if text.is_empty() {
            return Err("empty version".into());
        }

        if !text.starts_with(|c: char| c.is_ascii_digit()) {
            if !text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                return Err(format!("invalid version '{text}'"));
            }
            // a development head is a branch name without numbers (master, main): "v5.4.0" is a
            // release written with a prefix, which would otherwise sort after every
            // release
            if text.contains(|c: char| c.is_ascii_digit()) {
                return Err(format!(
                    "invalid version '{text}': a version starts with a digit (5.4.0); a development head (master, \
                     main) has none"
                ));
            }
            return Ok(Version {
                text: text.into(),
                key: Key::Head,
            });
        }

        // build metadata: kept in the text, not compared
        let compared = match text.split_once('+') {
            Some((compared, metadata)) => {
                if metadata.is_empty()
                    || !metadata
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
                {
                    return Err(format!("invalid build metadata in version '{text}'"));
                }
                compared
            }
            None => text,
        };
        let numeric_end = compared
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(compared.len());
        let (numeric, rest) = compared.split_at(numeric_end);

        if numeric.ends_with('.') || numeric.contains("..") {
            return Err(format!("invalid version '{text}'"));
        }

        let mut numbers = numeric
            .split('.')
            .map(|n| {
                n.parse::<u64>()
                    .map_err(|_| format!("invalid version '{text}'"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        while numbers.len() > 1 && numbers.last() == Some(&0) {
            numbers.pop();
        }

        let suffix = if rest.is_empty() {
            Suffix::None
        } else if let Some(pre) = rest.strip_prefix('-') {
            if pre.is_empty() || !pre.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
                return Err(format!("invalid pre-release in version '{text}'"));
            }
            Suffix::Pre(pre.into())
        } else if rest.chars().all(|c| c.is_ascii_lowercase()) {
            Suffix::Letters(rest.into())
        } else {
            return Err(format!("invalid version '{text}'"));
        };

        Ok(Version {
            text: text.into(),
            key: Key::Release(numbers, suffix),
        })
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Version {}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Comparison {
    op: Op,
    version: Version,
}

impl Comparison {
    fn holds(&self, v: &Version) -> bool {
        let ord = v.cmp(&self.version);
        match self.op {
            Op::Lt => ord == Ordering::Less,
            Op::Le => ord != Ordering::Greater,
            Op::Gt => ord == Ordering::Greater,
            Op::Ge => ord != Ordering::Less,
            Op::Eq => ord == Ordering::Equal,
        }
    }
}

/// A set of versions (see the module documentation for the syntax).
#[derive(Debug, Clone)]
pub struct VersionRange {
    text: String,
    alternatives: Vec<Vec<Comparison>>,
}

impl VersionRange {
    pub fn contains(&self, version: &Version) -> bool {
        self.alternatives
            .iter()
            .any(|all| all.iter().all(|c| c.holds(version)))
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl PartialEq for VersionRange {
    fn eq(&self, other: &Self) -> bool {
        self.alternatives == other.alternatives
    }
}

impl FromStr for VersionRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim().to_string();
        let alternatives = text
            .split("||")
            .map(|alternative| {
                alternative
                    .split(',')
                    .map(|comparison| {
                        let comparison = comparison.trim();
                        let (op, rest) = [
                            (">=", Op::Ge),
                            ("<=", Op::Le),
                            (">", Op::Gt),
                            ("<", Op::Lt),
                            ("=", Op::Eq),
                        ]
                        .iter()
                        .find_map(|(prefix, op)| comparison.strip_prefix(prefix).map(|r| (*op, r)))
                        .ok_or_else(|| {
                            format!(
                                "invalid version range '{text}': '{comparison}' does not start with <, <=, >, >= or ="
                            )
                        })?;
                        let version = rest
                            .parse::<Version>()
                            .map_err(|e| format!("invalid version range '{text}': {e}"))?;
                        Ok(Comparison { op, version })
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(VersionRange { text, alternatives })
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Serialize for VersionRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for VersionRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        s.parse().unwrap()
    }

    fn r(s: &str) -> VersionRange {
        s.parse().unwrap()
    }

    #[test]
    fn numeric_versions_are_ordered_by_their_numbers() {
        assert!(v("5.4.0") < v("5.5.1"));
        assert!(v("5.10.0") > v("5.9.9"));
        assert_eq!(v("5.4"), v("5.4.0"));
        assert!(v("4.4.0") < v("4.7.0"));
    }

    #[test]
    fn letter_suffixes_follow_the_plain_version() {
        assert!(v("1.0.1") < v("1.0.1a"));
        assert!(v("1.0.1f") < v("1.0.1g"));
        assert!(v("1.0.1z") < v("1.0.1za"));
        assert!(v("1.0.1za") < v("1.0.2"));
        assert!(v("1.1.1j") < v("1.1.1k"));
    }

    #[test]
    fn pre_releases_precede_the_plain_version() {
        assert!(v("3.0.0-alpha1") < v("3.0.0"));
        assert!(v("2.9.9") < v("3.0.0-alpha1"));
    }

    #[test]
    fn development_heads_are_newer_than_every_release() {
        assert!(v("master").is_head());
        assert!(v("main").is_head());
        // a release with a prefix is not a head
        assert!("v5.4.0"
            .parse::<Version>()
            .unwrap_err()
            .contains("starts with a digit"));
        assert!("release-5.x".parse::<Version>().is_err());
        assert!(v("master") > v("99.0.0"));
        assert!(!r("< 5.5.1").contains(&v("master")));
        assert!(r(">= 5.5.2").contains(&v("master")));
    }

    #[test]
    fn build_metadata_is_kept_and_not_compared() {
        let commit = v("1.1.1g+git.368d0d87d0bd");
        assert_eq!(commit.as_str(), "1.1.1g+git.368d0d87d0bd");
        assert_eq!(commit, v("1.1.1g"));
        assert!(r("< 1.1.1h").contains(&commit) && !r(">= 1.1.1h").contains(&commit));
        for bad in ["1.1.1+", "1.1.1+a b", "1.1.1+a+b"] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn invalid_versions_are_refused() {
        for bad in ["", "5..4", "5.4.", "5.4.0X", "5.4.0-", "a b"] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn ranges_combine_comparisons_and_alternatives() {
        let freak = r(">= 1.0.0, < 1.0.0p || >= 1.0.1, < 1.0.1k");
        assert!(freak.contains(&v("1.0.0")));
        assert!(freak.contains(&v("1.0.0o")));
        assert!(!freak.contains(&v("1.0.0p")));
        assert!(freak.contains(&v("1.0.1f")));
        assert!(!freak.contains(&v("1.0.1k")));
        assert!(!freak.contains(&v("1.0.2u")));

        let heartbleed = r(">= 1.0.1, < 1.0.1g");
        assert!(heartbleed.contains(&v("1.0.1")));
        assert!(heartbleed.contains(&v("1.0.1f")));
        assert!(!heartbleed.contains(&v("1.0.1g")));

        assert!(r("= 5.3.0").contains(&v("5.3")));
        assert!(!r("= 5.3.0").contains(&v("5.3.1")));
        assert!(r("<= 5.3.0").contains(&v("5.3.0")));
        assert!(r("> 5.3.0").contains(&v("5.3.0a")));
    }

    #[test]
    fn invalid_ranges_are_refused() {
        for bad in ["", "5.4.0", ">= 5.4.0,", "=> 5.4.0", ">= 5.4.0 || ", "~5.4"] {
            assert!(bad.parse::<VersionRange>().is_err(), "{bad:?} accepted");
        }
    }
}
