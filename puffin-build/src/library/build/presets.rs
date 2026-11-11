//! The presets of a vendor, `vendors/<vendor>/presets.toml`: the builds it names.
//!
//! Format 2 (`format = 2`) describes the library once and lists the versions tested with the
//! harness:
//!
//! ```toml
//! format = 2
//!
//! [library]
//! repo = "https://github.com/wolfSSL/wolfssl.git"  # git sources (url = "<template>": archives)
//! builder = "wolfssl"                             # the builtin builder (its builder.cmake)
//! ref = "v{version}-stable"                       # branch or tag of a version, or rules by range:
//!                                                 # [{ versions = "< 3.0.0", ref = "OpenSSL_{version_}" }]
//! name = "wolfssl{compact}"                       # name of a version's build (default: <vendor>{compact})
//!
//! [versions]                                      # tested with the harness
//! "5.4.0" = {}
//! "master" = { ref = "master" }                   # its own ref, commit, repo, url, hash or name
//!
//! [modifiers]                                     # the modifiers of this vendor's names, their value
//! asan = { default = false, doc = "…" }           # in a build of a version (sancov on, the rest as
//! sancov = { default = true, doc = "…" }          # the builder's defaults)
//!
//! [aliases]                                       # named builds (benchmarks, their history): a version,
//! wolfssl540-buf = "5.4.0,fix-CVE-2022-42905"     # modifiers, fix-<ID>+<ID>
//!
//! [[patches]]                                     # applied to every build of these versions, after the
//! versions = ">= 5.5.2, < master"                 # builder's own patches and before the catalogue's fixes
//! files = ["patches/claims-AllowClaim-552.patch"]
//! why = "…"
//! ```
//!
//! Templates: `{version}`, `{version_}` (its dots replaced by `_`), `{compact}` (without its dots).
//! Every other build has a name of the vendor's names (`wolfssl540-asan`, `5.4.0,asan,only-BUF`:
//! see [`crate::catalogue::spec`]): presets.toml lists only versions and the builds named for
//! benchmarks.
//!
//! (Format 1, one table per build, each a whole configuration, is no longer read: the tests keep
//! the last files of that format to check that each of their names still gives the same build.)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::builder::Builder;
use super::config::Config;
use super::options::Options;
use super::sources::Sources;
use crate::catalogue::{self, Version, VersionRange};
use crate::utils::git;

/// The builds a presets.toml names.
#[derive(Debug, Clone)]
pub struct Presets {
    /// The named builds: the build of each version and the aliases
    pub configs: BTreeMap<String, Config>,
    /// Patches applied to every build of their versions
    pub patches: Vec<LibraryPatch>,
    /// The modifiers of the vendor's names
    pub modifiers: BTreeMap<String, Modifier>,
    /// The version of each version's build, by its name
    pub versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryPatch {
    pub versions: VersionRange,
    /// Patch files, relative to the vendor directory, applied in order
    pub files: Vec<String>,
    /// Why every build of these versions needs it
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Modifier {
    /// Its value in the build of a version
    pub default: bool,
    pub doc: String,
}

impl Presets {
    /// The patch files of presets.toml for a build of `version`, in order (absolute paths).
    pub fn patches_for(&self, dir: &Path, version: &str) -> Vec<PathBuf> {
        let Ok(version) = version.parse::<Version>() else {
            return vec![];
        };
        self.patches
            .iter()
            .filter(|p| p.versions.contains(&version))
            .flat_map(|p| p.files.iter().map(|f| dir.join(f)))
            .collect()
    }
}

/// The presets of `vendor` in [`catalogue::vendors_dir`].
pub fn load(vendor: &str) -> Result<Presets, String> {
    load_from(vendor, &catalogue::vendors_dir().join(vendor))
}

/// The presets of `vendor` in its directory `dir`.
pub fn load_from(vendor: &str, dir: &Path) -> Result<Presets, String> {
    let file = dir.join("presets.toml");
    let content = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let presets = parse(vendor, &content, &builder_defaults(dir))?;
    for patch in &presets.patches {
        for f in &patch.files {
            if !dir.join(f).is_file() {
                return Err(format!(
                    "presets.toml of {vendor}: patch file {f} not found"
                ));
            }
        }
    }
    Ok(presets)
}

/// The builder's own defaults of the boolean options: run.cmake's (the instrumentation, off) and
/// those of the vendor's builder.cmake.
pub fn builder_defaults(dir: &Path) -> BTreeMap<String, bool> {
    let read = |path: PathBuf| std::fs::read_to_string(path).unwrap_or_default();
    let mut defaults = catalogue::parse_builder_options(&read(
        catalogue::build_dir().join("cmake/builder/run.cmake"),
    ));
    defaults.extend(catalogue::parse_builder_options(&read(
        dir.join("builder.cmake"),
    )));
    defaults
}

/// Parse a presets.toml of `vendor` (`defaults`: the builder's defaults, see [`builder_defaults`]).
pub fn parse(
    vendor: &str,
    content: &str,
    defaults: &BTreeMap<String, bool>,
) -> Result<Presets, String> {
    let err = |m: String| format!("presets.toml of {vendor}: {m}");
    let table: toml::Table = toml::from_str(content).map_err(|e| err(e.to_string()))?;
    match table.get("format") {
        Some(toml::Value::Integer(2)) => parse_v2(vendor, content, defaults).map_err(err),
        None => Err(err(
            "format 1 (one table per build) is no longer read: write format = 2 (see puffin-build/README.md)".into(),
        )),
        Some(other) => Err(err(format!("unknown format {other} (2)"))),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV2 {
    #[allow(dead_code)]
    format: u32,
    library: LibraryV2,
    versions: BTreeMap<String, VersionV2>,
    modifiers: BTreeMap<String, Modifier>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    patches: Vec<LibraryPatch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LibraryV2 {
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    url: Option<String>,
    builder: String,
    #[serde(default, rename = "ref")]
    reference: Option<RefRule>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RefRule {
    One(String),
    ByVersions(Vec<RefRange>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefRange {
    versions: VersionRange,
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct VersionV2 {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "ref")]
    reference: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    hash: Option<String>,
}

/// A template with a version: `{version}`, `{version_}`, `{compact}`.
fn expand(template: &str, version: &str) -> String {
    template
        .replace("{version_}", &version.replace('.', "_"))
        .replace("{compact}", &version.replace('.', ""))
        .replace("{version}", version)
}

fn parse_v2(
    vendor: &str,
    content: &str,
    defaults: &BTreeMap<String, bool>,
) -> Result<Presets, String> {
    let file: FileV2 = toml::from_str(content).map_err(|e| e.to_string())?;

    // the modifiers: the instrumentation and the builder's options, each with its plain value
    let declared: Vec<&String> = file.modifiers.keys().collect();
    let known: Vec<&String> = defaults.keys().collect();
    if declared != known {
        return Err(format!(
            "[modifiers] must declare the instrumentation and the builder's options, no more: {} (declared: {})",
            known.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            declared.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    for (name, modifier) in &file.modifiers {
        let plain = name == "sancov" || defaults[name];
        if modifier.default != plain {
            return Err(format!(
                "[modifiers] {name}: default = {plain} (sancov is on in a build of a version, the rest \
                 as the builder's defaults)"
            ));
        }
    }
    // in a build of a version: the modifiers whose value is not the builder's default (sancov)
    let mut plain_options = Options::default();
    for (name, modifier) in &file.modifiers {
        if modifier.default != defaults[name] {
            plain_options.insert(name.as_str(), modifier.default);
        }
    }
    let builder = Builder::BuiltIn {
        name: file.library.builder.clone(),
    };

    let mut configs = BTreeMap::new();
    let mut versions = BTreeMap::new();
    let mut name_of_version = BTreeMap::new();
    for (version, entry) in &file.versions {
        let name = match &entry.name {
            Some(name) => name.clone(),
            None => expand(
                file.library
                    .name
                    .as_deref()
                    .unwrap_or(&format!("{vendor}{{compact}}")),
                version,
            ),
        };
        let repo = || {
            entry
                .repo
                .clone()
                .or_else(|| file.library.repo.clone())
                .ok_or_else(|| format!("version {version}: no repo"))
        };
        let sources = if let Some(commit) = &entry.commit {
            Sources::Git {
                tree: git::Tree::new(git::Repo::new(repo()?), git::Head::commit(commit)),
                version: version.clone(),
            }
        } else if let Some(url) = entry
            .url
            .clone()
            .or_else(|| file.library.url.as_ref().map(|t| expand(t, version)))
        {
            Sources::Url {
                url,
                hash: entry.hash.clone(),
                version: version.clone(),
            }
        } else {
            let reference = match (&entry.reference, &file.library.reference) {
                (Some(reference), _) => reference.clone(),
                (None, Some(RefRule::One(template))) => expand(template, version),
                (None, Some(RefRule::ByVersions(rules))) => {
                    let parsed = version.parse::<Version>().ok();
                    let rule = rules
                        .iter()
                        .find(|r| parsed.as_ref().is_some_and(|v| r.versions.contains(v)))
                        .ok_or_else(|| format!("version {version}: no ref rule for it"))?;
                    expand(&rule.reference, version)
                }
                (None, None) => {
                    return Err(format!(
                        "version {version}: no ref (give ref, commit or url)"
                    ))
                }
            };
            Sources::Git {
                tree: git::Tree::new(git::Repo::new(repo()?), git::Head::branch(reference)),
                version: version.clone(),
            }
        };
        if configs
            .insert(
                name.clone(),
                Config::new(sources, builder.clone(), plain_options.clone()),
            )
            .is_some()
        {
            return Err(format!("two versions are named {name}"));
        }
        versions.insert(name.clone(), version.clone());
        name_of_version.insert(version.clone(), name);
    }

    for (alias, build) in &file.aliases {
        if configs.contains_key(alias) {
            return Err(format!("alias {alias}: the name of a version's build"));
        }
        let mut tokens = build.split(',').map(str::trim);
        let version = tokens.next().unwrap_or_default();
        let base = name_of_version
            .get(version)
            .ok_or_else(|| format!("alias {alias}: '{version}' is not a version of [versions]"))?;
        let mut config = configs[base].clone();
        let mut fix: Vec<String> = vec![];
        for token in tokens {
            if let Some(ids) = token.strip_prefix("fix-") {
                fix.extend(ids.split(catalogue::ID_SEPARATOR).map(String::from));
                continue;
            }
            let (modifier, on) = match token.strip_prefix("no-") {
                Some(m) => (m, false),
                None => (token, true),
            };
            if !file.modifiers.contains_key(modifier) {
                return Err(format!(
                    "alias {alias}: '{token}' (an alias is a version, modifiers of [modifiers] and fix-<ID>+<ID>)"
                ));
            }
            config.options_mut().insert(modifier, on);
        }
        if !fix.is_empty() {
            config.options_mut().insert("fix", fix);
        }
        configs.insert(alias.clone(), config);
    }

    Ok(Presets {
        configs,
        patches: file.patches,
        modifiers: file.modifiers,
        versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> BTreeMap<String, bool> {
        BTreeMap::from([
            ("asan".into(), false),
            ("gcov".into(), false),
            ("llvm_cov".into(), false),
            ("postauth".into(), true),
            ("sancov".into(), false),
        ])
    }

    const V2: &str = r#"
format = 2

[library]
repo = "https://example.org/lib.git"
builder = "lib"
ref = [{ versions = "< 3.0.0", ref = "Lib_{version_}" }, { versions = ">= 3.0.0", ref = "lib-{version}" }]

[versions]
"1.1.1j" = {}
"3.4.1" = {}
"master" = { ref = "master" }
"1.0.0+git.abc" = { name = "lib2020", commit = "abc" }

[modifiers]
asan = { default = false, doc = "ASan" }
gcov = { default = false, doc = "gcov" }
llvm_cov = { default = false, doc = "llvm coverage" }
postauth = { default = true, doc = "post-auth" }
sancov = { default = true, doc = "coverage" }

[aliases]
lib341-sdos = "3.4.1,no-postauth,asan,fix-CVE-1+CVE-2"

[[patches]]
versions = ">= 3.0.0, < master"
files = ["patches/a.patch"]
why = "claims"
"#;

    #[test]
    fn format_2_names_a_build_per_version_and_the_aliases() {
        let presets = parse("lib", V2, &defaults()).unwrap();
        assert_eq!(
            presets.configs.keys().collect::<Vec<_>>(),
            vec!["lib111j", "lib2020", "lib341", "lib341-sdos", "libmaster"]
        );
        let toml_of = |name: &str| toml::to_string(&presets.configs[name]).unwrap();
        assert!(
            toml_of("lib111j").contains("branch = \"Lib_1_1_1j\""),
            "{}",
            toml_of("lib111j")
        );
        assert!(toml_of("lib341").contains("branch = \"lib-3.4.1\""));
        assert!(toml_of("libmaster").contains("branch = \"master\""));
        assert!(toml_of("lib2020").contains("commit = \"abc\""));
        // a version's build: sancov on, the rest as the builder's defaults (not written)
        let plain = presets.configs["lib341"].options().booleans();
        assert_eq!(plain, BTreeMap::from([("sancov".to_string(), true)]));
        let alias = &presets.configs["lib341-sdos"];
        assert_eq!(
            alias.options().booleans(),
            BTreeMap::from([
                ("asan".to_string(), true),
                ("postauth".to_string(), false),
                ("sancov".to_string(), true)
            ])
        );
        assert_eq!(
            alias.options().fix(),
            vec!["CVE-1".to_string(), "CVE-2".to_string()]
        );
        // the patches of a version
        let dir = Path::new("/v");
        assert_eq!(
            presets.patches_for(dir, "3.4.1"),
            vec![dir.join("patches/a.patch")]
        );
        assert!(presets.patches_for(dir, "1.1.1j").is_empty());
        assert!(presets.patches_for(dir, "master").is_empty());
    }

    #[test]
    fn format_2_says_what_is_wrong() {
        let error = |content: String| parse("lib", &content, &defaults()).unwrap_err();
        assert!(
            error(V2.replace("postauth = { default = true, doc = \"post-auth\" }\n", ""))
                .contains("[modifiers] must declare")
        );
        assert!(
            error(V2.replace("sancov = { default = true", "sancov = { default = false"))
                .contains("sancov: default = true")
        );
        assert!(error(V2.replace("no-postauth", "tls13")).contains("alias lib341-sdos: 'tls13'"));
        assert!(error(V2.replace("\"3.4.1,no", "\"9.9.9,no")).contains("'9.9.9' is not a version"));
        assert!(error(V2.replace("format = 2", "format = 3")).contains("unknown format 3"));
        assert!(error(V2.replace("format = 2", ""))
            .contains("format 1 (one table per build) is no longer read"));
    }

    #[test]
    fn every_name_of_the_format_1_files_gives_the_same_build() {
        // the presets.toml files before format 2 (testdata/presets-v1): each of their builds, by
        // its name, is the same configuration today
        let testdata =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/library/build/testdata/presets-v1");
        let mut checked = 0;
        for entry in std::fs::read_dir(&testdata).unwrap() {
            let path = entry.unwrap().path();
            let vendor = path.file_stem().unwrap().to_str().unwrap().to_string();
            let before: BTreeMap<String, Config> =
                toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            for (name, config) in &before {
                let now = Config::resolve(&vendor, name)
                    .unwrap_or_else(|e| panic!("{vendor}:{name}: {e}"));
                assert_eq!(&now, config, "{vendor}:{name}");
                checked += 1;
            }
        }
        assert!(checked >= 66, "{checked} builds checked");
    }
}
