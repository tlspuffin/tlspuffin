//! The catalogue of known vulnerabilities of each vendor library:
//! `vendors/<vendor>/vulnerabilities.toml`.
//!
//! It is the only source of what a library build knows about bugs: which ones affect a version,
//! which patch removes each of them, how each one shows up when triggered (its oracle) and what
//! puffin needs to reach it. Builds take the active bugs and the fix patches from it, the PUT
//! metadata records the state of every entry, and the generic catalogue test checks every entry on
//! real executions of its witness trace.
//!
//! The format of an entry is documented in `puffin-build/README.md` (section "Vulnerability
//! catalogue").

mod cvss;
pub mod spec;
mod version;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

pub use cvss::{base_score_v31, Cvss};
use serde::{Deserialize, Serialize};
pub use spec::Spec;
pub use version::{Version, VersionRange};

/// Name of the catalogue file in a vendor directory.
pub const FILE_NAME: &str = "vulnerabilities.toml";

/// Separators of the vendor names derived from the catalogue (`<preset>-only-<ID>`,
/// `<preset>-fix-<ID>+<ID>`).
pub const DERIVED_ONLY: &str = "-only-";
pub const DERIVED_FIX: &str = "-fix-";
pub const DERIVED_FIX_ALL: &str = "-fix-all";
pub const ID_SEPARATOR: char = '+';

/// Environment variable naming the puffin-build directory to read the catalogue from instead of
/// the source tree's (see [`build_dir`]).
pub const BUILD_DIR_ENV: &str = "PUFFIN_BUILD_DIR";

/// Whether a file named in a vendor's files (a patch) is a path inside the vendor directory:
/// relative, without `..`.
pub fn is_inside(file: &str) -> bool {
    let path = Path::new(file);
    !file.is_empty()
        && path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// The puffin-build directory the catalogue is read from at run time (its vendors, the
/// capabilities of vendorinfo.sh.in): that of the source tree this crate was built from, or
/// `$PUFFIN_BUILD_DIR` when set, for a binary run outside its source tree (e.g. a copy kept in a
/// cache: the `puffin-build` of a checkout of the same commit).
pub fn build_dir() -> PathBuf {
    match std::env::var_os(BUILD_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(env!("CARGO_MANIFEST_DIR")),
    }
}

/// Directory holding one sub-directory per vendor (`presets.toml`, `builder.cmake`, the catalogue
/// and its patches), in [`build_dir`].
pub fn vendors_dir() -> PathBuf {
    build_dir().join("vendors")
}

/// Names of the vendors that have a directory in [`vendors_dir`].
pub fn vendors() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(vendors_dir())
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Resolve the name of a build of `vendor` (a preset, `5.4.0,asan,only-BUF`, ...: see [`spec`]).
pub fn resolve_name(vendor: &str, name: &str) -> Result<Spec, String> {
    let dir = vendors_dir().join(vendor);
    if !dir.join("presets.toml").exists() {
        return Err(format!(
            "unknown vendor '{vendor}' (vendors: {})",
            vendors().join(", ")
        ));
    }
    let context = VendorContext::load(vendor, &dir).map_err(|e| e.to_string())?;
    let catalogue = Catalogue::load_from(vendor, &dir, &context).map_err(|e| e.to_string())?;
    spec::resolve(&catalogue, &context, name)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Short name used in the papers and on the bench (e.g. "BUF")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub summary: String,
    /// Open list: memory, auth-bypass, dos, info-leak, downgrade, protocol, ...
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<Cvss>,
    /// Why a CVE has no CVSS v3.1 score (e.g. NVD only gives a v2 score)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_cvss: Option<String>,

    /// Library versions with the bug (the presets' `version`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected: Option<VersionRange>,
    /// tlspuffin commits with the bug, for bugs of tlspuffin's own harness code (`"not containing
    /// <commit>"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_commits: Option<String>,
    /// Build options the bug needs (options of the vendor's builder.cmake)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires: BTreeMap<String, bool>,

    /// PUT capabilities needed to trigger it (its witnesses run on PUTs that have them all)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// PUT options needed to trigger it (its witnesses run with them)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub put_options: BTreeMap<String, String>,

    /// A bug of the fuzzing harness, not of the library
    #[serde(default, skip_serializing_if = "is_false")]
    pub bug_in_harness: bool,
    /// Whether objectives found by fuzzing reproduce on replay
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub replayable: bool,

    /// How the bug shows when triggered (only an entry without witness may lack one: its
    /// objectives then cannot be recognized)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<Oracle>,
    /// Top stack frames, shown to people, never used to decide
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_frames: Vec<String>,

    /// The build `<vendor>:<ID>` and `<vendor>:only-<ID>` start from: a preset, or a version and
    /// modifiers (`5.4.0,asan`); default: the newest preset with the bug, ASan presets first
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// More builds the CI checks the entry on (presets, or versions and modifiers)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub check: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Other entries the witness of this one is known to trigger too
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_triggers: Vec<String>,
    /// Library versions on which the witnesses reach the bug, when they cannot on every affected
    /// version (e.g. a record size older releases refuse): elsewhere they are not expected to
    /// trigger it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_versions: Option<VersionRange>,
    /// Why there is no witness trace (the entry then cannot be checked on executions)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_witness: Option<String>,
    /// Why there is no patch (the entry then cannot be validated by patch differential)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_patch: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub find: Option<Find>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<Patch>,
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OracleKind {
    /// The execution crashes (signal, sanitizer report, panic)
    Crash,
    /// The security oracle reports a claim violation
    Claim,
}

impl fmt::Display for OracleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OracleKind::Crash => "crash",
            OracleKind::Claim => "claim",
        })
    }
}

/// The signature an objective of the bug must have. A field it does not give matches anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oracle {
    pub kind: OracleKind,
    /// Signal that ends the execution (e.g. "SIGSEGV", "SIGABRT")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    /// Type of the AddressSanitizer report (e.g. "stack-buffer-overflow", "heap-buffer-overflow",
    /// "SEGV")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asan: Option<String>,
    /// Message of the security violation (claims)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation: Option<String>,
    /// Message of a panic
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic: Option<String>,
}

pub const SIGNALS: &[&str] = &[
    "SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE", "SIGTRAP", "SIGSYS",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Find {
    /// First found by puffin (a new bug), not only re-found
    pub by_puffin: bool,
    /// First tlspuffin commit known to find it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// cargo features needed to find it
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// fuzzer flags needed to find it (e.g. "--put-use-clear")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Only detected with ASan
    #[serde(default, skip_serializing_if = "is_false")]
    pub asan: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<FindTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Time to find, measured by fuzzing campaigns (informational: the bench shows its own numbers
/// beside).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindTime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_s: Option<f64>,
    pub runs: u32,
    pub found: u32,
    pub budget_s: f64,
    pub cores: u32,
    pub commit: String,
    pub preset: String,
    /// Where the numbers come from (task ids, report)
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchTarget {
    /// The library sources
    #[default]
    Library,
    /// tlspuffin's own sources (bugs of the harness)
    Harness,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    #[serde(default)]
    pub target: PatchTarget,
    /// Library versions this patch is for (target = library)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<VersionRange>,
    /// tlspuffin commits this patch is for (target = harness)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<String>,
    /// Patch files, relative to the vendor directory, applied in order
    pub files: Vec<String>,
    /// Upstream fix the patch comes from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// The catalogue of one vendor.
#[derive(Debug, Clone)]
pub struct Catalogue {
    pub vendor: String,
    pub dir: PathBuf,
    pub entries: BTreeMap<String, Entry>,
    /// Hash of the catalogue file and of every patch it uses
    pub hash: String,
    entry_hashes: BTreeMap<String, String>,
    build_hashes: BTreeMap<String, String>,
    patch_hashes: BTreeMap<String, String>,
}

/// What the loader needs to know about the vendor besides its catalogue.
#[derive(Debug, Clone, Default)]
pub struct VendorContext {
    /// preset name -> (version, options relevant to the catalogue)
    pub presets: BTreeMap<String, PresetInfo>,
    /// builder options (`option(<name> "<doc>" ON|OFF)` of builder.cmake) and their defaults
    pub builder_options: BTreeMap<String, bool>,
    /// capabilities a PUT can declare (vendorinfo.sh.in)
    pub capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PresetInfo {
    pub version: String,
    pub asan: bool,
    pub fix: Vec<String>,
    pub options: BTreeMap<String, bool>,
}

impl Catalogue {
    /// Load and check the catalogue of `vendor` from [`vendors_dir`]. A vendor without catalogue
    /// file has an empty catalogue.
    pub fn load(vendor: &str) -> Result<Catalogue, CatalogueError> {
        let dir = vendors_dir().join(vendor);
        let context = VendorContext::load(vendor, &dir)?;
        Self::load_from(vendor, &dir, &context)
    }

    pub fn load_from(
        vendor: &str,
        dir: &Path,
        context: &VendorContext,
    ) -> Result<Catalogue, CatalogueError> {
        let file = dir.join(FILE_NAME);
        let content = match std::fs::read_to_string(&file) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(CatalogueError::new(
                    vendor,
                    format!("cannot read {}: {e}", file.display()),
                ))
            }
        };
        Self::parse(vendor, dir, &content, context)
    }

    pub fn parse(
        vendor: &str,
        dir: &Path,
        content: &str,
        context: &VendorContext,
    ) -> Result<Catalogue, CatalogueError> {
        let err = |msg: String| CatalogueError::new(vendor, msg);

        let entries: BTreeMap<String, Entry> =
            toml::from_str(content).map_err(|e| err(format!("invalid {FILE_NAME}: {e}")))?;

        let mut patch_hashes = BTreeMap::new();
        for entry in entries.values() {
            for patch in &entry.patches {
                for file in &patch.files {
                    if !is_inside(file) {
                        return Err(err(format!(
                            "patch file '{file}': a path inside the vendor directory (relative, without '..')"
                        )));
                    }
                    let path = dir.join(file);
                    let bytes = std::fs::read(&path)
                        .map_err(|e| err(format!("cannot read patch {}: {e}", path.display())))?;
                    patch_hashes.insert(file.clone(), sha256::digest(bytes.as_slice()));
                }
            }
        }

        let mut catalogue = Catalogue {
            vendor: vendor.into(),
            dir: dir.to_path_buf(),
            entries,
            hash: String::new(),
            entry_hashes: BTreeMap::new(),
            build_hashes: BTreeMap::new(),
            patch_hashes,
        };

        let mut problems = vec![];
        for (id, entry) in &catalogue.entries {
            problems.extend(
                catalogue
                    .check_entry(id, entry, context)
                    .into_iter()
                    .map(|p| format!("{id}: {p}")),
            );
        }
        problems.extend(catalogue.check_preset_fixes(context));
        // a bug's ID or alias reads in a name as the bug, not as a modifier or a catalogue part
        let modifiers = spec::modifiers(context);
        for (id, entry) in &catalogue.entries {
            for name in std::iter::once(id.as_str()).chain(entry.alias.as_deref()) {
                let lower = name.to_ascii_lowercase();
                let modifier = modifiers
                    .iter()
                    .any(|m| lower == *m || lower == format!("no-{m}"));
                if modifier
                    || lower == "fix-all"
                    || lower.starts_with("only-")
                    || lower.starts_with("fix-")
                {
                    problems.push(format!(
                        "{id}: '{name}' would read as a modifier or a catalogue part of a name (asan, \
                         no-<modifier>, only-…, fix-…)"
                    ));
                }
            }
        }
        // a bug is named by its ID or its alias, in any case
        let mut names: BTreeMap<String, &str> = BTreeMap::new();
        for (id, entry) in &catalogue.entries {
            for name in std::iter::once(id.as_str()).chain(entry.alias.as_deref()) {
                if let Some(other) = names.insert(name.to_ascii_lowercase(), id) {
                    if other != id {
                        problems.push(format!(
                            "{id}: '{name}' also names {other} (IDs and aliases are unique, in any case)"
                        ));
                    }
                }
            }
        }
        if !problems.is_empty() {
            return Err(CatalogueError {
                vendor: vendor.into(),
                problems,
            });
        }

        catalogue.entry_hashes = catalogue
            .entries
            .iter()
            .map(|(id, entry)| (id.clone(), catalogue.compute_entry_hash(id, entry)))
            .collect();
        catalogue.build_hashes = catalogue
            .entries
            .iter()
            .map(|(id, entry)| (id.clone(), catalogue.compute_build_hash(id, entry)))
            .collect();
        catalogue.hash = sha256::digest(
            std::iter::once(content.to_string())
                .chain(
                    catalogue
                        .patch_hashes
                        .iter()
                        .map(|(file, hash)| format!("{file} {hash}")),
                )
                .collect::<Vec<_>>()
                .join("\n"),
        );

        Ok(catalogue)
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Hash of an entry: its definition and the content of its patches.
    pub fn entry_hash(&self, id: &str) -> Option<&str> {
        self.entry_hashes.get(id).map(String::as_str)
    }

    /// Hash of what a library build takes from an entry: its affected versions and commits, the
    /// options it requires, its patches and their content. Builds record it (see
    /// [`LibraryState`]): an edit of the rest of the entry (oracle, witness versions,
    /// description) leaves the builds as they are.
    pub fn build_hash(&self, id: &str) -> Option<&str> {
        self.build_hashes.get(id).map(String::as_str)
    }

    /// Hash of a patch file (path relative to the vendor directory).
    pub fn patch_hash(&self, file: &str) -> Option<&str> {
        self.patch_hashes.get(file).map(String::as_str)
    }

    fn compute_entry_hash(&self, id: &str, entry: &Entry) -> String {
        let definition = toml::to_string(&BTreeMap::from([(id, entry)]))
            .expect("failed to serialize a catalogue entry");
        let patches = entry
            .patches
            .iter()
            .flat_map(|p| p.files.iter())
            .map(|f| format!("{f} {}", self.patch_hashes[f]))
            .collect::<Vec<_>>()
            .join("\n");
        sha256::digest(format!("{definition}\n{patches}"))
    }

    fn compute_build_hash(&self, id: &str, entry: &Entry) -> String {
        #[derive(Serialize)]
        struct BuildPart<'a> {
            affected: Option<&'a str>,
            affected_commits: Option<&'a str>,
            requires: &'a BTreeMap<String, bool>,
            patches: &'a [Patch],
        }
        let part = BuildPart {
            affected: entry.affected.as_ref().map(|r| r.as_str()),
            affected_commits: entry.affected_commits.as_deref(),
            requires: &entry.requires,
            patches: &entry.patches,
        };
        let definition = toml::to_string(&BTreeMap::from([(id, part)]))
            .expect("failed to serialize a catalogue entry");
        let patches = entry
            .patches
            .iter()
            .flat_map(|p| p.files.iter())
            .map(|f| format!("{f} {}", self.patch_hashes[f]))
            .collect::<Vec<_>>()
            .join("\n");
        sha256::digest(format!("{definition}\n{patches}"))
    }

    fn check_entry(&self, id: &str, entry: &Entry, context: &VendorContext) -> Vec<String> {
        let mut problems = vec![];
        let mut problem = |p: String| problems.push(p);

        if !is_valid_id(id) {
            problem(format!(
                "invalid id: use letters, digits, '-', '_' and '.' (not '{ID_SEPARATOR}'), and not \"all\""
            ));
        }
        if let Some(alias) = &entry.alias {
            if !is_valid_id(alias) || alias.contains(',') {
                problem(format!(
                    "invalid alias '{alias}': use letters, digits, '-', '_' and '.' (it names the \
                     bug in vendor names: only-{alias})"
                ));
            }
        }
        if entry.summary.trim().is_empty() {
            problem("empty summary".into());
        }
        if entry.category.is_empty()
            || !entry
                .category
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            problem(format!(
                "invalid category '{}' (lowercase words separated by '-')",
                entry.category
            ));
        }

        let is_cve = id.starts_with("CVE-");
        match (&entry.cvss, &entry.no_cvss) {
            (Some(cvss), None) if is_cve => {
                if let Err(e) = cvss.check() {
                    problem(e);
                }
            }
            (Some(_), _) if !is_cve => {
                problem("CVSS scores come from NVD: only CVE entries have one".into())
            }
            (None, None) if is_cve => problem(
                "missing cvss (NVD's v3.1 base score with its vector), or no_cvss = \"<reason>\""
                    .into(),
            ),
            (Some(_), Some(_)) => problem("both cvss and no_cvss".into()),
            (None, Some(reason)) if reason.trim().is_empty() => {
                problem("empty no_cvss reason".into())
            }
            _ => (),
        }

        // a bug of the harness keyed by tlspuffin commits ("not containing <commit>") is a bug of
        // past commits: the tree that holds the catalogue has its fix, so no build of it has the
        // bug (`affects` is false) and nothing can show it (no witness); the bench names the
        // objectives of older commits after it. A harness patch, for a bug of this tree's harness,
        // is not applied by builds nor by the test yet: refused below.
        if entry.affected.is_none() && entry.affected_commits.is_none() {
            problem(
                "missing affected (library versions) or affected_commits (tlspuffin commits)"
                    .into(),
            );
        }
        if let Some(commits) = &entry.affected_commits {
            if !entry.bug_in_harness {
                problem(
                    "affected_commits is for bugs of the harness (bug_in_harness = true)".into(),
                );
            }
            if entry.affected.is_some() {
                problem(
                    "both affected (library versions) and affected_commits (tlspuffin commits)"
                        .into(),
                );
            }
            let fix = commits.strip_prefix("not containing ").unwrap_or_default();
            if !(7..=40).contains(&fix.len()) || !fix.bytes().all(|b| b.is_ascii_hexdigit()) {
                problem(format!(
                    "affected_commits '{commits}': \"not containing <commit>\" (the commit of the fix, 7 to \
                     40 hexadecimal digits)"
                ));
            }
            if entry.no_witness.is_none() {
                problem(
                    "a bug of past tlspuffin commits (affected_commits) is fixed in this tree, where no \
                     witness can show it: no_witness = \"<reason>\""
                        .into(),
                );
            }
        }

        for option in entry.requires.keys() {
            if !context.builder_options.contains_key(option) {
                problem(format!(
                    "requires '{option}', which is not an option of builder.cmake (options: {})",
                    context
                        .builder_options
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }

        for capability in &entry.capabilities {
            if !context.capabilities.contains(capability) {
                problem(format!(
                    "unknown capability '{capability}' (known: {})",
                    context
                        .capabilities
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }

        match &entry.oracle {
            Some(oracle) => {
                if let Err(e) = oracle.check() {
                    problem(format!("oracle: {e}"));
                }
            }
            None if entry.no_witness.is_none() => problem("missing oracle".into()),
            None => (),
        }

        for other in &entry.also_triggers {
            if other == id || !self.entries.contains_key(other) {
                problem(format!(
                    "also_triggers '{other}': not another entry of this catalogue"
                ));
            }
        }

        if let Some(reason) = &entry.no_witness {
            if reason.trim().is_empty() {
                problem("empty no_witness reason".into());
            }
            if entry.witness_versions.is_some() {
                problem("witness_versions without witness (no_witness)".into());
            }
        }

        match (&entry.no_patch, entry.patches.is_empty()) {
            (Some(_), false) => problem("both patches and no_patch".into()),
            (None, true) => problem("no patch: add one, or no_patch = \"<reason>\"".into()),
            (Some(reason), true) if reason.trim().is_empty() => {
                problem("empty no_patch reason".into())
            }
            _ => (),
        }

        if let Some(find) = &entry.find {
            if let Some(time) = &find.time {
                if time.source.trim().is_empty() {
                    problem("find.time without source".into());
                }
                if time.found > time.runs {
                    problem("find.time: found > runs".into());
                }
                if time.found > 0 && (time.mean_s.is_none() || time.median_s.is_none()) {
                    problem("find.time: mean_s and median_s are needed when found > 0".into());
                }
            }
        }

        for (n, patch) in entry.patches.iter().enumerate() {
            let n = n + 1;
            if patch.files.is_empty() {
                problem(format!("patch {n}: no files"));
            }
            match patch.target {
                PatchTarget::Library => {
                    if patch.commits.is_some() {
                        problem(format!("patch {n}: commits is for harness patches"));
                    }
                    match (&patch.versions, &entry.affected) {
                        (None, _) => problem(format!("patch {n}: library patch without versions")),
                        (Some(_), None) => problem(format!(
                            "patch {n}: library patch for an entry without affected versions"
                        )),
                        _ => (),
                    }
                }
                PatchTarget::Harness => {
                    problem(format!(
                        "patch {n}: harness patches (target = \"harness\") are not supported yet"
                    ));
                    if !entry.bug_in_harness {
                        problem(format!(
                            "patch {n}: harness patches fix bugs of the harness (bug_in_harness = true)"
                        ));
                    }
                    if patch.versions.is_some() {
                        problem(format!("patch {n}: versions is for library patches"));
                    }
                    if patch.commits.is_none() || entry.affected_commits.is_none() {
                        problem(format!(
                            "patch {n}: harness patch without commits, or entry without affected_commits"
                        ));
                    }
                }
            }
        }

        // a library patch is checked (check-patches, the catalogue test) on the versions of its
        // range that presets.toml has: a range without any can never be
        for (n, patch) in entry.patches.iter().enumerate() {
            let Some(range) = &patch.versions else {
                continue;
            };
            let tested = context.presets.values().any(|info| {
                info.version
                    .parse::<Version>()
                    .is_ok_and(|v| range.contains(&v))
            });
            if !tested && !context.presets.is_empty() {
                problem(format!(
                    "patch {}: no version of presets.toml is in its range ({}): it could never be checked \
                     (add one of its versions to [versions])",
                    n + 1,
                    range.as_str()
                ));
            }
        }

        // ranges, checked on the versions of the vendor's presets
        for (preset, info) in &context.presets {
            let Ok(version) = info.version.parse::<Version>() else {
                continue;
            };
            let affected = entry
                .affected
                .as_ref()
                .is_some_and(|r| r.contains(&version));
            let patches: Vec<usize> = entry
                .patches
                .iter()
                .enumerate()
                .filter(|(_, p)| p.versions.as_ref().is_some_and(|r| r.contains(&version)))
                .map(|(n, _)| n + 1)
                .collect();
            if !patches.is_empty() && !affected {
                problem(format!(
                    "patch {} is for version {} (preset {preset}), which is not affected",
                    patches[0], info.version
                ));
            }
            if patches.len() > 1 {
                problem(format!(
                    "patches {} and {} are both for version {} (preset {preset})",
                    patches[0], patches[1], info.version
                ));
            }
        }

        if let Err(e) = self.reference_preset(id, entry, context) {
            problem(e);
        }

        for build in &entry.check {
            match spec::named_build(self, context, build) {
                Err(e) => problem(format!("check: {e}")),
                Ok((_, info)) if !entry.is_active_in(&info, context) => {
                    problem(format!("check: the bug is not in '{build}'"))
                }
                _ => (),
            }
        }

        problems
    }

    fn check_preset_fixes(&self, context: &VendorContext) -> Vec<String> {
        let mut problems = vec![];
        for (preset, info) in &context.presets {
            if preset.contains(DERIVED_ONLY)
                || preset.contains(DERIVED_FIX)
                || preset.contains(',')
                || spec::names_a_bug(self, preset)
            {
                problems.push(format!(
                    "preset '{preset}': preset names cannot contain '{DERIVED_ONLY}', '{DERIVED_FIX}' or ',' \
                     nor be the ID or the alias of a bug (they would read as other names)"
                ));
            }
            for id in &info.fix {
                match self.entries.get(id) {
                    None => problems.push(format!(
                        "preset '{preset}': fix '{id}' is not an entry of the catalogue"
                    )),
                    Some(entry) => {
                        if !entry.is_active_in(info, context) {
                            problems.push(format!(
                                "preset '{preset}': fix '{id}', which does not affect version {} with its options",
                                info.version
                            ));
                        } else if entry.patch_for(&info.version).is_none() {
                            problems.push(format!(
                                "preset '{preset}': fix '{id}', which has no patch for version {}",
                                info.version
                            ));
                        }
                    }
                }
            }
        }
        problems
    }

    /// The build `<vendor>:<ID>` starts from, as the entry names it (a preset, or a version and
    /// modifiers), else the newest preset with the bug; empty for a bug of the harness.
    pub fn reference_preset(
        &self,
        id: &str,
        entry: &Entry,
        context: &VendorContext,
    ) -> Result<String, String> {
        if entry.affected.is_none() {
            // a bug of tlspuffin's own code, keyed by commits: built from any preset
            return Ok(String::new());
        }

        if let Some(reference) = &entry.reference {
            let (_, info) = spec::named_build(self, context, reference)
                .map_err(|e| format!("reference: {e}"))?;
            if !entry.is_active_in(&info, context) {
                return Err(format!("reference: the bug is not in '{reference}'"));
            }
            if info.fix.contains(&id.to_string()) {
                return Err(format!("reference: '{reference}' fixes it"));
            }
            return Ok(reference.clone());
        }

        // the newest version with the bug, the plainest preset of it (see `prefer`)
        context
            .presets
            .iter()
            .filter(|(_, info)| {
                entry.is_active_in(info, context) && !info.fix.contains(&id.to_string())
            })
            .filter_map(|(name, info)| {
                info.version
                    .parse::<Version>()
                    .ok()
                    .map(|v| (v, info, name))
            })
            .max_by(|(va, ia, na), (vb, ib, nb)| prefer(va, ia, na, vb, ib, nb))
            .map(|(_, _, name)| name.clone())
            .ok_or_else(|| {
                "no preset has the bug: give reference = \"<version>,<modifier>…\"".into()
            })
    }
}

/// What a library build takes from the catalogue: the bugs it has, the ones it fixes and the
/// patches doing it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BuildPlan {
    /// Entries affecting the version with these options, before fixes
    pub known: Vec<String>,
    /// Entries fixed by the build (the `fix` list)
    pub fixed: Vec<String>,
    /// Patch files applied, in order (absolute paths)
    pub patches: Vec<PathBuf>,
}

impl Catalogue {
    /// The plan of a build of `version` with build `options` (unset ones take builder.cmake's
    /// defaults), fixing the entries of `fix`. Every fixed entry must affect the build and have
    /// a patch for its version.
    pub fn plan(
        &self,
        version: &str,
        options: &BTreeMap<String, bool>,
        fix: &[String],
    ) -> Result<BuildPlan, String> {
        let defaults = parse_builder_options(
            &std::fs::read_to_string(self.dir.join("builder.cmake")).unwrap_or_default(),
        );

        let known: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.affects(version, options, &defaults))
            .map(|(id, _)| id.clone())
            .collect();

        let mut plan = BuildPlan {
            known,
            ..BuildPlan::default()
        };

        for id in fix {
            let entry = self.entries.get(id).ok_or_else(|| {
                format!(
                    "cannot fix '{id}': not an entry of the {} catalogue",
                    self.vendor
                )
            })?;
            if !plan.known.contains(id) {
                return Err(format!(
                    "cannot fix '{id}': it does not affect {} {version} with these options (affected: {}{})",
                    self.vendor,
                    entry.affected.as_ref().map(|r| r.as_str()).unwrap_or("-"),
                    if entry.requires.is_empty() {
                        String::new()
                    } else {
                        format!(", requires: {:?}", entry.requires)
                    }
                ));
            }
            let patch = entry.patch_for(version).ok_or_else(|| {
                format!("cannot fix '{id}': no patch for {} {version}", self.vendor)
            })?;
            if plan.fixed.contains(id) {
                continue;
            }
            plan.fixed.push(id.clone());
            plan.patches
                .extend(patch.files.iter().map(|file| self.dir.join(file)));
        }

        Ok(plan)
    }
}

/// File of a library directory recording the state of every catalogue entry in that build.
pub const STATE_FILE: &str = ".catalogue";

/// What a library build records about every entry of its vendor's catalogue: whether the build has
/// the bug, the hashes of the catalogue and of what the build took from each entry (affected
/// versions, options, patches).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryState {
    pub vendor: String,
    pub version: String,
    /// Hash of the catalogue the library was built with
    pub catalogue: String,
    /// For a derived vendor name (`<preset>-only-<ID>`, ...): how it was derived
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived: Option<Derived>,
    pub entries: BTreeMap<String, EntryState>,
    /// The patches of presets.toml applied to this version (the claims instrumentation, build
    /// fixes): file -> sha256 of its content, so that a library built before one of them
    /// changed is stale
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub library_patches: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryState {
    pub state: Status,
    /// Build hash of the entry (see [`Catalogue::build_hash`])
    pub hash: String,
    /// Hashes of the patch files fixing the entry at this version: applied when fixed, empty when
    /// there is no patch for this version
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The build has the bug
    Active,
    /// The build has the bug's patch
    Fixed,
    /// The bug does not affect this version with these options
    Unaffected,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Active => "active",
            Status::Fixed => "fixed",
            Status::Unaffected => "unaffected",
        })
    }
}

/// How a derived vendor name was resolved (see [`Catalogue::derive`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    /// The preset it derives from
    pub base: String,
    /// "only" (every other active bug fixed), "fix" (these fixed), "fix-all"
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
}

impl Catalogue {
    /// The state of every entry in a build of `version` following `plan`.
    pub fn library_state(&self, version: &str, plan: &BuildPlan) -> LibraryState {
        let entries = self
            .entries
            .iter()
            .map(|(id, entry)| {
                let state = if plan.fixed.contains(id) {
                    Status::Fixed
                } else if plan.known.contains(id) {
                    Status::Active
                } else {
                    Status::Unaffected
                };
                let patches = match state {
                    Status::Unaffected => vec![],
                    _ => entry
                        .patch_for(version)
                        .map(|p| {
                            p.files
                                .iter()
                                .map(|f| self.patch_hashes[f].clone())
                                .collect()
                        })
                        .unwrap_or_default(),
                };
                (
                    id.clone(),
                    EntryState {
                        state,
                        hash: self.build_hashes[id].clone(),
                        patches,
                    },
                )
            })
            .collect();

        LibraryState {
            vendor: self.vendor.clone(),
            version: version.into(),
            catalogue: self.hash.clone(),
            derived: None,
            entries,
            library_patches: BTreeMap::new(),
        }
    }
}

/// A derived vendor name resolved to its base preset and explicit fix list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    pub derived: Derived,
    /// The fix list of the derived build (the base preset's fixes included)
    pub fix: Vec<String>,
    /// Derived builds of a single bug (`<vendor>:<ID>`) are always built with ASan
    pub force_asan: bool,
}

impl Catalogue {
    /// Resolve a derived vendor name:
    /// - `<ID>`: the entry's reference preset, every other active bug patched (only `<ID>` left),
    ///   ASan;
    /// - `<preset>-only-<ID>[+<ID>...]`: the preset with every other active bug patched;
    /// - `<preset>-fix-<ID>[+<ID>...]`: the preset with these bugs patched too;
    /// - `<preset>-fix-all`: the preset with every active bug that has a patch patched.
    ///
    /// Returns `Ok(None)` when `name` is not a derived name (a preset, or unknown).
    pub fn derive(
        &self,
        name: &str,
        context: &VendorContext,
    ) -> Result<Option<Derivation>, String> {
        if self.entries.contains_key(name) {
            let spec = spec::resolve(self, context, name)?;
            return Ok(spec.derived.map(|derived| Derivation {
                derived,
                fix: spec.info.fix,
                force_asan: true,
            }));
        }

        let (base, kind, ids) = if let Some(base) = name.strip_suffix(DERIVED_FIX_ALL) {
            (base, "fix-all", vec![])
        } else if let Some((base, ids)) = name.split_once(DERIVED_ONLY) {
            (
                base,
                "only",
                ids.split(ID_SEPARATOR).map(String::from).collect(),
            )
        } else if let Some((base, ids)) = name.split_once(DERIVED_FIX) {
            (
                base,
                "fix",
                ids.split(ID_SEPARATOR).map(String::from).collect(),
            )
        } else {
            return Ok(None);
        };

        if !context.presets.contains_key(base) {
            return Ok(None);
        }

        self.derive_from(base, kind, &ids, context).map(Some)
    }

    fn derive_from(
        &self,
        base: &str,
        kind: &str,
        ids: &[String],
        context: &VendorContext,
    ) -> Result<Derivation, String> {
        self.derive_on(base, &context.presets[base], kind, ids, context)
    }

    /// Derive a build of `kind` ("only", "fix", "fix-all") from the build `preset` (a preset, or a
    /// version and options, named `base`; its fixes stay).
    pub fn derive_on(
        &self,
        base: &str,
        preset: &PresetInfo,
        kind: &str,
        ids: &[String],
        context: &VendorContext,
    ) -> Result<Derivation, String> {
        let active: Vec<&String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_active_in(preset, context))
            .map(|(id, _)| id)
            .collect();
        let patchable = |id: &str| self.entries[id].patch_for(&preset.version).is_some();

        if kind != "fix-all" && ids.is_empty() {
            return Err(format!("'{base}-{kind}-': no ids after '{kind}-'"));
        }
        for id in &preset.fix {
            if !active.contains(&id) || !patchable(id) {
                return Err(format!(
                    "'{base}' fixes '{id}', which is not in this build or has no patch for it"
                ));
            }
        }
        for id in ids {
            if !self.entries.contains_key(id) {
                return Err(format!(
                    "'{id}' is not an entry of the {} catalogue",
                    self.vendor
                ));
            }
            if !active.contains(&id) {
                let entry = &self.entries[id];
                let needs: Vec<String> = entry
                    .requires
                    .iter()
                    .filter(|(option, wanted)| spec::value(preset, context, option) != **wanted)
                    .map(|(option, wanted)| {
                        if *wanted {
                            option.clone()
                        } else {
                            format!("no-{option}")
                        }
                    })
                    .collect();
                return Err(if needs.is_empty() {
                    format!(
                        "'{id}' does not affect {base} (version {}; affected: {})",
                        preset.version,
                        entry.affected.as_ref().map(|r| r.as_str()).unwrap_or("-")
                    )
                } else {
                    format!(
                        "'{id}' does not affect {base}: it needs {}",
                        needs.join(", ")
                    )
                });
            }
            if preset.fix.contains(id) {
                return Err(format!("'{base}' already fixes '{id}'"));
            }
            if kind == "fix" && !patchable(id) {
                return Err(format!(
                    "'{id}' has no patch for version {}",
                    preset.version
                ));
            }
        }

        let extra: Vec<String> = active
            .iter()
            .filter(|id| !preset.fix.contains(id))
            .filter(|id| match kind {
                "only" => !ids.contains(id) && patchable(id),
                "fix-all" => patchable(id),
                _ => ids.contains(id),
            })
            .map(|id| id.to_string())
            .collect();

        Ok(Derivation {
            derived: Derived {
                base: base.into(),
                kind: kind.into(),
                ids: ids.to_vec(),
            },
            fix: preset.fix.iter().cloned().chain(extra).collect(),
            force_asan: false,
        })
    }

    /// The validation set of a build (a preset, or a name that is not derived from the catalogue):
    /// its `-fix-all` build and one `-only-<ID>` build per active bug that has a patch for its
    /// version, named after its slug.
    pub fn validation_set(&self, name: &str, context: &VendorContext) -> Vec<String> {
        if let Some(info) = context.presets.get(name) {
            return self.validation_set_of(name, info, context);
        }
        match spec::resolve(self, context, name) {
            Ok(spec) if spec.derived.is_none() => {
                self.validation_set_of(&spec.slug, &spec.info, context)
            }
            _ => vec![],
        }
    }

    /// The validation set of the build `info`, named `preset`.
    pub fn validation_set_of(
        &self,
        preset: &str,
        info: &PresetInfo,
        context: &VendorContext,
    ) -> Vec<String> {
        std::iter::once(format!("{preset}{DERIVED_FIX_ALL}"))
            .chain(
                self.entries
                    .iter()
                    .filter(|(id, entry)| {
                        entry.is_active_in(info, context)
                            && !info.fix.contains(id)
                            && entry.patch_for(&info.version).is_some()
                    })
                    .map(|(id, _)| format!("{preset}{DERIVED_ONLY}{id}")),
            )
            .collect()
    }

    /// The builds the CI checks the catalogue on, by their slugs: for every entry with a witness,
    /// the newest preset of each of its patch ranges (ASan presets first), its reference build when
    /// it has no patch, and its `check` builds.
    pub fn check_presets(&self, context: &VendorContext) -> BTreeMap<String, Vec<String>> {
        let mut presets: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, entry) in &self.entries {
            if entry.no_witness.is_some() || entry.affected.is_none() {
                continue;
            }
            let slug = |name: &str| spec::named_build(self, context, name).ok().map(|(s, _)| s);
            let mut chosen: Vec<String> = entry.check.iter().filter_map(|c| slug(c)).collect();
            if entry.patches.is_empty() {
                if let Ok(reference) = self.reference_preset(id, entry, context) {
                    chosen.extend(slug(&reference));
                }
            }
            for patch in &entry.patches {
                let Some(range) = &patch.versions else {
                    continue;
                };
                let newest = context
                    .presets
                    .iter()
                    .filter(|(_, info)| {
                        entry.is_active_in(info, context)
                            && !info.fix.contains(id)
                            && info
                                .version
                                .parse::<Version>()
                                .is_ok_and(|v| range.contains(&v))
                    })
                    .filter_map(|(name, info)| {
                        info.version
                            .parse::<Version>()
                            .ok()
                            .map(|v| (v, info, name))
                    })
                    .max_by(|(va, ia, na), (vb, ib, nb)| prefer(va, ia, na, vb, ib, nb))
                    .map(|(_, _, name)| name.clone());
                chosen.extend(newest);
            }
            for preset in chosen {
                // the CI builds them with ASan: a build without, by the name of its ASan build
                // (`<name>-asan`: that build, with ASan), so that the library's name says it
                let preset = match context.presets.get(&preset) {
                    Some(info) if !info.asan => {
                        let with_asan = format!("{preset}-asan");
                        match spec::resolve(self, context, &with_asan) {
                            Ok(spec) if spec.derived.is_none() && spec.info.asan => with_asan,
                            _ => preset,
                        }
                    }
                    _ => preset,
                };
                let ids = presets.entry(preset).or_default();
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        }
        presets
    }
}

impl LibraryState {
    pub fn status(&self, id: &str) -> Option<Status> {
        self.entries.get(id).map(|e| e.state)
    }

    pub fn ids_with(&self, status: Status) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(move |(_, e)| e.state == status)
            .map(|(id, _)| id.as_str())
    }

    /// Whether the entry has a patch for this build's version.
    pub fn patchable(&self, id: &str) -> bool {
        self.entries.get(id).is_some_and(|e| !e.patches.is_empty())
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("failed to serialize a library state")
    }

    pub fn from_toml(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("invalid library catalogue state: {e}"))
    }
}

impl Entry {
    /// Whether the entry's witnesses are expected to reach the bug on `version` (see
    /// `witness_versions`).
    pub fn witness_reaches(&self, version: &str) -> bool {
        match (&self.witness_versions, version.parse::<Version>()) {
            (None, _) => true,
            (Some(range), Ok(v)) => range.contains(&v),
            (Some(_), Err(_)) => false,
        }
    }

    /// Whether the bug is in a build of the preset (version affected and `requires` met), before
    /// any fix.
    pub fn is_active_in(&self, preset: &PresetInfo, context: &VendorContext) -> bool {
        self.affects(&preset.version, &preset.options, &context.builder_options)
    }

    /// Whether the bug is in a build of `version` with `options` (unset options take the builder's
    /// default).
    pub fn affects(
        &self,
        version: &str,
        options: &BTreeMap<String, bool>,
        defaults: &BTreeMap<String, bool>,
    ) -> bool {
        let Some(range) = &self.affected else {
            return false;
        };
        let Ok(version) = version.parse::<Version>() else {
            return false;
        };
        range.contains(&version)
            && self.requires.iter().all(|(option, wanted)| {
                options
                    .get(option)
                    .or_else(|| defaults.get(option))
                    .is_some_and(|value| value == wanted)
            })
    }

    /// The library patch for `version`.
    pub fn patch_for(&self, version: &str) -> Option<&Patch> {
        let version = version.parse::<Version>().ok()?;
        self.patches.iter().find(|p| {
            p.target == PatchTarget::Library
                && p.versions.as_ref().is_some_and(|r| r.contains(&version))
        })
    }
}

impl Oracle {
    pub fn check(&self) -> Result<(), String> {
        let nonempty = |field: &Option<String>, name: &str| match field {
            Some(value) if value.trim().is_empty() => Err(format!("empty {name}")),
            _ => Ok(()),
        };
        nonempty(&self.signal, "signal")?;
        nonempty(&self.asan, "asan")?;
        nonempty(&self.violation, "violation")?;
        nonempty(&self.panic, "panic")?;

        match self.kind {
            OracleKind::Claim => {
                if self.violation.is_none() {
                    return Err("a claim oracle needs its violation message".into());
                }
                if self.signal.is_some() || self.asan.is_some() || self.panic.is_some() {
                    return Err("a claim oracle has no signal, asan or panic".into());
                }
            }
            OracleKind::Crash => {
                if self.violation.is_some() {
                    return Err("a crash oracle has no violation message".into());
                }
                if self.signal.is_none() && self.asan.is_none() && self.panic.is_none() {
                    return Err(
                        "a crash oracle needs a signal, an asan report type or a panic message"
                            .into(),
                    );
                }
                if let Some(signal) = &self.signal {
                    if !SIGNALS.contains(&signal.as_str()) {
                        return Err(format!(
                            "unknown signal '{signal}' (known: {})",
                            SIGNALS.join(", ")
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for Oracle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        for (name, value) in [
            ("signal", &self.signal),
            ("asan", &self.asan),
            ("violation", &self.violation),
            ("panic", &self.panic),
        ] {
            if let Some(value) = value {
                write!(f, " {name}=\"{value}\"")?;
            }
        }
        Ok(())
    }
}

/// Order of preference between presets with the bug: the newest version, then the fewest fixes
/// (a version's own build rather than an alias), then an ASan preset (derived builds force ASan
/// anyway), then the shortest name.
fn prefer(
    va: &Version,
    ia: &PresetInfo,
    na: &String,
    vb: &Version,
    ib: &PresetInfo,
    nb: &String,
) -> std::cmp::Ordering {
    va.cmp(vb)
        .then_with(|| ib.fix.len().cmp(&ia.fix.len()))
        .then_with(|| ia.asan.cmp(&ib.asan))
        .then_with(|| nb.len().cmp(&na.len()))
        .then_with(|| nb.cmp(na))
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id != "all"
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

impl VendorContext {
    /// Read what the loader needs from the vendor directory: presets.toml, builder.cmake, and the
    /// capabilities of vendorinfo.sh.in.
    pub fn load(vendor: &str, dir: &Path) -> Result<VendorContext, CatalogueError> {
        let err = |msg: String| CatalogueError::new(vendor, msg);

        let presets = if dir.join("presets.toml").exists() {
            crate::library::presets::load_from(vendor, dir)
                .map_err(err)?
                .configs
                .iter()
                .map(|(name, config)| (name.clone(), PresetInfo::of(config)))
                .collect()
        } else {
            BTreeMap::new()
        };

        let builder_options = std::fs::read_to_string(dir.join("builder.cmake"))
            .map(|content| parse_builder_options(&content))
            .unwrap_or_default();

        let vendorinfo = build_dir().join("cmake/builder/cmake/vendorinfo.sh.in");
        let capabilities = std::fs::read_to_string(&vendorinfo)
            .map(|content| parse_capabilities(&content))
            .map_err(|e| err(format!("cannot read {}: {e}", vendorinfo.display())))?;

        Ok(VendorContext {
            presets,
            builder_options,
            capabilities,
        })
    }
}

impl PresetInfo {
    /// What the catalogue needs of a build's configuration.
    pub fn of(config: &crate::library::Config) -> PresetInfo {
        let options = config.options().booleans();
        PresetInfo {
            version: config.sources().version(),
            asan: options.get("asan").copied().unwrap_or(false),
            fix: config.options().fix(),
            options,
        }
    }
}

/// `option(<name> "<doc>" ON|OFF)` lines of a builder.cmake.
pub fn parse_builder_options(content: &str) -> BTreeMap<String, bool> {
    let re = regex::Regex::new(
        r#"(?m)^\s*option\(\s*([A-Za-z_][A-Za-z0-9_]*)\s+"[^"]*"\s+(ON|OFF)\s*\)"#,
    )
    .expect("invalid regex");
    re.captures_iter(content)
        .map(|c| (c[1].to_string(), &c[2] == "ON"))
        .collect()
}

/// Capability names of vendorinfo.sh.in (`$<$<BOOL:@tls13@>:tls13>`).
pub fn parse_capabilities(content: &str) -> BTreeSet<String> {
    let Some(start) = content.find("declare -a CAPABILITIES=(") else {
        return BTreeSet::new();
    };
    let block = &content[start..];
    let block = &block[..block.find("\n)").unwrap_or(block.len())];
    let re = regex::Regex::new(r"\$<\$<BOOL:@([A-Za-z0-9_]+)@>:([A-Za-z0-9_]+)>")
        .expect("invalid regex");
    re.captures_iter(block).map(|c| c[2].to_string()).collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatalogueError {
    pub vendor: String,
    pub problems: Vec<String>,
}

impl CatalogueError {
    fn new(vendor: &str, problem: String) -> Self {
        Self {
            vendor: vendor.into(),
            problems: vec![problem],
        }
    }
}

impl fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "invalid vulnerability catalogue of '{}':", self.vendor)?;
        for problem in &self.problems {
            writeln!(f, "  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CatalogueError {}

#[cfg(test)]
mod tests;
