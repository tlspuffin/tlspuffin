//! Names of vendor builds: what a name says to build, its canonical name and its slug.
//!
//! The name of a build of a vendor (what follows `<vendor>:`) is
//! - `<version>[,<modifier>…]`, the canonical form: `5.4.0,asan,only-CVE-2022-39173`;
//!   - `<version>`: a version of the vendor's presets as the project writes it (`5.4.0`, `1.1.1j`,
//!     `master`), or without its dots when that is unambiguous (`540`, `111j`); a preset's name in
//!     its place starts from that preset (`wolfssl540-sdos2,asan`);
//!   - `<modifier>`s, in any order: `asan`, `sancov`, `gcov`, `llvm_cov` and the builder's options
//!     (the `option()`s of its builder.cmake: wolfSSL's `postauth`), each also `no-<modifier>`;
//!     `gcov` implies `no-sancov` (a build measuring coverage is not fuzzed);
//!   - at most one catalogue part: `only-<bugs>` (every other known bug of the build patched),
//!     `fix-<bugs>` (these patched), `fix-all` (every known bug with a patch patched), `<bugs>`
//!     being IDs or aliases of the catalogue (any case) joined by `+`. `only-<bugs>` brings what
//!     its bugs need: the build options they require and ASan when their oracle is an ASan report,
//!     unless the name says otherwise (a required option said otherwise is an error: the build
//!     would not have the bug). Without a version, `only-<bug>` starts from the bug's reference
//!     build;
//! - the same with `-` between the parts (`540-asan-only-BUF`, `5.4.0-no-postauth`);
//! - a preset of presets.toml (`wolfssl540-asan`): that configuration exactly; followed by
//!   `-<modifier>`s and a catalogue part (`wolfssl540-asan-only-CVE-2022-39173`): that
//!   configuration so modified, nothing implied (the form of slugs);
//! - an ID or an alias of the catalogue alone (`CVE-2022-39173`, `BUF`): the bug's reference build,
//!   only that bug left, with ASan.
//!
//! A name resolves to a [`Spec`]: the build (version, options, fixes), how the catalogue derives
//! it, its canonical name and its slug. The canonical name is the first form with the fewest
//! modifiers (those the version and the catalogue part do not give by themselves), in a fixed order
//! (instrumentation, builder options, catalogue part); it resolves to the same build, and that of
//! a preset resolves to the preset. The slug names the build's directory and its PUT: the name of a
//! preset with that build, else that of the build it starts from (a preset, or the plainest preset
//! of its version followed by `-<modifier>`s), followed by the catalogue part. It is today's form
//! of names, so that builds keep their names.

use std::collections::BTreeMap;

use super::{Catalogue, Derived, PresetInfo, VendorContext, Version, ID_SEPARATOR};

/// The instrumentation every vendor has: the `option()`s of puffin-build's
/// cmake/builder/run.cmake.
pub const INSTRUMENTATION: [&str; 4] = ["asan", "sancov", "gcov", "llvm_cov"];

/// A build of a vendor, as a name says it.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    /// The preset whose sources and builder the build uses
    pub preset: String,
    /// The build: version, options (instrumentation and the builder's), fixes
    pub info: PresetInfo,
    /// The options of the build that differ from the preset's
    pub changes: BTreeMap<String, bool>,
    /// How the catalogue derives it, if it does (`base`: the slug of the build it derives from)
    pub derived: Option<Derived>,
    /// The canonical name, without the vendor: `5.4.0,asan,only-CVE-2022-39173`
    pub canonical: String,
    /// The name of its directory and of its PUT: `wolfssl540-asan-only-CVE-2022-39173`
    pub slug: String,
}

/// A catalogue part: `only-<IDs>`, `fix-<IDs>`, `fix-all`.
#[derive(Debug, Clone, PartialEq)]
struct Select {
    kind: &'static str,
    ids: Vec<String>,
}

#[derive(Debug, Clone)]
enum Start {
    Preset(String),
    Version(String),
}

/// What a name asks, before it is resolved.
#[derive(Debug, Clone, Default)]
struct Request {
    start: Option<Start>,
    /// the modifiers the name says
    flags: BTreeMap<String, bool>,
    select: Option<Select>,
    /// a preset followed by modifiers (a slug): nothing implied
    exact: bool,
}

/// A resolved build, before its canonical name.
struct Built {
    preset: String,
    info: PresetInfo,
    derived: Option<Derived>,
    slug: String,
}

/// Resolve a name of a build of `catalogue`'s vendor (see the module documentation).
pub fn resolve(catalogue: &Catalogue, context: &VendorContext, name: &str) -> Result<Spec, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("empty name".into());
    }
    let built = if context.presets.contains_key(name) {
        Built {
            preset: name.into(),
            info: context.presets[name].clone(),
            derived: None,
            slug: name.into(),
        }
    } else {
        build(catalogue, context, request_of(catalogue, context, name)?)?
    };
    let preset_info = &context.presets[&built.preset];
    let changes = modifiers(context)
        .into_iter()
        .filter_map(|m| {
            let on = value(&built.info, context, &m);
            (on != value(preset_info, context, &m)).then_some((m, on))
        })
        .collect();
    Ok(Spec {
        canonical: canonical(catalogue, context, &built),
        changes,
        preset: built.preset,
        info: built.info,
        derived: built.derived,
        slug: built.slug,
    })
}

/// The modifiers of a vendor: the instrumentation, then its builder's options.
pub fn modifiers(context: &VendorContext) -> Vec<String> {
    INSTRUMENTATION
        .iter()
        .map(std::string::ToString::to_string)
        .chain(context.builder_options.keys().cloned())
        .collect()
}

/// The value of an option in a build: its own, else the builder's default, else off.
pub fn value(info: &PresetInfo, context: &VendorContext, option: &str) -> bool {
    info.options
        .get(option)
        .or_else(|| context.builder_options.get(option))
        .copied()
        .unwrap_or(false)
}

/// Whether two builds are the same: version, options and fixes.
fn same_build(a: &PresetInfo, b: &PresetInfo, context: &VendorContext) -> bool {
    let sorted = |fix: &[String]| {
        let mut fix = fix.to_vec();
        fix.sort();
        fix.dedup();
        fix
    };
    a.version == b.version
        && sorted(&a.fix) == sorted(&b.fix)
        && modifiers(context)
            .iter()
            .all(|m| value(a, context, m) == value(b, context, m))
}

/// The plain value of a modifier: sancov on, the other instrumentation off, the builder's options
/// as builder.cmake says.
pub fn plain_value(context: &VendorContext, modifier: &str) -> bool {
    match modifier {
        "sancov" => true,
        _ => context
            .builder_options
            .get(modifier)
            .copied()
            .unwrap_or(false),
    }
}

/// Records a modifier a name says: `m` and `no-m` both is an error, saying one twice is not. The
/// rule of every name: the vendor names here, the aliases of presets.toml.
pub(crate) fn say_modifier(
    flags: &mut BTreeMap<String, bool>,
    modifier: &str,
    on: bool,
) -> Result<(), String> {
    if flags.insert(modifier.to_string(), on) == Some(!on) {
        return Err(format!("both {modifier} and no-{modifier}"));
    }
    Ok(())
}

/// A gcov build measures coverage, it is not fuzzed: gcov implies no-sancov, and a name saying both
/// gcov and sancov is an error. True when the build must be without sancov.
pub(crate) fn gcov_without_sancov(flags: &BTreeMap<String, bool>) -> Result<bool, String> {
    if flags.get("gcov") != Some(&true) {
        return Ok(false);
    }
    if flags.get("sancov") == Some(&true) {
        return Err(
            "gcov and sancov: a gcov build measures coverage, it is not fuzzed (gcov implies \
             no-sancov)"
                .into(),
        );
    }
    Ok(true)
}

fn is_modifier(context: &VendorContext, name: &str) -> bool {
    INSTRUMENTATION.contains(&name) || context.builder_options.contains_key(name)
}

fn modifier_text(modifier: &str, on: bool) -> String {
    if on {
        modifier.into()
    } else {
        format!("no-{modifier}")
    }
}

fn unknown_modifier(catalogue: &Catalogue, context: &VendorContext, token: &str) -> String {
    format!(
        "'{token}': not a modifier of {} (its modifiers: {}, each also no-<modifier>; only-<bugs>, \
         fix-<bugs>, fix-all)",
        catalogue.vendor,
        modifiers(context).join(", ")
    )
}

/// The versions of a vendor's presets, oldest first.
pub fn versions(context: &VendorContext) -> Vec<String> {
    let mut versions: Vec<String> = context
        .presets
        .values()
        .map(|p| p.version.clone())
        .collect();
    versions.sort_by(|a, b| match (a.parse::<Version>(), b.parse::<Version>()) {
        (Ok(va), Ok(vb)) => va.cmp(&vb).then_with(|| a.cmp(b)),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    });
    versions.dedup();
    versions
}

/// The version of the presets a token names: as written, a development head by its other name
/// (`main` = `master`), the same release written otherwise (`5.4` = `5.4.0`), or without its dots
/// (`540` = `5.4.0`).
fn version_of(context: &VendorContext, token: &str) -> Result<Option<String>, String> {
    let versions = versions(context);
    if versions.iter().any(|v| v == token) {
        return Ok(Some(token.into()));
    }
    let heads = ["master", "main"];
    if heads.contains(&token) {
        let found: Vec<&String> = versions
            .iter()
            .filter(|v| heads.contains(&v.as_str()))
            .collect();
        if let [head] = found.as_slice() {
            return Ok(Some((*head).clone()));
        }
    }
    if let Some(release) = token.parse::<Version>().ok().filter(|r| !r.is_head()) {
        let found: Vec<&String> = versions
            .iter()
            .filter(|v| v.parse::<Version>().is_ok_and(|v| v == release))
            .collect();
        if let [one] = found.as_slice() {
            return Ok(Some((*one).clone()));
        }
    }
    let compact: Vec<&String> = versions
        .iter()
        .filter(|v| v.replace('.', "") == token)
        .collect();
    match compact.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).clone())),
        several => Err(format!(
            "'{token}' could be {}: write the version with its dots",
            several
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" or ")
        )),
    }
}

/// The forms a dashed name may start with: versions as written and without their dots (when that
/// is unambiguous), longest first.
fn version_forms(context: &VendorContext) -> Vec<(String, String)> {
    let versions = versions(context);
    let mut forms: Vec<(String, String)> = vec![];
    for version in &versions {
        forms.push((version.clone(), version.clone()));
        let compact = version.replace('.', "");
        if compact != *version
            && versions
                .iter()
                .filter(|v| v.replace('.', "") == compact)
                .count()
                == 1
        {
            forms.push((compact, version.clone()));
        }
    }
    forms.sort_by_key(|(form, _)| std::cmp::Reverse(form.len()));
    forms
}

fn not_a_start(catalogue: &Catalogue, context: &VendorContext, token: &str) -> String {
    format!(
        "'{token}': neither a version nor a preset of {} (its versions: {})",
        catalogue.vendor,
        versions(context).join(", ")
    )
}

/// Whether a name is the ID or the alias of a bug of the catalogue, in any case.
pub(super) fn names_a_bug(catalogue: &Catalogue, name: &str) -> bool {
    bug(catalogue, name).is_some()
}

/// A bug of the catalogue by its ID or its alias, in any case.
fn bug(catalogue: &Catalogue, text: &str) -> Option<String> {
    if catalogue.entries.contains_key(text) {
        return Some(text.into());
    }
    catalogue
        .entries
        .iter()
        .find(|(id, entry)| {
            id.eq_ignore_ascii_case(text)
                || entry
                    .alias
                    .as_deref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(text))
        })
        .map(|(id, _)| id.clone())
}

/// A catalogue part (`only-<bugs>`, `fix-<bugs>`, `fix-all`), its IDs sorted; `None`: the text is
/// not one.
fn select_of(catalogue: &Catalogue, text: &str) -> Result<Option<Select>, String> {
    if text == "fix-all" {
        return Ok(Some(Select {
            kind: "fix-all",
            ids: vec![],
        }));
    }
    let (kind, bugs) = if let Some(bugs) = text.strip_prefix("only-") {
        ("only", bugs)
    } else if let Some(bugs) = text.strip_prefix("fix-") {
        ("fix", bugs)
    } else {
        return Ok(None);
    };
    if bugs.is_empty() {
        return Err(format!("'{text}': no bug after '{kind}-'"));
    }
    let mut ids = bugs
        .split(ID_SEPARATOR)
        .map(|b| {
            bug(catalogue, b).ok_or_else(|| {
                format!(
                    "'{b}' is no bug of the {} catalogue (an ID or an alias)",
                    catalogue.vendor
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    ids.dedup();
    Ok(Some(Select { kind, ids }))
}

fn select_text(select: &Select) -> String {
    match select.kind {
        "fix-all" => "fix-all".into(),
        kind => format!("{kind}-{}", select.ids.join(&ID_SEPARATOR.to_string())),
    }
}

/// What a name (not a preset) asks.
fn request_of(
    catalogue: &Catalogue,
    context: &VendorContext,
    name: &str,
) -> Result<Request, String> {
    if let Some(id) = bug(catalogue, name) {
        // `<ID>`: its reference build, only that bug left, ASan
        let mut request = catalogue.reference_request(&id, context)?;
        request.flags.insert("asan".into(), true);
        request.select = Some(Select {
            kind: "only",
            ids: vec![id],
        });
        return Ok(request);
    }
    if name.contains(',') {
        parse_comma(catalogue, context, name)
    } else {
        parse_dashed(catalogue, context, name)
    }
}

/// `<version>,<modifier>,…`.
fn parse_comma(
    catalogue: &Catalogue,
    context: &VendorContext,
    name: &str,
) -> Result<Request, String> {
    let mut request = Request::default();
    for (i, token) in name.split(',').map(str::trim).enumerate() {
        if token.is_empty() {
            return Err(format!("'{name}': an empty part between commas"));
        }
        if let Some(select) = select_of(catalogue, token)? {
            if request.select.is_some() {
                return Err(format!(
                    "'{name}': one of only-…, fix-…, fix-all, not several"
                ));
            }
            request.select = Some(select);
            continue;
        }
        if i == 0 && !is_modifier(context, token.strip_prefix("no-").unwrap_or(token)) {
            request.start = Some(if context.presets.contains_key(token) {
                Start::Preset(token.into())
            } else {
                Start::Version(
                    version_of(context, token)?
                        .ok_or_else(|| not_a_start(catalogue, context, token))?,
                )
            });
            continue;
        }
        let (modifier, on) = match token.strip_prefix("no-") {
            Some(m) => (m, false),
            None => (token, true),
        };
        if !is_modifier(context, modifier) {
            return Err(unknown_modifier(catalogue, context, token));
        }
        say_modifier(&mut request.flags, modifier, on).map_err(|e| format!("'{name}': {e}"))?;
    }
    Ok(request)
}

/// A dashed name: a preset (exact: a slug) or a version, then `-<modifier>`s and a catalogue part.
fn parse_dashed(
    catalogue: &Catalogue,
    context: &VendorContext,
    name: &str,
) -> Result<Request, String> {
    if name.ends_with('-') {
        return Err(format!("'{name}': a '-' with nothing after it"));
    }
    let mut presets: Vec<&String> = context
        .presets
        .keys()
        .filter(|p| name.starts_with(&format!("{p}-")))
        .collect();
    presets.sort_by_key(|p| std::cmp::Reverse(p.len()));
    let mut first_error = None;
    for preset in presets {
        match dashed_rest(catalogue, context, &name[preset.len() + 1..]) {
            Ok((flags, select)) => {
                return Ok(Request {
                    start: Some(Start::Preset(preset.clone())),
                    flags,
                    select,
                    exact: true,
                })
            }
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }

    let version_request = |version: String, rest: &str| -> Result<Request, String> {
        let (flags, select) = if rest.is_empty() {
            (BTreeMap::new(), None)
        } else {
            dashed_rest(catalogue, context, rest)?
        };
        Ok(Request {
            start: Some(Start::Version(version)),
            flags,
            select,
            exact: false,
        })
    };
    for (form, version) in version_forms(context) {
        if name == form {
            return version_request(version, "");
        }
        if let Some(rest) = name.strip_prefix(&format!("{form}-")) {
            return version_request(version, rest);
        }
    }
    if let Some(select) = select_of(catalogue, name)? {
        return Ok(Request {
            select: Some(select),
            ..Request::default()
        });
    }
    let (first, rest) = name.split_once('-').unwrap_or((name, ""));
    match version_of(context, first)? {
        Some(version) => version_request(version, rest),
        None => Err(not_a_start(catalogue, context, name)),
    }
}

/// `<modifier>-…-<catalogue part>` of a dashed name; a modifier off is `no-<modifier>` or
/// `no<modifier>`.
fn dashed_rest(
    catalogue: &Catalogue,
    context: &VendorContext,
    rest: &str,
) -> Result<(BTreeMap<String, bool>, Option<Select>), String> {
    let mut flags = BTreeMap::new();
    let mut rest = rest;
    loop {
        if rest.is_empty() {
            return Err("a '-' with nothing after it".into());
        }
        if let Some(select) = select_of(catalogue, rest)? {
            return Ok((flags, Some(select)));
        }
        let (token, mut tail) = rest.split_once('-').unwrap_or((rest, ""));
        let (modifier, on) = if token == "no" {
            let (modifier, after) = tail.split_once('-').unwrap_or((tail, ""));
            tail = after;
            (modifier, false)
        } else {
            match token.strip_prefix("no") {
                Some(m) if !is_modifier(context, token) && is_modifier(context, m) => (m, false),
                _ => (token, true),
            }
        };
        if !is_modifier(context, modifier) {
            let written = if token == "no" {
                format!("no-{modifier}")
            } else {
                token.to_string()
            };
            return Err(unknown_modifier(catalogue, context, &written));
        }
        say_modifier(&mut flags, modifier, on)?;
        if tail.is_empty() {
            return Ok((flags, None));
        }
        rest = tail;
    }
}

/// The plainest preset of a version, without fixes: no ASan, the fewest options off their plain
/// value, the shortest name.
fn plain_preset(
    catalogue: &Catalogue,
    context: &VendorContext,
    version: &str,
) -> Result<(String, PresetInfo), String> {
    let of_version: Vec<(&String, &PresetInfo)> = context
        .presets
        .iter()
        .filter(|(_, p)| p.version == version)
        .collect();
    if of_version.is_empty() {
        return Err(not_a_start(catalogue, context, version));
    }
    of_version
        .into_iter()
        .filter(|(_, p)| p.fix.is_empty())
        .min_by_key(|(name, p)| {
            let away = modifiers(context)
                .iter()
                .filter(|m| *m != "asan" && value(p, context, m) != plain_value(context, m))
                .count();
            (p.asan, away, name.len(), (*name).clone())
        })
        .map(|(name, p)| (name.clone(), p.clone()))
        .ok_or_else(|| {
            format!(
                "every preset of {} {version} fixes bugs: add one without `fix`, to build from",
                catalogue.vendor
            )
        })
}

/// The name of a build: `prefer` if it is a preset with that build, else another preset with that
/// build, else `from` (a preset) followed by the modifiers that differ from it.
fn build_name(
    context: &VendorContext,
    info: &PresetInfo,
    prefer: &str,
    from: (&str, &PresetInfo),
) -> Result<String, String> {
    if context
        .presets
        .get(prefer)
        .is_some_and(|p| same_build(p, info, context))
    {
        return Ok(prefer.into());
    }
    if let Some((name, _)) = context
        .presets
        .iter()
        .filter(|(_, p)| same_build(p, info, context))
        .min_by_key(|(name, _)| (name.len(), (*name).clone()))
    {
        return Ok(name.clone());
    }
    let (from_name, from_info) = from;
    let mut name = from_name.to_string();
    for modifier in modifiers(context) {
        let on = value(info, context, &modifier);
        if on != value(from_info, context, &modifier) {
            name.push('-');
            name.push_str(&modifier_text(&modifier, on));
        }
    }
    if context.presets.contains_key(&name) {
        return Err(format!(
            "this build would be named {name}, the name of a preset with another build: rename \
             that preset"
        ));
    }
    Ok(name)
}

/// A request resolved.
fn build(
    catalogue: &Catalogue,
    context: &VendorContext,
    mut request: Request,
) -> Result<Built, String> {
    let (preset, mut info) = match request.start.clone() {
        Some(Start::Preset(preset)) => {
            let info = context.presets[&preset].clone();
            (preset, info)
        }
        Some(Start::Version(version)) => plain_preset(catalogue, context, &version)?,
        None => {
            // `only-<bug>` without a version: from the bug's reference build
            let Some(select) = request.select.clone().filter(|s| s.kind == "only") else {
                return Err(
                    "a version first (only-<bug> alone starts from the bug's reference build)"
                        .into(),
                );
            };
            if select.ids.len() > 1 {
                return Err(format!(
                    "only-{}: several bugs need a version (each bug alone starts from its own reference build)",
                    select.ids.join("+")
                ));
            }
            let reference = catalogue.reference_request(&select.ids[0], context)?;
            request.start = reference.start;
            for (modifier, on) in reference.flags {
                request.flags.entry(modifier).or_insert(on);
            }
            return build(catalogue, context, request);
        }
    };

    // the modifiers said; a gcov build is not fuzzed
    for (modifier, on) in &request.flags {
        info.options.insert(modifier.clone(), *on);
    }
    if gcov_without_sancov(&request.flags)? {
        info.options.insert("sancov".into(), false);
    }

    // what the bugs of `only-` need, unless said otherwise (a slug says everything)
    if !request.exact {
        if let Some(select) = request.select.as_ref().filter(|s| s.kind == "only") {
            for id in &select.ids {
                let entry = &catalogue.entries[id];
                for (option, wanted) in &entry.requires {
                    match request.flags.get(option) {
                        Some(said) if said != wanted => {
                            return Err(format!(
                                "{id} needs {}: without it the build does not have the bug",
                                modifier_text(option, *wanted)
                            ))
                        }
                        _ => {
                            info.options.insert(option.clone(), *wanted);
                        }
                    }
                }
                let asan_report = entry.oracle.as_ref().is_some_and(|o| o.asan.is_some())
                    || entry.find.as_ref().is_some_and(|f| f.asan);
                if asan_report && !request.flags.contains_key("asan") {
                    info.options.insert("asan".into(), true);
                }
            }
        }
    }
    info.asan = value(&info, context, "asan");

    if request.exact {
        // a slug: its preset's fixes stay, its catalogue part comes on top
        let base = if request.flags.is_empty() {
            preset.clone()
        } else {
            build_name(
                context,
                &info,
                &preset,
                (&preset, &context.presets[&preset]),
            )?
        };
        let derived = match &request.select {
            None => None,
            Some(select) => {
                let derivation =
                    catalogue.derive_on(&base, &info, select.kind, &select.ids, context)?;
                info.fix = derivation.fix;
                Some(derivation.derived)
            }
        };
        let slug = match &request.select {
            Some(select) => format!("{base}-{}", select_text(select)),
            None => base,
        };
        return Ok(finish(context, preset, info, derived, slug));
    }

    // otherwise the build is named from its version: the fixes of the preset it starts from join
    // its catalogue part
    let start_fixes = std::mem::take(&mut info.fix);
    let select = match request.select.take() {
        Some(select) if select.kind == "only" => {
            if let Some(id) = select.ids.iter().find(|id| start_fixes.contains(id)) {
                return Err(format!(
                    "{preset} fixes {id}: only-{id} cannot leave it (start from the version)"
                ));
            }
            Some(select)
        }
        Some(Select { kind: "fix", ids }) => {
            let mut ids: Vec<String> = ids.into_iter().chain(start_fixes).collect();
            ids.sort();
            ids.dedup();
            Some(Select { kind: "fix", ids })
        }
        Some(fix_all) => Some(fix_all),
        None if start_fixes.is_empty() => None,
        None => {
            let mut ids = start_fixes;
            ids.sort();
            Some(Select { kind: "fix", ids })
        }
    };
    let (plain, plain_info) = plain_preset(catalogue, context, &info.version)?;
    let base = build_name(context, &info, &preset, (&plain, &plain_info))?;
    let Some(select) = select else {
        return Ok(finish(context, preset, info, None, base));
    };
    let derivation = catalogue.derive_on(&base, &info, select.kind, &select.ids, context)?;
    info.fix = derivation.fix;
    if select.kind == "fix" {
        // fixes a preset has: that preset
        if let Some((name, _)) = context
            .presets
            .iter()
            .filter(|(_, p)| same_build(p, &info, context))
            .min_by_key(|(name, _)| (name.len(), (*name).clone()))
        {
            let name = name.clone();
            return Ok(finish(context, name.clone(), info, None, name));
        }
    }
    let slug = format!("{base}-{}", select_text(&select));
    Ok(finish(
        context,
        preset,
        info,
        Some(derivation.derived),
        slug,
    ))
}

/// A resolved build; a build named after a preset uses that preset.
fn finish(
    context: &VendorContext,
    preset: String,
    info: PresetInfo,
    derived: Option<Derived>,
    slug: String,
) -> Built {
    let preset = if derived.is_none() && context.presets.contains_key(&slug) {
        slug.clone()
    } else {
        preset
    };
    Built {
        preset,
        info,
        derived,
        slug,
    }
}

/// The comma form of a build with the fewest modifiers that give it back.
fn canonical(catalogue: &Catalogue, context: &VendorContext, built: &Built) -> String {
    let info = &built.info;
    let sorted = |ids: &[String]| {
        let mut ids = ids.to_vec();
        ids.sort();
        ids.dedup();
        ids
    };
    let select = match &built.derived {
        Some(d) if d.kind == "only" => Some(Select {
            kind: "only",
            ids: sorted(&d.ids),
        }),
        Some(d) if d.kind == "fix-all" => Some(Select {
            kind: "fix-all",
            ids: vec![],
        }),
        _ if info.fix.is_empty() => None,
        _ => Some(Select {
            kind: "fix",
            ids: sorted(&info.fix),
        }),
    };
    let gives = |flags: &BTreeMap<String, bool>| {
        build(
            catalogue,
            context,
            Request {
                start: Some(Start::Version(info.version.clone())),
                flags: flags.clone(),
                select: select.clone(),
                exact: false,
            },
        )
        .is_ok_and(|b| same_build(&b.info, info, context))
    };
    // every modifier said, then each one left out when the build does not need it said
    let mut flags: BTreeMap<String, bool> = modifiers(context)
        .into_iter()
        .map(|m| {
            let on = value(info, context, &m);
            (m, on)
        })
        .collect();
    if gives(&flags) {
        for modifier in modifiers(context) {
            let mut fewer = flags.clone();
            fewer.remove(&modifier);
            if gives(&fewer) {
                flags = fewer;
            }
        }
    }
    let mut parts = vec![info.version.clone()];
    parts.extend(
        modifiers(context)
            .iter()
            .filter_map(|m| flags.get(m).map(|on| modifier_text(m, *on))),
    );
    parts.extend(select.as_ref().map(select_text));
    parts.join(",")
}

impl Catalogue {
    /// Where `<ID>` and `only-<ID>` without a version start: the entry's `reference` (a preset, or
    /// a version and modifiers), else the newest preset with the bug (see `reference_preset`).
    fn reference_request(&self, id: &str, context: &VendorContext) -> Result<Request, String> {
        let reference = self.reference_preset(id, &self.entries[id], context)?;
        if reference.is_empty() {
            return Err(format!(
                "{id} is a bug of the harness: it has no reference build"
            ));
        }
        reference_request(self, context, &reference)
    }
}

/// A build a catalogue field names (`reference`, `check`): a preset, or a version and modifiers,
/// no catalogue part; its slug and its build.
pub(super) fn named_build(
    catalogue: &Catalogue,
    context: &VendorContext,
    name: &str,
) -> Result<(String, PresetInfo), String> {
    if let Some(info) = context.presets.get(name) {
        return Ok((name.into(), info.clone()));
    }
    let request = reference_request(catalogue, context, name)?;
    let built = build(catalogue, context, request)?;
    Ok((built.slug, built.info))
}

fn reference_request(
    catalogue: &Catalogue,
    context: &VendorContext,
    reference: &str,
) -> Result<Request, String> {
    if context.presets.contains_key(reference) {
        return Ok(Request {
            start: Some(Start::Preset(reference.into())),
            ..Request::default()
        });
    }
    let not_a_build = || {
        format!(
            "'{reference}': a preset, or a version and modifiers (no only-, fix-, fix-all, bug)"
        )
    };
    if bug(catalogue, reference).is_some() {
        return Err(not_a_build());
    }
    let request = if reference.contains(',') {
        parse_comma(catalogue, context, reference)?
    } else {
        parse_dashed(catalogue, context, reference)?
    };
    if request.select.is_some() || request.start.is_none() {
        return Err(not_a_build());
    }
    Ok(Request {
        exact: false,
        ..request
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{vendors, vendors_dir};

    fn load(vendor: &str) -> (Catalogue, VendorContext) {
        let context = VendorContext::load(vendor, &vendors_dir().join(vendor)).unwrap();
        (Catalogue::load(vendor).unwrap(), context)
    }

    fn resolved(vendor: &str, name: &str) -> Spec {
        let (catalogue, context) = load(vendor);
        resolve(&catalogue, &context, name).unwrap_or_else(|e| panic!("{vendor}:{name}: {e}"))
    }

    #[test]
    fn the_instrumentation_is_that_of_run_cmake() {
        let run =
            std::fs::read_to_string(crate::catalogue::build_dir().join("cmake/builder/run.cmake"))
                .unwrap();
        let options: Vec<String> = crate::catalogue::parse_builder_options(&run)
            .into_keys()
            .collect();
        let mut instrumentation: Vec<String> = INSTRUMENTATION
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        instrumentation.sort();
        assert_eq!(options, instrumentation);
    }

    #[test]
    fn every_preset_round_trips_through_its_canonical_name() {
        for vendor in vendors() {
            let (catalogue, context) = load(&vendor);
            for name in context.presets.keys() {
                let spec = resolve(&catalogue, &context, name).unwrap();
                assert_eq!(&spec.slug, name, "{vendor}:{name}");
                let again = resolve(&catalogue, &context, &spec.canonical)
                    .unwrap_or_else(|e| panic!("{vendor}:{name} as {}: {e}", spec.canonical));
                assert_eq!(&again.slug, name, "{vendor}:{name} as {}", spec.canonical);
                assert!(
                    same_build(&again.info, &spec.info, &context),
                    "{vendor}:{name}"
                );
                assert_eq!(again.canonical, spec.canonical);
            }
        }
    }

    #[test]
    fn derived_names_keep_their_names_and_fixes() {
        for vendor in vendors() {
            let (catalogue, context) = load(&vendor);
            for preset in context.presets.keys() {
                for derived in catalogue.validation_set(preset, &context) {
                    let before = catalogue.derive(&derived, &context).unwrap().unwrap();
                    let spec = resolve(&catalogue, &context, &derived).unwrap();
                    assert_eq!(spec.slug, derived);
                    assert_eq!(
                        spec.derived.as_ref(),
                        Some(&before.derived),
                        "{vendor}:{derived}"
                    );
                    let mut fix = spec.info.fix.clone();
                    let mut fix_before = before.fix.clone();
                    fix.sort();
                    fix_before.sort();
                    assert_eq!(fix, fix_before, "{vendor}:{derived}");
                    // the canonical name gives the same build, and its slug a name of its own
                    let again =
                        resolve(&catalogue, &context, &spec.canonical).unwrap_or_else(|e| {
                            panic!("{vendor}:{derived} as {}: {e}", spec.canonical)
                        });
                    assert!(
                        same_build(&again.info, &spec.info, &context),
                        "{vendor}:{derived} as {}",
                        spec.canonical
                    );
                    let by_slug = resolve(&catalogue, &context, &again.slug).unwrap();
                    assert!(
                        same_build(&by_slug.info, &spec.info, &context),
                        "{vendor}:{}",
                        again.slug
                    );
                    assert_eq!(by_slug.slug, again.slug);
                }
            }
        }
    }

    #[test]
    fn the_comma_form() {
        let asan = resolved("wolfssl", "5.4.0,asan");
        assert_eq!(
            (asan.slug.as_str(), asan.canonical.as_str()),
            ("wolfssl540-asan", "5.4.0,asan")
        );
        assert_eq!(
            resolved("wolfssl", "wolfssl540-asan").canonical,
            "5.4.0,asan"
        );
        assert_eq!(resolved("wolfssl", "5.4.0").slug, "wolfssl540");

        let buf = resolved("wolfssl", "5.4.0,asan,only-BUF");
        assert_eq!(buf.slug, "wolfssl540-asan-only-CVE-2022-39173");
        assert_eq!(
            buf.canonical, "5.4.0,only-CVE-2022-39173",
            "ASan comes with BUF's oracle"
        );
        assert_eq!(buf.info.fix, vec!["CVE-2022-42905".to_string()]);
        assert_eq!(buf.derived.as_ref().unwrap().base, "wolfssl540-asan");
        for same in [
            "5.4.0,only-buf",
            "only-BUF",
            "540,only-BUF",
            "540-asan-only-buf",
            "5.4,asan,only-CVE-2022-39173",
            "BUF",
            "CVE-2022-39173",
            "wolfssl540-asan-only-BUF",
        ] {
            assert_eq!(resolved("wolfssl", same).slug, buf.slug, "{same}");
        }
        let no_asan = resolved("wolfssl", "5.4.0,no-asan,only-BUF");
        assert_eq!(no_asan.slug, "wolfssl540-only-CVE-2022-39173");
        assert_eq!(no_asan.canonical, "5.4.0,no-asan,only-CVE-2022-39173");

        // what SDOS2 needs comes with it: postauth off, ASan (its oracle is an ASan report)
        let (catalogue, context) = load("wolfssl");
        let sdos2 = resolved("wolfssl", "5.4.0,only-SDOS2");
        assert!(!value(&sdos2.info, &context, "postauth") && sdos2.info.asan);
        assert_eq!(sdos2.canonical, "5.4.0,only-CVE-2022-38152");
        assert_eq!(
            sdos2.slug,
            "wolfssl540-asan-no-postauth-only-CVE-2022-38152"
        );
        let by_slug = resolve(&catalogue, &context, &sdos2.slug).unwrap();
        assert!(same_build(&by_slug.info, &sdos2.info, &context));
        assert_eq!(by_slug.slug, sdos2.slug);

        // a preset's fixes, written as such, give the preset
        assert_eq!(
            resolved("wolfssl", "wolfssl540-buf").canonical,
            "5.4.0,fix-CVE-2022-42905"
        );
        assert_eq!(resolved("wolfssl", "5.4.0,fix-HEAP").slug, "wolfssl540-buf");
        assert_eq!(
            resolved("wolfssl", "wolfssl540-sdos2").canonical,
            "5.4.0,no-postauth,fix-CVE-2022-39173"
        );
        assert_eq!(
            resolved("wolfssl", "5.4.0,no-postauth,fix-BUF").slug,
            "wolfssl540-sdos2"
        );
        assert_eq!(
            resolved("wolfssl", "5.4.0,no-postauth").slug,
            "wolfssl540-no-postauth"
        );
        assert_eq!(
            resolved("wolfssl", "540-no-postauth").slug,
            "wolfssl540-no-postauth"
        );
        let gcov = resolved("wolfssl", "5.4.0,gcov");
        assert_eq!(
            (gcov.slug.as_str(), gcov.canonical.as_str()),
            ("wolfssl540-no-sancov-gcov", "5.4.0,gcov")
        );

        // the development head, other vendors
        assert_eq!(resolved("wolfssl", "master").slug, "wolfsslmaster");
        assert_eq!(resolved("wolfssl", "main,asan").slug, "wolfsslmaster-asan");
        assert_eq!(resolved("openssl", "1.1.1j,asan").slug, "openssl111j-asan");
        assert_eq!(resolved("openssl", "111j-asan").slug, "openssl111j-asan");
        assert_eq!(
            resolved("openssl", "1.1.1j,only-SDOS1").slug,
            "openssl111j-asan-only-CVE-2021-3449"
        );
        assert_eq!(
            resolved("libssh", "0.10.4,no-sancov").slug,
            "libssh0104-no-sancov"
        );
        assert_eq!(
            resolved("boringssl", "boringssl202403-asan").canonical,
            "1.1.1g+git.368d0d87d0bd,asan"
        );
    }

    #[test]
    fn the_ci_checks_builds_under_names_that_say_asan() {
        // it builds them with ASan: a build without is checked by the name of its ASan build
        for vendor in vendors() {
            let (catalogue, context) = load(&vendor);
            for name in catalogue.check_presets(&context).keys() {
                let spec = resolve(&catalogue, &context, name).unwrap();
                assert!(spec.info.asan, "{vendor}:{name}");
                assert!(spec.derived.is_none(), "{vendor}:{name}");
                assert!(
                    !catalogue.validation_set(name, &context).is_empty(),
                    "{vendor}:{name}"
                );
            }
        }
    }

    #[test]
    fn what_cannot_be_built_is_said() {
        let (catalogue, context) = load("wolfssl");
        let error = |name: &str| resolve(&catalogue, &context, name).unwrap_err();
        assert!(error("5.4.0,postauth,only-SDOS2").contains("needs no-postauth"));
        assert!(error("5.4.0,tls13").contains(
            "not a modifier of wolfssl (its modifiers: asan, sancov, gcov, llvm_cov, postauth"
        ));
        assert!(error("5.4.0,only-NOSUCHBUG").contains("no bug of the wolfssl catalogue"));
        assert!(error("9.9.9").contains("neither a version nor a preset of wolfssl"));
        assert!(error("5.4.0,only-BUF,fix-HEAP").contains("not several"));
        assert!(error("5.4.0,asan,no-asan").contains("both asan and no-asan"));
        assert!(error("540-asan-no-asan").contains("both asan and no-asan"));
        assert!(error("540-no-asan-").contains("a '-' with nothing after it"));
        assert!(error("540-no-bogus").contains("'no-bogus': not a modifier"));
        assert!(error("only-BUF+HEAP").contains("several bugs need a version"));
        assert!(error("5.4.0,gcov,sancov").contains("gcov implies no-sancov"));
        assert!(error("wolfssl540-buf,only-HEAP").contains("wolfssl540-buf fixes CVE-2022-42905"));
        assert!(
            error("wolfssl540-only-SDOS2").contains("does not affect"),
            "a slug: nothing implied"
        );
        let (openssl, openssl_context) = load("openssl");
        assert!(resolve(&openssl, &openssl_context, "1.1.1j,postauth")
            .unwrap_err()
            .contains(
                "not a modifier of openssl (its modifiers: asan, sancov, gcov, llvm_cov, each"
            ));
    }
}
