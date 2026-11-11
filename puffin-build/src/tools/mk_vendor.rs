use clap::{Parser, Subcommand};
use puffin_build::catalogue::{self, Catalogue, LibraryState, Status, VendorContext};
use puffin_build::{library, vendor_dir};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(about = "helper script to build vendor libraries for tlspuffin", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// `mk_vendor make [--force] [--asan] [--name=<name>] <vendor>:<build>`
    ///
    /// `<build>`: `<version>[,<modifier>…]` (`5.4.0,asan,only-BUF`: see `mk_vendor modifiers
    /// <vendor>`), a preset of the vendor's presets.toml (`wolfssl540-asan`), a preset followed
    /// by `-<modifier>`s and `-only-<IDs>`, `-fix-<IDs>` or `-fix-all`, or a bug of the catalogue
    /// alone (`CVE-2022-39173`: its reference build, only that bug left, ASan). The library
    /// directory and the PUT are named after the build (`mk_vendor resolve` shows it).
    #[command(arg_required_else_help = true)]
    Make {
        /// The build (e.g. 'openssl:1.1.1j,asan', 'wolfssl:5.4.0,only-BUF', 'openssl:openssl312')
        #[arg(value_name = "CONFIG")]
        #[arg(value_parser = parse_config_arg)]
        config: (String, String),

        /// Name the library directory and the PUT otherwise
        #[arg(short, long)]
        name: Option<String>,

        /// Force configuration rebuild if it already exists
        #[arg(short, long)]
        #[arg(default_value_t = false)]
        force: bool,

        /// Build with AddressSanitizer whatever the preset says
        #[arg(long)]
        #[arg(default_value_t = false)]
        asan: bool,
    },

    /// `mk_vendor list <vendor>:<name> [--json]`: the catalogue entries of a build and their
    /// state, and the validation set of the preset (its `-fix-all` build and one `-only-<ID>`
    /// build per active bug with a patch).
    ///
    /// `mk_vendor list --check [--json]`: the presets the catalogue is checked on, with their
    /// validation sets.
    #[command(arg_required_else_help = true)]
    List {
        #[arg(value_name = "CONFIG")]
        #[arg(value_parser = parse_config_arg)]
        #[arg(required_unless_present = "check")]
        config: Option<(String, String)>,

        /// List the presets the catalogue is checked on (every vendor)
        #[arg(long)]
        #[arg(conflicts_with = "config")]
        check: bool,

        /// Output JSON
        #[arg(long)]
        json: bool,
    },

    /// `mk_vendor resolve <vendor>:<build> [--json]`: what a name builds: its canonical name, the
    /// name of its directory and PUT, its sources, options, fixes and the bugs it has.
    #[command(arg_required_else_help = true)]
    Resolve {
        #[arg(value_name = "CONFIG")]
        #[arg(value_parser = parse_config_arg)]
        config: (String, String),

        /// Output JSON
        #[arg(long)]
        json: bool,
    },

    /// `mk_vendor modifiers <vendor> [--json]`: the modifiers a name of the vendor's builds may
    /// use.
    #[command(arg_required_else_help = true)]
    Modifiers {
        vendor: String,

        /// Output JSON
        #[arg(long)]
        json: bool,
    },

    /// `mk_vendor check-patches [<vendor>]`: apply the patches of presets.toml and dry-run the
    /// catalogue's on the sources of every version one of them is for: the presets.toml patches of
    /// the version, then each catalogue patch alone, then all of them together (as its `-fix-all`
    /// build applies them, without the builder's own patches).
    CheckPatches {
        /// Only this vendor
        vendor: Option<String>,
    },
}

pub fn main() -> std::process::ExitCode {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_env(
            env_logger::Env::default()
                .filter("MK_VENDOR_LOG")
                .write_style("MK_VENDOR_LOG_STYLE"),
        )
        .init();

    let Cli { command } = Cli::parse();

    let result = match command {
        Commands::Make {
            config: (vendor, name),
            name: output_name,
            force,
            asan,
        } => make(&vendor, &name, output_name, force, asan),
        Commands::List {
            config: Some((vendor, name)),
            json,
            ..
        } => list(&vendor, &name, json),
        Commands::List {
            check: true, json, ..
        } => list_check(json),
        Commands::Resolve {
            config: (vendor, name),
            json,
        } => resolve(&vendor, &name, json),
        Commands::Modifiers { vendor, json } => modifiers(&vendor, json),
        Commands::CheckPatches { vendor } => check_patches(vendor.as_deref()),
        Commands::List { .. } => Err("expected <vendor>:<name> or --check".into()),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn make(
    vendor: &str,
    name: &str,
    output_name: Option<String>,
    force: bool,
    asan: bool,
) -> Result<(), String> {
    let (mut config, build_name) = library::Config::resolve_named(vendor, name)?;
    if asan {
        config.option("asan", true);
    }

    // an invalid catalogue fails here, before `--force` removes the library
    config.catalogue_state()?;

    let output_name = output_name.unwrap_or(build_name);

    vendor_dir::VendorDir::default()
        .library_dir(&output_name)
        .and_then(|library_dir| {
            if force {
                library_dir.remove()?
            }

            library_dir.make(&config, true)
        })
        .map(|_| ())
        .map_err(|e| format!("Error while building vendor library '{output_name}': {e}"))
}

#[derive(Debug, Serialize)]
struct EntryLine {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    state: Status,
    /// whether the entry has a patch for this version
    patchable: bool,
    bug_in_harness: bool,
    /// objectives found by fuzzing reproduce on replay
    replayable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    oracle: Option<catalogue::Oracle>,
    summary: String,
    category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_witness: Option<String>,
    /// hash of the entry (its whole definition and its patches): validations record it
    hash: String,
    /// hash of what the build takes from the entry (affected versions, options, patches), as the
    /// build records it
    build_hash: String,
}

#[derive(Debug, Serialize)]
struct Listing {
    vendor: String,
    name: String,
    /// the canonical name of the build (`<vendor>:<version>[,<modifier>…]`)
    canonical: String,
    /// the name of its library directory and PUT
    slug: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived: Option<catalogue::Derived>,
    fix: Vec<String>,
    asan: bool,
    catalogue: String,
    entries: Vec<EntryLine>,
    /// the derived builds the catalogue is validated on, for this preset (empty for a derived
    /// name)
    validation_set: Vec<String>,
}

fn listing(vendor: &str, name: &str) -> Result<Listing, String> {
    let config = library::Config::resolve(vendor, name)?;
    let spec = catalogue::resolve_name(vendor, name)?;
    let state: LibraryState = config
        .catalogue_state()?
        .ok_or_else(|| format!("vendor '{vendor}' has no catalogue"))?;
    let catalogue = Catalogue::load(vendor).map_err(|e| e.to_string())?;
    let context = VendorContext::load(vendor, &catalogue.dir).map_err(|e| e.to_string())?;

    let entries = state
        .entries
        .iter()
        .map(|(id, entry_state)| {
            let entry = catalogue.entry(id).expect("state of an unknown entry");
            EntryLine {
                id: id.clone(),
                alias: entry.alias.clone(),
                state: entry_state.state,
                patchable: state.patchable(id),
                bug_in_harness: entry.bug_in_harness,
                replayable: entry.replayable,
                oracle: entry.oracle.clone(),
                summary: entry.summary.clone(),
                category: entry.category.clone(),
                cvss: entry.cvss.as_ref().map(|c| c.score),
                no_witness: entry.no_witness.clone(),
                hash: catalogue.entry_hash(id).unwrap_or_default().to_string(),
                build_hash: entry_state.hash.clone(),
            }
        })
        .collect();

    Ok(Listing {
        vendor: vendor.into(),
        name: name.into(),
        canonical: format!("{vendor}:{}", spec.canonical),
        slug: spec.slug.clone(),
        version: state.version.clone(),
        derived: state.derived.clone(),
        fix: config.options().fix(),
        asan: config
            .options()
            .booleans()
            .get("asan")
            .copied()
            .unwrap_or(false),
        catalogue: state.catalogue.clone(),
        entries,
        validation_set: if config.derived().is_some() {
            vec![]
        } else {
            catalogue.validation_set(&spec.slug, &context)
        },
    })
}

fn list(vendor: &str, name: &str, json: bool) -> Result<(), String> {
    let listing = listing(vendor, name)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&listing).unwrap());
        return Ok(());
    }

    println!(
        "{}{}: version {}{}{}",
        listing.canonical,
        if listing.slug != name {
            format!(" ({})", listing.slug)
        } else {
            String::new()
        },
        listing.version,
        if listing.asan { ", ASan" } else { "" },
        listing
            .derived
            .as_ref()
            .map(|d| format!(", derived from {} ({})", d.base, d.kind))
            .unwrap_or_default()
    );
    for entry in &listing.entries {
        println!(
            "  {:<16} {:<12} {:<10} {}{}{}",
            entry.id,
            entry.alias.as_deref().unwrap_or(""),
            entry.state.to_string(),
            match (entry.state, entry.patchable) {
                (Status::Unaffected, _) => "",
                (_, true) => "patch",
                (_, false) => "no patch",
            },
            if entry.bug_in_harness {
                ", harness bug"
            } else {
                ""
            },
            if entry.no_witness.is_some() {
                ", no witness"
            } else {
                ""
            },
        );
    }
    if !listing.validation_set.is_empty() {
        println!("validation set:");
        for build in &listing.validation_set {
            println!("  {vendor}:{build}");
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct Resolved {
    vendor: String,
    name: String,
    /// `<vendor>:<version>[,<modifier>…]`
    canonical: String,
    /// the name of its library directory and PUT
    slug: String,
    /// the preset whose sources and builder it uses
    preset: String,
    version: String,
    /// every modifier and its value in the build
    options: std::collections::BTreeMap<String, bool>,
    fix: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived: Option<catalogue::Derived>,
    /// the bugs of the catalogue the build has (affected, not fixed)
    active: Vec<String>,
}

fn resolve(vendor: &str, name: &str, json: bool) -> Result<(), String> {
    let spec = catalogue::resolve_name(vendor, name)?;
    let catalogue = Catalogue::load(vendor).map_err(|e| e.to_string())?;
    let context = VendorContext::load(vendor, &catalogue.dir).map_err(|e| e.to_string())?;
    let resolved = Resolved {
        vendor: vendor.into(),
        name: name.into(),
        canonical: format!("{vendor}:{}", spec.canonical),
        slug: spec.slug.clone(),
        preset: spec.preset.clone(),
        version: spec.info.version.clone(),
        options: catalogue::spec::modifiers(&context)
            .into_iter()
            .map(|m| {
                let on = catalogue::spec::value(&spec.info, &context, &m);
                (m, on)
            })
            .collect(),
        fix: spec.info.fix.clone(),
        derived: spec.derived.clone(),
        active: catalogue
            .entries
            .iter()
            .filter(|(id, entry)| {
                entry.is_active_in(&spec.info, &context) && !spec.info.fix.contains(id)
            })
            .map(|(id, _)| id.clone())
            .collect(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&resolved).unwrap());
        return Ok(());
    }
    let with_alias = |id: &String| match catalogue.entry(id).and_then(|e| e.alias.as_deref()) {
        Some(alias) => format!("{id} ({alias})"),
        None => id.clone(),
    };
    let on_off = |on: bool| -> Vec<&str> {
        resolved
            .options
            .iter()
            .filter(|(_, v)| **v == on)
            .map(|(m, _)| m.as_str())
            .collect()
    };
    println!("{}", resolved.canonical);
    println!("  name     {} (library directory and PUT)", resolved.slug);
    println!(
        "  sources  {} {} (preset {})",
        vendor, resolved.version, resolved.preset
    );
    println!(
        "  options  on: {}; off: {}",
        on_off(true).join(", "),
        on_off(false).join(", ")
    );
    println!(
        "  fixes    {}",
        if resolved.fix.is_empty() {
            "-".to_string()
        } else {
            resolved
                .fix
                .iter()
                .map(with_alias)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if let Some(derived) = &resolved.derived {
        println!(
            "  derived  {} {}, from {}",
            derived.kind,
            derived.ids.join("+"),
            derived.base
        );
    }
    println!(
        "  bugs     {}",
        if resolved.active.is_empty() {
            "-".to_string()
        } else {
            resolved
                .active
                .iter()
                .map(|id| {
                    let patch = catalogue
                        .entry(id)
                        .and_then(|e| e.patch_for(&resolved.version))
                        .is_some();
                    format!(
                        "{}{}",
                        with_alias(id),
                        if patch { "" } else { " (no patch)" }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct Modifier {
    name: String,
    /// "instrumentation" (every vendor) or "option" (of the vendor's builder.cmake)
    kind: &'static str,
    /// its value in a plain build
    default: bool,
    doc: String,
}

fn modifiers(vendor: &str, json: bool) -> Result<(), String> {
    let dir = catalogue::vendors_dir().join(vendor);
    let context = VendorContext::load(vendor, &dir).map_err(|e| e.to_string())?;
    if context.presets.is_empty() {
        return Err(format!(
            "unknown vendor '{vendor}' (vendors: {})",
            catalogue::vendors().join(", ")
        ));
    }
    // presets.toml's [modifiers] (their docs), in the order of the names
    let declared = library::presets::load(vendor)?.modifiers;
    let list: Vec<Modifier> = catalogue::spec::modifiers(&context)
        .into_iter()
        .map(|m| Modifier {
            kind: if catalogue::spec::INSTRUMENTATION.contains(&m.as_str()) {
                "instrumentation"
            } else {
                "option"
            },
            default: catalogue::spec::plain_value(&context, &m),
            doc: declared.get(&m).map(|d| d.doc.clone()).unwrap_or_default(),
            name: m,
        })
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return Ok(());
    }
    println!(
        "{vendor}:<version>[,<modifier>…], the modifiers in any order, each also no-<modifier>:"
    );
    for m in &list {
        println!(
            "  {:<10} {:<16} {:<12} {}",
            m.name,
            m.kind,
            if m.default {
                "default on"
            } else {
                "default off"
            },
            m.doc
        );
    }
    println!(
        "  only-<bugs>, fix-<bugs>, fix-all: the bugs of the catalogue (IDs or aliases joined by \
         '+'; `mk_vendor list {vendor}:<version>`)"
    );
    println!(
        "versions: {}",
        catalogue::spec::versions(&context).join(", ")
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct CheckPreset {
    /// unique name of the check (`<vendor>-<preset>`)
    name: String,
    vendor: String,
    preset: String,
    /// the entries this preset checks
    entries: Vec<String>,
    /// the derived builds to make (`<vendor>:<build>`)
    builds: Vec<String>,
}

fn list_check(json: bool) -> Result<(), String> {
    let mut checks = vec![];
    for vendor in catalogue::vendors() {
        let catalogue = Catalogue::load(&vendor).map_err(|e| e.to_string())?;
        let context = VendorContext::load(&vendor, &catalogue.dir).map_err(|e| e.to_string())?;
        for (preset, entries) in catalogue.check_presets(&context) {
            checks.push(CheckPreset {
                name: format!("{vendor}-{preset}"),
                vendor: vendor.clone(),
                builds: catalogue.validation_set(&preset, &context),
                preset,
                entries,
            });
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&checks).unwrap());
    } else {
        for check in &checks {
            println!(
                "{}:{} ({})",
                check.vendor,
                check.preset,
                check.entries.join(", ")
            );
            for build in &check.builds {
                println!("  {}:{build}", check.vendor);
            }
        }
    }
    Ok(())
}

fn check_patches(only: Option<&str>) -> Result<(), String> {
    use std::process::Command;

    let apply = |dir: &std::path::Path, file: &std::path::Path, check: bool| {
        let mut cmd = Command::new("git");
        cmd.arg("--git-dir=").arg("-C").arg(dir).arg("apply");
        if check {
            cmd.arg("--check");
        }
        cmd.arg(file)
            .output()
            .map(|o| {
                (
                    o.status.success(),
                    String::from_utf8_lossy(&o.stderr).trim().to_string(),
                )
            })
            .map_err(|e| format!("cannot run git: {e}"))
    };

    let mut failures = 0;
    for vendor in catalogue::vendors()
        .into_iter()
        .filter(|v| only.is_none_or(|o| o == v))
    {
        let catalogue = Catalogue::load(&vendor).map_err(|e| e.to_string())?;
        let context = VendorContext::load(&vendor, &catalogue.dir).map_err(|e| e.to_string())?;

        // one check per sources (several presets of a version share them)
        let presets = library::presets::load(&vendor)?;
        let mut checked: Vec<library::Sources> = vec![];
        for (preset, info) in &context.presets {
            let patches: Vec<(&String, &catalogue::Patch)> = catalogue
                .entries
                .iter()
                .filter(|(_, entry)| entry.is_active_in(info, &context))
                .filter_map(|(id, entry)| entry.patch_for(&info.version).map(|p| (id, p)))
                .collect();
            if patches.is_empty()
                && presets
                    .patches_for(&catalogue.dir, &info.version)
                    .is_empty()
            {
                continue;
            }
            let config = library::Config::resolve(&vendor, preset)?;
            if checked.contains(config.sources()) {
                continue;
            }
            checked.push(config.sources().clone());

            let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
            let archive = config
                .sources()
                .download(tmp.path().join("download"))
                .map_err(|e| {
                    format!(
                        "{vendor} {}: cannot download the sources: {e}",
                        info.version
                    )
                })?;
            let extracted = tmp.path().join("src");
            std::fs::create_dir_all(&extracted).map_err(|e| e.to_string())?;
            let status = Command::new("tar")
                .arg("-xf")
                .arg(&archive)
                .arg("-C")
                .arg(&extracted)
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!(
                    "{vendor} {}: cannot extract {}",
                    info.version,
                    archive.display()
                ));
            }
            let entries: Vec<_> = std::fs::read_dir(&extracted)
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok())
                .collect();
            let dir = match entries.as_slice() {
                [single] if single.path().is_dir() => single.path(),
                _ => extracted.clone(),
            };

            // the patches of presets.toml for this version first, as a build applies them
            let library_patches = presets.patches_for(&catalogue.dir, &info.version);
            for file in &library_patches {
                let (ok, err) = apply(&dir, file, false)?;
                println!(
                    "{} {vendor} {} presets.toml {}",
                    if ok { "ok  " } else { "FAIL" },
                    info.version,
                    file.strip_prefix(&catalogue.dir).unwrap_or(file).display()
                );
                if !ok {
                    failures += 1;
                    println!("     {err}");
                }
            }
            for (id, patch) in &patches {
                for file in &patch.files {
                    let (ok, err) = apply(&dir, &catalogue.dir.join(file), true)?;
                    println!(
                        "{} {vendor} {} {id} {file}",
                        if ok { "ok  " } else { "FAIL" },
                        info.version
                    );
                    if !ok {
                        failures += 1;
                        println!("     {err}");
                    }
                }
            }
            // all together, in the order of a build's fix list
            let mut together = true;
            for (id, patch) in &patches {
                for file in &patch.files {
                    let (ok, err) = apply(&dir, &catalogue.dir.join(file), false)?;
                    if !ok {
                        together = false;
                        failures += 1;
                        println!("FAIL {vendor} {} all patches together: {id} {file} does not apply after the others", info.version);
                        println!("     {err}");
                    }
                }
            }
            if together && patches.len() > 1 {
                println!(
                    "ok   {vendor} {} all {} patches together",
                    info.version,
                    patches.len()
                );
            }
        }
    }

    if failures > 0 {
        Err(format!("{failures} patch check(s) failed"))
    } else {
        Ok(())
    }
}

fn parse_config_arg(s: &str) -> Result<(String, String), String> {
    match s
        .split_once(':')
        .map(|(vendor, name)| (vendor.trim(), name.trim()))
    {
        Some((vendor, name)) if !vendor.is_empty() && !name.is_empty() && !name.contains(':') => {
            Ok((vendor.to_string(), name.to_string()))
        }
        _ => Err("invalid config format (expected '<vendor>:<name>')".to_string()),
    }
}
