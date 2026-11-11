use super::*;

fn context() -> VendorContext {
    let preset = |version: &str, asan: bool, fix: &[&str], options: &[(&str, bool)]| PresetInfo {
        version: version.into(),
        asan,
        fix: fix.iter().map(std::string::ToString::to_string).collect(),
        options: options
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .chain(asan.then(|| ("asan".to_string(), true)))
            .collect(),
    };

    VendorContext {
        presets: BTreeMap::from([
            ("lib510".into(), preset("5.1.0", false, &[], &[])),
            ("lib510-asan".into(), preset("5.1.0", true, &[], &[])),
            ("lib540".into(), preset("5.4.0", false, &[], &[])),
            ("lib540-asan".into(), preset("5.4.0", true, &[], &[])),
            (
                "lib540-buf".into(),
                preset("5.4.0", true, &["CVE-2022-39173"], &[]),
            ),
            (
                "lib540-nopostauth".into(),
                preset("5.4.0", false, &[], &[("postauth", false)]),
            ),
            ("lib552-asan".into(), preset("5.5.2", true, &[], &[])),
        ]),
        builder_options: BTreeMap::from([("postauth".into(), true)]),
        capabilities: ["tls12", "tls13", "tls13_session_resumption"]
            .into_iter()
            .map(String::from)
            .collect(),
    }
}

struct Dir(tempfile::TempDir);

fn vendor_dir(patches: &[&str]) -> Dir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("patches")).unwrap();
    for patch in patches {
        std::fs::write(
            dir.path().join("patches").join(patch),
            format!("patch {patch}\n"),
        )
        .unwrap();
    }
    Dir(dir)
}

const BUF: &str = r#"
[CVE-2022-39173]
alias = "BUF"
summary = "stack-buffer-overflow in RefineSuites"
category = "memory"
cvss = { version = "3.1", score = 7.5, vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source = "nvd" }
affected = "< 5.5.1"
capabilities = ["tls13", "tls13_session_resumption"]
oracle = { kind = "crash", asan = "stack-buffer-overflow" }

[[CVE-2022-39173.patches]]
versions = ">= 5.0.0, < 5.5.1"
files = ["patches/fix-buf.patch"]
"#;

fn parse(content: &str, dir: &Dir) -> Result<Catalogue, CatalogueError> {
    Catalogue::parse("lib", dir.0.path(), content, &context())
}

fn problems(content: &str, dir: &Dir) -> Vec<String> {
    parse(content, dir).map_or_else(|e| e.problems, |_| vec![])
}

fn assert_problem(content: &str, dir: &Dir, expected: &str) {
    let problems = problems(content, dir);
    assert!(
        problems.iter().any(|p| p.contains(expected)),
        "expected a problem containing {expected:?}, got {problems:#?}"
    );
}

#[test]
fn a_valid_catalogue_loads() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let catalogue = parse(BUF, &dir).unwrap();
    let entry = catalogue.entry("CVE-2022-39173").unwrap();

    assert_eq!(entry.alias.as_deref(), Some("BUF"));
    assert!(entry.replayable);
    assert!(!entry.bug_in_harness);
    assert_eq!(
        catalogue.reference_preset("CVE-2022-39173", entry, &context()),
        Ok("lib540-asan".into())
    );
    assert!(entry.patch_for("5.4.0").is_some());
    assert!(entry.patch_for("4.4.0").is_none());
    assert_eq!(catalogue.entry_hash("CVE-2022-39173").unwrap().len(), 64);
    assert_eq!(catalogue.hash.len(), 64);
}

#[test]
fn hashes_follow_the_entry_and_its_patches() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let before = parse(BUF, &dir).unwrap();

    std::fs::write(
        dir.0.path().join("patches/fix-buf.patch"),
        "another patch\n",
    )
    .unwrap();
    let patched = parse(BUF, &dir).unwrap();
    assert_ne!(
        before.entry_hash("CVE-2022-39173"),
        patched.entry_hash("CVE-2022-39173")
    );
    assert_ne!(before.hash, patched.hash);

    let edited = parse(
        &BUF.replace("RefineSuites\"", "RefineSuites (edited)\""),
        &dir,
    )
    .unwrap();
    assert_ne!(
        patched.entry_hash("CVE-2022-39173"),
        edited.entry_hash("CVE-2022-39173")
    );
}

#[test]
fn unknown_fields_are_refused() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace("alias =", "aliass ="),
        &dir,
        "unknown field `aliass`",
    );
}

#[test]
fn cvss_must_match_its_vector() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace("score = 7.5", "score = 7.6"),
        &dir,
        "does not match its vector",
    );
    assert_problem(
        &BUF.replace(
            r#"cvss = { version = "3.1", score = 7.5, vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source = "nvd" }"#,
            "",
        ),
        &dir,
        "missing cvss",
    );
}

#[test]
fn patch_files_must_exist() {
    let dir = vendor_dir(&[]);
    assert_problem(BUF, &dir, "cannot read patch");
}

#[test]
fn every_entry_has_a_patch_or_says_why_not() {
    let dir = vendor_dir(&[]);
    let without = &BUF[..BUF.find("[[CVE-2022-39173.patches]]").unwrap()];
    assert_problem(without, &dir, "no patch: add one, or no_patch");

    let with_reason = without.replace(
        "affected = ",
        "no_patch = \"the upstream fix does not apply\"\naffected = ",
    );
    // the entry is fine; only the preset that fixes it is not
    assert_eq!(
        problems(&with_reason, &dir),
        vec![
            "preset 'lib540-buf': fix 'CVE-2022-39173', which has no patch for version 5.4.0"
                .to_string()
        ]
    );
}

#[test]
fn patch_ranges_stay_inside_the_affected_versions() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace(">= 5.0.0, < 5.5.1", ">= 5.0.0"),
        &dir,
        "which is not affected",
    );
}

#[test]
fn two_patches_of_an_entry_cannot_cover_one_version() {
    let dir = vendor_dir(&["fix-buf.patch", "fix-buf-2.patch"]);
    let content = format!(
        "{BUF}\n[[CVE-2022-39173.patches]]\nversions = \">= 5.4.0, < 5.5.1\"\nfiles = [\"patches/fix-buf-2.patch\"]\n"
    );
    assert_problem(&content, &dir, "are both for version 5.4.0");
}

#[test]
fn requires_names_builder_options() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace(
            "affected = ",
            "requires = { nopostauth = false }\naffected = ",
        ),
        &dir,
        "not an option of builder.cmake",
    );
}

#[test]
fn requires_decides_which_builds_have_the_bug() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let catalogue = parse(
        &BUF.replace(
            "affected = ",
            "requires = { postauth = false }\naffected = ",
        ),
        &dir,
    );
    // lib540-buf fixes it although it does not have it any more (postauth is on by default)
    let catalogue = catalogue.unwrap_err();
    assert!(catalogue
        .problems
        .iter()
        .any(|p| p.contains("lib540-buf") && p.contains("does not affect")));

    let content = BUF.replace(
        "affected = ",
        "requires = { postauth = false }\naffected = ",
    );
    let entry: BTreeMap<String, Entry> = toml::from_str(&content).unwrap();
    let entry = &entry["CVE-2022-39173"];
    let ctx = context();
    assert!(!entry.is_active_in(&ctx.presets["lib540"], &ctx));
    assert!(entry.is_active_in(&ctx.presets["lib540-nopostauth"], &ctx));
}

#[test]
fn capabilities_are_known_ones() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace("\"tls13_session_resumption\"]", "\"tls13_resumption\"]"),
        &dir,
        "unknown capability 'tls13_resumption'",
    );
}

#[test]
fn oracles_are_complete() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace(
            r#"{ kind = "crash", asan = "stack-buffer-overflow" }"#,
            r#"{ kind = "crash" }"#,
        ),
        &dir,
        "a crash oracle needs",
    );
    assert_problem(
        &BUF.replace(
            r#"{ kind = "crash", asan = "stack-buffer-overflow" }"#,
            r#"{ kind = "claim" }"#,
        ),
        &dir,
        "a claim oracle needs its violation message",
    );
    assert_problem(
        &BUF.replace(
            r#"{ kind = "crash", asan = "stack-buffer-overflow" }"#,
            r#"{ kind = "crash", signal = "SIGWHAT" }"#,
        ),
        &dir,
        "unknown signal",
    );
}

#[test]
fn reference_must_have_the_bug() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    assert_problem(
        &BUF.replace("affected = ", "reference = \"lib552-asan\"\naffected = "),
        &dir,
        "reference: the bug is not in 'lib552-asan'",
    );
    assert_problem(
        &BUF.replace("affected = ", "reference = \"lib540-buf\"\naffected = "),
        &dir,
        "reference: 'lib540-buf' fixes it",
    );
    assert_problem(
        &BUF.replace("affected = ", "reference = \"5.5.2,asan\"\naffected = "),
        &dir,
        "reference: the bug is not in '5.5.2,asan'",
    );
    assert_problem(
        &BUF.replace("affected = ", "reference = \"5.4.0,only-BUF\"\naffected = "),
        &dir,
        "reference: '5.4.0,only-BUF': a preset, or a version and modifiers",
    );
    assert_problem(
        &BUF.replace("affected = ", "reference = \"5.4.0,tls13\"\naffected = "),
        &dir,
        "reference: 'tls13': not a modifier of lib",
    );
}

#[test]
fn reference_and_check_builds_in_the_comma_form() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let ctx = context();
    let catalogue = parse(
        &BUF.replace(
            "affected = ",
            "reference = \"5.4.0,asan\"\ncheck = [\"5.1.0,no-postauth\"]\naffected = ",
        ),
        &dir,
    )
    .unwrap();
    let entry = catalogue.entry("CVE-2022-39173").unwrap();
    assert_eq!(
        catalogue.reference_preset("CVE-2022-39173", entry, &ctx),
        Ok("5.4.0,asan".into())
    );
    // the CI checks named builds by their names (slugs)
    let checks = catalogue.check_presets(&ctx);
    assert!(checks.contains_key("lib510-no-postauth"), "{checks:?}");
    assert_eq!(
        catalogue.validation_set("lib510-no-postauth", &ctx),
        vec![
            "lib510-no-postauth-fix-all".to_string(),
            "lib510-no-postauth-only-CVE-2022-39173".to_string()
        ]
    );
    // `<ID>` starts from the reference build
    let single = catalogue.derive("CVE-2022-39173", &ctx).unwrap().unwrap();
    assert_eq!(single.derived.base, "lib540-asan");
}

#[test]
fn patch_files_are_inside_the_vendor_directory() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    for outside in [
        "../outside.patch",
        "/etc/passwd",
        "patches/../../x.patch",
        "",
    ] {
        let content = BUF.replace("patches/fix-buf.patch", outside);
        let problems = parse(&content, &dir).map_or_else(|e| e.problems, |_| vec![]);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("a path inside the vendor directory")),
            "{outside:?}: {problems:?}"
        );
    }
    assert!(is_inside("patches/fix-buf.patch") && is_inside("fix.patch"));
}

#[test]
fn ids_and_aliases_name_one_bug_each() {
    let dir = vendor_dir(&["fix-buf.patch", "fix-heap.patch"]);
    assert_problem(
        &format!(
            "{BUF}{}",
            HEAP.replace("alias = \"HEAP\"", "alias = \"buf\"")
        ),
        &dir,
        "'buf' also names CVE-2022-39173",
    );
    assert_problem(
        &BUF.replace("alias = \"BUF\"", "alias = \"B,UF\""),
        &dir,
        "invalid alias 'B,UF'",
    );
}

#[test]
fn preset_fixes_are_known_and_patchable() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    // lib540-buf fixes CVE-2022-39173: with the patch range moved away, 5.4.0 has no patch
    assert_problem(
        &BUF.replace(">= 5.0.0, < 5.5.1", ">= 5.0.0, < 5.4.0"),
        &dir,
        "fix 'CVE-2022-39173', which has no patch for version 5.4.0",
    );
    let other = BUF.replace("[CVE-2022-39173", "[CVE-2022-39999");
    assert_problem(&other, &dir, "fix 'CVE-2022-39173' is not an entry");
}

#[test]
fn what_the_builds_and_the_test_cannot_apply_yet_is_refused() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    // a bug of the harness keyed by tlspuffin commits, with a harness patch
    let harness = BUF
        .replace(
            "affected = \"< 5.5.1\"",
            "bug_in_harness = true\naffected_commits = \"not containing 0123abc\"",
        )
        .replace(
            "versions = \">= 5.0.0, < 5.5.1\"",
            "target = \"harness\"\ncommits = \"not containing 0123abc\"",
        );
    assert_problem(
        &harness,
        &dir,
        "harness patches (target = \"harness\") are not supported yet",
    );
    // a bug of the harness keyed by library versions is fine
    let by_versions = BUF.replace(
        "affected = \"< 5.5.1\"",
        "affected = \"< 5.5.1\"\nbug_in_harness = true",
    );
    assert!(
        parse(&by_versions, &dir)
            .unwrap()
            .entry("CVE-2022-39173")
            .unwrap()
            .bug_in_harness
    );
}

#[test]
fn a_bug_of_past_tlspuffin_commits_is_never_in_a_build() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    // a bug of the harness of the commits before 0123abc (no patch, no witness), next to BUF (the
    // presets fix it)
    let past = |commits: &str, more: &str| {
        format!(
            r#"{BUF}
[HKDF]
summary = "a bug of the harness"
category = "memory"
bug_in_harness = true
affected_commits = "{commits}"
oracle = {{ kind = "crash", asan = "global-buffer-overflow" }}
no_patch = "fixed in the harness"
{more}
"#
        )
    };
    let fine = past(
        "not containing 0123abc",
        "no_witness = \"fixed in this tree\"",
    );
    let catalogue = parse(&fine, &dir).unwrap();
    let entry = catalogue.entry("HKDF").unwrap();
    assert!(entry.bug_in_harness);
    assert!(!entry.affects("5.4.0", &BTreeMap::new(), &BTreeMap::new()));

    assert_problem(
        &past("not containing 0123abc", ""),
        &dir,
        "is fixed in this tree, where no witness can show it",
    );
    assert_problem(
        &past("before 0123abc", "no_witness = \"fixed\""),
        &dir,
        "\"not containing <commit>\"",
    );
    assert_problem(
        &past(
            "not containing 0123abc",
            "no_witness = \"fixed\"\naffected = \"< 5.5.1\"",
        ),
        &dir,
        "both affected (library versions) and affected_commits",
    );
    assert_problem(
        &past("not containing 0123abc", "no_witness = \"fixed\"")
            .replace("bug_in_harness = true\n", ""),
        &dir,
        "affected_commits is for bugs of the harness",
    );
}

#[test]
fn a_patch_range_needs_a_version_of_the_presets() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    // the presets have 5.1.0, 5.4.0 and 5.5.2: 5.0.x has none
    assert_problem(
        &BUF.replace(">= 5.0.0, < 5.5.1", ">= 5.0.0, < 5.1.0"),
        &dir,
        "patch 1: no version of presets.toml is in its range (>= 5.0.0, < 5.1.0)",
    );
}

#[test]
fn ids_and_aliases_cannot_read_as_modifiers_or_catalogue_parts() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    for alias in [
        "asan",
        "ASan",
        "no-postauth",
        "postauth",
        "only-BUF",
        "fix-all",
        "fix-BUF",
    ] {
        assert_problem(
            &BUF.replace("alias = \"BUF\"", &format!("alias = \"{alias}\"")),
            &dir,
            &format!("'{alias}' would read as a modifier or a catalogue part"),
        );
    }
}

#[test]
fn a_catalogue_without_entries_still_checks_the_fix_lists() {
    let dir = vendor_dir(&[]);
    // lib540-buf fixes CVE-2022-39173, which an empty catalogue does not have
    assert_problem(
        "",
        &dir,
        "preset 'lib540-buf': fix 'CVE-2022-39173' is not an entry of the catalogue",
    );
}

#[test]
fn ids_cannot_hold_the_separator_of_derived_names() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let content = BUF
        .replace("[CVE-2022-39173]", "[\"CVE+39173\"]")
        .replace("[[CVE-2022-39173.patches]]", "[[\"CVE+39173\".patches]]");
    assert_problem(&content, &dir, "invalid id");
}

#[test]
fn find_time_needs_its_source() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let content = format!(
        "{BUF}\n[CVE-2022-39173.find]\nby_puffin = true\ntime = {{ runs = 10, found = 2, budget_s = 3600.0, cores = 1, \
         mean_s = 10.0, median_s = 10.0, commit = \"abc\", preset = \"lib540-buf\", source = \"\" }}\n"
    );
    assert_problem(&content, &dir, "find.time without source");
}

#[test]
fn builder_options_and_capabilities_are_parsed_from_the_build_files() {
    let options = parse_builder_options(
        "use_languages(C)\noption(postauth \"Build with post-auth\" ON)\n  option(foo \"x\" OFF)\n",
    );
    assert_eq!(
        options,
        BTreeMap::from([("postauth".into(), true), ("foo".into(), false)])
    );

    let capabilities = parse_capabilities(
        "declare -a CAPABILITIES=(\n    $<$<BOOL:@tls12@>:tls12>\n    $<$<BOOL:@tls13@>:tls13>\n)\n\
         declare -a INSTRUMENTATION=(\n    $<$<BOOL:@asan@>:asan>\n)\n",
    );
    assert_eq!(
        capabilities,
        BTreeSet::from(["tls12".into(), "tls13".into()])
    );
}

#[test]
fn the_vendor_catalogues_of_this_tree_are_valid() {
    for vendor in vendors() {
        if let Err(e) = Catalogue::load(&vendor) {
            panic!("{e}");
        }
    }
}

#[test]
fn build_plans_take_the_active_entries_and_the_patches_of_the_fixed_ones() {
    let dir = vendor_dir(&["fix-buf.patch", "fix-sdos.patch"]);
    std::fs::write(
        dir.0.path().join("builder.cmake"),
        "option(postauth \"Build with post-auth\" ON)\n",
    )
    .unwrap();
    let content = format!(
        "{BUF}\n[CVE-2022-38152]\nsummary = \"x\"\ncategory = \"dos\"\nno_cvss = \"test\"\naffected = \"< 5.5.0\"\n\
         requires = {{ postauth = false }}\noracle = {{ kind = \"crash\", signal = \"SIGSEGV\" }}\n\
         reference = \"lib540-nopostauth\"\n\
         [[CVE-2022-38152.patches]]\nversions = \">= 5.4.0, < 5.5.0\"\nfiles = [\"patches/fix-sdos.patch\"]\n"
    );
    let mut ctx = context();
    ctx.presets.get_mut("lib540-nopostauth").unwrap().asan = true;
    let catalogue = Catalogue::parse("lib", dir.0.path(), &content, &ctx).unwrap();

    let no_options = BTreeMap::new();
    let plan = catalogue.plan("5.4.0", &no_options, &[]).unwrap();
    assert_eq!(plan.known, vec!["CVE-2022-39173".to_string()]);
    assert!(plan.fixed.is_empty() && plan.patches.is_empty());

    let nopostauth = BTreeMap::from([("postauth".to_string(), false)]);
    let plan = catalogue
        .plan(
            "5.4.0",
            &nopostauth,
            &["CVE-2022-39173".into(), "CVE-2022-38152".into()],
        )
        .unwrap();
    assert_eq!(
        plan.known,
        vec!["CVE-2022-38152".to_string(), "CVE-2022-39173".to_string()]
    );
    assert_eq!(
        plan.fixed,
        vec!["CVE-2022-39173".to_string(), "CVE-2022-38152".to_string()]
    );
    assert_eq!(
        plan.patches,
        vec![
            dir.0.path().join("patches/fix-buf.patch"),
            dir.0.path().join("patches/fix-sdos.patch")
        ]
    );

    assert!(catalogue
        .plan("5.4.0", &no_options, &["CVE-2022-38152".into()])
        .unwrap_err()
        .contains("does not affect"));
    assert!(catalogue
        .plan("5.5.2", &no_options, &["CVE-2022-39173".into()])
        .unwrap_err()
        .contains("does not affect"));
    assert!(catalogue
        .plan("4.4.0", &no_options, &["CVE-2022-39173".into()])
        .unwrap_err()
        .contains("no patch"));
    assert!(catalogue
        .plan("5.4.0", &no_options, &["CVE-0000-0000".into()])
        .unwrap_err()
        .contains("not an entry"));
}

const HEAP: &str = r#"
[CVE-2022-42905]
alias = "HEAP"
summary = "heap over-read"
category = "memory"
cvss = { version = "3.1", score = 9.1, vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", source = "nvd" }
affected = "< 5.5.2"
oracle = { kind = "crash", asan = "heap-buffer-overflow" }

[[CVE-2022-42905.patches]]
versions = ">= 5.4.0, < 5.5.0"
files = ["patches/fix-heap.patch"]

[CVE-2024-5814]
summary = "downgrade"
category = "downgrade"
no_cvss = "test"
affected = "< 5.7.2"
oracle = { kind = "claim", violation = "Negotiated cipher is not in agent's configured ciphers list" }
no_patch = "none yet"
"#;

fn three_entries() -> (Dir, Catalogue) {
    let dir = vendor_dir(&["fix-buf.patch", "fix-heap.patch"]);
    let catalogue = parse(&format!("{BUF}{HEAP}"), &dir).unwrap();
    (dir, catalogue)
}

#[test]
fn derived_names_resolve_to_explicit_fix_lists() {
    let (_dir, catalogue) = three_entries();
    let ctx = context();
    let derive = |name: &str| catalogue.derive(name, &ctx);

    // presets and unknown names are not derived names
    assert_eq!(derive("lib540-asan"), Ok(None));
    assert_eq!(derive("nothing-fix-all"), Ok(None));

    let only = derive("lib540-asan-only-CVE-2022-39173").unwrap().unwrap();
    assert_eq!(only.derived.base, "lib540-asan");
    assert_eq!(only.derived.kind, "only");
    assert_eq!(only.fix, vec!["CVE-2022-42905".to_string()]);
    assert!(!only.force_asan);

    let fix_all = derive("lib540-asan-fix-all").unwrap().unwrap();
    assert_eq!(
        fix_all.fix,
        vec!["CVE-2022-39173".to_string(), "CVE-2022-42905".to_string()]
    );

    let fix_one = derive("lib540-fix-CVE-2022-42905").unwrap().unwrap();
    assert_eq!(fix_one.fix, vec!["CVE-2022-42905".to_string()]);
    assert_eq!(
        derive("lib540-fix-CVE-2022-42905+CVE-2022-39173")
            .unwrap()
            .unwrap()
            .fix,
        vec!["CVE-2022-39173".to_string(), "CVE-2022-42905".to_string()]
    );

    // a bug alone: its reference preset, ASan
    let single = derive("CVE-2022-42905").unwrap().unwrap();
    assert_eq!(single.derived.base, "lib540-asan");
    assert_eq!(single.fix, vec!["CVE-2022-39173".to_string()]);
    assert!(single.force_asan);

    // a preset's own fixes stay
    let buf_fixed = derive("lib540-buf-fix-all").unwrap().unwrap();
    assert_eq!(
        buf_fixed.fix,
        vec!["CVE-2022-39173".to_string(), "CVE-2022-42905".to_string()]
    );

    assert!(derive("lib540-fix-CVE-2024-5814")
        .unwrap_err()
        .contains("no patch"));
    assert!(derive("lib552-asan-only-CVE-2022-42905")
        .unwrap_err()
        .contains("does not affect"));
    assert!(derive("lib540-buf-only-CVE-2022-39173")
        .unwrap_err()
        .contains("already fixes"));
    assert!(derive("lib540-only-CVE-0000-0000")
        .unwrap_err()
        .contains("not an entry"));
}

#[test]
fn validation_sets_have_one_build_per_patchable_active_entry() {
    let (_dir, catalogue) = three_entries();
    let ctx = context();
    assert_eq!(
        catalogue.validation_set("lib540-asan", &ctx),
        vec![
            "lib540-asan-fix-all".to_string(),
            "lib540-asan-only-CVE-2022-39173".to_string(),
            "lib540-asan-only-CVE-2022-42905".to_string()
        ]
    );
    // 5.1.0: only BUF has a patch there
    assert_eq!(
        catalogue.validation_set("lib510-asan", &ctx),
        vec![
            "lib510-asan-fix-all".to_string(),
            "lib510-asan-only-CVE-2022-39173".to_string()
        ]
    );
}

#[test]
fn check_presets_cover_every_patch_range_and_unpatched_entries() {
    let (_dir, catalogue) = three_entries();
    let checks = catalogue.check_presets(&context());
    assert_eq!(
        checks,
        BTreeMap::from([
            (
                "lib540-asan".to_string(),
                vec!["CVE-2022-39173".to_string(), "CVE-2022-42905".to_string()]
            ),
            ("lib552-asan".to_string(), vec!["CVE-2024-5814".to_string()]),
        ])
    );
}

#[test]
fn library_states_record_every_entry() {
    let (_dir, catalogue) = three_entries();
    let plan = catalogue
        .plan("5.4.0", &BTreeMap::new(), &["CVE-2022-42905".into()])
        .unwrap();
    let state = catalogue.library_state("5.4.0", &plan);

    assert_eq!(state.status("CVE-2022-39173"), Some(Status::Active));
    assert_eq!(state.status("CVE-2022-42905"), Some(Status::Fixed));
    assert_eq!(state.status("CVE-2024-5814"), Some(Status::Active));
    assert!(state.patchable("CVE-2022-39173"));
    assert!(!state.patchable("CVE-2024-5814"));
    assert_eq!(state.catalogue, catalogue.hash);
    assert_eq!(
        state.entries["CVE-2022-42905"].patches,
        vec![catalogue
            .patch_hash("patches/fix-heap.patch")
            .unwrap()
            .to_string()]
    );

    let reread = LibraryState::from_toml(&state.to_toml()).unwrap();
    assert_eq!(reread, state);

    let state = catalogue.library_state(
        "5.5.2",
        &catalogue.plan("5.5.2", &BTreeMap::new(), &[]).unwrap(),
    );
    assert_eq!(state.status("CVE-2022-39173"), Some(Status::Unaffected));
    assert_eq!(state.status("CVE-2022-42905"), Some(Status::Unaffected));
}

#[test]
fn every_vendor_with_entries_has_a_harness_whose_crate_checks_its_witnesses() {
    // the catalogue test of a protocol crate (e.g. tlspuffin/tests/catalogue.rs) checks the vendors
    // whose C harness is in `<protocol>puffin/harness/<vendor>`: entries of any other vendor
    // would have no witness check
    for vendor in vendors() {
        let catalogue = Catalogue::load(&vendor).unwrap();
        let harnessed = std::fs::read_dir(crate::puffin::project_dir())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .any(|e| e.path().join("harness").join(&vendor).is_dir());
        assert!(
            catalogue.entries.is_empty() || harnessed,
            "{vendor} has catalogue entries but no C harness in a protocol crate: no catalogue test checks their \
             witnesses"
        );
    }
}

#[test]
fn build_hashes_only_follow_what_builds_take_from_an_entry() {
    let dir = vendor_dir(&["fix-buf.patch"]);
    let before = parse(BUF, &dir).unwrap();
    let id = "CVE-2022-39173";

    // a new summary or oracle: the entry changes, its builds do not
    let described = parse(
        &BUF.replace("RefineSuites\"", "RefineSuites, described again\"")
            .replace(
                "stack-buffer-overflow\" }",
                "stack-buffer-overflow\", signal = \"SIGABRT\" }",
            ),
        &dir,
    )
    .unwrap();
    assert_ne!(before.entry_hash(id), described.entry_hash(id));
    assert_eq!(before.build_hash(id), described.build_hash(id));

    // another affected range or another patch: the builds change
    let narrowed = parse(
        &BUF.replace("affected = \"< 5.5.1\"", "affected = \"< 5.5.0\""),
        &dir,
    )
    .unwrap();
    assert_ne!(before.build_hash(id), narrowed.build_hash(id));
    std::fs::write(
        dir.0.path().join("patches/fix-buf.patch"),
        "another patch\n",
    )
    .unwrap();
    let patched = parse(BUF, &dir).unwrap();
    assert_ne!(before.build_hash(id), patched.build_hash(id));

    // what a build records
    let plan = before.plan("5.4.0", &BTreeMap::new(), &[]).unwrap();
    assert_eq!(
        before.library_state("5.4.0", &plan).entries[id].hash,
        before.build_hash(id).unwrap()
    );
}
