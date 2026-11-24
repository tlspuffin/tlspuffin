//! sshpuffin/build.rs
//!
//! 1. Generates Rust FFI bindings from `sshpuffin/include/puffin/ssh.h` (the harness ABI header).
//!    This is bindgen *parity* with `tlspuffin/build.rs` — the same mechanism, not a new one.
//! 2. Finds every libssh and wolfSSH instance in the vendor directory and compiles the C harness
//!    (`sshpuffin/harness/{libssh,wolfssh}/`) against each, bundling them via puffin-build
//!    (`harness::bundle`).
//! 3. Links the `atexit` shim of the profile runtime when a PUT's library has gcov or llvm_cov.
//!
//! A PUT has the instrumentation of its vendor build (ASan, gcov, llvm_cov), and puffin-build adds
//! the link flags it needs, as for tlspuffin. The vendors this script builds when the vendor
//! directory has none follow the vendors present (`fallback`).

use std::path::PathBuf;

use puffin_build::{catalogue, harness, library, vendor_dir};

/// libssh preset built when no libssh vendor is present (e.g. a fresh CI
/// checkout): 0.11.4, the version the evaluation, the differential corpus and the
/// PUT-gated tests (`has_put = "libssh0114"`) use. It used to be 0.10.4, which
/// silently compiled those tests out of the CI unit-test job.
const LIBSSH_PRESET: &str = "libssh0114";

fn main() {
    // Cargo caches a build script's output and only re-runs it when one of its declared inputs
    // changes. This script reads two environment variables — `VENDOR_DIR` (via
    // `vendor_dir::from_env()`, which decides WHICH vendor tree the harness compiles and links
    // against) and `SSHPUFFIN_ONLY_VENDOR` — and without these declarations a change to either is
    // invisible: cargo replays the cached `rustc-link-search` / `rustc-link-lib` directives from
    // the previous run and silently links the OLD vendor.
    //
    // That is not hypothetical. Building an instrumented wolfSSH into a separate
    // `CARGO_TARGET_DIR` with `VENDOR_DIR` pointing at a copied tree produced a binary that linked
    // the DEFAULT vendor instead — the instrumented archive was correct and present, and the
    // binary simply never saw it. The only way out was `rm -rf target/release/build/sshpuffin-*`.
    // The same staleness made a vendor build operate on the default tree while appearing to work
    // inside the copy.
    println!("cargo:rerun-if-env-changed=VENDOR_DIR");
    println!("cargo:rerun-if-env-changed=SSHPUFFIN_ONLY_VENDOR");
    // `sort_by_preference` reads each vendor's `[library] latest`.
    for vendor in ["libssh", "wolfssh"] {
        let presets = catalogue::vendors_dir().join(vendor).join("presets.toml");
        println!("cargo:rerun-if-changed={}", presets.display());
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let project_dir = puffin_build::puffin::project_dir();

    // ── 1. Generate Rust FFI bindings from ssh.h ──────────────────────────

    let bindings_path = PathBuf::from(&out_dir).join("bindings.rs");

    bindgen::Builder::default()
        .ctypes_prefix("::libc")
        // puffin/include – needed for puffin.h (AGENT, RESULT, …)
        .clang_arg(format!("-I{}", project_dir.join("puffin/include").display()))
        // sshpuffin/include – needed for ssh.h (SSH_AGENT_DESCRIPTOR, …)
        .clang_arg(format!(
            "-I{}",
            project_dir.join("sshpuffin/include").display()
        ))
        // Only generate bindings for types declared in our own headers.
        .allowlist_file(r".*/puffin/[^/]+\.h")
        .allowlist_recursively(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .rustified_enum(".*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_eq(true)
        .derive_default(true)
        // As tlspuffin: the vtables hold function pointers, whose comparison is unreliable.
        .derive_partialeq(false)
        .no_copy("^AGENT_TYPE$")
        .header(
            project_dir
                .join("sshpuffin/include/puffin/ssh.h")
                .to_string_lossy()
                .to_string(),
        )
        .generate()
        .expect("Unable to generate Rust FFI bindings for sshpuffin harness")
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings");

    println!(
        "cargo:rustc-env=RUST_BINDINGS_FILE={}",
        bindings_path.display()
    );

    // ── 2. Compile one C harness object per libssh in the vendor dir ──────

    let out_bundle = PathBuf::from(&out_dir).join("harness_bundle");

    // The registry's default PUT is the first one bundled, and the vendor directory lists its
    // libraries in no particular order: sort each vendor's builds (libssh before wolfSSH).
    let mut libssh_vendors = ensure_libssh_vendors();
    sort_by_preference("libssh", &mut libssh_vendors);

    // wolfSSH vendors are discovered from vendor/ (pre-built), or built from the preset.
    let mut wolfssh_vendors = ensure_wolfssh_vendors(&libssh_vendors);
    sort_by_preference("wolfssh", &mut wolfssh_vendors);

    // `has_libssh` / `has_wolfssh`: the binary has a PUT of that vendor, whatever its version and
    // instrumentation (`has_put` names one build, `libssh0114`, and not `libssh0122-asan`). The PUT
    // tests are gated on these and run on every PUT of the vendor (`put_registry::put_names`).
    println!("cargo:rustc-check-cfg=cfg(has_libssh, has_wolfssh)");
    if !libssh_vendors.is_empty() {
        println!("cargo:rustc-cfg=has_libssh");
    }
    if !wolfssh_vendors.is_empty() {
        println!("cargo:rustc-cfg=has_wolfssh");
    }

    let puts: Vec<harness::Put> = libssh_vendors
        .iter()
        .chain(wolfssh_vendors.iter())
        .filter_map(|lib| build_harness(lib.clone(), &out_bundle))
        .collect();

    let bundle = harness::bundle(puts).build(&out_bundle);
    bundle.print_cargo_metadata();

    // libssh static archives depend on OpenSSL's libcrypto and zlib.
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=z");
    // wolfSSL (bundled in the wolfssh vendor) needs libm and libpthread.
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");

    // ── 3. The atexit shim of the profile runtime ─────────────────────────
    //
    // `bundle.print_cargo_metadata()` above adds the ASan and coverage link flags of each PUT's
    // library. The profile runtime of gcov and llvm_cov (libclang_rt.profile) also references
    // atexit, which glibc keeps in libc_nonshared.a — suppressed by rust's -nodefaultlibs. When a
    // PUT's library has either, compile a shim that provides atexit (via __cxa_atexit in libc.so)
    // and link it, so the build resolves instead of failing with "undefined reference to atexit".
    if libssh_vendors
        .iter()
        .chain(wolfssh_vendors.iter())
        .any(|lib| has_instrumentation(lib, "gcov") || has_instrumentation(lib, "llvm_cov"))
    {
        let shim_src = project_dir.join("sshpuffin/harness/gcov_atexit_shim.c");
        let shim_obj = PathBuf::from(&out_dir).join("gcov_atexit_shim.o");
        let status = std::process::Command::new("clang")
            .args(["-c", "-fPIC", "-o"])
            .arg(&shim_obj)
            .arg(&shim_src)
            .status()
            .expect("failed to compile gcov atexit shim");
        assert!(status.success(), "gcov atexit shim compile failed");
        println!("cargo:rustc-link-arg={}", shim_obj.display());
    }
}

const WOLFSSH_PRESET: &str = "wolfssh150";

/// Ensure at least one wolfSSH vendor is available, building it from the
/// puffin-build `wolfssh150` preset (which builds wolfSSL --enable-ssh then
/// wolfSSH) if none is present. Mirrors `ensure_libssh_vendors`. The PUT name is
/// `wolfssh150` (version-carrying, like `libssh0114`); the vendor identity stays
/// `wolfssh` (the `vendors/wolfssh/` dir and `metadata().vendor` below).
///
/// The fallback has the ASan and coverage instrumentation of the libssh vendors found (`libssh`):
/// `wolfssh150-asan` next to `libssh0114-asan`, for instance (see `fallback`).
fn ensure_wolfssh_vendors(libssh: &[library::Library]) -> Vec<library::Library> {
    // Explicit single-vendor selection for reproducible campaign builds. When
    // `SSHPUFFIN_ONLY_VENDOR=libssh`, omit the wolfSSH PUT entirely. This is
    // AUTHORITATIVE and checked before anything else: it is robust where moving
    // vendor dirs is not, because the fallback build (`fallback`) resolves
    // the preset from a compiled-in source and would otherwise REBUILD wolfSSH
    // into vendor/ even with both the cache dir and the preset dir moved away.
    // (The Rust PUT registry is bundle-driven, so a build with no wolfSSH simply
    // yields a libssh-only binary.)
    if std::env::var("SSHPUFFIN_ONLY_VENDOR").ok().as_deref() == Some("libssh") {
        println!("cargo:warning=SSHPUFFIN_ONLY_VENDOR=libssh: building without the wolfSSH PUT");
        return vec![];
    }
    let vendor = vendor_dir::from_env();
    let is_wolfssh = |lib: &library::Library| {
        lib.metadata().vendor == "wolfssh"
            && lib.path().join("include/wolfssh/ssh.h").exists()
            && !lib.link_libraries().is_empty()
            // Require the session-id claim instrumentation: the cross-vendor s2c
            // decryption recipe sources the exchange hash H from a claim
            // (fn_claim_exchange_hash), so a wolfSSH vendor WITHOUT the `claimer`
            // marker would silently make transcript
            // evaluation disappear. Reject such a vendor here so build.rs falls
            // through to the preset builder (which injects the accessor) instead.
            && lib
                .metadata()
                .instrumentation
                .contains(&String::from("claimer"))
    };

    let existing: Vec<library::Library> =
        vendor.all().into_iter().filter(|l| is_wolfssh(l)).collect();
    if !existing.is_empty() {
        return existing;
    }

    let (config, name) = match fallback("wolfssh", WOLFSSH_PRESET, libssh) {
        Ok(build) => build,
        Err(e) => {
            // No preset and no pre-built vendor: nothing to build (optional PUT).
            println!("cargo:warning=no wolfSSH vendor and no build of {WOLFSSH_PRESET}: {e}");
            return vec![];
        }
    };

    if let Some(Ok(_)) = vendor
        .library_dir(&name)
        .ok()
        .map(|dir| dir.make(&config, false))
    {
        // built successfully
    } else {
        // wolfSSH is an optional second PUT; if its build fails, continue with
        // libssh only rather than breaking the whole sshpuffin build.
        println!("cargo:warning=wolfSSH vendor '{name}' unavailable; building without it");
        return vec![];
    }

    vendor.all().into_iter().filter(|l| is_wolfssh(l)).collect()
}

/// Sorts the builds of `vendor` by preference, the first one being the default PUT when it is
/// the first vendor: the latest release (`[library] latest` in the vendor's presets.toml) first,
/// then newer versions before older ones; for one version, the fuzzing build (no instrumentation
/// besides `sancov` and the claims) before the `asan`, `gcov` and `llvm_cov` ones; then by name.
fn sort_by_preference(vendor: &str, libs: &mut [library::Library]) {
    let latest = library::presets::load(vendor)
        .ok()
        .and_then(|presets| presets.latest);
    libs.sort_by_key(|lib| {
        let metadata = lib.metadata();
        let instrumented = metadata
            .instrumentation
            .iter()
            .any(|i| !matches!(i.as_str(), "sancov" | "claimer"));
        (
            latest.as_deref() != Some(metadata.version.as_str()),
            std::cmp::Reverse(metadata.version.parse::<catalogue::Version>().ok()),
            instrumented,
            lib.name(),
        )
    });
}

fn ensure_libssh_vendors() -> Vec<library::Library> {
    // Explicit single-vendor selection (see ensure_wolfssh_vendors). When
    // `SSHPUFFIN_ONLY_VENDOR=wolfssh`, omit the libssh PUT entirely — authoritative
    // and checked first, so it overrides even a libssh vendor still present in the
    // cache. libssh is otherwise the default primary PUT, but the bundle-driven
    // Rust registry adapts to a wolfSSH-only binary.
    if std::env::var("SSHPUFFIN_ONLY_VENDOR").ok().as_deref() == Some("wolfssh") {
        println!("cargo:warning=SSHPUFFIN_ONLY_VENDOR=wolfssh: building without the libssh PUT");
        return vec![];
    }
    let vendor = vendor_dir::from_env();
    let existing: Vec<library::Library> = vendor
        .all()
        .into_iter()
        .filter(|lib| lib.metadata().vendor == "libssh")
        .filter(|lib| {
            lib.path().join("include/libssh/libssh.h").exists() && !lib.link_libraries().is_empty()
        })
        .collect();

    // Unlike a wolfSSH vendor, a libssh vendor without the claims is kept: rebuilding it from its
    // preset would replace a directory the user built. Say so now rather than at the first seed
    // that needs its session id.
    for lib in &existing {
        if !lib
            .metadata()
            .instrumentation
            .contains(&String::from("claimer"))
        {
            println!(
                "cargo:warning=libssh vendor '{}' has no `claimer` instrumentation: its session \
                 id is unavailable, so the seeds cannot decrypt its replies. Rebuild it with \
                 `just mk_vendor`",
                lib.name()
            );
        }
    }

    if !existing.is_empty() {
        return existing;
    }

    // libssh is OPTIONAL: if the tree has been deliberately reduced to a single
    // other vendor (a wolfSSH vendor is present but no libssh — the
    // "mv the others out before building" workflow used to produce a
    // wolfSSH-only binary), respect that instead of force-building libssh back
    // from the preset. The Rust PUT registry is driven entirely by the harness
    // bundle (RUST_PUTS_BUNDLE_FILE), so a bundle without libssh simply yields a
    // binary whose only PUT is wolfSSH — no Rust symbol pins libssh. This
    // mirrors how `ensure_wolfssh_vendors` already treats wolfSSH as optional.
    // We ONLY fall through to the build-from-preset default when the tree is
    // genuinely empty (a fresh checkout), preserving the default DY-fuzzing UX.
    let wolfssh_present = vendor.all().into_iter().any(|lib| {
        lib.metadata().vendor == "wolfssh"
            && lib.path().join("include/wolfssh/ssh.h").exists()
            && !lib.link_libraries().is_empty()
    });
    if wolfssh_present {
        println!(
            "cargo:warning=no libssh vendor found but a wolfSSH vendor is present; \
             building a wolfSSH-only sshpuffin (libssh PUT omitted)"
        );
        return vec![];
    }

    // No SSH vendor is present, so the fallback has no instrumentation to follow.
    let (config, name) = fallback("libssh", LIBSSH_PRESET, &[])
        .unwrap_or_else(|e| panic!("no build of libssh:{LIBSSH_PRESET}: {e}"));

    vendor
        .library_dir(&name)
        .and_then(|dir| dir.make(&config, false))
        .unwrap_or_else(|e| panic!("failed to build vendored libssh '{name}': {e}"));

    vendor
        .all()
        .into_iter()
        .filter(|lib| lib.name() == name)
        .filter(|lib| {
            lib.path().join("include/libssh/libssh.h").exists() && !lib.link_libraries().is_empty()
        })
        .collect()
}

fn has_instrumentation(lib: &library::Library, kind: &str) -> bool {
    lib.metadata().instrumentation.iter().any(|i| i == kind)
}

/// The build of `preset` that this script makes when the vendor directory has no `vendor` library,
/// and its name: the preset with the ASan and coverage instrumentation of the SSH vendors present,
/// `present`, and without sancov when the `sancov` feature is off. The name says it, as `mk_vendor
/// make <vendor>:<name>` names it (`wolfssh150-asan`; `wolfssh150-no-sancov-gcov`: a gcov build has
/// no sancov).
fn fallback(
    vendor: &str,
    preset: &str,
    present: &[library::Library],
) -> Result<(library::Config, String), String> {
    let mut name = preset.to_string();
    if !cfg!(feature = "sancov") {
        name.push_str("-no-sancov");
    }
    for kind in ["asan", "gcov", "llvm_cov"] {
        if present.iter().any(|lib| has_instrumentation(lib, kind)) {
            name.push('-');
            name.push_str(kind);
        }
    }
    library::Config::resolve_named(vendor, &name)
}

fn build_harness(lib: library::Library, out_bundle: &std::path::Path) -> Option<harness::Put> {
    let out_dir = out_bundle.join(format!("harness_{}", lib.id()));
    harness::Harness::harness_for("ssh", lib)
        .map(|h| h.wrap(out_dir).expect("failed to compile libssh C harness"))
}
