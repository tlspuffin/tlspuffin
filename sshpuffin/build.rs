//! sshpuffin/build.rs
//!
//! 1. Generates Rust FFI bindings from `sshpuffin/include/puffin/ssh.h`.
//! 2. Finds every libssh instance in the vendor directory and compiles the C harness
//!    (`sshpuffin/harness/libssh/`) against it via puffin-build.
//! 3. Compiles `harness/libssh/crypto/crypto.c` as a separate static library so that the puffin_*
//!    FFI functions are available to Rust without being stripped by the PUT partial-relocation
//!    step.
//! 4. Emits ASAN / coverage linker flags when the corresponding features are active.

use std::path::PathBuf;

use puffin_build::{harness, library, vendor_dir};

const LIBSSH_PRESET: &str = "libssh0104";

fn main() {
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

    let libssh_vendors = ensure_libssh_vendors();

    // ── 2b. Compile crypto.c FIRST so it appears before puts-bundle in link order.
    // The puffin_* functions must be globally visible to Rust FFI but the PUT
    // partial-relocation step strips all symbols except REGISTER.  We compile
    // crypto.c independently so its symbols are never stripped.
    // IMPORTANT: puffin_crypto references libssh symbols (ssh_pki_import_privkey_base64
    // etc.) which are defined in puts-bundle. The linker resolves symbols left-to-right
    // for static libs, so puffin_crypto MUST come BEFORE puts-bundle for forward refs
    // to work. Actually for Linux, the order is: library that NEEDS symbols first,
    // then the library that PROVIDES symbols. So puffin_crypto (needs libssh) comes
    // first, then puts-bundle (provides libssh) comes after. Wait, that's backwards:
    // in GNU ld, libraries are processed left-to-right. When processing puffin_crypto.a,
    // it picks up symbols that puffin_crypto references as "needed". Then when
    // puts-bundle is processed, it resolves those needs.
    // Actually, GNU ld processes: for each .a, it includes .o files that satisfy
    // currently-unresolved symbols. So puffin_crypto must come AFTER puts-bundle
    // for its own symbols to be resolved... but then Rust code calling puffin_* finds
    // them in puffin_crypto which is after.
    // The correct order for GNU ld: puts-bundle, then puffin_crypto.
    // But we need puffin_crypto symbols to be visible to Rust. They should be in any
    // position since Rust code is the "application" and its undefined refs will be
    // resolved by static libs in order. As long as puffin_crypto comes AFTER puts-bundle
    // (so that puffin_crypto's refs to libssh can be resolved), it should work.
    // Let us move crypto building AFTER the bundle printing.

    // wolfSSH vendors are discovered from vendor/ (pre-built); no preset build.
    let wolfssh_vendors = ensure_wolfssh_vendors();

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

    // ── 3. Sanitizer / coverage linker flags ──────────────────────────────

    if cfg!(feature = "asan") {
        let runtime_dir = puffin_build::utils::clang::runtime_dir();
        println!("cargo:rustc-link-arg=-Wl,-rpath,{runtime_dir}");
        println!("cargo:rustc-link-arg=-fsanitize=address");

        if cfg!(target_os = "macos") {
            println!("cargo:rustc-link-search=native={runtime_dir}");
            println!("cargo:rustc-link-lib=dylib=clang_rt.asan_osx_dynamic");
        } else {
            println!("cargo:rustc-link-arg=-shared-libasan");
        }
    }

    if cfg!(feature = "gcov") {
        println!("cargo:rustc-link-arg=-ftest-coverage");
        println!("cargo:rustc-link-arg=-fprofile-arcs");
        // The gcov/profile runtime references atexit, which glibc keeps in
        // libc_nonshared.a — suppressed by rust's -nodefaultlibs. Compile a shim
        // that provides atexit (via __cxa_atexit in libc.so) and link it, so the
        // gcov build resolves instead of failing with "undefined reference to
        // atexit".
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

    if cfg!(feature = "llvm_cov") {
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-fcoverage-mapping");
    }
}

const WOLFSSH_PRESET: &str = "wolfssh";

/// Ensure at least one wolfSSH vendor is available, building it from the
/// puffin-build `wolfssh` preset (which builds wolfSSL --enable-ssh then
/// wolfSSH) if none is present. Mirrors `ensure_libssh_vendors`.
fn ensure_wolfssh_vendors() -> Vec<library::Library> {
    // Explicit single-vendor selection for reproducible campaign builds. When
    // `SSHPUFFIN_ONLY_VENDOR=libssh`, omit the wolfSSH PUT entirely. This is
    // AUTHORITATIVE and checked before anything else: it is robust where moving
    // vendor dirs is not, because `library::Config::preset("wolfssh")` resolves
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
    };

    let existing: Vec<library::Library> =
        vendor.all().into_iter().filter(|l| is_wolfssh(l)).collect();
    if !existing.is_empty() {
        return existing;
    }

    let mut config = match library::Config::preset("wolfssh", WOLFSSH_PRESET) {
        Some(c) => c,
        None => {
            // No preset and no pre-built vendor: nothing to build (optional PUT).
            return vec![];
        }
    };
    apply_instrumentation_options(&mut config);

    let name = if cfg!(feature = "asan") {
        format!("{WOLFSSH_PRESET}-asan")
    } else {
        WOLFSSH_PRESET.to_string()
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

    let mut config = library::Config::preset("libssh", LIBSSH_PRESET)
        .unwrap_or_else(|| panic!("missing preset libssh:{LIBSSH_PRESET}"));
    apply_instrumentation_options(&mut config);

    let name = if cfg!(feature = "asan") {
        format!("{LIBSSH_PRESET}-asan")
    } else {
        LIBSSH_PRESET.to_string()
    };

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

fn apply_instrumentation_options(config: &mut library::Config) {
    config.option("sancov", cfg!(feature = "sancov"));
    config.option("asan", cfg!(feature = "asan"));
    config.option("gcov", cfg!(feature = "gcov"));
    config.option("llvm_cov", cfg!(feature = "llvm_cov"));
}

fn build_harness(lib: library::Library, out_bundle: &std::path::Path) -> Option<harness::Put> {
    let out_dir = out_bundle.join(format!("harness_{}", lib.id()));
    harness::Harness::harness_for("ssh", lib, harness::Kind::C)
        .map(|h| h.wrap(out_dir).expect("failed to compile libssh C harness"))
}
