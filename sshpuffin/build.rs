//! sshpuffin/build.rs
//!
//! 1. Generates Rust FFI bindings from `sshpuffin/include/puffin/ssh.h` (the harness ABI header).
//!    This is bindgen *parity* with `tlspuffin/build.rs` — the same mechanism, not a new one.
//! 2. Finds every libssh instance in the vendor directory and compiles the C harness
//!    (`sshpuffin/harness/libssh/`) against each, bundling them via puffin-build
//!    (`harness::bundle`).
//! 3. Emits ASAN / coverage linker flags when the corresponding features are active.

use std::path::PathBuf;

use puffin_build::{harness, library, vendor_dir};

/// libssh preset built when no libssh vendor is present (e.g. a fresh CI
/// checkout): 0.11.4, the version the evaluation, the differential corpus and the
/// PUT-gated tests (`has_put = "libssh0114"`) use. It used to be 0.10.4, which
/// silently compiled those tests out of the CI unit-test job.
const LIBSSH_PRESET: &str = "libssh0114";

fn main() {
    // Cargo caches a build script's output and only re-runs it when one of its declared inputs
    // changes. This script reads the environment variable `VENDOR_DIR` (via
    // `vendor_dir::from_env()`, which decides WHICH vendor tree the harness compiles and links
    // against), and without this declaration a change to it is invisible: cargo replays the
    // cached `rustc-link-search` / `rustc-link-lib` directives from the previous run and silently
    // links the OLD vendor.
    //
    // That is not hypothetical. Building an instrumented wolfSSH into a separate
    // `CARGO_TARGET_DIR` with `VENDOR_DIR` pointing at a copied tree produced a binary that linked
    // the DEFAULT vendor instead — the instrumented archive was correct and present, and the
    // binary simply never saw it. The only way out was `rm -rf target/release/build/sshpuffin-*`.
    // The same staleness made a vendor build operate on the default tree while appearing to work
    // inside the copy.
    println!("cargo:rerun-if-env-changed=VENDOR_DIR");

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

    let libssh_vendors = ensure_libssh_vendors();

    let puts: Vec<harness::Put> = libssh_vendors
        .iter()
        .filter_map(|lib| build_harness(lib.clone(), &out_bundle))
        .collect();

    let bundle = harness::bundle(puts).build(&out_bundle);
    bundle.print_cargo_metadata();

    // libssh static archives depend on OpenSSL's libcrypto and zlib.
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=z");

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

fn ensure_libssh_vendors() -> Vec<library::Library> {
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
    harness::Harness::harness_for("ssh", lib)
        .map(|h| h.wrap(out_dir).expect("failed to compile libssh C harness"))
}
