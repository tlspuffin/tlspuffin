use std::process::Command;

use puffin_build::vendor;

#[cfg(any(
    all(feature = "openssl-binding", feature = "wolfssl-binding"),
    all(feature = "openssl-binding", feature = "boringssl-binding"),
    all(feature = "wolfssl-binding", feature = "boringssl-binding")
))]
compile_error!("Selecting multiple vendored PUT is currently not supported: openssl/libressl, wolfssl and boringssl feature flags are mutually exclusive.");

fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_instr, values(\"sancov\", \"asan\", \"gcov\", \"llvm_cov\", \"claimer\"))");

    if let Ok(boringssl_root) = std::env::var("DEP_BORING_ROOT") {
        configure_rust_put(boringssl_root);
    }

    if let Ok(openssl_root) = std::env::var("DEP_OPENSSL_ROOT") {
        configure_rust_put(openssl_root);
    }

    if let Ok(wolfssl_root) = std::env::var("DEP_WOLFSSL_ROOT") {
        configure_rust_put(wolfssl_root);
    }
}

fn configure_rust_put(vendor_root: impl AsRef<std::path::Path>) {
    let vendor_name = vendor_root
        .as_ref()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let library = vendor::dir()
        .lock(vendor_name)
        .expect("failed to get vendor directory")
        .library()
        .expect("failed to get vendor library")
        .unwrap();

    for instrumentation_type in library.instrumentation.iter() {
        println!("cargo:rustc-cfg=has_instr=\"{instrumentation_type}\"");
    }

    if library.instrumentation.iter().any(|i| i == "asan") {
        // NOTE adding compiler-rt to rpath for libasan is not straightforward
        //
        //     Unfortunately, passing `-frtlib-add-rpath` to clang doesn't add
        //     the correct rpath on linux platforms. Instead, we find the folder
        //     containing the compiler-rt runtime and add it to rpath ourselves.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", runtime_dir());
        println!("cargo:rustc-link-arg=-fsanitize=address");
        println!("cargo:rustc-link-arg=-shared-libasan");
    }

    if library.instrumentation.iter().any(|i| i == "gcov") {
        println!("cargo:rustc-link-arg=-ftest-coverage");
        println!("cargo:rustc-link-arg=-fprofile-arcs");
    }

    if library.instrumentation.iter().any(|i| i == "llvm_cov") {
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-fcoverage-mapping");
    }
}

fn runtime_dir() -> String {
    // NOTE the current process for finding the runtime-dir might be incomplete
    //
    //     We try the following in order:
    //       - `clang --print-runtime-dir` (clang >= 13)
    //       - `clang --print-resource-dir`/lib/<os>
    //       - panic
    //
    //     Note that extracting the directory path directly from the result of
    //     `--print-file-name=libclang_rt.asan-<arch>.<dylib_suffix>` would be
    //     an alternative solution but it was broken for a long time on Apple
    //     clang.
    //
    //     - see https://github.com/llvm/llvm-project/commit/aafc3f7be804d117a632365489a18c3e484a3931
    let output = Command::new("clang")
        .args(["--print-runtime-dir"])
        .output()
        .expect("failed to get runtime dir from `clang --print-runtime-dir`. Is clang in PATH?");

    let clang_runtime_dir = output
        .status
        .success()
        .then(|| std::str::from_utf8(&output.stdout).unwrap().trim())
        .unwrap_or("");

    if clang_runtime_dir.is_empty() {
        return runtime_dir_fallback();
    }

    clang_runtime_dir.to_string()
}

fn runtime_dir_fallback() -> String {
    let output = Command::new("clang")
        .args(["--print-resource-dir"])
        .output()
        .expect("failed to get resource dir from `clang --print-resource-dir`. Is clang in PATH?");

    let clang_resource_dir = output
        .status
        .success()
        .then(|| std::str::from_utf8(&output.stdout).unwrap().trim())
        .expect("failed to get resource dir from `clang --print-resource-dir`");

    let clang_sysname = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        _ => panic!("cannot get compiler runtime dir: unsupported os"),
    };

    let runtime_dir = format!("{}/lib/{}/", clang_resource_dir, clang_sysname);
    if !std::path::Path::new(&runtime_dir).exists() {
        panic!("failed to find clang runtime dir");
    }

    runtime_dir
}
