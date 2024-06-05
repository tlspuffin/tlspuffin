use std::process::Command;

#[cfg(any(
    all(feature = "openssl-binding", feature = "wolfssl-binding"),
    all(feature = "openssl-binding", feature = "boringssl-binding"),
    all(feature = "wolfssl-binding", feature = "boringssl-binding")
))]
compile_error!("Selecting multiple vendored PUT is currently not supported: openssl/libressl, wolfssl and boringssl feature flags are mutually exclusive.");

fn main() {
    if cfg!(feature = "asan") {
        // NOTE adding compiler-rt to rpath for libasan is not straightforward
        //
        //     Unfortunately, passing `-frtlib-add-rpath` to clang doesn't add
        //     the correct rpath on linux platforms. Instead, we find the folder
        //     containing the compiler-rt runtime and add it to rpath ourselves.
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", runtime_dir());
        println!("cargo:rustc-link-arg=-fsanitize=address");
        println!("cargo:rustc-link-arg=-shared-libasan");
    }

    if cfg!(feature = "gcov_analysis") {
        println!("cargo:rustc-link-arg=-ftest-coverage");
        println!("cargo:rustc-link-arg=-fprofile-arcs");
    }

    if cfg!(feature = "llvm_cov_analysis") {
        println!("cargo:rustc-link-arg=-fprofile-instr-generate");
        println!("cargo:rustc-link-arg=-fcoverage-mapping");
    }

    // expose the capabilities of linked PUTs as cfg
    tls_harness::tls_puts()
        .iter()
        .for_each(|(name, (harness, library, _))| {
            if library.with_sancov {
                println!("cargo:rust-cfg={}=\"sancov\"", name);
            }
            if library.with_asan {
                println!("cargo:rust-cfg={}=\"asan\"", name);
            }
            if library.with_gcov {
                println!("cargo:rust-cfg={}=\"gcov\"", name);
            }
            if library.with_llvm_cov {
                println!("cargo:rust-cfg={}=\"llvm_cov\"", name);
            }

            println!("cargo:rustc-cfg=has_put=\"{}\"", name);

            harness
                .capabilities
                .iter()
                .for_each(|capability| println!("cargo:rustc-cfg={}=\"{}\"", capability, name));

            library
                .known_vulnerabilities
                .iter()
                .for_each(|vulnerability| {
                    println!("cargo:rustc-cfg={}=\"{}\"", vulnerability, name)
                });
        });
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
