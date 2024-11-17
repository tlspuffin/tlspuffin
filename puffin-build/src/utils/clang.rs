use std::process::Command;

pub fn runtime_dir() -> String {
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
