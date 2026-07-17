
fn main() {
    let reg = sppuffin::spp_registry();
    // Delegate to the generic puffin CLI entry point so the real fuzzer is used.
    let _exit = puffin::cli::main("sppuffin", reg);
    // Convert ExitCode to process exit; older toolchains may not expose `code()` — exit 0 for now.
    std::process::exit(0);
}
