fn main() -> std::process::ExitCode {
    let reg = sppuffin::spp_registry();
    // Delegate to the generic puffin CLI entry point so the real fuzzer is used.
    puffin::cli::main("sppuffin", reg)
}
