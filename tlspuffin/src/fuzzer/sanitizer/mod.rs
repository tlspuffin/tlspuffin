#[cfg(all(feature = "sancov_pcguard_log", feature = "sancov_libafl"))]
compile_error!("`sancov_pcguard_log` and `sancov_libafl` features are mutually exclusive.");

cfg_if::cfg_if! {
    if #[cfg(test)] {
        // Use dummy in tests and benchmarking
        pub mod sancov_dummy;
    } else {
        #[allow(unused_imports)]
        // This import achieves that OpenSSl compiled with -fsanitize-coverage=trace-pc-guard can link
        pub use libafl_targets;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(not(test), feature = "sancov_pcguard_log"))] {
        pub mod sancov_pcguard_log;
    }
}
