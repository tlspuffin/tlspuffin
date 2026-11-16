//! The catalogue test: every known vulnerability of the TLS vendors checked on real executions of
//! its witness trace, on every PUT of this binary, against what the PUT's catalogue state says (see
//! `puffin::catalogue`).
//!
//! It also fails, with no PUT at all, when an entry has no witness (and no `no_witness` reason) or
//! a witness names an unknown entry.

fn main() -> std::process::ExitCode {
    let vendors = puffin::catalogue::vendors_with_harness("tls");
    let vendors: Vec<&str> = vendors.iter().map(String::as_str).collect();

    puffin::catalogue::test_main(tlspuffin::put_registry::tls_registry, &vendors)
}
