//! Witness traces for the SSH vulnerability catalogue
//! (`puffin-build/vendors/<vendor>/vulnerabilities.toml`).
//!
//! Each `#[puffin::witness("<ID>")]` function returns a `Trace` that triggers the catalogue
//! entry's oracle on an affected PUT and nothing on a fixed one; it auto-registers at link time
//! (linkme), so there is no per-CVE test to write. The catalogue test
//! (`sshpuffin/tests/catalogue.rs`) runs every witness on every PUT of the binary and checks the
//! outcome against the PUT's catalogue state.
