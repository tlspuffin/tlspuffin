# CLAUDE.md

## Project Overview

`tlspuffin` is a Dolev-Yao (DY) model-guided fuzzer for TLS protocol implementations. It fuzzes TLS libraries (OpenSSL, BoringSSL, wolfSSL, LibreSSL) by generating symbolic "traces" — sequences of abstract protocol messages — that are then concretized and executed against real TLS agents.

## Technical points

### How to run tests
All Tests: `cargo test -p tlspuffin --features=cputs`
Seeds Tests: `cargo test -p tlspuffin --features=cputs --lib seeds`
Specific Test: `cargo test -p tlspuffin --features=cputs --lib tls::seeds::tests::test_seed_successful_with_tickets`
Build executable: `cargo build --features=cputs --bin tlspuffin`
Run executable: `./target/debug/tlspuffin`
- Generate seeds `./target/debug/tlspuffin seed [--differential]` With differential option you can generate seeds for the differential test.
- Execute `./target/debug/tlspuffin execute seeds/tlspuffin::tls::seeds::seed_client_attacker.trace`
- Display execute
- Differential execute

See more commands and options to run the executable in the file "cli.rs"
You also can precede any execution with RUST_LOG=<info|debug|trace..> to see more logs. You can forward the logs in a temp file as they can be big sometimes, speciffically with trace but even sometimes with the others.


## Commits
Be human
Do NOT write "written by Opus XXX..." in the commit message.
NEVER push to origin