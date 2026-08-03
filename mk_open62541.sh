rm -rf vendor/open62541
cargo run --bin mk_vendor make open62541:open62541

cargo build --release -p opcuapuffin

