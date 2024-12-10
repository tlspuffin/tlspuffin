fn main() {
    println!("cargo::rerun-if-changed={}", env!("CARGO_MANIFEST_DIR"));
}
