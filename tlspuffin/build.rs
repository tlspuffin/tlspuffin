fn main() {
    if cfg!(feature = "asan") {
        let output = Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .expect("failed to clang to get resource dir");
        let clang: &str = std::str::from_utf8(&output.stdout).unwrap().trim();

        println!("cargo:rustc-link-arg=-Wl,-rpath={}/lib/linux/", clang);
        println!("cargo:rustc-link-arg=-fsanitize=address");
        println!("cargo:rustc-link-arg=-shared-libasan");
    }
}
