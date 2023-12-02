use std::env;
use std::path::PathBuf;

pub fn build_vendor(vendor_dir: PathBuf, version: &str) -> PathBuf {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    println!(
        "cargo:rerun-if-changed={}",
        vendor_dir.join("CMakeLists.txt").display()
    );

    // TODO add features to the vendor path
    //
    //     The vendor library need to be rebuilt each time a cargo PUT feature
    //     changes and coexist with other libs that have a different set of
    //     features. To distinguish between the different variants, we should
    //     had a path component that is unique to the combination of features
    //     passed to cargo.
    //
    //     They are mainly two ways to solve the problem: create a hashed
    //     version of the features set or simply concatenate the features.  The
    //     advantage of keeping the feature names is the improved
    //     discoverability for the user, but depending on the number of features
    //     we expose through cargo this might result is very long paths.
    //
    //     If we choose to use a hash for the features, it would make sense to
    //     add a file containing the set of features inside the install prefix
    //     directory, so that the user can still figure out against which
    //     configuration he's building the PUT.
    //
    let vendor_prefix = vendor_dir
        .join(env::var("TARGET").unwrap())
        .join("openssl")
        .join(version);

    cmake::Config::new(src_dir.join("vendor"))
        .always_configure(false)
        .define("OPENSSL_GIT_REF", version)
        .out_dir(&vendor_prefix)
        .build_target("openssl")
        .build();

    vendor_prefix
}

pub fn build(vendor_prefix: PathBuf, tlspuffin_include_dir: PathBuf) {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = env::var("OUT_DIR").unwrap();
    let cput_source = src_dir.join("src/put.c");

    println!("cargo:rerun-if-changed={}", cput_source.display());
    println!(
        "cargo:rerun-if-changed={}",
        src_dir.join("CMakeLists.txt").display()
    );

    cmake::Config::new(src_dir)
        .define("OPENSSL_DIR", vendor_prefix)
        .define("TLSPUFFIN_INCDIR", tlspuffin_include_dir)
        .build();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=cputopenssl");
}
