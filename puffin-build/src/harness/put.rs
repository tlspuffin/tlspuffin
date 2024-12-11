use std::collections::HashSet;

use itertools::Itertools;

use crate::harness;
use crate::harness::Harness;
use crate::library::Library;
use crate::utils::{clang, make_rust_identifier};

#[derive(Debug, Clone)]
pub struct Put {
    library: Library,
    harness: Harness,
    objects: Vec<std::path::PathBuf>,
}

impl Put {
    pub fn new(library: Library, harness: Harness, objects: Vec<std::path::PathBuf>) -> Self {
        Self {
            library,
            harness,
            objects,
        }
    }

    pub fn name(&self) -> String {
        self.library.name().clone()
    }

    pub fn id(&self) -> String {
        self.library.id()
    }

    pub fn library(&self) -> Library {
        self.library.clone()
    }

    pub fn harness(&self) -> Harness {
        self.harness.clone()
    }

    pub fn objects(&self) -> Vec<std::path::PathBuf> {
        self.objects.clone()
    }

    pub fn rust_registration(&self) -> String {
        let registration_macro = match self.harness.kind {
            harness::Kind::Rust => "registration_rust",
            harness::Kind::C => "registration_c",
        };

        format!(
            r###"
            {registration_macro}!(
                {id},
                r#"{name}"#,
                r#"{harness_name} {harness_version}"#,
                r#"{library_name} {library_version}"#,
                std::collections::HashSet::from([
                    {capabilities}
                ])
            );
            "###,
            id = self.id(),
            name = self.name(),
            library_name = self.library.metadata().vendor,
            library_version = self.library.metadata().version,
            harness_name = "puffin",
            harness_version = crate::puffin::version(),
            capabilities = self
                .library
                .metadata()
                .capabilities
                .iter()
                .map(|s| format!(r#"String::from("{s}")"#))
                .join(","),
        )
    }

    pub fn print_cargo_metadata(&self) {
        println!("cargo:rerun-if-changed={}", self.library.path().display());

        if matches!(self.harness.kind, harness::Kind::Rust) {
            println!("cargo:rustc-check-cfg=cfg(has_instr, values(\"sancov\", \"asan\", \"gcov\", \"llvm_cov\", \"claimer\"))");
            for instrumentation_type in self.library.metadata().instrumentation.iter() {
                println!("cargo:rustc-cfg=has_instr=\"{instrumentation_type}\"");
            }
        }

        for instrumentation_type in self.library.metadata().instrumentation.iter() {
            println!(
                "cargo:rustc-cfg={}=\"{}\"",
                make_rust_identifier(instrumentation_type),
                self.name()
            )
        }

        let lib = self.library.metadata();
        let known_vulnerabilities: HashSet<String> =
            HashSet::from_iter(lib.known_vulnerabilities.iter().cloned());
        let fixed_vulnerabilities: HashSet<String> =
            HashSet::from_iter(lib.fixed_vulnerabilities.iter().cloned());

        known_vulnerabilities
            .difference(&fixed_vulnerabilities)
            .for_each(|vulnerability| {
                println!(
                    "cargo:rustc-cfg={}=\"{}\"",
                    make_rust_identifier(vulnerability),
                    self.name()
                )
            });

        lib.capabilities.iter().for_each(|capability| {
            println!(
                "cargo:rustc-cfg={}=\"{}\"",
                make_rust_identifier(capability),
                self.name()
            )
        });

        println!(
            "cargo:rustc-cfg={}=\"{}\"",
            make_rust_identifier(&lib.vendor),
            self.name()
        );
        println!("cargo:rustc-cfg=has_put=\"{}\"", self.name());

        if self
            .library
            .metadata()
            .instrumentation
            .iter()
            .any(|i| i == "asan")
        {
            // NOTE adding compiler-rt to rpath for libasan is not straightforward
            //
            //     Unfortunately, passing `-frtlib-add-rpath` to clang doesn't add
            //     the correct rpath on linux platforms. Instead, we find the folder
            //     containing the compiler-rt runtime and add it to rpath ourselves.
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", clang::runtime_dir());
            println!("cargo:rustc-link-arg=-fsanitize=address");
            println!("cargo:rustc-link-arg=-shared-libasan");
        }

        if self
            .library
            .metadata()
            .instrumentation
            .iter()
            .any(|i| i == "gcov")
        {
            println!("cargo:rustc-link-arg=-ftest-coverage");
            println!("cargo:rustc-link-arg=-fprofile-arcs");
        }

        if self
            .library
            .metadata()
            .instrumentation
            .iter()
            .any(|i| i == "llvm_cov")
        {
            println!("cargo:rustc-link-arg=-fprofile-instr-generate");
            println!("cargo:rustc-link-arg=-fcoverage-mapping");
        }
    }
}
