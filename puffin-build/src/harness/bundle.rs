use itertools::Itertools;

use super::Put;
use crate::utils::cmake;

#[derive(Debug, Clone, Default)]
pub struct BundleBuilder {
    puts: Vec<Put>,
}

impl BundleBuilder {
    pub fn new(puts: Vec<Put>) -> Self {
        Self { puts }
    }

    pub fn build(self, out_dir: impl AsRef<std::path::Path>) -> Bundle {
        let out_dir = out_dir.as_ref();

        let bundle_bindings = format!(
            r#"
            #[allow(unused_macros)]
            #[macro_export]
            macro_rules! for_puts {{
                ( $($tail:tt)* ) => {{
                    {puts_macros}
                }};
            }}

            pub use for_puts;

            fn register() -> Vec<GlobalFactory> {{
                vec![None, {registration}].into_iter().flatten().collect()
            }}

            {puts_modules}
            "#,
            registration = self
                .puts
                .iter()
                .map(|put| format!("{}::register()", put.id()))
                .join(", "),
            puts_modules = self
                .puts
                .iter()
                .map(|put| put.rust_registration())
                .join("\n\n"),
            puts_macros = self.puts.iter().map(|put| {
               format!(r#"puffin_macros::replace!(__PUTSTR__ => "{name}" in {{ puffin_macros::replace!(__PUT__ => {id} in {{ $($tail)* }}); }});"#, name = put.name(), id = put.id())
            }).join("\n")
        );

        std::fs::create_dir_all(out_dir).unwrap();
        std::fs::write(out_dir.join(Bundle::bindings_file()), bundle_bindings)
            .expect("failed to write Rust PUT bindings");

        let mut cmake_conf = cmake::command("bundle", out_dir);

        cmake_conf.cfg_args.push(format!(
            "-D=PUTS={}",
            self.puts
                .iter()
                .flat_map(|put| put.objects())
                .map(|obj| obj.display().to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));

        cmake_conf.build().unwrap();

        Bundle::new(self.puts, out_dir.to_path_buf())
    }
}

pub struct Bundle {
    puts: Vec<Put>,
    dir: std::path::PathBuf,
}

impl Bundle {
    pub fn print_cargo_metadata(&self) {
        for put in self.puts.iter() {
            put.print_cargo_metadata();
        }

        println!(
            "cargo:rustc-env=RUST_PUTS_BUNDLE_FILE={}",
            self.dir.join(Self::bindings_file()).display()
        );

        println!("cargo:rustc-link-search=native={}", self.dir.display());
        println!("cargo:rustc-link-lib=static=puts-bundle");
    }

    pub(in crate::harness) fn new(puts: Vec<Put>, dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            puts,
            dir: dir.into(),
        }
    }

    pub(self) fn bindings_file() -> std::path::PathBuf {
        std::path::PathBuf::from("put_bindings.rs")
    }
}
