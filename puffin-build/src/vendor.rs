use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::cmake::{self};
use crate::git::{self};

pub fn dir() -> VendorDir {
    let path = env::var("VENDOR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("invalid CARGO_MANIFEST_DIR")
                .join("vendor")
        });

    VendorDir { path }
}

pub struct VendorDir {
    path: PathBuf,
}

impl VendorDir {
    pub fn lock(&self, name: impl AsRef<str>) -> io::Result<ConfigDir> {
        std::fs::create_dir_all(&self.path)?;

        let conf_dir = self.path.join(name.as_ref());
        let lock_file = self.path.join(format!(".vendor_lock_{}", name.as_ref()));

        let lock = nix::fcntl::Flock::lock(
            File::create(&lock_file)?,
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .or_else(|(f, _)| {
            log::info!("waiting for lock on vendor config '{}'", name.as_ref());
            nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        })
        .map_err(|(_, e)| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(ConfigDir {
            path: conf_dir,
            lock,
        })
    }
}

impl fmt::Display for VendorDir {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path.fmt(f)
    }
}

#[derive(Debug)]
pub struct ConfigDir {
    path: PathBuf,

    #[allow(dead_code)]
    lock: nix::fcntl::Flock<File>,
}

impl ConfigDir {
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn library(&self) -> io::Result<Option<Library>> {
        if self.is_empty()? {
            return Ok(None);
        }

        let toml_str = fs::read_to_string(self.path.join(".vendor"))?;

        toml::from_str::<Library>(&toml_str)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map(Some)
    }

    pub fn config(&self) -> io::Result<Option<Config>> {
        if self.is_empty()? {
            return Ok(None);
        }

        let toml_str = fs::read_to_string(self.path.join(".vendor_config"))?;

        toml::from_str::<Config>(&toml_str)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map(Some)
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        self.path
            .join(".vendor_config")
            .try_exists()
            .map(|exists| !exists)
    }

    pub fn remove(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.path())?;
        std::fs::remove_dir_all(self.path())?;
        Ok(())
    }

    pub fn make(&self, config: impl AsRef<Config>) -> io::Result<PathBuf> {
        let config_file = self.path.join(".vendor_config");

        // NOTE ensure intermediate folders exist and there is no artifact from a previous build
        self.remove()?;

        config.as_ref().build(self.path()).map(|_| {
            std::fs::write(&config_file, toml::to_string(config.as_ref()).unwrap()).ok();
            self.path().to_path_buf()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Library {
    pub libname: String,
    pub version: String,
    pub instrumentation: Vec<String>,
    pub known_vulnerabilities: Vec<String>,
    pub fixed_vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    builder: Builder,
    sources: Sources,

    #[serde(default)]
    #[serde(flatten)]
    options: Options,
}

impl Config {
    pub fn new(sources: Sources, builder: Builder) -> Self {
        Self {
            builder,
            sources,
            options: Default::default(),
        }
    }

    pub fn preset(vendor: impl AsRef<str>, name: impl AsRef<str>) -> Option<Config> {
        // TODO gracefully handle error cases rather than using `unwrap`

        // FIXME don't use harcoded path to configuration files (CARGO_MANIFEST_DIR, ...)
        let configs_str = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("vendors")
                .join(vendor.as_ref())
                .join("presets.toml"),
        )
        .unwrap();

        toml::from_str::<HashMap<String, Config>>(&configs_str)
            .unwrap()
            .get(name.as_ref())
            .cloned()
    }

    pub fn build(&self, out_dir: impl AsRef<Path>) -> io::Result<()> {
        let sources_dir = out_dir.as_ref().join("src");
        std::fs::create_dir_all(&sources_dir)?;

        let sources = self.sources.download(sources_dir)?;
        self.builder
            .build(sources, out_dir, self.sources.version(), &self.options)
    }

    pub fn option(&mut self, name: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.options.insert(name, value);
        self
    }
}

impl AsRef<Config> for Config {
    fn as_ref(&self) -> &Config {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Sources {
    Git {
        #[serde(flatten)]
        tree: git::Tree,
        version: String,
    },
    Url {
        url: String,
        hash: Option<String>,
        version: String,
    },
}

impl Sources {
    pub fn download(&self, dest_dir: impl AsRef<Path>) -> io::Result<PathBuf> {
        match self {
            Sources::Git { tree, .. } => git::archive(tree.clone()).to_dir(dest_dir),
            Sources::Url { .. } => todo!(),
        }
    }

    pub fn version(&self) -> String {
        match self {
            Sources::Git { version, .. } | Sources::Url { version, .. } => version.clone(),
        }
    }
}

impl AsRef<Sources> for Sources {
    fn as_ref(&self) -> &Sources {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Builder {
    BuiltIn { name: String, hash: Option<String> },
    CMake { path: PathBuf, hash: Option<String> },
}

const BUILDER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/builder");

impl Builder {
    pub fn build(
        &self,
        sources: impl AsRef<Path>,
        out_dir: impl AsRef<Path>,
        version: impl AsRef<str>,
        options: impl AsRef<Options>,
    ) -> io::Result<()> {
        match self {
            Self::BuiltIn { .. } | Self::CMake { .. } => {
                let mut cmake_conf = match self {
                    Self::BuiltIn { .. } => cmake::Config {
                        src_dir: BUILDER_DIR.into(),
                        out_dir: out_dir.as_ref().to_path_buf(),
                        bld_dir: out_dir.as_ref().join("build"),
                        cfg_args: vec![],
                    },
                    Self::CMake { path, .. } => cmake::Config {
                        src_dir: path.clone(),
                        out_dir: out_dir.as_ref().to_path_buf(),
                        bld_dir: out_dir.as_ref().join("build"),
                        cfg_args: vec![],
                    },
                };

                if let Self::BuiltIn { name, .. } = self {
                    cmake_conf.cfg_args.push(format!("-DBUILDER={}", name));
                }

                cmake_conf
                    .cfg_args
                    .push(format!("-DSOURCES={}", sources.as_ref().display()));
                cmake_conf
                    .cfg_args
                    .push(format!("-DVENDOR_VERSION={}", version.as_ref()));
                cmake_conf
                    .cfg_args
                    .push(String::from("-DCMAKE_C_COMPILER=clang"));
                cmake_conf
                    .cfg_args
                    .push(String::from("-DCMAKE_CXX_COMPILER=clang++"));
                cmake_conf
                    .cfg_args
                    .push(String::from("-DCMAKE_BUILD_TYPE=Release"));

                for (name, value) in options.as_ref().into_iter() {
                    cmake_conf
                        .cfg_args
                        .push(format!("-D{}={}", name, value.to_cmake_value()));
                }

                cmake_conf.build()
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Options(HashMap<String, Value>);

impl Options {
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.0.insert(name.into(), value.into());
    }
}

impl<'a> IntoIterator for &'a Options {
    type IntoIter = std::collections::hash_map::Iter<'a, String, Value>;
    type Item = (&'a String, &'a Value);

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<Options> for Options {
    fn as_ref(&self) -> &Options {
        self
    }
}

pub type Array = Vec<Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    String(String),
    Array(Array),
}

impl Value {
    pub fn to_cmake_value(&self) -> String {
        match self {
            Value::Boolean(b) => b.to_string().to_uppercase(),
            Value::Integer(i) => i.to_string(),
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().map(Value::to_cmake_value).join(","),
        }
    }
}

impl From<Array> for Value {
    fn from(value: Array) -> Self {
        Self::Array(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Vec<String>> for Value {
    fn from(value: Vec<String>) -> Self {
        Self::Array(value.into_iter().map(Value::from).collect())
    }
}
