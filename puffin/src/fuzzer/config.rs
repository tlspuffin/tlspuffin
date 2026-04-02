use std::path::PathBuf;

use log::LevelFilter;

use crate::fuzzer::mutations::MutationConfig;
use crate::put::PutDescriptor;

/// Minimum of executions before starting to run bit-level mutations
pub const MIN_BIT_EXECS: usize = 5_000; // one 1 core
/// Minimum of test cases in corpus before starting to run bit-level mutations
pub const MIN_BIT_CORPUS: usize = 200; // on 1 core

#[derive(Clone, Debug)]
pub struct FuzzerConfig {
    pub initial_corpus_dir: PathBuf,
    pub static_seed: Option<u64>,
    pub max_iters: Option<u64>,
    pub core_definition: String,
    pub stats_file: PathBuf,
    pub corpus_dir: PathBuf,
    pub objective_dir: PathBuf,
    pub broker_port: u16,
    pub minimizer: bool, // FIXME: support this property
    pub mutation_stage_config: MutationStageConfig,
    pub mutation_config: MutationConfig,
    pub tui: bool,
    pub no_launcher: bool,
    pub log_folder: PathBuf,
    pub is_experiment: bool,
    pub put_use_clear: bool, // use clear instead of free on Agents in between traces of some Input
    pub verbosity: LevelFilter, // level for the client logging
    pub target: FuzzingTarget,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        let current = std::env::current_dir().unwrap();
        Self {
            initial_corpus_dir: current.join("./seeds"),
            static_seed: None,
            max_iters: None,
            core_definition: "1".to_string(),
            stats_file: current.join("log/stats.json"),
            corpus_dir: current.join("corpus"),
            objective_dir: current.join("objective"),
            broker_port: 1337,
            minimizer: false,
            tui: false,
            no_launcher: false,
            log_folder: current.join("log"),
            is_experiment: false,
            verbosity: LevelFilter::Info, // default verbosity
            mutation_stage_config: Default::default(),
            mutation_config: Default::default(),
            put_use_clear: false,
            target: Default::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum FuzzingTarget {
    Single(Option<PutDescriptor>),
    Differential(PutDescriptor, PutDescriptor),
}

impl Default for FuzzingTarget {
    fn default() -> Self {
        Self::Single(None)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MutationStageConfig {
    /// How many iterations each stage gets, as an upper bound
    /// It may randomly continue earlier. Each iteration works on a different Input from the corpus
    pub max_iterations_per_stage: u64,
    pub max_mutations_pow_per_iteration: u64,
    // Whether to truncate the input after mutations, prior to adding it to the corpus
    pub with_truncation: bool,
}

impl Default for MutationStageConfig {
    //  TODO:EVAL: evaluate modifications of this config
    fn default() -> Self {
        Self {
            max_iterations_per_stage: 128,
            max_mutations_pow_per_iteration: 7,
            with_truncation: false,
            // Default for StdMutationalStage and StdMutationalStage (=HavocScheduledMutator)
        }
    }
}
