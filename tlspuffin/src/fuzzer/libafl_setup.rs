use super::harness;
use super::{EDGES_MAP, MAX_EDGES_NUM};
use crate::fuzzer::mutations::trace_mutations;
use crate::fuzzer::mutations::util::TermConstraints;
use crate::fuzzer::stages::{PuffinMutationalStage, PuffinScheduledMutator};
use crate::fuzzer::stats::PuffinMonitor;
use crate::fuzzer::stats_observer::StatsStage;
use crate::openssl_binding::make_deterministic;
use crate::trace::Trace;
use core::time::Duration;

use libafl::bolts::os::Cores;
use libafl::bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl::corpus::RandCorpusScheduler;
use libafl::events::{EventConfig, HasEventManagerId, LlmpRestartingEventManager};
use libafl::{
    bolts::{rands::StdRand, tuples::tuple_list},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    executors::{inprocess::InProcessExecutor, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    state::{HasCorpus, StdState},
    Error,
};
use std::path::PathBuf;

/// Default value, how many iterations each stage gets, as an upper bound
/// It may randomly continue earlier. Each iteration works on a different Input from the corpus
pub static MAX_ITERATIONS_PER_STAGE: u64 = 256;
pub static MAX_MUTATIONS_PER_ITERATION: u64 = 16;
pub static MAX_TRACE_LENGTH: usize = 15;
pub static MIN_TRACE_LENGTH: usize = 5;

pub static FRESH_ZOO_AFTER: u64 = 100000;

/// Below this term size we no longer mutate. Note that it is possible to reach
/// smaller terms by having a mutation which removes all symbols in a single mutation.
pub static MIN_TERM_SIZE: usize = 0;
/// Above this term size we no longer mutate.
pub static MAX_TERM_SIZE: usize = 300;

macro_rules! minimizer_feedback {
    ($edges_feedback_state:ident, $edges_observer:ident, $time_observer:ident) => {
        feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
            MaxMapFeedback::new_tracking(&$edges_feedback_state, &$edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            // needed for IndexesLenTimeMinimizerCorpusScheduler
            TimeFeedback::new_with_observer(&$time_observer)
        )
    };
}

macro_rules! no_minimizer_feedback {
    ($edges_feedback_state:ident, $edges_observer:ident, $time_observer:ident) => {
        feedback_or!(MaxMapFeedback::new_tracking(
            &$edges_feedback_state,
            &$edges_observer,
            false, // [TODO] [LH] Why are track_index and track_novelties are false?
            false
        ))
    };
}

macro_rules! new_run_client {
    ($static_seed:ident, $objective_dir:ident, $corpus_dir:ident, $max_iters:ident, $feedback:ident, $scheduler:expr, $corpus:expr) => {
        |state: Option<StdState<_, _, _, _, _>>,
                          mut restarting_mgr: LlmpRestartingEventManager<_, _, _, _>,
                          _unknown: usize| {
        info!("We're a client, let's fuzz :)");

        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", unsafe {
            &mut EDGES_MAP[0..MAX_EDGES_NUM]
        }));
        let time_observer = TimeObserver::new("time");

        let edges_feedback_state = MapFeedbackState::with_observer(&edges_observer);

        let feedback = $feedback!(edges_feedback_state, edges_observer, time_observer);

        // A feedback to choose if an input is a solution or not
        let objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());
        // [LH] [TODO] Why not using feedback_or_fast?

        let sender_id = restarting_mgr.mgr_id();
        info!("Sender ID is {}", sender_id.id);

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            let seed = $static_seed.unwrap_or(sender_id.id as u64);
            info!("Seed is {}", seed);
            StdState::new(
                StdRand::with_seed(seed),
                $corpus,
                OnDiskCorpus::new($objective_dir.clone()).unwrap(),
                // They are the data related to the feedbacks that you want to persist in the State.
                tuple_list!(edges_feedback_state),
            )
        });

        let mutations = trace_mutations::<StdState<_, _, Trace, _, _>>(
            MIN_TRACE_LENGTH,
            MAX_TRACE_LENGTH,
            TermConstraints {
                min_term_size: MIN_TERM_SIZE,
                max_term_size: MAX_TERM_SIZE,
            },
            FRESH_ZOO_AFTER,
        );
        let mutator = PuffinScheduledMutator::new(mutations, MAX_MUTATIONS_PER_ITERATION);
        let mut stages = tuple_list!(
            PuffinMutationalStage::new(mutator, MAX_ITERATIONS_PER_STAGE),
            StatsStage::new()
        );

        let scheduler = $scheduler;

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut harness_fn = &mut harness::harness;

        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness_fn,
                // hint: edges_observer is expensive to serialize (only noticeable if we add all inputs to the corpus)
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut restarting_mgr,
            )?,
            Duration::new(2, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut restarting_mgr,
                    &[$corpus_dir.clone()],
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "Failed to load initial corpus at {:?}: {}",
                        &$corpus_dir, err
                    )
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if let Some(max_iters) = $max_iters {
            fuzzer.fuzz_loop_for(
                &mut stages,
                &mut executor,
                &mut state,
                &mut restarting_mgr,
                max_iters,
            )?;
        } else {
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        }

        Ok(())
    }
    };
}

/// Starts the fuzzing loop
pub fn start(
    core_definition: &str,
    monitor_file: PathBuf,
    on_disk_corpus: Option<PathBuf>,
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    broker_port: u16,
    max_iters: Option<u64>,
    static_seed: Option<u64>,
    minimizer: bool,
) {
    info!("Running on {} cores", core_definition);

    make_deterministic();
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = PuffinMonitor::new(
        |s| {
            info!("{}", s);
        },
        monitor_file,
    )
    .unwrap();

    let cores = Cores::from_cmdline(core_definition).unwrap(); // possibly replace by parse_core_bind_arg
    let config: EventConfig = "launcher default".into();

    if let Err(error) = if minimizer {
        if let Some(on_disk_corpus) = on_disk_corpus {
            libafl::bolts::launcher::Launcher::builder()
                .shmem_provider(shmem_provider)
                .configuration(config)
                .monitor(monitor)
                .cores(&cores)
                .broker_port(broker_port)
                .run_client(&mut new_run_client!(
                    static_seed,
                    objective_dir,
                    corpus_dir,
                    max_iters,
                    minimizer_feedback,
                    // A minimization+queue policy to get testcasess from the corpus
                    IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new()),
                    OnDiskCorpus::new(on_disk_corpus.clone()).unwrap()
                ))
                .build()
                .launch()
        } else {
            libafl::bolts::launcher::Launcher::builder()
                .shmem_provider(shmem_provider)
                .configuration(config)
                .monitor(monitor)
                .cores(&cores)
                .broker_port(broker_port)
                .run_client(&mut new_run_client!(
                    static_seed,
                    objective_dir,
                    corpus_dir,
                    max_iters,
                    minimizer_feedback,
                    // A minimization+queue policy to get testcasess from the corpus
                    IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new()),
                    InMemoryCorpus::new()
                ))
                .build()
                .launch()
        }
    } else {
        if on_disk_corpus.is_some() {
            panic!("Unsupported config");
        }

        libafl::bolts::launcher::Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(config)
            .monitor(monitor)
            .cores(&cores)
            .broker_port(broker_port)
            .run_client(&mut new_run_client!(
                static_seed,
                objective_dir,
                corpus_dir,
                max_iters,
                no_minimizer_feedback,
                RandCorpusScheduler::new(),
                InMemoryCorpus::new()
            ))
            .build()
            .launch()
    } {
        match error {
            Error::ShuttingDown => {
                // ignore
            }
            _ => {
                panic!("{}", error)
            }
        }
    }
}
