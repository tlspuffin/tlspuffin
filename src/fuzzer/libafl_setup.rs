use core::time::Duration;
use std::path::PathBuf;

use itertools::Itertools;
use libafl::bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl::{
    bolts::{
        current_nanos,
        rands::{StdRand},
        tuples::{tuple_list, Merge},
    },
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler, RandCorpusScheduler,
    },
    events::{setup_restarting_mgr_std, Event, EventManager, EventRestarter, LogSeverity},
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{
        CrashFeedback, FeedbackStatesTuple, MapFeedbackState, MapIndexesMetadata, MaxMapFeedback,
        MaxReducer, TimeFeedback, TimeoutFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::{
        havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    stats::{MultiStats, SimpleStats},
    Error, Evaluator,
};
use crate::openssl_binding::make_deterministic;
use crate::{
    fuzzer::{mutations::trace_mutations},
};
use super::{harness};
use super::{EDGES_MAP, MAX_EDGES_NUM};
use crate::fuzzer::error_observer::ErrorObserver;
use crate::fuzzer::stages::PuffinMutationalStage;

/// Starts the fuzzing loop
pub fn start(num_cores: usize, corpus_dirs: &[PathBuf], objective_dir: &PathBuf, broker_port: u16) {
    make_deterministic();
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let stats = MultiStats::new(|s| info!("{}", s));

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut restarting_mgr| {
        info!("We're a client, let's fuzz :)");

        let edges_observer = StdMapObserver::new("edges", unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] });
        let time_observer = TimeObserver::new("time");
        let error_observer = ErrorObserver::new("error");

        let edges_feedback_state = MapFeedbackState::with_observer(&edges_observer);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            //MaxMapFeedback::new_tracking(&edges_feedbac_k_state, &edges_observer, true, false),
            MaxMapFeedback::new(&edges_feedback_state, &edges_observer)
            // Time feedback, this one does not need a feedback state
            //TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            let seed = current_nanos();
            warn!("Seed is {}", seed);
            StdState::new(
                // RNG
                StdRand::with_seed(seed),
                // Corpus that will be evolved, we keep it in memory for performance
                //OnDiskCorpus::new(PathBuf::from("corpus_inspection")).unwrap(),
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                //InMemoryCorpus::new(),
                // States of the feedbacks.
                // They are the data related to the feedbacks that you want to persist in the State.
                //tuple_list!(),
                tuple_list!(edges_feedback_state),
            )
        });

        // Setup a basic mutator with a mutational stage
        let mutator = StdScheduledMutator::new(trace_mutations());
        let mut stages = tuple_list!(PuffinMutationalStage::new(mutator));

        // A minimization+queue policy to get testcasess from the corpus
        //let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
        let scheduler = RandCorpusScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut harness_fn = &mut harness::harness;
        /*let mut harness_fn = &mut harness::harness;*/

        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut harness_fn,
                // hint: edges_observer is expensive to serialize
                tuple_list!(edges_observer, error_observer),
                &mut fuzzer,
                &mut state,
                &mut restarting_mgr,
            )?,
            // 10 seconds timeout
            Duration::new(2, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut restarting_mgr,
                    &corpus_dirs,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "Failed to load initial corpus at {:?}: {}",
                        &corpus_dirs, err
                    )
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };

    libafl::bolts::launcher::Launcher::builder()
        .shmem_provider(shmem_provider)
        .stats(stats)
        .run_client(&mut run_client)
        .cores(&(0..num_cores).collect_vec()) // possibly replace by parse_core_bind_arg
        .broker_port(broker_port)
        //todo where should we log the output of the harness?
        //.stdout_file(Some("/dev/null"))
        .build()
        .launch()
        .expect("Launcher failed");
}
