use core::time::Duration;
use std::{fs, path::PathBuf, thread, time};

use libafl::bolts::rands::{Rand, RomuTrioRand};
use libafl::corpus::RandCorpusScheduler;
use libafl::events::{Event, EventManager, LogSeverity};
use libafl::feedbacks::{FeedbackStatesTuple, MapIndexesMetadata, MaxReducer, OrFeedback};
use libafl::{
    bolts::tuples::{tuple_list, Merge},
    bolts::{current_nanos, rands::StdRand},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::{setup_restarting_mgr_std, EventRestarter},
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::scheduled::{tokens_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    stats::SimpleStats,
    Error, Evaluator,
};
// Leave this import such that -fsanitize-coverage=trace-pc-guard generated code can link
use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};

use crate::fuzzer::mutations::trace_mutations;
use crate::fuzzer::seeds::seed_successful;
use crate::trace::TraceContext;

mod harness;
mod mutations;
pub mod seeds;

pub fn fuzz(
    corpus_dirs: &[PathBuf],
    objective_dir: PathBuf,
    broker_port: u16,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) = match setup_restarting_mgr_std(stats, broker_port) {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // A feedback to choose if an input is a solution or not
    let objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
        //TimeoutFeedback::new()
    );

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(trace_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // A minimization+queue policy to get testcasess from the corpus
    // let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let scheduler = RandCorpusScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let harness_fn = &mut harness::harness;
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            harness_fn,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
        )?,
        // 10 seconds timeout
        Duration::new(10, 0),
    );

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        /*state
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
        });*/
        let mut ctx = TraceContext::new();
        let seed = seed_successful(&mut ctx);
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut restarting_mgr, seed.2)
            .unwrap();
        //restarting_mgr.process(&mut fuzzer, &mut state, &mut executor).unwrap();
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // This fuzzer restarts after 1 mio `fuzz_one` executions.
    // Each fuzz_one will internally do many executions of the target.
    // If your target is very instable, setting a low count here may help.
    // However, you will lose a lot of performance that way.
    let iters = 1_000_000;
    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut state,
        &mut executor,
        &mut restarting_mgr,
        iters,
    )?;

    // It's important, that we store the state before restarting!
    // Else, the parent will not respawn a new child and quit.
    restarting_mgr.on_restart(&mut state)?;

    Ok(())
}
