use super::harness;
use super::{EDGES_MAP, MAX_EDGES_NUM};
use crate::concretize::PUT_REGISTRY;
use crate::fuzzer::mutations::trace_mutations;
use crate::fuzzer::mutations::util::TermConstraints;
use crate::fuzzer::stages::{PuffinMutationalStage, PuffinScheduledMutator};
use crate::fuzzer::stats::PuffinMonitor;
use crate::fuzzer::stats_observer::StatsStage;
use crate::trace::Trace;
use core::time::Duration;
use libafl::bolts::os::Cores;
use libafl::bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl::corpus::CorpusScheduler;
use libafl::corpus::RandCorpusScheduler;
use libafl::events::EventManager;
use libafl::events::ProgressReporter;
use libafl::events::{EventFirer, EventRestarter, HasEventManagerId, LlmpRestartingEventManager};
use libafl::executors::{Executor, ExitKind};
use libafl::feedbacks::FeedbackStatesTuple;
use libafl::feedbacks::{
    CombinedFeedback, DifferentIsNovel, Feedback, LogicEagerOr, MapFeedback, MaxReducer,
};
use libafl::observers::ObserversTuple;
use libafl::state::{
    HasClientPerfMonitor, HasExecutions, HasFeedbackStates, HasMaxSize, HasMetadata, HasRand,
    HasSolutions, State,
};
use libafl::Evaluator;
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
use log::info;
use std::fmt;
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

pub fn no_minimizer_feedback<'a, S: 'a>(
    edges_feedback_state: &'a MapFeedbackState<u8>,
    edges_observer: &'a HitcountsMapObserver<StdMapObserver<u8>>,
) -> impl Feedback<Trace, S> + 'a
where
    S: HasExecutions + HasClientPerfMonitor + HasFeedbackStates + fmt::Debug,
{
    feedback_or!(MaxMapFeedback::new_tracking(
        edges_feedback_state,
        edges_observer,
        false, // [TODO] [LH] Why are track_index and track_novelties are false?
        false
    ))
}

pub fn no_feedback<'a, S: 'a>() -> impl Feedback<Trace, S> + 'a
where
    S: HasExecutions + HasClientPerfMonitor + HasFeedbackStates + fmt::Debug,
{
    ()
}

pub fn minimizer_feedback<'a, S: 'a>(
    edges_feedback_state: &'a MapFeedbackState<u8>,
    time_observer: &'a TimeObserver,
    edges_observer: &'a HitcountsMapObserver<StdMapObserver<u8>>,
) -> impl Feedback<Trace, S> + 'a
where
    S: HasExecutions + HasClientPerfMonitor + HasFeedbackStates + fmt::Debug,
{
    feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
        MaxMapFeedback::new_tracking(edges_feedback_state, edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        // needed for IndexesLenTimeMinimizerCorpusScheduler
        TimeFeedback::new_with_observer(time_observer)
    )
}

type Harness = fn(&Trace) -> ExitKind;

type ExecutorType<'a, H, S> = TimeoutExecutor<
    InProcessExecutor<
        'a,
        H,
        Trace,
        (
            HitcountsMapObserver<StdMapObserver<'a, u8>>,
            (TimeObserver, ()),
        ),
        S,
    >,
>;

pub fn run_client<'a, H, S, EM, F, OF, OT, CS>(
    harness_fn: &'a mut H,
    static_seed: Option<u64>,
    max_iters: Option<u64>,
    state: Option<S>,
    scheduler: CS,
    new_state: impl FnOnce((MapFeedbackState<u8>, ())) -> S,
    sender_id: u32,
    mut event_manager: EM,
    feedback: F,
    objective: OF,
) -> Result<(), Error>
where
    H: FnMut(&Trace) -> ExitKind,
    OF: Feedback<Trace, S>,
    F: Feedback<Trace, S>,
    OT: ObserversTuple<Trace, S> + serde::Serialize + serde::de::DeserializeOwned,
    CS: CorpusScheduler<Trace, S>,
    EM: EventFirer<Trace>
        + EventRestarter<S>
        + EventManager<ExecutorType<'a, H, S>, Trace, S, StdFuzzer<CS, F, Trace, OF, OT, S>>
        + ProgressReporter<Trace>,
    //E: Executor<EM, Trace, S, StdFuzzer<CS, F, Trace, OF, OT, S>>,
    S: HasExecutions
        + HasClientPerfMonitor
        + HasFeedbackStates
        + HasSolutions<Trace>
        + fmt::Debug
        + HasMetadata
        + HasRand
        + HasCorpus<Trace>
        + HasMaxSize,
{
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", unsafe {
        &mut EDGES_MAP[0..MAX_EDGES_NUM]
    }));

    let time_observer = TimeObserver::new("time");

    let edges_feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // A feedback to choose if an input is a solution or not
    /*    let objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());*/
    // [LH] [TODO] Why not using feedback_or_fast?

    //let sender_id = restarting_mgr.mgr_id();
    info!("Sender ID is {}", sender_id);

    // If not restarting, create a State from scratch
    let mut state: S = state.unwrap_or_else(|| {
        let seed = static_seed.unwrap_or(sender_id as u64);
        info!("Seed is {}", seed);
        let state: S = new_state(tuple_list!(edges_feedback_state));
        state
    });

    let mutations = trace_mutations::<S>(
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
        /*PuffinMutationalStage::new(mutator, MAX_ITERATIONS_PER_STAGE),

        StatsStage::new()*/
    );

    // A minimization+queue policy to get testcasess from the corpus
    /*#[cfg(not(feature = "no-minimizer"))]
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    #[cfg(feature = "no-minimizer")]
    let scheduler = RandCorpusScheduler::new();*/

    let mut fuzzer: StdFuzzer<CS, F, Trace, OF, OT, S> =
        StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            harness_fn,
            // hint: edges_observer is expensive to serialize (only noticeable if we add all inputs to the corpus)
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut event_manager,
        )?,
        Duration::new(2, 0),
    );

    // In case the corpus is empty (on first run), reset
    /*    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut restarting_mgr,
                &[initial_corpus_dir.clone()],
            )
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {}",
                    &initial_corpus_dir, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }*/

    if let Some(max_iters) = max_iters {
        fuzzer.fuzz_loop_for(
            &mut stages,
            &mut executor,
            &mut state,
            &mut event_manager,
            max_iters,
        )?;
    } else {
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut event_manager)?;
    }
    Ok(())
}

/// Starts the fuzzing loop
pub fn start(
    core_definition: &str,
    monitor_file: PathBuf,
    on_disk_corpus: Option<PathBuf>,
    initial_corpus_dir: PathBuf,
    objective_dir: PathBuf,
    broker_port: u16,
    max_iters: Option<u64>,
    static_seed: Option<u64>,
    minimizer: bool,
) {
    info!("Running on {} cores", core_definition);

    PUT_REGISTRY.make_deterministic();
    let shmem_provider: StdShMemProvider =
        StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = PuffinMonitor::new(
        |s| {
            info!("{}", s);
        },
        monitor_file,
    )
    .unwrap();
    let path_buf = on_disk_corpus.unwrap();
    let mut run_client =
        |state: Option<StdState<_, _, _, _, _>>,
         mut restarting_mgr: LlmpRestartingEventManager<Trace, _, _, StdShMemProvider>,
         _unknown: usize|
         -> Result<(), Error> {
            info!("We're a client, let's fuzz :)");

            run_client(
                &mut harness::harness,
                static_seed,
                max_iters,
                state,
                RandCorpusScheduler::new(),
                |feedback_states| {
                    StdState::new(
                        StdRand::with_seed(0),
                        OnDiskCorpus::new(path_buf.clone()).unwrap(),
                        //InMemoryCorpus::new(),
                        OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                        // They are the data related to the feedbacks that you want to persist in the State.
                        feedback_states,
                    )
                },
                0,
                restarting_mgr,
                no_feedback(),
                no_feedback(),
            )?;

            Ok(())
        };

    if let Err(error) = libafl::bolts::launcher::Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration("launcher default".into())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&Cores::from_cmdline(core_definition).unwrap()) // possibly replace by parse_core_bind_arg
        .broker_port(broker_port)
        //todo where should we log the output of the harness?
        /*.stdout_file(Some("/dev/null"))*/
        .build()
        .launch()
    {
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
