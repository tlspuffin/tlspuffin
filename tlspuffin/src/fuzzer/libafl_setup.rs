use core::time::Duration;
use std::{fmt, path::PathBuf};

use libafl::{
    bolts::{
        core_affinity::Cores,
        rands::{Rand, StdRand},
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{
        EventFirer, EventManager, EventRestarter, LlmpRestartingEventManager, ProgressReporter,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, Feedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::tui::TuiMonitor,
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler, Scheduler},
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasNamedMetadata, StdState},
    Error,
};
use log::info;

use super::harness;
use crate::{
    fuzzer::{
        mutations::{trace_mutations, util::TermConstraints},
        stages::{PuffinMutationalStage, PuffinScheduledMutator},
        stats::PuffinMonitor,
        stats_observer::StatsStage,
    },
    registry::PUT_REGISTRY,
    trace::Trace,
};

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

// TODO: Use feedback_or_fast
pub fn no_minimizer_feedback<'a, 'b, S: 'b>(
    edges_observer: &'a HitcountsMapObserver<StdMapObserver<'b, u8>>,
) -> impl Feedback<Trace, S> + 'b
where
    S: HasExecutions + HasClientPerfMonitor + fmt::Debug + HasNamedMetadata,
{
    feedback_or!(MaxMapFeedback::new_tracking(
        edges_observer,
        false, // [TODO] [LH] Why are track_index and track_novelties are false?
        false
    ))
}

pub fn no_feedback<'a, 'b, S: 'b>() -> impl Feedback<Trace, S> + 'b
where
    S: HasExecutions + HasClientPerfMonitor + fmt::Debug + HasNamedMetadata,
{
}

pub fn minimizer_feedback<'a, 'b, S: 'b>(
    time_observer: &'a TimeObserver,
    edges_observer: &'a HitcountsMapObserver<StdMapObserver<'b, u8>>,
) -> impl Feedback<Trace, S> + 'b
where
    S: HasExecutions + HasClientPerfMonitor + fmt::Debug + HasNamedMetadata,
{
    feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
        MaxMapFeedback::new_tracking(edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        // needed for IndexesLenTimeMinimizerCorpusScheduler
        TimeFeedback::new_with_observer(time_observer)
    )
}

type ConcreteExecutor<'a, H, OT, S> = TimeoutExecutor<InProcessExecutor<'a, H, Trace, OT, S>>;

type ConcreteState<C, R, SC> = StdState<C, Trace, R, SC>;

pub fn run_client<'a, H, C, R, SC, EM, F, OF, OT, CS>(
    observers: OT,
    harness_fn: &'a mut H,
    static_seed: Option<u64>,
    max_iters: Option<u64>,
    state: Option<ConcreteState<C, R, SC>>,
    scheduler: CS,
    new_state: impl FnOnce(&mut F, &mut OF) -> ConcreteState<C, R, SC>,
    sender_id: u32,
    init_state: impl FnOnce(
        &mut ConcreteState<C, R, SC>,
        &mut StdFuzzer<CS, F, Trace, OF, OT, ConcreteState<C, R, SC>>,
        &mut ConcreteExecutor<'a, H, OT, ConcreteState<C, R, SC>>,
        &mut EM,
    ),
    mut event_manager: EM,
    mut feedback: F,
    mut objective: OF,
) -> Result<(), Error>
where
    C: Corpus<Trace>,
    R: Rand,
    SC: Corpus<Trace>,
    H: FnMut(&Trace) -> ExitKind,
    OF: Feedback<Trace, ConcreteState<C, R, SC>>,
    OT: ObserversTuple<Trace, ConcreteState<C, R, SC>>
        + serde::Serialize
        + serde::de::DeserializeOwned,
    F: Feedback<Trace, ConcreteState<C, R, SC>>,
    CS: Scheduler<Trace, ConcreteState<C, R, SC>>,
    EM: EventFirer<Trace>
        + EventRestarter<ConcreteState<C, R, SC>>
        + EventManager<
            ConcreteExecutor<'a, H, OT, ConcreteState<C, R, SC>>,
            Trace,
            ConcreteState<C, R, SC>,
            StdFuzzer<CS, F, Trace, OF, OT, ConcreteState<C, R, SC>>,
        > + ProgressReporter<Trace>,
{
    //let sender_id = restarting_mgr.mgr_id();
    info!("Sender ID is {}", sender_id);

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        let seed = static_seed.unwrap_or(sender_id as u64);
        info!("Seed is {}", seed);

        new_state(&mut feedback, &mut objective)
    });

    let mutations = trace_mutations(
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

    let mut fuzzer: StdFuzzer<CS, F, Trace, OF, OT, _> =
        StdFuzzer::new(scheduler, feedback, objective);

    let mut executor: ConcreteExecutor<'a, H, OT, _> = TimeoutExecutor::new(
        InProcessExecutor::new(
            harness_fn,
            // hint: edges_observer is expensive to serialize (only noticeable if we add all inputs to the corpus)
            observers,
            &mut fuzzer,
            &mut state,
            &mut event_manager,
        )?,
        Duration::new(2, 0),
    );

    init_state(&mut state, &mut fuzzer, &mut executor, &mut event_manager);

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
    _on_disk_corpus: Option<PathBuf>,
    initial_corpus_dir: PathBuf,
    objective_dir: PathBuf,
    broker_port: u16,
    max_iters: Option<u64>,
    static_seed: Option<u64>,
    _minimizer: bool,
) {
    info!("Running on {} cores", core_definition);

    PUT_REGISTRY.make_deterministic();

    let shmem_provider: StdShMemProvider =
        StdShMemProvider::new().expect("Failed to init shared memory");

    let _monitor = PuffinMonitor::new(
        |s| {
            info!("{}", s);
        },
        monitor_file,
    )
    .unwrap();

    let monitor = TuiMonitor::new("test".to_string(), false);

    //let path_buf = on_disk_corpus.unwrap();
    let mut run_client =
        |state: Option<StdState<_, _, _, _>>,
         restarting_mgr: LlmpRestartingEventManager<Trace, _, _, StdShMemProvider>,
         _unknown: usize|
         -> Result<(), Error> {
            info!("We're a client, let's fuzz :)");

            #[cfg(not(feature = "sancov_libafl"))]
            let (feedback, observers) = { (no_feedback(), ()) };

            #[cfg(feature = "sancov_libafl")]
            let (feedback, observers) = {
                let time_observer = TimeObserver::new("time");
                let edges_observer =
                    HitcountsMapObserver::new(StdMapObserver::new("edges", unsafe {
                        &mut super::EDGES_MAP[0..super::MAX_EDGES_NUM]
                    }));
                let feedback = minimizer_feedback(&time_observer, &edges_observer);
                let observers = tuple_list!(time_observer, edges_observer);
                (feedback, observers)
            };

            run_client(
                observers,
                &mut harness::harness,
                static_seed,
                max_iters,
                state,
                //RandScheduler::new(),
                // A minimization+queue policy to get testcasess from the corpus
                IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new()),
                |feedback, objective| {
                    StdState::new(
                        StdRand::with_seed(0),
                        //OnDiskCorpus::new(path_buf.clone()).unwrap(),
                        InMemoryCorpus::new(),
                        OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                        feedback,
                        objective,
                    )
                    .unwrap()
                },
                0,
                |state, fuzzer, executor, manager| {
                    // In case the corpus is empty (on first run), reset
                    if state.corpus().count() < 1 {
                        state
                            .load_initial_inputs(
                                fuzzer,
                                executor,
                                manager,
                                &[initial_corpus_dir.clone()],
                            )
                            .unwrap_or_else(|err| {
                                panic!(
                                    "Failed to load initial corpus at {:?}: {}",
                                    &initial_corpus_dir, err
                                )
                            });
                        println!("We imported {} inputs from disk.", state.corpus().count());
                    }
                },
                restarting_mgr,
                feedback,
                feedback_or!(CrashFeedback::new(), TimeoutFeedback::new()),
            )
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
