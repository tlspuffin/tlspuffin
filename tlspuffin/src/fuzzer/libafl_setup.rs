use core::time::Duration;
use std::{fmt, path::PathBuf};

use libafl::{
    bolts::{
        core_affinity::Cores,
        rands::{Rand, StdRand},
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{
        EventConfig, EventFirer, EventManager, EventRestarter, HasEventManagerId,
        LlmpRestartingEventManager, ProgressReporter,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{
        CombinedFeedback, CrashFeedback, DifferentIsNovel, Feedback, LogicEagerOr, MapFeedback,
        MaxMapFeedback, MaxReducer, TimeFeedback, TimeoutFeedback,
    },
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
        monitor::PuffinMonitor,
        mutations::{trace_mutations, util::TermConstraints},
        stages::{PuffinMutationalStage, PuffinScheduledMutator},
        stats_observer::StatsStage,
    },
    put_registry::PUT_REGISTRY,
    trace::Trace,
};

// TODO: Use feedback_or_fast
pub fn no_minimizer_feedback<'harness, 'b, S: 'b>(
    edges_observer: &'harness HitcountsMapObserver<StdMapObserver<'b, u8>>,
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

pub fn no_feedback<'harness, 'b, S: 'b>() -> impl Feedback<Trace, S> + 'b
where
    S: HasExecutions + HasClientPerfMonitor + fmt::Debug + HasNamedMetadata,
{
}

pub fn minimizer_feedback<'harness, 'b, S: 'b>(
    time_observer: &'harness TimeObserver,
    edges_observer: &'harness HitcountsMapObserver<StdMapObserver<'b, u8>>,
) -> impl Feedback<Trace, S> + 'b
where
    S: HasExecutions + HasClientPerfMonitor + fmt::Debug + HasNamedMetadata,
{
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
        MaxMapFeedback::new_tracking(edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        // needed for IndexesLenTimeMinimizerCorpusScheduler
        TimeFeedback::new_with_observer(time_observer)
    );
    feedback
}

type ConcreteExecutor<'harness, H, OT, S> =
    TimeoutExecutor<InProcessExecutor<'harness, H, Trace, OT, S>>;

type ConcreteState<C, R, SC> = StdState<C, Trace, R, SC>;

#[derive(Clone)]
pub struct FuzzerConfig {
    pub initial_corpus_dir: PathBuf,
    pub static_seed: Option<u64>,
    pub max_iters: Option<u64>,
    pub core_definition: String,
    pub monitor_file: PathBuf,
    pub corpus_dir: PathBuf,
    pub objective_dir: PathBuf,
    pub broker_port: u16,
    pub minimizer: bool, // FIXME: support this property
    pub mutation_stage_config: MutationStageConfig,
    pub mutation_config: MutationConfig,
    pub monitor: bool,
}

#[derive(Clone, Copy)]
pub struct MutationStageConfig {
    /// How many iterations each stage gets, as an upper bound
    /// It may randomly continue earlier. Each iteration works on a different Input from the corpus
    pub max_iterations_per_stage: u64,
    pub max_mutations_per_iteration: u64,
}

impl Default for MutationStageConfig {
    fn default() -> Self {
        Self {
            max_iterations_per_stage: 256,
            max_mutations_per_iteration: 16,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MutationConfig {
    pub fresh_zoo_after: u64,
    pub max_trace_length: usize,
    pub min_trace_length: usize,
    /// Below this term size we no longer mutate. Note that it is possible to reach
    /// smaller terms by having a mutation which removes all symbols in a single mutation.
    /// Above this term size we no longer mutate.
    pub term_constraints: TermConstraints,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            fresh_zoo_after: 100000,
            max_trace_length: 15,
            min_trace_length: 5,
            term_constraints: TermConstraints {
                min_term_size: 0,
                max_term_size: 300,
            },
        }
    }
}

struct RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS>
where
    C: Corpus<Trace>,
    R: Rand,
    SC: Corpus<Trace>,
{
    config: FuzzerConfig,
    harness_fn: &'harness mut H,
    existing_state: Option<ConcreteState<C, R, SC>>,
    rand: Option<R>,
    objective_corpus: Option<SC>,
    corpus: Option<C>,
    scheduler: Option<CS>,
    event_manager: EM,
    observers: Option<OT>,
    feedback: Option<F>,
    objective: Option<OF>,
}

impl<'harness, H, C, R, SC, EM, F, OF, OT, CS>
    RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS>
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
            ConcreteExecutor<'harness, H, OT, ConcreteState<C, R, SC>>,
            Trace,
            ConcreteState<C, R, SC>,
            StdFuzzer<CS, F, Trace, OF, OT, ConcreteState<C, R, SC>>,
        > + ProgressReporter<Trace>,
{
    fn new(
        config: FuzzerConfig,
        harness_fn: &'harness mut H,
        existing_state: Option<ConcreteState<C, R, SC>>,
        event_manager: EM,
    ) -> Self {
        Self {
            config,
            harness_fn,
            existing_state,
            rand: None,
            objective_corpus: None,
            corpus: None,
            scheduler: None,
            event_manager,
            observers: None,
            feedback: None,
            objective: None,
        }
    }
    fn with_rand(mut self, rand: R) -> Self {
        self.rand = Some(rand);
        self
    }

    fn with_corpus(mut self, corpus: C) -> Self {
        self.corpus = Some(corpus);
        self
    }

    fn with_objective_corpus(mut self, objective_corpus: SC) -> Self {
        self.objective_corpus = Some(objective_corpus);
        self
    }

    fn with_scheduler(mut self, scheduler: CS) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    fn with_feedback(mut self, feedback: F) -> Self {
        self.feedback = Some(feedback);
        self
    }

    fn with_objective(mut self, objective: OF) -> Self {
        self.objective = Some(objective);
        self
    }

    fn with_observers(mut self, observers: OT) -> Self {
        self.observers = Some(observers);
        self
    }

    fn run_client(mut self) -> Result<(), Error> {
        let event_manager_id = self.event_manager.mgr_id().id as u64;
        info!("Event manager ID is {}", event_manager_id);

        let mut feedback = self.feedback.unwrap();
        let mut objective = self.objective.unwrap();

        // If not restarting, create a State from scratch
        let mut state = self.existing_state.unwrap_or_else(|| {
            StdState::new(
                self.rand.unwrap(),
                self.corpus.unwrap(),
                self.objective_corpus.unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let FuzzerConfig {
            initial_corpus_dir,
            static_seed: _,
            max_iters,
            core_definition: _,
            monitor_file: _,
            objective_dir: _,
            broker_port: _,
            minimizer: _, // FIXME: Unused
            mutation_stage_config:
                MutationStageConfig {
                    max_iterations_per_stage,
                    max_mutations_per_iteration,
                },
            mutation_config:
                MutationConfig {
                    fresh_zoo_after,
                    max_trace_length,
                    min_trace_length,
                    term_constraints,
                },
            ..
        } = self.config;

        let mutations = trace_mutations(
            min_trace_length,
            max_trace_length,
            term_constraints,
            fresh_zoo_after,
        );

        let mutator = PuffinScheduledMutator::new(mutations, max_mutations_per_iteration);
        let mut stages = tuple_list!(
            PuffinMutationalStage::new(mutator, max_iterations_per_stage),
            StatsStage::new()
        );

        let mut fuzzer: StdFuzzer<CS, F, Trace, OF, OT, _> =
            StdFuzzer::new(self.scheduler.unwrap(), feedback, objective);

        let mut executor: ConcreteExecutor<'harness, H, OT, _> = TimeoutExecutor::new(
            InProcessExecutor::new(
                self.harness_fn,
                // hint: edges_observer is expensive to serialize (only noticeable if we add all inputs to the corpus)
                self.observers.unwrap(),
                &mut fuzzer,
                &mut state,
                &mut self.event_manager,
            )?,
            Duration::new(2, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut self.event_manager,
                    &[initial_corpus_dir.clone()],
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "Failed to load initial corpus at {:?}: {}",
                        &initial_corpus_dir, err
                    )
                });
            info!("We imported {} inputs from disk.", state.corpus().count());
        }

        if let Some(max_iters) = max_iters {
            fuzzer.fuzz_loop_for(
                &mut stages,
                &mut executor,
                &mut state,
                &mut self.event_manager,
                max_iters,
            )?;
        } else {
            fuzzer.fuzz_loop(
                &mut stages,
                &mut executor,
                &mut state,
                &mut self.event_manager,
            )?;
        }
        Ok(())
    }
}

type ConcreteMinimizer<C, R, SC> =
    IndexesLenTimeMinimizerScheduler<QueueScheduler, Trace, ConcreteState<C, R, SC>>;

type ConcreteObservers<'a> = (
    TimeObserver,
    (HitcountsMapObserver<StdMapObserver<'a, u8>>, ()),
);

type ConcreteFeedback<'a, C, R, SC> = CombinedFeedback<
    MapFeedback<
        Trace,
        DifferentIsNovel,
        HitcountsMapObserver<StdMapObserver<'a, u8>>,
        MaxReducer,
        ConcreteState<C, R, SC>,
        u8,
    >,
    TimeFeedback,
    LogicEagerOr,
    Trace,
    ConcreteState<C, R, SC>,
>;

impl<'harness, 'a, H, SC, C, R, EM, OF>
    RunClientBuilder<
        'harness,
        H,
        C,
        R,
        SC,
        EM,
        ConcreteFeedback<'a, C, R, SC>,
        OF,
        ConcreteObservers<'a>,
        ConcreteMinimizer<C, R, SC>,
    >
where
    C: Corpus<Trace> + fmt::Debug,
    R: Rand,
    SC: Corpus<Trace> + fmt::Debug,
    H: FnMut(&Trace) -> ExitKind,
    OF: Feedback<Trace, ConcreteState<C, R, SC>>,
    EM: EventFirer<Trace>
        + EventRestarter<ConcreteState<C, R, SC>>
        + EventManager<
            ConcreteExecutor<'harness, H, ConcreteObservers<'a>, ConcreteState<C, R, SC>>,
            Trace,
            ConcreteState<C, R, SC>,
            StdFuzzer<
                ConcreteMinimizer<C, R, SC>,
                ConcreteFeedback<'a, C, R, SC>,
                Trace,
                OF,
                ConcreteObservers<'a>,
                ConcreteState<C, R, SC>,
            >,
        > + ProgressReporter<Trace>,
{
    fn install_minimizer(self) -> Self {
        let (feedback, observers) = {
            let time_observer = TimeObserver::new("time");
            let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", unsafe {
                &mut super::EDGES_MAP[0..super::MAX_EDGES_NUM]
            }));
            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
                MaxMapFeedback::new_tracking(&edges_observer, true, false),
                // Time feedback, this one does not need a feedback state
                // needed for IndexesLenTimeMinimizerCorpusScheduler
                TimeFeedback::new_with_observer(&time_observer)
            );
            let observers = tuple_list!(time_observer, edges_observer);
            (feedback, observers)
        };
        self.with_feedback(feedback)
            .with_observers(observers)
            .with_scheduler(IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new()))
    }
}

/// Starts the fuzzing loop
pub fn start(config: FuzzerConfig) {
    info!("Running on {} cores", &config.core_definition);

    let mut run_client =
        |state: Option<StdState<_, Trace, _, _>>,
         event_manager: LlmpRestartingEventManager<Trace, _, _, StdShMemProvider>,
         _unknown: usize|
         -> Result<(), Error> {
            PUT_REGISTRY.make_deterministic();
            let seed = config
                .static_seed
                .unwrap_or(event_manager.mgr_id().id as u64);
            info!("Seed is {}", seed);
            RunClientBuilder::new(config.clone(), &mut harness::harness, state, event_manager)
                .with_rand(StdRand::with_seed(seed))
                .with_corpus(CachedOnDiskCorpus::new(config.corpus_dir.clone(), 1000).unwrap())
                .with_objective_corpus(OnDiskCorpus::new(config.objective_dir.clone()).unwrap())
                .with_objective(feedback_or!(CrashFeedback::new(), TimeoutFeedback::new()))
                .install_minimizer()
                .run_client()
        };

    let cores = Cores::from_cmdline(config.core_definition.as_str()).unwrap();
    let configuration: EventConfig = "launcher default".into();
    let sh_mem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let launch_result = match config.monitor {
        true => libafl::bolts::launcher::Launcher::builder()
            .shmem_provider(sh_mem_provider)
            .configuration(configuration)
            .monitor(TuiMonitor::new("test".to_string(), false))
            .run_client(&mut run_client)
            .cores(&cores)
            .broker_port(config.broker_port)
            //todo where should we log the output of the harness?
            /*.stdout_file(Some("/dev/null"))*/
            .build()
            .launch(),
        false => libafl::bolts::launcher::Launcher::builder()
            .shmem_provider(sh_mem_provider)
            .configuration(configuration)
            .monitor(
                PuffinMonitor::new(
                    |s| {
                        info!("{}", s);
                    },
                    config.monitor_file.clone(),
                )
                .unwrap(),
            )
            .run_client(&mut run_client)
            .cores(&cores)
            .broker_port(config.broker_port)
            //todo where should we log the output of the harness?
            /*.stdout_file(Some("/dev/null"))*/
            .build()
            .launch(),
    };
    if let Err(error) = launch_result {
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
