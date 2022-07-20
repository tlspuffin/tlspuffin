use core::time::Duration;
use std::{fmt, fmt::Debug, path::PathBuf};

use libafl::{
    bolts::{
        core_affinity::Cores,
        rands::{Rand, StdRand},
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsRefIterator,
    },
    corpus::{ondisk::OnDiskMetadataFormat, CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{
        setup_restarting_mgr_std, EventConfig, EventFirer, EventManager, EventRestarter,
        HasEventManagerId, LlmpRestartingEventManager, ProgressReporter,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{
        CombinedFeedback, CrashFeedback, DifferentIsNovel, Feedback, LogicEagerOr, MapFeedback,
        MaxMapFeedback, MaxReducer, TimeFeedback, TimeoutFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::{tui::TuiMonitor, MultiMonitor},
    observers::{HitcountsMapObserver, MapObserver, ObserversTuple, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler, Scheduler},
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasNamedMetadata, StdState},
    Error, Evaluator,
};
use log::{info, warn};
use log4rs::Handle;
use serde::{de::DeserializeOwned, Serialize};

use super::harness;
use crate::{
    algebra::set_current_signature,
    fuzzer::{
        mutations::{trace_mutations, util::TermConstraints},
        stages::{PuffinMutationalStage, PuffinScheduledMutator},
        stats_monitor::StatsMonitor,
        stats_stage::StatsStage,
    },
    log::create_file_config,
    put_registry::{ProtocolBehavior, PutRegistry},
    trace::Trace,
};

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";

type ConcreteExecutor<'harness, H, OT, S> =
    TimeoutExecutor<InProcessExecutor<'harness, H, Trace, OT, S>>;

type ConcreteState<C, R, SC> = StdState<C, Trace, R, SC>;

#[derive(Clone)]
pub struct FuzzerConfig<PB: ProtocolBehavior + Clone + 'static> {
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
    pub no_launcher: bool,
    pub log_file: PathBuf,
    pub put_registry: &'static dyn PutRegistry<PB>,
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
            min_trace_length: 2,
            term_constraints: TermConstraints {
                min_term_size: 0,
                max_term_size: 300,
            },
        }
    }
}

struct RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, PB>
where
    C: Corpus<Trace>,
    R: Rand,
    SC: Corpus<Trace>,
    PB: ProtocolBehavior + Clone + 'static,
{
    config: FuzzerConfig<PB>,

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

impl<'harness, H, C, R, SC, EM, F, OF, OT, CS, PB>
    RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, PB>
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
    PB: ProtocolBehavior + Clone + 'static,
{
    fn new(
        config: FuzzerConfig<PB>,
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
            max_iters,
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
            put_registry,
            ..
        } = self.config;

        let mutations = trace_mutations(
            min_trace_length,
            max_trace_length,
            term_constraints,
            fresh_zoo_after,
            PB::signature(),
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
            Duration::new(5, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().is_empty() {
            if initial_corpus_dir.exists() {
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
                info!("Imported {} inputs from disk.", state.corpus().count());
            } else {
                warn!("Initial seed corpus not found. Using embedded seeds.");

                for (seed, name) in PB::create_corpus() {
                    info!("Using seed {}", name);
                    fuzzer
                        .add_input(&mut state, &mut executor, &mut self.event_manager, seed)
                        .expect("Failed to add input");
                }
            }
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

impl<'harness, 'a, H, SC, C, R, EM, OF, PB>
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
        PB,
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
    PB: ProtocolBehavior + Clone + 'static,
{
    fn install_minimizer(self) -> Self {
        #[cfg(not(test))]
        let map = unsafe {
            pub use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
            &mut EDGES_MAP[0..MAX_EDGES_NUM]
        };

        #[cfg(test)]
        let map = unsafe {
            // When testing we should not import libafl_targets, else it conflicts with sancov_dummy
            pub const EDGES_MAP_SIZE: usize = 65536;
            pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
            pub static mut MAX_EDGES_NUM: usize = 0;
            &mut EDGES_MAP[0..MAX_EDGES_NUM]
        };

        let map_feedback = MaxMapFeedback::with_names_tracking(
            MAP_FEEDBACK_NAME,
            EDGES_OBSERVER_NAME,
            true,
            false,
        );

        let (feedback, observers) = {
            let time_observer = TimeObserver::new("time");
            let edges_observer =
                HitcountsMapObserver::new(StdMapObserver::new(EDGES_OBSERVER_NAME, map));
            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
                map_feedback,
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
pub fn start<PB: ProtocolBehavior + Clone + 'static>(
    config: FuzzerConfig<PB>,
    log_handle: Handle,
) -> Result<(), libafl::Error> {
    let FuzzerConfig {
        core_definition,
        corpus_dir,
        objective_dir,
        static_seed,
        log_file,
        monitor_file,
        broker_port,
        monitor,
        no_launcher,
        ..
    } = &config;

    info!("Running on cores: {}", &core_definition);

    let mut run_client =
        |state: Option<StdState<_, Trace, _, _>>,
         event_manager: LlmpRestartingEventManager<Trace, _, _, StdShMemProvider>,
         _unknown: usize|
         -> Result<(), Error> {
            let seed = static_seed.unwrap_or(event_manager.mgr_id().id as u64);
            info!("Seed is {}", seed);
            let harness_fn = &mut harness::harness::<PB>;

            let mut builder =
                RunClientBuilder::new(config.clone(), harness_fn, state, event_manager);
            builder = builder
                .with_rand(StdRand::with_seed(seed))
                .with_corpus(
                    CachedOnDiskCorpus::new_save_meta(
                        corpus_dir.clone(),
                        Some(OnDiskMetadataFormat::Json),
                        1000,
                    )
                    .unwrap(),
                )
                .with_objective_corpus(
                    OnDiskCorpus::new_save_meta(
                        objective_dir.clone(),
                        Some(OnDiskMetadataFormat::JsonPretty),
                    )
                    .unwrap(),
                )
                .with_objective(feedback_or!(CrashFeedback::new(), TimeoutFeedback::new()));

            #[cfg(feature = "sancov_libafl")]
            {
                builder = builder.install_minimizer();
            }

            #[cfg(not(feature = "sancov_libafl"))]
            {
                log::error!("Running without minimizer is unsupported");
                builder = builder
                    .with_feedback(())
                    .with_observers(())
                    .with_scheduler(libafl::schedulers::RandScheduler::new());
            }

            log_handle.clone().set_config(create_file_config(log_file));

            builder.run_client()
        };

    if *no_launcher {
        let (state, restarting_mgr) = setup_restarting_mgr_std(
            StatsMonitor::new(
                |s| {
                    info!("{}", s);
                },
                monitor_file.clone(),
            )
            .unwrap(),
            *broker_port,
            EventConfig::AlwaysUnique,
        )?;

        run_client(state, restarting_mgr, 0)
    } else {
        let cores = Cores::from_cmdline(config.core_definition.as_str()).unwrap();
        let configuration: EventConfig = "launcher default".into();
        let sh_mem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        if *monitor {
            libafl::bolts::launcher::Launcher::builder()
                .shmem_provider(sh_mem_provider)
                .configuration(configuration)
                .monitor(TuiMonitor::new("test".to_string(), false))
                .run_client(&mut run_client)
                .cores(&cores)
                .broker_port(*broker_port)
                .build()
                .launch()
        } else {
            libafl::bolts::launcher::Launcher::builder()
                .shmem_provider(sh_mem_provider)
                .configuration(configuration)
                .monitor(
                    StatsMonitor::new(
                        |s| {
                            info!("{}", s);
                        },
                        monitor_file.clone(),
                    )
                    .unwrap(),
                )
                .run_client(&mut run_client)
                .cores(&cores)
                .broker_port(*broker_port)
                // There is no need to disable the stdout of the clients.
                // tlspuffin never logs or outputs to stdout. It always logs its output
                // to tlspuffin-log.json.
                // Therefore, this the following has no effect: .stdout_file(Some("/dev/null"))
                .build()
                .launch()
        }
    }
}
