use core::time::Duration;
use std::{fmt, path::PathBuf};

use libafl::{
    corpus::ondisk::OnDiskMetadataFormat,
    monitors::tui::{ui::TuiUI, TuiMonitor},
    prelude::*,
};
use log::{error, info, trace, LevelFilter};
use log4rs::Handle;

use super::harness;
use crate::{
    fuzzer::{
        mutations::trace_mutations,
        utils::TermConstraints,
        stats_monitor::StatsMonitor,
    },
    log::create_file_config,
    protocol::ProtocolBehavior,
    trace::Trace,
};

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";

type ConcreteExecutor<'harness, H, OT, S> = TimeoutExecutor<InProcessExecutor<'harness, H, OT, S>>;

type ConcreteState<C, R, SC, I> = StdState<I, C, R, SC>;

#[derive(Clone, Debug)]
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
    pub no_launcher: bool,
    pub log_file: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct MutationStageConfig {
    /// How many iterations each stage gets, as an upper bound
    /// It may randomly continue earlier. Each iteration works on a different Input from the corpus
    pub max_iterations_per_stage: u64,
    pub max_mutations_per_iteration: u64,
}

impl Default for MutationStageConfig {
    //  TODO:EVAL: evaluate modif to this config
    fn default() -> Self {
        Self {
            max_iterations_per_stage: 256,
            max_mutations_per_iteration: 16,
        }
    }
}

#[derive(Clone, Copy, Debug)]
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
    //  TODO:EVAL: evaluate modif to this config
    fn default() -> Self {
        Self {
            fresh_zoo_after: 100000,
            max_trace_length: 15,
            min_trace_length: 2,
            term_constraints: TermConstraints::default(),
        }
    }
}

struct RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, MT, I>
where
    I: Input,
{
    config: FuzzerConfig,

    harness_fn: &'harness mut H,
    existing_state: Option<ConcreteState<C, R, SC, I>>,
    rand: Option<R>,
    objective_corpus: Option<SC>,
    corpus: Option<C>,
    scheduler: Option<CS>,
    event_manager: EM,
    observers: Option<OT>,
    feedback: Option<F>,
    objective: Option<OF>,
    initial_inputs: Option<Vec<(I, &'static str)>>,
    mutations: Option<MT>,
}

impl<'harness, H, C, R, SC, EM, F, OF, OT, CS, MT, I>
    RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, MT, I>
where
    ConcreteState<C, R, SC, I>: UsesInput<Input = I>,
    I: Input + HasLen,
    C: Corpus + UsesInput<Input = I>,
    R: Rand,
    SC: Corpus + UsesInput<Input = I>,
    H: FnMut(&I) -> ExitKind,
    CS: Scheduler + UsesState<State = ConcreteState<C, R, SC, I>>,
    F: Feedback<ConcreteState<C, R, SC, I>>,
    OF: Feedback<ConcreteState<C, R, SC, I>>,
    OT: ObserversTuple<ConcreteState<C, R, SC, I>> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventFirer
        + EventRestarter
        + EventManager<
            ConcreteExecutor<'harness, H, OT, ConcreteState<C, R, SC, I>>,
            StdFuzzer<CS, F, OF, OT>,
        > + ProgressReporter
        + UsesState<State = ConcreteState<C, R, SC, I>>,
    MT: MutatorsTuple<I, ConcreteState<C, R, SC, I>>,
    <EM as UsesState>::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
{
    fn new(
        config: FuzzerConfig,
        harness_fn: &'harness mut H,
        existing_state: Option<ConcreteState<C, R, SC, I>>,
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
            initial_inputs: None,
            mutations: None,
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

    fn with_initial_inputs(mut self, initial_inputs: Vec<(I, &'static str)>) -> Self {
        self.initial_inputs = Some(initial_inputs);
        self
    }

    fn with_mutations(mut self, mutations: MT) -> Self {
        self.mutations = Some(mutations);
        self
    }

    fn run_client(mut self) -> Result<(), Error> {
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
                    max_iterations_per_stage: _,
                    max_mutations_per_iteration: _,
                },
            ..
        } = self.config;

        // FIXME let mutator = PuffinScheduledMutator::new(self.mutations.unwrap(), max_mutations_per_iteration);
        let mutator = StdScheduledMutator::new(self.mutations.unwrap());
        let mut stages = tuple_list!(
            // FIXMEPuffinMutationalStage::new(mutator, max_iterations_per_stage),
            StdMutationalStage::new(mutator),
            // FIXME StatsStage::new()
        );

        let mut fuzzer: StdFuzzer<CS, F, OF, OT> =
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
                info!("Initial seed corpus not found. Using embedded seeds.");

                for (seed, name) in self.initial_inputs.unwrap() {
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

type ConcreteMinimizer<S> = IndexesLenTimeMinimizerScheduler<QueueScheduler<S>>;

type ConcreteObservers<'a> = (
    HitcountsMapObserver<StdMapObserver<'a, u8, false>>,
    (TimeObserver, ()),
);

type ConcreteFeedback<'a, S> = CombinedFeedback<
    MapFeedback<
        DifferentIsNovel,
        HitcountsMapObserver<StdMapObserver<'a, u8, false>>,
        MaxReducer,
        S,
        u8,
    >,
    TimeFeedback,
    LogicEagerOr,
    S,
>;

impl<'harness, 'a, H, SC, C, R, EM, OF, CS, MT, I>
    RunClientBuilder<
        'harness,
        H,
        C,
        R,
        SC,
        EM,
        ConcreteFeedback<'a, ConcreteState<C, R, SC, I>>,
        OF,
        ConcreteObservers<'a>,
        CS,
        MT,
        I,
    >
where
    ConcreteState<C, R, SC, I>: UsesInput<Input = I>,
    I: Input + HasLen,
    C: Corpus + UsesInput<Input = I> + fmt::Debug,
    R: Rand,
    SC: Corpus + UsesInput<Input = I> + fmt::Debug,
    H: FnMut(&I) -> ExitKind,
    OF: Feedback<ConcreteState<C, R, SC, I>>,
    CS: Scheduler + UsesState<State = ConcreteState<C, R, SC, I>>,
    EM: EventFirer
        + EventRestarter
        + EventManager<
            ConcreteExecutor<'harness, H, ConcreteObservers<'a>, ConcreteState<C, R, SC, I>>,
            StdFuzzer<
                ConcreteMinimizer<ConcreteState<C, R, SC, I>>,
                ConcreteFeedback<'a, ConcreteState<C, R, SC, I>>,
                OF,
                ConcreteObservers<'a>,
            >,
        > + ProgressReporter
        + UsesState<State = ConcreteState<C, R, SC, I>>,
    MT: MutatorsTuple<I, ConcreteState<C, R, SC, I>>,
    <EM as UsesState>::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
{
    fn create_feedback_observers(
        &self,
    ) -> (
        ConcreteFeedback<'a, ConcreteState<C, R, SC, I>>,
        ConcreteObservers<'a>,
    ) {
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

        return {
            let time_observer = TimeObserver::new("time");
            let edges_observer =
                HitcountsMapObserver::new(unsafe { StdMapObserver::new(EDGES_OBSERVER_NAME, map) });
            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                // `track_indexes` needed because of IndexesLenTimeMinimizerCorpusScheduler
                map_feedback,
                // Time feedback, this one does not need a feedback state
                // needed for IndexesLenTimeMinimizerCorpusScheduler
                TimeFeedback::with_observer(&time_observer)
            );
            let observers = tuple_list!(edges_observer, time_observer);
            (feedback, observers)
        };
    }
}

/// Starts the fuzzing loop
pub fn start<PB: ProtocolBehavior + Clone + 'static>(
    config: FuzzerConfig,
    log_handle: Handle,
) -> Result<(), Error> {
    let FuzzerConfig {
        core_definition,
        corpus_dir,
        objective_dir,
        static_seed: _,
        log_file,
        monitor_file,
        broker_port,
        monitor,
        no_launcher,
        mutation_config:
            MutationConfig {
                fresh_zoo_after,
                max_trace_length,
                min_trace_length,
                term_constraints,
            },
        ..
    } = &config;

    info!("Running on cores: {}", &core_definition);

    info!("Config: {:?}\n\nlog_handle: {:?}", &config, &log_handle);

    let mut run_client = |state: Option<StdState<Trace<PB::Matcher>, _, _, _>>,
                          event_manager: LlmpRestartingEventManager<_, StdShMemProvider>,
                          _core_id: CoreId|
     -> Result<(), Error> {
        let harness_fn = &mut harness::harness::<PB>;

        let mut builder = RunClientBuilder::new(config.clone(), harness_fn, state, event_manager);
        builder = builder
            .with_mutations(trace_mutations::<_, _, PB>(
                *min_trace_length,
                *max_trace_length,
                *term_constraints,
                *fresh_zoo_after,
                PB::signature(),
            ))
            .with_initial_inputs(PB::create_corpus())
            .with_rand(StdRand::new())
            .with_corpus(
                //InMemoryCorpus::new(),
                CachedOnDiskCorpus::with_meta_format(
                    corpus_dir.clone(),
                    4096, // mimicking libafl_sugar: https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/lib.rs#L78
                    OnDiskMetadataFormat::Json,
                )
                .unwrap(),
            )
            .with_objective_corpus(
                CachedOnDiskCorpus::with_meta_format(
                    objective_dir.clone(),
                    4096, // mimicking libafl_sugar: https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/lib.rs#L78
                    OnDiskMetadataFormat::Json,
                )
                .unwrap(),
            )
            .with_objective(feedback_or_fast!(
                // don't execute second if first is conclusive, mimicking https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/inmemory.rs#L164
                CrashFeedback::new(),
                TimeoutFeedback::new()
            ));

        //#[cfg(feature = "sancov_libafl")]
        //{
        /*            let (feedback, observers) = builder.create_feedback_observers();*/
        /*            builder = builder*/
        /*                .with_feedback(feedback)*/
        /*                .with_observers(observers)*/
        /*                .with_scheduler(IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new()));*/
        //}

        //#[cfg(not(feature = "sancov_libafl"))]
        {
            // FIXME
            log::error!("Running without minimizer is unsupported");
            let (feedback, observer) = builder.create_feedback_observers();
            builder = builder
                .with_feedback(feedback)
                .with_observers(observer)
                .with_scheduler(RandScheduler::new());
        } // TODO:EVAL investigate using QueueScheduler instead (see https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/inmemory.rs#L190)

        // TODO: Allow configuring the following warn level
        log_handle
            .clone()
            .set_config(create_file_config(LevelFilter::Warn, log_file));

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

        run_client(state, restarting_mgr, CoreId(0))
    } else {
        let cores = Cores::from_cmdline(config.core_definition.as_str()).unwrap();
        let configuration: EventConfig = "launcher default".into();
        let sh_mem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        if *monitor {
            Launcher::builder()
                .shmem_provider(sh_mem_provider)
                .configuration(configuration)
                .monitor(TuiMonitor::new(TuiUI::new(String::from("test"), false)))
                .run_client(&mut run_client)
                .cores(&cores)
                .broker_port(*broker_port)
                // tlspuffin never logs or outputs to stdout. It always logs its output
                // to tlspuffin.log.
                // We can safely, disable the log output of clients.
                // [LH] Just to test this assumption:
                .stdout_file(Some(&format!(
                    "{}.should-be-empty.log",
                    monitor_file
                        .clone()
                        .into_os_string()
                        .into_string()
                        .expect("Fail")
                        .to_owned()
                )))
                .build()
                .launch()
        } else {
            Launcher::builder()
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
                // tlspuffin never logs or outputs to stdout. It always logs its output
                // to tlspuffin.log.
                // We can safely, disable the log output of clients.
                // [LH] Just to test this assumption:
                .stdout_file(Some(&format!(
                    "{}.should-be-empty.log",
                    monitor_file
                        .clone()
                        .into_os_string()
                        .into_string()
                        .expect("Fail")
                        .to_owned()
                )))
                .build()
                .launch()
        }
    }
}
