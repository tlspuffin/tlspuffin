use core::time::Duration;
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;

use libafl::corpus::ondisk::OnDiskMetadataFormat;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use log4rs::Handle;

use super::harness;
use crate::fuzzer::feedback::MinimizingFeedback;
use crate::fuzzer::mutations::{trace_mutations, MutationConfig};
use crate::fuzzer::stages::PuffinMutationalStage;
use crate::fuzzer::stats_monitor::StatsMonitor;
use crate::fuzzer::stats_stage::{StatsStage, CORPUS_EXEC, CORPUS_EXEC_MINIMAL};
use crate::log::load_fuzzing_client;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::PutDescriptor;
use crate::put_registry::PutRegistry;
use crate::trace::{Spawner, Trace, TraceContext};

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
    pub stats_file: PathBuf,
    pub corpus_dir: PathBuf,
    pub objective_dir: PathBuf,
    pub broker_port: u16,
    pub minimizer: bool, // FIXME: support this property
    pub mutation_stage_config: MutationStageConfig,
    pub mutation_config: MutationConfig,
    pub tui: bool,
    pub no_launcher: bool,
    pub log_file: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct MutationStageConfig {
    /// How many iterations each stage gets, as an upper bound
    /// It may randomly continue earlier. Each iteration works on a different Input from the corpus
    pub max_iterations_per_stage: u64,
    pub max_mutations_per_iteration: u64,
    // Whether to truncate the input after mutations, prior to adding it to the corpus
    pub with_truncation: bool,
}

impl Default for MutationStageConfig {
    //  TODO:EVAL: evaluate modifications of this config
    fn default() -> Self {
        Self {
            max_iterations_per_stage: 256,
            max_mutations_per_iteration: 16,
            with_truncation: true,
        }
    }
}

struct RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, PT>
where
    PT: ProtocolTypes + 'static,
{
    config: FuzzerConfig,

    harness_fn: &'harness mut H,
    existing_state: Option<ConcreteState<C, R, SC, Trace<PT>>>,
    rand: Option<R>,
    objective_corpus: Option<SC>,
    corpus: Option<C>,
    scheduler: Option<CS>,
    event_manager: EM,
    observers: Option<OT>,
    feedback: Option<F>,
    objective: Option<OF>,
    initial_inputs: Option<Vec<(Trace<PT>, &'static str)>>,
    phantom_data: PhantomData<PT>,
}

impl<'harness, H, C, R, SC, EM, F, OF, OT, CS, PT>
    RunClientBuilder<'harness, H, C, R, SC, EM, F, OF, OT, CS, PT>
where
    ConcreteState<C, R, SC, Trace<PT>>: UsesInput<Input = Trace<PT>>,
    C: Corpus + UsesInput<Input = Trace<PT>>,
    R: Rand,
    SC: Corpus + UsesInput<Input = Trace<PT>>,
    H: FnMut(&Trace<PT>) -> ExitKind,
    CS: Scheduler + UsesState<State = ConcreteState<C, R, SC, Trace<PT>>>,
    F: Feedback<ConcreteState<C, R, SC, Trace<PT>>>,
    OF: Feedback<ConcreteState<C, R, SC, Trace<PT>>>,
    OT: ObserversTuple<ConcreteState<C, R, SC, Trace<PT>>>
        + serde::Serialize
        + serde::de::DeserializeOwned,
    EM: EventFirer
        + EventRestarter
        + EventManager<
            ConcreteExecutor<'harness, H, OT, ConcreteState<C, R, SC, Trace<PT>>>,
            StdFuzzer<CS, F, OF, OT>,
        > + ProgressReporter
        + UsesState<State = ConcreteState<C, R, SC, Trace<PT>>>,
    <EM as UsesState>::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
    PT: ProtocolTypes + 'static,
{
    fn new(
        config: FuzzerConfig,
        harness_fn: &'harness mut H,
        existing_state: Option<ConcreteState<C, R, SC, Trace<PT>>>,
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
            phantom_data: Default::default(),
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

    fn with_initial_inputs(mut self, initial_inputs: Vec<(Trace<PT>, &'static str)>) -> Self {
        self.initial_inputs = Some(initial_inputs);
        self
    }

    fn run_client<PB>(mut self, put_registry: &'harness PutRegistry<PB>) -> Result<(), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT> + 'static,
    {
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
            mutation_config,
            ..
        } = self.config;

        // ==== DY mutational stage
        let mutator_dy = StdScheduledMutator::new(trace_mutations(
            mutation_config,
            <PT>::signature(),
            put_registry,
        ));
        // Always run DY mutations (if enabled)
        let cb_dy =
            |_: &mut _, _: &mut _, _: &mut _, _: &mut _, _idx: CorpusId| -> Result<bool, Error> {
                log::debug!("[*] DY StdMutationalStage");
                Ok(true)
            };
        let stage_dy = IfStage::new(
            cb_dy,
            tuple_list!(PuffinMutationalStage::new(
                mutator_dy,
                self.config.mutation_stage_config.max_iterations_per_stage
            )),
        );

        // A stage that only enables in introspection mode and executes each testcase in corpus
        // prior to executing other stages on it
        let stage_test_input = ClosureStage::new(
            |_: &mut _,
             _: &mut _,
             cs: &mut ConcreteState<C, R, SC, Trace<PT>>,
             _: &mut _,
             idx: CorpusId|
             -> Result<(), Error> {
                if cfg!(feature = "introspection") {
                    CORPUS_EXEC.increment();
                    log::debug!("[*] Introspection stage");
                    let current_testcase = cs.corpus().get(idx)?.borrow_mut();
                    // Input will already be loaded.
                    let current_input = current_testcase.input().as_ref().unwrap();
                    let spawner = Spawner::new(put_registry.clone());
                    let mut ctx = TraceContext::new(spawner);
                    let error_ok;
                    match current_input.execute_until_step_wrap(
                        &mut ctx,
                        current_input.len(),
                        &mut 0,
                    ) {
                        Ok(()) => {
                            CORPUS_EXEC_MINIMAL.increment();
                            return Ok(());
                        }
                        Err(e) => match e {
                            crate::error::Error::Put(_) => {
                                error_ok = true;
                            }
                            crate::error::Error::SecurityClaim(_) => {
                                error_ok = true;
                            }
                            _ => {
                                // Other error: not OK (no increment of CORPUS_EXEC_SUCCESS)
                                return Ok(());
                            }
                        },
                    }
                    if error_ok {
                        // If it failed because of the PUT or the security claim, we only consider
                        // the testcase to be "minimal" if it failed at the very last step
                        if ctx.executed_until == current_input.len() - 1 {
                            CORPUS_EXEC_MINIMAL.increment();
                            return Ok(());
                        }
                    }
                }
                Ok(())
            },
        );

        // ==== All stages put together
        let mut stages = tuple_list!(stage_test_input, stage_dy, StatsStage::new());

        let mut fuzzer: StdFuzzer<CS, F, OF, OT> =
            StdFuzzer::new(self.scheduler.unwrap(), feedback, objective);

        let mut executor: ConcreteExecutor<'harness, H, OT, _> = TimeoutExecutor::new(
            InProcessExecutor::new(
                self.harness_fn,
                // hint: edges_observer is expensive to serialize (only noticeable if we add all
                // inputs to the corpus)
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
                log::info!("Imported {} inputs from disk.", state.corpus().count());
            } else {
                log::info!("Initial seed corpus not found. Using embedded seeds.");

                for (seed, name) in self.initial_inputs.unwrap() {
                    log::info!("Using seed {}", name);
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

impl<'harness, 'a, H, SC, C, R, EM, OF, CS, PT>
    RunClientBuilder<
        'harness,
        H,
        C,
        R,
        SC,
        EM,
        CombinedFeedback<
            MinimizingFeedback<
                StdState<
                    Trace<PT>,
                    CachedOnDiskCorpus<Trace<PT>>,
                    RomuDuoJrRand,
                    CachedOnDiskCorpus<Trace<PT>>,
                >,
                PT,
            >,
            CombinedFeedback<
                MapFeedback<
                    DifferentIsNovel,
                    HitcountsMapObserver<StdMapObserver<'_, u8, false>>,
                    MaxReducer,
                    StdState<
                        Trace<PT>,
                        CachedOnDiskCorpus<Trace<PT>>,
                        RomuDuoJrRand,
                        CachedOnDiskCorpus<Trace<PT>>,
                    >,
                    u8,
                >,
                TimeFeedback,
                LogicEagerOr,
                StdState<
                    Trace<PT>,
                    CachedOnDiskCorpus<Trace<PT>>,
                    RomuDuoJrRand,
                    CachedOnDiskCorpus<Trace<PT>>,
                >,
            >,
            LogicEagerOr,
            StdState<
                Trace<PT>,
                CachedOnDiskCorpus<Trace<PT>>,
                RomuDuoJrRand,
                CachedOnDiskCorpus<Trace<PT>>,
            >,
        >,
        OF,
        ConcreteObservers<'a>,
        CS,
        PT,
    >
where
    ConcreteState<C, R, SC, Trace<PT>>: UsesInput<Input = Trace<PT>>,
    C: Corpus + UsesInput<Input = Trace<PT>> + fmt::Debug,
    R: Rand,
    SC: Corpus + UsesInput<Input = Trace<PT>> + fmt::Debug,
    H: FnMut(&Trace<PT>) -> ExitKind,
    OF: Feedback<ConcreteState<C, R, SC, Trace<PT>>>,
    CS: Scheduler + UsesState<State = ConcreteState<C, R, SC, Trace<PT>>>,
    EM: EventFirer
        + EventRestarter
        + EventManager<
            ConcreteExecutor<
                'harness,
                H,
                ConcreteObservers<'a>,
                ConcreteState<C, R, SC, Trace<PT>>,
            >,
            StdFuzzer<
                ConcreteMinimizer<ConcreteState<C, R, SC, Trace<PT>>>,
                ConcreteFeedback<'a, ConcreteState<C, R, SC, Trace<PT>>>,
                OF,
                ConcreteObservers<'a>,
            >,
        > + ProgressReporter
        + UsesState<State = ConcreteState<C, R, SC, Trace<PT>>>,
    <EM as UsesState>::State: HasClientPerfMonitor + HasMetadata + HasExecutions,
    PT: ProtocolTypes + 'static,
{
    fn create_feedback_observers(
        &self,
    ) -> (
        ConcreteFeedback<'a, ConcreteState<C, R, SC, Trace<PT>>>,
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

        {
            let time_observer = TimeObserver::new("time");
            let edges_observer =
                HitcountsMapObserver::new(unsafe { StdMapObserver::new(EDGES_OBSERVER_NAME, map) });
            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback
                // state `track_indexes` needed because of
                // IndexesLenTimeMinimizerCorpusScheduler
                map_feedback,
                // Time feedback, this one does not need a feedback state
                // needed for IndexesLenTimeMinimizerCorpusScheduler
                TimeFeedback::with_observer(&time_observer)
            );
            let observers = tuple_list!(edges_observer, time_observer);
            (feedback, observers)
        }
    }
}

/// Starts the fuzzing loop
pub fn start<PB>(
    put_registry: &PutRegistry<PB>,
    put: PutDescriptor,
    config: FuzzerConfig,
    log_handle: Handle,
) -> Result<(), Error>
where
    PB: ProtocolBehavior + Clone + 'static,
{
    let FuzzerConfig {
        core_definition,
        corpus_dir,
        objective_dir,
        static_seed: _,
        log_file,
        stats_file,
        broker_port,
        tui,
        no_launcher,
        mutation_stage_config,
        ..
    } = &config;

    log::info!("Running on cores: {}", &core_definition);
    log::info!("Config: {:?}\n\nlog_handle: {:?}", &config, &log_handle);

    let mut run_client = |state: Option<StdState<Trace<PB::ProtocolTypes>, _, _, _>>,
                          event_manager: LlmpRestartingEventManager<_, StdShMemProvider>,
                          _core_id: CoreId|
     -> Result<(), Error> {
        log_handle.clone().set_config(load_fuzzing_client());

        let harness_fn = &mut (|input: &_| harness::harness::<PB>(put_registry, input));

        let mut builder = RunClientBuilder::new(config.clone(), harness_fn, state, event_manager);
        builder = builder
            .with_initial_inputs(PB::create_corpus(put.clone()))
            .with_rand(StdRand::new())
            .with_corpus(
                //InMemoryCorpus::new(),
                CachedOnDiskCorpus::with_meta_format(
                    corpus_dir.clone(),
                    4096, // mimicking libafl_sugar: https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/lib.rs#L78
                    Some(OnDiskMetadataFormat::Json),
                )
                .unwrap(),
            )
            .with_objective_corpus(
                CachedOnDiskCorpus::with_meta_format(
                    objective_dir.clone(),
                    4096, // mimicking libafl_sugar: https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/lib.rs#L78
                    Some(OnDiskMetadataFormat::Json),
                )
                .unwrap(),
            )
            .with_objective(feedback_or_fast!(
                // don't execute second if first is conclusive, mimicking https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/inmemory.rs#L164
                CrashFeedback::new(),
                TimeoutFeedback::new()
            ));

        //#[cfg(feature = "sancov")]
        //{
        /* let (feedback, observers) = builder.create_feedback_observers(); */
        /* builder = builder */
        /* .with_feedback(feedback) */
        /* .with_observers(observers) */
        /* .with_scheduler(IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new())); */
        //}

        //#[cfg(not(feature = "sancov"))]
        {
            // FIXME
            log::error!("Running without minimizer is unsupported");
            let (feedback, observer) = builder.create_feedback_observers();
            let feedback_with_minimizer = feedback_or!(
                MinimizingFeedback::new(mutation_stage_config.with_truncation),
                feedback
            );
            #[cfg(feature = "with-min-scheduler")]
            let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
            #[cfg(not(feature = "with-min-scheduler"))]
            let scheduler = RandScheduler::new();

            builder = builder
                .with_feedback(feedback_with_minimizer)
                .with_observers(observer)
                .with_scheduler(scheduler);
        } // TODO:EVAL investigate using QueueScheduler instead (see https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/inmemory.rs#L190)
          // TODO:EVAL: investigate this versus Rand, versus Queue, versus Minimizer
        builder.run_client(put_registry)
    };

    if *no_launcher {
        let stats_monitor = StatsMonitor::with_raw_output(stats_file.clone());

        let (state, restarting_mgr) =
            setup_restarting_mgr_std(stats_monitor, *broker_port, EventConfig::AlwaysUnique)?;

        run_client(state, restarting_mgr, CoreId(0))
    } else {
        let cores = Cores::from_cmdline(config.core_definition.as_str()).unwrap();
        let configuration: EventConfig = "launcher default".into();
        let sh_mem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        // NOTE tlspuffin's fuzzer should never write to stdout
        //
        // During fuzzing the logs are redirected to `log_file` (which is
        // usually `tlspuffin.log`) and there should be no reason to print
        // directly to stdout. We should therefore be able to safely discard the
        // log output of clients.
        //
        // To verify this assumption, we save the clients' output to a file that
        // should always be empty.
        let out_path = log_file.with_extension("out");
        let out_file = out_path
            .to_str()
            .expect("failed to create path to redirect fuzzer clients' stdout");

        if *tui {
            let stats_monitor = StatsMonitor::with_tui_output(stats_file.clone());

            Launcher::builder()
                .shmem_provider(sh_mem_provider)
                .configuration(configuration)
                .monitor(stats_monitor)
                .run_client(&mut run_client)
                .cores(&cores)
                .broker_port(*broker_port)
                .stdout_file(Some(out_file))
                .build()
                .launch()
        } else {
            let stats_monitor = StatsMonitor::with_raw_output(stats_file.clone());

            Launcher::builder()
                .shmem_provider(sh_mem_provider)
                .configuration(configuration)
                .monitor(stats_monitor)
                .run_client(&mut run_client)
                .cores(&cores)
                .broker_port(*broker_port)
                .stdout_file(Some(out_file))
                .build()
                .launch()
        }
    }
}
