use core::time::Duration;
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;

use libafl::corpus::ondisk::OnDiskMetadataFormat;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use log::LevelFilter;
use log4rs::Handle;

use super::harness;
use crate::fuzzer::bit_mutations::{
    bit_mutations_dy, havoc_mutations_dy, MakeMessage, ReadMessage,
};
use crate::fuzzer::mutations::{dy_mutations, MutationConfig};
use crate::fuzzer::stages::FocusScheduledMutator;
use crate::fuzzer::stats_monitor::StatsMonitor;
use crate::log::{load_fuzzing_client, set_experiment_fuzzing_client};
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put::PutDescriptor;
use crate::put_registry::PutRegistry;
use crate::trace::Trace;

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";
const MIN_BIT_EXECS: usize = 5_000; // one 1 core
const MIN_BIT_CORPUS: usize = 200; // on 1 core

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
    pub log_folder: PathBuf,
    pub is_experiment: bool,
    pub verbosity: LevelFilter, // level for the client logging
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            initial_corpus_dir: PathBuf::from("corpus"),
            static_seed: None,
            max_iters: None,
            core_definition: "1".to_string(),
            stats_file: PathBuf::from("stats.json"),
            corpus_dir: PathBuf::from("corpus"),
            objective_dir: PathBuf::from("objective_corpus"),
            broker_port: 1337,
            minimizer: false,
            tui: false,
            no_launcher: false,
            log_folder: PathBuf::from("logs"),
            is_experiment: false,
            verbosity: LevelFilter::Info, // default verbosity
            mutation_stage_config: Default::default(),
            mutation_config: Default::default(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct MutationStageConfig {
    /// How many iterations each stage gets, as an upper bound
    /// It may randomly continue earlier. Each iteration works on a different Input from the corpus
    pub max_iterations_per_stage: u64,
    pub max_mutations_per_iteration: u64,
}

impl Default for MutationStageConfig {
    //  TODO:EVAL: evaluate modifications of this config
    fn default() -> Self {
        Self {
            max_iterations_per_stage: 128, // Was the default of StdMutationalStage (=128)
            max_mutations_per_iteration: 32, /* With TuneableScheduledMutator, we set the
                                            * probability
                                            * to mutate n times for 1 <= n <=
                                            * max_mutations_per_iteration to be (2/n)/N (N: to
                                            * normalize. */
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

        /*
        Standard AFL-like configuration:
        A: Main mutator with StdScheduledMutator
            1. Compute the number of iterations im used to apply stacked mutations: 1 << (1 + rand(0<= r <= 7))
            2. For each time (0..im) : Apply randomly a mutation from the given list (here havoc)
          ==> let mutator = StdScheduledMutator::new(havoc_mutations());
        B: Main mutational stage with StdMutationalStage:
            1. Take the scheduled input from the corpus
            2. Pick a random iterations is between 1 and 128 (default)
            3. For each 0..is: clone input, mutate using mutator, execute
          ==> let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        C: We provide a list of stages: all of them are run one after the other, on the same scheduled testcase though. We might want to add more stages in the future, in particular https://docs.rs/libafl/0.15.0/libafl/stages/tmin/struct.StdTMinMutationalStage.html; see https://docs.rs/libafl/0.15.0/libafl/stages/index.html#modules

        Note: A minimization+queue policy to get test cases from the corpus
          ==> let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        Warning: To achieve this, the fuzzer maintains a state that describes which test cases are short and take a short time to execute. Internally, LibAFL attaches metadata to the fuzzer state ( TopRatedsMetadata) and test cases ( IsFavoredMetadata and MapIndexesMetadata). The important part to note here is that this specific scheduler depends on having an observer who can track indices. This is true for our edges_observer because we used the track_indices function when setting it up. For more information, refer to the source code.
        ------------
        We adapt this to our specific setup:
           ==> let mut stages = tuple_list!(stage_dy, stage_bit);
        where:
         - stage_dy is a StdScheduledMutator stage over DY mutations, enabled when DY mutations are
         - stage_bit is a StdScheduledMutator with only 1 run stage over bit-level mutations, enabled when bit mutations are enabled and when sufficiently many executions and corpus testcases have been done/found
        */

        // ==== DY mutational stage
        let mutator_dy = StdScheduledMutator::new(dy_mutations(
            mutation_config,
            <PT>::signature(),
            put_registry,
        ));
        // Always run DY mutations (if enabled)
        let cb_dy =
            |_: &mut _, _: &mut _, _: &mut _, _: &mut _, _idx: CorpusId| -> Result<bool, Error> {
                if mutation_config.with_dy {
                    log::debug!("[*] DY StdMutationalStage");
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            };
        let stage_dy = IfStage::new(cb_dy, tuple_list!(StdMutationalStage::new(mutator_dy)));

        // ==== Bit-level mutational stage
        let mutator_bit = StdScheduledMutator::new(bit_mutations_dy::<
            StdState<Trace<PT>, C, R, SC>,
            PB,
        >(mutation_config, put_registry));
        // Run bit-levlel muts. if bit-level enabled + already sufficiently advanced (to save a bit
        // of time)
        let cb_bit_level = |_: &mut _,
                            _: &mut _,
                            state: &mut ConcreteState<C, R, SC, Trace<PT>>,
                            _: &mut _,
                            _idx: CorpusId|
         -> Result<bool, Error> {
            if !mutation_config.with_bit_level {
                return Ok(false);
            }
            // Return false if the campaign is not advanced enough (per client/core), except if no
            // DY
            if !mutation_config.with_dy
                || (*state.executions() > MIN_BIT_EXECS && state.corpus().count() > MIN_BIT_CORPUS)
            {
                log::debug!("[*] BIT StdMutationalStage");
                return Ok(true);
            } else {
                return Ok(false);
            }
        };
        let mutator_bit_focus = FocusScheduledMutator::new(
            tuple_list!(MakeMessage::new(mutation_config, put_registry)),
            havoc_mutations_dy::<StdState<Trace<PT>, C, R, SC>>(mutation_config),
            tuple_list!(ReadMessage::new(mutation_config, put_registry)),
        );

        let stage_bit = IfStage::new(
            cb_bit_level,
            tuple_list!(
                StdMutationalStage::new(mutator_bit), // Old-style stage
                StdMutationalStage::new(mutator_bit_focus)
            ), // Focus stage, first MakeMessage, then HAVOC, then ReadMessage
        );

        // ==== All stages put together
        let mut stages = tuple_list!(stage_dy, stage_bit);

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
        ConcreteFeedback<'a, ConcreteState<C, R, SC, Trace<PT>>>,
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
pub fn start<'harness, PB>(
    put_registry: &'harness PutRegistry<PB>,
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
        stats_file,
        broker_port,
        tui,
        no_launcher,
        is_experiment,
        log_folder,
        verbosity,
        ..
    } = &config;

    log::info!("Running on cores: {}", &core_definition);
    log::info!("Config: {:?}\n\nlog_handle: {:?}", &config, &log_handle);

    let mut run_client = |state: Option<StdState<Trace<PB::ProtocolTypes>, _, _, _>>,
                          event_manager: LlmpRestartingEventManager<_, StdShMemProvider>,
                          _core_id: CoreId|
     -> Result<(), Error> {
        if *is_experiment {
            log_handle
                .clone()
                .set_config(set_experiment_fuzzing_client(log_folder, *verbosity));
        } else {
            log_handle.clone().set_config(load_fuzzing_client());
        }
        log::info!("log_handle: {:?}", &log_handle);

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
            log::warn!("Running without minimizer is unsupported");
            let (feedback, observer) = builder.create_feedback_observers();
            builder = builder
                .with_feedback(feedback)
                .with_observers(observer)
                .with_scheduler(RandScheduler::new());
        } // TODO:EVAL investigate using QueueScheduler instead (see https://github.com/AFLplusplus/LibAFL/blob/8445ae54b34a6cea48ae243d40bb1b1b94493898/libafl_sugar/src/inmemory.rs#L190)

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
        let out_path = log_folder.join("puffin_main_broker_stdout.log");
        let out_file = out_path
            .to_str()
            .expect("failed to create path to redirect fuzzer clients' stdout");
        let err_path = log_folder.join("puffin_main_broker_stderr.log");
        let err_file = err_path
            .to_str()
            .expect("failed to create path to redirect fuzzer clients' stderr");

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
                .stderr_file(Some(err_file))
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
                .stderr_file(Some(err_file))
                .build()
                .launch()
        }
    }
}
