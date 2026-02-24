use core::time::Duration;
use std::fmt;
use std::marker::PhantomData;

use libafl::corpus::ondisk::OnDiskMetadataFormat;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use log4rs::Handle;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::harness;
use crate::fuzzer::bit_mutations::{
    bit_mutations_dy, havoc_mutations_dy, MakeMessage, ReadMessage,
};
pub(crate) use crate::fuzzer::config::FuzzerConfig;
use crate::fuzzer::config::{FuzzingTarget, MIN_BIT_CORPUS, MIN_BIT_EXECS};
use crate::fuzzer::feedback::MinimizingFeedback;
use crate::fuzzer::mutations::{dy_mutations, MutationConfig};
use crate::fuzzer::stages::FocusScheduledMutator;
use crate::fuzzer::stats_monitor::StatsMonitor;
use crate::fuzzer::stats_stage::{StatsStage, CORPUS_EXEC, CORPUS_EXEC_MINIMAL};
use crate::log::{load_fuzzing_client, set_experiment_fuzzing_client};
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{ConfigTrace, Spawner, Trace, TraceContext};

pub const MAP_FEEDBACK_NAME: &str = "edges";
const EDGES_OBSERVER_NAME: &str = "edges_observer";

type ConcreteExecutor<'harness, EM, H, I, OT, S, Z> =
    InProcessExecutor<'harness, EM, H, I, OT, S, Z>;

type ConcreteState<C, R, SC, I> = StdState<C, I, R, SC>;

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
    C: Corpus<Trace<PT>> + Serialize + DeserializeOwned,
    R: Rand,
    SC: Corpus<Trace<PT>> + Serialize + DeserializeOwned,
    H: FnMut(&Trace<PT>) -> ExitKind,
    CS: Scheduler<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>,
    F: Feedback<EM, Trace<PT>, OT, ConcreteState<C, R, SC, Trace<PT>>>,
    OF: Feedback<EM, Trace<PT>, OT, ConcreteState<C, R, SC, Trace<PT>>>,
    OT: ObserversTuple<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>
        + Serialize
        + DeserializeOwned,
    EM: EventFirer<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>
        + EventRestarter<ConcreteState<C, R, SC, Trace<PT>>>
        + SendExiting
        + EventReceiver<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>
        + ProgressReporter<ConcreteState<C, R, SC, Trace<PT>>>,
    ConcreteState<C, R, SC, Trace<PT>>: HasClientPerfMonitor + HasMetadata + HasExecutions,
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
        A: Main mutator with HavocScheduledMutator
            1. Compute the number `im` of iterations of stacked mutations: 1 << (1 + rand(0 <= r <= 7))
            2. For each time (0..im) : Apply randomly a mutation from the given list (here havoc)
          ==> let mutator = HavocScheduledMutator::new(...);
        B: Main mutational stage with StdMutationalStage:
            1. Take the scheduled input from the corpus
            2. Pick a random iterations is between 1 and 128 (default)
            3. For each 0..is: clone input, mutate using mutator, execute
          ==> let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        C: We provide a list of stages: all of them are run one after the other, on the same scheduled testcase though.
        Note: We might want to add more stages in the future, in particular https://docs.rs/libafl/0.15.0/libafl/stages/tmin/struct.StdTMinMutationalStage.html; see https://docs.rs/libafl/0.15.0/libafl/stages/index.html#modules
        ------------
        We adapt this to our specific setup:
           ==> let mut stages = tuple_list!(stage_dy, stage_bit);
        where:
         - stage_dy is a HavocScheduledMutator stage over DY mutations, enabled when DY mutations are
         - stage_bit is a HavocScheduledMutator with only 1 run stage over bit-level mutations, enabled
         when bit mutations are enabled and when sufficiently many executions and corpus testcases have been done/found

         We refine this initial design below with the addition of a Focused stage where the payload
         on which we'll apply HAVOC mutations is first randomly chosen for the whole mutational stage.
        */

        // ==== DY mutational stage
        let mutation_config_dy = MutationConfig {
            with_focus: false,
            ..mutation_config
        };
        let mutator_dy = HavocScheduledMutator::new(dy_mutations(
            mutation_config_dy,
            <PT>::signature(),
            put_registry,
        ));
        // Always run DY mutations (if enabled)
        let cb_dy = |_: &mut _, _: &mut _, _: &mut _, _: &mut _| -> Result<bool, Error> {
            if mutation_config.with_dy {
                log::debug!("[*] DY StdMutationalStage");
                Ok(true)
            } else {
                Ok(false)
            }
        };
        let stage_dy = IfStage::new(
            cb_dy,
            tuple_list!(StdMutationalStage::with_max_iterations(
                mutator_dy,
                self.config.mutation_stage_config.max_iterations_per_stage
            )),
        );

        // ==== Bit-level mutational stage
        let mutation_config_bit = MutationConfig {
            with_focus: false,
            ..mutation_config
        };
        let mutator_bit = HavocScheduledMutator::new(bit_mutations_dy::<
            StdState<C, Trace<PT>, R, SC>,
            PT,
            PB,
        >(mutation_config_bit, put_registry));
        // Run bit-level muts. if bit-level enabled + already sufficiently advanced (to save a bit
        // of time)
        let cb_bit_level = |_: &mut _,
                            _: &mut _,
                            state: &mut ConcreteState<C, R, SC, Trace<PT>>,
                            _: &mut _|
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
                Ok(true)
            } else {
                Ok(false)
            }
        };
        let mutation_config_focus = mutation_config; // focus is already sets to the wanted value
        let mutator_bit_focus = FocusScheduledMutator::new(
            tuple_list!(MakeMessage::new(mutation_config_focus, put_registry)),
            havoc_mutations_dy::<StdState<C, Trace<PT>, R, SC>, PT>(mutation_config_focus),
            tuple_list!(ReadMessage::new(mutation_config_focus, put_registry)),
        );
        let cb_focus_bit_level = |_: &mut _,
                                  _: &mut _,
                                  _: &mut ConcreteState<C, R, SC, Trace<PT>>,
                                  _: &mut _|
         -> Result<bool, Error> {
            if !mutation_config.with_focus {
                return Ok(false);
            }
            log::debug!("[*] BIT FocusScheduledMutator");
            Ok(true)
        };
        let stage_bit = IfStage::new(
            cb_bit_level,
            tuple_list!(
                StdMutationalStage::with_max_iterations(
                    mutator_bit,
                    self.config.mutation_stage_config.max_iterations_per_stage
                ), // Old-style HAVOC stage
                IfStage::new(
                    cb_focus_bit_level,
                    tuple_list!(StdMutationalStage::with_max_iterations(
                        mutator_bit_focus,
                        self.config.mutation_stage_config.max_iterations_per_stage
                    ),)
                ),
            ), // Focus stage, first MakeMessage, then HAVOC, then ReadMessage
        );
        // A stage that only enables in introspection mode and executes each testcase in corpus
        // prior to executing other stages on it
        let stage_test_input = ClosureStage::new(
            |_: &mut _,
             _: &mut _,
             cs: &mut ConcreteState<C, R, SC, Trace<PT>>,
             _: &mut _|
             -> Result<(), Error> {
                if cfg!(feature = "introspection") {
                    CORPUS_EXEC.increment();
                    log::debug!("[*] Introspection stage");

                    // If there is no current testcase (e.g., empty corpus / no scheduled item),
                    // just skip.
                    let Some(current_idx) = cs.corpus().current() else {
                        return Ok(());
                    };

                    let mut current_testcase = cs.corpus().get(*current_idx)?.borrow_mut();
                    // Input will already be loaded.
                    let current_input = current_testcase.load_input(cs.corpus()).unwrap();
                    let spawner = Spawner::new(put_registry.clone());
                    let mut ctx = TraceContext::new_config(
                        spawner,
                        ConfigTrace {
                            with_bit_level: self.config.mutation_config.with_bit_level,
                            ..Default::default()
                        },
                    );
                    let error_ok;
                    match current_input.execute_until_step_wrap(
                        &mut ctx,
                        current_input.len(),
                        &mut 0,
                        true,
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
        let mut stages = tuple_list!(stage_test_input, stage_dy, stage_bit, StatsStage::new());

        let mut fuzzer: StdFuzzer<CS, F, _, _, OF> =
            StdFuzzer::new(self.scheduler.unwrap(), feedback, objective);

        let mut executor: ConcreteExecutor<
            'harness,
            EM,
            H,
            Trace<PT>,
            OT,
            ConcreteState<C, R, SC, Trace<PT>>,
            StdFuzzer<CS, F, _, _, OF>,
        > = InProcessExecutor::with_timeout(
            self.harness_fn,
            // hint: edges_observer is expensive to serialize (only noticeable if we add all
            // inputs to the corpus)
            self.observers.unwrap(),
            &mut fuzzer,
            &mut state,
            &mut self.event_manager,
            Duration::new(5, 0),
        )?;

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

type EdgesObserver = HitcountsMapObserver<StdMapObserver<'static, u8, false>>;
type EdgesTracking = ExplicitTracking<EdgesObserver, true, false>;

type ConcreteObservers<'a> = (EdgesTracking, (TimeObserver, ()));

type ConcreteFeedback<'a> =
    CombinedFeedback<MaxMapFeedback<EdgesTracking, EdgesObserver>, TimeFeedback, LogicEagerOr>;

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
                    CachedOnDiskCorpus<Trace<PT>>,
                    Trace<PT>,
                    RomuDuoJrRand,
                    CachedOnDiskCorpus<Trace<PT>>,
                >,
                PT,
            >,
            ConcreteFeedback<'a>,
            LogicEagerOr,
        >,
        OF,
        ConcreteObservers<'a>,
        CS,
        PT,
    >
where
    Trace<PT>: Input,
    //ConcreteState<C, R, SC, Trace<PT>>: Input,
    C: Corpus<Trace<PT>> + fmt::Debug,
    R: Rand,
    SC: Corpus<Trace<PT>> + fmt::Debug,
    H: FnMut(&Trace<PT>) -> ExitKind,
    OF: Feedback<EM, Trace<PT>, ConcreteObservers<'a>, ConcreteState<C, R, SC, Trace<PT>>>,
    CS: Scheduler<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>,
    EM: EventFirer<Trace<PT>, ConcreteState<C, R, SC, Trace<PT>>>
        + EventRestarter<ConcreteState<C, R, SC, Trace<PT>>>
        + HasEventManagerId
        + ProgressReporter<ConcreteState<C, R, SC, Trace<PT>>>,
    ConcreteState<C, R, SC, Trace<PT>>: HasClientPerfMonitor + HasMetadata + HasExecutions,
    PT: ProtocolTypes + 'static,
{
    fn create_feedback_observers(&self) -> (ConcreteFeedback<'a>, ConcreteObservers<'a>) {
        #[cfg(not(test))]
        let map = unsafe {
            pub use libafl_targets::{EDGES_MAP, MAX_EDGES_FOUND};
            &mut EDGES_MAP[0..MAX_EDGES_FOUND]
        };

        #[cfg(test)]
        let map = unsafe {
            // When testing we should not import libafl_targets, else it conflicts with sancov_dummy
            pub const EDGES_MAP_SIZE: usize = 65536;
            pub static mut EDGES_MAP: [u8; EDGES_MAP_SIZE] = [0; EDGES_MAP_SIZE];
            pub static mut MAX_EDGES_FOUND: usize = 0;
            &mut EDGES_MAP[0..MAX_EDGES_FOUND]
        };

        {
            let time_observer = TimeObserver::new("time");
            let edges_observer =
                HitcountsMapObserver::new(unsafe { StdMapObserver::new(EDGES_OBSERVER_NAME, map) });

            let edges_observer = edges_observer.track_indices();

            let map_feedback = MaxMapFeedback::with_name(MAP_FEEDBACK_NAME, &edges_observer);

            let feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback
                // state `track_indexes` needed because of
                // IndexesLenTimeMinimizerCorpusScheduler
                map_feedback,
                // Time feedback, this one does not need a feedback state
                // needed for IndexesLenTimeMinimizerCorpusScheduler
                TimeFeedback::new(&time_observer)
            );
            let observers = tuple_list!(edges_observer, time_observer);
            (feedback, observers)
        }
    }
}

/// Starts the fuzzing loop
pub fn start<PB>(
    put_registry: &PutRegistry<PB>,
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
        mutation_stage_config,
        is_experiment,
        log_folder,
        verbosity,
        target,
        ..
    } = &config;

    log::info!("Running on cores: {}", &core_definition);
    log::info!("Config: {:?}\n\nlog_handle: {:?}", &config, &log_handle);

    let mut run_client = |state: Option<StdState<_, Trace<PB::ProtocolTypes>, _, _>>,
                          event_manager: LlmpRestartingEventManager<
        _,
        Trace<PB::ProtocolTypes>,
        StdState<_, Trace<PB::ProtocolTypes>, _, _>,
        _,
        StdShMemProvider,
    >,
                          _client_description: ClientDescription|
     -> Result<(), Error> {
        if *is_experiment {
            log_handle
                .clone()
                .set_config(set_experiment_fuzzing_client(log_folder, *verbosity));
        } else {
            log_handle.clone().set_config(load_fuzzing_client());
        }
        log::info!("log_handle: {:?}", &log_handle);

        let default_put = put_registry.default_put_descriptor();

        // Choose a harness to do single target/differential fuzzing
        // We can't directly return a closure since they don't have the same
        // signature so we return a boxed closure that we call in the next closure
        let mut boxed_harness_fn: Box<dyn FnMut(&Trace<PB::ProtocolTypes>) -> ExitKind> =
            match target {
                FuzzingTarget::Single(put) => {
                    let put_desc = if let Some(put_desc) = put {
                        put_desc
                    } else {
                        &default_put
                    };
                    Box::new(|input: &_| harness::harness::<PB>(put_registry, put_desc, input))
                }
                FuzzingTarget::Differential(first, second) => Box::new(|input: &_| {
                    harness::differential_harness::<PB>(put_registry, first, second, input)
                }),
            };

        let harness_fn = &mut (|input: &_| boxed_harness_fn(input));

        let mut builder = RunClientBuilder::new(config.clone(), harness_fn, state, event_manager);
        builder = builder
            .with_initial_inputs(PB::create_corpus(put_registry.default_put().clone()))
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

        run_client(
            state,
            restarting_mgr,
            ClientDescription::new(0, 0, CoreId(0)),
        )
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
