//! Stats to display both cumulative and per-client stats

use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use dyn_clone::DynClone;
use libafl::monitors::stats::*;
use libafl::monitors::tui::TuiMonitor;
use libafl::prelude::*;
use libafl_bolts::prelude::{current_time, ClientId};
use serde::Serialize;
use serde_json::Serializer as JSONSerializer;

use crate::fuzzer::libafl_setup::MAP_FEEDBACK_NAME;
use crate::fuzzer::stats_stage::{RuntimeStats, DUPLICATES, STATS};

trait ClonableMonitor: Monitor + DynClone {}
impl ClonableMonitor for TuiMonitor {}
impl ClonableMonitor for NopMonitor {}
dyn_clone::clone_trait_object!(ClonableMonitor);

/// Tracking stats during fuzzing and display both per-client and cumulative info.
pub struct StatsMonitor {
    monitor: Box<dyn ClonableMonitor>,
    handlers: Vec<Box<dyn EventHandler>>,
    stats_interval: Duration,
    last_client_write: HashMap<ClientId, Instant>,
    last_global_write: Instant,
}

impl Clone for StatsMonitor {
    fn clone(&self) -> Self {
        Self {
            monitor: self.monitor.clone(),
            handlers: self.handlers.clone(),
            stats_interval: self.stats_interval,
            last_client_write: HashMap::new(),
            last_global_write: Instant::now() - self.stats_interval,
        }
    }
}

impl StatsMonitor {
    pub fn with_tui_output(stats_file: PathBuf, stats_interval: Duration) -> Self {
        let monitor = Box::new(
            TuiMonitor::builder()
                .title(String::from("tlspuffin [press q to exit]"))
                .enhanced_graphics(true)
                .build(),
        );
        let handlers: Vec<Box<dyn EventHandler>> =
            vec![Box::new(JSONEventHandler::new(stats_file))];

        Self::new(monitor, handlers, stats_interval)
    }

    pub fn with_raw_output(stats_file: PathBuf, stats_interval: Duration) -> Self {
        let monitor = Box::new(NopMonitor::new());
        let handlers: Vec<Box<dyn EventHandler>> = vec![
            Box::new(|_, msg: &str, stats: &Statistics| log::info!("[{}] {}", msg, stats)),
            Box::new(JSONEventHandler::new(stats_file)),
        ];

        Self::new(monitor, handlers, stats_interval)
    }

    fn new(
        monitor: Box<dyn ClonableMonitor>,
        handlers: Vec<Box<dyn EventHandler>>,
        stats_interval: Duration,
    ) -> Self {
        Self {
            monitor,
            handlers,
            stats_interval,
            last_client_write: HashMap::new(),
            last_global_write: Instant::now() - stats_interval,
        }
    }

    fn client(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        id: ClientId,
    ) -> Result<Statistics, Error> {
        client_stats_manager.update_client_stats_for(id, |client| {
            #[cfg(feature = "introspection")]
            let introspect_feature = {
                let intro_stats = &client.introspection_stats;
                let elapsed_cycles = intro_stats.elapsed_cycles();
                let elapsed = if elapsed_cycles == 0 {
                    1.0
                } else {
                    elapsed_cycles as f32
                };

                // calculate mean across all used stages in `introspect_features`
                let mut introspect_features = IntrospectFeatures::new();

                for (_, features) in intro_stats.used_stages() {
                    for (feature_index, feature) in features.iter().enumerate() {
                        // Calculate this current stage's percentage
                        let feature_percent = *feature as f32 / elapsed;

                        // Ignore this feature if it isn't used
                        if feature_percent == 0.0 {
                            continue;
                        }

                        // Get the actual feature from the feature index for printing its name
                        let feature: PerfFeature = feature_index.into();

                        // Write the percentage for this feature
                        introspect_features.record(&feature, feature_percent);
                    }

                    // todo measure self.feedbacks()
                }

                IntrospectStatistics {
                    scheduler: intro_stats.scheduler_cycles() as f32 / elapsed,
                    manager: intro_stats.manager_cycles() as f32 / elapsed,
                    elapsed_cycles,
                    introspect_features,
                }
            };

            let cur_time = current_time();
            let exec_sec = client.execs_per_sec(cur_time);
            let total_execs = client.executions();

            let trace = TraceStatistics::new(client);
            let mut error_counter = ErrorStatistics::new(total_execs);

            error_counter.count(client);

            let corpus_size = client.corpus_size();
            let objective_size = client.objective_size();

            let coverage =
                client
                    .user_stats()
                    .get(MAP_FEEDBACK_NAME)
                    .and_then(|s| match s.value() {
                        UserStatsValue::Ratio(a, b) => {
                            Some(CoverageStatistics { hit: *a, max: *b })
                        }
                        _ => None,
                    });

            let duplicates = get_number(client, DUPLICATES.name);

            Statistics::Client(ClientStatistics {
                id: id.0,
                time: SystemTime::now(),
                trace,
                errors: error_counter,
                #[cfg(feature = "introspection")]
                intro: introspect_feature,
                coverage,
                corpus_size,
                objective_size,
                total_execs,
                exec_per_sec: exec_sec as u64,
                duplicates,
            })
        })
    }

    fn global(&mut self, client_stats_manager: &mut ClientStatsManager) -> Statistics {
        let duplicates: u64 = client_stats_manager
            .client_stats()
            .values()
            .map(|client| get_number(client, DUPLICATES.name))
            .sum();

        let global_stats = client_stats_manager.global_stats();

        Statistics::Global(GlobalStatistics {
            time: SystemTime::now(),

            clients: global_stats.client_stats_count as u32,
            corpus_size: global_stats.corpus_size,
            objective_size: global_stats.objective_size,
            duplicates,
            total_execs: global_stats.total_execs,
            exec_per_sec: global_stats.execs_per_sec as u64,
        })
    }

    fn dispatch(&mut self, sender: ClientId, msg: &str, stats: &Statistics) {
        self.handlers
            .iter_mut()
            .for_each(|h| h.process(sender, msg, stats));
    }
}

impl Monitor for StatsMonitor {
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        _event_msg: &str,
        sender_id: ClientId,
    ) -> Result<(), Error> {
        client_stats_manager.client_stats_insert(sender_id)?;

        // Rate limit logging of stats to once every interval for each client (core) and global
        // Normalize event message name as filtering makes event names inconsistent and no longer
        // relatable
        let now = Instant::now();
        let event_msg = "Monitor";

        let last_client = self
            .last_client_write
            .get(&sender_id)
            .copied()
            .unwrap_or(now - self.stats_interval);

        if now.duration_since(last_client) >= self.stats_interval {
            self.last_client_write.insert(sender_id, now);
            let client_stats = self.client(client_stats_manager, sender_id)?;
            self.dispatch(sender_id, event_msg, &client_stats);
        }

        // Rate limit logging of stats to once every interval for global,
        // it has its own timer but can be logged only if a client sends a signal
        if now.duration_since(self.last_global_write) >= self.stats_interval {
            self.last_global_write = now;
            let global_stats = self.global(client_stats_manager);
            self.dispatch(sender_id, event_msg, &global_stats);
        }

        self.monitor
            .display(client_stats_manager, event_msg, sender_id)?;
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum Statistics {
    #[serde(rename = "client")]
    Client(ClientStatistics),
    #[serde(rename = "global")]
    Global(GlobalStatistics),
}

impl Display for Statistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(client_stats) => {
                write!(
                    f,
                    "(CLIENT) id: {}, corpus: {}, obj: {}, execs: {}, exec/sec: {}",
                    client_stats.id,
                    client_stats.corpus_size,
                    client_stats.objective_size,
                    client_stats.total_execs,
                    client_stats.exec_per_sec
                )?;

                if let Some(CoverageStatistics { hit, max }) = client_stats.coverage {
                    match max {
                        0 => write!(f, ", edges: {hit}/{max}"),
                        _ => write!(f, ", edges: {hit}/{max} ({}%)", hit * 100 / max),
                    }
                } else {
                    Ok(())
                }
            }

            Self::Global(global_stats) => {
                write!(
                    f,
                    "(GLOBAL) clients: {}, corpus: {}, obj: {}, execs: {}, exec/sec: {}",
                    global_stats.clients,
                    global_stats.corpus_size,
                    global_stats.objective_size,
                    global_stats.total_execs,
                    global_stats.exec_per_sec,
                )
            }
        }
    }
}

#[derive(Serialize)]
struct GlobalStatistics {
    time: SystemTime,

    clients: u32,

    corpus_size: u64,
    objective_size: u64,

    total_execs: u64,
    exec_per_sec: u64,
    duplicates: u64,
}

#[derive(Serialize)]
struct ClientStatistics {
    /// Some log file unique id
    id: u32,
    time: SystemTime,
    errors: ErrorStatistics,
    trace: TraceStatistics,
    #[cfg(feature = "introspection")]
    intro: IntrospectStatistics,
    coverage: Option<CoverageStatistics>,

    corpus_size: u64,
    objective_size: u64,
    total_execs: u64,
    exec_per_sec: u64,
    duplicates: u64,
}

#[derive(Serialize)]
struct CoverageStatistics {
    hit: u64,
    max: u64,
}

#[cfg(feature = "introspection")]
#[derive(Serialize)]
struct IntrospectStatistics {
    scheduler: f32,
    manager: f32,
    elapsed_cycles: u64,
    introspect_features: IntrospectFeatures,
}

#[cfg(feature = "introspection")]
#[derive(Serialize)]
struct IntrospectFeatures {
    get_input_from_corpus: f32,
    mutate: f32,
    mutate_post_exec: f32,
    target_execution: f32,
    pre_exec: f32,
    post_exec: f32,
    pre_exec_observers: f32,
    post_exec_observers: f32,
    get_feedback_interesting_all: f32,
    get_objectives_interesting_all: f32,
}

/// Aggregates error and execution statistics for a fuzzing client.
///
/// This struct collects counts for various error types and execution outcomes,
/// as defined by the `RuntimeStats` variants. It is used to summarize and report
/// the number of occurrences for each tracked event during fuzzing.
///
/// Fields:
/// - `total_execs`: Total number of executions performed by the client
/// - `all_term_eval`: Total number of term evaluations.
/// - `all_term_eval_success`: Number of successful term evaluations.
/// - `variable_eval` / `variable_eval_fail`: query evaluations, and those left unanswered.
/// - `deconstructor_eval`: Number of `DYTerm::Deconstructor` node evaluations.
/// - `deconstructor_eval_fail`: Number of deconstructor evaluations that failed because no
///   sub-value of the target type matched the query (the symbol's own failure mode); the ratio
///   `deconstructor_eval_fail / deconstructor_eval` is its extraction-failure rate.
/// - `eval_*_error`: Number of X errors when evaluating a term
/// - `all_exec`: Total number of trace executions.
/// - `all_exec_success`: Number of successful trace executions.
/// - `all_exec_agent_success`: Number of successful trace executions where all agents are in a
///   successful state.
/// - `harness_exec`: Number of harness trace executions.
/// - `harness_exec_success`: Number of successful harness trace executions.
/// - `harness_exec_agent_success`: Number of successful harness trace executions where all agents
///   are eventually successful.
/// - `bit_exec`: Number of bit-level trace executions (Make Message and Read Message).
/// - `bit_exec_success`: Number of successful bit-level executions (Make Message and Read Message).
/// - `mm_exec`: Same as bit_exec but only when focused.
/// - `mm_exec_success`: Same as bit_exec_success but only when focused.
/// - `fn_error`: Number of function errors encountered while the harness execute traces.
/// - `term_error`: Number of term errors encountered while the harness execute traces.
/// - `term_bug_error`: Number of term bug errors encountered while the harness execute traces.
/// - `codec_error`: Number of codec errors encountered while the harness execute traces.
/// - `put_error`: Number of put errors encountered while the harness execute traces.
/// - `io_error`: Number of I/O errors encountered while the harness execute traces.
/// - `agent_error`: Number of agent errors encountered while the harness execute traces.
/// - `stream_error`: Number of stream errors encountered while the harness execute traces.
/// - `extraction_error`: Number of extraction errors encountered while the harness execute traces.
/// - `corpus_exec`: Number of executions of corpus testcases that were successful without any
///   errors.
/// - `corpus_exec_minimal`: Number of executions of corpus testcases that were successful without
///   any errors except PUT or security claim violation errors on last step.
#[derive(Serialize)]
struct ErrorStatistics {
    #[serde(skip)]
    #[allow(dead_code)]
    total_execs: u64,
    // Term eval
    eval_fn_crypto_error: u64,
    eval_fn_malformed_error: u64,
    eval_fn_unknown_error: u64,
    eval_fn_codec_error: u64,
    eval_term_error: u64,
    eval_termbug_error: u64,
    eval_codec_error: u64,
    all_term_eval: u64,
    all_term_eval_success: u64,
    // Deconstructor eval: `deconstructor_eval_fail / deconstructor_eval` is the deconstructor
    // symbol's extraction-failure rate, comparable to `1 - all_term_eval_success / all_term_eval`.
    deconstructor_eval: u64,
    deconstructor_eval_fail: u64,
    variable_eval: u64,
    variable_eval_fail: u64,

    // Trace exec
    fn_error: u64,
    term_error: u64,
    term_bug_error: u64,
    codec_error: u64,
    put_error: u64,
    io_error: u64,
    agent_error: u64,
    stream_error: u64,
    extraction_error: u64,
    all_exec: u64,
    all_exec_success: u64,
    all_exec_agent_success: u64,
    harness_exec: u64,
    harness_exec_success: u64,
    harness_exec_agent_success: u64,
    bit_exec: u64,
    bit_exec_success: u64,
    mm_exec: u64,
    mm_exec_success: u64,

    corpus_exec: u64,
    corpus_exec_minimal: u64,
    duplicates: u64,
}

#[derive(Serialize)]
struct TraceStatistics {
    min_trace_length: Option<u64>,
    max_trace_length: Option<u64>,
    mean_trace_length: Option<u64>,

    max_nb_payload: Option<u64>,
    mean_nb_payload: Option<u64>,

    min_payload_size: Option<u64>,
    max_payload_size: Option<u64>,
    mean_payload_size: Option<u64>,

    min_term_size: Option<u64>,
    max_term_size: Option<u64>,
    mean_term_size: Option<u64>,
}

#[cfg(feature = "introspection")]
impl IntrospectFeatures {
    pub fn new() -> Self {
        Self {
            get_input_from_corpus: 0.0,
            mutate: 0.0,
            mutate_post_exec: 0.0,
            target_execution: 0.0,
            pre_exec: 0.0,
            post_exec: 0.0,
            pre_exec_observers: 0.0,
            post_exec_observers: 0.0,
            get_feedback_interesting_all: 0.0,
            get_objectives_interesting_all: 0.0,
        }
    }

    fn make_mean(value: &mut f32, new_value: f32) {
        if *value == 0.0 {
            *value = new_value
        } else {
            *value = (*value + new_value) / 2_f32
        }
    }

    pub fn record(&mut self, feature: &PerfFeature, relative_cycles: f32) {
        match feature {
            PerfFeature::GetInputFromCorpus => {
                Self::make_mean(&mut self.get_input_from_corpus, relative_cycles)
            }
            PerfFeature::Mutate => Self::make_mean(&mut self.mutate, relative_cycles),
            PerfFeature::MutatePostExec => {
                Self::make_mean(&mut self.mutate_post_exec, relative_cycles)
            }
            PerfFeature::TargetExecution => {
                Self::make_mean(&mut self.target_execution, relative_cycles)
            }
            PerfFeature::PreExec => Self::make_mean(&mut self.pre_exec, relative_cycles),
            PerfFeature::PostExec => Self::make_mean(&mut self.post_exec, relative_cycles),
            PerfFeature::PreExecObservers => {
                Self::make_mean(&mut self.pre_exec_observers, relative_cycles)
            }
            PerfFeature::PostExecObservers => {
                Self::make_mean(&mut self.post_exec_observers, relative_cycles)
            }
            PerfFeature::GetFeedbackInterestingAll => {
                Self::make_mean(&mut self.get_feedback_interesting_all, relative_cycles)
            }
            PerfFeature::GetObjectivesInterestingAll => {
                Self::make_mean(&mut self.get_objectives_interesting_all, relative_cycles)
            }
            PerfFeature::Count => {}
        }
    }
}

#[cfg(feature = "introspection")]
impl Default for IntrospectFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorStatistics {
    pub const fn new(total_execs: u64) -> Self {
        Self {
            total_execs,
            eval_fn_crypto_error: 0,
            eval_fn_malformed_error: 0,
            eval_fn_unknown_error: 0,
            eval_fn_codec_error: 0,
            eval_term_error: 0,
            eval_termbug_error: 0,
            fn_error: 0,
            term_error: 0,
            term_bug_error: 0,
            all_term_eval: 0,
            all_term_eval_success: 0,
            deconstructor_eval: 0,
            deconstructor_eval_fail: 0,
            variable_eval: 0,
            variable_eval_fail: 0,
            all_exec: 0,
            all_exec_success: 0,
            all_exec_agent_success: 0,
            harness_exec: 0,
            harness_exec_success: 0,
            harness_exec_agent_success: 0,
            bit_exec: 0,
            bit_exec_success: 0,
            mm_exec: 0,
            mm_exec_success: 0,
            codec_error: 0,
            put_error: 0,
            io_error: 0,
            agent_error: 0,
            stream_error: 0,
            extraction_error: 0,
            corpus_exec: 0,
            corpus_exec_minimal: 0,
            duplicates: 0,
            eval_codec_error: 0,
        }
    }

    pub fn count(&mut self, client_stats: &ClientStats) {
        for stat_definition in &STATS {
            match stat_definition {
                RuntimeStats::EvalFnCryptoError(c) => {
                    self.eval_fn_crypto_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalFnMalformedError(c) => {
                    self.eval_fn_malformed_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalFnUnknownError(c) => {
                    self.eval_fn_unknown_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalFnCodecError(c) => {
                    self.eval_fn_codec_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalTermError(c) => {
                    self.eval_term_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalTermBugError(c) => {
                    self.eval_termbug_error += get_number(client_stats, c.name)
                }
                RuntimeStats::EvalCodecError(c) => {
                    self.eval_codec_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllFnError(c) => self.fn_error += get_number(client_stats, c.name),
                RuntimeStats::AllTermError(c) => {
                    self.term_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllTermBugError(c) => {
                    self.term_bug_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllCodecError(c) => {
                    self.codec_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllPutError(c) => self.put_error += get_number(client_stats, c.name),
                RuntimeStats::AllIOError(c) => self.io_error += get_number(client_stats, c.name),
                RuntimeStats::AllAgentError(c) => {
                    self.agent_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllStreamError(c) => {
                    self.stream_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllExtractionError(c) => {
                    self.extraction_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AllTermEval(c) => {
                    self.all_term_eval += get_number(client_stats, c.name)
                }
                RuntimeStats::AllTermEvalSuccess(c) => {
                    self.all_term_eval_success += get_number(client_stats, c.name)
                }
                RuntimeStats::DeconstructorEval(c) => {
                    self.deconstructor_eval += get_number(client_stats, c.name)
                }
                RuntimeStats::DeconstructorEvalFail(c) => {
                    self.deconstructor_eval_fail += get_number(client_stats, c.name)
                }
                RuntimeStats::VariableEval(c) => {
                    self.variable_eval += get_number(client_stats, c.name)
                }
                RuntimeStats::VariableEvalFail(c) => {
                    self.variable_eval_fail += get_number(client_stats, c.name)
                }
                RuntimeStats::AllExec(c) => self.all_exec += get_number(client_stats, c.name),
                RuntimeStats::AllExecSuccess(c) => {
                    self.all_exec_success += get_number(client_stats, c.name)
                }
                RuntimeStats::AllExecAgentSuccess(c) => {
                    self.all_exec_agent_success += get_number(client_stats, c.name)
                }
                RuntimeStats::HarnessExec(c) => {
                    self.harness_exec += get_number(client_stats, c.name)
                }
                RuntimeStats::HarnessExecSuccess(c) => {
                    self.harness_exec_success += get_number(client_stats, c.name)
                }
                RuntimeStats::HarnessExecAgentSuccess(c) => {
                    self.harness_exec_agent_success += get_number(client_stats, c.name)
                }
                RuntimeStats::BitExec(c) => self.bit_exec += get_number(client_stats, c.name),
                RuntimeStats::BitExecSuccess(c) => {
                    self.bit_exec_success += get_number(client_stats, c.name)
                }
                RuntimeStats::MMExec(c) => self.mm_exec += get_number(client_stats, c.name),
                RuntimeStats::MMNExecSuccess(c) => {
                    self.mm_exec_success += get_number(client_stats, c.name)
                }
                RuntimeStats::CorpusExec(c) => self.corpus_exec += get_number(client_stats, c.name),
                RuntimeStats::CorpusExecMinimal(c) => {
                    self.corpus_exec_minimal += get_number(client_stats, c.name)
                }
                RuntimeStats::Duplicates(c) => self.duplicates += get_number(client_stats, c.name),
                // MinMaxMean stats are not counted in ErrorStatistics
                RuntimeStats::TraceLength(_) => {}
                RuntimeStats::NbPayload(_) => {}
                RuntimeStats::PayloadLength(_) => {}
                RuntimeStats::TermSize(_) => {}
            }
        }
    }
}

fn get_number(user_stats: &ClientStats, name: &str) -> u64 {
    user_stats
        .user_stats()
        .get(name)
        .and_then(|s| match s.value() {
            UserStatsValue::Number(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0u64)
}

impl TraceStatistics {
    pub fn new(user_stats: &ClientStats) -> Self {
        let mut trace_stats = Self {
            min_trace_length: None,
            max_trace_length: None,
            mean_trace_length: None,
            max_nb_payload: None,
            mean_nb_payload: None,
            min_payload_size: None,
            max_payload_size: None,
            mean_payload_size: None,
            min_term_size: None,
            max_term_size: None,
            mean_term_size: None,
        };

        // Sum for all TraceLength and TermSize
        for stat_definition in &STATS {
            match stat_definition {
                RuntimeStats::TraceLength(mmm) => {
                    trace_stats.min_trace_length =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-min")));
                    trace_stats.max_trace_length =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-max")));
                    trace_stats.mean_trace_length =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-mean")));
                }
                RuntimeStats::TermSize(mmm) => {
                    trace_stats.min_term_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-min")));
                    trace_stats.max_term_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-max")));
                    trace_stats.mean_term_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-mean")));
                }
                RuntimeStats::NbPayload(mmm) => {
                    trace_stats.max_nb_payload =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-max")));
                    trace_stats.mean_nb_payload =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-mean")));
                }
                RuntimeStats::PayloadLength(mmm) => {
                    trace_stats.min_payload_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-min")));
                    trace_stats.max_payload_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-max")));
                    trace_stats.mean_payload_size =
                        Some(get_number(user_stats, &(mmm.name.to_owned() + "-mean")));
                }
                _ => {}
            }
        }

        trace_stats
    }
}

trait EventHandler: DynClone {
    fn process(&mut self, source: ClientId, msg: &str, stats: &Statistics);
}

dyn_clone::clone_trait_object!(EventHandler);

impl<F> EventHandler for F
where
    F: FnMut(ClientId, &str, &Statistics) + Clone + 'static,
{
    fn process(&mut self, source: ClientId, msg: &str, stats: &Statistics) {
        self(source, msg, stats);
    }
}

struct JSONEventHandler {
    output_path: PathBuf,
    writer: BufWriter<File>,
}

impl JSONEventHandler {
    fn new<P>(output_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let writer = BufWriter::new({
            let mut o = OpenOptions::new();
            OpenOptions::append(&mut o, true);
            o.create(true).open(output_path.as_ref()).unwrap()
        });

        Self {
            output_path: output_path.as_ref().to_path_buf(),
            writer,
        }
    }
}

impl Clone for JSONEventHandler {
    fn clone(&self) -> Self {
        Self::new(self.output_path.clone())
    }
}

impl EventHandler for JSONEventHandler {
    fn process(&mut self, _source: ClientId, _msg: &str, stats: &Statistics) {
        let mut serializer = JSONSerializer::new(&mut self.writer);
        stats.serialize(&mut serializer).unwrap();
        self.writer.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use libafl::monitors::stats::ClientStatsManager;
    use libafl_bolts::prelude::ClientId;

    use super::*;

    #[test]
    fn test_display_with_unregistered_client_id_0() {
        let mut monitor =
            StatsMonitor::with_raw_output(PathBuf::from("/dev/null"), Duration::from_secs(1));
        let mut mgr = ClientStatsManager::default();
        // Simule le broker heartbeat : ClientId(0) non encore enregistré
        monitor
            .display(&mut mgr, "Broker Heartbeat", ClientId(0))
            .expect("display should not fail for unregistered ClientId(0)");
    }
}
