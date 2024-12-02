//! Stats to display both cumulative and per-client stats

use core::time::Duration;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use dyn_clone::DynClone;
use libafl::monitors::tui::ui::TuiUI;
use libafl::monitors::tui::TuiMonitor;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use serde::Serialize;
use serde_json::Serializer as JSONSerializer;

use crate::fuzzer::libafl_setup::MAP_FEEDBACK_NAME;
use crate::fuzzer::stats_stage::{RuntimeStats, STATS};

trait ClonableMonitor: Monitor + DynClone {}
impl ClonableMonitor for TuiMonitor {}
impl ClonableMonitor for NopMonitor {}
dyn_clone::clone_trait_object!(ClonableMonitor);

#[derive(Clone)]
/// Tracking stats during fuzzing and display both per-client and cumulative info.
pub struct StatsMonitor {
    monitor: Box<dyn ClonableMonitor>,
    handlers: Vec<Box<dyn EventHandler>>,
}

impl StatsMonitor {
    pub fn with_tui_output(stats_file: PathBuf) -> Self {
        let monitor = Box::new(TuiMonitor::new(TuiUI::new(
            String::from("tlspuffin [press q to exit]"),
            false,
        )));
        let handlers: Vec<Box<dyn EventHandler>> =
            vec![Box::new(JSONEventHandler::new(stats_file))];

        Self::new(monitor, handlers)
    }

    pub fn with_raw_output(stats_file: PathBuf) -> Self {
        let monitor = Box::new(NopMonitor::new());
        let handlers: Vec<Box<dyn EventHandler>> = vec![
            Box::new(|_, msg: &str, stats: &Statistics| log::info!("[{}] {}", msg, stats)),
            Box::new(JSONEventHandler::new(stats_file)),
        ];

        Self::new(monitor, handlers)
    }

    fn new(monitor: Box<dyn ClonableMonitor>, handlers: Vec<Box<dyn EventHandler>>) -> Self {
        Self { monitor, handlers }
    }

    fn client(&mut self, id: ClientId) -> Statistics {
        let client = self.client_stats_mut_for(id);

        #[cfg(feature = "introspection")]
        let introspect_feature = {
            let intro_stats = &client.introspection_monitor;
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
        let total_execs = client.executions;

        let trace = TraceStatistics::new(client);
        let mut error_counter = ErrorStatistics::new(total_execs);

        error_counter.count(client);

        let corpus_size = client.corpus_size;
        let objective_size = client.objective_size;

        let coverage = client
            .user_monitor
            .get(MAP_FEEDBACK_NAME)
            .and_then(|s| match s.value() {
                UserStatsValue::Ratio(a, b) => Some(CoverageStatistics { hit: *a, max: *b }),
                _ => None,
            });

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
        })
    }

    fn global(&mut self) -> Statistics {
        Statistics::Global(GlobalStatistics {
            time: SystemTime::now(),

            clients: self.client_stats().len() as u32,
            corpus_size: self.corpus_size(),
            objective_size: self.objective_size(),
            total_execs: self.total_execs(),
            exec_per_sec: self.execs_per_sec() as u64,
        })
    }

    fn dispatch(&mut self, sender: ClientId, msg: &str, stats: &Statistics) {
        self.handlers
            .iter_mut()
            .for_each(|h| h.process(sender, msg, stats));
    }
}

impl Monitor for StatsMonitor {
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.monitor.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.monitor.client_stats()
    }

    fn start_time(&self) -> Duration {
        self.monitor.start_time()
    }

    fn set_start_time(&mut self, time: Duration) {
        self.monitor.set_start_time(time);
    }

    fn display(&mut self, event_msg: String, sender_id: ClientId) {
        let global_stats = self.global();
        let client_stats = self.client(sender_id);
        self.dispatch(sender_id, &event_msg, &global_stats);
        self.dispatch(sender_id, &event_msg, &client_stats);
        self.monitor.display(event_msg, sender_id);
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
                    "(CLIENT) corpus: {}, obj: {}, execs: {}, exec/sec: {}",
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

#[derive(Serialize)]
struct ErrorStatistics {
    #[serde(skip)]
    #[allow(dead_code)]
    total_execs: u64,

    fn_error: u64,
    term_error: u64,
    ssl_error: u64,
    io_error: u64,
    ag_error: u64,
    str_error: u64,
    ext_error: u64,
}

#[derive(Serialize)]
struct TraceStatistics {
    min_trace_length: Option<u64>,
    max_trace_length: Option<u64>,
    mean_trace_length: Option<u64>,

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
            fn_error: 0,
            term_error: 0,
            ssl_error: 0,
            io_error: 0,
            ag_error: 0,
            str_error: 0,
            ext_error: 0,
        }
    }

    pub fn count(&mut self, client_stats: &ClientStats) {
        for stat_definition in &STATS {
            match stat_definition {
                RuntimeStats::FnError(c) => self.fn_error += get_number(client_stats, c.name),
                RuntimeStats::TermError(c) => self.term_error += get_number(client_stats, c.name),
                RuntimeStats::PutError(c) => self.ssl_error += get_number(client_stats, c.name),
                RuntimeStats::IOError(c) => self.io_error += get_number(client_stats, c.name),
                RuntimeStats::AgentError(c) => self.ag_error += get_number(client_stats, c.name),
                RuntimeStats::StreamError(c) => self.str_error += get_number(client_stats, c.name),
                RuntimeStats::ExtractionError(c) => {
                    self.ext_error += get_number(client_stats, c.name);
                }
                _ => {}
            }
        }
    }
}

fn get_number(user_stats: &ClientStats, name: &str) -> u64 {
    user_stats
        .user_monitor
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
    serializer: JSONSerializer<BufWriter<File>>,
}

impl JSONEventHandler {
    fn new<P>(output_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let writer = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(output_path.as_ref())
                .unwrap(),
        );

        Self {
            output_path: output_path.as_ref().to_path_buf(),
            serializer: JSONSerializer::new(writer),
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
        stats.serialize(&mut self.serializer).unwrap();
    }
}
