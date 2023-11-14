//! Stats to display both cumulative and per-client stats

use core::{time, time::Duration};
use std::{
    fs::{File, OpenOptions},
    io,
    io::BufWriter,
    path::PathBuf,
    time::SystemTime,
};

use libafl::prelude::*;
use serde::Serialize;
use serde_json::Serializer as JSONSerializer;

use crate::fuzzer::{
    libafl_setup::MAP_FEEDBACK_NAME,
    stats_stage::{RuntimeStats, STATS},
};

/// Tracking stats during fuzzing and display both per-client and cumulative info.
pub struct StatsMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    log_count: u64,
    stats_file: PathBuf,
    json_writer: JSONSerializer<BufWriter<File>>,
}

impl<F> Clone for StatsMonitor<F>
where
    F: FnMut(String) + Clone,
{
    fn clone(&self) -> Self {
        Self {
            print_fn: self.print_fn.clone(),
            start_time: self.start_time,
            client_stats: self.client_stats.clone(),
            log_count: self.log_count,
            stats_file: self.stats_file.clone(),
            json_writer: JSONSerializer::new(BufWriter::new(
                OpenOptions::new()
                    .append(true)
                    .open(&self.stats_file)
                    .unwrap(),
            )),
        }
    }
}

impl<F> StatsMonitor<F>
where
    F: FnMut(String),
{
    fn client(&mut self, event_msg: &String, sender_id: ClientId) {
        let client = self.client_stats_mut_for(sender_id);

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
        let mut fmt = format!(
            "[{}] (CLIENT) corpus: {}, obj: {}, execs: {}, exec/sec: {}",
            event_msg, corpus_size, objective_size, total_execs, exec_sec
        );

        // log edges
        let coverage = if let Some(edges) = client.user_monitor.get(MAP_FEEDBACK_NAME) {
            fmt += &format!(", {}: {}", "edges", edges);

            if let UserStats::Ratio(a, b) = edges {
                Some(CoverageStatistics {
                    discovered: *a,
                    max: *b,
                })
            } else {
                None
            }
        } else {
            None
        };

        (self.print_fn)(fmt);

        Statistics::Client(ClientStatistics {
            id: sender_id.0,
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
        .serialize(&mut self.json_writer)
        .unwrap();
    }

    fn global(&mut self, event_msg: &String) {
        let total_execs = self.total_execs();

        let global_fmt = format!(
            "[{}] (GLOBAL) clients: {}, corpus: {}, obj: {}, execs: {}, exec/sec: {}",
            event_msg,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            total_execs,
            self.execs_per_sec()
        );

        (self.print_fn)(global_fmt);

        Statistics::Global(GlobalStatistics {
            time: SystemTime::now(),

            clients: self.client_stats().len() as u32,
            corpus_size: self.corpus_size(),
            objective_size: self.objective_size(),
            total_execs,
            exec_per_sec: self.execs_per_sec() as u64,
        })
        .serialize(&mut self.json_writer)
        .unwrap();
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
    discovered: u64,
    max: u64,
}

#[derive(Serialize)]
struct IntrospectStatistics {
    scheduler: f32,
    manager: f32,
    elapsed_cycles: u64,
    introspect_features: IntrospectFeatures,
}

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

impl ErrorStatistics {
    pub fn new(total_execs: u64) -> Self {
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
                    self.ext_error += get_number(client_stats, c.name)
                }
                _ => {}
            }
        }
    }
}

fn get_number(user_stats: &ClientStats, name: &str) -> u64 {
    if let Some(user_stat) = user_stats.user_monitor.get(name) {
        match user_stat {
            UserStats::Number(n) => *n,
            _ => 0u64,
        }
    } else {
        0u64
    }
}

impl TraceStatistics {
    pub fn new(user_stats: &ClientStats) -> TraceStatistics {
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

impl<F> Monitor for StatsMonitor<F>
where
    F: FnMut(String),
{
    /// the client stats, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client stats
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: ClientId) {
        self.log_count += 1;

        self.global(&event_msg);
        self.client(&event_msg, sender_id);
    }
}

impl<F> StatsMonitor<F>
where
    F: FnMut(String),
{
    pub fn new(print_fn: F, stats_file: PathBuf) -> Result<Self, io::Error> {
        let json_writer = JSONSerializer::new(BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(&stats_file)?,
        ));
        Ok(Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
            log_count: 0,
            stats_file,
            json_writer,
        })
    }
}
