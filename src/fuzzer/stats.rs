//! Stats to disply both cumulative and per-client stats

use core::{time, time::Duration};
use std::{fmt, io};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use libafl::{
    bolts::current_time,
    stats::{ClientStats, Stats},
};
use libafl::stats::UserStats;
use serde::ser::SerializeSeq;
use serde::Serialize;
use serde::Serializer;
use serde_json::{Serializer as JSONSerializer, to_value, to_writer};

use crate::fuzzer::stats_observer::{RuntimeStats, STATS};

/// Tracking stats during fuzzing and display both per-client and cumulative info.
pub struct PuffinStats<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    log_count: u64,
    stats_file: PathBuf,
    serializer: JSONSerializer<BufWriter<File>>,
}

impl<F> Clone for PuffinStats<F>
where
    F: FnMut(String) + Clone,
{
    fn clone(&self) -> Self {
        Self {
            print_fn: self.print_fn.clone(),
            start_time: self.start_time.clone(),
            client_stats: self.client_stats.clone(),
            log_count: self.log_count,
            stats_file: self.stats_file.clone(),
            serializer: JSONSerializer::new(BufWriter::new(
                OpenOptions::new()
                    .append(true)
                    .open(&self.stats_file)
                    .unwrap(),
            )),
        }
    }
}

impl<F> PuffinStats<F>
where
    F: FnMut(String),
{
    fn client(&mut self, event_msg: &String, sender_id: u32) {
        let client = self.client_stats_mut_for(sender_id);
        let cur_time = current_time();
        let exec_sec = client.execs_per_sec(cur_time);
        let total_execs = client.executions;

        let trace = TraceStatistics::new(client);
        let mut error_counter = ErrorStatistics::new(total_execs);

        error_counter.count(client);

        let corpus_size = client.corpus_size;
        let objective_size = client.objective_size;
        let mut fmt = format!(
            "[{}] (CLIENT) corpus: {}, obj: {}, execs: {}, exec/sec: {}, errors: {}",
            event_msg, corpus_size, objective_size, total_execs, exec_sec, error_counter
        );

        // log edges
        let coverage = if let Some(edges) = client.user_stats.get("edges") {
            fmt += &format!(", {}: {}", "edges", edges);

            if let UserStats::Ratio(a, b) = edges {
                Some(Coverage {
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

        ClientStatistics {
            id: sender_id,
            time: SystemTime::now(),
            trace,
            errors: error_counter,
            coverage,
            corpus_size,
            objective_size,
            total_execs,
            exec_per_sec: exec_sec,
        }
        .serialize(&mut self.serializer)
        .unwrap();
    }

    fn global(&mut self, event_msg: &String) {
        let total_execs = self.total_execs();
        let mut error_counter = ErrorStatistics::new(total_execs);

        // Summarize errors
        for client_stats in &self.client_stats {
            error_counter.count(client_stats);
        }

        let global_fmt = format!(
            "[{}] (GLOBAL) clients: {}, corpus: {}, obj: {}, execs: {}, exec/sec: {}, errors: {}",
            event_msg,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            total_execs,
            self.execs_per_sec(),
            error_counter
        );
        (self.print_fn)(global_fmt);
    }
}

#[derive(Serialize)]
struct Coverage {
    discovered: u64,
    max: u64,
}

#[derive(Serialize)]
struct ClientStatistics {
    /// Some log file unique id
    id: u32,
    time: SystemTime,
    errors: ErrorStatistics,
    trace: TraceStatistics,
    coverage: Option<Coverage>,

    corpus_size: u64,
    objective_size: u64,
    total_execs: u64,
    exec_per_sec: u64,
}

#[derive(Serialize)]
struct ErrorStatistics {
    #[serde(skip)]
    total_execs: u64,

    fn_error: u64,
    term_error: u64,
    ssl_error: u64,
    io_error: u64,
    ag_error: u64,
    str_error: u64,
    ext_error: u64,
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
                RuntimeStats::FnError(c) => {
                    self.fn_error += get_number(client_stats, c.name)
                }
                RuntimeStats::TermError(c) => {
                    self.term_error += get_number(client_stats, c.name)
                }
                RuntimeStats::OpenSSLError(c) => {
                    self.ssl_error += get_number(client_stats, c.name)
                }
                RuntimeStats::IOError(c) => {
                    self.io_error += get_number(client_stats, c.name)
                }
                RuntimeStats::AgentError(c) => {
                    self.ag_error += get_number(client_stats, c.name)
                }
                RuntimeStats::StreamError(c) => {
                    self.str_error += get_number(client_stats, c.name)
                }
                RuntimeStats::ExtractionError(c) => {
                    self.ext_error += get_number(client_stats, c.name)
                }
                _ => {}
            }
        }
    }
}

fn get_number(user_stats: &ClientStats, name: &str) -> u64 {
    if let Some(user_stat) = user_stats.user_stats.get(name) {
        match user_stat {
            UserStats::Number(n) => *n,
            _ => 0u64,
        }
    } else {
        0u64
    }
}

#[derive(Serialize)]
struct TraceStatistics {
    min_trace_length: u64,
    max_trace_length: u64,
    mean_trace_length: u64,

    min_term_size: u64,
    max_term_size: u64,
    mean_term_size: u64,
}

impl TraceStatistics {
    pub fn new(user_stats: &ClientStats) -> TraceStatistics {
        let mut trace_stats = Self {
            min_trace_length: 0,
            max_trace_length: 0,
            mean_trace_length: 0,
            min_term_size: 0,
            max_term_size: 0,
            mean_term_size: 0,
        };

        for stat_definition in &STATS {
                match stat_definition {
                    RuntimeStats::TraceLength(mmm) => {
                        trace_stats.min_trace_length += get_number(user_stats, &(mmm.name.to_owned() + "-min"));
                        trace_stats.max_trace_length += get_number(user_stats, &(mmm.name.to_owned() + "-max"));
                        trace_stats.mean_trace_length += get_number(user_stats, &(mmm.name.to_owned() + "-mean"));
                    }
                    RuntimeStats::TermSize(mmm) => {
                        trace_stats.min_term_size += get_number(user_stats, &(mmm.name.to_owned() + "-min"));
                        trace_stats.max_term_size += get_number(user_stats, &(mmm.name.to_owned() + "-max"));
                        trace_stats.mean_term_size += get_number(user_stats, &(mmm.name.to_owned() + "-mean"));
                    }
                    _ => {}
                }
            }

        trace_stats
    }
}

impl fmt::Display for ErrorStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fn:{:.2}|term:{:.2}|ssl:{:.2}|io:{:.2}|ag:{:.2}|str:{:.2}|ext:{:.2}",
            self.fn_error as f32 / self.total_execs as f32,
            self.term_error as f32 / self.total_execs as f32,
            self.ssl_error as f32 / self.total_execs as f32,
            self.io_error as f32 / self.total_execs as f32,
            self.ag_error as f32 / self.total_execs as f32,
            self.str_error as f32 / self.total_execs as f32,
            self.ext_error as f32 / self.total_execs as f32,
        )
    }
}

impl<F> Stats for PuffinStats<F>
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

    fn display(&mut self, event_msg: String, sender_id: u32) {
        self.log_count += 1;

        if self.log_count % 5000 != 0 {
            return;
        }

        self.global(&event_msg);
        self.client(&event_msg, sender_id);
    }
}

impl<F> PuffinStats<F>
where
    F: FnMut(String),
{
    pub fn new(print_fn: F, stats_file: PathBuf) -> Result<Self, io::Error> {
        let writer = JSONSerializer::new(BufWriter::new(
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
            serializer: writer,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde::ser::SerializeSeq;
    use serde::Serializer;
    use serde_json::to_value;

    // todo
    #[test]
    pub fn test_streaming_writing() {
        let rows = vec!["a", "b", "c"];
        let mut out = std::io::stdout();

        let mut ser = serde_json::Serializer::new(out);
        //let mut seq = ser.serialize_seq(None).unwrap(); // or None if unknown
        for row in rows {
            println!("{}", to_value(row).unwrap())
        }

        //seq.end().unwrap();
    }
}
