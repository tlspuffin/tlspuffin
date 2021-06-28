//! Stats to disply both cumulative and per-client stats

use core::{time, time::Duration};

use libafl::stats::UserStats;
use libafl::{
    bolts::current_time,
    stats::{ClientStats, Stats},
};

/// Tracking stats during fuzzing and display both per-client and cumulative info.
#[derive(Clone, Debug)]
pub struct PuffinStats<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    corpus_size: usize,
    client_stats: Vec<ClientStats>,
    log_count: u64,
}

impl<F> PuffinStats<F>
where
    F: FnMut(String),
{
    fn client(&mut self, event_msg: &String, sender_id: u32) {
        let client = self.client_stats_mut_for(sender_id);
        let cur_time = current_time();
        let exec_sec = client.execs_per_sec(cur_time);

        let mut fn_error: u64 = 0;
        let mut term_error: u64 = 0;
        let mut ssl_error: u64 = 0;
        let mut io_error: u64 = 0;
        let mut ag_error: u64 = 0;
        let mut str_error: u64 = 0;
        let mut ext_error: u64 = 0;

        for (key, val) in &client.user_stats {
            let n = match val {
                UserStats::Number(n) => *n,
                _ => 0u64,
            };
            match key.as_str() {
                "fn" => fn_error += n,
                "term" => term_error += n,
                "ssl" => ssl_error += n,
                "io" => io_error += n,
                "ag" => ag_error += n,
                "str" => str_error += n,
                "ext" => ext_error += n,
                _ => {}
            }
        }

        let mut fmt = format!(
            "[{}] (CLIENT) corpus: {}, obj: {}, execs: {}, exec/sec: {}, fn:{}|term:{}|ssl:{}|io:{}|ag:{}|str:{}|ext:{}",
            event_msg, client.corpus_size, client.objective_size, client.executions, exec_sec,
            fn_error,
            term_error,
            ssl_error,
            io_error,
            ag_error,
            str_error,
            ext_error,
        );

        // log edges
        if let Some(edges) = client.user_stats.get("edges") {
            fmt += &format!(", {}: {}", "edges", edges);
        }

        (self.print_fn)(fmt);
    }

    fn global(&mut self, event_msg: &String) {
        let mut fn_error: u64 = 0;
        let mut term_error: u64 = 0;
        let mut ssl_error: u64 = 0;
        let mut io_error: u64 = 0;
        let mut ag_error: u64 = 0;
        let mut str_error: u64 = 0;
        let mut ext_error: u64 = 0;

        // Summarize errors
        for client_stats in &self.client_stats {
            for (key, val) in &client_stats.user_stats {
                let n = match val {
                    UserStats::Number(n) => *n,
                    _ => 0u64,
                };
                match key.as_str() {
                    "fn" => fn_error += n,
                    "term" => term_error += n,
                    "ssl" => ssl_error += n,
                    "io" => io_error += n,
                    "ag" => ag_error += n,
                    "str" => str_error += n,
                    "ext" => ext_error += n,
                    _ => {}
                }
            }
        }

        let global_fmt = format!(
            "[{}] (GLOBAL) clients: {}, corpus: {}, obj: {}, execs: {}, exec/sec: {}, fn:{}|term:{}|ssl:{}|io:{}|ag:{}|str:{}|ext:{}",
            event_msg,
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec(),
            fn_error,
            term_error,
            ssl_error,
            io_error,
            ag_error,
            str_error,
            ext_error,
        );
        (self.print_fn)(global_fmt);
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
    pub fn new(print_fn: F) -> Self {
        Self {
            print_fn,
            start_time: current_time(),
            corpus_size: 0,
            client_stats: vec![],
            log_count: 0,
        }
    }
}
