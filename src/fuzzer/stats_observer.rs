use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};

use itertools::Itertools;
use libafl::bolts::tuples::Named;
use libafl::events::Event::UpdateUserStats;
use libafl::events::{Event, EventFirer};
use libafl::inputs::Input;
use libafl::observers::Observer;
use libafl::state::State;
use libafl::stats::UserStats;
use libafl::{executors::HasExecHooks, Error};
use serde::{Deserialize, Serialize};

pub enum RuntimeStats {
    FnError(&'static Counter),
    TermError(&'static Counter),
    OpenSSLError(&'static Counter),
    IOError(&'static Counter),
    AgentError(&'static Counter),
    StreamError(&'static Counter),
    ExtractionError(&'static Counter),
    TraceLength(&'static MinMaxMean),
    TermSize(&'static MinMaxMean),
}

impl RuntimeStats {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            RuntimeStats::FnError(inner) => inner.fire(consume),
            RuntimeStats::TermError(inner) => inner.fire(consume),
            RuntimeStats::OpenSSLError(inner) => inner.fire(consume),
            RuntimeStats::IOError(inner) => inner.fire(consume),
            RuntimeStats::AgentError(inner) => inner.fire(consume),
            RuntimeStats::StreamError(inner) => inner.fire(consume),
            RuntimeStats::ExtractionError(inner) => inner.fire(consume),
            RuntimeStats::TraceLength(inner) => inner.fire(consume),
            RuntimeStats::TermSize(inner) => inner.fire(consume),
        }
    }
}

// Fn(FnError),
pub static FN_ERROR: Counter = Counter::new("fn");
// Term(String),
pub static TERM: Counter = Counter::new("term");
// OpenSSL(ErrorStack),
pub static OPENSSL: Counter = Counter::new("ssl");
// IO(String),
pub static IO: Counter = Counter::new("io");
// Agent(String),
pub static AGENT: Counter = Counter::new("ag");
// Stream(String),
pub static STREAM: Counter = Counter::new("str");
// Extraction(ContentType),
pub static EXTRACTION: Counter = Counter::new("extr");

pub static TRACE_LENGTH: MinMaxMean = MinMaxMean::new("trace-length");

pub static TERM_SIZE: MinMaxMean = MinMaxMean::new("term-size");

pub static STATS: [RuntimeStats; 9] = [
    RuntimeStats::FnError(&FN_ERROR),
    RuntimeStats::TermError(&TERM),
    RuntimeStats::OpenSSLError(&OPENSSL),
    RuntimeStats::IOError(&IO),
    RuntimeStats::AgentError(&AGENT),
    RuntimeStats::StreamError(&STREAM),
    RuntimeStats::ExtractionError(&EXTRACTION),
    RuntimeStats::TraceLength(&TRACE_LENGTH),
    RuntimeStats::TermSize(&TERM_SIZE),
];

pub trait Fire: Sync {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error>;
}

pub struct Counter {
    pub name: &'static str,
    counter: AtomicUsize,
}

impl Counter {
    const fn new(name: &'static str) -> Counter {
        Self {
            name,
            counter: AtomicUsize::new(0),
        }
    }

    pub fn increment(&self) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl Fire for Counter {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        consume(
            self.name.to_string(),
            UserStats::Number(self.counter.load(Ordering::SeqCst) as u64),
        )
    }
}

pub struct MinMaxMean {
    pub name: &'static str,
    min: AtomicUsize,
    max: AtomicUsize,
    mean: AtomicUsize,
}

impl MinMaxMean {
    const fn new(name: &'static str) -> MinMaxMean {
        Self {
            name,
            min: AtomicUsize::new(usize::MAX),
            max: AtomicUsize::new(0),
            mean: AtomicUsize::new(0),
        }
    }

    pub fn update(&self, value: usize) {
        self.mean(value);
        self.max(value);
        self.min(value);
    }

    fn mean(&self, value: usize) {
        self.mean
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |mean| {
                Some((mean + value) / 2)
            })
            .unwrap();
    }

    fn max(&self, value: usize) {
        self.max.fetch_max(value, Ordering::SeqCst);
    }

    fn min(&self, value: usize) {
        self.min.fetch_min(value, Ordering::SeqCst);
    }
}

impl Fire for MinMaxMean {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        consume(
            self.name.to_string() + "-min",
            UserStats::Number(self.min.load(Ordering::SeqCst) as u64),
        )?;
        consume(
            self.name.to_string() + "-max",
            UserStats::Number(self.max.load(Ordering::SeqCst) as u64),
        )?;
        consume(
            self.name.to_string() + "-mean",
            UserStats::Number(self.mean.load(Ordering::SeqCst) as u64),
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorObserver {
    name: String,
}

impl ErrorObserver {
    /// Creates a new [`ErrorObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl Observer for ErrorObserver {}

impl<EM, I, S, Z> HasExecHooks<EM, I, S, Z> for ErrorObserver
where
    EM: EventFirer<I, S>,
    I: Input,
    S: State,
{
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        for stat in &STATS {
            stat.fire(&mut |name, stats| {
                mgr.fire(
                    state,
                    Event::UpdateUserStats {
                        name,
                        value: stats,
                        phantom: Default::default(),
                    },
                )
            })?;
        }

        Ok(())
    }
}

impl Named for ErrorObserver {
    fn name(&self) -> &str {
        &self.name
    }
}
