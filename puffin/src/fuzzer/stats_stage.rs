use std::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use libafl::prelude::*;
pub enum RuntimeStats {
    FnError(&'static Counter),
    TermError(&'static Counter),
    PutError(&'static Counter),
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
            RuntimeStats::PutError(inner) => inner.fire(consume),
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
// Put(String),
pub static PUT: Counter = Counter::new("put");
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
    RuntimeStats::PutError(&PUT),
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
    min_set: AtomicBool,
    min: AtomicUsize,
    max_set: AtomicBool,
    max: AtomicUsize,
    mean_set: AtomicBool,
    mean: AtomicUsize,
}

impl MinMaxMean {
    const fn new(name: &'static str) -> MinMaxMean {
        Self {
            name,
            min_set: AtomicBool::new(false),
            min: AtomicUsize::new(usize::MAX),
            max_set: AtomicBool::new(false),
            max: AtomicUsize::new(0),
            mean_set: AtomicBool::new(false),
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
                if !self.mean_set.fetch_or(true, Ordering::SeqCst) {
                    Some(value)
                } else {
                    Some((mean + value) / 2)
                }
            })
            .unwrap();
    }

    fn max(&self, value: usize) {
        self.max_set.fetch_or(true, Ordering::SeqCst);
        self.max.fetch_max(value, Ordering::SeqCst);
    }

    fn min(&self, value: usize) {
        self.min_set.fetch_or(true, Ordering::SeqCst);
        self.min.fetch_min(value, Ordering::SeqCst);
    }
}

impl Fire for MinMaxMean {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.min_set.load(Ordering::SeqCst) {
            consume(
                self.name.to_string() + "-min",
                UserStats::Number(self.min.load(Ordering::SeqCst) as u64),
            )?;
        }
        if self.max_set.load(Ordering::SeqCst) {
            consume(
                self.name.to_string() + "-max",
                UserStats::Number(self.max.load(Ordering::SeqCst) as u64),
            )?;
        }
        if self.mean_set.load(Ordering::SeqCst) {
            consume(
                self.name.to_string() + "-mean",
                UserStats::Number(self.mean.load(Ordering::SeqCst) as u64),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct StatsStage<E, EM, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> UsesState for StatsStage<E, EM, Z>
where
    EM: EventFirer,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
{
    type State = Z::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for StatsStage<E, EM, Z>
where
    EM: EventFirer,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        for stat in &STATS {
            stat.fire(&mut |name, stats| {
                manager.fire(
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

impl<E, EM, Z> StatsStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
{
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
