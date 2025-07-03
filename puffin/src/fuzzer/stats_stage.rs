use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libafl::prelude::*;
pub enum RuntimeStats {
    // Term Eval error counters
    EvalFnCryptoError(&'static Counter),
    EvalFnMalformedError(&'static Counter),
    EvalFnUnknownError(&'static Counter),
    EvalTermError(&'static Counter),
    EvalTermBugError(&'static Counter),
    EvalCodecError(&'static Counter),
    // Trace Exec error counters
    AllCodecError(&'static Counter),
    AllPutError(&'static Counter),
    AllIOError(&'static Counter),
    AllAgentError(&'static Counter),
    AllStreamError(&'static Counter),
    AllExtractionError(&'static Counter),
    AllFnError(&'static Counter),
    AllTermError(&'static Counter),
    AllTermBugError(&'static Counter),
    // Term eval counters
    AllTermEval(&'static Counter),
    AllTermEvalSuccess(&'static Counter),
    // Trace exec counters
    AllExec(&'static Counter),
    AllExecSuccess(&'static Counter),
    AllExecAgentSuccess(&'static Counter),
    // Trace execs by harness counters
    HarnessExec(&'static Counter),
    HarnessExecSuccess(&'static Counter),
    HarnessExecAgentSuccess(&'static Counter),
    // Trace execs by bit-mutations counters
    BitExec(&'static Counter),
    BitExecSuccess(&'static Counter),
    // Trace execs by MakeMessage and ReadMessage counters
    MMExec(&'static Counter),
    MMNExecSuccess(&'static Counter),
    // Full execs of corpus trace scheduled counter
    CorpusExec(&'static Counter),
    CorpusExecMinimal(&'static Counter),
    TraceLength(&'static MinMaxMean),
    TermSize(&'static MinMaxMean),
    NbPayload(&'static MinMaxMean),
    PayloadLength(&'static MinMaxMean),
}

impl RuntimeStats {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::EvalFnCryptoError(inner) => inner.fire(consume),
            Self::EvalFnMalformedError(inner) => inner.fire(consume),
            Self::EvalFnUnknownError(inner) => inner.fire(consume),
            Self::EvalTermError(inner) => inner.fire(consume),
            Self::EvalTermBugError(inner) => inner.fire(consume),
            Self::EvalCodecError(inner) => inner.fire(consume),
            Self::AllFnError(inner) => inner.fire(consume),
            Self::AllTermError(inner) => inner.fire(consume),
            Self::AllTermBugError(inner) => inner.fire(consume),
            Self::AllTermEval(inner) => inner.fire(consume),
            Self::AllTermEvalSuccess(inner) => inner.fire(consume),
            Self::AllExec(inner) => inner.fire(consume),
            Self::AllExecSuccess(inner) => inner.fire(consume),
            Self::AllExecAgentSuccess(inner) => inner.fire(consume),
            Self::HarnessExec(inner) => inner.fire(consume),
            Self::HarnessExecSuccess(inner) => inner.fire(consume),
            Self::HarnessExecAgentSuccess(inner) => inner.fire(consume),
            Self::BitExec(inner) => inner.fire(consume),
            Self::BitExecSuccess(inner) => inner.fire(consume),
            Self::MMExec(inner) => inner.fire(consume),
            Self::MMNExecSuccess(inner) => inner.fire(consume),
            Self::CorpusExec(inner) => inner.fire(consume),
            Self::CorpusExecMinimal(inner) => inner.fire(consume),
            Self::AllCodecError(inner) => inner.fire(consume),
            Self::AllPutError(inner) => inner.fire(consume),
            Self::AllIOError(inner) => inner.fire(consume),
            Self::AllAgentError(inner) => inner.fire(consume),
            Self::AllStreamError(inner) => inner.fire(consume),
            Self::AllExtractionError(inner) => inner.fire(consume),
            Self::TraceLength(inner) => inner.fire(consume),
            Self::TermSize(inner) => inner.fire(consume),
            Self::NbPayload(inner) => inner.fire(consume),
            Self::PayloadLength(inner) => inner.fire(consume),
        }
    }
}

/// Errors counters triggered by term evaluations
pub static EVAL_ERR_FN_CRYPTO: Counter = Counter::new("eval-error-fn-crypto");
pub static EVAL_ERR_FN_MALFORMED: Counter = Counter::new("eval-error-fn-malformed");
pub static EVAL_ERR_FN_UNKNOWN: Counter = Counter::new("eval-error-fn-unknown");
pub static EVAL_ERR_TERM: Counter = Counter::new("eval-error-term");
pub static EVAL_ERR_TERMBUG: Counter = Counter::new("eval-error-termbug");
pub static EVAL_ERR_CODEC: Counter = Counter::new("eval-error-codec");
/// Errors counters triggered by all trace executions
// Fn(FnError),
pub static ERROR_FN: Counter = Counter::new("error-fn");
// Term(String),
pub static ERROR_TERM: Counter = Counter::new("error-term");
// TermBug(String),
pub static ERROR_TERMBUG: Counter = Counter::new("error-term-bug");
// Codec(String),
pub static ERROR_CODEC: Counter = Counter::new("error-codec");
// Put(String),
pub static ERROR_PUT: Counter = Counter::new("error-put");
// IO(String),
pub static ERROR_IO: Counter = Counter::new("error-io");
// Agent(String),
pub static ERROR_AGENT: Counter = Counter::new("error-ag");
// Stream(String),
pub static ERROR_STREAM: Counter = Counter::new("error-str");
// Extraction(ContentType),
pub static ERROR_EXTRACTION: Counter = Counter::new("error-extr");

/// Metric for traces, terms, and payloads
pub static TRACE_LENGTH: MinMaxMean = MinMaxMean::new("trace-length");
pub static TERM_SIZE: MinMaxMean = MinMaxMean::new("term-size");
pub static NB_PAYLOAD: MinMaxMean = MinMaxMean::new("nb-payload");
pub static PAYLOAD_LENGTH: MinMaxMean = MinMaxMean::new("payload-length");

/// Metrics for evaluations and executions
pub static ALL_EXEC: Counter = Counter::new("all-exec");
pub static ALL_EXEC_SUCCESS: Counter = Counter::new("all-exec-success");
pub static ALL_EXEC_AGENT_SUCCESS: Counter = Counter::new("all-exec-agents-success");
pub static HARNESS_EXEC: Counter = Counter::new("harness-exec");
pub static HARNESS_EXEC_AGENT_SUCCESS: Counter = Counter::new("harness-exec-agents-success");
pub static HARNESS_EXEC_SUCCESS: Counter = Counter::new("harness-exec-success");
pub static ALL_TERM_EVAL: Counter = Counter::new("all-term-eval");
pub static ALL_TERM_EVAL_SUCCESS: Counter = Counter::new("all-term-eval-success");
pub static BIT_EXEC: Counter = Counter::new("bit-exec");
pub static BIT_EXEC_SUCCESS: Counter = Counter::new("bit-exec-success");
pub static MM_EXEC: Counter = Counter::new("mm-exec");
pub static MM_EXEC_SUCCESS: Counter = Counter::new("mmn-exec-success");
pub static CORPUS_EXEC: Counter = Counter::new("corpus-exec");
pub static CORPUS_EXEC_MINIMAL: Counter = Counter::new("corpus-exec-success");

pub static STATS: [RuntimeStats; 33] = [
    RuntimeStats::EvalFnCryptoError(&EVAL_ERR_FN_CRYPTO),
    RuntimeStats::EvalFnMalformedError(&EVAL_ERR_FN_MALFORMED),
    RuntimeStats::EvalFnUnknownError(&EVAL_ERR_FN_UNKNOWN),
    RuntimeStats::EvalTermError(&EVAL_ERR_TERM),
    RuntimeStats::EvalTermBugError(&EVAL_ERR_TERMBUG),
    RuntimeStats::EvalCodecError(&EVAL_ERR_CODEC),
    RuntimeStats::AllFnError(&ERROR_FN),
    RuntimeStats::AllTermError(&ERROR_TERM),
    RuntimeStats::AllTermBugError(&ERROR_TERMBUG),
    RuntimeStats::AllCodecError(&ERROR_CODEC),
    RuntimeStats::AllPutError(&ERROR_PUT),
    RuntimeStats::AllIOError(&ERROR_IO),
    RuntimeStats::AllAgentError(&ERROR_AGENT),
    RuntimeStats::AllStreamError(&ERROR_STREAM),
    RuntimeStats::AllExtractionError(&ERROR_EXTRACTION),
    RuntimeStats::TraceLength(&TRACE_LENGTH),
    RuntimeStats::TermSize(&TERM_SIZE),
    RuntimeStats::NbPayload(&NB_PAYLOAD),
    RuntimeStats::PayloadLength(&PAYLOAD_LENGTH),
    RuntimeStats::AllTermEval(&ALL_TERM_EVAL),
    RuntimeStats::AllTermEvalSuccess(&ALL_TERM_EVAL_SUCCESS),
    RuntimeStats::AllExec(&ALL_EXEC),
    RuntimeStats::AllExecSuccess(&ALL_EXEC_SUCCESS),
    RuntimeStats::AllExecAgentSuccess(&ALL_EXEC_AGENT_SUCCESS),
    RuntimeStats::HarnessExec(&HARNESS_EXEC),
    RuntimeStats::HarnessExecSuccess(&HARNESS_EXEC_SUCCESS),
    RuntimeStats::HarnessExecAgentSuccess(&HARNESS_EXEC_AGENT_SUCCESS),
    RuntimeStats::BitExec(&BIT_EXEC),
    RuntimeStats::BitExecSuccess(&BIT_EXEC_SUCCESS),
    RuntimeStats::MMExec(&MM_EXEC),
    RuntimeStats::MMNExecSuccess(&MM_EXEC_SUCCESS),
    RuntimeStats::CorpusExec(&CORPUS_EXEC),
    RuntimeStats::CorpusExecMinimal(&CORPUS_EXEC_MINIMAL),
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
    const fn new(name: &'static str) -> Self {
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
            UserStats::new(
                UserStatsValue::Number(self.counter.load(Ordering::SeqCst) as u64),
                AggregatorOps::Sum,
            ),
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
    const fn new(name: &'static str) -> Self {
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
                UserStats::new(
                    UserStatsValue::Number(self.min.load(Ordering::SeqCst) as u64),
                    AggregatorOps::Min,
                ),
            )?;
        }
        if self.max_set.load(Ordering::SeqCst) {
            consume(
                self.name.to_string() + "-max",
                UserStats::new(
                    UserStatsValue::Number(self.max.load(Ordering::SeqCst) as u64),
                    AggregatorOps::Max,
                ),
            )?;
        }
        if self.mean_set.load(Ordering::SeqCst) {
            consume(
                self.name.to_string() + "-mean",
                UserStats::new(
                    UserStatsValue::Number(self.mean.load(Ordering::SeqCst) as u64),
                    AggregatorOps::Avg,
                ),
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
        if cfg!(feature = "introspection") {
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
    pub const fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<E, EM, Z> Default for StatsStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
{
    fn default() -> Self {
        Self::new()
    }
}
