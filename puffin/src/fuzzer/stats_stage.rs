use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libafl::monitors::stats::*;
use libafl::prelude::*;
use libafl_bolts::Named;

pub enum RuntimeStats {
    // Term Eval error counters
    EvalFnCryptoError(&'static Counter),
    EvalFnCodecError(&'static Counter),
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
    MMFailReach(&'static Counter),
    MMFailMake(&'static Counter),
    FrontierSkip(&'static Counter),
    MmTermOk(&'static Counter),
    MmOkOpaque(&'static Counter),
    MmFailreachOpaque(&'static Counter),
    RmOk(&'static Counter),
    RmSkipNoterm(&'static Counter),
    // Full execs of corpus trace scheduled counter
    CorpusExec(&'static Counter),
    CorpusExecMinimal(&'static Counter),
    // Stats about traces and payloads
    TraceLength(&'static MinMaxMean),
    TermSize(&'static MinMaxMean),
    NbPayload(&'static MinMaxMean),
    PayloadLength(&'static MinMaxMean),
    /// [R1 datapoint #1] Deepest trace step reached during execution (ctx.executed_until), recorded
    /// for every execution (success or early failure). mean << trace length => traces die early.
    ReachedStep(&'static MinMaxMean),
    Duplicates(&'static Counter),
    // [shared-payload] Phase 5 observability counters
    MmSharedOk(&'static Counter),
    MmSharedSingleton(&'static Counter),
    SharedSyncPropagated(&'static Counter),
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
            Self::EvalFnCodecError(inner) => inner.fire(consume),
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
            Self::MMFailReach(inner) => inner.fire(consume),
            Self::MMFailMake(inner) => inner.fire(consume),
            Self::FrontierSkip(inner) => inner.fire(consume),
            Self::MmTermOk(inner) => inner.fire(consume),
            Self::MmOkOpaque(inner) => inner.fire(consume),
            Self::MmFailreachOpaque(inner) => inner.fire(consume),
            Self::RmOk(inner) => inner.fire(consume),
            Self::RmSkipNoterm(inner) => inner.fire(consume),
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
            Self::ReachedStep(inner) => inner.fire(consume),
            Self::Duplicates(inner) => inner.fire(consume),
            Self::MmSharedOk(inner) => inner.fire(consume),
            Self::MmSharedSingleton(inner) => inner.fire(consume),
            Self::SharedSyncPropagated(inner) => inner.fire(consume),
        }
    }
}

/// Errors counters triggered by term evaluations
pub static EVAL_ERR_FN_CRYPTO: Counter = Counter::new("eval-error-fn-crypto");
pub static EVAL_ERR_FN_CODEC: Counter = Counter::new("eval-error-fn-codec");
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
/// [R1 #1] Deepest step index reached per execution.
pub static REACHED_STEP: MinMaxMean = MinMaxMean::new("reached-step");

/// [reached-step histogram] Per-execution bucket counts of how many trace steps executed WITHOUT
/// error (= ctx.executed_until). Answers "what fraction of executions die at step 0/1/2/3/>=4" as a
/// DISTRIBUTION (the mean alone is misleading + integer-truncated). Compare --with-bit vs DY-only.
pub static REACHED_B0: AtomicUsize = AtomicUsize::new(0);
pub static REACHED_B1: AtomicUsize = AtomicUsize::new(0);
pub static REACHED_B2: AtomicUsize = AtomicUsize::new(0);
pub static REACHED_B3: AtomicUsize = AtomicUsize::new(0);
pub static REACHED_B4PLUS: AtomicUsize = AtomicUsize::new(0);

/// Bucket one execution by its reached-step count, and periodically dump the histogram + ratios to
/// the log (every 100k executions). Lightweight (atomic + log), like the locator histogram.
pub fn reached_step_bucket(n: usize) {
    let c = match n {
        0 => &REACHED_B0,
        1 => &REACHED_B1,
        2 => &REACHED_B2,
        3 => &REACHED_B3,
        _ => &REACHED_B4PLUS,
    };
    c.fetch_add(1, Ordering::Relaxed);
    let b0 = REACHED_B0.load(Ordering::Relaxed);
    let b1 = REACHED_B1.load(Ordering::Relaxed);
    let b2 = REACHED_B2.load(Ordering::Relaxed);
    let b3 = REACHED_B3.load(Ordering::Relaxed);
    let b4 = REACHED_B4PLUS.load(Ordering::Relaxed);
    let total = b0 + b1 + b2 + b3 + b4;
    if total % 100_000 == 0 && total > 0 {
        let p = |x: usize| 100.0 * x as f64 / total as f64;
        log::info!(
            "[reached-step-hist] total={total} n0={b0}({:.1}%) n1={b1}({:.1}%) n2={b2}({:.1}%) n3={b3}({:.1}%) n>=4={b4}({:.1}%)",
            p(b0), p(b1), p(b2), p(b3), p(b4)
        );
    }
}

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
/// [INV-A counters] MakeMessage failures split: reachability (trace can't execute to the step) vs
/// eval (payload computation failed at the step). And how often the frontier pre-check skips.
pub static MM_FAIL_REACH: Counter = Counter::new("mm-fail-reach");
pub static MM_FAIL_MAKE: Counter = Counter::new("mm-fail-make");
pub static FRONTIER_SKIP: Counter = Counter::new("frontier-skip");
/// [INV-B per-case] MakeMessage outcomes split by whether the target is strictly under an
/// opaque/reframing boundary. "plain" is derived = total (mm_term_ok / mm_fail_reach) minus *_opaque.
pub static MM_TERM_OK: Counter = Counter::new("mm-term-ok");
pub static MM_OK_OPAQUE: Counter = Counter::new("mm-ok-opaque");
pub static MM_FAILREACH_OPAQUE: Counter = Counter::new("mm-failreach-opaque");
/// [INV-C] ReadMessage outcomes: applied (read_message_term ok) vs skipped (no payload term found).
pub static RM_OK: Counter = Counter::new("rm-ok");
pub static RM_SKIP_NOTERM: Counter = Counter::new("rm-skip-noterm");
pub static CORPUS_EXEC: Counter = Counter::new("corpus-exec");
pub static CORPUS_EXEC_MINIMAL: Counter = Counter::new("corpus-exec-success");
pub static DUPLICATES: Counter = Counter::new("duplicates");
/// [shared-payload] Phase 5 observability counters.
/// MM_SHARED_OK: MakeMessageShared successfully formed a linked group (≥2 members).
/// MM_SHARED_SINGLETON: MakeMessageShared found no duplicate occurrences (group size 1).
/// SHARED_SYNC_PROPAGATED: payloads propagated to non-authority members by sync_shared_payloads.
pub static MM_SHARED_OK: Counter = Counter::new("mm-shared-ok");
pub static MM_SHARED_SINGLETON: Counter = Counter::new("mm-shared-singleton");
pub static SHARED_SYNC_PROPAGATED: Counter = Counter::new("shared-sync-propagated");

pub static STATS: [RuntimeStats; 47] = [
    RuntimeStats::EvalFnCryptoError(&EVAL_ERR_FN_CRYPTO),
    RuntimeStats::EvalFnMalformedError(&EVAL_ERR_FN_MALFORMED),
    RuntimeStats::EvalFnUnknownError(&EVAL_ERR_FN_UNKNOWN),
    RuntimeStats::EvalTermError(&EVAL_ERR_TERM),
    RuntimeStats::EvalFnCodecError(&EVAL_ERR_FN_CODEC),
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
    RuntimeStats::ReachedStep(&REACHED_STEP),
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
    RuntimeStats::MMFailReach(&MM_FAIL_REACH),
    RuntimeStats::MMFailMake(&MM_FAIL_MAKE),
    RuntimeStats::FrontierSkip(&FRONTIER_SKIP),
    RuntimeStats::MmTermOk(&MM_TERM_OK),
    RuntimeStats::MmOkOpaque(&MM_OK_OPAQUE),
    RuntimeStats::MmFailreachOpaque(&MM_FAILREACH_OPAQUE),
    RuntimeStats::RmOk(&RM_OK),
    RuntimeStats::RmSkipNoterm(&RM_SKIP_NOTERM),
    RuntimeStats::CorpusExec(&CORPUS_EXEC),
    RuntimeStats::CorpusExecMinimal(&CORPUS_EXEC_MINIMAL),
    RuntimeStats::Duplicates(&DUPLICATES),
    // [shared-payload] Phase 5
    RuntimeStats::MmSharedOk(&MM_SHARED_OK),
    RuntimeStats::MmSharedSingleton(&MM_SHARED_SINGLETON),
    RuntimeStats::SharedSyncPropagated(&SHARED_SYNC_PROPAGATED),
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
    // [#6] true running mean: sum + count (replaces the old recency-biased EMA `mean`)
    sum: AtomicUsize,
    count: AtomicUsize,
}

impl MinMaxMean {
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            min_set: AtomicBool::new(false),
            min: AtomicUsize::new(usize::MAX),
            max_set: AtomicBool::new(false),
            max: AtomicUsize::new(0),
            sum: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
        }
    }

    pub fn update(&self, value: usize) {
        // [#6] true running mean: accumulate sum + count (was an EMA `(mean+value)/2`, which is
        // recency-biased + integer-truncated). sum stays well within usize on 64-bit.
        self.sum.fetch_add(value, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        self.max(value);
        self.min(value);
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
        let count = self.count.load(Ordering::SeqCst);
        if count > 0 {
            consume(
                self.name.to_string() + "-mean",
                UserStats::new(
                    UserStatsValue::Number(self.sum.load(Ordering::SeqCst) as u64 / count as u64),
                    AggregatorOps::Avg,
                ),
            )?;
        }
        Ok(())
    }
}

static STATS_STAGE_ID: AtomicUsize = AtomicUsize::new(0);
/// The name for closure stage
pub static STATS_STAGE_NAME: &str = "StatsStage";

#[derive(Clone, Debug)]
pub struct StatsStage<E, EM, Z, S, I> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z, S, I)>,
    name: Cow<'static, str>,
}

impl<E, EM, Z, S, I> Named for StatsStage<E, EM, Z, S, I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, S, Z, I> Stage<E, EM, S, Z> for StatsStage<E, EM, S, Z, I>
where
    EM: EventFirer<I, S>,
    E: Executor<EM, I, S, Z>,
    Z: Evaluator<E, EM, I, S>,
    I: Input,
    S: HasExecutions,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if cfg!(feature = "introspection") {
            for stat in &STATS {
                stat.fire(&mut |name, stats| {
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::UpdateUserStats {
                                name: Cow::from(name),
                                value: stats,
                                phantom: Default::default(),
                            },
                            *state.executions(),
                        ),
                    )
                })?;
            }
        }

        Ok(())
    }
}

impl<E, EM, S, Z, I> Restartable<S> for StatsStage<E, EM, S, Z, I>
where
    EM: EventFirer<I, S>,
    E: Executor<EM, I, S, Z>,
    Z: Evaluator<E, EM, I, S>,
    I: Input,
    S: HasExecutions + HasNamedMetadata,
{
    // This is only a stat stage, we don't need to restart anything
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, S, Z, I> StatsStage<E, EM, S, Z, I>
where
    EM: EventFirer<I, S>,
    E: Executor<EM, I, S, Z>,
    Z: Evaluator<E, EM, I, S>,
    I: Input,
{
    pub fn new() -> Self {
        let stage_id = STATS_STAGE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            phantom: PhantomData,
            name: Cow::Owned(STATS_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
        }
    }
}

impl<E, EM, S, Z, I> Default for StatsStage<E, EM, S, Z, I>
where
    EM: EventFirer<I, S>,
    E: Executor<EM, I, S, Z>,
    Z: Evaluator<E, EM, I, S>,
    I: Input,
{
    fn default() -> Self {
        Self::new()
    }
}
