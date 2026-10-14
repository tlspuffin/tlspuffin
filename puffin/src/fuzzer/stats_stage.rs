use std::borrow::Cow;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

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
    // Deconstructor eval counters
    DeconstructorEval(&'static Counter),
    DeconstructorEvalFail(&'static Counter),
    VariableEval(&'static Counter),
    VariableEvalFail(&'static Counter),
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
    // Stats about traces and payloads
    TraceLength(&'static MinMaxMean),
    TermSize(&'static MinMaxMean),
    NbPayload(&'static MinMaxMean),
    PayloadLength(&'static MinMaxMean),
    Duplicates(&'static Counter),
    // Stats that fire one entry per list type (and slot) rather than a single one, such as the
    // stats about the lists of a trace
    PerType(&'static dyn Fire),
}

impl RuntimeStats {
    /// Whether this stat fires one entry per list type rather than a single one.
    const fn is_per_type(&self) -> bool {
        matches!(self, Self::PerType(_))
    }

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
            Self::DeconstructorEval(inner) => inner.fire(consume),
            Self::DeconstructorEvalFail(inner) => inner.fire(consume),
            Self::VariableEval(inner) => inner.fire(consume),
            Self::VariableEvalFail(inner) => inner.fire(consume),
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
            Self::Duplicates(inner) => inner.fire(consume),
            Self::PerType(inner) => inner.fire(consume),
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

/// Metrics for evaluations and executions
pub static ALL_EXEC: Counter = Counter::new("all-exec");
pub static ALL_EXEC_SUCCESS: Counter = Counter::new("all-exec-success");
pub static ALL_EXEC_AGENT_SUCCESS: Counter = Counter::new("all-exec-agents-success");
pub static HARNESS_EXEC: Counter = Counter::new("harness-exec");
pub static HARNESS_EXEC_AGENT_SUCCESS: Counter = Counter::new("harness-exec-agents-success");
pub static HARNESS_EXEC_SUCCESS: Counter = Counter::new("harness-exec-success");
pub static ALL_TERM_EVAL: Counter = Counter::new("all-term-eval");
pub static ALL_TERM_EVAL_SUCCESS: Counter = Counter::new("all-term-eval-success");
/// Deconstructor-specific eval counters. `DECONSTRUCTOR_EVAL` counts every evaluation of a
/// `DYTerm::Deconstructor` node; `DECONSTRUCTOR_EVAL_FAIL` counts those that fail specifically
/// because no sub-value of the target type matched the query (the deconstructor's own failure
/// mode). Their ratio `deconstructor-eval-fail / deconstructor-eval` is the symbol's failure rate,
/// directly comparable to the global `all-term-eval-success / all-term-eval`.
pub static DECONSTRUCTOR_EVAL: Counter = Counter::new("deconstructor-eval");
pub static DECONSTRUCTOR_EVAL_FAIL: Counter = Counter::new("deconstructor-eval-fail");
/// Query eval counters, the counterpart of the deconstructor ones: `VARIABLE_EVAL_FAIL` counts the
/// evaluations the knowledge (or the claims) could not answer.
pub static VARIABLE_EVAL: Counter = Counter::new("variable-eval");
pub static VARIABLE_EVAL_FAIL: Counter = Counter::new("variable-eval-fail");
pub static BIT_EXEC: Counter = Counter::new("bit-exec");
pub static BIT_EXEC_SUCCESS: Counter = Counter::new("bit-exec-success");
pub static MM_EXEC: Counter = Counter::new("mm-exec");
pub static MM_EXEC_SUCCESS: Counter = Counter::new("mmn-exec-success");
pub static CORPUS_EXEC: Counter = Counter::new("corpus-exec");
pub static CORPUS_EXEC_MINIMAL: Counter = Counter::new("corpus-exec-success");
pub static DUPLICATES: Counter = Counter::new("duplicates");
/// Metrics for lists, broken down by list type: the length distribution in power-of-two buckets
/// and how many of a list's elements are distinct, over all the lists and over the executable ones.
pub static LISTS: ListStats = ListStats::new();

pub static STATS: [RuntimeStats; 40] = [
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
    RuntimeStats::AllTermEval(&ALL_TERM_EVAL),
    RuntimeStats::AllTermEvalSuccess(&ALL_TERM_EVAL_SUCCESS),
    RuntimeStats::DeconstructorEval(&DECONSTRUCTOR_EVAL),
    RuntimeStats::DeconstructorEvalFail(&DECONSTRUCTOR_EVAL_FAIL),
    RuntimeStats::VariableEval(&VARIABLE_EVAL),
    RuntimeStats::VariableEvalFail(&VARIABLE_EVAL_FAIL),
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
    RuntimeStats::Duplicates(&DUPLICATES),
    RuntimeStats::PerType(&LISTS),
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

/// Separator between the three fields of a per-list-type stat name: `<metric>|<type>|<slot>`.
/// Rust type names never contain it, so the monitor can split a name back apart.
pub const PER_TYPE_SEP: char = '|';

/// Number of length buckets of [`ListStats`]: bucket 0 holds the empty lists, bucket `b > 0` the
/// lengths in `2^(b-1)..2^b`, and the last one everything from `2^(BUCKETS-2)` up. With 12
/// buckets the labels are 0, 1, 2, 4, ... 512, >=1024.
///
/// Nothing caps a list's *length*; what binds is
/// [`max_term_size`](crate::fuzzer::utils::TermConstraints::max_term_size), the node budget the
/// mutators select under, which a list spends one node per element plus one for itself. At its
/// default of 800 a list of one-node elements saturates just under 800 elements, so the `>=1024`
/// bucket is out of reach: it filling means the budget was raised (or something escaped it),
/// which is worth seeing rather than folding into `512`.
pub const LENGTH_BUCKETS: usize = 12;

/// The lower bound of bucket `bucket`, which is also how a bar chart labels it.
#[must_use]
pub fn bucket_label(bucket: usize) -> usize {
    if bucket == 0 {
        0
    } else {
        1 << (bucket - 1)
    }
}

/// The bucket a label produced by [`bucket_label`] came from, or `None` when the label is no
/// bucket's lower bound.
///
/// A label *is* a length -- the smallest one its bucket holds -- so this is just the bucketing of
/// a length, with the labels that no bucket starts at rejected.
#[must_use]
pub fn bucket_of_label(label: usize) -> Option<usize> {
    (label == 0 || label.is_power_of_two()).then(|| length_bucket(label))
}

/// Return bucket index given a list length.
#[must_use]
fn length_bucket(length: usize) -> usize {
    if length == 0 {
        0
    } else {
        ((usize::BITS - length.leading_zeros()) as usize).min(LENGTH_BUCKETS - 1)
    }
}

/// Drops the module paths out of a `std::any::type_name`, so that
/// `alloc::vec::Vec<tlspuffin::tls::..::ClientExtension>` fires as `Vec<ClientExtension>`.
///
/// Two types that only differ by module therefore share a name here; they would be merged in the
/// stats, which is a readability trade-off, not a correctness one -- the accumulators themselves
/// stay keyed by the full name.
#[must_use]
pub fn short_type_name(name: &str) -> String {
    let mut short = String::with_capacity(name.len());
    // Where in `short` the identifier being collected starts, so that a `::` can drop it.
    let mut segment_start = 0;
    let mut chars = name.char_indices();
    while let Some((index, c)) = chars.next() {
        if name[index..].starts_with("::") {
            short.truncate(segment_start);
            chars.next(); // the second `:`
            continue;
        }
        short.push(c);
        if !(c.is_alphanumeric() || c == '_') {
            segment_start = short.len();
        }
    }
    short
}

/// The names of the slots [`ListCounters`] fires diversity counters under, in the order of
/// [`ListCounters::diversity`].
const DIVERSITY_SLOTS: [&str; 5] = [
    "lists",
    "nonempty",
    "elements",
    "distinct",
    "ratio-permille",
];

/// The counters of one family of the lists of one type: either all of them or only the executable
/// ones.
///
/// The raw sums are what is fired; the monitor divides them, so that the ratios stay exact under
/// the cross-client `Sum` aggregation (averaging averages would not).
#[derive(Default)]
struct ListCounters {
    /// Lengths in power-of-two buckets, see [`LENGTH_BUCKETS`].
    lengths: [AtomicUsize; LENGTH_BUCKETS],
    /// Lists observed, empty ones included.
    lists: AtomicUsize,
    /// Lists with at least one element: the denominator of `ratio_permille`.
    nonempty: AtomicUsize,
    /// Elements over all those lists.
    elements: AtomicUsize,
    /// Distinct elements, summed per list.
    distinct: AtomicUsize,
    /// `distinct / length` per list, in permille, summed.
    ratio_permille: AtomicUsize,
}

impl ListCounters {
    /// Records one list, given its length and its number of distinct elements.
    fn record(&self, length: usize, distinct: usize) {
        self.lengths[length_bucket(length)].fetch_add(1, Ordering::Relaxed);
        self.lists.fetch_add(1, Ordering::Relaxed);
        self.elements.fetch_add(length, Ordering::Relaxed);
        self.distinct.fetch_add(distinct, Ordering::Relaxed);
        if let Some(permille) = (distinct * 1000).checked_div(length) {
            self.nonempty.fetch_add(1, Ordering::Relaxed);
            self.ratio_permille.fetch_add(permille, Ordering::Relaxed);
        }
    }

    /// The diversity counters, in the order of [`DIVERSITY_SLOTS`].
    fn diversity(&self) -> [&AtomicUsize; DIVERSITY_SLOTS.len()] {
        [
            &self.lists,
            &self.nonempty,
            &self.elements,
            &self.distinct,
            &self.ratio_permille,
        ]
    }

    /// Fires every counter under the matching name of `names`.
    fn fire(
        &self,
        names: &ListNames,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let lengths = self.lengths.iter().zip(&names.lengths);
        let diversity = self.diversity().into_iter().zip(&names.diversity);
        for (counter, name) in lengths.chain(diversity) {
            consume(
                name.clone(),
                UserStats::new(
                    UserStatsValue::Number(counter.load(Ordering::Relaxed) as u64),
                    AggregatorOps::Sum,
                ),
            )?;
        }
        Ok(())
    }
}

/// The names a [`ListCounters`] fires under: `<metric>|<short type>|<slot>`.
///
/// Built once per list type, so that firing -- which happens for every slot of every type every
/// second -- does not have to format them again.
struct ListNames {
    /// One per length bucket, labelled by the bucket's lower bound.
    lengths: Vec<String>,
    /// One per [`DIVERSITY_SLOTS`].
    diversity: [String; DIVERSITY_SLOTS.len()],
}

impl ListNames {
    fn new(length_metric: &str, diversity_metric: &str, short_type: &str) -> Self {
        let name = |metric: &str, slot: &str| {
            format!("{metric}{PER_TYPE_SEP}{short_type}{PER_TYPE_SEP}{slot}")
        };
        Self {
            lengths: (0..LENGTH_BUCKETS)
                .map(|bucket| name(length_metric, &bucket_label(bucket).to_string()))
                .collect(),
            diversity: DIVERSITY_SLOTS.map(|slot| name(diversity_metric, slot)),
        }
    }
}

/// Everything observed about the lists of one type.
struct ListEntry {
    all: ListCounters,
    all_names: ListNames,
    /// Only the lists of steps that were executed.
    executable: ListCounters,
    executable_names: ListNames,
}

impl ListEntry {
    fn new(list_type: &str) -> Self {
        let short_type = short_type_name(list_type);
        Self {
            all: ListCounters::default(),
            all_names: ListNames::new("list-length", "list-diversity", &short_type),
            executable: ListCounters::default(),
            executable_names: ListNames::new(
                "executable-list-length",
                "executable-list-diversity",
                &short_type,
            ),
        }
    }
}

/// The length distribution and element diversity of the lists, one entry per list type, lazily
/// created the first time that type is observed.
///
/// The list types of a signature are registered at link time (see
/// [`define_list_types!`](crate::define_list_types)), so they cannot be laid out in a `const`
/// array the way the other stats are. The map is therefore behind an [`RwLock`]: observing a type
/// already seen -- the overwhelmingly common case -- only takes the read lock and then touches
/// atomics, so the writers only contend once per type. Everything about a list is kept in one
/// entry so that recording it costs a single lookup.
///
/// Four metrics are fired per type: `list-length` (a histogram in power-of-two buckets) and
/// `list-diversity` (how many of a list's elements are distinct) over all the lists, and the same
/// two prefixed with `executable-` over the lists of executed steps.
pub struct ListStats {
    /// Keyed by the full `type_name`; the shortened name to fire under lives in the entry.
    /// [`LazyLock`] only because a `HashMap`'s hasher cannot be built in a `const fn`.
    entries: LazyLock<RwLock<HashMap<&'static str, ListEntry>>>,
}

impl ListStats {
    const fn new() -> Self {
        Self {
            entries: LazyLock::new(|| RwLock::new(HashMap::new())),
        }
    }

    /// Records one list of type `list_type`, given its length and its number of distinct elements.
    /// `executable` tells whether the step it belongs to was executed.
    pub fn update(
        &self,
        list_type: &'static str,
        length: usize,
        distinct: usize,
        executable: bool,
    ) {
        let record = |entry: &ListEntry| {
            entry.all.record(length, distinct);
            if executable {
                entry.executable.record(length, distinct);
            }
        };

        if let Some(entry) = self.entries.read().unwrap().get(list_type) {
            record(entry);
            return;
        }

        let mut entries = self.entries.write().unwrap();
        record(
            entries
                .entry(list_type)
                .or_insert_with(|| ListEntry::new(list_type)),
        );
    }
}

impl Fire for ListStats {
    fn fire(
        &self,
        consume: &mut dyn FnMut(String, UserStats) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for entry in self.entries.read().unwrap().values() {
            entry.all.fire(&entry.all_names, consume)?;
            entry.executable.fire(&entry.executable_names, consume)?;
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
    last_per_type_fire: Instant,
}

/// How often the per-list-type stats are fired. They are one entry per list type and bucket, so
/// firing them every iteration the way the scalar counters are would multiply the monitor's event
/// traffic by the number of list types -- for values the monitor only reads once per
/// `--stats-interval` anyway. A name that is not re-fired keeps its last value, so this only makes
/// the list panels slightly stale, never gappy.
const PER_TYPE_FIRE_INTERVAL: Duration = Duration::from_secs(1);

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
            let fire_per_type = self.last_per_type_fire.elapsed() >= PER_TYPE_FIRE_INTERVAL;
            if fire_per_type {
                self.last_per_type_fire = Instant::now();
            }

            for stat in &STATS {
                if stat.is_per_type() && !fire_per_type {
                    continue;
                }
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
            last_per_type_fire: Instant::now(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_lose_their_module_paths() {
        assert_eq!(
            short_type_name("alloc::vec::Vec<tlspuffin::tls::msgs::ClientExtension>"),
            "Vec<ClientExtension>"
        );
        assert_eq!(short_type_name("alloc::vec::Vec<u8>"), "Vec<u8>");
        assert_eq!(
            short_type_name("alloc::vec::Vec<alloc::vec::Vec<u8>>"),
            "Vec<Vec<u8>>"
        );
        // A name with no path is already short.
        assert_eq!(
            short_type_name("Vec<ClientExtension>"),
            "Vec<ClientExtension>"
        );
    }

    #[test]
    fn lengths_land_in_power_of_two_buckets() {
        // Bucket 0 is the empty list; bucket `b` covers `2^(b-1)..2^b`.
        assert_eq!(length_bucket(0), 0);
        assert_eq!(length_bucket(1), 1);
        assert_eq!(length_bucket(2), 2);
        assert_eq!(length_bucket(3), 2);
        assert_eq!(length_bucket(4), 3);
        assert_eq!(length_bucket(7), 3);
        assert_eq!(length_bucket(1024), LENGTH_BUCKETS - 1);
        // Everything past the last labelled bucket saturates into it.
        assert_eq!(length_bucket(usize::MAX), LENGTH_BUCKETS - 1);
    }

    #[test]
    fn bucket_labels_round_trip() {
        for bucket in 0..LENGTH_BUCKETS {
            assert_eq!(bucket_of_label(bucket_label(bucket)), Some(bucket));
        }
        assert_eq!(bucket_label(LENGTH_BUCKETS - 1), 1024);
        assert_eq!(bucket_of_label(3), None);
    }

    #[test]
    fn list_stats_are_fired_per_type_family_and_slot() {
        static LISTS: ListStats = ListStats::new();

        let list_type = "alloc::vec::Vec<test::Extension>";
        LISTS.update(list_type, 0, 0, true);
        // 5 distinct elements.
        LISTS.update(list_type, 5, 5, true);
        // 6 elements, 3 of them distinct, in a step that was never executed.
        LISTS.update(list_type, 6, 3, false);

        let mut fired = HashMap::new();
        let mut collect = |name: String, stats: UserStats| {
            if let UserStatsValue::Number(n) = stats.value() {
                fired.insert(name, *n);
            }
            Ok(())
        };
        LISTS.fire(&mut collect).unwrap();

        // 5 and 6 share the 4..7 bucket, labelled 4.
        assert_eq!(fired["list-length|Vec<Extension>|0"], 1);
        assert_eq!(fired["list-length|Vec<Extension>|4"], 2);
        assert_eq!(fired["list-length|Vec<Extension>|2"], 0);
        assert_eq!(fired["list-diversity|Vec<Extension>|lists"], 3);
        assert_eq!(fired["list-diversity|Vec<Extension>|nonempty"], 2);
        assert_eq!(fired["list-diversity|Vec<Extension>|elements"], 11);
        assert_eq!(fired["list-diversity|Vec<Extension>|distinct"], 8);
        // 1000 for the first non-empty list, 500 for the second.
        assert_eq!(fired["list-diversity|Vec<Extension>|ratio-permille"], 1500);

        // The unexecuted list only counts in the plain stats.
        assert_eq!(fired["executable-list-length|Vec<Extension>|0"], 1);
        assert_eq!(fired["executable-list-length|Vec<Extension>|4"], 1);
        assert_eq!(fired["executable-list-diversity|Vec<Extension>|lists"], 2);
        assert_eq!(
            fired["executable-list-diversity|Vec<Extension>|nonempty"],
            1
        );
        assert_eq!(
            fired["executable-list-diversity|Vec<Extension>|elements"],
            5
        );
        assert_eq!(
            fired["executable-list-diversity|Vec<Extension>|distinct"],
            5
        );
        assert_eq!(
            fired["executable-list-diversity|Vec<Extension>|ratio-permille"],
            1000
        );
    }
}
