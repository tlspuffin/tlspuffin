use std::any::TypeId;
use std::cmp::{max, min};
use std::collections::HashSet;

use itertools::Itertools;
use libafl::corpus::InMemoryCorpus;
use libafl::state::{HasRand, StdState};
use libafl_bolts::rands::{Rand, RomuDuoJrRand, StdRand};

use crate::agent::AgentName;
use crate::algebra::error::FnError;
use crate::algebra::signature::{FunctionDefinition, Signature};
use crate::algebra::term::TermType;
use crate::algebra::{DYTerm, Term};
use crate::error::Error;
use crate::execution::{ExecutionStatus, ForkError};
use crate::fuzzer::term_zoo::TermZoo;
use crate::fuzzer::utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints};
use crate::graphviz::write_graphviz;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::put_registry::PutRegistry;
use crate::trace::{Action, InputAction, MetadataTrace, Spawner, Step, Trace, TraceContext};

impl<PT: ProtocolTypes> Trace<PT> {
    #[must_use]
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        self.steps
            .iter()
            .map(|step| match &step.action {
                Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                Action::Output(_) => 0,
            })
            .sum()
    }

    #[must_use]
    pub fn count_functions(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .map(|term| term.size())
            .sum()
    }

    pub fn write_plots(&self, i: u16) {
        write_graphviz(
            format!("test_mutation{i}.svg").as_str(),
            "svg",
            self.dot_graph(true).as_str(),
        )
        .unwrap();
    }
}

impl<PT: ProtocolTypes> Term<PT> {
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        let mut found = 0;
        for term in self {
            if let DYTerm::Application(func, _) = &term.term {
                if func.name() == find_name {
                    found += 1;
                }
            }
        }
        found
    }
}

// ── Term zoo tests ────────────────────────────────────────────────────────────
//
// Protocol-generic checks over a "zoo" of generated terms, one test per property of the
// signature: every symbol can be generated, evaluated, read back and re-encoded, and carry
// payloads (the MakeMessage path) that bit-level mutations then change. Each protocol calls them
// from its `tests/term_zoo.rs` with its signature, registry and the symbols it expects to fail.

/// A term-zoo run: for each symbol of `signature`, generate terms rooted at it and apply a check
/// to them (see [`ZooTest::run`]).
pub struct ZooTest<'a, PB: ProtocolBehavior> {
    pub signature: &'a Signature<PB::ProtocolTypes>,
    pub registry: PutRegistry<PB>,
    /// Number of terms to generate for each function symbol (at root position).
    pub how_many: usize,
    /// Do not test further terms of a symbol once one passed the check.
    pub stop_on_success: bool,
    /// Do not test further terms of a symbol once one failed the check.
    pub stop_on_error: bool,
    /// Only generate terms that evaluate.
    pub filter_executable: bool,
    /// Do not generate terms rooted at a `[no_gen]` symbol.
    pub filter_no_gen: bool,
    /// Only test this symbol.
    pub filter: Option<&'a FunctionDefinition<PB::ProtocolTypes>>,
    /// Symbols expected to fail the check; the run also fails if one of them passes.
    pub ignored_functions: HashSet<String>,
    /// Symbols whose outcome is not checked either way.
    pub unstable_functions: HashSet<String>,
}

impl<'a, PB: ProtocolBehavior> ZooTest<'a, PB> {
    /// Whether the check's outcome on `symbol` counts (it is neither ignored nor unstable).
    fn counts(&self, symbol: &str) -> bool {
        !self.ignored_functions.contains(symbol) && !self.unstable_functions.contains(symbol)
    }

    #[must_use]
    pub fn new(signature: &'a Signature<PB::ProtocolTypes>, registry: PutRegistry<PB>) -> Self {
        Self {
            signature,
            registry,
            how_many: 20,
            stop_on_success: true,
            stop_on_error: false,
            filter_executable: true,
            filter_no_gen: true,
            filter: None,
            ignored_functions: HashSet::new(),
            unstable_functions: HashSet::new(),
        }
    }

    /// Generates the zoo and applies `test_map` to every term. Returns whether every symbol that
    /// is neither ignored nor unstable passed the check at least once, and no ignored one did.
    pub fn run<Ft>(&self, mut rand: RomuDuoJrRand, mut test_map: Ft) -> bool
    where
        Ft: FnMut(
            &Term<PB::ProtocolTypes>,
            &TraceContext<PB>,
            &mut RomuDuoJrRand,
        ) -> Result<(), Error>,
    {
        let spawner = Spawner::new(self.registry.clone());
        let ctx = TraceContext::new(spawner);

        // `test_map` draws from its own RNG, so that whatever it consumes cannot shift the stream
        // `generate_many` draws from. Sharing one RNG makes the generated zoo depend on the
        // closure's internals: a change to the sub-term sampling it uses (`reservoir_sample`, say)
        // then silently regenerates the whole zoo, and coverage assertions over rare symbols flip
        // on seeds unrelated to the change.
        let mut test_map_rand = RomuDuoJrRand::with_seed(rand.next());

        let all_functions_shape = self.signature.functions.to_owned();
        let number_functions = all_functions_shape.len();
        let mut number_terms = 0;
        let mut number_success = 0;
        let mut number_failure = 0;
        let mut number_failure_on_ignored = 0;
        let mut successful_functions = vec![];

        let how_many = self.how_many;
        let bucket_size = 200;
        for f in &all_functions_shape {
            if self.filter.is_none() || self.filter.is_some_and(|g| g.0.name == f.0.name) {
                'outer: for i in 0..max(1, how_many / bucket_size) {
                    let bucket_size_step =
                        if how_many < bucket_size || i < how_many / bucket_size - 1 {
                            min(how_many, bucket_size)
                        } else {
                            min(
                                how_many,
                                how_many - bucket_size * (how_many / bucket_size - 1),
                            )
                        };
                    log::error!("Call generate_many with bucket_size_step={bucket_size_step} and function {} and filter_executable: {}", f.0.name, self.filter_executable);
                    let zoo_f = TermZoo::<PB>::generate_many(
                        &ctx,
                        self.signature,
                        &mut rand,
                        bucket_size_step,
                        TermConstraints::default().zoo_max_depth,
                        Some(f),
                        self.filter_executable,
                        self.filter_no_gen,
                    );
                    let terms_f = zoo_f.terms();
                    if terms_f.len() != how_many {
                        log::warn!(
                            "Failed to generate {bucket_size_step} terms (only {}) for function {}.",
                            terms_f.len(),
                            f.0.name
                        );
                    }
                    number_terms += terms_f.len();

                    for term in terms_f {
                        match test_map(term, &ctx, &mut test_map_rand) {
                            Ok(()) => {
                                successful_functions.push(term.name().to_string());
                                number_success += 1;
                                if self.stop_on_success {
                                    break 'outer;
                                }
                            }
                            Err(e) => {
                                if self.ignored_functions.contains(term.name()) {
                                    log::debug!("[Ignored function] Failed to test_map term {term} with error {e}. ");
                                    number_failure_on_ignored += 1;
                                } else {
                                    log::error!("[Not ignored function] Failed to test_map term {term} with error {e}. ");
                                    number_failure += 1;
                                    if self.stop_on_error {
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let all_functions = all_functions_shape
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut successful_functions = successful_functions
            .into_iter()
            .collect::<HashSet<String>>();
        let successful_functions_tested = successful_functions.clone();
        successful_functions.extend(self.ignored_functions.clone());

        let difference = all_functions.difference(&successful_functions);
        let difference_inverse = successful_functions_tested.intersection(&self.ignored_functions);

        // We do not crash the test if we have issues with the unstable functions
        let unstable = &self.unstable_functions;
        let difference_set: HashSet<String> = difference.map(String::to_string).collect();
        let difference_inverse_set: HashSet<String> =
            difference_inverse.map(String::to_string).collect();
        let difference_wo_unstable: HashSet<&String> =
            difference_set.difference(unstable).collect();
        let difference_inverse_wo_unstable: HashSet<&String> =
            difference_inverse_set.difference(unstable).collect();

        log::debug!(
            "[zoo_test] ignored_functions: {:?}\n",
            &self.ignored_functions
        );
        log::debug!("[zoo_test] unstable functions: {:?}\n", unstable);
        log::error!("[zoo_test] Diff: {:?}", &difference_set);
        log::error!(
            "[zoo_test] Diff without unstable: {:?}",
            &difference_wo_unstable
        );
        log::error!(
            "[zoo_test] Intersect with ignored: {:?}",
            &difference_inverse_set
        );
        log::error!(
            "[zoo_test] Intersect ignored without unstable: {:?}",
            &difference_inverse_wo_unstable
        );
        log::error!(
            "[zoo_test] Stats: how_many: {how_many}, stop_on_success: {}, stop_on_error: {}\n\
            --> number_functions: {}, number_terms: {}, number_success: {}, number_failure: {}, number_failure_on_ignored: {}\n\
            --> Successfully built (out of {:?} functions): {:?}",
            self.stop_on_success,
            self.stop_on_error,
            number_functions,
            number_terms,
            number_success,
            number_failure,
            number_failure_on_ignored,
            &all_functions.len(),
            &successful_functions_tested.len()
        );
        difference_wo_unstable.is_empty() && difference_inverse_wo_unstable.is_empty()
    }
}

/// Outcome tally of [`term_read_encode`].
#[derive(Debug, Default, Clone)]
pub struct ReadEncodeStats {
    /// Evaluations that `try_read_bytes` read back as their declared type.
    pub read_count: usize,
    /// …and whose re-encoding was byte-identical to the evaluation.
    pub read_success: usize,
    /// `try_read_bytes` failed, on a symbol that is neither ignored nor unstable.
    pub read_fail: usize,
    /// Read back but re-encoded differently, on a symbol that is neither ignored nor unstable.
    pub read_wrong: usize,
    /// The symbols counted in `read_wrong`.
    pub wrong_functions: Vec<String>,
}

/// Evaluate, read back with [`ProtocolBehavior::try_read_bytes`] and re-encode every term of the
/// zoo: the re-encoding must be the evaluation. Returns whether every run of the zoo passed (see
/// [`ZooTest::run`]), and the tally.
pub fn term_read_encode<PB: ProtocolBehavior>(
    zoo: &ZooTest<PB>,
    seeds: impl IntoIterator<Item = u64>,
) -> (bool, ReadEncodeStats) {
    let mut stats = ReadEncodeStats::default();
    let mut all_ok = true;
    for seed in seeds {
        let res = zoo.run(StdRand::with_seed(seed), |term, ctx, _| {
            let type_id: TypeId = term.get_type_shape().clone().into();
            let eval1 = term.evaluate(ctx)?;
            match PB::try_read_bytes(&eval1, type_id) {
                Ok(message_back) => {
                    stats.read_count += 1;
                    let eval2 = PB::any_get_encoding(message_back.as_ref());
                    if eval2 == *eval1 {
                        stats.read_success += 1;
                        Ok(())
                    } else {
                        log::error!("[FAIL] Not the same read for term {}!\n  -Encoding1: {:?}\n  -Encoding2: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, eval2, term.get_type_shape(), type_id);
                        if zoo.counts(term.name()) {
                            stats.read_wrong += 1;
                            let name = term.name().to_string();
                            if !stats.wrong_functions.contains(&name) {
                                stats.wrong_functions.push(name);
                            }
                        }
                        Err(Error::Term("Not the same read".to_string()))
                    }
                }
                Err(e) => {
                    log::error!("Failed to read for term {}!\n  and encoding: {:?}\n  - TypeShape:{}, TypeId: {:?}", term, eval1, term.get_type_shape(), type_id);
                    if zoo.counts(term.name()) {
                        stats.read_fail += 1;
                    }
                    Err(Error::Fn(FnError::Codec(format!("Failed to read: {e}"))))
                }
            }
        });
        log::error!("[term_read_encode] seed {seed}: {res}");
        all_ok &= res;
    }
    log::error!("[term_read_encode] Read stats: {stats:?}");
    (all_ok, stats)
}

/// Outcome tally of [`term_payloads_eval`] and [`term_payloads_mutate_eval`].
#[derive(Debug, Default, Clone)]
pub struct PayloadEvalStats {
    /// Terms that evaluated with their payloads.
    pub success: usize,
    /// Terms, rooted at a counted symbol, on which no payload could be placed.
    pub add_payload_fail: usize,
    /// Terms, rooted at a counted symbol, that failed to evaluate with payloads.
    pub eval_payload_fail: usize,
    /// Bit-level mutations that left the payload unchanged or were skipped.
    pub mutate_fail: usize,
    /// Terms whose evaluation with payloads hit [`Error::TermBug`]: the payload machinery could
    /// not find a payload's bytes in its parent's encoding, i.e. the parent symbol is missing its
    /// `[opaque]` / `[get]` / `[list]` flag. Always a bug, whatever the root symbol.
    pub term_bug: usize,
    /// The first terms counted in `term_bug`.
    pub term_bug_terms: Vec<String>,
}

impl PayloadEvalStats {
    fn record_term_bug(&mut self, term: &dyn std::fmt::Display) {
        self.term_bug += 1;
        if self.term_bug_terms.len() < 10 {
            self.term_bug_terms.push(term.to_string());
        }
    }
}

/// Place a few random payloads on every evaluable term of the zoo (as `MakeMessage` does), and
/// evaluate it with them. Returns whether every run of the zoo passed (see [`ZooTest::run`]),
/// and the tally, whose `term_bug` must be 0.
pub fn term_payloads_eval<PB: ProtocolBehavior>(
    zoo: &ZooTest<PB>,
    seeds: impl IntoIterator<Item = u64>,
) -> (bool, PayloadEvalStats) {
    let mut stats = PayloadEvalStats::default();
    let mut all_ok = true;
    for seed in seeds {
        let res = zoo.run(StdRand::with_seed(seed), |term, ctx, rand2| {
            term.evaluate(ctx)?;
            let mut term_with_payloads = term.clone();
            add_payloads_randomly(&mut term_with_payloads, rand2, ctx);
            if term_with_payloads.count_payloads() == 0 {
                log::warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
                if zoo.counts(term.name()) {
                    stats.add_payload_fail += 1;
                }
                return Err(Error::Term("Failed to add payloads".to_string()));
            }
            log::debug!("Term with payloads: {term_with_payloads}");
            // Sanity check:
            test_pay(&term_with_payloads);
            // `evaluate_config` rather than `evaluate`: the latter panics on `Error::TermBug` in
            // debug builds, which this check counts instead.
            match term_with_payloads.evaluate_config(ctx, true) {
                Ok(_) => {
                    stats.success += 1;
                    Ok(())
                }
                Err(e) => {
                    log::error!("Eval FAILED with payloads: {term_with_payloads}.");
                    if matches!(e, Error::TermBug(_)) {
                        stats.record_term_bug(&term_with_payloads);
                    }
                    if zoo.counts(term.name()) {
                        stats.eval_payload_fail += 1;
                    }
                    Err(Error::Term("Failed to evaluate with payloads".to_string()))
                }
            }
        });
        log::error!("[term_payloads_eval] seed {seed}: {res}");
        all_ok &= res;
    }
    log::error!("[term_payloads_eval] Stats: {stats:?}");
    (all_ok, stats)
}

/// A libafl state with only a random generator, for mutators that need no corpus.
fn rand_state<PT: ProtocolTypes>(
    seed: u64,
) -> StdState<InMemoryCorpus<Trace<PT>>, Trace<PT>, RomuDuoJrRand, InMemoryCorpus<Trace<PT>>> {
    StdState::new(
        StdRand::with_seed(seed),
        InMemoryCorpus::new(),
        InMemoryCorpus::new(),
        &mut (),
        &mut (),
    )
    .unwrap()
}

/// As [`term_payloads_eval`], but also flip a bit in one of the payloads (as the bit-level
/// mutations do) before evaluating: some mutant of every term must still evaluate.
pub fn term_payloads_mutate_eval<PB: ProtocolBehavior>(
    zoo: &ZooTest<PB>,
    seeds: impl IntoIterator<Item = u64>,
) -> (bool, PayloadEvalStats) {
    use libafl::mutators::mutations::BitFlipMutator;
    use libafl::mutators::{MutationResult, Mutator};

    let mut stats = PayloadEvalStats::default();
    let mut all_ok = true;
    for seed in seeds {
        let res = zoo.run(StdRand::with_seed(seed), |term, ctx, rand2| {
            let mut state = rand_state::<PB::ProtocolTypes>(1235);
            let mut term_with_payloads = term.clone();
            add_payloads_randomly(&mut term_with_payloads, rand2, ctx);
            if term_with_payloads.count_payloads() == 0 {
                log::warn!("Failed to add payloads, skipping... For:\n   {term_with_payloads}");
                if zoo.counts(term.name()) {
                    stats.add_payload_fail += 1;
                }
                return Err(Error::Term("Failed to add payloads".to_string()));
            }
            log::debug!("Term with payloads: {term_with_payloads}");
            // Sanity check:
            test_pay(&term_with_payloads);
            let mut tries = 0;
            while tries < 1_000 {
                let mut mutant = term_with_payloads.clone();
                tries += 1;
                let mut all_payloads = mutant.all_payloads_mut();
                let idx = state.rand_mut().between(0, all_payloads.len() - 1);
                let payload_to_mutate = all_payloads.remove(idx);
                let payload_to_mutate_orig = payload_to_mutate.payload_0.clone();
                let payload_to_mutate = &mut payload_to_mutate.payload;
                match BitFlipMutator.mutate(&mut state, payload_to_mutate).unwrap() {
                    MutationResult::Mutated => {
                        if payload_to_mutate_orig == *payload_to_mutate {
                            log::warn!("Mutated payload is the same as original: {payload_to_mutate_orig:?} == {payload_to_mutate:?}");
                            stats.mutate_fail += 1;
                            continue;
                        }
                        // `evaluate_config`: see `term_payloads_eval`.
                        match mutant.evaluate_config(ctx, true) {
                            Ok(_) => {
                                stats.success += 1;
                                return Ok(());
                            }
                            Err(e) => {
                                log::warn!("Eval FAILED with payloads: {term_with_payloads} and error {e}.");
                                if matches!(e, Error::TermBug(_)) {
                                    stats.record_term_bug(&mutant);
                                }
                                if zoo.counts(term.name()) {
                                    stats.eval_payload_fail += 1;
                                }
                                continue;
                            }
                        }
                    }
                    MutationResult::Skipped => {
                        stats.mutate_fail += 1;
                    }
                }
            }
            Err(Error::Term(format!(
                "Failed to find a way to mutate {term_with_payloads}!"
            )))
        });
        log::error!("[term_payloads_mutate_eval] seed {seed}: {res}");
        all_ok &= res;
    }
    log::error!("[term_payloads_mutate_eval] Stats: {stats:?}");
    (all_ok, stats)
}

/// Add up to a third of the term's sub-terms (at least one) as payloads, at random places.
pub fn add_payloads_randomly<
    PT: ProtocolTypes,
    R: Rand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
>(
    t: &mut Term<PT>,
    rand: &mut R,
    ctx: &TraceContext<PB>,
) {
    let all_subterms: Vec<&Term<PT>> = t.into_iter().collect_vec();
    let nb_subterms = all_subterms.len() as i32;
    let mut i = 0;
    let nb = (1..max(4, nb_subterms / 3))
        .collect::<Vec<i32>>()
        .choose(rand)
        .unwrap()
        .to_owned();
    log::debug!(
        "Adding {nb} payloads for #subterms={nb_subterms}, max={} in term: {t}...",
        max(2, nb_subterms / 5)
    );
    let mut tries = 0;
    while i < nb {
        tries += 1;
        if tries > nb * 100 {
            log::error!("Failed to add the payloads after {} attempts", tries);
            break;
        }
        if let Ok(()) = add_one_payload_randomly(t, rand, ctx) {
            i += 1;
        }
    }
}

/// Sanity check for the payload tests: no payload may sit below another one.
pub fn test_pay<PT: ProtocolTypes>(term: &Term<PT>) {
    rec_inside(term, false, term);
    pub fn rec_inside<PT: ProtocolTypes>(
        term: &Term<PT>,
        already_found: bool,
        whole_term: &Term<PT>,
    ) {
        let already_found = already_found || !term.is_symbolic();
        match &term.term {
            DYTerm::Variable(_) => {}
            DYTerm::Application(_, sub) => {
                for ti in sub {
                    if already_found && !ti.is_symbolic() {
                        panic!("Eheh, found one! Sub: {ti},\n whole_term: {whole_term}")
                    } else {
                        rec_inside(ti, already_found, whole_term)
                    }
                }
            }
        }
    }
}

/// Place one payload at a random sub-term (as the `MakeMessage` mutation does) and change it.
pub fn add_one_payload_randomly<
    PT: ProtocolTypes,
    R: Rand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
>(
    t: &mut Term<PT>,
    rand: &mut R,
    ctx: &TraceContext<PB>,
) -> Result<(), Error> {
    let trace = Trace {
        descriptors: vec![],
        steps: vec![Step {
            agent: AgentName::new(),
            action: Action::Input(InputAction {
                precomputations: vec![],
                recipe: t.clone(),
            }),
        }],
        prior_traces: vec![],
        metadata_trace: MetadataTrace::default(),
    };
    if let Some((st_, (step, path))) = choose(
        &trace,
        &TermConstraints {
            // as for Make_message.mutate
            no_payload_in_subterm: false,
            not_inside_list: false, // should be true, TODO: fix this
            weighted_depth: false,  // should be true, TODO: fix this
            ..TermConstraints::default()
        },
        rand,
    ) {
        let st = find_term_by_term_path_mut(t, &path).unwrap();
        if let Ok(()) = st.make_payload(ctx) {
            log::debug!("Added payload for subterm at path {path:?}, step{step},\n - sub_term: {st_}\n  - whole_term {trace}\n  - evaluated={:?}, ", st.payloads.as_ref().unwrap().payload_0);
            if let Some(payloads) = &mut st.payloads {
                let mut a: Vec<u8> = payloads.payload.clone().into();
                a.push(2); // TODO: make something random here! (I suggest mutate with bit-level mutations)
                a.push(2);
                a.push(2);
                a[0] = 2;
                payloads.payload = a.into();
                log::debug!("Added a payload at path {path:?}.");
                Ok(())
            } else {
                panic!("Should never happen")
            }
        } else {
            Err(Error::Term(
                "[add_one_payload_randomly] Unable to make_message".to_string(),
            ))
        }
    } else {
        Err(Error::Term(
            "[add_one_payload_randomly] Unable to choose a suitable sub-term".to_string(),
        ))
    }
}

pub trait AssertExecution {
    fn expect_crash(self);
}

impl AssertExecution for Result<ExecutionStatus, ForkError> {
    fn expect_crash(self) {
        use ExecutionStatus as S;
        match self {
            Ok(S::Crashed) => (),
            Ok(S::Failure(_)) => panic!("invalid trace"),
            Ok(S::Timeout) => panic!("trace execution timed out"),
            Ok(S::Interrupted) => panic!("trace execution interrupted"),
            Ok(S::Success) => panic!("expected trace execution to crash, but succeeded"),
            Err(reason) => panic!("trace execution error: {reason}"),
        }
    }
}

#[macro_export]
macro_rules! test_puts {
    // handle default arguments
    ( $func:ident) => { test_puts!( $func, attrs = [], filter = all() ); };
    ( $func:ident, puts = $puts:tt ) => { test_puts!( $func, puts = $puts, attrs = [], filter = all() ); };
    ( $func:ident, puts = $puts:tt, attrs = $attrs:tt ) => { test_puts!( $func, puts = $puts, attrs = $attrs, filter = all() ); };
    ( $func:ident, puts = $puts:tt, filter = $filter:meta ) => { test_puts!( $func, puts = $puts, attrs = [], filter = $filter ); };
    ( $func:ident, attrs = $attrs:tt  ) => { test_puts!( $func, puts = all, attrs = $attrs, filter = all() ); };
    ( $func:ident, filter = $filter:meta ) => { test_puts!( $func, puts = all, attrs = [], filter = $filter ); };
    ( $func:ident, attrs = $attrs:tt, filter = $filter:meta ) => { test_puts!( $func, puts = all, attrs = $attrs, filter = $filter ); };

    // put arguments in a canonical order
    ( $func:ident, attrs = $attrs:tt, puts = $puts:tt, filter = $filter:meta ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, attrs = $attrs:tt, filter = $filter:meta, puts = $puts:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, filter = $filter:meta, puts = $puts:tt, attrs = $attrs:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, filter = $filter:meta, attrs = $attrs:tt, puts = $puts:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };
    ( $func:ident, puts = $puts:tt, filter = $filter:meta, attrs = $attrs:tt ) => { test_puts!($func, puts = $puts, attrs = $attrs, filter = $filter); };

    // expand `puts` argument when `all` was requested
    ( $func:ident, puts = all, attrs = $attrs:tt, filter = $filter:meta ) => {
        mod $func {
            #![allow(unused_imports)]
            #![allow(unexpected_cfgs)]

            use super::$func;
            use super::for_puts;
            use super::test_puts;
            use puffin_macros::expand_cfg;

            for_puts!(
                test_puts!(@expand-one $func, put = __PUT__:__PUTSTR__, attrs = $attrs, filter = $filter);
            );
        }
    };

    // actual expansion with canonical arguments
    ( $func:ident, puts = [ $($put:ident : $putstr:literal),* ], attrs = $attrs:tt, filter = $filter:meta ) => {
        mod $func {
            #![allow(unused_imports)]
            #![allow(unexpected_cfgs)]

            use super::$func;
            use super::test_puts;
            use puffin_macros::expand_cfg;

            $(
                test_puts!(@expand-one $func, put = $put : $putstr, attrs = $attrs, filter = $filter);
            )*
        }
    };

    (@expand-one $func:ident, put = $put:ident : $putstr:literal, attrs = [ $( $attr:meta ),* ], filter = $filter:meta) => {
        #[cfg(has_put = $putstr)]
        #[expand_cfg($putstr, $filter)]
        #[test_log::test]
        $( #[$attr] )*
        fn $put() {
            $func($putstr);
        }
    };
}

#[macro_export]
macro_rules! test_differential_puts {
    ($func:ident,first = $first:literal,second = $second:literal) => {
        mod $func {
            #![allow(unexpected_cfgs)]
            use super::*;

            #[cfg(all(has_put = $first, has_put = $second))]
            #[test_log::test]
            fn run() {
                super::$func();
            }
        }
    };
}

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! supports {
    ($put:expr, $cap:expr) => {{
        use crate::put_registry::tls_registry;

        tls_registry()
            .find_by_id($put)
            .expect("PUT was not found")
            .supports($cap)
    }};
}

#[allow(unused_imports)]
pub(crate) use {supports, test_differential_puts, test_puts};
