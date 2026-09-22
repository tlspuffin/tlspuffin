use crate::algebra::term::TermType;
use crate::algebra::{DYTerm, Term};
use crate::execution::{ExecutionStatus, ForkError};
use crate::graphviz::write_graphviz;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::trace::{Action, Trace};

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

/// Outcome tally of [`zoo_read_encode`]: how many generated terms evaluated, then
/// survived a `try_read_bytes` → re-encode round-trip.
#[derive(Debug, Default, Clone)]
pub struct ReadEncodeStats {
    /// Terms whose evaluation re-read successfully via `try_read_bytes`.
    pub read_count: usize,
    /// …and whose re-encoding was byte-identical to the original evaluation.
    pub read_success: usize,
    /// `try_read_bytes` failed on a NON-ignored function's evaluation.
    pub read_fail: usize,
    /// `try_read_bytes` succeeded but re-encoding DIFFERED, on a NON-ignored function.
    pub read_wrong: usize,
    /// Distinct function-symbol names counted in `read_wrong` (for diagnostics: names
    /// the exact offenders so a `read_wrong > 0` failure is actionable).
    pub wrong_functions: Vec<String>,
}

/// Protocol-parametric encode / `try_read_bytes` / re-encode round-trip check.
///
/// This is the reusable, `PB`-generic core of the term-zoo read/encode test
/// (`tlspuffin/tests/term_zoo.rs::test_term_read_encode` is the reference
/// implementation for TLS). Any protocol opts in by calling it with its own
/// signature + registry — sshpuffin does so in `ssh::mod`'s test module — so the
/// "every message that can be built also round-trips through the wire codec"
/// invariant is exercised uniformly across protocols rather than being TLS-only.
///
/// For every function symbol in `signature`, generates `how_many` terms (per RNG
/// seed), evaluates each in an empty context (PUT-free), and — for those that
/// evaluate — reads the encoding back with [`ProtocolBehavior::try_read_bytes`],
/// re-encodes, and tallies the outcome. `ignored_functions` are symbols whose
/// read/re-encode mismatch is a known, accepted limitation (never counted in
/// `read_fail`/`read_wrong`). Returns the [`ReadEncodeStats`]; the caller decides
/// what to assert (typically `read_wrong == 0`).
///
/// Generation uses `filter_evaluated = false` deliberately: with it `true`,
/// `TermZoo::generate_for` burns the full `PB::ZOO_MAX_TRIES` budget (140k) on every
/// hard-to-evaluate symbol trying to force `how_many` *evaluable* draws, which makes
/// this test take ~9 min per seed regardless of `how_many`. Cheap syntactic
/// generation plus the explicit `evaluate()` skip below gives the same round-trip
/// coverage of every generatable symbol in well under a second.
pub fn zoo_read_encode<PB: ProtocolBehavior>(
    signature: &crate::algebra::signature::Signature<PB::ProtocolTypes>,
    registry: impl Into<crate::put_registry::PutRegistry<PB>>,
    seeds: &[u64],
    how_many: usize,
    ignored_functions: &std::collections::HashSet<String>,
) -> ReadEncodeStats {
    use std::any::TypeId;

    use libafl_bolts::rands::StdRand;

    use crate::fuzzer::term_zoo::TermZoo;
    use crate::fuzzer::utils::TermConstraints;
    use crate::trace::{Spawner, TraceContext};

    let spawner = Spawner::new(registry.into());
    let ctx = TraceContext::new(spawner);

    let mut stats = ReadEncodeStats::default();
    for &seed in seeds {
        let mut rand = StdRand::with_seed(seed);
        for def in &signature.functions {
            let zoo = TermZoo::<PB>::generate_many(
                &ctx,
                signature,
                &mut rand,
                how_many,
                TermConstraints::default().zoo_max_depth,
                Some(def),
                false, // filter_evaluated: keep cheap — we evaluate + skip below
                true,  // filter_no_gen: skip probe-only `[no_gen]` symbols
            );
            for term in zoo.terms() {
                let type_id: TypeId = term.get_type_shape().clone().into();
                let Ok(eval1) = term.evaluate(&ctx) else {
                    continue; // non-evaluable draw; not a read/encode outcome
                };
                match PB::try_read_bytes(&eval1, type_id) {
                    Ok(back) => {
                        stats.read_count += 1;
                        let eval2 = PB::any_get_encoding(back.as_ref());
                        if eval2 == *eval1 {
                            stats.read_success += 1;
                        } else if !ignored_functions.contains(term.name()) {
                            log::error!(
                                "[zoo_read_encode] re-encode differs for {}: {:?} != {:?}",
                                term.name(),
                                eval1,
                                eval2
                            );
                            stats.read_wrong += 1;
                            let name = term.name().to_string();
                            if !stats.wrong_functions.contains(&name) {
                                stats.wrong_functions.push(name);
                            }
                        }
                    }
                    Err(e) => {
                        if !ignored_functions.contains(term.name()) {
                            log::error!("[zoo_read_encode] read failed for {}: {e}", term.name());
                            stats.read_fail += 1;
                        }
                    }
                }
            }
        }
    }
    stats
}

/// Outcome tally of [`zoo_payloads_eval`].
#[derive(Debug, Default, Clone)]
pub struct PayloadEvalStats {
    /// Terms that still evaluated after payloads were added.
    pub success: usize,
    /// Terms (rooted at a NON-ignored symbol) on which no payload could be placed.
    pub add_payload_fail: usize,
    /// Terms (rooted at a NON-ignored symbol) that evaluated plainly but FAILED once
    /// payloads were added, with an `Error::TermBug` — the payload machinery could not
    /// locate a payload-bearing child's bytes in its parent: the flag-audit signal.
    pub eval_payload_fail: usize,
    /// Payload evaluations that failed with any OTHER error (e.g. a perturbed payload
    /// no longer parses) — expected noise, not a flag problem.
    pub other_eval_fail: usize,
    /// Per *parent* symbol of a payload-bearing sub-term: `(evals ok, TermBug fails)`.
    /// The parent's `FunctionAttributes` (`[opaque]` / `[get]` / `[list]`) decide
    /// whether the payload machinery can locate the child's bytes inside the parent's
    /// encoding, so a parent with a high failure count is the flag-audit signal.
    pub by_parent: std::collections::BTreeMap<String, (usize, usize)>,
}

/// Place one random payload in `t` (as the `MakeMessage` mutation would) and
/// perturb it; returns the name of the payload-bearing sub-term's parent symbol
/// (`"<root>"` for a root payload), or `None` if no payload could be placed.
fn add_one_payload_randomly<PB: ProtocolBehavior, R: libafl_bolts::rands::Rand>(
    t: &mut Term<PB::ProtocolTypes>,
    rand: &mut R,
    ctx: &crate::trace::TraceContext<PB>,
) -> Option<String> {
    use crate::agent::AgentName;
    use crate::fuzzer::utils::{choose, find_term_by_term_path_mut, TermConstraints};
    use crate::trace::{InputAction, MetadataTrace, Step};

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
    let constraints = TermConstraints {
        // as for MakeMessage.mutate (mirrors tlspuffin's add_one_payload_randomly)
        no_payload_in_subterm: false,
        not_inside_list: false,
        weighted_depth: false,
        ..TermConstraints::default()
    };
    let path = choose(&trace, &constraints, rand)?.1 .1;
    let parent = if path.is_empty() {
        "<root>".to_string()
    } else {
        find_term_by_term_path_mut(t, &path[..path.len() - 1])?
            .name()
            .to_string()
    };
    let st = find_term_by_term_path_mut(t, &path)?;
    st.make_payload(ctx).ok()?;
    let payloads = st.payloads.as_mut()?;
    let mut a: Vec<u8> = payloads.payload.clone().into();
    a.push(2);
    a.push(2);
    a.push(2);
    a[0] = 2;
    payloads.payload = a.into();
    Some(parent)
}

/// Protocol-parametric payload-evaluation check: generate terms per symbol (as
/// [`zoo_read_encode`] does), add a few random payloads to each evaluable term
/// (the `MakeMessage` + bit-mutation path), and re-evaluate. An `Error::TermBug`
/// means the payload machinery could not locate a payload-bearing sub-term's bytes
/// inside its parent's encoding — the symptom of a missing/wrong `[opaque]` /
/// `[get]` / `[list]` attribute on that parent (see `FunctionAttributes`). This is
/// the correctness check behind a signature flag audit (tlspuffin's
/// `test_term_payloads_eval` is the TLS reference).
pub fn zoo_payloads_eval<PB: ProtocolBehavior>(
    signature: &crate::algebra::signature::Signature<PB::ProtocolTypes>,
    registry: impl Into<crate::put_registry::PutRegistry<PB>>,
    seeds: &[u64],
    how_many: usize,
    ignored_functions: &std::collections::HashSet<String>,
) -> PayloadEvalStats {
    use libafl_bolts::rands::StdRand;

    use crate::fuzzer::term_zoo::TermZoo;
    use crate::fuzzer::utils::{Choosable, TermConstraints};
    use crate::trace::{Spawner, TraceContext};

    let spawner = Spawner::new(registry.into());
    let ctx = TraceContext::new(spawner);

    let mut stats = PayloadEvalStats::default();
    for &seed in seeds {
        let mut rand = StdRand::with_seed(seed);
        // Separate stream so payload placement cannot shift generation.
        let mut prand = StdRand::with_seed(seed ^ 0x5eed_5eed);
        for def in &signature.functions {
            let zoo = TermZoo::<PB>::generate_many(
                &ctx,
                signature,
                &mut rand,
                how_many,
                TermConstraints::default().zoo_max_depth,
                Some(def),
                false, // cheap syntactic generation; evaluate-skip below
                true,
            );
            for term in zoo.terms() {
                if term.evaluate(&ctx).is_err() {
                    continue;
                }
                let mut t = term.clone();
                let n_sub = (&t).into_iter().count() as i32;
                let nb = *(1..std::cmp::max(4, n_sub / 3))
                    .collect::<Vec<i32>>()
                    .choose(&mut prand)
                    .unwrap_or(&1);
                let mut parents = vec![];
                let mut tries = 0;
                while (parents.len() as i32) < nb && tries < nb * 100 {
                    tries += 1;
                    if let Some(p) = add_one_payload_randomly(&mut t, &mut prand, &ctx) {
                        parents.push(p);
                    }
                }
                if t.count_payloads() == 0 {
                    if !ignored_functions.contains(term.name()) {
                        stats.add_payload_fail += 1;
                    }
                    continue;
                }
                // `evaluate_config` (not `evaluate`): the `_wrap` layer panics on
                // `Error::TermBug` in debug/test builds, which is exactly the
                // outcome this check needs to observe and tally.
                let res = t.evaluate_config(&ctx, true);
                let term_bug = matches!(res, Err(crate::error::Error::TermBug(_)));
                if res.is_err() && !term_bug {
                    stats.other_eval_fail += 1;
                    continue;
                }
                for p in parents {
                    let e = stats.by_parent.entry(p).or_default();
                    if term_bug {
                        e.1 += 1;
                    } else {
                        e.0 += 1;
                    }
                }
                if !term_bug {
                    stats.success += 1;
                } else if !ignored_functions.contains(term.name()) {
                    stats.eval_payload_fail += 1;
                }
            }
        }
    }
    stats
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
