use std::any::Any;
use std::borrow::Cow;
use std::cmp::min;
use std::ops::Not;

use libafl::mutators::mutations::{
    BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesDeleteMutator,
    BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator, BytesRandInsertMutator,
    BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordAddMutator,
    DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
};
use libafl::prelude::*;
use libafl_bolts::bolts_prelude::Merge;
use libafl_bolts::prelude::{tuple_list, tuple_list_type};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;

use super::utils::{
    choose_filtered, choose_term_path_filtered, find_term, find_term_mut, TermConstraints,
    TracePath,
};
use crate::algebra::bitstrings::is_opaque_boundary_in_path;
use crate::algebra::{DYTerm, Term, TermType};
use crate::fuzzer::utils::choose_term_filtered_mut;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::trace::{ConfigTrace, Spawner, Trace, TraceContext};

/* List from: https://docs.rs/libafl/latest/src/libafl/mutators/havoc_mutations.rs.html#60
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesInsertCopyMutator,
    BytesSwapMutator,
    CrossoverInsertMutator,
    CrossoverReplaceMutator,
*/

pub type HavocMutationsTypeDY<S, PT> = tuple_list_type!(
    BitFlipMutatorDY<S, PT>,
    ByteFlipMutatorDY<S, PT>,
    ByteIncMutatorDY<S, PT>,
    ByteDecMutatorDY<S, PT>,
    ByteNegMutatorDY<S, PT>,
    ByteRandMutatorDY<S, PT>,
    ByteAddMutatorDY<S, PT>,
    WordAddMutatorDY<S, PT>,
    DwordAddMutatorDY<S, PT>,
    QwordAddMutatorDY<S, PT>,
    ByteInterestingMutatorDY<S, PT>,
    WordInterestingMutatorDY<S, PT>,
    DwordInterestingMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesExpandMutatorDY<S, PT>,
    BytesLargeExpandMutatorDY<S, PT>, // NEW! Different from classical havoc!!
    BytesInsertMutatorDY<S, PT>,
    BytesRandInsertMutatorDY<S, PT>,
    BytesSetMutatorDY<S, PT>,
    BytesRandSetMutatorDY<S, PT>,
    BytesCopyMutatorDY<S, PT>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S, PT>,
    CrossoverReplaceMutatorDY<S, PT>,
    SpliceMutatorDY<S, PT>,
);

pub type BitMutations<'harness, PB, PT, S> = tuple_list_type!(
    MakeMessage<'harness, PB>,
    ReadMessage<'harness, PB>,
    BitFlipMutatorDY<S, PT>,
    ByteFlipMutatorDY<S, PT>,
    ByteIncMutatorDY<S, PT>,
    ByteDecMutatorDY<S, PT>,
    ByteNegMutatorDY<S, PT>,
    ByteRandMutatorDY<S, PT>,
    ByteAddMutatorDY<S, PT>,
    WordAddMutatorDY<S, PT>,
    DwordAddMutatorDY<S, PT>,
    QwordAddMutatorDY<S, PT>,
    ByteInterestingMutatorDY<S, PT>,
    WordInterestingMutatorDY<S, PT>,
    DwordInterestingMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesExpandMutatorDY<S, PT>,
    BytesLargeExpandMutatorDY<S, PT>,
    BytesInsertMutatorDY<S, PT>,
    BytesRandInsertMutatorDY<S, PT>,
    BytesSetMutatorDY<S, PT>,
    BytesRandSetMutatorDY<S, PT>,
    BytesCopyMutatorDY<S, PT>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S, PT>,
    CrossoverReplaceMutatorDY<S, PT>,
    SpliceMutatorDY<S, PT>,
);

pub type AllMutations<'harness, PT, PB, S> = tuple_list_type!(
    RepeatMutator<S>,
    SkipMutator<S>,
    ReplaceReuseMutator<S>,
    ReplaceMatchMutator<S, PT>,
    RemoveAndLiftMutator<S>,
    GenerateMutator<'harness, S, PB>,
    SwapMutator<S>,
    MakeMessage<'harness, PB>,
    ReadMessage<'harness, PB>,
    BitFlipMutatorDY<S, PT>,
    ByteFlipMutatorDY<S, PT>,
    ByteIncMutatorDY<S, PT>,
    ByteDecMutatorDY<S, PT>,
    ByteNegMutatorDY<S, PT>,
    ByteRandMutatorDY<S, PT>,
    ByteAddMutatorDY<S, PT>,
    WordAddMutatorDY<S, PT>,
    DwordAddMutatorDY<S, PT>,
    QwordAddMutatorDY<S, PT>,
    ByteInterestingMutatorDY<S, PT>,
    WordInterestingMutatorDY<S, PT>,
    DwordInterestingMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesDeleteMutatorDY<S, PT>,
    BytesExpandMutatorDY<S, PT>,
    BytesLargeExpandMutatorDY<S, PT>,
    BytesInsertMutatorDY<S, PT>,
    BytesRandInsertMutatorDY<S, PT>,
    BytesSetMutatorDY<S, PT>,
    BytesRandSetMutatorDY<S, PT>,
    BytesCopyMutatorDY<S, PT>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S, PT>,
    CrossoverReplaceMutatorDY<S, PT>,
    SpliceMutatorDY<S, PT>,
);

#[must_use]
pub fn havoc_mutations_dy<S: HasRand + HasMaxSize + HasCorpus<Trace<PT>>, PT: ProtocolTypes>(
    mutation_config: MutationConfig,
) -> HavocMutationsTypeDY<S, PT> {
    tuple_list!(
        BitFlipMutatorDY::new(mutation_config),
        ByteFlipMutatorDY::new(mutation_config),
        ByteIncMutatorDY::new(mutation_config),
        ByteDecMutatorDY::new(mutation_config),
        ByteNegMutatorDY::new(mutation_config),
        ByteRandMutatorDY::new(mutation_config),
        ByteAddMutatorDY::new(mutation_config),
        WordAddMutatorDY::new(mutation_config),
        DwordAddMutatorDY::new(mutation_config),
        QwordAddMutatorDY::new(mutation_config),
        ByteInterestingMutatorDY::new(mutation_config),
        WordInterestingMutatorDY::new(mutation_config),
        DwordInterestingMutatorDY::new(mutation_config),
        BytesDeleteMutatorDY::new(mutation_config),
        BytesDeleteMutatorDY::new(mutation_config),
        BytesDeleteMutatorDY::new(mutation_config),
        BytesDeleteMutatorDY::new(mutation_config),
        BytesExpandMutatorDY::new(mutation_config),
        BytesLargeExpandMutatorDY::new(mutation_config),
        BytesInsertMutatorDY::new(mutation_config),
        BytesRandInsertMutatorDY::new(mutation_config),
        BytesSetMutatorDY::new(mutation_config),
        BytesRandSetMutatorDY::new(mutation_config),
        BytesCopyMutatorDY::new(mutation_config),
        BytesInsertCopyMutatorDY::new(mutation_config),
        BytesSwapMutatorDY::new(mutation_config),
        CrossoverInsertMutatorDY::new(mutation_config),
        CrossoverReplaceMutatorDY::new(mutation_config),
        SpliceMutatorDY::new(mutation_config),
    )
}

#[must_use]
pub fn bit_mutations_dy<S: HasRand + HasMaxSize + HasCorpus<Trace<PT>>, PT: ProtocolTypes, PB>(
    mutation_config: MutationConfig,
    put_registry: &PutRegistry<PB>,
) -> BitMutations<'_, PB, PT, S>
where
    PB: ProtocolBehavior,
{
    tuple_list!(
        MakeMessage::new(mutation_config, put_registry),
        ReadMessage::new(mutation_config, put_registry)
    )
    .merge(havoc_mutations_dy(mutation_config))
}

pub fn all_mutations<'harness, S, PT: ProtocolTypes, PB>(
    mutation_config: MutationConfig,
    signature: &'static Signature<PT>,
    put_registry: &'harness PutRegistry<PB>,
) -> AllMutations<'harness, PT, PB, S>
where
    S: HasCorpus<Trace<PT>> + HasMetadata + HasMaxSize + HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    dy_mutations(mutation_config, signature, put_registry)
        .merge(bit_mutations_dy(mutation_config, put_registry))
}

// --------------------------------------------------------------------------------------------------
// MakeMessage mutation
// --------------------------------------------------------------------------------------------------

/// MAKE MESSAGE: transforms a sub term into a message which can then be mutated using havoc
pub struct MakeMessage<'a, PB> {
    put_registry: &'a PutRegistry<PB>,
    config: MutationConfig,
}

impl<'a, PB> MakeMessage<'a, PB> {
    #[must_use]
    pub const fn new(config: MutationConfig, put_registry: &'a PutRegistry<PB>) -> Self {
        Self {
            config,
            put_registry,
        }
    }
}

/// [INV-B] Classify a MakeMessage target for per-case success measurement:
/// (sub-term depth, whether under an opaque/reframing boundary, head message-symbol at the step).
fn mm_case<PT: ProtocolTypes>(tr: &Trace<PT>, path: &TracePath) -> (usize, bool, &'static str) {
    let depth = path.1.len();
    let root = find_term(tr, &(path.0, vec![]));
    let under = root.map_or(false, |r| is_opaque_boundary_in_path(r, &path.1));
    let head = root.map_or("?", |r| match &r.term {
        DYTerm::Application(fd, _) => fd.name(),
        DYTerm::Variable(_) => "var",
    });
    (depth, under, head)
}

/// `MakeMessage` on the term at path `path` in `tr`.
fn make_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> Result<(), crate::error::Error> {
    let target_step = path.0;
    // [INV-B] per-case classification (computed before the &mut execution borrow)
    let (mm_depth, mm_under, mm_head) = mm_case(tr, path);
    let mm_tag = format!("depth={mm_depth} under_boundary={mm_under} head={mm_head}");
    log::debug!("make_message_term: executing until path.0: {}", target_step);
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    let res = tr.execute_until_step(ctx, target_step, &mut 0, true);
    // [MM-measure] Disentangles WHY a MakeMessage at `target_step` is (not) applied:
    //   - `reached` = how far THIS trace actually executed (ctx.executed_until, <= target_step);
    //   - outcome=fail_reach => the trace could NOT be executed up to the payload's step (it died
    //     earlier, possibly still past step 1) -> we never even attempt the bit mutation there;
    //   - outcome=fail_make  => reached the step but payload computation (term eval) failed there;
    //   - outcome=ok         => payload created at `target_step`.
    // Aggregating (target_step, reached, outcome) answers: do we fail bit-mutations at step>1
    // because traces die early, or because eval breaks at the step? (grep `[MM-measure]`)
    let reached = ctx.executed_until;
    if let Err(e) = res {
        MM_FAIL_REACH.increment();
        if mm_under {
            MM_FAILREACH_OPAQUE.increment(); // [INV-B] fail_reach under opaque/reframing boundary
        }
        log::debug!(
            "[MM-measure] target_step={target_step} reached={reached} outcome=fail_reach {mm_tag}"
        );
        // 20% to 50% MakeMessage mutations fail, so this is a bit costly :(
        // TODO: we could memoize the term evaluation in a Option<ConcreteMessage> and use that here
        log::debug!("mutation::MakeMessage trace is not executable until step {target_step},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            Error: {e}. Skipped MakeMessage...");
        log::trace!("{}", &tr);
        return Err(e);
    }

    let t = find_term_mut(tr, path).expect("make_message_term - Should never happen.");
    match t.make_payload(ctx) {
        Ok(()) => {
            MM_TERM_OK.increment();
            if mm_under {
                MM_OK_OPAQUE.increment(); // [INV-B] success under opaque/reframing boundary
            }
            log::debug!(
                "[MM-measure] target_step={target_step} reached={reached} outcome=ok {mm_tag}"
            );
            Ok(())
        }
        Err(e) => {
            MM_FAIL_MAKE.increment();
            log::debug!("[MM-measure] target_step={target_step} reached={reached} outcome=fail_make {mm_tag}");
            Err(e)
        }
    }
}

impl<'a, S, PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>> Mutator<Trace<PT>, S>
    for MakeMessage<'a, PB>
where
    S: HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());
        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate MakeMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let nb_payloads = trace.all_payloads().len();
        let nb_payloads_no_readable = trace
            .all_payloads()
            .iter()
            .filter(|p| !p.metadata.readable)
            .count();
        let nb_terms = trace.steps.len();
        let payloads_term_ratio = nb_payloads / std::cmp::max(1, nb_terms);
        let no_more_new_payloads =
            payloads_term_ratio > self.config.term_constraints.threshold_max_payloads_per_term;
        if no_more_new_payloads {
            log::debug!("[MakeMessage] on a trace with too many payloads: {trace}")
        } else {
            log::debug!("[MakeMessage] Do a regular MakeMessage")
        }
        let rand = state.rand_mut();
        let mut constraints_make_message = TermConstraints {
            must_be_symbolic: true, /* we exclude non-symbolic terms, which were already mutated
                                     * with MakeMessage */
            no_payload_in_subterm: false, /* change to true to exclude picking a term with a
                                           * payload in a sub-term */
            // TODO: we may want to set no_payload_subterm to true
            // pros of adding: less mutations on sub-terms that could be subsumed by mutations on a
            // larger term done in the first place cons: might be useful to first
            // shotgun small mutations on a small term to make the trace progress with possibly more
            // actions and then do larger mutations on a larger term from there
            // (might have an impact later). TODO: balance out this trade-off
            must_payload_in_subterm: no_more_new_payloads, /* change to true when there are too
                                                            * many payloads already */
            not_inside_list: true, /* true means we are not picking terms inside list (like
                                    * fn_append in the middle) */
            // we set it to true since it would otherwise be redundant with picking each of the item
            // as mutated term
            weighted_depth: false, /* true means we select a sub-term by giving higher-priority
                                    * to deeper sub-terms */
            // Set two lasts to false now as this allows to find more case for now.
            // TODO: fix reservoir sampling and set this to true (as well as in
            // integration_test/term_zoo.rs)
            not_readable: true,
            ..self.config.term_constraints
        };
        if !self.config.with_dy && !self.config.bit_allow_subterm_no_dy {
            constraints_make_message.must_be_root = true;
        }

        // If debug mode, test that trace has no focus and panic otherwise
        #[cfg(any(debug_assertions, feature = "debug"))]
        if trace.get_focus().is_some() {
            log::error!(
                "[MakeMessage] with_focus is set but trace has a focus already: {:?}. Trace:\n{trace}",
                trace.get_focus().unwrap()
            );
            return Ok(MutationResult::Skipped);
        }

        // choose a random sub term
        if let Some(trace_path) = if self.config.with_focus {
            if nb_payloads > 0 && payloads_term_ratio > 1 {
                if nb_payloads_no_readable == 0 {
                    log::debug!("[MakeMessage] With focus and enough existing payloads but all are readable. Skipping...");
                    return Ok(MutationResult::Skipped);
                }
                log::debug!(
                    "[MakeMessage] With focus and enough existing payloads: randomly picking one"
                );
                constraints_make_message.must_be_symbolic = false;
                constraints_make_message.must_payload_in_subterm = false;
                if let Some((_, trace_path)) = choose_filtered(
                    trace,
                    &constraints_make_message,
                    |t| !t.is_symbolic(),
                    state.rand_mut(),
                ) {
                    log::debug!("[MakeMessage] Picked existing payload and focus set to it: {trace_path:?}. Mutated.");
                    trace.set_focus(trace_path.clone());
                    Some(trace_path)
                } else {
                    log::error!("[MakeMessage] Skipped as we failed selecting a term with existing payloads while there is at least one payload. Trace: {trace}. Constraints: {:?}.", constraints_make_message);
                    return Ok(MutationResult::Skipped);
                }
            } else {
                log::debug!("[MakeMessage] With focus and no enough existing payloads, picking a random term");
                choose_filtered(trace, &constraints_make_message, |t| !t.is_no_bit(), rand)
                    .map(|(_, p)| p)
            }
        } else {
            log::debug!("[MakeMessage] Without focus, picking a random term");
            choose_filtered(trace, &constraints_make_message, |t| !t.is_no_bit(), rand)
                .map(|(_, p)| p)
        } {
            // [executability frontier — soft bias] Most deep-step MakeMessage failures are
            // reachability failures, not eval failures (INV-A): the (already-mutated) trace can't be
            // executed up to the chosen step. If the chosen step is beyond where this trace last
            // executed, skip with high probability BEFORE the expensive execute_until_step — saving
            // the wasted execution. SOFT (keep ~1/PROCEED_DENOM exploration) so that a structurally
            // repaired trace can still push the frontier outward. Frontier travels with the trace
            // metadata and is kept current by Repeat/Skip mutators.
            if self.config.frontier_bias {
                if let Some(frontier) = trace.executable_frontier() {
                    if trace_path.0 > frontier {
                        // proceed-probability beyond the frontier:
                        //  - FIXED (default): ~1/8 regardless of distance;
                        //  - DECAY (--frontier-decay): ~1/2^distance (capped) -> near-frontier steps
                        //    proceed often (1/2, 1/4, ...) to keep pushing the frontier outward,
                        //    far/unreachable steps are skipped aggressively.
                        let proceed_denom: usize = if self.config.frontier_decay {
                            let dist = (trace_path.0 - frontier).min(7) as u32;
                            1usize << dist
                        } else {
                            8
                        };
                        if state.rand_mut().below_or_zero(proceed_denom) != 0 {
                            FRONTIER_SKIP.increment();
                            log::debug!(
                                "[MakeMessage] frontier-skip: step {} > frontier {frontier} (proceed_denom={proceed_denom})",
                                trace_path.0
                            );
                            return Ok(MutationResult::Skipped);
                        }
                    }
                }
            }
            let target_term =
                find_term(trace, &trace_path).expect("make_message_term - Should never happen.");
            log::debug!("[Mutation-bit] Mutate MakeMessage on term\n{}", target_term);

            let do_shared_intent = if self.config.only_shared_payloads {
                true
            } else if self.config.shared_payloads {
                state.rand_mut().next() % 2 == 0 // probability 1/2
            } else {
                false
            };

            if self.config.only_shared_payloads
                && (target_term.has_variable() || target_term.size() < 2)
            {
                return Ok(MutationResult::Skipped);
            }

            // shared behavior only applies if target is variable-free and has size >= 2
            let do_shared =
                do_shared_intent && !target_term.has_variable() && target_term.size() >= 2;

            let spawner = Spawner::new(self.put_registry.clone());
            // log::trace!("Using self.put_registry {:?} to compute ctx",
            // self.put_registry.default().name());
            let mut ctx = TraceContext::new_config(
                spawner,
                ConfigTrace {
                    with_bit_level: self.config.with_bit_level,
                    ..Default::default()
                },
            );
            if self.config.with_focus {
                MM_EXEC.increment();
            }
            BIT_EXEC.increment();

            let mutation_result = if do_shared {
                use crate::fuzzer::stats_stage::{MM_SHARED_OK, MM_SHARED_SINGLETON};
                use crate::fuzzer::utils::find_all_term_filtered;

                let unconstrained = TermConstraints {
                    must_be_symbolic: false,
                    no_payload_in_subterm: false,
                    must_payload_in_subterm: false,
                    not_inside_list: false,
                    weighted_depth: false,
                    not_readable: false,
                    must_be_root: false,
                    ..TermConstraints::default()
                };

                let target_clone = target_term.clone();
                let occurrences: Vec<TracePath> = find_all_term_filtered(
                    trace,
                    |n| *n == target_clone && !n.has_variable(),
                    &unconstrained,
                );

                if occurrences.len() < 2 {
                    MM_SHARED_SINGLETON.increment();
                    make_message_term(trace, &trace_path, &mut ctx)
                } else {
                    // [Phase 3 FIX #2] The shared target is variable-free (`do_shared` requires
                    // `!has_variable()`), so `evaluate_symbolic` is CONTEXT-INDEPENDENT: it computes
                    // the same bytes regardless of protocol state. So we do NOT execute_until_step
                    // here -- the old code did, and abandoned the whole shared mutation on fail_reach
                    // (the ~50% INV-A wall) even though no execution was needed. That spuriously
                    // suppressed shared-group formation. We compute the bytes directly from a fresh
                    // ctx (unused for variable-free terms).
                    let payload_bytes_opt =
                        find_term(trace, &trace_path).and_then(|t| t.evaluate_symbolic(&ctx).ok());

                    if let Some(payload_bytes) = payload_bytes_opt {
                        let shared_id = trace.fresh_shared_id();
                        for occ_path in &occurrences {
                            if let Some(t) = find_term_mut(trace, occ_path) {
                                t.add_payload(payload_bytes.clone());
                                if let Some(ref mut p) = t.payloads {
                                    p.shared_id = Some(shared_id);
                                }
                            }
                        }
                        MM_SHARED_OK.increment();
                        // [Phase 3 FIX] No sync needed at formation: all members were just set
                        // to identical bytes (add_payload of the same payload_bytes clone).
                        Ok(())
                    } else {
                        MM_FAIL_MAKE.increment();
                        Err(crate::error::Error::Term(
                            "Failed to evaluate for shared".to_string(),
                        ))
                    }
                }
            } else {
                make_message_term(trace, &trace_path, &mut ctx)
            };

            match mutation_result {
                // TODO: possibly we would need to make sure the mutated trace can be executed (if
                // not directly dropped by the feedback loop once executed).
                // TODO: maybe add a consistency check: same encoding by reading/encoding
                Ok(()) => {
                    log::debug!("mutation::MakeMessage successful!");
                    if self.config.with_focus {
                        MM_EXEC_SUCCESS.increment();
                        log::debug!("mutation::MakeMessage set focus on {trace_path:?}");
                        trace.set_focus(trace_path);
                    }
                    BIT_EXEC_SUCCESS.increment();
                    Ok(MutationResult::Mutated)
                }
                Err(e) => {
                    log::warn!(
                        "mutation::MakeMessage failed (with_focus: {}) due to {e}",
                        self.config.with_focus
                    );
                    log::debug!("mutation::MakeMessage failed due to {e}");
                    log::debug!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            log::debug!(
                "mutation::MakeMessage failed to choose term in trace:\n {}",
                &trace
            );
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, PB> Named for MakeMessage<'a, PB>
where
    PB: ProtocolBehavior,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MakeMessage")
    }
}

// --------------------------------------------------------------------------------------------------
// ReadMessage mutation
// --------------------------------------------------------------------------------------------------

/// READ MESSAGE: picks a sub-term having itself a sub-term with payload, evaluate, read and
/// performs an in-place replacement
pub struct ReadMessage<'a, PB> {
    config: MutationConfig,
    put_registry: &'a PutRegistry<PB>,
}

impl<'a, PB> ReadMessage<'a, PB> {
    #[must_use]
    pub const fn new(config: MutationConfig, put_registry: &'a PutRegistry<PB>) -> Self {
        Self {
            config,
            put_registry,
        }
    }
}

/// `ReadMessage` on the term at path `path` in `tr`.
fn read_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> Result<(), crate::error::Error> {
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    log::debug!("Try eval until path.0: {}", path.0);
    tr.execute_until_step(ctx, path.0, &mut 0, true).map_err(|e| {
        log::debug!("mutation::ReadMessage trace is not executable until step {}, \
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace. Skipped ReadMessage\
            Error: {e}. Skipping ReadMessage...", path.0);
        log::trace!("{}", &tr);
        e
    })?;

    let t = find_term_mut(tr, path).expect("read_message_term - Should never happen.");
    log::debug!(
        "[mutation::ReadMessage] [read_message_term] Mutate ReadMessage on term\n{}\n Trying read for type shape: {} and type id : {:?}",
        t, t.get_type_shape(), t.term.type_id()
    );
    // Evaluate the term and try to read it into the term type
    let eval = t.evaluate(ctx)?; // We do not measure failure or not for this specific eval (less costly than trace execution)
    let read_term = PB::try_read_bytes(&eval, t.get_type_shape().clone().into())?; // skip if try_read fails

    // The evaluation of this readable term eval_read is likely NOT the original evaluation itself
    // eval. What we keep here is eval_read since we aim to store the re-interpretation of the
    // payload. Note that when eval != eval_read, it likely means that `t` is length-prefixed or has
    // some headers and that havoc mutations have messed up with those or the payload length. We
    // will loose part of this. However, it is likely that we could have ReadMessage a
    // strict-subterm instead to avoid this.
    let eval_read = read_term.get_encoding();

    // [AUDIT A3] Only store a readable payload that itself round-trips. Otherwise the readable
    // branch of `eval_until_opaque` would later fail to read it back and raise a TermBug. If
    // `eval_read` is not re-readable, this `?` propagates an error that the caller
    // (`ReadMessage::mutate`) turns into `MutationResult::Skipped` -- no poison payload is stored.
    let _ = PB::try_read_bytes(&eval_read, t.get_type_shape().clone().into())?;

    t.add_payload_readable(eval_read);
    Ok(())
}

impl<'a, S, PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>> Mutator<Trace<PT>, S>
    for ReadMessage<'a, PB>
where
    S: HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());
        let focus = trace.get_focus().cloned();
        if self.config.with_focus {
            trace.clear_focus(); // to save a bit of memory (no need to serialize focus in the
                                 // corpus!)
        }
        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate ReadMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let mut constraints_read_message = TermConstraints {
            no_payload_in_subterm: false, /* change to true to exclude picking a term with a
                                           * payload in a sub-term */
            not_inside_list: true, /* true means we are not picking terms inside list (like
                                    * fn_append in the middle) */
            weighted_depth: false, /* true means we select a sub-term by giving higher-priority
                                    * to deeper sub-terms */
            not_readable: true,
            ..self.config.term_constraints
        };
        if !self.config.with_dy && !self.config.bit_allow_subterm_no_dy {
            constraints_read_message.must_be_root = true;
        }
        let chosen_path = if self.config.with_focus {
            if let Some(trace_path) = focus {
                // We run ReadMessage with proba 1/4 in focus mode (i.e. SKIP it 3/4 of the time),
                // so that most focused HAVOC rounds keep their raw bit-mutations (e.g. "lying" about
                // length prefixes) instead of having them re-normalized by a re-interpretation.
                // NOTE (audit A1): the `!` previously bound to `rand.between(..)` (bitwise NOT of a
                // ~1e9 usize), making the comparison always false -> this throttle was DEAD and
                // ReadMessage always ran in focus mode. Parenthesized to negate the comparison.
                let proba_run = self.config.read_message_prob; // [#7] tunable (was hardcoded 1/4)
                let max_range = (1_000_000_000.0 * proba_run) as usize;
                if !(rand.between(0, 1_000_000_000 - 1) < max_range) {
                    log::debug!("read_message_term: skipping as we do in 3/4 of times");
                    return Ok(MutationResult::Skipped);
                }
                // If focus was already set, we use it as is!
                // TODO: investigate whether we still want to explore application on parents
                log::debug!("read_message_term::mutate - Using focus {trace_path:?}");
                trace_path.clone()
            } else {
                log::debug!("read_message_term::mutate - No focus set and yet with_focus config. Should only happen when initial MakeMessage failed! Skipping...");
                return Ok(MutationResult::Skipped); // First MakeMessage failed, we won't apply
                                                    // further mutations then
            }
        } else {
            // Randomly choose a random sub term
            // Specifically for ReadMessage, we should prioritize terms close to a sub-term with
            // payloads. We first randomly pick a term with payload. With proba p:=1/2 we pick
            // that one. With proba. p:=p/2 we pick the parent term, etc.
            if let Some(mut chosen_path) = choose_term_path_filtered(
                trace,
                |x| x.is_symbolic().not(),
                &constraints_read_message,
                rand,
            ) {
                log::debug!("[ReadMessage] Initially picked term at {chosen_path:?}");
                let term = find_term_mut(trace, &chosen_path)
                    .expect("mutation::ReadMessage::mutate - Should never happen!");
                let payloads = term.payloads.as_ref().expect(
                    "mutation::ReadMessage::mutate - Should never happen, we should have filtered out symbolic terms",
                );
                if !payloads.has_changed() {
                    // Extremely likely that payload.payload == payload.payload0 then!
                    log::debug!("       Skipped {} because payload unchanged", self.name());
                    return Ok(MutationResult::Skipped);
                }
                let mut proba = 1.0 / 2.0;
                while !chosen_path.1.is_empty() {
                    let max_range = (1_000_000_000.0 * proba) as usize;
                    if rand.between(0, 1_000_000_000 - 1) < max_range {
                        log::trace!("[ReadMessage] Going up, proba was {proba}");
                        proba /= 2.0;
                        chosen_path.1.pop();
                    } else {
                        break;
                    }
                }
                log::debug!("[ReadMessage] Finally picked term at {chosen_path:?}");
                chosen_path
            } else {
                log::trace!(
                    "[mutation::ReadMessage] Failed to choose term with payload in trace:\n {}",
                    &trace
                );
                RM_SKIP_NOTERM.increment(); // [INV-C] ReadMessage couldn't find a payload-bearing term
                log::warn!(
                    "       Skipped {} as we failed to choose a term with payload in the trace.",
                    self.name()
                );
                return Ok(MutationResult::Skipped);
            }
        };
        let term =
            find_term_mut(trace, &chosen_path).expect("read_message_term - Should never happen.");
        if term.is_list() || term.is_readable() {
            log::debug!(
                "[ReadMessage] Skipping ReadMessage on term\n{term:?}, because it is a list or already readable or has no det"
            );
            return Ok(MutationResult::Skipped);
        }

        let spawner = Spawner::new(self.put_registry.clone());
        // log::trace!("Using self.put_registry {:?} to compute ctx",
        // self.put_registry.default().name());
        let mut ctx = TraceContext::new_config(
            spawner,
            ConfigTrace {
                with_bit_level: self.config.with_bit_level,
                ..Default::default()
            },
        );
        if self.config.with_focus {
            MM_EXEC.increment();
        }
        BIT_EXEC.increment();
        match read_message_term(trace, &chosen_path, &mut ctx) {
            Ok(_) => {
                RM_OK.increment(); // [INV-C] ReadMessage applied (re-interpreted a payload)
                if self.config.with_focus {
                    MM_EXEC_SUCCESS.increment();
                }
                BIT_EXEC_SUCCESS.increment();
                log::debug!("[ReadMessage] Path chosen: {chosen_path:?}");
                log::debug!("[mutation::ReadMessage] successful!");
                Ok(MutationResult::Mutated)
            }
            Err(e) => {
                log::debug!("[mutation::ReadMessage] failed due to {e}");
                log::debug!("       Skipped {}", self.name());
                Ok(MutationResult::Skipped)
            }
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, PB> Named for ReadMessage<'a, PB>
where
    PB: ProtocolBehavior,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ReadMessage")
    }
}

// --------------------------------------------------------------------------------------------------
// Term-level bit-level mutations
// --------------------------------------------------------------------------------------------------

use libafl::mutators::{MutationResult, Mutator};
use libafl::state::{HasCorpus, HasMaxSize, HasRand};
use libafl::Error;

use crate::algebra::bitstrings::Payloads;
use paste::paste;

use crate::algebra::signature::Signature;
use crate::fuzzer::mutations::{
    dy_mutations, GenerateMutator, MutationConfig, RemoveAndLiftMutator, RepeatMutator,
    ReplaceMatchMutator, ReplaceReuseMutator, SkipMutator, SwapMutator,
};
use crate::fuzzer::stats_stage::{
    BIT_EXEC, BIT_EXEC_SUCCESS, FRONTIER_SKIP, MM_EXEC, MM_EXEC_SUCCESS, MM_FAILREACH_OPAQUE,
    MM_FAIL_MAKE, MM_FAIL_REACH, MM_OK_OPAQUE, MM_TERM_OK, RM_OK, RM_SKIP_NOTERM,
};
use crate::put_registry::PutRegistry;

macro_rules! expand_mutation {
    ($mutation:ident) => {
paste!{
        /// mutation definition
pub struct [<$mutation  DY>]<S, PT>
    where
        S: HasRand + HasMaxSize,
        PT: ProtocolTypes,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<(S, PT)>,
}

impl<S, PT> [<$mutation  DY>]<S, PT>
    where
        S: HasRand + HasMaxSize,
        PT: ProtocolTypes,
{
    #[must_use]
    pub const fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for [<$mutation  DY>]<S, PT>
    where
        S: HasRand + HasMaxSize,
        PT: ProtocolTypes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate {} skipped because bit-level mutations are disabled", self.name());
            return Ok(MutationResult::Skipped)
        }
        match choose_term_with_payload_mut(
            trace,
            state,
            &self.config.term_constraints,
            self.config.with_focus,
        ) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term\n{to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    let result = $mutation.mutate(state, &mut payloads.payload)
                              .and_then(|r| {
                               payloads.set_changed();
                               Ok(r)
                          });
                    // [shared-payload Phase 3 FIX] Sync FROM the just-mutated payload (capture its
                    // shared_id + bytes here, while borrowed) to all group members. The old global
                    // sync_shared_payloads() guessed the authority as "first member differing from
                    // payload_0", which after the first sync is ALWAYS every member -> it reverted
                    // iterated mutations on non-first members. Targeted sync is unambiguous.
                    let shared = payloads.shared_id;
                    let new_bytes: Vec<u8> = payloads.payload.mutator_bytes().to_vec();
                    if matches!(result, Ok(MutationResult::Mutated)) {
                        if let Some(id) = shared {
                            trace.sync_shared_payloads_from(id, &new_bytes);
                        }
                    }
                    result
                } else {
                    panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
                }
            }
            None => {
                log::debug!("       Skipped {}", self.name());
                Ok(MutationResult::Skipped)
            }
        }
    }

    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<S, PT> Named for [<$mutation  DY>]<S, PT>
    where
        S: HasRand + HasMaxSize,
        PT: ProtocolTypes,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed(stringify!($mutation))
    }
}
}};
}

#[macro_export]
macro_rules! expand_mutations {
    () => {};
    ($mutation:ident) => {
          expand_mutation!($mutation);
    };
    ($mutation:ident,) => {
          expand_mutation!($mutation);
    };
    ($mutation:ident, $($MS:ident),*) => {
          expand_mutation!($mutation);
          $crate::expand_mutations!($($MS),*);
    };
}
// Use of `expand_mutations` is below
expand_mutations!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesLargeExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator /* The next 2 require custom implementations:
                      *   BytesInsertCopyMutator,
                      *   BytesSwapMutator,
                      * The three next require to pick up another test-case (cross-over), see
                      * dedicated implementations:
                      *   CrossoverInsertMutator
                      *   CrossoverReplaceMutator
                      *   SpliceMutator */
);

// We could write another macro for the two following mutations
// BytesSwapMutatorDY
pub struct BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    config: MutationConfig,
    tmp_buf: BytesSwapMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            tmp_buf: BytesSwapMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesSwapMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        match choose_term_with_payload_mut(
            trace,
            state,
            &self.config.term_constraints,
            self.config.with_focus,
        ) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term\n{to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    let result =
                        BytesSwapMutator::mutate(&mut self.tmp_buf, state, &mut payloads.payload)
                            .map(|r| {
                                payloads.set_changed();
                                r
                            });
                    let shared = payloads.shared_id;
                    let new_bytes: Vec<u8> = payloads.payload.mutator_bytes().to_vec();
                    if matches!(result, Ok(MutationResult::Mutated)) {
                        if let Some(id) = shared {
                            trace.sync_shared_payloads_from(id, &new_bytes); // [Phase 3 FIX] targeted
                        }
                    }
                    result
                } else {
                    panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
                }
            }
            None => {
                log::debug!("       Skipped {}", self.name());
                Ok(MutationResult::Skipped)
            }
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Named for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("BytesSwapMutatorDY")
    }
}

// BytesInsertCopyMutatorDY
pub struct BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    config: MutationConfig,
    tmp_buf: BytesInsertCopyMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            tmp_buf: BytesInsertCopyMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesInsertCopyMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        match choose_term_with_payload_mut(
            trace,
            state,
            &self.config.term_constraints,
            self.config.with_focus,
        ) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term\n{to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    let result = BytesInsertCopyMutator::mutate(
                        &mut self.tmp_buf,
                        state,
                        &mut payloads.payload,
                    )
                    .map(|r| {
                        payloads.set_changed();
                        r
                    });
                    let shared = payloads.shared_id;
                    let new_bytes: Vec<u8> = payloads.payload.mutator_bytes().to_vec();
                    if matches!(result, Ok(MutationResult::Mutated)) {
                        if let Some(id) = shared {
                            trace.sync_shared_payloads_from(id, &new_bytes); // [Phase 3 FIX] targeted
                        }
                    }
                    result
                } else {
                    panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
                }
            }
            None => {
                log::debug!("       Skipped {}", self.name());
                Ok(MutationResult::Skipped)
            }
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> Named for BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("BytesInsertCopyMutatorDY")
    }
}

// --------------------------------------------------------------------------------------------------
// Trace-level bit-level mutations --> Cross-over need to consider traces with the HasBytesVec
// trait!
// --------------------------------------------------------------------------------------------------

/// Returns the focused payload or randomly choose a non-symbolic payload in a trace (mutable
/// reference).
pub fn choose_term_with_payload_mut<'a, PT, S>(
    trace: &'a mut Trace<PT>,
    state: &mut S,
    term_constraints: &TermConstraints,
    with_focus: bool,
) -> Option<&'a mut Term<PT>>
where
    S: HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    if with_focus {
        if let Some(path_trace) = trace.get_focus() {
            log::debug!("choose_term_with_payload_mut -- Focused path: {path_trace:?}");
            let term = find_term_mut(trace, &path_trace.clone())
                .expect("choose_term_with_payload_mut -- should never happen");
            Some(term)
        } else {
            log::debug!("choose_term_with_payload_mut -- No focus set and yet with_focus config. Skipping...");
            None // First MakeMessage failed, we won't apply further mutations then
        }
    } else {
        let res = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            term_constraints,
            state.rand_mut(),
        );
        log::debug!("choose_term_with_payload_mut -- Chosen term, not focus");
        res
    }
}

pub fn choose_payload_mut<'a, PT, S>(
    trace: &'a mut Trace<PT>,
    state: &mut S,
    config: &MutationConfig,
) -> Option<&'a mut Payloads>
where
    S: HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    match choose_term_with_payload_mut(trace, state, &config.term_constraints, config.with_focus) {
        Some(term) => {
            let payloads = term
                .payloads
                .as_mut()
                .expect("[choose_payload_mut] should never happen");
            if payloads.payload.as_mut().len() < 2 {
                log::debug!(
                    "[choose_payload_mut] Skipped because payload is too small: {} bytes",
                    payloads.payload.as_mut().len()
                );
                None
            } else {
                Some(payloads)
            }
        }
        None => None,
    }
}

/// Copied from `libafl::mutators::mutations`
/// Returns the first and last diff position between the given vectors, stopping at the min len
fn locate_diffs(this: &[u8], other: &[u8]) -> (i64, i64) {
    let mut first_diff: i64 = -1;
    let mut last_diff: i64 = -1;
    for (i, (this_el, other_el)) in this.iter().zip(other.iter()).enumerate() {
        if this_el != other_el {
            if first_diff < 0 {
                first_diff = i as i64;
            }
            last_diff = i as i64;
        }
    }

    (first_diff, last_diff)
}

/// Copied from `libafl::mutators::mutations`
/// Mem move in the own vec
#[inline]
pub(crate) unsafe fn buffer_self_copy<T>(data: &mut [T], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe {
            core::ptr::copy(ptr.add(from), ptr.add(to), len);
        }
    }
}

/// Mem move between vecs
#[inline]
pub(crate) unsafe fn buffer_copy<T>(dst: &mut [T], src: &[T], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe {
            core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len);
        }
    }
}

// CrossoverInsertMutatorDY
pub struct CrossoverInsertMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<(S, PT)>,
}

impl<S, PT> CrossoverInsertMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    #[must_use]
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for CrossoverInsertMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverInsertMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some(payloads) = choose_payload_mut(trace, state, &self.config) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        // [shared-payload Phase 3] cross-trace copies materialise into independent payloads
        payloads.shared_id = None;
        let input = payloads.payload.as_mut();
        let metadata = &mut payloads.metadata;

        // Inlined from libafl::mutators::mutations pub struct CrossoverInsertMutator
        let size = input.len();
        let max_size = state.max_size();
        if size >= max_size {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());

        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                log::debug!("       Skipped {}", self.name());
                return Ok(MutationResult::Skipped);
            }
        }

        // let other_size = {
        //     let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        //     other_testcase.load_input(state.corpus())?.bytes().len()
        // };
        let size_vec_payloads = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other_input_trace = other_testcase.load_input(state.corpus())?;
            other_input_trace.all_payloads().len()
        };
        if size_vec_payloads < 1 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, size_vec_payloads - 1);
        let other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .mutator_bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        let range = rand_range(
            state,
            other_size,
            min(other_size, max_size - size).try_into()?,
        );
        let target = state.rand_mut().below_or_zero(size);

        input.resize(size + range.len(), 0);
        unsafe {
            buffer_self_copy(input, target, target + range.len(), size - target);
        }

        // let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // // No need to load the input again, it'll still be cached.
        // let other = other_testcase.input().as_ref().unwrap();
        let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .mutator_bytes();
        let _other_size = other_input.len();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        // [Phase 3 FIX] No sync: this payload was materialized (shared_id=None) above, so it left
        // its group; remaining group members are unchanged + internally consistent.
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S, PT> Named for CrossoverInsertMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CrossoverInsertMutatorDY")
    }
}

pub struct CrossoverReplaceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<(S, PT)>,
}

impl<S, PT> CrossoverReplaceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    #[must_use]
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Named for CrossoverReplaceMutatorDY<S, PT>
where
    PT: ProtocolTypes,
    S: HasCorpus<Trace<PT>> + HasMaxSize + HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CrossoverReplaceMutatorDY")
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for CrossoverReplaceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverReplaceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some(payloads) = choose_payload_mut(trace, state, &self.config) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        // [shared-payload Phase 3] cross-trace copies materialise into independent payloads
        payloads.shared_id = None;
        let input = payloads.payload.as_mut();
        let metadata = &mut payloads.metadata;

        // Inlined from libafl::mutators::mutations pub struct CrossoverReplaceMutator
        let size = input.len();
        if size == 0 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                log::debug!("       Skipped {}", self.name());
                return Ok(MutationResult::Skipped);
            }
        }

        // let other_size = {
        //     let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        //     other_testcase.load_input(state.corpus())?.bytes().len()
        // };
        let size_vec_payloads = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other_input_trace = other_testcase.load_input(state.corpus())?;
            other_input_trace.all_payloads().len()
        };
        if size_vec_payloads < 1 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, size_vec_payloads - 1);
        let other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .mutator_bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below_or_zero(size);
        let range = rand_range(
            state,
            other_size,
            min(other_size, size - target).try_into()?,
        );

        // let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // // No need to load the input again, it'll still be cached.
        // let other = other_testcase.input().as_ref().unwrap();
        let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .mutator_bytes();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        // [Phase 3 FIX] No sync: this payload was materialized (shared_id=None) above, so it left
        // its group; remaining group members are unchanged + internally consistent.
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

pub struct SpliceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<(S, PT)>,
}

impl<S, PT> SpliceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    #[must_use]
    pub fn new(config: MutationConfig) -> Self {
        Self {
            config: MutationConfig {
                term_constraints: TermConstraints {
                    not_readable: true,
                    ..config.term_constraints
                },
                ..config
            },
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, PT> Named for SpliceMutatorDY<S, PT>
where
    PT: ProtocolTypes,
    S: HasCorpus<Trace<PT>> + HasMaxSize + HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SpliceMutatorDY")
    }
}

impl<S, PT> Mutator<Trace<PT>, S> for SpliceMutatorDY<S, PT>
where
    S: HasCorpus<Trace<PT>> + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    fn mutate(&mut self, state: &mut S, trace: &mut Trace<PT>) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate SpliceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some(payloads) = choose_payload_mut(trace, state, &self.config) else {
            log::trace!("choose_payload_mut failed");
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };
        // [shared-payload Phase 3] cross-trace copies materialise into independent payloads
        payloads.shared_id = None;
        let input = payloads.payload.as_mut();
        let metadata = &mut payloads.metadata;

        // Inlined from libafl::mutators::mutations pub struct SpliceMutator
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                log::trace!("Same other testcase");
                log::debug!("       Skipped {}", self.name());
                return Ok(MutationResult::Skipped);
            }
        }

        // Picking up other payload
        let size_vec_payloads = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other_input_trace = other_testcase.load_input(state.corpus())?;
            other_input_trace.all_payloads().len()
        };
        if size_vec_payloads < 1 {
            log::trace!("other payload is too short: {size_vec_payloads}");
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, size_vec_payloads - 1);
        let _other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .mutator_bytes();
            other_input.len()
        };
        //

        let (first_diff, last_diff) = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .mutator_bytes();

            // [AUDIT B2] locate_diffs is deterministic in (input, other_input); the previous loop
            // re-called it up to 4x with identical args. Call once; skip if no usable diff range.
            let (f, l) = locate_diffs(input, other_input);
            if f != l && f >= 0 && l >= 2 {
                (f as usize, l as usize)
            } else {
                log::debug!("       Skipped {} (no usable diff range)", self.name());
                return Ok(MutationResult::Skipped);
            }
        };

        let split_at = state.rand_mut().between(first_diff, last_diff);

        let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .mutator_bytes();

        input.splice(split_at.., other_input[split_at..].iter().copied());
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        // [Phase 3 FIX] No sync: payload materialized (shared_id=None) above -> left its group.
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

/***************************************************************************************************
                      New BytesLargeExpandMutator mutation
***************************************************************************************************/

/// Large number of bytes expand mutation for inputs with a bytes vector (expand range: from 2^5 to
/// 2^12)
#[derive(Default, Debug)]
pub struct BytesLargeExpandMutator;

impl<I, S> Mutator<I, S> for BytesLargeExpandMutator
where
    S: HasRand + HasMaxSize,
    I: HasMutatorBytes + ResizableMutator<u8>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let min_length_log = 5;
        let max_length_log = 12;

        let max_size = state.max_size();
        let size = input.mutator_bytes().len();
        if size == 0 || size >= max_size {
            return Ok(MutationResult::Skipped);
        }
        if size < 1 << min_length_log {
            return Ok(MutationResult::Skipped);
        }
        let len_log = state.rand_mut().between(min_length_log, max_length_log);
        let len = min(1 << len_log, max_size - size);
        let start = state.rand_mut().between(0, size);
        let range = start..(start + len);
        log::trace!("[BytesLargeExpandMutator] len: {len}, range: {range:?}, size: {size}");
        input.resize(size + range.len(), 0);
        unsafe {
            buffer_self_copy(
                input.mutator_bytes_mut(),
                range.start,
                range.start + range.len(),
                size - range.start,
            );
        }
        log::trace!("After mutation, length is: {}", input.mutator_bytes().len());

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for BytesLargeExpandMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("BytesLargexpandMutator")
    }
}

impl BytesLargeExpandMutator {
    /// Creates a new [`BytesLargeExpandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
