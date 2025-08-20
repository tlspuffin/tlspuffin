use std::any::Any;
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
    choose_filtered, choose_term_path_filtered, find_term_mut, TermConstraints, TracePath,
};
use crate::algebra::{Term, TermType};
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

pub type HavocMutationsTypeDY<S> = tuple_list_type!(
    BitFlipMutatorDY<S>,
    ByteFlipMutatorDY<S>,
    ByteIncMutatorDY<S>,
    ByteDecMutatorDY<S>,
    ByteNegMutatorDY<S>,
    ByteRandMutatorDY<S>,
    ByteAddMutatorDY<S>,
    WordAddMutatorDY<S>,
    DwordAddMutatorDY<S>,
    QwordAddMutatorDY<S>,
    ByteInterestingMutatorDY<S>,
    WordInterestingMutatorDY<S>,
    DwordInterestingMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesExpandMutatorDY<S>,
    BytesLargeExpandMutatorDY<S>, // NEW! Different from classical havoc!!
    BytesInsertMutatorDY<S>,
    BytesRandInsertMutatorDY<S>,
    BytesSetMutatorDY<S>,
    BytesRandSetMutatorDY<S>,
    BytesCopyMutatorDY<S>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S>,
    CrossoverReplaceMutatorDY<S>,
    SpliceMutatorDY<S>,
);

pub type BitMutations<'harness, PB, S> = tuple_list_type!(
    MakeMessage<'harness, PB>,
    ReadMessage<'harness, PB>,
    BitFlipMutatorDY<S>,
    ByteFlipMutatorDY<S>,
    ByteIncMutatorDY<S>,
    ByteDecMutatorDY<S>,
    ByteNegMutatorDY<S>,
    ByteRandMutatorDY<S>,
    ByteAddMutatorDY<S>,
    WordAddMutatorDY<S>,
    DwordAddMutatorDY<S>,
    QwordAddMutatorDY<S>,
    ByteInterestingMutatorDY<S>,
    WordInterestingMutatorDY<S>,
    DwordInterestingMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesExpandMutatorDY<S>,
    BytesLargeExpandMutatorDY<S>,
    BytesInsertMutatorDY<S>,
    BytesRandInsertMutatorDY<S>,
    BytesSetMutatorDY<S>,
    BytesRandSetMutatorDY<S>,
    BytesCopyMutatorDY<S>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S>,
    CrossoverReplaceMutatorDY<S>,
    SpliceMutatorDY<S>,
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
    BitFlipMutatorDY<S>,
    ByteFlipMutatorDY<S>,
    ByteIncMutatorDY<S>,
    ByteDecMutatorDY<S>,
    ByteNegMutatorDY<S>,
    ByteRandMutatorDY<S>,
    ByteAddMutatorDY<S>,
    WordAddMutatorDY<S>,
    DwordAddMutatorDY<S>,
    QwordAddMutatorDY<S>,
    ByteInterestingMutatorDY<S>,
    WordInterestingMutatorDY<S>,
    DwordInterestingMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesDeleteMutatorDY<S>,
    BytesExpandMutatorDY<S>,
    BytesLargeExpandMutatorDY<S>,
    BytesInsertMutatorDY<S>,
    BytesRandInsertMutatorDY<S>,
    BytesSetMutatorDY<S>,
    BytesRandSetMutatorDY<S>,
    BytesCopyMutatorDY<S>,
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S>,
    CrossoverReplaceMutatorDY<S>,
    SpliceMutatorDY<S>,
);

#[must_use]
pub fn havoc_mutations_dy<S: HasRand + HasMaxSize + HasCorpus>(
    mutation_config: MutationConfig,
) -> HavocMutationsTypeDY<S> {
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
pub fn bit_mutations_dy<S: HasRand + HasMaxSize + HasCorpus, PB>(
    mutation_config: MutationConfig,
    put_registry: &PutRegistry<PB>,
) -> BitMutations<PB, S>
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
    S: HasCorpus + HasMetadata + HasMaxSize + HasRand,
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

/// `MakeMessage` on the term at path `path` in `tr`.
fn make_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> Result<(), crate::error::Error>
where
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    log::debug!("make_message_term: executing until path.0: {}", path.0);
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    tr.execute_until_step(ctx, path.0, &mut 0).err().map(|e| {
        // 20% to 50% MakeMessage mutations fail, so this is a bit costly :(
        // TODO: we could memoize the term evaluation in a Option<ConcreteMessage> and use that here
        log::debug!("mutation::MakeMessage trace is not executable until step {},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            Error: {e}", path.0);
        log::trace!("{}", &tr);
        log::debug!("       Skipped MakeMessage");
        Ok::<MutationResult, Error>(MutationResult::Skipped)
    });

    let t = find_term_mut(tr, path).expect("make_message_term - Should never happen.");
    t.make_payload(ctx)?;
    Ok(())
}

impl<'a, S, PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>> Mutator<Trace<PT>, S>
    for MakeMessage<'a, PB>
where
    S: HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());
        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate MakeMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let nb_payloads = trace.all_payloads().len();
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
            // TODO: fix reservori sampling and set this to true (as well as in
            // integration_test/term_zoo.rs)
            ..self.config.term_constraints
        };
        if !self.config.with_dy {
            constraints_make_message.must_be_root = true;
        }

        // choose a random sub term
        if let Some((chosen_term, trace_path)) =
            choose_filtered(trace, &constraints_make_message, |t| !t.is_no_bit(), rand)
        {
            log::debug!("[Mutation-bit] Mutate MakeMessage on term\n{}", chosen_term);
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
            BIT_EXEC.increment();
            match make_message_term(trace, &trace_path, &mut ctx) {
                // TODO: possibly we would need to make sure the mutated trace can be executed (if
                // not directly dropped by the feedback loop once executed).
                // TODO: maybe add a consitency check: same encoding by reading /encoding
                Ok(()) => {
                    log::debug!("mutation::MakeMessage successful!");
                    BIT_EXEC_SUCCESS.increment();
                    Ok(MutationResult::Mutated)
                }
                Err(e) => {
                    log::warn!(
                        "mutation::MakeMessage failed (with_focus: {}) due to {e}",
                        false
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
}

impl<'a, PB> Named for MakeMessage<'a, PB>
where
    PB: ProtocolBehavior,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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

impl<'a, S, PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>> Mutator<Trace<PT>, S>
    for ReadMessage<'a, PB>
where
    S: HasRand,
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // Nothing for now
        Ok(MutationResult::Skipped)
    }
}

impl<'a, PB> Named for ReadMessage<'a, PB>
where
    PB: ProtocolBehavior,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
    }
}

// --------------------------------------------------------------------------------------------------
// Term-level bit-level mutations
// --------------------------------------------------------------------------------------------------

use paste::paste;

use crate::algebra::bitstrings::PayloadMetadata;
use crate::algebra::signature::Signature;
use crate::fuzzer::mutations::{
    dy_mutations, remove_prefix_and_type, GenerateMutator, MutationConfig, RemoveAndLiftMutator,
    RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator, SkipMutator, SwapMutator,
};
use crate::fuzzer::stats_stage::{BIT_EXEC, BIT_EXEC_SUCCESS, MM_EXEC, MM_EXEC_SUCCESS};
use crate::put_registry::PutRegistry;

macro_rules! expand_mutation {
    ($mutation:ident) => {
paste!{
        /// mutation definition
pub struct [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
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

impl<S, PT> Mutator<Trace<PT>, S> for [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
        PT: ProtocolTypes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        stage_idx: i32,
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
            false,
        ) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term {to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    $mutation.mutate(state, &mut payloads.payload, stage_idx)
                              .and_then(|r| {
                               payloads.set_changed();
                               Ok(r)
                          })
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
}

impl<S> Named for [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<[<$mutation  DY>]<S>>())
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesSwapMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        match choose_term_with_payload_mut(trace, state, &self.config.term_constraints, false) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term {to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    BytesSwapMutator::mutate(
                        &mut self.tmp_buf,
                        state,
                        &mut payloads.payload,
                        stage_idx,
                    )
                    .and_then(|r| {
                        payloads.set_changed();
                        Ok(r)
                    })
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
}

impl<S> Named for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesInsertCopyMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        match choose_term_with_payload_mut(trace, state, &self.config.term_constraints, false) {
            Some(to_mutate) => {
                log::debug!("[Mutation-bit] Mutate {} on term {to_mutate}", self.name(),);
                if let Some(payloads) = &mut to_mutate.payloads {
                    BytesInsertCopyMutator::mutate(
                        &mut self.tmp_buf,
                        state,
                        &mut payloads.payload,
                        stage_idx,
                    )
                    .and_then(|r| {
                        payloads.set_changed();
                        Ok(r)
                    })
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
}

impl<S> Named for BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    let res = choose_term_filtered_mut(
        trace,
        |x| x.is_symbolic().not(),
        term_constraints,
        state.rand_mut(),
    );
    log::debug!("choose_term_with_payload_mut -- Chosen term, not focus");
    res
}

pub fn choose_payload_mut<'a, PT, S>(
    trace: &'a mut Trace<PT>,
    state: &mut S,
    config: &MutationConfig,
) -> Option<(&'a mut Vec<u8>, &'a mut PayloadMetadata)>
where
    S: HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    match choose_term_with_payload_mut(trace, state, &config.term_constraints, false) {
        Some(term) => {
            let payloads = term
                .payloads
                .as_mut()
                .expect("[choose_payload_mut] should never happen");
            let input = payloads.payload.bytes_mut();
            if input.len() < 2 {
                log::debug!(
                    "[choose_payload_mut] Skipped because payload is too small: {} bytes",
                    input.len()
                );
                None
            } else {
                Some((input, &mut payloads.metadata))
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
pub struct CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
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

impl<S, PT> Mutator<Trace<PT>, S> for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S: libafl::inputs::UsesInput<Input = Trace<PT>>,
    PT: ProtocolTypes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverInsertMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, metadata)) = choose_payload_mut(trace, state, &self.config) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };

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
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        let range = rand_range(state, other_size, min(other_size, max_size - size));
        let target = state.rand_mut().below(size as u64) as usize;

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
            .bytes();
        let _other_size = other_input.len();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
    }
}

pub struct CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
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

impl<S, PT> Mutator<Trace<PT>, S> for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S: libafl::inputs::UsesInput<Input = Trace<PT>>,
    PT: ProtocolTypes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverReplaceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, metadata)) = choose_payload_mut(trace, state, &self.config) else {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };

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
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below(size as u64) as usize;
        let range = rand_range(state, other_size, min(other_size, size - target));

        // let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // // No need to load the input again, it'll still be cached.
        // let other = other_testcase.input().as_ref().unwrap();
        let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .bytes();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
    }
}

pub struct SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    config: MutationConfig,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
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

impl<S, PT> Mutator<Trace<PT>, S> for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    //        <S as libafl::inputs::UsesInput>::Input = BytesInput,
    S: libafl::inputs::UsesInput<Input = Trace<PT>>,
    PT: ProtocolTypes,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<PT>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());

        if !self.config.with_bit_level {
            log::debug!("[Mutation-bit] Mutate SpliceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, metadata)) = choose_payload_mut(trace, state, &self.config) else {
            log::trace!("choose_payload_mut failed");
            log::debug!("       Skipped {}", self.name());
            return Ok(MutationResult::Skipped);
        };

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
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let _other_size = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        let (first_diff, last_diff) = {
            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();

            let mut counter: u32 = 0;
            loop {
                let (f, l) = locate_diffs(input, other_input);

                if f != l && f >= 0 && l >= 2 {
                    break (f as u64, l as u64);
                }
                if counter == 3 {
                    log::trace!("counter is 3");
                    log::debug!("       Skipped {}", self.name());
                    return Ok(MutationResult::Skipped);
                }
                counter += 1;
            }
        };

        let split_at = state.rand_mut().between(first_diff, last_diff) as usize;

        let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .bytes();

        input.splice(split_at.., other_input[split_at..].iter().copied());
        metadata.has_changed = true;

        log::debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        log::trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        remove_prefix_and_type(std::any::type_name::<Self>())
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
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let min_length_log = 5;
        let max_length_log = 12;

        let max_size = state.max_size();
        let size = input.bytes().len();
        if size == 0 || size >= max_size {
            return Ok(MutationResult::Skipped);
        }
        if size < 1 << min_length_log {
            return Ok(MutationResult::Skipped);
        }
        let len_log = state
            .rand_mut()
            .between(min_length_log as u64, max_length_log as u64) as usize;
        let len = min(1 << len_log, max_size - size);
        let start = state.rand_mut().between(0, size as u64) as usize;
        let range = start..(start + len);
        log::trace!("[BytesLargeExpandMutator] len: {len}, range: {range:?}, size: {size}");
        input.bytes_mut().resize(size + range.len(), 0);
        unsafe {
            buffer_self_copy(
                input.bytes_mut(),
                range.start,
                range.start + range.len(),
                size - range.start,
            );
        }
        log::trace!("After mutation, length is: {}", input.bytes().len());
        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesLargeExpandMutator {
    fn name(&self) -> &str {
        "BytesLargexpandMutator"
    }
}

impl BytesLargeExpandMutator {
    /// Creates a new [`BytesLargeExpandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
