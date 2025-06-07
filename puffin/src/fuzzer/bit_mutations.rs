use std::any::Any;
use std::cmp::min;
use std::ops::Not;

use libafl::prelude::*;
use libafl_bolts::bolts_prelude::Merge;
use libafl_bolts::prelude::{tuple_list, tuple_list_type};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;

use super::utils::{choose, choose_filtered, choose_term_path_filtered, find_term_mut, TermConstraints, TracePath};
use crate::algebra::TermType;
use crate::fuzzer::utils::choose_term_filtered_mut;
use crate::protocol::{ProtocolBehavior, ProtocolTypes};
use crate::trace::{ConfigTrace, Spawner, Trace, TraceContext};
pub type HavocMutationsTypeDY<'a, S, PB> = tuple_list_type!(
    MakeMessage<'a, PB>,
    ReadMessage<'a, PB>,
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

#[must_use]
pub fn havoc_mutations_dy<'a, S: HasRand + HasMaxSize + HasCorpus, PB>(
    mutation_config: MutationConfig,
    put_registry: &'a PutRegistry<PB>,
) -> HavocMutationsTypeDY<'a, S, PB>
where
    PB: ProtocolBehavior,
{
    let with_bit_level = mutation_config.with_bit_level;
    tuple_list!(
        MakeMessage::new(mutation_config, put_registry),
        ReadMessage::new(mutation_config, put_registry),
        BitFlipMutatorDY::new(with_bit_level),
        ByteFlipMutatorDY::new(with_bit_level),
        ByteIncMutatorDY::new(with_bit_level),
        ByteDecMutatorDY::new(with_bit_level),
        ByteNegMutatorDY::new(with_bit_level),
        ByteRandMutatorDY::new(with_bit_level),
        ByteAddMutatorDY::new(with_bit_level),
        WordAddMutatorDY::new(with_bit_level),
        DwordAddMutatorDY::new(with_bit_level),
        QwordAddMutatorDY::new(with_bit_level),
        ByteInterestingMutatorDY::new(with_bit_level),
        WordInterestingMutatorDY::new(with_bit_level),
        DwordInterestingMutatorDY::new(with_bit_level),
        BytesDeleteMutatorDY::new(with_bit_level),
        BytesDeleteMutatorDY::new(with_bit_level),
        BytesDeleteMutatorDY::new(with_bit_level),
        BytesDeleteMutatorDY::new(with_bit_level),
        BytesExpandMutatorDY::new(with_bit_level),
        BytesInsertMutatorDY::new(with_bit_level),
        BytesRandInsertMutatorDY::new(with_bit_level),
        BytesSetMutatorDY::new(with_bit_level),
        BytesRandSetMutatorDY::new(with_bit_level),
        BytesCopyMutatorDY::new(with_bit_level),
        BytesInsertCopyMutatorDY::new(with_bit_level),
        BytesSwapMutatorDY::new(with_bit_level),
        CrossoverInsertMutatorDY::new(with_bit_level),
        CrossoverReplaceMutatorDY::new(with_bit_level),
        SpliceMutatorDY::new(with_bit_level),
    )
}

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
        .merge(havoc_mutations_dy(mutation_config, put_registry))
}

// --------------------------------------------------------------------------------------------------
// MakeMessage mutation
// --------------------------------------------------------------------------------------------------

/// MAKE MESSAGE : transforms a sub term into a message which can then be mutated using havoc
pub struct MakeMessage<'a, PB> {
    with_bit_level: bool,
    constraints: TermConstraints,
    put_registry: &'a PutRegistry<PB>,
    with_dy: bool,
}

impl<'a, PB> MakeMessage<'a, PB> {
    #[must_use]
    pub const fn new(mutation_config: MutationConfig, put_registry: &'a PutRegistry<PB>) -> Self {
        Self {
            with_bit_level: mutation_config.with_bit_level,
            constraints: mutation_config.term_constraints,
            put_registry,
            with_dy: mutation_config.with_dy,
        }
    }
}

/// `MakeMessage` on the term at path `path` in `tr`.
fn make_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> anyhow::Result<()>
where
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    tr.execute_until_step(ctx, path.0, &mut 0).err().map(|e| {
        // 20% to 50% MakeMessage mutations fail, so this is a bit costly :(
        // TODO: we could memoize the recipe evaluation in a Option<ConcreteMessage> and use that
        log::debug!("mutation::MakeMessage trace is not executable until step {},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            Error: {e}", path.0);
        log::trace!("{}", &tr);
        log::debug!("       Skipped MakeMessage");
        Ok::<MutationResult, Error>(MutationResult::Skipped)
    });

    let t = find_term_mut(tr, path).expect("make_message_term - Should never happen.");
    // We get payload_0 by symbolically evaluating the term! (and not full eval with potential
    // payloads in sub-terms). This because, doing differently would dramatically complexify the
    // computation of replace_payloads. See terms.rs. Also, one could argue the mutations of the
    // strict sub-terms could have been done on the larger term in the first place.
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
    ) -> anyhow::Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());
        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate MakeMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let nb_payloads = trace.all_payloads().len();
        let nb_terms = trace.steps.len();
        let no_more_new_payloads = nb_payloads / std::cmp::max(1, nb_terms)
            > self.constraints.threshold_max_payloads_per_term;
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
            must_payload_in_subterm: no_more_new_payloads, /* change to true when there are too
                                                            * many payloads already */
            not_inside_list: true, /* true means we are not picking terms inside list (like
                                    * fn_append in the middle) */
            // we set it to true since it would otherwise be redundant with picking each of the item
            // as mutated term
            weighted_depth: false, /* true means we select a sub-term by giving higher-priority
                                    * to deeper sub-terms */
            // TODO: set two lasts to false now as they allow to find more case. TODO: fix reservori
            // sampling and set this to true (as well as in
            // integration_test/term_zoo.rs)
            not_readable: true,
            ..self.constraints
        };
        if !self.with_dy {
            constraints_make_message.must_be_root = true;
        }
        // choose a random sub term
        if let Some((chosen_term, (step_index, term_path))) =
            choose_filtered(trace, constraints_make_message, |t| !t.is_no_bit(), rand)
        {
            log::debug!("[Mutation-bit] Mutate MakeMessage on term\n{}", chosen_term);
            let spawner = Spawner::new(self.put_registry.clone());
            // log::trace!("Using self.put_registry {:?} to compute ctx",
            // self.put_registry.default().name());
            let mut ctx = TraceContext::new_config(
                spawner,
                ConfigTrace {
                    with_bit_level: self.with_bit_level,
                    ..Default::default()
                },
            );
            match make_message_term(trace, &(step_index, term_path), &mut ctx) {
                // TODO: possibly we would need to make sure the mutated trace can be executed (if
                // not directly dropped by the feedback loop once executed).
                // TODO: maybe check we get the same by reading /encoding
                Ok(()) => {
                    log::debug!("mutation::MakeMessage successful!");
                    Ok(MutationResult::Mutated)
                }
                Err(e) => {
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

/// READ MESSAGE : picks a sub-term having itself a sub-term with payload, evaluate, read and
/// performs an in-place replacement
pub struct ReadMessage<'a, PB> {
    with_bit_level: bool,
    constraints: TermConstraints,
    put_registry: &'a PutRegistry<PB>,
    with_dy: bool,
}

impl<'a, PB> ReadMessage<'a, PB> {
    #[must_use]
    pub const fn new(mutation_config: MutationConfig, put_registry: &'a PutRegistry<PB>) -> Self {
        Self {
            with_bit_level: mutation_config.with_bit_level,
            constraints: mutation_config.term_constraints,
            put_registry,
            with_dy: mutation_config.with_dy,
        }
    }
}

/// `ReadMessage` on the term at path `path` in `tr`.
fn read_message_term<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    tr: &mut Trace<PT>,
    path: &TracePath,
    ctx: &mut TraceContext<PB>,
) -> anyhow::Result<()>
where
    PB: ProtocolBehavior<ProtocolTypes = PT>,
{
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    log::debug!("Try eval until path.0: {}", path.0);
    tr.execute_until_step(ctx, path.0, &mut 0).err().map(|e| {
        // 20% to 50% MakeMessage mutations fail (so should do ReadMessage), so this is a bit costly :(
        // TODO: we could memoize the recipe evaluation in a Option<ConcreteMessage> and use that
        log::debug!("mutation::ReadMessage trace is not executable until step {},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            Error: {e}", path.0);
        log::trace!("{}", &tr);
        log::debug!("       Skipped ReadMessage");
        Ok::<MutationResult, Error>(MutationResult::Skipped)
    });

    let t = find_term_mut(tr, path).expect("read_message_term - Should never happen.");
    log::debug!("[mutation::ReadMessage] [read_message_term] Mutate ReadMessage on term\n{}", t);
    log::debug!("[mutation::ReadMessage] [read_message_term] Trying read for type shape: {} and type id : {:?}", t.get_type_shape(), t.term.type_id());
    // Evaluate the term and try to read it into the term type
    let eval = t.evaluate(ctx)?;
    let read_term = PB::try_read_bytes(&*eval, t.get_type_shape().clone().into())?; // skip if try_read fails

    // The evaluation of this readable term eval_read is likely NOT the original evaluation itself
    // eval. What we keep here is eval_read since we aim to store the re-interpretation of the
    // payload. Note that when eval != eval_read, it likely means that `t` is length-prefixed or has
    // some headers and that havoc mutations have messed up with those or the payload length. We
    // will loose part of this. However, it is likely that we could have ReadMessage a
    // strict-subterm instead to avoid this.
    let eval_read = read_term.get_encoding();
    t.add_payload_readable(eval_read);
    Ok(())
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
    ) -> anyhow::Result<MutationResult, Error> {
        log::debug!("[Bit] Start mutate with {}", self.name());
        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate ReadMessage skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        let mut term_constraints = TermConstraints {
            not_readable: true,
            ..self.constraints
        };
        if !self.with_dy {
            term_constraints.must_be_root = true;
        }
        // Randomly choose a random sub term
        // Specifically for ReadMessage, we should prioritize terms close to a sub-term with
        // payloads. We first randomly pick a term with payload. With proba p:=1/2 we pick
        // that one. With proba. p:=p/2 we pick the parent term, etc.
        if let Some((step, path)) =
            choose_term_path_filtered(trace, |x| x.is_symbolic().not(), term_constraints, rand)
        {
            let mut chosen_path = (step, path);
            log::trace!("[ReadMessage] Initially picked term at {chosen_path:?}");
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
                let max_range = (1_000_000_000.0 * proba) as u64;
                if rand.between(0, 1_000_000_000 - 1) < max_range {
                    log::trace!("[ReadMessage] Going up, proba was {proba}");
                    proba = proba / 2.0;
                    chosen_path.1.pop();
                } else {
                    break;
                }
            }
            let chosen_path = (step, chosen_path);
            let spawner = Spawner::new(self.put_registry.clone());
            // log::trace!("Using self.put_registry {:?} to compute ctx",
            // self.put_registry.default().name());
            let mut ctx = TraceContext::new_config(
                spawner,
                ConfigTrace {
                    with_bit_level: self.with_bit_level,
                    ..Default::default()
                },
            );
            match read_message_term(trace, &chosen_path, &mut ctx) {
                Ok(_) => {
                    log::debug!("[mutation::ReadMessage] successful!");
                    Ok(MutationResult::Mutated)
                }
                Err(e) => {
                    log::debug!("[mutation::ReadMessage] failed due to {e}");
                    log::debug!("       Skipped {}", self.name());
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            log::debug!(
                "[mutation::ReadMessage] Failed to choose term with payload in trace:\n {}",
                &trace
            );
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
        }
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

use crate::algebra::bitstrings::Payloads;
use crate::algebra::signature::Signature;
use crate::fuzzer::mutations::{
    dy_mutations, remove_prefix_and_type, GenerateMutator, MutationConfig, RemoveAndLiftMutator,
    RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator, SkipMutator, SwapMutator,
};
use crate::put_registry::PutRegistry;

macro_rules! expand_mutation {
    ($mutation:ident) => {
paste!{
        /// mutation definition
pub struct [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    with_bit_level: bool,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    #[must_use]
    pub const fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate {} skipped because bit-level mutations are disabled", self.name());
            return Ok(MutationResult::Skipped)
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints {
                not_readable: true,
                ..TermConstraints::default()
            },
            // TODO: we may want to add no_payload_subterm
            // pros of adding: less mutations on sub-terms that could be subsumed by mutations on a larger term done in the first place
            // cons: might be useful to first shotgun small mutations on a small term to make the trace progress with possibly more actions and then
            //       do larger mutations on a larger term from there (might have an impact later).
            // TODO: balance out this trade-off
            rand,
        ) {
            log::debug!("[Mutation-bit] [macro] Mutate {} on term\n{}", self.name(), &to_mutate);
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::$mutation.mutate(state, &mut payloads.payload, stage_idx)
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
            }
        } else {
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
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
    with_bit_level: bool,
    tmp_buf: BytesSwapMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesSwapMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints {
                not_readable: true,
                ..TermConstraints::default()
            },
            rand,
        ) {
            log::debug!(
                "[Mutation-bit] Mutate {} on term\n{}",
                self.name(),
                &to_mutate
            );
            if let Some(payloads) = &mut to_mutate.payloads {
                BytesSwapMutator::mutate(&mut self.tmp_buf, state, &mut payloads.payload, stage_idx)
                    .and_then(|r| {
                        payloads.set_changed();
                        Ok(r)
                    })
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
            }
        } else {
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
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
    with_bit_level: bool,
    tmp_buf: BytesInsertCopyMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate BytesInsertCopyMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints {
                not_readable: true,
                ..TermConstraints::default()
            },
            rand,
        ) {
            log::debug!(
                "[Mutation-bit] Mutate {} on term\n{}",
                self.name(),
                &to_mutate
            );
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::BytesInsertCopyMutator::mutate(
                    &mut self.tmp_buf,
                    state,
                    &mut payloads.payload,
                    stage_idx,
                )                    .and_then(|r| {
                    payloads.set_changed();
                    Ok(r)
                })
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
            }
        } else {
            log::debug!("       Skipped {}", self.name());
            Ok(MutationResult::Skipped)
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

/// Randomly choose a payload and its index (nth) in a trace (mutable reference), if there is any
/// and if it has at least 2 bytes. Also returns a mutable ref to the payload metadata.
pub fn choose_payload_mut<'a, PT, S>(
    trace: &'a mut Trace<PT>,
    state: &mut S,
) -> Option<(&'a mut Vec<u8>, usize, &'a mut PayloadMetadata)>
where
    S: HasCorpus + HasRand + HasMaxSize,
    PT: ProtocolTypes,
{
    let mut all_payloads: Vec<&'a mut Payloads> = trace.all_payloads_mut();
    if all_payloads.is_empty() {
        return None;
    }
    let idx = state.rand_mut().between(0, (all_payloads.len() - 1) as u64) as usize;
    let input = all_payloads.remove(idx);
    let metada = &mut input.metadata;
    let input = input.payload.bytes_mut();
    if input.len() < 2 {
        return None;
    }
    Some((input, idx, metada))
}

// Randomly choose a payload and its index (n-th) in a trace, if there is any and if it has at
// least 2 bytes
// fn choose_payload<'a, PT, S>(trace: &'a Trace<PT>, state: &mut S) -> Option<(&'a [u8], usize)>
// where
//     S: HasCorpus + HasRand + HasMaxSize,
//     PT: ProtocolTypes,
// {
//     let all_payloads = trace.all_payloads();
//     if all_payloads.is_empty() {
//         return None;
//     }
//     let idx = state.rand_mut().between(0, (all_payloads.len() - 1) as u64) as usize;
//     let input = all_payloads[idx].payload.bytes();
//     if input.len() < 2 {
//         return None;
//     }
//     Some((input, idx))
// }

// Access the n-th payload of a trace, if it exists
// fn get_payload<PT>(trace: &Trace<PT>, idx: usize) -> Option<&[u8]>
// where
//     PT: ProtocolTypes,
// {
//     let all_payloads = trace.all_payloads();
//     if all_payloads.len() <= idx {
//         return None;
//     }
//     let input = all_payloads[idx].payload.bytes();
//     if input.len() < 2 {
//         return None;
//     }
//     Some(input)
// }

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
    with_bit_level: bool,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverInsertMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _, metadata)) = choose_payload_mut(trace, state) else {
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
    with_bit_level: bool,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate CrossoverReplaceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _, metadata)) = choose_payload_mut(trace, state) else {
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
    with_bit_level: bool,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
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

        if !self.with_bit_level {
            log::debug!("[Mutation-bit] Mutate SpliceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _, metadata)) = choose_payload_mut(trace, state) else {
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
