use libafl::prelude::*;
use log::{debug, error, info, warn};
use std::ops::Not;
use std::thread::panicking;
use util::{Choosable, *};
use anyhow::{Context, Result};

use crate::algebra::{Payloads, search_sub_vec, TermEval, TermType};
use crate::codec::Codec;
use crate::fuzzer::bit_mutations::*;
use crate::fuzzer::harness::default_put_options;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;
use crate::{
    algebra::{atoms::Function, signature::Signature, Matcher, Subterms, Term},
    fuzzer::term_zoo::TermZoo,
    trace::Trace,
};
use crate::trace::Action::Input;

pub fn trace_mutations<S, M: Matcher, PB>(
    min_trace_length: usize,
    max_trace_length: usize,
    constraints: TermConstraints,
    fresh_zoo_after: u64,
    signature: &'static Signature,
) -> tuple_list_type!(
          RepeatMutator<S>,
          SkipMutator<S>,
          ReplaceReuseMutator<S>,
          ReplaceMatchMutator<S>,
          RemoveAndLiftMutator<S>,
          GenerateMutator<S, M>,
          SwapMutator<S>,
          MakeMessage<S,PB>,
   // Type of the mutations that compose the Havoc mutator (copied and pasted from above)
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
      )
where
    S: HasCorpus + HasMetadata + HasMaxSize + HasRand,
    PB: ProtocolBehavior,
{
    #[cfg(feature = "no-repeat")]
    let l = tuple_list!(
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints, signature),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints));
    #[cfg(feature = "no-skip")]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints, signature),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints));
    #[cfg(feature = "no-replaceR")]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceMatchMutator::new(constraints, signature),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints));
    #[cfg(feature = "no-replaceM")]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints));
    #[cfg(feature = "no-remove")]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints, signature),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints));
    #[cfg(feature = "no-swap")]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints, signature),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
    );
    
    #[cfg(not(any(feature = "no-repeat", feature = "no-skip", feature = "no-replaceR", feature = "no-replaceM", feature = "no-remove", feature = "no-gen", feature = "no-swap")))]
    let l = tuple_list!(
        RepeatMutator::new(max_trace_length),
        SkipMutator::new(min_trace_length),
        ReplaceReuseMutator::new(constraints),
        ReplaceMatchMutator::new(constraints, signature),
        RemoveAndLiftMutator::new(constraints),
        GenerateMutator::new(0, fresh_zoo_after, constraints, None, signature), // Refresh zoo after 100000M mutations
        SwapMutator::new(constraints),
        MakeMessage::new(constraints),
    )
    .merge(havoc_mutations_DY())
}

/// SWAP: Swaps a sub-term with a different sub-term which is part of the trace

/// (such that types match).
pub struct SwapMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SwapMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(constraints: TermConstraints) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M: Matcher> Mutator<Trace<M>, S> for SwapMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let a = BytesInsertMutator;
        let rand = state.rand_mut();
        if let Some((term_a, trace_path_a)) = choose(trace, self.constraints, rand) {
            if let Some(trace_path_b) = choose_term_path_filtered(
                trace,
                |term: &TermEval<M>| term.get_type_shape() == term_a.get_type_shape(),
                // TODO-bitlevel: maybe also check that both terms are .is_symbolic()
                self.constraints,
                rand,
            ) {
                let term_a_cloned = term_a.clone();
                if let Some(term_b_mut) = find_term_mut(trace, &trace_path_b) {
                    let term_b_cloned = term_b_mut.clone();
                    term_b_mut.mutate(term_a_cloned);
                    if let Some(trace_a_mut) = find_term_mut(trace, &trace_path_a) {
                        trace_a_mut.mutate(term_b_cloned);
                    }
                    return Ok(MutationResult::Mutated);
                }
            }
        }
        Ok(MutationResult::Skipped)
    }
}
impl<S> Named for SwapMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<SwapMutator<S>>()
    }
}

/// REMOVE AND LIFT: Removes a sub-term from a term and attaches orphaned children to the parent

/// (such that types match). This only works if there is only a single child.
pub struct RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(constraints: TermConstraints) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M: Matcher> Mutator<Trace<M>, S> for RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        let filter = |term: &TermEval<M>| match &term.term {
            Term::Variable(_) => false,
            Term::Application(_, subterms) =>
            // TODO-bitlevel: maybe add: term.is_symbolic() &&
            {
                subterms
                    .find_subterm(|subterm| match &subterm.term {
                        Term::Variable(_) => false,
                        Term::Application(_, grand_subterms) => {
                            grand_subterms.find_subterm_same_shape(subterm).is_some()
                        }
                    })
                    .is_some()
            }
        };
        if let Some(mut to_mutate) = choose_term_filtered_mut(trace, filter, self.constraints, rand)
        {
            match &mut to_mutate.term {
                // TODO-bitlevel: maybe also SKIP if not(to_mutate.is_symbolic())
                Term::Variable(_) => Ok(MutationResult::Skipped),
                Term::Application(_, ref mut subterms) => {
                    if let Some(((subterm_index, _), grand_subterm)) = choose_iter(
                        subterms.filter_grand_subterms(|subterm, grand_subterm| {
                            subterm.get_type_shape() == grand_subterm.get_type_shape()
                        }),
                        rand,
                    ) {
                        let grand_subterm_cloned = grand_subterm.clone();
                        subterms.push(grand_subterm_cloned);
                        subterms.swap_remove(subterm_index);
                        return Ok(MutationResult::Mutated);
                    }
                    Ok(MutationResult::Skipped)
                }
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for RemoveAndLiftMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<RemoveAndLiftMutator<S>>()
    }
}

/// REPLACE-MATCH: Replaces a function symbol with a different one (such that types match).

/// An example would be to replace a constant with another constant or the binary function

/// fn_add with fn_sub.

/// It can also replace any variable with a constant.
pub struct ReplaceMatchMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    signature: &'static Signature,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> ReplaceMatchMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(constraints: TermConstraints, signature: &'static Signature) -> Self {
        Self {
            constraints,
            signature,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M: Matcher> Mutator<Trace<M>, S> for ReplaceMatchMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        if let Some(mut to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            match &mut to_mutate.term {
                // TODO-bitlevel: maybe also SKIP if not(to_mutate.is_symbolic())
                Term::Variable(variable) => {
                    if let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                        |(shape, _)| variable.typ == shape.return_type && shape.is_constant(),
                        rand,
                    ) {
                        to_mutate.mutate(TermEval::from(Term::Application(
                            Function::new(shape.clone(), dynamic_fn.clone()),
                            Vec::new(),
                        )));
                        Ok(MutationResult::Mutated)
                    } else {
                        Ok(MutationResult::Skipped)
                    }
                }
                Term::Application(func_mut, _) => {
                    if let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
                        |(shape, _)| {
                            func_mut.shape() != shape
                                && func_mut.shape().return_type == shape.return_type
                                && func_mut.shape().argument_types == shape.argument_types
                        },
                        rand,
                    ) {
                        func_mut.change_function(shape.clone(), dynamic_fn.clone());
                        Ok(MutationResult::Mutated)
                    } else {
                        Ok(MutationResult::Skipped)
                    }
                }
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for ReplaceMatchMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<ReplaceMatchMutator<S>>()
    }
}

/// REPLACE-REUSE: Replaces a sub-term with a different sub-term which is part of the trace

/// (such that types match). The new sub-term could come from another step which has a different recipe term.
pub struct ReplaceReuseMutator<S>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> ReplaceReuseMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(constraints: TermConstraints) -> Self {
        Self {
            constraints,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M: Matcher> Mutator<Trace<M>, S> for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        if let Some(replacement) = choose_term(trace, self.constraints, rand).cloned() {
            if let Some(to_replace) = choose_term_filtered_mut(
                trace,
                |term: &TermEval<M>| term.get_type_shape() == replacement.get_type_shape(),
                // TODO-bitlevel: maybe also check that both are .is_symbolic()
                self.constraints,
                rand,
            ) {
                to_replace.mutate(replacement);
                return Ok(MutationResult::Mutated);
            }
        }
        Ok(MutationResult::Skipped)
    }
}

impl<S> Named for ReplaceReuseMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<ReplaceReuseMutator<S>>()
    }
}

/// SKIP:  Removes an input step
pub struct SkipMutator<S>
where
    S: HasRand,
{
    min_trace_length: usize,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SkipMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(min_trace_length: usize) -> Self {
        Self {
            min_trace_length,
            phantom_s: std::marker::PhantomData,
        }
    }
}
impl<S, M: Matcher> Mutator<Trace<M>, S> for SkipMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let steps = &mut trace.steps;
        let length = steps.len();
        if length <= self.min_trace_length {
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            return Ok(MutationResult::Skipped);
        }
        let remove_index = state.rand_mut().between(0, (length - 1) as u64) as usize;
        steps.remove(remove_index);
        Ok(MutationResult::Mutated)
    }
}
impl<S> Named for SkipMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<SkipMutator<S>>()
    }
}

/// REPEAT: Repeats an input which is already part of the trace
pub struct RepeatMutator<S>
where
    S: HasRand,
{
    max_trace_length: usize,
    phantom_s: std::marker::PhantomData<S>,
}
impl<S> RepeatMutator<S>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(max_trace_length: usize) -> Self {
        Self {
            max_trace_length,
            phantom_s: std::marker::PhantomData,
        }
    }
}
impl<S, M: Matcher> Mutator<Trace<M>, S> for RepeatMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let steps = &trace.steps;
        let length = steps.len();
        if length >= self.max_trace_length {
            return Ok(MutationResult::Skipped);
        }
        if length == 0 {
            return Ok(MutationResult::Skipped);
        }
        let insert_index = state.rand_mut().between(0, length as u64) as usize;
        let step = state.rand_mut().choose(steps).clone();
        trace.steps.insert(insert_index, step);
        Ok(MutationResult::Mutated)
    }
}
impl<S> Named for RepeatMutator<S>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<RepeatMutator<S>>()
    }
}

/// GENERATE: Generates a previously-unseen term using a term zoo
pub struct GenerateMutator<S, M: Matcher>
where
    S: HasRand,
{
    mutation_counter: u64,
    refresh_zoo_after: u64,
    constraints: TermConstraints,
    zoo: Option<TermZoo<M>>,
    signature: &'static Signature,
    phantom_s: std::marker::PhantomData<S>,
}
impl<S, M: Matcher> GenerateMutator<S, M>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(
        mutation_counter: u64,
        refresh_zoo_after: u64,
        constraints: TermConstraints,
        zoo: Option<TermZoo<M>>,
        signature: &'static Signature,
    ) -> Self {
        Self {
            mutation_counter,
            refresh_zoo_after,
            constraints,
            zoo,
            signature,
            phantom_s: std::marker::PhantomData,
        }
    }
}
impl<S, M: Matcher> Mutator<Trace<M>, S> for GenerateMutator<S, M>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_mut(trace, self.constraints, rand) {
            self.mutation_counter += 1;
            let zoo = if self.mutation_counter % self.refresh_zoo_after == 0 {
                self.zoo.insert(TermZoo::generate(self.signature, rand))
            } else {
                self.zoo
                    .get_or_insert_with(|| TermZoo::generate(self.signature, rand))
            };
            if let Some(term) = zoo.choose_filtered(
                |term| to_mutate.get_type_shape() == term.get_type_shape(),
                rand,
            ) {
                to_mutate.mutate(term.clone());
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}
impl<S, M: Matcher> Named for GenerateMutator<S, M>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<GenerateMutator<S, M>>()
    }
}

// ******************************************************************************************************
// Start bit-level Mutations

/// MAKE MESSAGE : transforms a sub term into a message which can then be mutated using havoc
pub struct MakeMessage<S, PB>
where
    S: HasRand,
{
    constraints: TermConstraints,
    phantom_s: (std::marker::PhantomData<S>, std::marker::PhantomData<PB>),
}

impl<S, PB> MakeMessage<S, PB>
where
    S: HasRand,
{
    #[must_use]
    pub fn new(constraints: TermConstraints) -> Self {
        Self {
            constraints,
            phantom_s: (std::marker::PhantomData, std::marker::PhantomData),
        }
    }
}

fn make_message_term<M: Matcher, PB: ProtocolBehavior<Matcher=M>>(t: &mut TermEval<M>, ctx: &TraceContext<PB>, path: &TracePath, trace: & Trace<M>)
    -> Result<(),anyhow::Error>
    where
    PB: ProtocolBehavior<Matcher=M>,
    {
        let step_index = &path.0;
        let term_path = &path.1;
        let evaluated = t.evaluate(&ctx).with_context(||
            format!("failed to evaluate chosen sub-term"))?; // TODO: because of function scope!
        let recipe = find_term(&trace, &(*step_index, term_path[0..0].to_vec())).expect("FAILURE FINDING SUBTERMN");
        let full_eval = recipe.evaluate(&ctx).with_context(||
            format!("failed to evaluate the recipe of the chosen sub-term"))?;
        {
            for i in 0..term_path.len() {
                let t = if i == 0 {
                    recipe
                } else {
                    find_term(&trace, &(*step_index, term_path[0..i].to_vec())).expect("FAILURE FINDING SUBTERMN")
                };
                let partial_eval = t.evaluate(&ctx).with_context(|| format!("failed to evaluate chosen sub-term at depth {i}. Unable to evaluate sub_term\n {} of recipe\n {}", &t, &recipe))?;
                if let Some(index) = search_sub_vec(&partial_eval, &evaluated) {
                    debug!("Found sub_term bitstring at depth {i}");
                } else {
                    if t.is_opaque() || recipe.is_opaque() {
                        warn!("[MakeMess FAILURE for opaque] Added payloads\n{:?}\n and full term was\n{:?}\n Term was\n{t}\n in recipe\n {}", &evaluated, &full_eval, &recipe);
                        return Ok(());
                    } else {
                        error!("[MakeMess FAILURE] Added payloads\n{:?}\n and full term was\n{:?}\n Term was\n {t}\n in recipe\n {}.\n Sub-term was\n{t} and payload was\n{:?}", &evaluated, &full_eval, &recipe, &partial_eval);
                        return Ok(());
                    }
                }
            }
            debug!("[SUCCESS] Added payloads\n{:?} and full term was\n{:?}\n Term was \n{t}\n in recipe \n{}", &evaluated, &full_eval, &recipe);
            if evaluated.is_empty() {
                // Theoretically, we would like to keep this case as further bit-level mutations may add data to this initially empty bitstring....
                warn!("mutation::MakeMessage::evaluated term is empty");
                Ok(())
            } else {
                // Proceed with the mutation: add the payloads to the TermEval
                t.add_payloads(evaluated);
                Ok(())
            }
        }
}

impl<S, M: Matcher, PB: ProtocolBehavior<Matcher=M>> Mutator<Trace<M>, S> for MakeMessage<S, PB>
    where
        S: HasRand,
        PB: ProtocolBehavior<Matcher=M>,
{
    // By Micol Giacomin
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let new_trace = trace.clone(); // for debugging only for now
        let rand = state.rand_mut();
        let constraints_make_message = TermConstraints {
            no_payload_in_subterm: false, // change to true to exclude picking a term with a payload in a sub-term
            not_inside_list: true, // true means we are not picking terms inside list (like fn_append in the middle)
            ..self.constraints
        };
        // choose a random sub term
        if let Some((to_mutate, (step_index, term_path))) =
            choose_mut(trace, constraints_make_message, rand)
        /* choose random sub tree (bias for nodes with smaller height)
        if let Some((to_mutate, (step_index, term_path))) =
            choose_with_weights(&trace.clone(), self.constraints, rand) */
        {
            warn!("Mutate MakeMessage on term {}", to_mutate);
            // Only execute shorter trace: trace[0..step_index])
            // execute the PUT on the first step_index steps and store the resulting trace context
            let mut ctx = TraceContext::new(PB::registry(), default_put_options().clone());
            new_trace.execute_until_step(&mut ctx, step_index).err().map(|e| {
                error!("mutation::MakeMessage trace is not executable, could only happen if this mutation is scheduled with other mutations that create a non-executable trace. TO CHECK! Error: {e}");
                return Ok::<MutationResult, Error>(MutationResult::Skipped)
            });

            // perform the MakeMessage mutation
            match make_message_term(to_mutate, &ctx, &(step_index, term_path), &new_trace) {
                Ok(()) => Ok(MutationResult::Mutated),
                Err(e) => {
                    warn!("mutation::MakeMessage failed due to {e}");
                    Ok(MutationResult::Skipped)
                },
            }
        } else {
            warn!("mutation::MakeMessage failed to choose term");
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S, PB> Named for MakeMessage<S, PB>
where
    S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<MakeMessage<S, PB>>()
    }
}

pub mod util {
    use libafl::bolts::rands::Rand;
    use log::error;

    use crate::algebra::{TermEval, TermType};
    use crate::protocol::ProtocolBehavior;
    use crate::trace::InputAction;
    use crate::{
        algebra::{Matcher, Term},
        trace::{Action, Step, Trace},
    };

    #[derive(Copy, Clone, Debug)]
    pub struct TermConstraints {
        pub min_term_size: usize,
        pub max_term_size: usize,
        // when true: only look for terms with no payload in sub-terms (for bit-le
        // note that we always exclude terms that are sub-terms of non-symbolic terms (i.e., with paylaods)
        pub no_payload_in_subterm: bool,
        // when true: we do not choose terms that have a list symbol and whose parent also has a list symbol
        // those terms are thus "inside a list", like t in fn_append(t,t3) for t = fn(append(t1,t2)
        pub not_inside_list: bool,
    }

    /// Default values which represent no constraint
    impl Default for TermConstraints {
        fn default() -> Self {
            Self {
                min_term_size: 0,
                max_term_size: 300, // was 9000 but we were rewriting this to 300 anyway when instantiating the fuzzer
                no_payload_in_subterm: false,
                not_inside_list: false,
            }
        }
    }

    pub trait Choosable<T, R: Rand> {
        fn choose_filtered<P>(&self, filter: P, rand: &mut R) -> Option<&T>
        where
            P: FnMut(&&T) -> bool;
        fn choose(&self, rand: &mut R) -> Option<&T>;
    }

    impl<T, R: Rand> Choosable<T, R> for Vec<T> {
        fn choose_filtered<P>(&self, filter: P, rand: &mut R) -> Option<&T>
        where
            P: FnMut(&&T) -> bool,
        {
            let filtered = self.iter().filter(filter).collect::<Vec<&T>>();
            let length = filtered.len();

            if length == 0 {
                None
            } else {
                let index = rand.below(length as u64) as usize;
                filtered.into_iter().nth(index)
            }
        }

        fn choose(&self, rand: &mut R) -> Option<&T> {
            let length = self.len();

            if length == 0 {
                None
            } else {
                let index = rand.below(length as u64) as usize;
                self.get(index)
            }
        }
    }

    pub fn choose_iter<I, E, T, R: Rand>(from: I, rand: &mut R) -> Option<T>
    where
        I: IntoIterator<Item = T, IntoIter = E>,
        E: ExactSizeIterator + Iterator<Item = T>,
    {
        // create iterator
        let mut iter = from.into_iter();
        let length = iter.len();

        if length == 0 {
            None
        } else {
            // pick a random, valid index
            let index = rand.below(length as u64) as usize;

            // return the item chosen
            iter.nth(index)
        }
    }

    pub type StepIndex = usize;
    pub type TermPath = Vec<usize>;
    pub type TracePath = (StepIndex, TermPath);

    /// https://en.wikipedia.org/wiki/Reservoir_sampling#Simple_algorithm
    // RULE: never choose a term for a DY or bit-level mutation which a sub-term of a not is_symbolic() term
    // Indeed, this latter term is considered atomic and a bitstring, including the former sub-term.
    // leaves --> considered as atoms and not terms!
    fn reservoir_sample<'a, R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
        trace: &'a Trace<M>,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<(&'a TermEval<M>, TracePath)> {
        let mut reservoir: Option<(&'a TermEval<M>, TracePath)> = None;
        let mut visited = 0;

        for (step_index, step) in trace.steps.iter().enumerate() {
            match &step.action {
                Action::Input(input) => {
                    let term = &input.recipe;

                    let size = term.size();
                    if size <= constraints.min_term_size || size >= constraints.max_term_size {
                        continue;
                        //TODO-bitlevel: consider removing this, we just want to exclude picking such terms
                        // but it is OK to enter the term and look for suitable sub-terms
                    }

                    let mut stack: Vec<(&TermEval<M>, TracePath, bool)> =
                        vec![(term, (step_index, Vec::new()), false)];// bool is true for terms inside a list (e.g., fn_append)

                    while let Some((term, path, is_inside_list)) = stack.pop() {
                        // push next terms onto stack
                        if term.is_symbolic() { // if not, we reached a leaf (real leaf or a term with payloads)
                            match &term.term {
                                Term::Variable(_) => {
                                    // reached leaf
                                }
                                Term::Application(fd, subterms) => {
                                    // inner node, recursively continue
                                    for (path_index, subterm) in subterms.iter().enumerate() {
                                        let mut new_path = path.clone();
                                        new_path.1.push(path_index); // invert because of .iter().rev()
                                        let is_inside_list_sub =
                                            constraints.not_inside_list &&
                                            fd.is_list();
                                        stack.push((subterm, new_path, is_inside_list_sub));
                                    }
                                }
                            }
                        }

                        // sample
                        if filter(term)
                            && (!constraints.no_payload_in_subterm ||
                                (term.is_symbolic() && term.all_payloads().is_empty()) ||
                                (!term.is_symbolic() && term.all_payloads().len() == 1))
                            && (!constraints.not_inside_list ||
                                !(is_inside_list && term.is_list())
                               ) {
                            visited += 1;

                            // consider in sampling
                            if reservoir.is_none() {
                                // fill initial reservoir
                                reservoir = Some((term, path));
                            } else {
                                // `1/visited` chance of overwriting
                                // replace elements with gradually decreasing probability
                                if rand.between(1, visited) == 1 {
                                    reservoir = Some((term, path));
                                }
                            }
                        }
                    }
                }
                Action::Output(_) => {
                    // no term -> skip
                }
            }
        }

        reservoir
    }

    fn find_term_by_term_path_mut<'a, M: Matcher>(
        term: &'a mut TermEval<M>,
        term_path: &mut TermPath,
    ) -> Option<&'a mut TermEval<M>> {
        if term_path.is_empty() {
            return Some(term);
        }

        let subterm_index = term_path.remove(0);

        match &mut term.term {
            Term::Variable(_) => None,
            Term::Application(_, subterms) => {
                if let Some(subterm) = subterms.get_mut(subterm_index) {
                    find_term_by_term_path_mut(subterm, term_path)
                } else {
                    None
                }
            }
        }
    }

    fn find_term_by_term_path<'a, M: Matcher>(
        term: &'a TermEval<M>,
        term_path: &mut TermPath,
    ) -> Option<&'a TermEval<M>> {
        if term_path.is_empty() {
            return Some(term);
        }

        let subterm_index = term_path.remove(0);

        match &term.term {
            Term::Variable(_) => None,
            Term::Application(_, subterms) => {
                if let Some(subterm) = subterms.get(subterm_index) {
                    find_term_by_term_path(subterm, term_path)
                } else {
                    None
                }
            }
        }
    }

    pub fn find_term_mut<'a, M: Matcher>(
        trace: &'a mut Trace<M>,
        trace_path: &TracePath,
    ) -> Option<&'a mut TermEval<M>> {
        let (step_index, term_path) = trace_path;

        let step: Option<&mut Step<M>> = trace.steps.get_mut(*step_index);
        if let Some(step) = step {
            match &mut step.action {
                Action::Input(input) => {
                    find_term_by_term_path_mut(&mut input.recipe, &mut term_path.clone())
                }
                Action::Output(_) => None,
            }
        } else {
            None
        }
    }

    pub fn find_term<'a, M: Matcher>(
        trace: &'a Trace<M>,
        trace_path: &TracePath,
    ) -> Option<&'a TermEval<M>> {
        let (step_index, term_path) = trace_path;

        let step: Option<&Step<M>> = trace.steps.get(*step_index);
        if let Some(step) = step {
            match &step.action {
                Action::Input(input) => {
                    find_term_by_term_path(&input.recipe, &mut term_path.clone())
                }
                Action::Output(_) => None,
            }
        } else {
            None
        }
    }

    pub fn choose<'a, R: Rand, M: Matcher>(
        trace: &'a Trace<M>,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<(&'a TermEval<M>, (usize, TermPath))> {
        reservoir_sample(trace, |_| true, constraints, rand)
    }

    pub fn choose_mut<'a, R: Rand, M: Matcher>(
        trace: &'a mut Trace<M>,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<(&'a mut TermEval<M>, (usize, TermPath))> {
        if let Some((t, (u, path))) = reservoir_sample(trace, |_| true, constraints, rand) {
            let t = find_term_mut(trace, &(u, path.clone()));
            t.map(|t| (t, (u, path)))
        } else {
            None
        }
    }

    pub fn choose_term<'a, R: Rand, M: Matcher>(
        trace: &'a Trace<M>,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a TermEval<M>> {
        reservoir_sample(trace, |_| true, constraints, rand).map(|ret| ret.0)
    }

    pub fn choose_term_mut<'a, R: Rand, M: Matcher>(
        trace: &'a mut Trace<M>,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a mut TermEval<M>> {
        if let Some(trace_path) = choose_term_path_filtered(trace, |_| true, constraints, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose_term_filtered_mut<'a, R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
        trace: &'a mut Trace<M>,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<&'a mut TermEval<M>> {
        if let Some(trace_path) = choose_term_path_filtered(trace, filter, constraints, rand) {
            find_term_mut(trace, &trace_path)
        } else {
            None
        }
    }

    pub fn choose_term_path<R: Rand, M: Matcher>(
        trace: &Trace<M>,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        choose_term_path_filtered(trace, |_| true, constraints, rand)
    }

    pub fn choose_term_path_filtered<R: Rand, M: Matcher, P: Fn(&TermEval<M>) -> bool + Copy>(
        trace: &Trace<M>,
        filter: P,
        constraints: TermConstraints,
        rand: &mut R,
    ) -> Option<TracePath> {
        reservoir_sample(trace, filter, constraints, rand).map(|ret| ret.1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use libafl::{
        bolts::rands::{RomuDuoJrRand, StdRand},
        corpus::InMemoryCorpus,
        mutators::{MutationResult, Mutator},
        state::StdState,
    };
    use log::debug;

    use super::*;
    use crate::{agent::AgentName, algebra::{
        dynamic_function::DescribableFunction,
        test_signature::{TestTrace, TestProtocolBehavior, *},
        AnyMatcher, Term,
    }, trace::{Action, Step}, trace};

    fn create_state(
    ) -> StdState<TestTrace, InMemoryCorpus<TestTrace>, RomuDuoJrRand, InMemoryCorpus<TestTrace>>
    {
        let rand = StdRand::with_seed(1235);
        let corpus: InMemoryCorpus<TestTrace> = InMemoryCorpus::new();
        StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
    }

    /// Checks whether repeat can repeat the last step
    #[test]
    fn test_repeat_mutator() {
        let mut state = create_state();

        let mut mutator = RepeatMutator::new(15);

        fn check_is_encrypt12(step: &Step<AnyMatcher>) -> bool {
            if let Action::Input(input) = &step.action {
                if input.recipe.name() == fn_encrypt12.name() {
                    return true;
                }
            }
            false
        }

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            let length = trace.steps.len();
            if let Some(last) = trace.steps.get(length - 1) {
                if check_is_encrypt12(last) {
                    if let Some(step) = trace.steps.get(length - 2) {
                        if check_is_encrypt12(step) {
                            break;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_replace_match_mutator() {
        let _server = AgentName::first();
        let mut state = create_state();
        let mut mutator = ReplaceMatchMutator::new(TermConstraints::default(), &TEST_SIGNATURE);

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let Some(last) = trace.steps.iter().last() {
                match &last.action {
                    Action::Input(input) => match &input.recipe.term {
                        Term::Variable(_) => {}
                        Term::Application(_, subterms) => {
                            if let Some(last_subterm) = subterms.iter().last() {
                                if last_subterm.name() == fn_seq_1.name() {
                                    break;
                                }
                            }
                        }
                    },
                    Action::Output(_) => {}
                }
            }
        }
    }

    #[test]
    fn test_remove_lift_mutator() {
        // Should remove an extension
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = RemoveAndLiftMutator::new(TermConstraints::default());

        // Returns the amount of extensions in the trace
        fn sum_extension_appends(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_client_extensions_append.name())
        }

        loop {
            let mut trace = setup_simple_trace();
            let before_mutation = sum_extension_appends(&trace);
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let MutationResult::Mutated = result {
                let after_mutation = sum_extension_appends(&trace);
                if after_mutation < before_mutation {
                    // extension removed
                    break;
                }
            }
        }
    }

    #[test]
    fn test_replace_reuse_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = ReplaceReuseMutator::new(TermConstraints::default());

        fn count_client_hello(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_client_hello.name())
        }

        fn count_finished(trace: &TestTrace) -> usize {
            trace.count_functions_by_name(fn_finished.name())
        }

        loop {
            let mut trace = setup_simple_trace();
            let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if let MutationResult::Mutated = result {
                let client_hellos = count_client_hello(&trace);
                let finishes = count_finished(&trace);
                if client_hellos == 2 && finishes == 0 {
                    // finished replaced by client_hello
                    break;
                }
            }
        }
    }

    #[test]
    fn test_skip_mutator() {
        let mut state = create_state();
        let _server = AgentName::first();
        let mut mutator = SkipMutator::new(2);

        loop {
            let mut trace = setup_simple_trace();
            let before_len = trace.steps.len();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            if before_len - 1 == trace.steps.len() {
                break;
            }
        }
    }

    #[test]
    fn test_swap_mutator() {
        let mut state = create_state();
        let mut mutator = SwapMutator::new(TermConstraints::default());

        loop {
            let mut trace = setup_simple_trace();
            mutator.mutate(&mut state, &mut trace, 0).unwrap();

            let is_first_not_ch = if let Some(first) = trace.steps.get(0) {
                match &first.action {
                    Action::Input(input) => Some(input.recipe.name() != fn_client_hello.name()),
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            let is_next_not_fn_client_key_exchange = if let Some(next) = trace.steps.get(1) {
                match &next.action {
                    Action::Input(input) => {
                        Some(input.recipe.name() != fn_client_key_exchange.name())
                    }
                    Action::Output(_) => None,
                }
            } else {
                None
            };

            if let Some(first) = is_first_not_ch {
                if let Some(second) = is_next_not_fn_client_key_exchange {
                    if first && second {
                        break;
                    }
                }
            }
        }
    }

    /// Bit-level mutations require concrete evaluations of terms to bitstrings and are thus tested in the tlspuffin crate

    #[test]
    fn test_find_term() {
        let mut rand = StdRand::with_seed(45);
        let mut trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut stats: HashSet<TracePath> = HashSet::new();

        for _ in 0..10000 {
            let path = choose_term_path(&trace, TermConstraints::default(), &mut rand).unwrap();
            find_term_mut(&mut trace, &path).unwrap();
            stats.insert(path);
        }

        assert_eq!(term_size, stats.len());
    }

    #[test]
    fn test_reservoir_sample_randomness() {
        /// https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html#standard-deviation
        fn std_deviation(data: &[u32]) -> Option<f32> {
            fn mean(data: &[u32]) -> Option<f32> {
                let sum = data.iter().sum::<u32>() as f32;
                let count = data.len();

                match count {
                    positive if positive > 0 => Some(sum / count as f32),
                    _ => None,
                }
            }

            match (mean(data), data.len()) {
                (Some(data_mean), count) if count > 0 => {
                    let variance = data
                        .iter()
                        .map(|value| {
                            let diff = data_mean - (*value as f32);

                            diff * diff
                        })
                        .sum::<f32>()
                        / count as f32;

                    Some(variance.sqrt())
                }
                _ => None,
            }
        }

        let trace = setup_simple_trace();
        let term_size = trace.count_functions();

        let mut rand = StdRand::with_seed(45);
        let mut stats: HashMap<u32, u32> = HashMap::new();

        for _ in 0..10000 {
            let term = choose(&trace, TermConstraints::default(), &mut rand).unwrap();

            let id = term.0.resistant_id();

            let count: u32 = *stats.get(&id).unwrap_or(&0);
            stats.insert(id, count + 1);
        }

        let std_dev =
            std_deviation(stats.values().cloned().collect::<Vec<u32>>().as_slice()).unwrap();
        /*        println!("{:?}", std_dev);
        println!("{:?}", stats);*/

        assert!(std_dev < 30.0);
        assert_eq!(term_size, stats.len());
    }
}