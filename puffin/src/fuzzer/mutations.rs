use libafl::prelude::*;
use log::{debug, error, info, warn};
use std::ops::Not;
use std::thread::panicking;
use super::utils::{Choosable, *};
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
    BytesInsertCopyMutatorDY<S>,
    BytesSwapMutatorDY<S>,
    CrossoverInsertMutatorDY<S>,
    CrossoverReplaceMutatorDY<S>,
    SpliceMutatorDY<S>,
    )
where
    S: HasCorpus + HasMetadata + HasMaxSize + HasRand,
    PB: ProtocolBehavior,
    <S as libafl::inputs::UsesInput>::Input: libafl::inputs::HasBytesVec,
{
    tuple_list!(
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
            debug!("Mutate GenerateMutator on term {}", to_mutate);
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

/// MakeMessage on the term at path `path` in `tr`.
fn make_message_term<M: Matcher, PB: ProtocolBehavior<Matcher=M>>(tr: &mut Trace<M>,
                                                                  path: &TracePath,
                                                                  ctx: &mut TraceContext<PB>)
    -> Result<(),anyhow::Error>
    where
    PB: ProtocolBehavior<Matcher=M>,
{
    // Only execute shorter trace: trace[0..step_index])
    // execute the PUT on the first step_index steps and store the resulting trace context
    tr.execute_until_step(ctx, path.0).err().map(|e| {
        error!("mutation::MakeMessage trace is not executable until step {},\
            could only happen if this mutation is scheduled with other mutations that create a non-executable trace.\
            TO CHECK! Error: {e}\n trace:\n{}", path.0, &tr);
        return Ok::<MutationResult, Error>(MutationResult::Skipped)
    });

    let mut t = find_term_mut(tr, path).expect("make_message_term - Should never happen.");
    // We get payload_0 by symbolically evaluating the term! (and not full eval with potential payloads in sub-terms). This
    // because, doing differently would dramatically complexify the computation of replace_payloads.
    // See terms.rs. Also, one could argue the mutations of the strict sub-terms could have been done on the larger
    // term in thje first place.
    t.make_payload(&ctx).with_context(||
        format!("failed to evaluate chosen sub-term"))?;
    Ok(())
}


impl<S, M: Matcher, PB: ProtocolBehavior<Matcher=M>> Mutator<Trace<M>, S> for MakeMessage<S, PB>
    where
        S: HasRand,
        PB: ProtocolBehavior<Matcher=M>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        let constraints_make_message = TermConstraints {
            no_payload_in_subterm: true, // change to true to exclude picking a term with a payload in a sub-term
                                          // we currently forbid this, could it lead to interesting series of mutations ?
                                          // not sure. However, it would make term evaluation a lot costlier for sure!
            not_inside_list: true, // true means we are not picking terms inside list (like fn_append in the middle)
            // we set it to true since a MakeMessage inside a list is never going to then be evaluated
            // indeed: the evaluation of a partial list is never going to be found in the evaluation of the
            // full list!
            weighted_depth: true,  // true means we select a sub-term by giving higher-priority to deeper sub-terms
            ..self.constraints
        };
        // choose a random sub term
        if let Some((chosen_term, (step_index, term_path))) =
            choose(trace, constraints_make_message, rand)
        {
            debug!("Mutate MakeMessage on term {}", chosen_term);
            let mut ctx = TraceContext::new(PB::registry(), default_put_options().clone());
            match make_message_term(trace, &(step_index, term_path), &mut ctx) {
                // TODO: possibly we would need to make sure the mutated trace can be executed (if not directly dropped
                // by the feedback loop once executed)
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
}