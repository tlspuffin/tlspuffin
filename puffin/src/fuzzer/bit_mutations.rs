use std::{ops::Not, thread::panicking};

use libafl::prelude::*;
use log::{debug, info, warn};

use super::utils::{Choosable, *};
use crate::{
    algebra::{atoms::Function, signature::Signature, Matcher, Subterms, Term, TermEval, TermType},
    codec::Codec,
    fuzzer::{harness::default_put_options, term_zoo::TermZoo, utils::choose_term_filtered_mut},
    protocol::ProtocolBehavior,
    trace::{Trace, TraceContext},
};

pub type HavocMutationsTypeDY<S: HasRand + HasMaxSize> = tuple_list_type!(
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

pub fn havoc_mutations_dy<S: HasRand + HasMaxSize + HasCorpus>(
    with_bit_level: bool,
) -> HavocMutationsTypeDY<S>
where
    <S as libafl::inputs::UsesInput>::Input: libafl::inputs::HasBytesVec,
{
    tuple_list!(
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

// --------------------------------------------------------------------------------------------------
// Term-level bit-level mutations
// --------------------------------------------------------------------------------------------------

use paste::paste;
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
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
        M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate {} skipped because bit-level mutations are disabled", std::any::type_name::<[<$mutation  DY>]<S>>());
            return Ok(MutationResult::Skipped)
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints::default(), // TODO: we may want to add no_paylaod_subterm
            // pros of adding: less mutations on sub-terms that could be subsumed by mutations on a larger term done in the first place
            // cons: might be useful to first shotgun small mutations on a small term to make the trace progress with possibly more actions and then
            //       do larger mutations on a larger term from there (might have an impact later).
            // TODO: balance out this trade-off
            rand,
        ) {
            debug!("[Mutation-bit] Mutate {} on term\n{}", std::any::type_name::<[<$mutation  DY>]<S>>(), &to_mutate);
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::$mutation.mutate(state, &mut payloads.payload, stage_idx)
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", std::any::type_name::<[<$mutation  DY>]<S>>());
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<[<$mutation  DY>]<S>>()
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
          crate::expand_mutations!($($MS),*);
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
    BytesCopyMutator // The next 4 fail because types of mutate seem a bit different, need a different macro for them
                     // TODO-bitlevel
                     // BytesInsertCopyMutator,
                     // BytesSwapMutator,
                     // CrossoverInsertMutator,
                     // CrossoverReplaceMutator
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

impl<S, M> Mutator<Trace<M>, S> for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate BytesSwapMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints::default(),
            rand,
        ) {
            debug!(
                "[Mutation-bit] Mutate {} on term\n{}",
                std::any::type_name::<BytesInsertCopyMutatorDY<S>>(),
                &to_mutate
            );
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::BytesSwapMutator::mutate(
                    &mut self.tmp_buf,
                    state,
                    &mut payloads.payload,
                    stage_idx,
                )
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", std::any::type_name:: <BytesInsertCopyMutatorDY<S>> ());
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<BytesSwapMutatorDY<S>>()
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

impl<S, M> Mutator<Trace<M>, S> for BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate BytesInsertCopyMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints::default(),
            rand,
        ) {
            debug!(
                "[Mutation-bit] Mutate {} on term\n{}",
                std::any::type_name::<BytesInsertCopyMutatorDY<S>>(),
                &to_mutate
            );
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::BytesInsertCopyMutator::mutate(
                    &mut self.tmp_buf,
                    state,
                    &mut payloads.payload,
                    stage_idx,
                )
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", std::any::type_name:: <BytesInsertCopyMutatorDY<S>> ());
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for BytesInsertCopyMutatorDY<S>
where
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<BytesInsertCopyMutatorDY<S>>()
    }
}

// --------------------------------------------------------------------------------------------------
// Trace-level bit-level mutations --> Cross-over need to consider traces with the HasBytesVec trait!
// --------------------------------------------------------------------------------------------------
// We could write another macro for the three following mutations
// CrossoverInsertMutatorDY
pub struct CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    with_bit_level: bool,
    tmp_buf: CrossoverInsertMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
            tmp_buf: CrossoverInsertMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
    M: Matcher,
    //        <S as libafl::inputs::UsesInput>::Input = BytesInput,
    S: libafl::inputs::UsesInput<Input = Trace<M>>,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate CrossoverInsertMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        // CrossoverInsertMutator::mutate(&mut self.tmp_buf,  state,trace, stage_idx)
        // // Either write HasBytesVec for Trace for the CrossOver and splice mutations in bit_mutations.rs
        // // Or inline the real one but choosing the crossover manually and doing the
        // // the same then.
        Ok(MutationResult::Skipped)
    }
}

impl<S> Named for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    fn name(&self) -> &str {
        std::any::type_name::<CrossoverInsertMutatorDY<S>>()
    }
}

pub struct CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    with_bit_level: bool,
    tmp_buf: CrossoverReplaceMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
            tmp_buf: CrossoverReplaceMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
    M: Matcher,
    //        <S as libafl::inputs::UsesInput>::Input = BytesInput,
    S: libafl::inputs::UsesInput<Input = Trace<M>>,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate CrossoverReplaceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        // CrossoverReplaceMutator::mutate(&mut self.tmp_buf,  state,trace, stage_idx)
        // // Either write HasBytesVec for Trace for the CrossOver and splice mutations in bit_mutations.rs
        // // Or inline the real one but choosing the crossover manually and doing the
        // // the same then.
        Ok(MutationResult::Skipped)
    }
}

impl<S> Named for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    fn name(&self) -> &str {
        std::any::type_name::<CrossoverReplaceMutatorDY<S>>()
    }
}

pub struct SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    with_bit_level: bool,
    tmp_buf: SpliceMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new(with_bit_level: bool) -> Self {
        Self {
            with_bit_level,
            tmp_buf: SpliceMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
    M: Matcher,
    //        <S as libafl::inputs::UsesInput>::Input = BytesInput,
    S: libafl::inputs::UsesInput<Input = Trace<M>>,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate SpliceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }
        // SpliceMutator::mutate(&mut self.tmp_buf,  state,trace, stage_idx)
        // // Either write HasBytesVec for Trace for the CrossOver and splice mutations in bit_mutations.rs
        // // Or inline the real one but choosing the crossover manually and doing the
        // // the same then.
        Ok(MutationResult::Skipped)
    }
}

impl<S> Named for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    fn name(&self) -> &str {
        std::any::type_name::<SpliceMutatorDY<S>>()
    }
}
