use super::utils::{Choosable, *};
use libafl::prelude::*;
use log::{info, debug, warn};
use std::ops::Not;
use std::thread::panicking;

use crate::algebra::{Payloads, TermEval, TermType};
use crate::codec::Codec;
use crate::fuzzer::harness::default_put_options;
use crate::fuzzer::utils::choose_term_filtered_mut;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;
use crate::{
    algebra::{atoms::Function, signature::Signature, Matcher, Subterms, Term},
    fuzzer::term_zoo::TermZoo,
    trace::Trace,
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

pub fn havoc_mutations_DY<S: HasRand + HasMaxSize + HasCorpus>() -> HavocMutationsTypeDY<S>
    where <S as libafl::inputs::UsesInput>::Input: libafl::inputs::HasBytesVec
{
    tuple_list!(
        BitFlipMutatorDY::new(),
        ByteFlipMutatorDY::new(),
        ByteIncMutatorDY::new(),
        ByteDecMutatorDY::new(),
        ByteNegMutatorDY::new(),
        ByteRandMutatorDY::new(),
        ByteAddMutatorDY::new(),
        WordAddMutatorDY::new(),
        DwordAddMutatorDY::new(),
        QwordAddMutatorDY::new(),
        ByteInterestingMutatorDY::new(),
        WordInterestingMutatorDY::new(),
        DwordInterestingMutatorDY::new(),
        BytesDeleteMutatorDY::new(),
        BytesDeleteMutatorDY::new(),
        BytesDeleteMutatorDY::new(),
        BytesDeleteMutatorDY::new(),
        BytesExpandMutatorDY::new(),
        BytesInsertMutatorDY::new(),
        BytesRandInsertMutatorDY::new(),
        BytesSetMutatorDY::new(),
        BytesRandSetMutatorDY::new(),
        BytesCopyMutatorDY::new(),
        BytesInsertCopyMutatorDY::new(),
        BytesSwapMutatorDY::new(),
        CrossoverInsertMutatorDY::new(),
        CrossoverReplaceMutatorDY::new(),
        SpliceMutatorDY::new(),

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
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> [<$mutation  DY>]<S>
    where
        S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
            debug!("Mutate {} on term {}", std::any::type_name::<[<$mutation  DY>]<S>>(), &to_mutate);
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
    BytesCopyMutator
    // The next 4 fail because types of mutate seem a bit different, need a different macro for them
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
    tmp_buf: BytesSwapMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesSwapMutatorDY<S>
    where
        S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints::default(),
            rand,
        ) {
            debug!("Mutate {} on term {}", std::any::type_name::<BytesInsertCopyMutatorDY<S>>(), &to_mutate);
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::BytesSwapMutator::mutate(&mut self.tmp_buf,  state,&mut payloads.payload, stage_idx)
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
        std::any::type_name::<BytesSwapMutatorDY<S>> ()
    }
}

// BytesInsertCopyMutatorDY
pub struct BytesInsertCopyMutatorDY<S>
    where
        S: HasRand + HasMaxSize,
{
    tmp_buf: BytesInsertCopyMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BytesInsertCopyMutatorDY<S>
    where
        S: HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
        let rand = state.rand_mut();
        if let Some(to_mutate) = choose_term_filtered_mut(
            trace,
            |x| x.is_symbolic().not(),
            TermConstraints::default(),
            rand,
        ) {
            debug!("Mutate {} on term {}", std::any::type_name::<BytesInsertCopyMutatorDY<S>>(), &to_mutate);
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::BytesInsertCopyMutator::mutate(&mut self.tmp_buf,  state,&mut payloads.payload, stage_idx)
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
        std::any::type_name::<BytesInsertCopyMutatorDY<S>> ()
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
    tmp_buf: CrossoverInsertMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverInsertMutatorDY<S>
    where
        S: HasCorpus + HasRand + HasMaxSize,
        S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
        M:Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
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
        std::any::type_name::<CrossoverInsertMutatorDY<S>> ()
    }
}


pub struct CrossoverReplaceMutatorDY<S>
    where
        S: HasCorpus + HasRand + HasMaxSize,
        S::Input: HasBytesVec,
{
    tmp_buf: CrossoverReplaceMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> CrossoverReplaceMutatorDY<S>
    where
        S: HasCorpus + HasRand + HasMaxSize,
        S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
        M:Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
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
        std::any::type_name::<CrossoverReplaceMutatorDY<S>> ()
    }
}

pub struct SpliceMutatorDY<S>
    where
        S: HasCorpus + HasRand + HasMaxSize,
        S::Input: HasBytesVec,
{
    tmp_buf: SpliceMutator,
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> SpliceMutatorDY<S>
    where
        S: HasCorpus + HasRand + HasMaxSize,
        S::Input: HasBytesVec,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
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
        M:Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
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
        std::any::type_name::<SpliceMutatorDY<S>> ()
    }
}
