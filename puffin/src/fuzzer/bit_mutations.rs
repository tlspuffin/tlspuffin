use libafl::prelude::*;
use log::info;
use std::ops::Not;
use std::thread::panicking;
use super::mutations::util::{Choosable, *};

use crate::algebra::{Payloads, TermEval, TermType};
use crate::codec::Codec;
use crate::fuzzer::harness::default_put_options;
use crate::protocol::ProtocolBehavior;
use crate::trace::TraceContext;
use crate::{
    algebra::{atoms::Function, signature::Signature, Matcher, Subterms, Term},
    fuzzer::term_zoo::TermZoo,
    trace::Trace,
};
use crate::fuzzer::mutations::util::choose_term_filtered_mut;


pub type HavocMutationsTypeDY<S:HasRand> = tuple_list_type!(
    BitFlipMutatorDY<S>
    // ByteFlipMutatorDY,
    // ByteIncMutatorDY,
    // ByteDecMutatorDY,
    // ByteNegMutatorDY,
    // ByteRandMutatorDY,
    // ByteAddMutatorDY,
    // WordAddMutatorDY,
    // DwordAddMutatorDY,
    // QwordAddMutatorDY,
    // ByteInterestingMutatorDY,
    // WordInterestingMutatorDY,
    // DwordInterestingMutatorDY,
    // BytesDeleteMutatorDY,
    // BytesDeleteMutatorDY,
    // BytesDeleteMutatorDY,
    // BytesDeleteMutatorDY,
    // BytesExpandMutatorDY,
    // BytesInsertMutatorDY,
    // BytesRandInsertMutatorDY,
    // BytesSetMutatorDY,
    // BytesRandSetMutatorDY,
    // BytesCopyMutatorDY,
    // BytesInsertCopyMutatorDY,
    // BytesSwapMutatorDY,
    // CrossoverInsertMutatorDY,
    // CrossoverReplaceMutatorDY,
);

pub fn havoc_mutations_DY<S:HasRand>() -> HavocMutationsTypeDY<S> {
    tuple_list!(
        BitFlipMutatorDY::new(),
    )
}



/// BitFlip : bit flip mutations

pub struct BitFlipMutatorDY<S>
    where
        S: HasRand,
{
    phantom_s: std::marker::PhantomData<S>,
}

impl<S> BitFlipMutatorDY<S>
    where
        S: HasRand,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for BitFlipMutatorDY<S>
    where
        S: HasRand,
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
            if let Some(payloads) = &mut to_mutate.payloads {
                BitFlipMutator.mutate(state, &mut payloads.payload, stage_idx)
            } else {
                panic!("mutation::BitFlip::this shouldn't happen since we filtered out terms that are symbolics!")
            }
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Named for BitFlipMutatorDY<S>
    where
        S: HasRand,
{
    fn name(&self) -> &str {
        std::any::type_name::<BitFlipMutatorDY<S>>()
    }
}
