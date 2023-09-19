use super::mutations::util::{Choosable, *};
use libafl::prelude::*;
use log::info;
use std::ops::Not;
use std::thread::panicking;

use crate::algebra::{Payloads, TermEval, TermType};
use crate::codec::Codec;
use crate::fuzzer::harness::default_put_options;
use crate::fuzzer::mutations::util::choose_term_filtered_mut;
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
    // BytesInsertCopyMutatorDY<S>,
    // BytesSwapMutatorDY<S>,
    // CrossoverInsertMutatorDY<S>,
    // CrossoverReplaceMutatorDY<S>,
);

pub fn havoc_mutations_DY<S: HasRand + HasMaxSize>() -> HavocMutationsTypeDY<S> {
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
        // BytesInsertCopyMutatorDY::new(),
        // BytesSwapMutatorDY::new(),
        // CrossoverInsertMutatorDY::new(),
        // CrossoverReplaceMutatorDY::new(),
    )
}

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
            TermConstraints::default(),
            rand,
        ) {
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::$mutation.mutate(state, &mut payloads.payload, stage_idx)
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolics!", std::any::type_name::<[<$mutation  DY>]<S>>());
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
    }
};
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
//
// pub struct BitFlipMutatorDY<S>
//     where
//         S: HasRand + HasMaxSize,
// {
//     phantom_s: std::marker::PhantomData<S>,
// }
//
// impl<S> BitFlipMutatorDY<S>
//     where
//         S: HasRand + HasMaxSize,
// {
//     #[must_use]
//     pub fn new() -> Self {
//         Self {
//             phantom_s: std::marker::PhantomData,
//         }
//     }
// }
//
// impl<S, M> Mutator<Trace<M>, S> for BitFlipMutatorDY<S>
//     where
//         S: HasRand + HasMaxSize,
//         M: Matcher,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         trace: &mut Trace<M>,
//         stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let rand = state.rand_mut();
//         if let Some(to_mutate) = choose_term_filtered_mut(
//             trace,
//             |x| x.is_symbolic().not(),
//             TermConstraints::default(),
//             rand,
//         ) {
//             if let Some(payloads) = &mut to_mutate.payloads {
//                 BitFlipMutator.mutate(state, &mut payloads.payload, stage_idx)
//             } else {
//                 panic!("mutation::BitFlip::this shouldn't happen since we filtered out terms that are symbolics!")
//             }
//         } else {
//             Ok(MutationResult::Skipped)
//         }
//     }
// }
//
// impl<S> Named for BitFlipMutatorDY<S>
//     where
//         S: HasRand + HasMaxSize,
// {
//     fn name(&self) -> &str {
//         std::any::type_name::<BitFlipMutatorDY<S>>()
//     }
// }
