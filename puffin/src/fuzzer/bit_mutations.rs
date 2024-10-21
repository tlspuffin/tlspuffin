use std::any::{type_name, TypeId};
use std::cmp::min;
use std::io::Read;
use std::ops::Not;
use std::thread::panicking;

use libafl::prelude::*;
use libafl_bolts::prelude::{tuple_list, tuple_list_type};
use libafl_bolts::rands::Rand;
use libafl_bolts::Named;
use log::{debug, info, trace, warn};

use super::utils::{Choosable, *};
use crate::algebra::atoms::Function;
use crate::algebra::signature::Signature;
use crate::algebra::{DYTerm, Matcher, Subterms, Term, TermType};
use crate::codec::Codec;
use crate::fuzzer::harness::default_put_options;
use crate::fuzzer::term_zoo::TermZoo;
use crate::fuzzer::utils::choose_term_filtered_mut;
use crate::protocol::ProtocolBehavior;
use crate::trace::{Trace, TraceContext};

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
) -> HavocMutationsTypeDY<S> {
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

use crate::algebra::bitstrings::Payloads;

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
        S: HasRand + HasMaxSize + 'static,
        M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        trace!("Start mutate with {:?}", self.name());

        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate {} skipped because bit-level mutations are disabled", self.name());
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
            debug!("[Mutation-bit] Mutate {} on term\n{}", self.name(), &to_mutate);
            if let Some(payloads) = &mut to_mutate.payloads {
                libafl::mutators::mutations::$mutation.mutate(state, &mut payloads.payload, stage_idx)
            } else {
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
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
                    .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last().unwrap()
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
    BytesCopyMutator /* The next 2 require custom implementations:
                      *   BytesInsertCopyMutator,
                      *   BytesSwapMutator,
                      * The three next require to pick up another test-case (cross-over), see
                      * dedicated implems:   CrossoverInsertMutator
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

impl<S, M> Mutator<Trace<M>, S> for BytesSwapMutatorDY<S>
where
    S: HasRand + HasMaxSize + 'static,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        trace!("Start mutate with {:?}", self.name());

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
                self.name(),
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
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
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
            .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last()
            .unwrap()
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
    S: HasRand + HasMaxSize + 'static,
    M: Matcher,
{
    fn mutate(
        &mut self,
        state: &mut S,
        trace: &mut Trace<M>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        trace!("Start mutate with {:?}", self.name());

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
                self.name(),
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
                panic!("mutation::{}::this shouldn't happen since we filtered out terms that are symbolic!", self.name());
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
            .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last()
            .unwrap()
    }
}

// --------------------------------------------------------------------------------------------------
// Trace-level bit-level mutations --> Cross-over need to consider traces with the HasBytesVec
// trait!
// --------------------------------------------------------------------------------------------------

/// Randomly choose a payload and its index (nth) in a trace (mutable reference), if there is any
/// and if it has at least 2 bytes
fn choose_payload_mut<'a, M, S>(
    trace: &'a mut Trace<M>,
    state: &mut S,
) -> Option<(&'a mut Vec<u8>, usize)>
where
    S: HasCorpus + HasRand + HasMaxSize,
    M: Matcher,
{
    let mut all_payloads: Vec<&'a mut Payloads> = trace.all_payloads_mut();
    if all_payloads.is_empty() {
        return None;
    }
    let idx = state.rand_mut().between(0, (all_payloads.len() - 1) as u64) as usize;
    let input = all_payloads.remove(idx);
    let input = input.payload.bytes_mut();
    if input.len() < 2 {
        return None;
    }
    return Some((input, idx));
}

/// Randomly choose a payload and its index (n-th) in a trace, if there is any and if it has at
/// least 2 bytes
fn choose_payload<'a, M, S>(trace: &'a Trace<M>, state: &mut S) -> Option<(&'a [u8], usize)>
where
    S: HasCorpus + HasRand + HasMaxSize,
    M: Matcher,
{
    let all_payloads = trace.all_payloads();
    if all_payloads.is_empty() {
        return None;
    }
    let idx = state.rand_mut().between(0, (all_payloads.len() - 1) as u64) as usize;
    let input = all_payloads[idx].payload.bytes();
    if input.len() < 2 {
        return None;
    }
    return Some((input, idx));
}

/// Access the n-th payload of a trace, if it exists
fn get_payload<'a, M>(trace: &'a Trace<M>, idx: usize) -> Option<(&'a [u8])>
where
    M: Matcher,
{
    let all_payloads = trace.all_payloads();
    if all_payloads.len() <= idx {
        return None;
    }
    let input = all_payloads[idx].payload.bytes();
    if input.len() < 2 {
        return None;
    }
    return Some(input);
}

/// Copied from libafl::mutators::mutations
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

/// Copied from libafl::mutators::mutations
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
    tmp_buf: CrossoverInsertMutator,
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
            tmp_buf: CrossoverInsertMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize + 'static,
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
        trace!("Start mutate with {:?}", self.name());

        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate CrossoverInsertMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _)) = choose_payload_mut(trace, state) else {
            return Ok(MutationResult::Skipped);
        };

        // Inlined from libafl::mutators::mutations pub struct CrossoverInsertMutator
        let size = input.len();
        let max_size = state.max_size();
        if size >= max_size {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());

        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
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
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let other_size = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
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
        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .bytes();
        let other_size = other_input.len();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for CrossoverInsertMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<CrossoverInsertMutatorDY<S>>()
            .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last()
            .unwrap()
    }
}

pub struct CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    with_bit_level: bool,
    tmp_buf: CrossoverReplaceMutator,
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
            tmp_buf: CrossoverReplaceMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize + 'static,
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
        trace!("Start mutate with {:?}", self.name());

        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate CrossoverReplaceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _)) = choose_payload_mut(trace, state) else {
            return Ok(MutationResult::Skipped);
        };

        // Inlined from libafl::mutators::mutations pub struct CrossoverReplaceMutator
        let size = input.len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
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
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let other_size = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below(size as u64) as usize;
        let range = rand_range(state, other_size, min(other_size, size - target));

        // let other_testcase = state.corpus().get(idx)?.borrow_mut();
        // // No need to load the input again, it'll still be cached.
        // let other = other_testcase.input().as_ref().unwrap();
        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .bytes();

        unsafe {
            buffer_copy(input, other_input, range.start, target, range.len());
        }
        debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for CrossoverReplaceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<CrossoverReplaceMutatorDY<S>>()
            .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last()
            .unwrap()
    }
}

pub struct SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    with_bit_level: bool,
    tmp_buf: SpliceMutator,
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
            tmp_buf: SpliceMutator::new(),
            phantom_s: std::marker::PhantomData,
        }
    }
}

impl<S, M> Mutator<Trace<M>, S> for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize + 'static,
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
        trace!("Start mutate with {:?}", self.name());

        if !self.with_bit_level {
            debug!("[Mutation-bit] Mutate SpliceMutatorDY skipped because bit-level mutations are disabled");
            return Ok(MutationResult::Skipped);
        }

        let Some((input, _)) = choose_payload_mut(trace, state) else {
            trace!("choose_payload_mut failed");
            return Ok(MutationResult::Skipped);
        };

        // Inlined from libafl::mutators::mutations pub struct SpliceMutator
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                trace!("Same other testcase");
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
            trace!("other payload is too short: {size_vec_payloads}");
            return Ok(MutationResult::Skipped);
        }
        let payload_idx = state // we need to split the choice of other_input int two steps to
            // avoid borrow checker issues (state need sto be immutably borrowed to access the
            // corpus and mutably borrowed to pick a random payload in the chosen trace)
            .rand_mut()
            .between(0, (size_vec_payloads - 1) as u64) as usize;
        let other_size = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            // Input will already be loaded.
            let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
                .payload
                .bytes();
            other_input.len()
        };
        //

        let (first_diff, last_diff) = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
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
                    trace!("counter is 3");
                    return Ok(MutationResult::Skipped);
                }
                counter += 1;
            }
        };

        let split_at = state.rand_mut().between(first_diff, last_diff) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // Input will already be loaded.
        let other_input = other_testcase.input().as_ref().unwrap().all_payloads()[payload_idx]
            .payload
            .bytes();

        input.splice(split_at.., other_input[split_at..].iter().copied());
        debug!("[Mutation-bit] Mutate {} on trace {trace:?} crossing over with corpus id {idx} and payload id {payload_idx}", self.name());
        trace!("Trace: {trace}");
        Ok(MutationResult::Mutated)
    }
}

impl<S> Named for SpliceMutatorDY<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        std::any::type_name::<SpliceMutatorDY<S>>()
            .splitn(2, '<')
            .collect::<Vec<&str>>()[0]
            .split(':')
            .collect::<Vec<&str>>()
            .last()
            .unwrap()
    }
}
