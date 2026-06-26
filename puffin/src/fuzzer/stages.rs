use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

use libafl::prelude::*;
use libafl_bolts::prelude::*;

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    name: Cow<'static, str>,
    mutations_core: MT,
    mutations_pre: MtPre,
    mutations_post: MtPost,
    max_stack_pow: usize,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, MtPre, MtPost, S> Debug for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FocusScheduledMutator with {} core mutations, {} pre-mutations, {} post-mutations, for Input type {}",
            self.mutations_core.len(),
            self.mutations_pre.len(),
            self.mutations_post.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, MtPre, MtPost, S> Named for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    MtPre: MutatorsTuple<I, S> + NamedTuple,
    MtPost: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, MT, MtPre, MtPost, S> Mutator<I, S> for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    MtPre: MutatorsTuple<I, S> + NamedTuple,
    MtPost: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<I, MT, MtPre, MtPost, S> ComposedByMutations for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S>,
    MtPre: MutatorsTuple<I, S>,
    MtPost: MutatorsTuple<I, S>,
    S: HasRand,
{
    type Mutations = MT;

    /// Get the core mutations (pre/post are handled separately in scheduled_mutate)
    fn mutations(&self) -> &Self::Mutations {
        &self.mutations_core
    }

    /// Get the core mutations (mutable)
    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        &mut self.mutations_core
    }
}

impl<I, MT, MtPre, MtPost, S> ScheduledMutator<I, S>
    for FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    MtPre: MutatorsTuple<I, S> + NamedTuple,
    MtPost: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below_or_zero(self.max_stack_pow))
    }

    /// Get the next mutation to apply (base implementation)
    fn schedule(&self, _: &mut S, _: &I) -> MutationId {
        panic!("[FocusScheduledMutator] mutations - schedule - should never be used");
    }

    /// New default implementation for mutate.
    /// Implementations must forward `mutate()` to this method
    fn scheduled_mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        log::debug!(
            "FocusScheduledMutator: num: {}, max_stack_pow: {}",
            num,
            self.max_stack_pow
        );
        // Pre-mutation: schedule exactly once
        // Note: the pre mutations will recognize this stage_idx and there is a certain probability
        // that the mutation won't be applied. However, a payload path will always be chosen and
        // stored in the input metadata for the later, HAVOC, and ReadMessage mutations.
        let idx = self.schedule_pre(state, input);
        log::debug!("FocusScheduledMutator: PRE idx: {}", idx);
        let outcome = self.mutations_pre_mut().get_and_mutate(idx, state, input)?;
        if outcome == MutationResult::Mutated {
            r = MutationResult::Mutated;
        }

        // Core mutations
        for _ in 0..num {
            let idx = self.schedule_core(state, input);
            log::debug!("FocusScheduledMutator: CORE idx: {}", idx);
            let outcome = self
                .mutations_core_mut()
                .get_and_mutate(idx, state, input)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }

        // Post-mutation: schedule exactly once
        // Note: the post mutations will recognize this stage_idx and there is a certain probability
        // that the mutation won't be applied, so we can skip it
        let idx = self.schedule_post(state, input);
        log::debug!("FocusScheduledMutator: POST idx: {}", idx);
        let outcome = self
            .mutations_post_mut()
            .get_and_mutate(idx, state, input)?;
        if outcome == MutationResult::Mutated {
            r = MutationResult::Mutated;
        }

        Ok(r)
    }
}

impl<I, MT, MtPre, MtPost, S> FocusScheduledMutator<I, MT, MtPre, MtPost, S>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    MtPre: MutatorsTuple<I, S> + NamedTuple,
    MtPost: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand,
{
    /// Create a new [`libafl::mutators::ScheduledMutator`] instance specifying mutations
    pub fn new(
        mutations_pre: MtPre,
        mutations_core: MT,
        mutations_post: MtPost,
        max_stack_pow: usize,
    ) -> Self {
        FocusScheduledMutator {
            name: Cow::from(format!(
                "FocusScheduledMutator[{};{};{}]",
                mutations_pre.names().join(", "),
                mutations_core.names().join(", "),
                mutations_post.names().join(", ")
            )),
            mutations_core,
            mutations_pre,
            mutations_post,
            // [#1b] tunable: was hardcoded 7, duplicating the (previously unused) config value.
            max_stack_pow,
            phantom: PhantomData,
        }
    }

    /// Create a new [`libafl::mutators::ScheduledMutator`] instance specifying mutations and the
    /// maximum number of iterations
    // pub fn with_max_stack_pow(mutations_pre:  MtPre, mutations: MT, mutations_post: MtPost,
    // max_stack_pow: u64) -> Self {     FocusScheduledMutator {
    //         name: format!("FocusScheduledMutator[{};{};{}]", mutations_pre.names().join(", "),
    // mutations.names().join(", "), mutations_post.names().join(", ")),         mutations,
    //         mutations_pre,
    //         mutations_post,
    //         max_stack_pow,
    //         phantom: PhantomData,
    //     }
    // }

    /// Get the next core-mutation to apply
    fn schedule_core(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_core.is_empty());
        state
            .rand_mut()
            .below_or_zero(self.mutations_core.len())
            .into()
    }

    /// Get the next pre-mutation to apply
    fn schedule_pre(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_pre.is_empty());
        state
            .rand_mut()
            .below_or_zero(self.mutations_pre.len())
            .into()
    }

    /// Get the next post-mutation to apply
    fn schedule_post(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations_post.is_empty());
        state
            .rand_mut()
            .below_or_zero(self.mutations_post.len())
            .into()
    }

    /// Get the pre-mutations (mutable): we use a custom selection instead of the default
    fn mutations_pre_mut(&mut self) -> &mut MtPre {
        &mut self.mutations_pre
    }

    /// Get the core-mutations (mutable): we use a custom selection instead of the default
    fn mutations_core_mut(&mut self) -> &mut MT {
        &mut self.mutations_core
    }

    /// Get the post-mutations (mutable): we use a custom selection instead of the default
    fn mutations_post_mut(&mut self) -> &mut MtPost {
        &mut self.mutations_post
    }

    pub fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    phantom: PhantomData<(I, S)>,
    max_mutations_per_iteration: usize,
}

impl<I, MT, S> Debug for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PuffinScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S> Named for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PuffinScheduledMutator")
    }
}

impl<I, MT, S> Mutator<I, S> for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<I, MT, S> ComposedByMutations for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    type Mutations = MT;

    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &Self::Mutations {
        &self.mutations
    }

    // Get the mutations (mut)
    #[inline]
    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        &mut self.mutations
    }
}

impl<I, MT, S> ScheduledMutator<I, S> for PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        state
            .rand_mut()
            .below_or_zero(self.max_mutations_per_iteration) as u64
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations().is_empty());
        state
            .rand_mut()
            .below_or_zero(self.mutations().len())
            .into()
    }
}

impl<I, MT, S> PuffinScheduledMutator<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[allow(dead_code)]
    /// Create a new [`PuffinScheduledMutator`] instance specifying mutations
    pub const fn new(mutations: MT, max_mutations_per_iteration: usize) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
            max_mutations_per_iteration,
        }
    }
}
