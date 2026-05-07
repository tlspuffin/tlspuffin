use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::num::NonZeroUsize;

use libafl::prelude::mutational::MutatedTransform;
use libafl::prelude::*;
use libafl_bolts::prelude::*;
use serde::{Deserialize, Serialize};

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
    pub fn new(mutations_pre: MtPre, mutations_core: MT, mutations_post: MtPost) -> Self {
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
            max_stack_pow: 7,
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

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct PuffinRetryCountRestartHelper {
    tries_remaining: Option<usize>,
    skipped: HashSet<CorpusId>,
}

impl_serdeany!(PuffinRetryCountRestartHelper);

impl PuffinRetryCountRestartHelper {
    /// Don't allow restart
    pub fn no_retry<S>(state: &mut S, name: &str) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasCurrentCorpusId,
    {
        Self::should_restart(state, name, 0, false)
    }

    /// Initializes (or counts down in) the progress helper, giving it the amount of max retries
    ///
    /// Returns `true` if the stage should run
    pub fn should_restart<S>(
        state: &mut S,
        name: &str,
        max_retries: usize,
        skip_traces: bool,
    ) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasCurrentCorpusId,
    {
        let corpus_id = state.current_corpus_id()?.ok_or_else(|| {
            Error::illegal_state(
                "No current_corpus_id set in State, but called RetryCountRestartHelper::should_skip",
            )
        })?;

        let initial_tries_remaining = max_retries + 2; // +1 for first run (before real retry), +1 because we substract before comparing
        let metadata = state.named_metadata_or_insert_with(name, || Self {
            tries_remaining: Some(initial_tries_remaining),
            skipped: HashSet::new(), // Do not allocate memory if no item added
        });
        let tries_remaining = metadata
            .tries_remaining
            .unwrap_or(initial_tries_remaining)
            .checked_sub(1)
            .ok_or_else(|| {
                Error::illegal_state(
                    "Attempted further retries after we had already gotten to none remaining.",
                )
            })?;

        metadata.tries_remaining = Some(tries_remaining);

        Ok(if tries_remaining == 0 {
            if skip_traces {
                metadata.skipped.insert(corpus_id);
            }
            false
        } else if skip_traces && metadata.skipped.contains(&corpus_id) {
            // skip this testcase, we already retried it often enough...
            false
        } else {
            true
        })
    }

    /// Clears the progress
    pub fn clear_progress<S>(state: &mut S, name: &str) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        state.named_metadata_mut::<Self>(name)?.tries_remaining = None;
        Ok(())
    }
}

/// A mutational stage that overrides retry behavior, unlike [`StdMutationalStage`] which caps
/// restarts to 3 per corpus item via `RetryCountRestartHelper`. When `max_retries` is 0, retries
/// are unlimited, fixing the ~40x regression in objective count for differential fuzzing campaigns
/// introduced by LibAFL 0.15.x. When `max_retries > 0`, the limit is enforced per corpus item.
pub struct PuffinMutationalStage<E, EM, I1, I2, M, S, Z> {
    inner: StdMutationalStage<E, EM, I1, I2, M, S, Z>,
    max_retries: usize,
    skip_traces: bool,
}

impl<E, EM, I, M, S, Z> PuffinMutationalStage<E, EM, I, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: MutatedTransform<I, S> + Input + Clone,
    S: HasCorpus<I> + HasRand + HasCurrentCorpusId + MaybeHasClientPerfMonitor,
    Z: Evaluator<E, EM, I, S>,
{
    pub fn with_max_iterations(
        mutator: M,
        max_iterations: NonZeroUsize,
        max_retries: usize,
        skip_traces: bool,
    ) -> Self {
        Self {
            inner: StdMutationalStage::with_max_iterations(mutator, max_iterations),
            max_retries,
            skip_traces,
        }
    }
}

impl<E, EM, I1, I2, M, S, Z> Named for PuffinMutationalStage<E, EM, I1, I2, M, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

impl<E, EM, I1, I2, M, S, Z> Stage<E, EM, S, Z> for PuffinMutationalStage<E, EM, I1, I2, M, S, Z>
where
    I1: Clone + MutatedTransform<I2, S>,
    I2: Input,
    M: Mutator<I1, S>,
    S: HasRand
        + HasCorpus<I2>
        + HasMetadata
        + HasExecutions
        + HasNamedMetadata
        + HasCurrentCorpusId
        + MaybeHasClientPerfMonitor,
    Z: Evaluator<E, EM, I2, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.inner.perform(fuzzer, executor, state, manager)
    }
}

impl<E, EM, I1, I2, M, S, Z> Restartable<S> for PuffinMutationalStage<E, EM, I1, I2, M, S, Z>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        PuffinRetryCountRestartHelper::should_restart(
            state,
            &self.name(),
            self.max_retries,
            self.skip_traces,
        )
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        PuffinRetryCountRestartHelper::clear_progress(state, &self.name())
    }
}
