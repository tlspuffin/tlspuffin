use std::borrow::Cow;
use std::collections::HashSet;

use libafl::executors::ExitKind;
use libafl::feedbacks::{Feedback, StateInitializer};
use libafl_bolts::prelude::MatchName;
use libafl_bolts::tuples::*;
use libafl_bolts::{Error, Named};

use crate::fuzzer::feedback::claim_observer::ClaimObserver;

/// Feedback based on individual claims.
/// It considers a trace interesting if it observes a novel claim string never encountered before.
pub struct ClaimFeedback {
    /// Global cache of all unique claims discovered across all fuzzing iterations.
    seen_claims: HashSet<String>,
    observer_handle: Handle<ClaimObserver>,
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for ClaimFeedback {}

impl ClaimFeedback {
    /// Creates a new [`ClaimFeedback`] linked to the given [`ClaimObserver`].
    pub fn new(observer: &ClaimObserver) -> Self {
        Self {
            seen_claims: HashSet::new(),
            observer_handle: observer.handle(),
            name: Cow::Borrowed("claim_feedback"),
        }
    }
}

impl Named for ClaimFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ClaimFeedback
where
    OT: MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let Some(claim_observer) = observers.get(&self.observer_handle) else {
            return Err(Error::illegal_state(
                "Observer referenced by Claimfeedback is not found in observers given to the fuzzer",
            ));
        };
        let mut discovered_new_claim = false;
        let mut new_keys_this_exec = Vec::new();

        // Identify and cache new claims found during this specific execution
        for key in &claim_observer.claims {
            if !self.seen_claims.contains(key) {
                discovered_new_claim = true;
                self.seen_claims.insert(key.clone());
                new_keys_this_exec.push(key.clone());
            }
        }
        // Trigger LibAFL interestingness if at least one new claim was registered
        if discovered_new_claim {
            for unique_claim in new_keys_this_exec {
                log::debug!("New claim discovered : {}", unique_claim);
            }
            return Ok(true);
        }
        Ok(false)
    }
}
/// Feedback that evaluates the global profile (sequence/combination) of claims.
/// Unlike [`ClaimFeedback`], it triggers when a new combination of claim
pub struct ProfileFeedback {
    /// Global cache tracking unique ordered sequences of claims.
    seen_profiles: HashSet<Vec<String>>,
    observer_handle: Handle<ClaimObserver>,
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for ProfileFeedback {}

impl ProfileFeedback {
    /// Creates a new [`ProfileFeedback`] linked to the given [`ClaimObserver`].
    pub fn new(observer: &ClaimObserver) -> Self {
        Self {
            seen_profiles: HashSet::new(),
            observer_handle: observer.handle(),
            name: Cow::Borrowed("profile_feedback"),
        }
    }
}

impl Named for ProfileFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ProfileFeedback
where
    OT: MatchName,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let Some(observer) = observers.get(&self.observer_handle) else {
            return Err(Error::illegal_state(
                "Observer referenced by Profilefeedback is not found in observers given to the fuzzer",
            ));
        };
        let current_profile = &observer.claims;

        if current_profile.is_empty() {
            return Ok(false);
        }
        // Check if the exact state transition sequence/profile is novel
        if !self.seen_profiles.contains(current_profile) {
            self.seen_profiles.insert(current_profile.clone());
            log::debug!("New profile discovered : {:?}", current_profile);
            return Ok(true);
        }
        Ok(false)
    }
}
