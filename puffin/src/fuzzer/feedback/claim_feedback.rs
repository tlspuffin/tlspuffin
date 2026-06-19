use core::marker::PhantomData;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;

use libafl::events::EventFirer;
use libafl::executors::ExitKind;
use libafl::feedbacks::new_hash_feedback::HashSetState;
use libafl::feedbacks::Feedback;
use libafl::observers::ObserversTuple;
use libafl::state::State;
use libafl_bolts::{Error, ErrorBacktrace, Named};

use crate::fuzzer::feedback::claim_observer::ClaimObserver;
pub struct ClaimFeedback<S> {
    pub seen_claims: HashSet<String>,
    phantom: PhantomData<S>,
}

impl<S> ClaimFeedback<S>
where
    S: State,
{
    pub fn new() -> Self {
        Self {
            seen_claims: HashSet::new(),
            phantom: PhantomData,
        }
    }
}

impl<S> Named for ClaimFeedback<S>
where
    S: State,
{
    fn name(&self) -> &str {
        "ClaimFeedback"
    }
}

impl<S> Feedback<S> for ClaimFeedback<S>
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let claim_observer = observers
            .match_name::<ClaimObserver>("claim_observer")
            .ok_or_else(|| {
                Error::KeyNotFound("ClaimObserver not found".to_string(), ErrorBacktrace::new())
            })?;

        let mut discovered_new_claim = false;
        let mut new_keys_this_exec = Vec::new();

        for key in &claim_observer.claims {
            if !self.seen_claims.contains(key) {
                discovered_new_claim = true;
                self.seen_claims.insert(key.clone());
                new_keys_this_exec.push(key.clone());
            }
        }
        if discovered_new_claim {
            // ======= DEBUG LOCAL START =======
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open("FEEDBACK_EST_VIVANT.txt")
            {
                for unique_claim in new_keys_this_exec {
                    let msg = format!("Nouvelle claim : {}\n", unique_claim);
                    let _: std::io::Result<()> = f.write_all(msg.as_bytes());
                }
                let _ = f.flush();
            }
            // ======= DEBUG LOCAL END =========
            return Ok(true);
        }
        Ok(false)
    }
}
