use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};

use itertools::Itertools;
use libafl::bolts::tuples::{Named};
use libafl::events::Event::UpdateUserStats;
use libafl::events::{EventFirer};
use libafl::inputs::Input;
use libafl::observers::{Observer};
use libafl::state::State;
use libafl::stats::UserStats;
use libafl::{executors::HasExecHooks, Error};
use serde::{Deserialize, Serialize};

// Fn(FnError),
pub static FN_ERROR: AtomicUsize = AtomicUsize::new(0);
// Term(String),
pub static TERM: AtomicUsize = AtomicUsize::new(0);
// OpenSSL(ErrorStack),
pub static OPENSSL: AtomicUsize = AtomicUsize::new(0);
// IO(String),
pub static IO: AtomicUsize = AtomicUsize::new(0);
// Agent(String),
pub static AGENT: AtomicUsize = AtomicUsize::new(0);
// Stream(String),
pub static STREAM: AtomicUsize = AtomicUsize::new(0);
// Extraction(ContentType),
pub static EXTRACTION: AtomicUsize = AtomicUsize::new(0);

pub fn increment(counter: &AtomicUsize) {
    counter.fetch_add(1, Ordering::SeqCst);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorObserver {
    name: String,
    last_runtime: Option<Duration>,
}

impl ErrorObserver {
    /// Creates a new [`ErrorObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            last_runtime: None,
        }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn last_runtime(&self) -> &Option<Duration> {
        &self.last_runtime
    }
}

impl Observer for ErrorObserver {}

impl<EM, I, S, Z> HasExecHooks<EM, I, S, Z> for ErrorObserver
where
    EM: EventFirer<I, S>,
    I: Input,
    S: State,
{
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        let reporters = [
            (&FN_ERROR, "fn"),
            (&TERM, "term"),
            (&OPENSSL, "ssl"),
            (&IO, "io"),
            (&AGENT, "agent"),
            (&STREAM, "stream"),
            (&EXTRACTION, "extr"),
        ];

        let stats = reporters
            .iter()
            .map(|(counter, name)| format!("{}:{}", name, counter.load(Ordering::SeqCst)))
            .join("|");

        _mgr.fire(
            _state,
            UpdateUserStats {
                name: "errors".to_string(),
                value: UserStats::String(stats),
                phantom: Default::default(),
            },
        )?;

        Ok(())
    }
}

impl Named for ErrorObserver {
    fn name(&self) -> &str {
        &self.name
    }
}
