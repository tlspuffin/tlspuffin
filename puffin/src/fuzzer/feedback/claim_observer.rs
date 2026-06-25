use std::any::Any;
use std::borrow::Cow;
use std::cell::RefCell;

use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

thread_local! {
    pub static CAPTURED_CLAIMS: RefCell<Option<Box<dyn Any>>> = RefCell::new(None);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClaimObserver {
    name: Cow<'static, str>,
    pub claims: Vec<String>,
}

impl ClaimObserver {
    /// Creates a new [`ClaimObserver`] with the given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            claims: Vec::new(),
        }
    }
}
impl<I, S> Observer<I, S> for ClaimObserver {
    fn post_exec(&mut self, state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
        let _ = state;
        CAPTURED_CLAIMS.with(|captured_cell| {
            if let Some(captured) = captured_cell.borrow().as_ref() {
                if let Some(keys) = captured.downcast_ref::<Vec<String>>() {
                    self.claims = keys.clone();
                }
            }
        });
        Ok(())
    }
}
impl Named for ClaimObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
