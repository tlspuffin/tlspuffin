use std::borrow::Cow;
use std::cell::RefCell;

use libafl::executors::ExitKind;
use libafl::observers::Observer;
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

thread_local! {
    pub static CAPTURED_TERMS: RefCell<Option<Vec<String>>> = RefCell::new(None);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TermObserver {
    name: Cow<'static, str>,
    /// Collection of all trace or message terms identified throughout the execution cycle
    pub discovered_terms: Vec<String>,
    pub terms_with_depths: Vec<(String, usize)>,
    /// Maximum structural nesting depth tracked across all parsed terms during a single loop.
    pub max_depth: usize,
}

impl TermObserver {
    /// Creates a new [`TermObserver`] with the given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            discovered_terms: Vec::new(),
            terms_with_depths: Vec::new(),
            max_depth: 0,
        }
    }

    fn extract_term_context(term: &str) -> String {
        term.split('(')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string()
    }

    fn compute_depth(term: &str) -> usize {
        let mut max_d = 0;
        let mut current_d = 0;

        for c in term.chars() {
            if c == '(' {
                current_d += 1;
                if current_d > max_d {
                    max_d = current_d;
                }
            } else if c == ')' {
                if current_d > 0 {
                    current_d -= 1;
                }
            }
        }
        max_d
    }
}

impl<I, S> Observer<I, S> for TermObserver {
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.discovered_terms.clear();
        self.terms_with_depths.clear();

        // Recover latest traces from the harness instrumentation memory slot
        CAPTURED_TERMS.with(|captured_cell| {
            if let Some(terms) = captured_cell.borrow().as_ref() {
                self.discovered_terms = terms.clone();
            }
        });
        // Parse terms to record the global maximum complexity depth achieved in this run
        let mut global_max_depth = 0;
        for term in &self.discovered_terms {
            let depth = Self::compute_depth(term);
            if depth > global_max_depth {
                global_max_depth = depth;
            }
            let context = Self::extract_term_context(term);
            self.terms_with_depths.push((context, depth));
        }
        self.max_depth = global_max_depth;
        Ok(())
    }
}

impl Named for TermObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
