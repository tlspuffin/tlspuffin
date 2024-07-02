use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum SshQueryMatcher {}

impl Matcher for SshQueryMatcher {
    fn matches(&self, _matcher: &Self) -> bool {
        true
    }

    fn specificity(&self) -> u32 {
        0
    }
}
