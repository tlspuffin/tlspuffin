use puffin::algebra::Matcher;
use serde::{Deserialize, Serialize};

/// [OpcuaQueryMatcher] contains OPC_UA-related typing information
/// This is currently a dummy implementation
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Hash, Eq, PartialEq)]
pub enum OpcuaQueryMatcher {
    Alert,
}

impl Matcher for OpcuaQueryMatcher {
    fn matches(&self, matcher: &OpcuaQueryMatcher) -> bool {
        match matcher {
            OpcuaQueryMatcher::Alert => matches!(self, OpcuaQueryMatcher::Alert),
        }
    }

    fn specificity(&self) -> u32 { 0 }
}