use core::fmt;

use serde::Serialize;

use crate::error::Error;
use crate::trace::Source;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub enum TraceDifference {
    Status(StatusDiff),
    Knowledges(KnowledgeDiff),
    Claims(ClaimDiff),
    SecurityClaim(SecurityClaimDiff),
}

impl TraceDifference {
    pub fn as_error(self) -> Error {
        Error::Difference(vec![self])
    }
}

impl fmt::Display for TraceDifference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceDifference::Status(diff) => writeln!(f, "Execution status difference\n{}", diff),
            TraceDifference::Knowledges(diff) => {
                writeln!(f, "Differences in knowledges: {}", diff)
            }
            TraceDifference::Claims(diff) => write!(f, "{diff}"),
            TraceDifference::SecurityClaim(diff) => write!(f, "{diff}"),
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StatusDiff {
    pub first_executed_steps: usize,
    pub first_status: String,
    pub second_executed_steps: usize,
    pub second_status: String,
    pub total_step: usize,
}

impl StatusDiff {
    pub fn as_trace_difference(self) -> TraceDifference {
        TraceDifference::Status(self)
    }
}

impl fmt::Display for StatusDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "\tfirst put : (step {}/{}) {}\n\tsecond put : (step {}/{}) {}",
            self.first_executed_steps,
            self.total_step,
            self.first_status,
            self.second_executed_steps,
            self.total_step,
            self.second_status
        )
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeDiff {
    DifferentTypes {
        index: usize,
        first_type: String,
        second_type: String,
        first_source: Source,
        second_source: Source,
    },
    InnerDifference {
        index: usize,
        type_name: String,
        diff: String,
        source: Source,
    },
}

impl fmt::Display for KnowledgeDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnowledgeDiff::DifferentTypes {
                index,
                first_type,
                second_type,
                first_source,
                second_source,
            } => writeln!(
                f,
                "knowledge[{}]: {} ({}) != {} ({})",
                index, first_type, first_source, second_type, second_source
            ),
            KnowledgeDiff::InnerDifference {
                index,
                type_name,
                diff,
                source,
            } => writeln!(
                f,
                "knowledge[{}] ({}, {}) : \n{}",
                index, type_name, source, diff
            ),
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaimDiff {
    DifferentTypes {
        agent: u8,
        index: usize,
        first_type: String,
        second_type: String,
    },
    InnerDifference {
        agent: u8,
        index: usize,
        diff: String,
    },
}

impl fmt::Display for ClaimDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimDiff::DifferentTypes {
                index,
                first_type,
                second_type,
                agent,
            } => {
                writeln!(
                    f,
                    "Claim [agent{agent},{}]: {} != {}",
                    index, first_type, second_type
                )
            }
            ClaimDiff::InnerDifference { index, diff, agent } => {
                writeln!(f, "Claim [agent{agent},{}]:\n{}", index, diff)
            }
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub enum SecurityClaimDiff {
    Different {
        put: u8,
        claim: String,
    },
    BothError {
        first_put: String,
        second_put: String,
    },
}

impl SecurityClaimDiff {
    pub fn as_trace_difference(self) -> TraceDifference {
        TraceDifference::SecurityClaim(self)
    }
}

impl fmt::Display for SecurityClaimDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityClaimDiff::Different { put, claim } => {
                writeln!(f, "Security Claim violation on PUT {} : \"{}\"", put, claim)
            }
            SecurityClaimDiff::BothError {
                first_put,
                second_put,
            } => writeln!(
                f,
                "Security Claim violation on both PUT : \"{}\" and \"{}\"",
                first_put, second_put
            ),
        }
    }
}
