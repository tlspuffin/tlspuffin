use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceDifference {
    Status(StatusDiff),
    Knowledges(KnowledgeDiff),
    Claims(ClaimDiff),
}

impl fmt::Display for TraceDifference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceDifference::Status(diff) => writeln!(f, "Execution status difference\n{}", diff),
            TraceDifference::Knowledges(diff) => {
                writeln!(f, "Differences in knowledges: {}", diff)
            }
            TraceDifference::Claims(diff) => write!(f, "{diff}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDiff {
    pub first_executed_steps: usize,
    pub first_status: String,
    pub second_executed_steps: usize,
    pub second_status: String,
    pub total_step: usize,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeDiff {
    DifferentTypes {
        index: usize,
        first_type: String,
        second_type: String,
    },
    InnerDifference {
        index: usize,
        type_name: String,
        diff: String,
    },
}

impl fmt::Display for KnowledgeDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnowledgeDiff::DifferentTypes {
                index,
                first_type,
                second_type,
            } => writeln!(f, "knowledge[{}]: {} != {}", index, first_type, second_type),
            KnowledgeDiff::InnerDifference {
                index,
                type_name,
                diff,
            } => writeln!(f, "knowledge[{}] ({}) : \n{}", index, type_name, diff),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
