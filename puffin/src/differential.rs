use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceDifference {
    Status(String, String),
    Knowledges(String),
    Claims(String),
}

impl fmt::Display for TraceDifference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceDifference::Status(a, b) => writeln!(
                f,
                "Execution status difference\n\tfirst put : {}\n\tsecond put: {}",
                a, b
            ),
            TraceDifference::Knowledges(diff) => {
                writeln!(f, "Differences in knowledges: {}", diff)
            }
            TraceDifference::Claims(_) => write!(f, ""),
        }
    }
}
