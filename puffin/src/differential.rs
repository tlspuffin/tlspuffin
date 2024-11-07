use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceDifference {
    Status(String, String),
    Knowledges(Vec<(String, String)>),
    Claims(Vec<String>),
}

impl fmt::Display for TraceDifference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceDifference::Status(a, b) => writeln!(
                f,
                "Execution status difference\n\tfirst put : {}\n\tsecond put: {}}}",
                a, b
            ),
            TraceDifference::Knowledges(diffs) => {
                writeln!(f, "Differences in knowledges:")?;
                for diff in diffs {
                    writeln!(f, "\tfirst put : {}, second put {}", diff.0, diff.1)?;
                }
                Ok(())
            }
            TraceDifference::Claims(_) => write!(f, ""),
        }
    }
}
