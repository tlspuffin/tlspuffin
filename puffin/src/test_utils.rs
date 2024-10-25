use crate::algebra::{DYTerm, Term};
use crate::execution::{ExecutionStatus, ForkError};
use crate::graphviz::write_graphviz;
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Trace};

impl<PT: ProtocolTypes> Trace<PT> {
    #[must_use]
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        self.steps
            .iter()
            .map(|step| match &step.action {
                Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                Action::Output(_) => 0,
            })
            .sum()
    }

    #[must_use]
    pub fn count_functions(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .map(super::algebra::term::TermType::size)
            .sum()
    }

    pub fn write_plots(&self, i: u16) {
        write_graphviz(
            format!("test_mutation{i}.svg").as_str(),
            "svg",
            self.dot_graph(true).as_str(),
        )
        .unwrap();
    }
}

impl<PT: ProtocolTypes> Term<PT> {
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        let mut found = 0;
        for term in self {
            if let DYTerm::Application(func, _) = &term.term {
                if func.name() == find_name {
                    found += 1;
                }
            }
        }
        found
    }
}

pub trait AssertExecution {
    fn expect_crash(self);
}

impl AssertExecution for Result<ExecutionStatus, ForkError> {
    fn expect_crash(self) {
        use ExecutionStatus as S;
        match self {
            Ok(S::Crashed) => (),
            Ok(S::Failure(_)) => panic!("invalid trace"),
            Ok(S::Timeout) => panic!("trace execution timed out"),
            Ok(S::Interrupted) => panic!("trace execution interrupted"),
            Ok(S::Success) => panic!("expected trace execution to crash, but succeeded"),
            Err(reason) => panic!("trace execution error: {reason}"),
        }
    }
}
