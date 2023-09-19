use crate::algebra::{TermEval, TermType};
use crate::{
    algebra::{Matcher, Term},
    graphviz::write_graphviz,
    trace::{Action, Trace},
};

impl<M: Matcher> Trace<M> {
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        self.steps
            .iter()
            .map(|step| match &step.action {
                Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                Action::Output(_) => 0,
            })
            .sum()
    }

    pub fn count_functions(&self) -> usize {
        self.steps
            .iter()
            .flat_map(|step| match &step.action {
                Action::Input(input) => Some(&input.recipe),
                Action::Output(_) => None,
            })
            .map(|term| term.size())
            .sum()
    }

    pub fn write_plots(&self, i: u16) {
        write_graphviz(
            format!("test_mutation{}.svg", i).as_str(),
            "svg",
            self.dot_graph(true).as_str(),
        )
        .unwrap();
    }
}

impl<M: Matcher> TermEval<M> {
    pub fn count_functions_by_name(&self, find_name: &'static str) -> usize {
        let mut found = 0;
        for term in self.into_iter() {
            if let Term::Application(func, _) = &term.term {
                if func.name() == find_name {
                    found += 1;
                }
            }
        }
        found
    }
}
