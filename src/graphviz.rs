//! This module adds plotting capabilities to[`Term`]sand Traces. The output of the functions in
//! this module can be passed to the command line utility `dot` which is part of graphviz.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};
use std::{fmt, io};

use itertools::Itertools;

use crate::term::{remove_prefix, Symbol, Term, TermIndex};
use crate::trace::{Action, Trace};

pub fn write_graphviz(output: &str, format: &str, dot_script: &str) -> Result<(), io::Error> {
    let mut child = Command::new("dot")
        .args(&["-o", output, "-T", format])
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn dot");

    let mut dot_stdin = child
        .stdin
        .take()
        .ok_or(io::Error::new(ErrorKind::Other, "Failed to open stdin"))?;
    dot_stdin.write_all(dot_script.as_bytes().as_ref())?;
    drop(dot_stdin);
    child.wait().expect("failed to execute dot");
    Ok(())
}

impl Trace {
    pub fn dot_graph(&self, tree_mode: bool) -> String {
        format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            self.dot_subgraphs(tree_mode).join("\n")
        )
    }

    pub fn dot_subgraphs(&self, tree_mode: bool) -> Vec<String> {
        let mut subgraphs = Vec::new();

        for (i, step) in self.steps.iter().enumerate() {
            let subgraph_name = format!("Step #{} (Agent  {})", i, step.agent);

            let subgraph = match &step.action {
                Action::Input(input) => {
                    format!(
                        "{}",
                        input
                            .recipe
                            .dot_subgraph(tree_mode, i, subgraph_name.as_str())
                    )
                }
                Action::Output(output) => format!(
                    "subgraph cluster{} {{ label=\"{} - ({},)\" \"\" [color=\"#00000000\"]; }}",
                    i,
                    subgraph_name.as_str(),
                    output.id
                ),
            };

            subgraphs.push(subgraph);
        }

        subgraphs
    }
}

impl TermIndex {
    fn unique_id(&self, term: &Term, tree_mode: bool, cluster_id: usize) -> String {
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(variable) => {
                if tree_mode {
                    format!("v_{}_{}", cluster_id, variable.unique_id)
                } else {
                    format!("v_{}", variable.resistant_id)
                }
            }
            Symbol::Application(func) => {
                if tree_mode {
                    format!("f_{}_{}", cluster_id, func.unique_id)
                } else {
                    format!("f_{}", func.resistant_id)
                }
            }
        }
    }

    fn node_attributes(displayable: impl fmt::Display, color: u8, shape: &str) -> String {
        format!(
            "[label=\"{}\",style=filled,colorscheme=dark28,fillcolor={},shape={}]",
            displayable, color, shape
        )
    }

    fn collect_statements(
        &self,
        term: &Term,
        tree_mode: bool,
        cluster_id: usize,
        statements: &mut Vec<String>,
    ) {
        match term.symbols.get(self.id).unwrap() {
            Symbol::Variable(variable) => {
                statements.push(format!(
                    "{} {};",
                    self.unique_id(term, tree_mode, cluster_id),
                    Self::node_attributes(variable, 1, "oval")
                ));
            }
            Symbol::Application(func) => {
                statements.push(format!(
                    "{} {};",
                    self.unique_id(term, tree_mode, cluster_id),
                    Self::node_attributes(
                        remove_prefix(func.name()),
                        if func.arity() == 0 { 1 } else { 2 },
                        "box"
                    )
                ));

                for subterm in &self.subterms {
                    statements.push(format!(
                        "{} -> {};",
                        self.unique_id(term, tree_mode, cluster_id),
                        subterm.unique_id(term, tree_mode, cluster_id)
                    ));
                    subterm.collect_statements(term, tree_mode, cluster_id, statements);
                }
            }
        }
    }

    /// If `tree_mode` is true then each subgraph is self-contained and does not reference other
    /// clusters or nodes outside of this subgraph. Therefore, only trees are generated. If it is
    /// false, then graphs are rendered.
    pub fn dot_subgraph(&self, term: &Term, tree_mode: bool, cluster_id: usize, label: &str) -> String {
        let mut statements = Vec::new();
        self.collect_statements(term, tree_mode, cluster_id, &mut statements);
        format!(
            "subgraph cluster{} {{ label=\"{}\" \n{}\n}}",
            cluster_id,
            label,
            statements.iter().join("\n")
        )
    }
}

impl Term {
    pub fn dot_subgraph(&self, tree_mode: bool, cluster_id: usize, label: &str) -> String {
        self.index.as_ref().unwrap().dot_subgraph(self, tree_mode, cluster_id, label)
    }
}

#[cfg(test)]
mod tests {
    use crate::agent::AgentName;
    use crate::fuzzer::seeds::seed_client_attacker12;

    #[test]
    fn test_dot_graph() {
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_client_attacker12(client, server);
        println!("{}", trace.dot_graph(true));
    }
}
