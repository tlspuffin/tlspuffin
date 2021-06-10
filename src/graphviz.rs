use std::{io, fmt};
use std::io::{BufWriter, ErrorKind, Write};
use std::process::{Command, Stdio};
use crate::trace::{Trace, Action};
use crate::term::{Term, remove_prefix};
use itertools::Itertools;

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
    let mut writer = BufWriter::new(&mut dot_stdin);
    writer.write(dot_script.as_bytes().as_ref())?;
    //child.kill().unwrap();
    //child.wait().expect("failed to execute dot");
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

impl Term {
    fn unique_id(&self, tree_mode: bool, cluster_id: usize) -> String {
        match self {
            Term::Variable(variable) => {
                if tree_mode {
                    format!("v_{}_{}", cluster_id, variable.unique_id)
                } else {
                    format!("v_{}", variable.resistant_id)
                }
            }
            Term::Application(func, _) => {
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
        term: &Term,
        tree_mode: bool,
        cluster_id: usize,
        statements: &mut Vec<String>,
    ) {
        match term {
            Term::Variable(variable) => {
                statements.push(format!(
                    "{} {};",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(variable, 1, "oval")
                ));
            }
            Term::Application(func, subterms) => {
                statements.push(format!(
                    "{} {};",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(
                        remove_prefix(func.name()),
                        if func.arity() == 0 { 1 } else { 2 },
                        "box"
                    )
                ));

                for subterm in subterms {
                    statements.push(format!(
                        "{} -> {};",
                        term.unique_id(tree_mode, cluster_id),
                        subterm.unique_id(tree_mode, cluster_id)
                    ));
                    Self::collect_statements(subterm, tree_mode, cluster_id, statements);
                }
            }
        }
    }

    /// If `tree_mode` is true then each subgraph is self-contained and does not reference other
    /// clusters or nodes outside of this subgraph. Therefore, only trees are generated. If it is
    /// false, then graphs are rendered.
    pub fn dot_subgraph(&self, tree_mode: bool, cluster_id: usize, label: &str) -> String {
        let mut statements = Vec::new();
        Self::collect_statements(self, tree_mode, cluster_id, &mut statements);
        format!(
            "subgraph cluster{} {{ label=\"{}\" \n{}\n}}",
            cluster_id,
            label,
            statements.iter().join("\n")
        )
    }
}