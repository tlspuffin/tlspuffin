//! This module adds plotting capabilities to[`DYTerm`]sand Traces. The output of the functions in
//! this module can be passed to the command line utility `dot` which is part of graphviz.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};
use std::{fmt, io};

use itertools::Itertools;

use crate::algebra::{remove_fn_prefix, remove_prefix, DYTerm, Term, TermType};
use crate::protocol::ProtocolTypes;
use crate::trace::{Action, Trace};

// Colorful theme
/*const FONT: &'static str = "Latin Modern Roman";
const SHAPE: &'static str = "box";
const SHAPE_LEAVES: &'static str = "oval";
const STYLE: &'static str = "filled";
const COLOR: &'static str = "2";
const COLOR_LEAVES: &'static str = "1";
const SHOW_LABELS: bool = false */

// Thesis theme
const FONT: &str = "Latin Modern Roman";
const SHAPE: &str = "none";
const SHAPE_PAYLOAD: &str = "box";
const SHAPE_LEAVES: &str = "none";
const SHAPE_LEAVES_PAYLOAD: &str = "parallelogram";

const STYLE: &str = "";
const COLOR: &str = "#ffff0000";
const COLOR_LEAVES: &str = "#00000000";
const COLOR_LEAVES_PAYLOAD: &str = "#ff00ff";
const COLOR_PAYLOAD: &str = "#ff0000";
const SHOW_LABELS: bool = false;

pub fn write_graphviz(output: &str, format: &str, dot_script: &str) -> Result<(), io::Error> {
    let mut child = Command::new("dot")
        .args(["-o", output, "-T", format])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == ErrorKind::NotFound {
                io::Error::new(
                    ErrorKind::NotFound,
                    "Unable to find dot in PATH. Install graphviz.",
                )
            } else {
                err
            }
        })?;

    let mut dot_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Failed to open stdin"))?;
    dot_stdin.write_all(dot_script.as_bytes().as_ref())?;
    drop(dot_stdin);
    child.wait()?;
    Ok(())
}

impl<PT: ProtocolTypes> Trace<PT> {
    #[must_use]
    pub fn dot_graph(&self, tree_mode: bool) -> String {
        format!(
            "strict digraph \"Trace\" \
            {{ \
                splines=false;\
                fontname=\"{}\";\
                {} \
            }}",
            FONT,
            self.dot_subgraphs(tree_mode).join("\n")
        )
    }

    #[must_use]
    pub fn dot_subgraphs(&self, tree_mode: bool) -> Vec<String> {
        log::warn!("Calling dot_subgraphs on: {}", self);
        let mut subgraphs = Vec::new();

        for (i, step) in self.steps.iter().enumerate() {
            let subgraph_name = format!("Step #{} (Agent  {})", i, step.agent);

            let subgraph = match &step.action {
                Action::Input(input) => input
                    .recipe
                    .dot_subgraph(tree_mode, i, subgraph_name.as_str())
                    .to_string(), // TODO-bitlevel: if not .is_symbolic(), display "bitstring"
                Action::Output(_) => format!(
                    "subgraph cluster{} \
                    {{ \
                        peripheries=0;\
                        label=\"{label}\";\
                        \"\" [color=\"#00000000\"];\
                    }}",
                    i,
                    label = (if SHOW_LABELS {
                        subgraph_name.as_str()
                    } else {
                        ""
                    }),
                ),
            };

            subgraphs.push(subgraph);
        }

        subgraphs
    }
}

impl<PT: ProtocolTypes> Term<PT> {
    fn unique_id(&self, tree_mode: bool, cluster_id: usize) -> String {
        match &self.term {
            DYTerm::Variable(variable) => {
                if tree_mode {
                    format!("v_{}_{}", cluster_id, variable.unique_id)
                } else {
                    format!("v_{}", variable.resistant_id)
                }
            }
            DYTerm::Application(func, _) => {
                if tree_mode {
                    format!("f_{}_{}", cluster_id, func.unique_id)
                } else {
                    format!("f_{}", func.resistant_id)
                }
            }
        }
    }

    fn node_attributes(displayable: impl fmt::Display, color: &str, shape: &str) -> String {
        format!(
            "[label=\"{displayable}\",style=\"{STYLE}\",colorscheme=dark28,fillcolor=\"{color}\",shape=\"{shape}\"]"
        )
    }

    fn collect_statements(
        term: &Self,
        tree_mode: bool,
        cluster_id: usize,
        statements: &mut Vec<String>,
    ) {
        if !term.is_symbolic() {
            log::debug!("WITH PAYLOADS: {:?} on term {}", term.all_payloads(), term);
        }
        match &term.term {
            DYTerm::Variable(variable) => {
                let color = if term.is_symbolic() {
                    COLOR_LEAVES
                } else {
                    COLOR_LEAVES_PAYLOAD
                };
                let shape = if term.is_symbolic() {
                    SHAPE_LEAVES
                } else {
                    SHAPE_LEAVES_PAYLOAD
                };
                statements.push(format!(
                    "{} {} [fontname=\"{}\"];",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(variable, color, shape),
                    FONT
                ));
            }
            DYTerm::Application(func, subterms) => {
                let color = if term.is_symbolic() {
                    if func.arity() == 0 {
                        COLOR_LEAVES
                    } else {
                        COLOR
                    }
                } else {
                    COLOR_PAYLOAD
                };
                let shape = if term.is_symbolic() {
                    if func.arity() == 0 {
                        SHAPE_LEAVES
                    } else {
                        SHAPE
                    }
                } else {
                    SHAPE_PAYLOAD
                };
                statements.push(format!(
                    "{} {} [fontname=\"{}\"];",
                    term.unique_id(tree_mode, cluster_id),
                    Self::node_attributes(
                        if term.is_symbolic() {
                            remove_fn_prefix(&remove_prefix(func.name()))
                        } else {
                            if term.is_readable() {
                                format!("BS-RD//{}", remove_fn_prefix(&remove_prefix(func.name())))
                            } else {
                                format!("BS//{}", remove_prefix(func.name()))
                            }
                        },
                        color,
                        shape,
                    ),
                    FONT
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
            "subgraph cluster{} \
            {{ \
               	peripheries=0;\
                fontname=\"{font}\";\
                label=\"{label}\";\
                \n{}\n\
            }}",
            cluster_id,
            statements.iter().join("\n"),
            label = (if SHOW_LABELS { label } else { "" }),
            font = FONT,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::algebra::test_signature::setup_simple_trace;

    #[test_log::test]
    fn test_dot_graph() {
        let trace = setup_simple_trace();
        let _string = trace.dot_graph(true);
        //println!("{}", string);
    }
}
