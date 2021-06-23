//! This module provides[`Term`]sas well as iterators over them.

use std::fmt::Formatter;
use std::{any::Any, fmt};

use id_tree::{
    InsertBehavior, Node, NodeId, NodeIdError, PreOrderTraversal, PreOrderTraversalIds,
    RemoveBehavior, Tree,
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::term::dynamic_function::TypeShape;
use crate::tls::error::FnError;
use crate::trace::TraceContext;

use super::atoms::{Function, Variable};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Term {
    pub tree: TermTree,
}

pub type TermTree = Tree<Symbol>;
pub type TermNode = Node<Symbol>;
pub type TermId = NodeId;

impl Term {
    pub fn new(tree: TermTree) -> Self {
        Term { tree }
    }
}

/// A first-order term: either a [`Variable`] or an application of an [`Function`].
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Symbol {
    /// A concrete but unspecified `Term` (e.g. `x`, `y`).
    /// See [`Variable`] for more information.
    ///
    Variable(Variable),
    /// An [`Function`] applied to zero or more `Term`s (e.g. (`f(x, y)`, `g()`).
    ///
    /// A `Term` that is an application of an [`Function`] with arity 0 applied to 0 `Term`s can be considered a constant.
    ///
    Application(Function),
}

impl Symbol {
    pub fn symbol_shape(&self) -> &TypeShape {
        match self {
            Symbol::Variable(v) => &v.typ,
            Symbol::Application(function) => &function.shape().return_type,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Symbol::Variable(v) => v.typ.name,
            Symbol::Application(function) => function.name(),
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.tree.write_formatted(f)
    }
}

impl Term {
    pub fn length(&self) -> usize {
        if let Some(len) = self.tree.root_node_id() {
            if let Ok(it) = self.tree.traverse_pre_order(len) {
                return it.count();
            }
        }
        0
    }

    pub fn length_filtered<P: Fn(&&TermNode) -> bool + Copy>(&self, filter: P) -> usize {
        if let Some(len) = self.tree.root_node_id() {
            if let Ok(it) = self.tree.traverse_pre_order(len) {
                return it.filter(filter).count();
            }
        }
        0
    }

    pub fn is_empty(&self) -> bool {
        self.tree.height() == 0
    }

    pub fn term_height(&self) -> usize {
        self.tree.height()
    }

    pub fn evaluate(&self, context: &TraceContext) -> Result<Box<dyn Any>, Error> {
        let root = self.root_node()?;
        self.evaluate_subterm(root, context)
    }

    pub fn evaluate_subterm(
        &self,
        node: &TermNode,
        context: &TraceContext,
    ) -> Result<Box<dyn Any>, Error> {
        match &node.data() {
            Symbol::Variable(v) => context
                .get_variable_by_type_id(v.typ, v.observed_id)
                .map(|data| data.clone_box_any())
                .ok_or(Error::Term(format!("Unable to find variable {}!", v))),
            Symbol::Application(func) => {
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new();
                for subterm_id in node.children() {
                    let subterm = self.node_at(subterm_id)?;
                    match self.evaluate_subterm(subterm, context) {
                        Ok(data) => {
                            dynamic_args.push(data);
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                let dynamic_fn = func.dynamic_fn();
                let result: Result<Box<dyn Any>, FnError> = dynamic_fn(&dynamic_args);
                result.map_err(|err| Error::Fn(err))
            }
        }
    }

    pub fn root_node_id(&self) -> Result<&TermId, Error> {
        let root_id = self
            .tree
            .root_node_id()
            .ok_or_else(|| Error::Term("Failed to get root!".to_string()))?;
        Ok(root_id)
    }

    pub fn root_node(&self) -> Result<&TermNode, Error> {
        self.node_at(self.root_node_id()?)
    }

    pub fn node_at(&self, id: &TermId) -> Result<&TermNode, Error> {
        Ok(self.tree.get(id)?)
    }

    pub fn node_at_mut(&mut self, id: &TermId) -> Result<&mut TermNode, Error> {
        Ok(self.tree.get_mut(id)?)
    }

    /// `insert_at` must be part of `self`
    pub fn replace_subterm_at(
        &mut self,
        at: &TermId,
        replacement: &Term,
        replacement_at: &TermId,
    ) -> Result<(), Error> {
        Ok(replace_subtree_at(
            &mut self.tree,
            at,
            &replacement.tree,
            replacement_at,
        )?)
    }

    pub fn traverse_from_root(&self) -> Result<PreOrderTraversal<Symbol>, Error> {
        Ok(self.tree.traverse_pre_order(self.root_node_id()?)?)
    }

    pub fn traverse_ids_from_root(&self) -> Result<PreOrderTraversalIds<Symbol>, Error> {
        Ok(self.tree.traverse_pre_order_ids(self.root_node_id()?)?)
    }
}

/// `tlspuffin::term::op_impl::op_protocol_version` -> `op_protocol_version`
/// `alloc::Vec<rustls::msgs::handshake::ServerExtension>` -> `Vec<rustls::msgs::handshake::ServerExtension>`
pub(crate) fn remove_prefix(str: &str) -> String {
    let split: Option<(&str, &str)> = str.split_inclusive("<").collect_tuple();

    if let Some((non_generic, generic)) = split {
        if let Some(pos) = non_generic.rfind("::") {
            non_generic[pos + 2..].to_string() + generic
        } else {
            non_generic.to_string() + generic
        }
    } else if let Some(pos) = str.rfind("::") {
        str[pos + 2..].to_string()
    } else {
        str.to_string()
    }
}

pub(crate) fn replace_subtree_at_with_whole_tree<T: Clone>(
    tree: &mut Tree<T>,
    at: &TermId,
    replacement: &Tree<T>,
) -> Result<(), NodeIdError> {
    // check if tree is empty
    if let Some(root_id) = replacement.root_node_id() {
        replace_subtree_at(tree, at, replacement, root_id);
    }

    Ok(())
}

/// Replaces a subtree at `insert_at` with the complete tree `to_insert`.
///
/// `insert_at` must be part of `tree`
///
/// `subtree` is usually root if you want to place the whole `replacement`. You can also just place
/// a subtree there
pub(crate) fn replace_subtree_at<T: Clone>(
    tree: &mut Tree<T>,
    at: &TermId,
    replacement: &Tree<T>,
    replacement_at: &TermId,
) -> Result<(), NodeIdError> {
    // Remove root_at node and set at to the node to which we append
    let mut start_at: Option<TermId> = tree.get(at)?.parent().cloned();
    tree.remove_node(at.clone(), RemoveBehavior::DropChildren)?;
    start_at = start_at.or_else(|| tree.root_node_id().cloned());

    let mut stack = vec![(replacement_at, start_at)];

    recursive_insert(tree, &mut stack, replacement)?;

    Ok(())
}

pub(crate) fn insert_tree_at<T: Clone>(
    tree: &mut Tree<T>,
    insert_at: InsertBehavior,
    to_insert: &Tree<T>,
) -> Result<(), NodeIdError> {
    // check if tree is empty
    if let Some(node_id) = to_insert.root_node_id() {
        let mut stack = vec![(
            node_id,
            if let InsertBehavior::UnderNode(at) = insert_at {
                // Some(...) means we are inserting below a node
                Some(at.clone())
            } else {
                // None  means we are inserting at the root
                None
            },
        )];

        recursive_insert(tree, &mut stack, to_insert)?;
    }

    Ok(())
}

pub(crate) fn recursive_insert<'a, T: Clone>(
    tree: &mut Tree<T>,
    stack: &mut Vec<(&'a TermId, Option<TermId>)>,
    to_insert: &'a Tree<T>,
) -> Result<(), NodeIdError> {
    while let Some((node_id, at)) = stack.pop() {
        let node = to_insert
            .get(node_id)
            .expect("getting node of existing node ref id");

        let cloned_node = Node::new(node.data().clone());
        let new_at = if let Some(at) = at {
            // Insert below node
            tree.insert(cloned_node, InsertBehavior::UnderNode(&at))?
        } else {
            // Tree seems empty as we did not have a root to insert below
            tree.insert(cloned_node, InsertBehavior::AsRoot)?
        };

        let children = node.children().iter().rev();
        for child_id in children {
            stack.push((child_id, Some(new_at.clone())));
        }
    }
    Ok(())
}
