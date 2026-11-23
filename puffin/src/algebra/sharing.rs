//! Support for the sharing of [`Term`] nodes (see [`Term`] for the DAG structure of terms):
//! serialization which keeps the sharing and the cache which evaluates a shared node only once.
//!
//! # Serialization
//!
//! A node is *shared* when it is referenced from several places, which [`Rc::strong_count`] tells
//! without any bookkeeping. A [`Term`] is serialized as one of:
//! - `Def(node)`: a node which is not shared. It is not numbered, and never referenced.
//! - `Shared(node)`: the first time a shared node is met. It is numbered, in the order in which the
//!   `Shared` are completed (children before their parent).
//! - `Ref(id)`: the next occurrences of a shared node, `id` being its number.
//!
//! The deserialization reads the same sequence and rebuilds the same sharing. A node counted as
//! shared while it is only referenced once (a handle held elsewhere) is harmless: it is numbered
//! and never referenced.
//!
//! The numbering spans the whole serialization of a structure (a [`crate::trace::Trace`] for
//! instance), which serde does not provide: it is kept in a thread-local state owned by a
//! [`Session`]. Every `Term` opens one, so a `Term` serialized alone is a structure of its own; a
//! structure containing several terms opens one around its whole (de)serialization to also share
//! the nodes between its terms.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::term::{Term, TermNode};
use crate::algebra::term::TermDAG;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};

#[derive(Default)]
struct State {
    depth: usize,
    /// Serialization: the number of the shared nodes already written, by node address.
    ids: HashMap<usize, u32>,
    /// Deserialization: the shared nodes already read, by number.
    nodes: Vec<Rc<dyn Any>>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// While alive, the terms (de)serialized on this thread share one numbering of nodes. Sessions
/// nest: the outermost one owns the numbering.
#[must_use = "the session ends when the guard is dropped"]
pub struct Session(());

impl Session {
    pub fn enter() -> Self {
        STATE.with(|state| state.borrow_mut().depth += 1);
        Self(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.depth -= 1;
            if state.depth == 0 {
                *state = State::default();
            }
        });
    }
}

/// The encoding of a term, `N` being a [`TermNode`] or a reference to it.
#[derive(Serialize, Deserialize)]
#[serde(rename = "Term")]
enum TermRepr<N> {
    Def(N),
    Shared(N),
    Ref(u32),
}

impl<PT: ProtocolTypes> Serialize for Term<PT> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let _session = Session::enter();
        let node = &**self.node();

        if !self.is_shared() {
            return TermRepr::Def(node).serialize(serializer);
        }

        let key = self.node_id();
        if let Some(id) = STATE.with(|state| state.borrow().ids.get(&key).copied()) {
            return TermRepr::<&TermNode<PT>>::Ref(id).serialize(serializer);
        }

        // The sub-terms are serialized (and numbered) first: the deserialization numbers a node
        // once it is complete.
        let result = TermRepr::Shared(node).serialize(serializer)?;
        STATE.with(|state| {
            let ids = &mut state.borrow_mut().ids;
            let id = u32::try_from(ids.len()).expect("too many term nodes");
            ids.insert(key, id);
        });
        Ok(result)
    }
}

impl<'de, PT: ProtocolTypes> Deserialize<'de> for Term<PT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _session = Session::enter();

        match TermRepr::<TermNode<PT>>::deserialize(deserializer)? {
            TermRepr::Def(node) => Ok(Self::from(node)),
            TermRepr::Shared(node) => {
                let term = Self::from(node);
                let node: Rc<dyn Any> = term.node().clone();
                STATE.with(|state| state.borrow_mut().nodes.push(node));
                Ok(term)
            }
            TermRepr::Ref(id) => {
                let node = STATE
                    .with(|state| state.borrow().nodes.get(id as usize).cloned())
                    .ok_or_else(|| D::Error::custom(format!("unknown term node #{id}")))?;
                let node = node
                    .downcast::<TermNode<PT>>()
                    .map_err(|_| D::Error::custom(format!("term node #{id} has another type")))?;
                Ok(Self::from_rc(node))
            }
        }
    }
}

/// Cache of the values of the shared nodes evaluated during the execution of a trace, see
/// [`crate::trace::TraceContext`].
///
/// A node is *shared* when it is referenced more than once; only those are cached, as the others
/// are evaluated once anyway. Values are keyed by node, and the cache keeps its nodes alive so
/// that an address is never reused by another node (which would then get a stale value).
pub struct EvalCache<PT: ProtocolTypes> {
    values: HashMap<usize, (Rc<TermNode<PT>>, Box<dyn EvaluatedTerm<PT>>)>,
}

impl<PT: ProtocolTypes> std::fmt::Debug for EvalCache<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalCache")
            .field("values", &self.values.len())
            .finish()
    }
}

impl<PT: ProtocolTypes> Default for EvalCache<PT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PT: ProtocolTypes> EvalCache<PT> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub(crate) fn get(&self, term: &Term<PT>) -> Option<Box<dyn EvaluatedTerm<PT>>> {
        if !term.is_shared() {
            return None;
        }
        self.values
            .get(&term.node_id())
            .map(|(_, value)| value.boxed())
    }

    pub(crate) fn insert(&mut self, term: &Term<PT>, value: &dyn EvaluatedTerm<PT>) {
        if term.is_shared() {
            self.values
                .insert(term.node_id(), (term.node().clone(), value.boxed()));
        }
    }
}
