use std::fmt::Display;

use libafl::inputs::{BytesInput, HasBytesVec};
use serde::{Deserialize, Serialize};

use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::{ConcreteMessage, DYTerm, Term, TermType};
use crate::error::Error;
use crate::error::Error::TermBug;
use crate::fuzzer::utils::TermPath;
use crate::protocol::{EvaluatedTerm, ProtocolBehavior, ProtocolTypes};
use crate::trace::{Source, TraceContext};

/// Constants governing heuristic for finding payloads in term evaluations
const THRESHOLD_SIZE: usize = 3; // minimum size of a payload to be directly searched in root_eval
const THRESHOLD_RATIO: usize = 100; // maximum ratio for root_eval/too_search for a direct search

/// `TermMetadata` stores some metadata about terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayloadMetadata {
    pub(crate) readable: bool, // true when the payload is readable and whole term should be read
    pub(crate) has_changed: bool, // true when the payload has been modified at least once
}

impl Default for PayloadMetadata {
    fn default() -> Self {
        Self {
            readable: false,
            has_changed: false,
        }
    }
}

/// `Term`s are `Term`s equipped with optional `Payloads` when they no longer are treated as
/// symbolic terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payloads {
    pub payload_0: BytesInput, // initially both are equal and correspond to the term evaluation
    pub payload: BytesInput,   // this one will later be subject to bit-level mutation
    pub(crate) metadata: PayloadMetadata, // stores metadata
}

impl Payloads {
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload_0.bytes().len()
    }

    #[must_use]
    pub fn has_changed(&self) -> bool {
        self.metadata.has_changed
    }

    pub fn set_changed(&mut self) {
        self.metadata.has_changed = true
    }
}

impl Display for Payloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n    payload_0: {:?}\n    payload:   {:?}\n}}",
            self.payload_0.bytes(),
            self.payload.bytes()
        )
    }
}
/// Payload with the context related to the term it originates from
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayloadContext<'a, PT: ProtocolTypes> {
    // not used if no payload to replace
    of_term: &'a Term<PT>,  // point to the corresponding term
    payloads: &'a Payloads, // point to the corresponding term.payload
    path: TermPath,         // path of the sub-term from which this payload originates
}

impl<'a, PT: ProtocolTypes> Display for PayloadContext<'a, PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\n{{ of_term:\n{}\n, payloads: {}, path: {:?}\n}}",
            self.of_term, self.payloads, self.path
        )
    }
}

/// A tree of evaluated term, linked to the term structure itself. Created while evaluating a term.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EvalTree {
    // not used (only the root) if no payload to replace
    encode: Option<ConcreteMessage>, // encoding, if it was necessary and could be computed
    path: TermPath,                  // path of the sub-term from which this payload originates
    args: Vec<EvalTree>,             // tree structure
}
impl EvalTree {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            encode: None, /* will contain the bitstring encoding when sub-terms have payloads and
                           * when evaluation succeeds */
            path: TermPath::new(),
            args: vec![], /* will be modified while evaluating `term` if there are payloads to
                           * replace in this sub-tree */
        }
    }

    #[must_use]
    pub fn with_path(path: TermPath) -> Self {
        let mut e_t = Self::empty();
        e_t.path = path;
        e_t
    }

    #[allow(dead_code)]
    fn get(&self, path: &[usize]) -> Result<&Self, Error> {
        if path.is_empty() {
            return Ok(self);
        }

        let nb = path[0];
        let path = &path[1..];
        if self.args.len() <= nb {
            return Err(Error::TermBug(format!(
                "[replace_payloads] [get] Should never happen! self.args.len() <= nb. EvalTree: {self:?}\n, path: {path:?}"
            )));
        }
        self.args[nb].get(path)
    }
}

/// Search and locate `to_search := eval_tree[path_to_search].encode` in
/// `root_eval:=eval_tree`[vec![]].encode (=`whole_term.encode(ctx)`) such that the match
/// corresponds to `path_to_search` (when `to_search` occurs multiple times). Also returns
/// a boolean flag envcountered_get_symbol indicating whether a get symbol is between the root and
/// the path_to_search, in which case, inconsistencies might occur.
pub fn find_unique_match<PT: ProtocolTypes>(
    path_to_search: &[usize],
    eval_tree: &EvalTree,
    whole_term: &Term<PT>,
    is_to_search_in_list: bool,
) -> Result<(usize, bool), Error> {
    Ok(find_unique_match_rec(
        path_to_search,
        eval_tree,
        whole_term,
        is_to_search_in_list,
    )?)
}

/// Goal: locate byte position of `to_search := eval_tree[path_to_search].encode` in
/// `root_eval:=eval_tree`[vec![]].encode (=`whole_term.encode(ctx)`) by traversing `eval_tree`
/// until reaching node at `pat_to_search`. Assumptions:
/// - encoded arguments of a term can be found in this same order in the evaluation of the father
///   node
/// - there can be headers of arbitrary length
/// - no trailer (no bytes added after the last argument encoding)
///  Also returns a boolean flag envcountered_get_symbol indicating whether a get symbol is between
/// he root and the path_to_search, in which case, inconsistencies might occur.
pub fn find_unique_match_rec<PT: ProtocolTypes>(
    path_to_search: &[usize],
    eval_tree: &EvalTree,
    whole_term: &Term<PT>,
    is_to_search_in_list: bool,
) -> Result<(usize, bool), Error> {
    log::debug!("[find_unique_match_rec] --- [STARTING] with {path_to_search:?}");
    log::trace!("[find_unique_match_rec] --- [STARTING] with {path_to_search:?},\n - eval_tree: {eval_tree:?},\n - to_search: {:?}", eval_tree.get(path_to_search)?.encode.as_ref().unwrap());
    // We traverse the eval_tree and update the followings until we reach the node at
    // `path_to_search`
    let mut path_to_search = path_to_search;
    let mut eval_tree = eval_tree;
    let mut term = whole_term;
    let mut start_pos = 0; // Current byte position of `term` in the original root term (encoded evaluations thereof)
    let eval_to_search = eval_tree
        .get(path_to_search)?
        .encode
        .as_ref()
        .expect("[find_unique_match_rec] path_to_search should exist in eval_tree");
    let mut encountered_get_symbol = false;

    // For later debugging
    #[cfg(any(debug_assertions, feature = "debug"))]
    let eval_root_orig: Vec<u8>;
    #[cfg(any(debug_assertions, feature = "debug"))]
    let eval_to_search_orig: Vec<u8>;
    #[cfg(any(debug_assertions, feature = "debug"))]
    {
        eval_root_orig = eval_tree.encode.as_ref().unwrap().clone();
        eval_to_search_orig = eval_to_search.clone();
    }

    // [WHILE LOOP TRAVERSAL] We traverse eval_tree towards reaching the node at path_to_search
    while !path_to_search.is_empty() {
        // Getting child information
        let parent_tp = term.get_type_shape();
        let parent_is_get = term.is_get();
        let parent_is_list = term.is_list();
        encountered_get_symbol = parent_is_get || encountered_get_symbol;
        let nb_children = eval_tree.args.len();
        let child_arg_number = path_to_search[0];
        log::debug!("[find_unique_match_rec] while step: {path_to_search:?}, nb_children: {nb_children}, child_arg: {child_arg_number}");
        let eval_parent = eval_tree
            .encode
            .as_ref()
            .expect("[find_unique_match_rec] EvalTree should have been computed");
        let children = &eval_tree.args;

        // Updating the term, eval_tree, path_to_search to the child
        eval_tree = eval_tree.get(&[child_arg_number])?; // we move to the next child for the future while iteration
        let eval_child = eval_tree
            .encode
            .as_ref()
            .expect("[find_unique_match_rec] EvalTree should have been computed");
        log::trace!("[find_unique_match_rec] --- [Rec call] with path_to_search (from parent):{path_to_search:?}, start_pos: {start_pos},\n - term_parent: {term}\n - eval_parent: {eval_parent:?}\n - eval_child: {eval_child:?}\n - eval_to_search: {eval_to_search:?}");
        path_to_search = &path_to_search[1..];
        term = term
            .get(&[child_arg_number])
            .expect("[find_unique_match_rec] term does not match eval_tree");

        // [STEP 1: DIRECT SEARCH] Directly search for eval_too_search in root_eval
        // We apply this fast heuristics if the likelyhood of a unique match seems high enough
        if eval_to_search.len() > 0
            && (eval_to_search.len() > THRESHOLD_SIZE
                || eval_parent.len() / eval_to_search.len() < THRESHOLD_RATIO)
        {
            if let Some(unique_pos) = first_sub_vec_unique(eval_parent, eval_to_search) {
                log::debug!(
                    "[find_unique_match_rec] [S1] Directly found unique match in root: {unique_pos}"
                );
                start_pos = start_pos + unique_pos;
                break;
            } else {
                log::debug!("[find_unique_match_rec] [S1] Direct found is not unique!");
            }
        }

        // [STEP 2: SEARCH CHILD IN PARENT] Searching for the child encoding in the parent
        // [2:1] [CASE EMPTY] Child encoding is empty, we will position relatively to the siblings
        // This assumes no trailer and no intermediate header (i.e., not present of the children
        // encodings.
        if eval_child.is_empty() {
            let mut eval_right_siblings = Vec::new();
            for right_sibling in (child_arg_number + 1)..nb_children {
                eval_right_siblings.extend_from_slice(
                    children[right_sibling].encode.as_ref().expect(
                        "[find_unique_match_rec] [S2:1] EvalTree should have been computed",
                    ),
                );
            }
            let pos_child = eval_parent.len() - eval_right_siblings.len();
            log::debug!("[S2:1] eval_child has an empty encoding, we use right siblings to position the child: pos = {pos_child}");

            start_pos += pos_child;
            continue;
        }

        // [2:special-list] If the parent and the target is a list symbol, we use a dedicated
        // heuristic to avoid paying the cost of searching the right position of the target in the
        // list. This could be extremely costly when the list is long, e.g., same element is
        // repeated many times. We assume there is no nested list of same type: that is if to_search
        // and parents are in a list of the same type, it should be the same list.
        if parent_is_list && is_to_search_in_list {
            if child_arg_number == 0 && path_to_search.iter().all(|x| *x == 0) {
                log::debug!("[find_unique_match_rec] [S2:special-list] [Nil*] Child is the NIL starting the list, pos is 0!");
                break;
            }
            log::debug!("[S2:special-list] Child is a list, we use a special heuristic to find the position of the target in the parent");
            if path_to_search.is_empty() {
                // Based on last two conditions: we know child_arg_number == 1
                #[cfg(any(debug_assertions, feature = "debug"))]
                {
                    assert_eq!(child_arg_number, 1);
                }
                // We know the target is the last element of the parent list
                let pos = eval_parent.len() - eval_to_search.len();
                log::debug!(
                    "[find_unique_match_rec] [S2:special-list] [pos=1] Found position: {pos}"
                );
                start_pos = start_pos + pos;
                break;
            }

            // Else: path_to_search is not empty
            // Since MakeMessage cannot be applied to is_list symbols, we know the target is a
            // "leaf" (single element stored in the list). Therefore, we can locate the position
            // of the target by computing the length of the parent of the target: we know this is
            // located at the beginning of the parent encoding and we know the target is at the end
            // of this encoding. This works because list elements are neither prefxed nor suffixed
            // with neither headers nor trailers.
            let eval_parent_to_search = eval_tree
                .get(&path_to_search[..path_to_search.len() - 1])?
                .encode
                .as_ref()
                .expect(
                    "[find_unique_match_rec] path_to_search[0..len-1] should exist in eval_tree",
                );
            let parent_to_search_tp = term
                .get(&path_to_search[..path_to_search.len() - 1])
                .expect("[find_unique_match_rec] path_to_search[0..len-1] should exist in term")
                .get_type_shape();
            if parent_tp != parent_to_search_tp {
                log::error!(
                    "[S2:special-list] [S2:1] Parent and target are not the same type, we cannot use the special heuristic. Continue..."
                );
            } else {
                log::debug!(
                    "[S2:special-list] Searching encoding of parent of target (at {:?}) in parent... AWE: \n  - eval_parent_to_search:{eval_parent_to_search:?}\n -eval_to_search: {eval_to_search:?}",
                    path_to_search[0..path_to_search.len() - 1].to_vec()
                );
                let pos = eval_parent_to_search.len() - eval_to_search.len();
                log::debug!(
                    "[find_unique_match_rec] [S2:special-list] [skip] Found position: {pos}"
                );
                start_pos = start_pos + pos;
                break;
            }
        }

        // [2:2] [CASE NON-EMPTY] We compute all matching positions of child in parent
        let all_matches = search_sub_vec_all(eval_parent, eval_child);
        log::debug!("[S2:2] Searched child #{child_arg_number} encoding in parent and found positions: {all_matches:?}. (for path {path_to_search:?})");

        //   - If match is unique: we found the (unique) right position
        if all_matches.len() == 1 {
            // We found the child encoding in the root
            log::debug!(
                "[S2:2] Found position is unique: {}. Continue...",
                all_matches[0]
            );
            start_pos += all_matches[0];
            continue;
        }
        //   - No matching case: either parent is a `get` symbol --> could happen, or critical error
        if all_matches.is_empty() {
            let ft = format!(
                "--> [find_unique_match_rec] [S2:2] Child {child_arg_number} encoding not found in root for path {path_to_search:?}\n - eval_parent:\n  {eval_parent:?}\n  - eval_child:\n  {eval_child:?}",
            );
            return if parent_is_get {
                // This case is to be expected: we are looking for a child encoding that might just
                // not been present in the encoding because the function symbol is a `get` symbol.
                // No relevant payload replacement is possible --> We returns a simple error in that
                // case.
                Err(Error::Term(format!(
                    "{}\n--> [S2:2] [symbol above was a get symbol so this is not a critical error]",
                    ft
                )))
            } else {
                Err(Error::TermBug(format!(
                    "{}\n--> [S2:2] [symbol above was not a get symbol so this is a critical error]",
                    ft
                )))
            };
        }

        // [STEP 2:2: POSITION CHILD RELATIVELY TO SIBLINGS] If no unique match, we must find which
        // matching position of child relatively to the position of the evaluation of all
        // right siblings.

        // We first compute evaluation of all right siblings
        let mut eval_right_siblings = Vec::new();
        for right_sibling in (child_arg_number + 1)..nb_children {
            eval_right_siblings.extend_from_slice(
                children[right_sibling]
                    .encode
                    .as_ref()
                    .expect("[find_unique_match_rec] [S2:2] EvalTree should have been computed"),
            );
        }

        if let Some(pos_right_siblings) = last_sub_vec(eval_parent, &eval_right_siblings) {
            //   - We found at least some match. We assume the real match is the last one:
            //     pos_right_siblings
            // We assume the right child position is the last match (idx) for which the end of the
            // match would not overlap with the right siblings:
            // all_matches[idx] + eval_child.len() <= pos_right_siblings
            log::debug!("[find_unique_match_rec] [S2:2] [sib] Found last matching position of eval_right_siblings in eval_parent: pos_right_siblings= {pos_right_siblings}");
            if let Some(pos_child) = all_matches
                .iter()
                .rev()
                .find(|p| **p + eval_child.len() <= pos_right_siblings)
            {
                log::debug!("[find_unique_match_rec] [S2:2] Found pos_child: {pos_child} by comparing with pos_right_siblings: {pos_right_siblings}. Continue....");
                start_pos += pos_child;
                continue;
            } else {
                let ft = format!("[find_unique_match_rec] [S2:2] [sib] Could not find at least one appropriate idx for all_matches: {all_matches:?} and eval_child.len: {}, eval_parent.len(): {}, pos_right_siblings: {pos_right_siblings}. Continue....\n\
                  - eval_right_siblings: {eval_right_siblings:?}\n\
                  - eval_parent: {eval_parent:?}", eval_child.len(), eval_parent.len());
                if !parent_is_get {
                    return Err(Error::TermBug(ft));
                } else {
                    return Err(Error::Term(ft));
                }
            }
        } else {
            // right_sibling could not be found --> warning
            let ft = format!("[[find_unique_match_rec] [S2:2] [not-sib] Could not find right siblings encoding in eval_parent: {eval_parent:?} for path {path_to_search:?}. eval_right_siblings: {eval_right_siblings:?}");
            log::error!("{ft}");
            #[cfg(any(debug_assertions, feature = "debug"))]
            {
                return if parent_is_get {
                    // This case is to be expected: we are looking for a child encoding that might
                    // just not been present in the encoding because the
                    // function symbol is a `get` symbol. No relevant payload
                    // replacement is possible --> We returns a simple error in that
                    // case.
                    Err(Error::Term(format!("{ft}")))
                } else {
                    Err(Error::TermBug(format!("{ft}")))
                };
            }
        }
    }

    // If match was found before reaching the target, update encountered_get_symbol
    if !encountered_get_symbol && path_to_search.len() > 0 {
        while path_to_search.len() > 0 {
            if term.is_get() {
                encountered_get_symbol = true;
                break;
            }
            let child_arg_number = path_to_search[0];
            path_to_search = &path_to_search[1..];
            term = term
                .get(&[child_arg_number])
                .expect("[find_unique_match_rec] term does not match eval_tree");
        }
    }

    log::debug!("[find_unique_match_rec] End of while, returning {start_pos}");

    // Check consistencies in debug mode
    #[cfg(any(debug_assertions, feature = "debug"))]
    {
        if !encountered_get_symbol {
            log::debug!("[find_unique_match_rec] [DEBUG] Checking consistencies...");
            assert!(start_pos + eval_to_search_orig.len() <= eval_root_orig.len());
            assert_eq!(
                eval_root_orig[start_pos..(start_pos + eval_to_search_orig.len())],
                eval_to_search_orig
            );
        }
    }

    Ok((start_pos, encountered_get_symbol))
}

/// Operate the payloads replacements in `eval_tree.encode`[vec![]] and returns the modified
/// bitstring by "splicing". `@payloads` follows this order: deeper terms first, left-to-right,
/// assuming no overlap (no two terms one being a sub-term of the other).
pub fn replace_payloads<PT: ProtocolTypes>(
    term: &Term<PT>,
    eval_tree: &mut EvalTree,
    payloads: Vec<PayloadContext<PT>>,
) -> Result<ConcreteMessage, Error> {
    log::trace!("[replace_payload] --------> START");
    let mut shift = 0_isize; // Number of bytes we need to shift on the right to operate the
                             // replacement (i.e., apply the splicing, taking into account previous payloads replacements).
                             // We assume the aforementioned invariant.
    let mut to_modify: Vec<u8> = eval_tree.encode.as_ref().unwrap().clone(); // unwrap: eval_until_opaque
                                                                             // returned an error if it cannot compute the encoding of the root having payloads
    log::trace!("to_modify before: {to_modify:?}");
    for payload_context in &payloads {
        let path_payload = &payload_context.path;
        log::trace!("[replace_payload] --------> treating {} at path {:?} on message of length = {}. Shift = {shift}", payload_context.payloads, payload_context.path, to_modify.len());
        let old_bitstring = if term.has_variable() {
            // We prefer looking for the payload in the term evaluation in case it has changed since
            // MakeMessage because of variables (that might contain different values now)
            eval_tree.get(path_payload)?.encode.as_ref().unwrap()
        } else {
            payload_context.payloads.payload_0.bytes()
        };

        // Consistency checks in debug mode
        #[cfg(any(debug_assertions, feature = "debug"))]
        if !term.has_variable() {
            assert_eq!(
                eval_tree.get(path_payload)?.encode.as_ref().unwrap(),
                payload_context.payloads.payload_0.bytes()
            );
        }

        // Goal: compute byte position of path_payload in eval_tree: `pos_start`
        let is_to_search_in_list = if path_payload.is_empty() {
            false
        } else {
            let path_parent = &path_payload[0..path_payload.len() - 1];
            term.get(path_parent)
                .expect("[replace_payload] Should never happen")
                .is_list()
        };
        let (pos_start, encountered_get_symbol) =
            find_unique_match(path_payload, eval_tree, term, is_to_search_in_list)?;
        let old_bitstring_len = old_bitstring.len();
        let new_bitstring = payload_context.payloads.payload.bytes();

        let start = (pos_start as isize + shift) as usize; // taking previous replacements into account, we need to shift the start
        let end = start + old_bitstring_len;

        if (pos_start as isize + shift) < 0 || start + old_bitstring_len > to_modify.len() {
            let ft = format!(
                "--> [replace_payload] Impossible to splice because of incompatible indices.\n\
                 - start = (pos_start as isize + shift) < 0: {start} = ({pos_start} + {shift}) < 0\n\
                 - end = start + old_bitstring_len > to_modify.len(): {end} = ({pos_start} + {shift} + {old_bitstring_len}) as usize > {}\n\
                 - payload_context: {payload_context}",
                to_modify.len());
            log::error!("{ft}");
            if !encountered_get_symbol {
                return Err(Error::TermBug(ft));
            } else {
                return Err(Error::Term(ft));
            }
        }

        log::trace!("[replace_payload] About to splice for indices to_replace.len={}, range={start}..{end} (shift={shift})\n  - to_modify[start..end]={:?}\n  - old_bitstring={old_bitstring:?}\n  - to_modify={to_modify:?}",
                to_modify.len(), &to_modify[start..end]);
        #[cfg(any(debug_assertions, feature = "debug"))]
        if to_modify[start..end] != *old_bitstring {
            let ft = format!(
                "--> [replace_payloads] Payloads returned by eval_until_opaque were inconsistent!\n\
                   - payload_path: {:?}\n\
                   - term: {term}\n\
                   - payload_0.bytes() != to_modify[{start}..{end}].to_vec()\n\
                   - old_bistring = payload_0.bytes()\n= {:?}\n\
                   - to_modify[{start}..{end}].to_vec()\n= {:?}\n\
                   - payload_context: {payload_context}\
                   - payload: {:?}",
                payload_context.path,
                old_bitstring,
                to_modify[start..end].to_vec(),
                payload_context.payloads,
            );
            log::error!("{ft}");
            if !encountered_get_symbol {
                return Err(Error::TermBug(ft));
            } else {
                return Err(Error::Term(ft));
            }
        }
        // Performing the bytes replaceents through splicing
        let to_remove: Vec<u8> = to_modify
            .splice(start..end, new_bitstring.to_vec())
            .collect();
        log::trace!(
            "[replace_payload] Removed elements (len={}): {:?}",
            to_remove.len(),
            &to_remove
        );
        log::trace!("[replace_payload] Shift update!: New_b: {}, old_b_len: {old_bitstring_len}, old_shift: {shift}, new_shift:{} ", new_bitstring.len(), shift + (new_bitstring.len() as isize - old_bitstring_len as isize));
        shift += new_bitstring.len() as isize - old_bitstring_len as isize;
    }
    log::trace!("to_modify afterwards: {to_modify:?}");
    Ok(to_modify)
}

impl<PT: ProtocolTypes> Term<PT> {
    /// Evaluate a term without replacing the payloads (returning the payloads with the
    /// corresponding paths instead, i.e., a `Vec<PayloadContext>` accumulator), except when
    /// reaching an opaque term with payloads as strict sub-terms. In the latter case, fully
    /// evaluate each of the arguments (and performing the payload replacements) before
    /// evaluating the opaque function, which then needs to be read to convert it back to a
    /// `Box<dyn EvaluatedTerm<PT>>`. @path: current path of &self in the overall recipe (initially
    /// []). Invariant: Returns the payloads to replace in this order: deeper first, left-most
    /// arguments first.
    /// When `with_payloads` is false, then this should be equivalent to `evaluate_lazy_test` and it
    /// always return empty `PayloadContext` vectors.
    pub(crate) fn eval_until_opaque<PB>(
        &self,
        eval_tree: &mut EvalTree,
        ctx: &TraceContext<PB>,
        with_payloads: bool,
        sibling_has_payloads: bool,
        type_term: &TypeShape<PT>,
    ) -> Result<(Box<dyn EvaluatedTerm<PT>>, Vec<PayloadContext<PT>>), Error>
    where
        PB: ProtocolBehavior<ProtocolTypes = PT>,
    {
        log::trace!("[eval_until_opaque] [START]: Eval term:\n {self}");
        // We optimize here by bypassing evaluation and directly read over the payload when the term
        // has no variable. Indeed, variables may contain different values since when we ran
        // MakeMessage
        if let (true, Some(payload)) = (with_payloads && !self.has_variable(), &self.payloads) {
            log::trace!(
                "[eval_until_opaque] Trying to read payload_0 to skip further computations... payload_0: {:?}",
                payload.payload_0.bytes(),
            );
            if let Ok(di) = PB::try_read_bytes(payload.payload_0.bytes(), type_term.clone().into())
            {
                // We must make sure that we read correctly and avoided cases where read and encode
                // are not inverse of each other. Otherwise, later payload replacements will fail.
                if &di.get_encoding()[..] != &payload.payload_0.bytes()[..] {
                    log::warn!(
                                "--> [eval_until_opaque] [argument is symbolic: {}] [Skipping eval bypass] Failed consistency check for read.encode a type {}:\n\
                                - bi (first eval)  : {:?}\n\
                                - read.encode:     : {:?}",
                                self.is_symbolic(),
                                 <TypeShape<PT> as Clone>::clone(type_term),
                payload.payload_0.bytes(),
                                di.get_encoding(),
                            );
                } else {
                    log::trace!("[eval_until_opaque] Successfully read term: {:?}", di);
                    let p_c = vec![PayloadContext {
                        of_term: self,
                        payloads: payload,
                        path: eval_tree.path.clone(),
                    }];
                    eval_tree.encode = Some(payload.payload_0.bytes().to_vec());
                    return Ok((di, p_c));
                }
            } else {
                // We expect this might fail because encode and read are not fully inverse of each
                // other. For example: read(encode(PayloadU8)) != PayloadU8 when its size exceeds
                // 255 because: encode will write it all, while read will only read
                // the announced length. Note: we don't want to make encode only write the announced
                // length since we precisely want to be able to "lie" about the announced lengths...
                log::trace!("[eval_until_opaque] Attempt to skip evaluation failed, fall back to normal evaluation...");
            }
        }

        // Specific case of readable terms (originated from ReadMessage): if the term is a readable
        // term, we MUST read it directly from payload!
        if with_payloads && self.is_readable() {
            let payload = self.payloads.as_ref().ok_or(TermBug(format!("[eval_until_opaque] Try to read a readable term without payload, should never happen!")))?;
            log::trace!(
                "[eval_until_opaque] Trying to read payload (originated from ReadMessage): {:?}",
                payload.payload.bytes(),
            );
            if let Ok(di) = PB::try_read_bytes(payload.payload.bytes(), type_term.clone().into()) {
                log::trace!("[eval_until_opaque] Successfully read term: {:?}", di);
                // We have set payload to di.get_encoding() when performing ReadMessage, so we can
                // use it here
                eval_tree.encode = Some(payload.payload.bytes().to_vec());
                return Ok((di, vec![]));
            } else {
                return Err(TermBug(format!("[eval_until_opaque] Fail to read a readable term (originated from ReadMessage), should never happen!")));
            }
        }

        match &self.term {
            DYTerm::Variable(variable) => {
                let d = ctx
                    .find_variable(variable.typ.clone(), &variable.query)
                    .map(|data| data.boxed())
                    .or_else(|| {
                        if let Some(Source::Agent(agent_name)) = &variable.query.source {
                            ctx.find_claim(*agent_name, variable.typ.clone())
                        } else {
                            // Claims doesn't have precomputations as source
                            None
                        }
                    })
                    .ok_or_else(|| {
                        Error::Term(format!("--> Unable to find variable {variable}!"))
                    })?;
                if with_payloads {
                    // TODO: we might want to relax this a bit and only do this for nodes that are
                    // in the paths towards a payload or a right sibling of such a node. Not sure
                    // this woulf save us a lot of computations though.
                    let eval = PB::any_get_encoding(d.as_ref());
                    log::trace!("        / Variable evaluated into: {eval:?}");
                    eval_tree.encode = Some(eval);
                    if self.payloads.is_some() {
                        log::trace!("[eval_until_opaque] [Var] Add a payload for a leaf at path: {:?}, payload is: {:?} and eval is: {:?}", eval_tree.path, self.payloads.as_ref().unwrap(), PB::any_get_encoding(d.as_ref()));
                        return Ok((
                            d,
                            vec![PayloadContext {
                                of_term: self,
                                payloads: self.payloads.as_ref().unwrap(),
                                path: eval_tree.path.clone(),
                            }],
                        ));
                    }
                }
                log::trace!("[eval_until_opaque] [Var] Did not add a payload for a leaf at path: {:?} and eval is: {:?}", eval_tree.path, PB::any_get_encoding(d.as_ref()));
                Ok((d, vec![]))
            }
            DYTerm::Application(func, args) => {
                log::trace!(
                    "[eval_until_opaque] [App]: Application from path={:?}",
                    eval_tree.path
                );
                let mut dynamic_args: Vec<Box<dyn EvaluatedTerm<PT>>> = Vec::new(); // will contain all the arguments on which to call the function symbol
                                                                                    // implementation
                let mut all_payloads = vec![]; // will collect all payloads contexts of arguments (except those under opaque
                                               // function symbols)
                let mut eval_tree_args = vec![]; // will collect the eval tree of the sub-terms, if `with_payloads`
                let self_has_payloads_wo_root = self.has_payload_to_replace_wo_root();
                for (i, ti) in args.iter().enumerate() {
                    log::trace!(
                        "  + Treating argument # {i} from path {:?}...",
                        eval_tree.path
                    );
                    if with_payloads && self.is_opaque() && ti.has_payload_to_replace() {
                        // Fully evaluate this sub-term and consume the payloads
                        log::trace!("    * [eval_until_opaque] Opaque and has payloads: Inner call of eval on term: {}\n with #{} payloads", ti, ti.payloads_to_replace().len());
                        let typei = func.shape().argument_types[i].clone();
                        let bi = ti.evaluate(ctx)?; // payloads in ti are consumed here!
                        let di = PB::try_read_bytes(&bi, typei.clone().into()) // TODO: to make this more robust, we might want to relax this when payloads are in deeper terms, then read there!
                            .map_err(|e| {
                                if !ti.is_symbolic() {
                                    log::warn!("[eval_until_opaque] [Argument has payload, might explain why] Warn: {}", e);
                                } else {
                                    log::warn!("[eval_until_opaque] [Argument is symbolic!] Err: {}", e);
                                }
                                e
                            })?; // This may fail for good or bad reasons, we don't distinguish for now
                                 // We must make sure that we read correctly and avoided cases where read and
                                 // encode are not inverse of each other.
                                 // Otherwise, later payload replacements will fail.
                        if &di.get_encoding()[..] != &bi[..] {
                            return Err(Error::Term(format!(
                                "--> [eval_until_opaque] [argument is symbolic: {}] [1] Failed consistency check for read.encode a type {}:\n\
                                - bi (first eval)  : {bi:?}\n\
                                - read.encode:     : {:?}",
                                ti.is_symbolic(),
                                typei,
                                di.get_encoding(),
                            )));
                        }

                        dynamic_args.push(di); // no need to add payloads to all_p as they were
                                               // consumed (opaque function symbol)
                    } else {
                        let mut path_i = eval_tree.path.clone();
                        path_i.push(i); // adding `i` for i-th argument
                        let mut eval_tree_i = if with_payloads {
                            EvalTree::with_path(path_i.clone())
                        } else {
                            EvalTree::with_path(vec![]) // dummy eval_tree
                        };
                        let (di, mut p_s) = ti.eval_until_opaque(
                            &mut eval_tree_i,
                            ctx,
                            with_payloads,
                            self_has_payloads_wo_root,
                            &func.shape().argument_types[i],
                        )?;
                        dynamic_args.push(di); // add the evaluation (Boc<dyn Any>) to the list of arguments
                        if with_payloads {
                            eval_tree_args.push(eval_tree_i);
                            all_payloads.append(p_s.as_mut()); // collect the payloads
                        }
                        log::trace!(
                            "  + Ending treating argument # {i} from path {:?}...",
                            eval_tree.path
                        );
                    }
                }
                log::trace!("[eval_until_opaque] Now calling the function symbol {} implementation and then updating payloads...", func.name());
                let dynamic_fn = &func.dynamic_fn();
                let result: Box<dyn EvaluatedTerm<PT>> = dynamic_fn(&dynamic_args)?; // evaluation of the function symbol implementation

                if with_payloads && self.payloads.is_some() {
                    all_payloads.push(PayloadContext {
                        of_term: self,
                        payloads: self.payloads.as_ref().unwrap(),
                        path: eval_tree.path.clone(),
                    });
                }

                // Sanity check!
                #[cfg(any(debug_assertions, feature = "debug"))]
                if let (true, Some(payload)) = (with_payloads, &self.payloads) {
                    log::trace!("[eval_until_opaque] Checking consistency!");
                    let new_payload_0 = PB::any_get_encoding(result.as_ref());
                    if new_payload_0 != payload.payload_0.bytes() {
                        let ft = format!("--> [eval_until_opaque] [term has variable:{}] Failed consistency check payload_0 versus new encoding.\n\
                                    - term: {}\n\
                                    - payload_0:    {:?}\n\
                                    - new_eval:     {new_payload_0:?}\n\
                                    - result: {result:?}",
                                         self.has_variable(), self, &payload.payload_0.bytes());
                        if self.has_variable() {
                            // Some mismatches are to be expected when there are variables
                            log::trace!("[term has variables --> only a log::trace] {}", ft);
                        } else {
                            return Err(Error::TermBug(ft));
                        }
                    }
                }

                // If there are payloads to replace in self or siblings, then we will *likely* have
                // to know the encoding of self, we save it for later in eval_tree
                if with_payloads && (!all_payloads.is_empty() || sibling_has_payloads) {
                    eval_tree.args = eval_tree_args;
                    let eval = PB::any_get_encoding(result.as_ref());
                    log::trace!("        / We successfully evaluated the term into: {eval:?}");
                    eval_tree.encode = Some(eval);
                }

                Ok((result, all_payloads))
            }
        }
    }
}

/// Return all the matching positions
#[must_use]
pub fn search_sub_vec_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut matches = Vec::new();
    if haystack.len() < needle.len() {
        // log::trace!("search_sub_vec_double: length");
        return matches;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if haystack[i..i + needle.len()] == needle[..] {
            // log::trace!("search_sub_vec_double: found for i:{i}");
            matches.push(i);
        }
    }
    // log::trace!("search_sub_vec_double: not found");
    matches
}

/// Return the last matching positions, if any
#[must_use]
pub fn last_sub_vec(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    for i in (0..=(haystack.len() - needle.len())).rev() {
        if haystack[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
    }
    None
}

/// Return the first matching positions, if any
#[must_use]
pub fn first_sub_vec(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    for i in (0..=(haystack.len() - needle.len())).rev() {
        if haystack[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
    }
    None
}

/// Return the first matching position when it us unique, and None otherwise
pub fn first_sub_vec_unique(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        // log::trace!("search_sub_vec_double: length");
        return None;
    }
    let mut first_found = false;
    let mut pos = 0;
    for i in 0..=(haystack.len() - needle.len()) {
        if haystack[i..i + needle.len()] == needle[..] {
            // log::trace!("search_sub_vec_double: found for i:{i}");
            if !first_found {
                pos = i;
                first_found = true;
            } else {
                // Double matches
                return None;
            }
        }
    }
    // log::trace!("search_sub_vec_double: not found");
    if first_found {
        Some(pos)
    } else {
        None
    }
}
