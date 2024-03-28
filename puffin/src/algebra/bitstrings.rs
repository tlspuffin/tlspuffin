use std::{
    any::{Any, TypeId},
    cmp::{max, min},
    fmt::format,
};

use anyhow::Context;
use libafl::inputs::{BytesInput, HasBytesVec};
use log::{debug, error, trace, warn};
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{
        bitstrings::TreeOrEval::Eval, dynamic_function::TypeShape, ConcreteMessage, Matcher, Term,
        TermEval, TermType,
    },
    error::Error,
    fuzzer::utils::{find_term_by_term_path, TermPath},
    protocol::ProtocolBehavior,
    trace::{Trace, TraceContext},
};

const THRESHOLD_SUM: usize = 40;
const THRESHOLD_RATIO: usize = 4;

/// `TermEval`s are `Term`s equipped with optional `Payloads` when they no longer are treated as
/// symbolic terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payloads {
    pub payload_0: BytesInput, // initially both are equal and correspond to the term evaluation
    pub payload: BytesInput,   // this one will later be subject to bit-level mutation
}
impl Payloads {
    pub fn len(self: &Self) -> usize {
        self.payload_0.bytes().len()
    }
}

/// Payload with the context related to the term it originates from
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayloadContext<'a, M: Matcher> {
    // not used if no payload to replace
    of_term: &'a TermEval<M>, // point to the corresponding term
    payloads: &'a Payloads,   // point to the corresponding term.payload
    path: TermPath,           // path of the sub-term from which this payload originates
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
    pub fn init() -> Self {
        EvalTree {
            encode: None, // will contain the bitstring encoding when sub-terms have payloads and when evaluation succeeds
            path: TermPath::new(),
            args: vec![], // will be modified while evaluating `term` if there are payloads to replace in this sub-tree
        }
    }
    pub fn init_with_path(path: TermPath) -> Self {
        let mut e_t = Self::init();
        e_t.path = path;
        return e_t;
    }

    fn get(self: &Self, path: &[usize]) -> Result<&Self, Error> {
        if path.is_empty() {
            return Ok(self);
        } else {
            let nb = path[0];
            let path = &path[1..];
            if self.args.len() <= nb {
                Err(Error::Term(format!(
                    "[replace_payloads] [get] Should never happen! EvalTree: {:?}\n, path: {:?}",
                    self, path
                )))
            } else {
                self.args[nb].get(path)
            }
        }
    }

    fn get_mut(self: &mut Self, path: &[usize]) -> Result<&mut Self, Error> {
        if path.is_empty() {
            return Ok(self);
        } else {
            let nb = path[0];
            let path = &path[1..];
            if self.args.len() <= nb {
                Err(Error::Term(format!(
                    "[replace_payloads] [get] Should never happen! EvalTree: {:?}\n, path: {:?}",
                    self, path
                )))
            } else {
                self.args[nb].get_mut(path)
            }
        }
    }
}

/// Useful struct to store local state when searching for a payload in a window
#[derive(Debug)]
pub struct StatusSearch {
    pub found_window: bool,
    pub unique_window: bool,
    pub found_match: bool,
    pub unique_match: bool,
    shift_window: usize,
    pos_in_window: usize,
}

impl Default for StatusSearch {
    fn default() -> Self {
        StatusSearch {
            found_window: true,
            unique_window: true,
            found_match: false,
            unique_match: true,
            shift_window: 0,
            pos_in_window: 0,
        }
    }
}

/// Storing the result of `eval_or_compute`
pub enum TreeOrEval<'a> {
    EvalTree(&'a ConcreteMessage),
    Eval(ConcreteMessage),
}
impl<'a> TreeOrEval<'a> {
    pub fn to_pointer(self: &'a Self) -> &'a ConcreteMessage {
        match self {
            TreeOrEval::EvalTree(e) => e,
            Eval(e) => &e,
        }
    }
}

/// Try to recover the evaluation from @eval_tree and this fails, because we have not computed it in the past,
/// then we evaluate the corresponding sub-term.
pub fn eval_or_compute<'a, M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    path_to_eval: &[usize],
    eval_tree: &'a EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
) -> Result<TreeOrEval<'a>, Error> {
    match eval_tree.get(&path_to_eval)?.encode.as_ref() {
        Some(eval) => Ok(TreeOrEval::EvalTree(eval)),
        None => {
            trace!("[eval_or_compute] We did not compute eval before, we do it now.");
            let sibling_term = find_term_by_term_path(whole_term, &path_to_eval).ok_or(
                Error::Term(format!("[eval_or_compute] Should never happen1")),
            )?;
            // we must evaluate sibling_term, replacing payloads until opaque ONLY!
            let mut et = EvalTree::init();
            let p = vec![];
            let (sibling_eval_box, _) = sibling_term.eval_until_opaque(
                &mut et,
                p,
                ctx,
                true,
                false,
                false,
                whole_term.get_type_shape(),
            )?;
            Ok(Eval(PB::any_get_encoding(&sibling_eval_box)?))
        }
    }
}
/// Search relative node. Spec: returns the path p to a node such that all nodes whose path is
///  - strictly between p and path_to_search (according to the lexicographic order)
///  - and that is not a descendant of p
/// has an empty encoding.
/// For example: if p is the closest cousin on the left, then all siblings on the left of path_to_search must have an empty
/// encoding. Returns p, and whether the encoding of path_to_search comes after the one of p (true) or before (false).
/// For instance, if p is an ancestor of path_to_search then it will be false.
/// If p is a sibling, then it depends whether it is on the left (true) or on the right (false) of path_to_search.
pub fn find_relative_node<'a, M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    path_to_search: &[usize],
    eval_tree: &'a EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
) -> Result<(TermPath, TreeOrEval<'a>, bool), Error> {
    if path_to_search.is_empty() {
        let ft = format!("[find_relative_node] Empty path_to_search!! Error!");
        error!("{}", ft);
        return Err(Error::Term(ft));
    }
    debug!("[find_relative_node] Look a relative node from {path_to_search:?}");
    let path_parent = &path_to_search[0..path_to_search.len() - 1];
    let mut att = 0;
    let eval_t_parent = eval_tree.get(path_parent)?;
    let nb_args = eval_t_parent.args.len();
    let arg_to_search = *path_to_search.last().unwrap();
    trace!("arg_to_search: {arg_to_search}, nb_args:{nb_args}, path_parent:{path_parent:?}");
    if arg_to_search > 0 {
        // search on the left until finding an appropriate sibling
        let mut sib_left = arg_to_search as isize - 1isize;
        while sib_left >= 0 && att < 20 {
            att += 1;
            debug!("[find_relative_node] trying on the left, arg_to_search:{arg_to_search}, sib_left:{sib_left}");
            let mut path_sib = path_parent.to_vec();
            path_sib.push(sib_left as usize);
            // We call eval_or_compute as we might not have tried to evaluate the sibling when creating eval_tree
            let eval_sib = eval_or_compute(&path_sib, eval_tree, whole_term, ctx)?;
            if !eval_sib.to_pointer().is_empty() {
                assert!(path_sib != path_to_search);
                return Ok((path_sib, eval_sib, true)); // on the left of path_to_search
            } else {
                sib_left -= 1;
            }
        }
    } // we failed to find a sibling candidate on the left, let us try on the right
    if arg_to_search < nb_args - 1 {
        // search on the right until finding an appropriate sibling
        let mut sib_right = arg_to_search + 1;
        while sib_right <= nb_args - 1 && att < 20 {
            att += 1;
            debug!("[find_relative_node] trying on the right, arg_to_search:{arg_to_search}, sib_right:{sib_right}");
            let mut path_sib = path_parent.to_vec();
            path_sib.push(sib_right as usize);
            // We call eval_or_compute as we might not have tried to evaluate the sibling when creating eval_tree
            let eval_sib = eval_or_compute(&path_sib, eval_tree, whole_term, ctx)?;
            if !eval_sib.to_pointer().is_empty() {
                let mut path_sib = path_parent.to_vec();
                path_sib.push(sib_right);
                assert!(path_sib != path_to_search);
                return Ok((path_sib, eval_sib, false)); // on the right of path_to_search
            } else {
                sib_right += 1;
            }
        }
    } // we failed to find a sibling candidate, therefore the parent has an empty encoding too, let us try from there!
    debug!("[find_relative_node] failed, trying parent at path {path_parent:?}");
    if path_parent.len() < path_to_search.len() {
        return find_relative_node(path_parent, eval_tree, whole_term, ctx);
    } else {
        panic!("[find_relative_node] should never happen, new path is not shorter!");
    }
}

/// Return the depth we should look for the next window, relatively to the current depth, according to
/// our heuristics
pub fn refine_window_heuristic(
    current_depth: usize,
    to_search: &[u8],
    window_len: usize,
    path_to_search: &[usize],
    st: &StatusSearch,
) -> usize {
    if path_to_search.is_empty() {
        trace!("[refine_window_heuristic] only possible window candidate is the root");
        return 0;
    }
    if to_search.is_empty() {
        trace!("[refine_window_heuristic] will be handled with a specific routine anyway");
        return max(0, path_to_search.len() - 1);
    }
    if window_len == 0 {
        trace!("[refine_window_heuristic] window is too narrow, we decrease the depth (= increases window)");
        return max(0, current_depth - 1);
    }
    if !st.found_window {
        trace!("[refine_window_heuristic] window might be too large or just at a sub-term for which encoding is not meaningful, go narrower");
        return min(path_to_search.len() - 1, current_depth + 1);
    }
    if !st.unique_window {
        trace!("[refine_window_heuristic] window is too narrow, we decreases the depth");
        return max(0, current_depth - 1);
    }
    if to_search.len() > 2
        || sum_vec_cap(to_search, 2) >= THRESHOLD_SUM
        || window_len / to_search.len() <= THRESHOLD_RATIO
    {
        if !st.unique_match {
            trace!("[refine_window_heuristic] the below failed, so we go to the first child {}, was {current_depth}, path_to_search: {path_to_search:?}", min(path_to_search.len(), current_depth + 1));
            return min(path_to_search.len() - 1, current_depth + 1);
        } else {
            trace!("[refine_window_heuristic] we keep as it is --> search in the whole window");
            return current_depth;
        }
    } else if to_search.len() > 1
        || sum_vec_cap(to_search, 1) >= THRESHOLD_SUM / 2
        || window_len / to_search.len() <= THRESHOLD_RATIO * 2
    {
        if !st.unique_match {
            trace!("[refine_window_heuristic] the below failed, so we go halfway");
            return min(
                path_to_search.len() - 1,
                max(
                    current_depth + 1,
                    (path_to_search.len() - current_depth) / 2,
                ),
            );
        } else {
            trace!("[refine_window_heuristic] we go a quarter");
            return min(
                path_to_search.len() - 1,
                max(
                    current_depth + 1,
                    (path_to_search.len() - current_depth) / 4,
                ),
            );
        }
    } else {
        trace!("[refine_window_heuristic] not empty but very unlikely we found uniquely except in window path[0..len-1]");
        if !st.unique_match {
            return path_to_search.len() - 1;
        } else {
            return max(0, path_to_search.len() - 1);
        }
    }
}

/// Search `to_search` (`eval_tree[path].encode`) in root_eval:=eval_tree[vec![]].encode (=whole_term.encode(ctx))
/// such that the match is unique in a window corresponding to the evaluation of a sub-term at a path
/// in between vec![] (root) and `path_to_search`. Return the position of the match in `in_eval`.
/// ctx is only used in rare occasions, where some evaluations were not computed in eval_tree (when searching for siblings).
// TODO: Investigate this other idea:
// another option would be to always encode messages having payloads or siblinbgs with payloads and thus storing in TermEval the pos in bytes of each sub-term
// --> could be more costly in terms of eval, but then much less search_sub and much less try and fail below, plus those pos could be serialized and stored as
// part of the test-case
pub fn find_unique_match<M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    to_search: &[u8],
    path_to_search: &[usize],
    eval_tree: &mut EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
) -> Result<usize, Error> {
    let root_eval = &eval_tree.encode.as_ref().unwrap()[..];
    let window = root_eval; // we start with the largest window (evaluation at the root)
    let path_window = vec![];
    // root path
    debug!("[find_unique_match] ## Start with path {path_to_search:?},\n - to_search: {to_search:?}\n - root_eval: {root_eval:?}\n - whole_term:{whole_term}\n - eval_tree: {eval_tree:?}");
    find_unique_match_rec(
        to_search,
        path_to_search,
        root_eval,
        &path_window,
        StatusSearch::default(),
        eval_tree,
        whole_term,
        ctx,
        0,
    )
}

/// Goal: search `to_search` in in_eval_: to_search == in_eval_[returned_value..Y]
/// Invariants:
/// - path_window is in between vec![] (root) and `path_to_search`
/// - window = eval_tree[path_window].encode.unwrap()
/// - window = eval_tree[vec![]].encode.unwrap()[shift_window..X]
/// - to_search = eval_tree[path_to_search].encode.unwrap()
/// - if `found_match`, then `to_search` is found in `window` at `pos`: to_search == window[pos_in_window..Z]
/// - if `found_window`, then try_new_path_window = path_window
/// - try_new_depth_path_window = path_to_search[0..try_new_depth_path_window]
/// Therefore: to_search can be found in the whole bitstring (eval_tree[vec![]].encode.unwrap())
/// at pos `shift_window + pos_in_window`.
pub fn find_unique_match_rec<'a, M, PB>(
    to_search: &[u8],
    path_to_search: &'a [usize],
    mut window: &'a [u8],
    mut path_window: &'a [usize],
    mut st: StatusSearch,
    eval_tree: &'a EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
    old_attempts: usize,
) -> Result<usize, Error>
where
    M: Matcher,
    PB: ProtocolBehavior<Matcher = M>,
{
    debug!("[find_unique_match_rec] Start with path_to_search {path_to_search:?},\n - to_search: {to_search:?}\n - window:: {window:?}\n - path_window:{path_window:?}");
    trace!(" - whole_term: {whole_term}");
    let mut try_new_depth_path_window =
        refine_window_heuristic(0, &to_search, window.len(), path_to_search, &st);
    let mut try_new_path_window = &path_to_search[0..try_new_depth_path_window];
    if try_new_depth_path_window != 0 {
        st.found_window = false;
    }
    let mut fallback_empty = false; // when everything fails, we fall back to the solution for empty payload (relying on closest nodes)
    let mut attempts = 0;
    let eval_root = &eval_tree.encode.as_ref().unwrap()[..];

    while !(st.found_window && st.unique_match && st.found_match && st.unique_window) {
        if attempts > 40 || attempts + old_attempts > 100 {
            let ft = format!("[replace_payloads] [find_unique_match_rec] [MAX ATTEMPTS] Unable to find a match after {attempts} attempts.\n - to_search:{:?}\n - window:{:?}\n - path_to_search:{:?},\n path_window:{:?}\n - eval_tree:{:?}", to_search, window, path_to_search, path_window, eval_tree);
            error!("{}", ft);
            return Err(Error::Term(ft));
        }
        // initially found_match is false (not searched and found to_search yet)
        debug!("[find_unique_match_rec] ATTEMPT #{attempts} with StatutSearch: {st:?}, fallback_empty:{fallback_empty}\n - path_window:{path_window:?}, try_new_path_window:{try_new_path_window:?}, to_search.len():{}, window.len():{}", to_search.len(), window.len());
        trace!("  - to_search: {to_search:?}\n  - window: {window:?}");
        attempts += 1;
        if attempts > 3 {
            warn!("[find_unique_match] HIGH NUMBER OF ATTEMPTS!");
        }
        if attempts > 15 {
            fallback_empty = true;
        }

        if path_to_search.is_empty() {
            return Ok(0); // only valid option
        }

        // SPECIAL CASE EMPTY PAYLOAD or FALLBACK
        if to_search.is_empty() || fallback_empty {
            // let mut sibling_eval = vec![];
            debug!(
                "[find_unique_match_rec] Empty to_search or fallback mode, looking for a relative!"
            );
            // Search for a relative node.
            // Spec: is the shortest sibling having a non-empty encoding (on the left or on the right)
            let (path_relative, eval_relative_, relative_on_left) =
                find_relative_node(path_to_search, eval_tree, whole_term, ctx)?;
            let eval_relative = eval_relative_.to_pointer();
            trace!("[find_unique_match_rec] Found a relative at path {path_relative:?}, is_on_the_left:{relative_on_left}\n eval_relative: {eval_relative:?}");

            let pos_relative_in_root = find_unique_match_rec(
                eval_relative,
                &path_relative,
                eval_root,
                &path_relative[0..0],
                StatusSearch::default(),
                eval_tree,
                whole_term,
                ctx,
                old_attempts + attempts,
            )?;

            return if relative_on_left {
                Ok(pos_relative_in_root + eval_relative.len())
            } else {
                Ok(pos_relative_in_root)
            };
        }

        // NEW WINDOW
        if !st.found_window {
            // then we need to compute and search for the new window
            debug!(
                "[find_unique_match] NEW WINDOW: from {path_window:?} to {try_new_path_window:?}"
            );
            st.found_match = false;
            st.found_window = false;
            let new_window_eval_tree = eval_tree.get(try_new_path_window)?;
            if let Some(new_window_eval) = &new_window_eval_tree.encode {
                debug!("[find_unique_match] window has encoding");
                if let Some((pos_w, unique_w)) = search_sub_vec_double(eval_root, new_window_eval) {
                    debug!("[find_unique_match] found the window");
                    if unique_w {
                        debug!("[find_unique_match] unique window match");
                        // refining window succeeds!
                        st = StatusSearch {
                            found_window: true,
                            unique_window: true,
                            shift_window: pos_w,
                            ..st
                        };
                        window = new_window_eval;
                        path_window = try_new_path_window;
                        debug!("Found window and is unique. New window with path_window:{path_window:?}");
                        continue;
                    } else {
                        // window found twice, it is too small, we reduce the try_new_path_depth
                        debug!("[find_unique_match] not unique window match");
                        st.found_window = true;
                    }
                } // else: not found, we leave st unmodified
                  // // {
                  //     // window not found, it might be too large, we increase try_new_path_depth
                  //     debug!("[find_unique_match] window not found");
                try_new_depth_path_window = refine_window_heuristic(
                    // window found twice
                    try_new_depth_path_window,
                    &to_search,
                    window.len(),
                    &path_to_search,
                    &st,
                );
                try_new_path_window = &path_to_search[0..try_new_depth_path_window];
                st.found_window = false;
                debug!("Found window but not unique. New window with try_new_path_window:{try_new_path_window:?}, path_window was {path_window:?}");
                continue;
            } else {
                // Was not able to encode this sub-message
                let ft = format!("[replace_payloads] [find_window] Unable to find a window due to missing evaluation on EvalTree.\n - to_search:{:?}\n - eval_root:{:?}\n - path_to_search:{:?}\n - eval_tree:{:?}",
                                 to_search, eval_root, path_to_search, eval_tree);
                error!("{}", ft);
                return Err(Error::Term(ft));
            }
        }

        if !st.found_match {
            // SEARCH IN NEW WINDOW
            if let Some((pos, unique)) = search_sub_vec_double(&window, to_search) {
                debug!("[find_unique_match] to_search was found in window");
                st.found_match = true;
                if unique {
                    debug!("[find_unique_match] to_search was uniquely found in window");
                    st.unique_match = true;
                    st.pos_in_window = pos;
                } else {
                    // to_search was found twice, we need to refine the search window
                    debug!("[find_unique_match] to_search was not uniquely found in window");
                    st.unique_match = false; // will yield a deeper path_sub and hence narrower window at the next iteration
                    let try_new_depth_path_window = refine_window_heuristic(
                        path_window.len(),
                        &to_search,
                        window.len(),
                        &path_to_search,
                        &st,
                    );
                    try_new_path_window = &path_to_search[0..try_new_depth_path_window];
                    st.found_window = false;
                    debug!("Found match but not unique. New window with try_new_path_window:{try_new_path_window:?}");
                    continue;
                }
            } else {
                let ft = format!("[replace_payloads] [find_window] Unable to find a to_search in current window. Should never happen!\n - to_search:{:?}\n -window: {:?}\n - in_eval:{:?}\n - path:{:?}\n - eval_tree:{:?}",
                                 to_search, window, eval_root, path_to_search, eval_tree);
                error!("{}", ft);
                return Err(Error::Term(ft));
            }
        } else {
            let ft = format!(
                "[replace_payloads] [find_window] Should never happen: end of while with st:{st:?}"
            );
            error!("{}", ft);
            return Err(Error::Term(ft));
        }
    }
    debug!(
        "[find_unique_match] ## END found a match for {path_to_search:?} at {}",
        st.shift_window + st.pos_in_window
    );
    Ok(st.shift_window + st.pos_in_window)
}

/// Operate the payloads replacements in eval_tree.encode[vec![]] and returns the modified bitstring.
/// `@payloads` follows this order: deeper terms first, left-to-right, assuming no overlap (no two terms
/// one being a sub-term of the other).
pub fn replace_payloads<'a, M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    term: &TermEval<M>,
    eval_tree: &'a mut EvalTree,
    payloads: Vec<PayloadContext<M>>,
    ctx: &TraceContext<PB>,
) -> Result<ConcreteMessage, Error> {
    trace!("[replace_payload] --------> START");
    let mut shift = 0 as isize; // Number of bytes we need to shift on the right to apply the
                                // splicing, taking into account previous payloads replacements). We assume the aforementioned invariant.
    let mut to_modify: Vec<u8> = eval_tree.encode.as_mut().unwrap().clone(); //unwrap: eval_until_opaque returns an error if it cannot compute the encoding of the root having payloads
    for payload_context in &payloads {
        trace!("[replace_payload] --------> treating {:?} at path {:?} on message of length = {}. Shift = {shift}", payload_context.payloads, payload_context.path, to_modify.len());
        let old_bitstring = payload_context.payloads.payload_0.bytes();
        let path_payload = &payload_context.path;
        //Goal: search `to_search` in to_modify[pos_start..pos_end]=eval(term[path]) for `path` between path vec![] and `path_payload`
        let pos_start = find_unique_match(old_bitstring, path_payload, eval_tree, term, ctx)
            .map_err(|e| {
                error!(
                    "[replace_payloads] find_unique_match returned the Err: {}",
                    e
                );
                e
            })?;

        let old_bitstring_len = old_bitstring.len();
        let new_bitstring = payload_context.payloads.payload.bytes();

        let start = (pos_start as isize + shift) as usize; // taking previous replacements into account, we need to shift the start
        let end = start + old_bitstring_len;

        if (pos_start as isize + shift) < 0
            || (pos_start as isize + shift + old_bitstring_len as isize) as usize > to_modify.len()
        // TODO: check if it is > or >=
        {
            let ft = format!("[replace_payload] Impossible to splice for indices to_replace.len={}, range={start}..{end}. Payload: {payload_context:?}", to_modify.len());
            error!("{}", ft);
            return Err(Error::Term(ft));
        }
        debug!("[replace_payload] About to splice for indices to_replace.len={}, range={start}..{end} (shift={shift}\n  - to_modify[start..end]={:?}\n  - old_bitstring={old_bitstring:?}",
                to_modify.len(), &to_modify[start..end]);
        // TODO: SANITY CHECK TO REMOVE IN PRODUCTION ! as it is costly!
        if !(to_modify[start..end] == *old_bitstring) {
            let ft = format!(
                "[replace_payload] Payloads returned by eval_until_opaque were inconsistent!\n\
                   - term: {term}\n\
                   - to_replace[start..end].to_vec() = !to_modify[{start}..{end}].to_vec() = {:?}\n\
                   - payload.payload_0.bytes() = {:?}\n\
                   - to_modify={to_modify:?}",
                to_modify[start..end].to_vec(),
                old_bitstring
            );
            error!("{}", ft);
            return Err(Error::Term(ft));
        }
        let to_remove: Vec<u8> = to_modify
            .splice(start..end, new_bitstring.to_vec())
            .collect();
        trace!(
            "[replace_payload] Removed elements (len={}): {:?}",
            to_remove.len(),
            &to_remove
        );
        trace!("[replace_payload] Shift update!: New_b: {}, old_b_len: {old_bitstring_len}, old_shift: {shift}, new_shift:{} ", new_bitstring.len(), shift + (new_bitstring.len() as isize - old_bitstring_len as isize));
        shift += (new_bitstring.len() as isize - old_bitstring_len as isize);
    }
    Ok(to_modify)
}

impl<M: Matcher> TermEval<M> {
    /// Evaluate a term without replacing the payloads (returning the payloads with the corresponding paths instead,
    /// i.e., a Vec<PayloadContext> accumulator), except when reaching an opaque term with payloads as strict sub-terms.
    /// In the latter case, fully evaluate each of the arguments (and performing the payload replacements) before
    /// evaluating the opaque function, which then needs to be read to convert it back to a Box<dyn Any>.
    /// @path: current path of &self in the overall recipe (initially []).
    /// Invariant: Returns the payloads to replace in this order: deeper first, left-most arguments first.
    // TODO REMOVE:
    // To each payload, we associate
    // the path from which it originates and the pos_in_context (offset (in # bytes) where to find the payload in the
    // current term and the window (context)). The offset is always relative to the current window
    // context.
    // Invariant: concrete[pos_in_context..pos_in_context+payload.payload_0.len()] == payload.payload_0
    // Therefore, the position/offset (usize) is the position where to replace the payload in the current context.
    //  term.eval_until_opaque(Vec::new(), context, with_payloads, false)
    pub(crate) fn eval_until_opaque<PB>(
        &self,
        eval_tree: &mut EvalTree,
        path: TermPath,
        ctx: &TraceContext<PB>,
        with_payloads: bool,
        is_in_list: bool,
        sibling_has_payloads: bool,
        type_term: &TypeShape,
    ) -> Result<(Box<dyn Any>, Vec<PayloadContext<M>>), Error>
    where
        PB: ProtocolBehavior<Matcher = M>,
    {
        debug!("[eval_until_opaque] [START]: Eval term:\n {self}");
        if let (true, Some(payload)) = (with_payloads, &self.payloads) {
            debug!("[eval_until_opaque] Trying to read payload_0 to skip further computations...........");
            if let Ok(di) =
                PB::try_read_bytes(payload.payload_0.clone().into(), (*type_term).into())
            {
                let p_c = vec![PayloadContext {
                    of_term: self,
                    payloads: &payload,
                    path,
                }];
                eval_tree.encode = Some(payload.payload_0.bytes().to_vec());
                return Ok((di, p_c));
            }
            debug!("[eval_until_opaque] Attempt failed, fall back to normal evaluation...");
        }

        match &self.term {
            Term::Variable(variable) => {
                let d = ctx
                    .find_variable(variable.typ, &variable.query)
                    .map(|data| data.boxed_any())
                    .or_else(|| ctx.find_claim(variable.query.agent_name, variable.typ))
                    .ok_or_else(|| Error::Term(format!("Unable to find variable {}!", variable)))?;
                if path.is_empty() || (with_payloads && self.payloads.is_some()) {
                    if let Some(payload) = &self.payloads {
                        trace!("        / We retrieve evaluation for eval_tree from payload.");
                        eval_tree.encode = Some(payload.payload_0.clone().into());
                    } else {
                        if let Ok(eval) = PB::any_get_encoding(&d) {
                            trace!("        / No payload so we evaluated into: {eval:?}");
                            eval_tree.encode = Some(eval);
                        } else {
                            if path.is_empty() {
                                return (Err(Error::Term(format!("[eval_until_opaque] Could not any_get_encode a var term at root position, which has payloads to replace. Current term: {}", &self.term)))
                                    .map_err(|e| {
                                        error!("[eval_until_opaque] Err: {}", e);
                                        e
                                    }));
                            } else {
                                // we might not need this eval later, we will try to replace payloads without using it // TODO: make sure we resist this!
                                warn!("[eval_until_opaque] Could not any_get_encode a sub-term at path {path:?}, sub-term:\n{}", &self.term);
                            }
                        }
                    }
                    if with_payloads && self.payloads.is_some() {
                        trace!("[eval_until_opaque] [Var] Add a payload for a leaf at path: {path:?}, payload is: {:?} and eval is: {:?}", self.payloads.as_ref().unwrap(), PB::any_get_encoding(&d).ok());
                        return Ok((
                            d,
                            vec![PayloadContext {
                                of_term: &self,
                                payloads: self.payloads.as_ref().unwrap(),
                                path,
                            }],
                        ));
                    }
                }
                trace!("[eval_until_opaque] [Var] Did not add a payload for a leaf at path: {path:?} and eval is: {:?}", PB::any_get_encoding(&d));
                Ok((d, vec![]))
            }
            Term::Application(func, args) => {
                debug!("[eval_until_opaque] [App]: Application from path={path:?}");
                let mut dynamic_args: Vec<Box<dyn Any>> = Vec::new(); // will contain all the arguments on which to call the function symbol implementation
                let mut all_payloads = vec![]; // will collect all payloads contexts of arguments (except those under opaque function symbols)
                let mut eval_tree_args = vec![]; // will collect the eval tree of the sub-terms, if `with_payloads`
                let self_has_payloads_wo_root = self.has_payload_to_replace_wo_root();
                for (i, ti) in args.iter().enumerate() {
                    debug!("  + Treating argument # {i} from path {path:?}...");
                    if with_payloads && self.is_opaque() && ti.has_payload_to_replace() {
                        // Fully evaluate this sub-term and consume the payloads
                        debug!("    * [eval_until_opaque] Opaque and has payloads: Inner call of eval on term: {}\n with #{} payloads", ti, ti.payloads_to_replace().len());
                        let bi = ti.evaluate(ctx)?; // payloads in ti are consumed here!
                        let typei = func.shape().argument_types[i];
                        let di = PB::try_read_bytes(bi, typei.into()) // TODO: to make this more robust, we might want to relax this when payloads are in deeper terms, then read there!
                            .with_context(||
                                format!("[Eval_until_opaque] Try Read bytes failed for typeid: {}, typeid: {:?} on term (arg: {i}):\n {}",
                                        typei, TypeId::from(typei), &self))
                            .map_err(|e| {
                                if !ti.is_symbolic() {
                                    warn!("[eval_until_opaque] [Argument has payload, might explain why] Warn: {}", e);

                                } else {
                                    warn!("[eval_until_opaque] [Argument is symbolic!] Err: {}", e);
                                }
                                e
                            })?;
                        dynamic_args.push(di); // no need to add payloads to all_p as they were consumed (opaque function symbol)
                    } else {
                        let mut path_i = path.clone();
                        path_i.push(i); // adding `i` for i-th argument
                        let mut eval_tree_i = if with_payloads {
                            EvalTree::init_with_path(path_i.clone())
                        } else {
                            EvalTree::init_with_path(vec![]) // dummy eval_tree
                        };
                        let (di, mut p_s) = ti.eval_until_opaque(
                            &mut eval_tree_i,
                            path_i,
                            ctx,
                            with_payloads,
                            self.is_list(),
                            self_has_payloads_wo_root,
                            &func.shape().argument_types[i],
                        )?;
                        dynamic_args.push(di); // add the evaluation (Boc<dyn Any>) to the list of arguments
                        if with_payloads {
                            eval_tree_args.push(eval_tree_i);
                            all_payloads.append(p_s.as_mut()); // collect the payloads
                        }
                        debug!("  + Ending treating argument # {i} from path {path:?}...");
                    }
                }
                debug!("[eval_until_opaque] Now calling the function symbol implementation and then updating payloads...");
                let dynamic_fn = &func.dynamic_fn();
                let result: Box<dyn Any> = dynamic_fn(&dynamic_args)?; // evaluation of the function symbol implementation

                if with_payloads && self.payloads.is_some() {
                    all_payloads.push(PayloadContext {
                        of_term: &self,
                        payloads: self.payloads.as_ref().unwrap(),
                        path: path.clone(),
                    });
                }

                // If there are payloads to replace in self, then we will *likely* have to know the encoding of self, we save it for later in eval_tree
                if with_payloads && (!all_payloads.is_empty() || sibling_has_payloads) {
                    eval_tree.args = eval_tree_args;
                    if let Ok(eval) = PB::any_get_encoding(&result) {
                        trace!("        / We successfully evaluated the term into: {eval:?}");
                        eval_tree.encode = Some(eval);
                    } else {
                        if path.is_empty() {
                            return (Err(Error::Term(format!("[eval_until_opaque] Could not any_get_encode an app term at root position, which has payloads to replace. Current term: {}", &self.term)))
                                .map_err(|e| {
                                    error!("[eval_until_opaque] Err: {}", e);
                                    e
                                }));
                        } else {
                            // we might not need this eval later, we will try to replace payloads without using it // TODO: make sure we resist this!
                            warn!("[eval_until_opaque] Could not any_get_encode a sub-term at path {path:?}, sub-term:\n{}", &self.term);
                        }
                    }
                }

                Ok((result, all_payloads))
            }
        }
    }
}

/// Return the first matching position i such that `haystack[i..i + needle.len()] == needle[..]`
pub fn search_sub_vec(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    for i in 0..haystack.len() - needle.len() + 1 {
        if haystack[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
    }
    None
}

/// Return the first matching position and whether it is unique (true) or not (false)
pub fn search_sub_vec_double(haystack: &[u8], needle: &[u8]) -> Option<(usize, bool)> {
    if haystack.len() < needle.len() {
        // trace!("search_sub_vec_double: length");
        return None;
    }
    for i in 0..haystack.len() - needle.len() + 1 {
        if haystack[i..i + needle.len()] == needle[..] {
            // trace!("search_sub_vec_double: found for i:{i}");
            return Some((i, search_sub_vec(&haystack[i + 1..], needle).is_none()));
        }
    }
    // trace!("search_sub_vec_double: not found");
    None
}

/// Sum the first `cap` bytes in the bytes-vector `v`
pub fn sum_vec_cap(v: &[u8], cap: usize) -> usize {
    let mut acc = 0;
    for i in 0..min(v.len(), cap) {
        acc += v[i] as usize;
    }
    return acc;
}
