use std::{
    any::{Any, TypeId},
    borrow::{
        Cow,
        Cow::{Borrowed, Owned},
    },
    cmp::{max, min},
    fmt::{format, Display, Formatter},
    ops::Deref,
};

use anyhow::Context;
use derivative::Derivative;
use libafl::inputs::{BytesInput, HasBytesVec};
use log::{debug, error, trace, warn};
use serde::{Deserialize, Serialize};

use crate::{
    algebra::{dynamic_function::TypeShape, ConcreteMessage, Matcher, Term, TermEval, TermType},
    error::Error,
    fuzzer::utils::{find_term_by_term_path, TermPath},
    protocol::ProtocolBehavior,
    trace::{Trace, TraceContext},
};

/// Constants governing heuritics for finding payloads in term evaluations
const THRESHOLD_SUM: usize = 40;
const THRESHOLD_RATIO: usize = 4;
const ATT_BEFORE_FALLBACK: usize = 10;
const ATT_BEFORE_FAIL: usize = 30;
const ATT_TOTAL_BEFORE_FAIL: usize = 40;

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

/// Useful struct to store local state when searching for a payload (to_search) in a window
#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct StatusSearch<'a, M: Matcher> {
    total_attempts: usize,       // total attempts so far
    path_to_search: &'a [usize], // path of the sub-term corresponding to `to_search` in `whole_term`
    path_window: &'a [usize],    // path of the sub-term corresponding to `window` in `whole_term`
    found_window: bool, // whether the current window has successfully been located (`pos_of_window` has been updated)
    unique_window: bool, // whether the current window has **uniquely** been located
    found_match: bool,  // whether `to_search` has been found in the current window
    unique_match: bool, // whether `to_search` has been **uniquely** been located
    pos_of_window: usize, // position of the window with respect to the whole term evaluation
    pos_in_window: usize, // position of `to_search` with respect to the current window
    tried_depth_path: Vec<bool>, // already tried path depths for the window (avoid cycling back)
    to_search: &'a [u8], // slice to be searched in the window
    window: &'a [u8],   // window where to look for `to_search`
    #[derivative(Debug = "ignore")]
    eval_tree: &'a EvalTree,
    #[derivative(Debug = "ignore")]
    whole_term: &'a TermEval<M>,
}

impl<'a, M: Matcher> StatusSearch<'a, M> {
    fn new(
        to_search: &'a [u8],
        path_to_search: &'a [usize],
        window: &'a [u8],
        path_window: &'a [usize],
        eval_tree: &'a EvalTree,
        whole_term: &'a TermEval<M>,
    ) -> Self {
        let mut tried_depth_path = Vec::new();
        tried_depth_path.resize(path_to_search.len(), false);
        StatusSearch {
            to_search,
            path_to_search,
            window,
            path_window,
            found_window: true,
            unique_window: true,
            found_match: false,
            unique_match: true,
            pos_of_window: 0,
            pos_in_window: 0,
            tried_depth_path,
            eval_tree,
            whole_term,
            total_attempts: 0,
        }
    }
}

/// Try to recover the evaluation from @eval_tree and, if this fails because we have not computed it in the past,
/// then we evaluate the corresponding sub-term.
pub fn eval_or_compute<'a, M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    path_to_eval: &[usize],
    eval_tree: &'a EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
) -> Result<Cow<'a, ConcreteMessage>, Error> {
    match eval_tree.get(&path_to_eval)?.encode.as_ref() {
        Some(eval) => Ok(Borrowed(eval)),
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
            Ok(Owned(PB::any_get_encoding(&sibling_eval_box)?))
        }
    }
}

/// Search and locate `to_search` (`eval_tree[path_to_search].encode`) in root_eval:=eval_tree[vec![]].encode (=whole_term.encode(ctx))
/// such that the match is unique in a window corresponding to the evaluation of a sub-term at a path
/// in between vec![] (root) and `path_to_search`. Return the position of the match in `root_eval`.
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
    debug!("[find_unique_match] ## Start with path {path_to_search:?},\n - to_search: {to_search:?}\n - root_eval: {root_eval:?}\n - whole_term:{whole_term}\n - eval_tree: {eval_tree:?}");
    find_unique_match_rec(
        StatusSearch::new(
            to_search,
            path_to_search,
            window,
            &path_to_search[0..0],
            eval_tree,
            whole_term,
        ),
        ctx,
    )
}

/// Goal: search and locate `st.to_search` in st.window: to_search == st.window[st.pos_in_window...X]
/// We must often refine the window (larger or smaller) as it is often the case to_search occurs multiple
/// times in the st.whole_term.evaluate.encode and we must find the correct occurrence, the one corresponding
/// to `path_to_search`.
/// Invariants:
/// - path_window is in between vec![] (root) and `path_to_search`
/// - window = eval_tree[path_window].encode.unwrap()
/// - window = eval_tree[vec![]].encode.unwrap()[pos_of_window..Y]
/// - to_search = eval_tree[path_to_search].encode.unwrap()
/// - if `found_match`, then `to_search` is found in `window` at position `pos_in_window`: to_search == window[pos_in_window..Z]
/// - if `found_window`, then try_new_path_window = path_window
/// - try_new_path_window = path_to_search[0..try_new_depth_path_window]
/// Therefore: to_search can be found in the whole bitstring (eval_tree[vec![]].encode.unwrap())
/// at pos `shift_window + pos_in_window`.
pub fn find_unique_match_rec<'a, M, PB>(
    mut st: StatusSearch<M>,
    ctx: &TraceContext<PB>,
) -> Result<usize, Error>
where
    M: Matcher,
    PB: ProtocolBehavior<Matcher = M>,
{
    debug!("[find_unique_match_rec] START ========\n {st:?}");
    trace!(" - whole_term: {}", st.whole_term);
    let mut try_new_depth_path_window = refine_window_heuristic(&st);
    let mut try_new_path_window = &st.path_to_search[0..try_new_depth_path_window];
    st.found_window = try_new_depth_path_window == 0; // no need to find the window if window=eval_root
    let eval_root = &st.eval_tree.encode.as_ref().unwrap()[..];

    let mut fallback_end_parent = false; // when basic heuristic fails, we fall back to searching the position relatively to the accumulation of all right siblings
    let mut fallback_empty = false; // when everything fails, we fall back to the solution for empty payload (relying on closest nodes)
    let mut attempts = 0; // while loop # attempts

    // Main while loop where we search for `to_search` in `eval_root` in a unique way (one match) by varying
    // the search window `window`
    while !(st.found_window && st.unique_match && st.found_match && st.unique_window) {
        if st.path_to_search.is_empty() {
            return Ok(0); // then to_search = window
        }

        if attempts > ATT_BEFORE_FAIL || attempts + st.total_attempts > ATT_TOTAL_BEFORE_FAIL {
            let ft = format!("[replace_payloads] [find_unique_match_rec] [MAX ATTEMPTS] Unable to find a match after {attempts} attempts.\n {st:?}");
            error!("{}", ft);
            return Err(Error::Term(ft));
        }

        // Prevent cycling larger -> smaller -> larger window, and fallback to other heuristics
        if attempts > 0 && !st.found_window && st.tried_depth_path[try_new_depth_path_window] {
            // we already tried to search for and locate this window!
            let ft = format!("[find_unique_match_rec] [CYCLING BACK] Unable to find a match after {attempts} attempts.\n {st:?}");
            warn!("{}", ft);
            fallback_end_parent = true;
        } else {
            st.tried_depth_path[try_new_depth_path_window] = true;
        }

        // initially found_match is false (not searched and found to_search yet)
        debug!("[find_unique_match_rec] ATTEMPT #{attempts} with fallback_end_parent: {fallback_end_parent}, fallback_empty:{fallback_empty}\n {st:?}");
        trace!(
            "  - whole_term: {}\n  - eval_tree: {:?}",
            st.whole_term,
            st.eval_tree
        );
        attempts += 1;
        if attempts > 3 {
            warn!("[find_unique_match_rec] HIGH NUMBER OF ATTEMPTS!");
        }

        // First fallback heuristic: compute right-shift with respect to the parent term evaluation
        if !fallback_empty && (fallback_end_parent || attempts > ATT_BEFORE_FALLBACK) {
            fallback_empty = true;
            if st.path_window.len() != st.path_to_search.len() - 1 {
                // this should be the case after a few iterations!
                fallback_empty = true;
                continue;
            }
            // We should address failing cases such as:
            // - to_search is included in header of parent term encoding (e.g., compression method is in header of ClientHello)
            // - to_search is included in siblings (e.g., same cipher suite repeated many times in a list)
            // Assumption: the formatting of t may add some header at the beginning, but no footer at the end
            //             so that t.encode = HEAD || [ti.encode]_i
            // Strategy: we compute the length of the evaluations of all siblings on the right and locate
            // to_search in the window of the parent term evaluation, shifting from the right by this
            // quantity.
            warn!("[find_unique_match_rec] Trying heuristic based on shift from the end of window {st:?}\n. Looking for the parent term at path {:?}", &st.path_to_search[0..st.path_to_search.len() - 1]);
            trace!("Whole_term {}", st.whole_term);
            let t_parent = find_term_by_term_path(
                st.whole_term,
                &st.path_to_search[0..st.path_to_search.len() - 1],
            )
            .ok_or({
                Error::Term(format!(
                    "[replace_payloads]  [find_unique_match_rec] Should never happen [Find Parent]"
                ))
            })?;

            if let Term::Application(_, args) = &t_parent.term {
                let arg_num = st.path_to_search[st.path_to_search.len() - 1];
                let mut acc = 0;
                let mut p = st.path_to_search.to_vec();
                for i in (arg_num..args.len()).rev() {
                    p[st.path_to_search.len() - 1] = i;
                    if let Ok(res) = eval_or_compute(&p, st.eval_tree, st.whole_term, ctx) {
                        trace!(
                            "[find_unique_match_rec] Argument {i} is {} bytes long",
                            res.deref().len()
                        );
                        acc += res.deref().len();
                        continue;
                    } else {
                        fallback_empty = true; // some failure happened, fallback to the final heuristic
                        break;
                    }
                }
                if !fallback_empty {
                    st.found_match = true;
                    st.unique_match = true;
                    debug!("[replace_payloads] [find_unique_match_rec] Found a shift of {acc} for arg number {arg_num} in\n {t_parent}");
                    st.pos_in_window = st.window.len() - acc;
                } else {
                    continue;
                }
            } else {
                return Err(Error::Term(format!(
                    "[find_unique_match_rec] Should never happen [Var]"
                )));
            }
        }

        // Second fallback heuristic: locate a sibling
        if st.to_search.is_empty() || fallback_empty {
            warn!(
                "[[replace_payloads] ] Empty to_search or fallback mode, looking for a relative!"
            );
            // to_search is empty, there is no way to locate it directly.
            // Instead, we compute and locate the closest sibling having a non-empty evaluation
            // and locate to_search relatively to the latter.
            // Spec: path_relative refers to the closest sibling having a non-empty encoding (on the left or on the right)
            let (path_relative, eval_relative_, relative_on_left) =
                find_relative_node(st.path_to_search, st.eval_tree, st.whole_term, ctx)?;
            let eval_relative = eval_relative_.deref();
            trace!("[replace_payloads] ] Found a relative at path {path_relative:?}, is_on_the_left:{relative_on_left}\n eval_relative: {eval_relative:?}");

            let mut st2 = StatusSearch::new(
                eval_relative,
                &path_relative,
                eval_root,
                &path_relative[0..0],
                st.eval_tree,
                st.whole_term,
            );
            st2.total_attempts += attempts + st.total_attempts;

            let pos_relative_in_root = find_unique_match_rec(st2, ctx)?;

            return if relative_on_left {
                Ok(pos_relative_in_root + eval_relative.len())
            } else {
                Ok(pos_relative_in_root)
            };
        }

        // Main heuristic: STEP 1 LOCATE THE NEW WINDOW
        if !st.found_window {
            // then we need to compute and search for the new window
            debug!(
                "[find_unique_match_rec] NEW WINDOW: from {:?} to {try_new_path_window:?}",
                st.path_window
            );
            st.found_match = false;
            st.found_window = false;
            let new_window_eval_tree = st.eval_tree.get(try_new_path_window)?;
            if let Some(new_window_eval) = &new_window_eval_tree.encode {
                debug!("[find_unique_match_rec] window has encoding");
                if let Some((pos_w, unique_w)) = search_sub_vec_double(eval_root, new_window_eval) {
                    debug!("[find_unique_match_rec] found the window");
                    if unique_w {
                        debug!("[find_unique_match_rec] unique window match");
                        // refining window succeeds!
                        st = StatusSearch {
                            found_window: true,
                            unique_window: true,
                            pos_of_window: pos_w,
                            ..st
                        };
                        st.window = new_window_eval;
                        st.path_window = try_new_path_window;
                        debug!(
                            "[find_unique_match_rec] Found window and is unique. New window with path_window:{:?}",
                            st.path_window
                        );
                        // We should now look for to_search in this window
                        continue;
                    } else {
                        // window found twice, it is too small, we reduce the try_new_path_depth
                        debug!("[find_unique_match_rec] not unique window match");
                        st.found_window = true;
                    }
                } else {
                    // not found, we leave st unmodified (with st.found_window = false)
                    debug!("[find_unique_match_rec] window not found");
                }
                let mut st2 = st.clone();
                st2.window = new_window_eval;
                st2.path_window = try_new_path_window;
                try_new_depth_path_window = refine_window_heuristic(&st2);
                try_new_path_window = &st.path_to_search[0..try_new_depth_path_window];
                st.found_window = false;
                debug!("[find_unique_match_rec] New window with try_new_path_window:{try_new_path_window:?}, path_window was {:?}", st.path_window);
                continue;
            } else {
                // Was not able to encode this sub-message
                let ft = format!("[replace_payloads] [find_unique_match_rec] Unable to find a window due to missing evaluation on EvalTree.\n - to_search:{:?}\n - eval_root:{:?}\n - path_to_search:{:?}\n - eval_tree:{:?}",
                                 st.to_search, eval_root, st.path_to_search, st.eval_tree);
                error!("{}", ft);
                return Err(Error::Term(ft));
            }
        }

        // Main heuristic: STEP 2 `to_search` in `window`
        if !st.found_match {
            if let Some((pos, unique)) = search_sub_vec_double(&st.window, st.to_search) {
                debug!("[find_unique_match_rec] to_search was found in window");
                st.found_match = true;
                if unique {
                    debug!("[find_unique_match_rec] to_search was uniquely found in window");
                    st.unique_match = true;
                    st.pos_in_window = pos;
                } else {
                    // to_search was found twice, we need to refine the search window
                    debug!("[find_unique_match_rec] to_search was not uniquely found in window");
                    st.unique_match = false; // will yield a deeper path_sub and hence narrower window at the next iteration
                    let try_new_depth_path_window = refine_window_heuristic(&st);
                    try_new_path_window = &st.path_to_search[0..try_new_depth_path_window];
                    st.found_window = false;
                    debug!("[find_unique_match_rec] Found match but not unique. New window with try_new_path_window:{try_new_path_window:?}");
                    continue;
                }
            } else {
                let ft = format!("[replace_payloads] [find_unique_match_rec] Unable to find a to_search in current window. Should never happen!\n - to_search:{:?}\n -window: {:?}\n - in_eval:{:?}\n - path:{:?}\n - eval_tree:{:?}",
                                 st.to_search, st.window, eval_root, st.path_to_search, st.eval_tree);
                error!("{}", ft);
                return Err(Error::Term(ft));
            }
        }
    }
    debug!(
        "[find_unique_match_rec] ## END found a match for {:?} at {}",
        st.path_to_search,
        st.pos_of_window + st.pos_in_window
    );
    Ok(st.pos_of_window + st.pos_in_window)
}

/// Search relative node. Spec: returns the path p to a node such that all nodes whose path is
///  - strictly between p and path_to_search (according to the lexicographic order)
///  - and that is not a descendant of p
/// has an empty encoding.
/// For example: if p is the closest cousin on the left, then all siblings on the left of path_to_search must have an empty
/// encoding.
/// Returns p, and whether the encoding of path_to_search comes after the one of p (true) or before (false).
/// For instance, if p is an ancestor of path_to_search then it will be false.
/// If p is a sibling, then it depends whether it is on the left (true) or on the right (false) of path_to_search.
pub fn find_relative_node<'a, M: Matcher, PB: ProtocolBehavior<Matcher = M>>(
    path_to_search: &[usize],
    eval_tree: &'a EvalTree,
    whole_term: &TermEval<M>,
    ctx: &TraceContext<PB>,
) -> Result<(TermPath, Cow<'a, ConcreteMessage>, bool), Error> {
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
            if !eval_sib.deref().is_empty() {
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
            if !eval_sib.deref().is_empty() {
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

/// Return the depth of the path we should look for the next window, given the current StatusSearch and
/// notably the current window path depth. This is following best efforts heuristics.
pub fn refine_window_heuristic<M: Matcher>(st: &StatusSearch<M>) -> usize {
    let window_len = st.window.len();
    let current_depth = st.path_window.len();
    if st.path_to_search.is_empty() {
        trace!("[refine_window_heuristic] only possible window candidate is the root");
        return 0;
    }
    if st.to_search.is_empty() {
        trace!("[refine_window_heuristic] will be handled with a specific routine anyway");
        return max(0, st.path_to_search.len() - 1);
    }
    if window_len == 0 {
        trace!("[refine_window_heuristic] window is too narrow, we decrease the depth (= increases window)");
        return max(0, current_depth - 1);
    }
    if !st.found_window {
        trace!("[refine_window_heuristic] window might be too large or just at a sub-term for which encoding is not meaningful, go narrower");
        return min(st.path_to_search.len() - 1, current_depth + 1);
    }
    if !st.unique_window {
        trace!("[refine_window_heuristic] window is too narrow, we decreases the depth");
        return max(0, current_depth - 1);
    }
    if st.to_search.len() > 4
        || sum_vec_cap(st.to_search, 2) >= THRESHOLD_SUM
        || window_len / st.to_search.len() <= THRESHOLD_RATIO
    {
        if !st.unique_match {
            trace!("[refine_window_heuristic] the below failed, so we go to the first child {}, was {current_depth}, path_to_search: {:?}", min(st.path_to_search.len(), current_depth + 1), st.path_to_search);
            return min(st.path_to_search.len() - 1, current_depth + 1);
        } else {
            trace!("[refine_window_heuristic] we keep as it is --> search in the whole window");
            return current_depth;
        }
    } else if st.to_search.len() > 2
        || sum_vec_cap(st.to_search, 1) >= THRESHOLD_SUM / 2
        || window_len / st.to_search.len() <= THRESHOLD_RATIO * 2
    {
        if !st.unique_match {
            trace!("[refine_window_heuristic] the below failed, so we go halfway");
            return min(
                st.path_to_search.len() - 1,
                max(
                    current_depth + 1,
                    (st.path_to_search.len() - current_depth) / 2,
                ),
            );
        } else {
            trace!("[refine_window_heuristic] we go a quarter");
            return min(
                st.path_to_search.len() - 1,
                max(
                    current_depth + 1,
                    (st.path_to_search.len() - current_depth) / 4,
                ),
            );
        }
    } else {
        trace!("[refine_window_heuristic] not empty but very unlikely we found uniquely except in window path[0..len-1]");
        if !st.unique_match {
            return max(0, st.path_to_search.len() - 1);
        } else {
            return min(
                // TODO: this slight optimization (trying st.path_to_search.len() -2) has not been benchmarked/measured
                st.path_to_search.len() - 1,
                max(current_depth + 1, max(st.path_to_search.len(), 2) - 2),
            );
        }
    }
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
                "[replace_payloads] Payloads returned by eval_until_opaque were inconsistent!\n\
                   - term: {term}\n\
                   - to_replace[start..end].to_vec() = !to_modify[{start}..{end}].to_vec() = {:?}\n\
                   - payload.payload_0.bytes() = {:?}\n\
                   - to_modify={to_modify:?}\n\
                   - payload_context: {payload_context:?}",
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
