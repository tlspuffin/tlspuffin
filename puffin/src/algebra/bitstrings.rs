use libafl::inputs::{BytesInput, HasBytesVec};
use serde::{Deserialize, Serialize};

use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::{ConcreteMessage, DYTerm, Term, TermType};
use crate::error::Error;
use crate::fuzzer::utils::TermPath;
use crate::protocol::{EvaluatedTerm, ProtocolBehavior, ProtocolTypes};
use crate::trace::{Source, TraceContext};

/// `Term`s are `Term`s equipped with optional `Payloads` when they no longer are treated as
/// symbolic terms.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payloads {
    pub payload_0: BytesInput, // initially both are equal and correspond to the term evaluation
    pub payload: BytesInput,   // this one will later be subject to bit-level mutation
}
impl Payloads {
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload_0.bytes().len()
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
                "[replace_payloads] [get] Should never happen! EvalTree: {self:?}\n, path: {path:?}"
            )));
        }
        self.args[nb].get(path)
    }
}

/// Operate the payloads replacements in `eval_tree.encode`[vec![]] and returns the modified
/// bitstring. `@payloads` follows this order: deeper terms first, left-to-right, assuming no
/// overlap (no two terms one being a sub-term of the other).
pub fn replace_payloads<PT: ProtocolTypes, PB: ProtocolBehavior<ProtocolTypes = PT>>(
    _term: &Term<PT>,
    _eval_tree: &mut EvalTree,
    _payloads: Vec<PayloadContext<PT>>,
    _ctx: &TraceContext<PB>,
) -> Result<ConcreteMessage, Error> {
    todo!("Done in another PR (bit mutations/term-evaluation)");
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
        log::debug!("[eval_until_opaque] [START]: Eval term:\n {self}");
        if let (true, Some(payload)) = (with_payloads, &self.payloads) {
            // TODO: investigate whether this value could be incorrect due to modifications to the
            // terms through mutations previously applied
            log::trace!("[eval_until_opaque] Trying to read payload_0 to skip further computations...........");
            if let Ok(di) = PB::try_read_bytes(
                payload.payload_0.bytes(),
                <TypeShape<PT> as Clone>::clone(type_term).into(),
            ) {
                let p_c = vec![PayloadContext {
                    of_term: self,
                    payloads: payload,
                    path: eval_tree.path.clone(),
                }];
                eval_tree.encode = Some(payload.payload_0.bytes().to_vec());
                return Ok((di, p_c));
            }
            log::trace!("[eval_until_opaque] Attempt to skip evaluation failed, fall back to normal evaluation...");
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
                    .ok_or_else(|| Error::Term(format!("Unable to find variable {variable}!")))?;
                if with_payloads && (eval_tree.path.is_empty() || (self.payloads.is_some())) {
                    if let Some(payload) = &self.payloads {
                        log::trace!("        / We retrieve evaluation for eval_tree from payload.");
                        eval_tree.encode = Some(payload.payload_0.clone().into());
                    } else {
                        let eval = PB::any_get_encoding(d.as_ref());
                        log::trace!("        / No payload so we evaluated into: {eval:?}");
                        eval_tree.encode = Some(eval);
                    }
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
                        let bi = ti.evaluate(ctx)?; // payloads in ti are consumed here!
                        let typei = func.shape().argument_types[i].clone();
                        let di = PB::try_read_bytes(&bi, typei.clone().into()) // TODO: to make this more robust, we might want to relax this when payloads are in deeper terms, then read there!
                            .map_err(|e| {
                                if !ti.is_symbolic() {
                                    log::warn!("[eval_until_opaque] [Argument has payload, might explain why] Warn: {}", e);
                                } else {
                                    log::warn!("[eval_until_opaque] [Argument is symbolic!] Err: {}", e);
                                }
                                e
                            })?;
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

                // If there are payloads to replace in self, then we will *likely* have to know the
                // encoding of self, we save it for later in eval_tree
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
