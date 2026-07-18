# Implementation Plan — Relaxed `ReplaceMatchMutator` (sub-signature replacement)

## Goal
Generalize the Dolev-Yao `ReplaceMatchMutator` so it can replace a function symbol `F`
with a different symbol `G` whenever **`G`'s argument types are a sub-multiset of `F`'s
argument types** (and the return types match), instead of requiring an *exact* signature
match. `F`'s existing child subterms then supply `G`'s arguments (by type); surplus
children are dropped. Exact-arity replacement becomes the special case where the two
argument multisets are equal.

Motivation: the current exact-match rule only lets a term be swapped for another of the
*identical* signature. A nullary symbol (e.g. `fn_encrypt_then_mac_extension`) can only
replace another nullary symbol of the same return type. The relaxed rule lets any
lower-arity compatible symbol replace a richer one — broadly increasing mutation
expressiveness (e.g. "simplify" any `ClientExtension` term to a marker extension, reusing
a subset of its children).

## Current code (to change)
`puffin/src/fuzzer/mutations.rs`, `impl Mutator for ReplaceMatchMutator::mutate`, the
`DYTerm::Application` arm (≈ lines 350–365):

```rust
DYTerm::Application(func_mut, _) => {
    if let Some((shape, dynamic_fn)) = self.signature.functions.choose_filtered(
        |(shape, _)| {
            func_mut.shape() != shape
                && func_mut.shape().return_type == shape.return_type
                && func_mut.shape().argument_types == shape.argument_types   // EXACT
        },
        rand,
    ) {
        func_mut.change_function(shape.clone(), dynamic_fn.clone());          // keeps children
        Ok(MutationResult::Mutated)
    } else { Ok(MutationResult::Skipped) }
}
```

`func_mut.change_function(shape, dynamic_fn)` (`puffin/src/algebra/atoms.rs:181`) swaps only
the function symbol and **keeps the existing children** — correct only when arities match.

## Relevant APIs (already available)
- `DYTerm::Application(Function<PT>, Vec<Term<PT>>)` — symbol + child subterms
  (`puffin/src/algebra/term.rs:38`). Child `i` has type `F.shape().argument_types[i]`.
- `Function::shape() -> &DynamicFunctionShape<PT>` with fields
  `argument_types: Vec<TypeShape<PT>>`, `return_type: TypeShape<PT>`
  (`puffin/src/algebra/dynamic_function.rs:99`).
- `TypeShape<PT>` is `Clone + Eq + Hash` (`dynamic_function.rs:320–333`) — usable for
  multiset comparison.
- `Function::new(shape, dynamic_fn)` (`atoms.rs:139`) + `Term::from(DYTerm::Application(..))`
  to build a replacement node.
- The `DYTerm::Variable` arm already demonstrates replacing the whole term via
  `to_mutate.mutate(Term::from(DYTerm::Application(Function::new(shape, dfn), Vec::new())))`.

## Proposed change

### 1. Relax the candidate filter
Replace the exact `argument_types ==` test with a sub-multiset test:

```rust
func_mut.shape() != shape
    && func_mut.shape().return_type == shape.return_type
    && is_sub_multiset(&shape.argument_types, &func_mut.shape().argument_types)
```

### 2. Reconstruct `G`'s children from `F`'s children (by type)
Because the child list must now change, bind the children in the match
(`DYTerm::Application(func_mut, args)`), and after choosing `G`, build its child vector by
selecting, for each of `G`'s argument types in order, an as-yet-unused child of `F` whose
type matches — cloning it. The sub-multiset invariant guarantees a match always exists.
Then replace the whole node:

```rust
let new_children = select_children_by_types(
    &func_mut.shape().argument_types, args, &shape.argument_types);
to_mutate.mutate(Term::from(DYTerm::Application(
    Function::new(shape.clone(), dynamic_fn.clone()), new_children)));
```

Drop `change_function` from this arm (it can't rebuild children).

### 3. Two small helpers (file-local, in `mutations.rs`)
```rust
/// true iff every element of `sub` appears in `sup` with at least equal multiplicity
fn is_sub_multiset<T: Eq + std::hash::Hash>(sub: &[T], sup: &[T]) -> bool {
    let mut counts: std::collections::HashMap<&T, usize> = std::collections::HashMap::new();
    for t in sup { *counts.entry(t).or_insert(0) += 1; }
    for t in sub {
        match counts.get_mut(t) { Some(n) if *n > 0 => *n -= 1, _ => return false }
    }
    true
}

/// For each type in `to_types`, pick (and consume) the first unused child of `F`
/// whose declared type matches, cloning it. Precondition: `to_types ⊆ from_types`.
fn select_children_by_types<PT: ProtocolTypes>(
    from_types: &[TypeShape<PT>], from_children: &[Term<PT>], to_types: &[TypeShape<PT>],
) -> Vec<Term<PT>> {
    let mut used = vec![false; from_children.len()];
    let mut out = Vec::with_capacity(to_types.len());
    for t in to_types {
        if let Some(i) = (0..from_children.len()).find(|&i| !used[i] && &from_types[i] == t) {
            used[i] = true;
            out.push(from_children[i].clone());
        }
    }
    out
}
```
(`TypeShape` import from `crate::algebra::dynamic_function::TypeShape`.)

## Borrow-checker note
`func_mut` and `args` both borrow `to_mutate.term`. Compute the chosen `shape`/`dynamic_fn`
(owned clones) and `new_children` (owned clones) **before** calling `to_mutate.mutate(..)`,
so the `&mut to_mutate.term` borrow ends first (non-lexical lifetimes). If the borrow
checker complains, hoist `func_mut.shape().clone()` into a `let from_shape = ...;` at the
top of the arm and use `from_shape` in the closure and reconstruction (removing the live
`func_mut` borrow inside `choose_filtered`).

## Behaviour preservation
- Exact-arity replacement is preserved: when `G.argument_types == F.argument_types`,
  `select_children_by_types` returns all children in order (identical to today).
- Return-type constraint unchanged, so terms stay well-typed and the trace stays
  evaluable.
- `func_mut.shape() != shape` still forbids replacing a symbol with itself.

## Testing
1. **Compile:** `cargo build --release --bin tlspuffin --features cputs`
   (edge-map env vars per `evaluation-ddyf/fingerprinting/setup.sh`).
2. **No regression:** run the existing DY-mutation unit tests
   (`cargo test -p puffin mutations`), plus `display-execute` / `differential-execute` on a
   standard seed to confirm traces still evaluate.
3. **New unit test:** construct a term `F(child_a: A, child_b: B)` and a signature
   containing `G(: A) -> ret(F)`; assert `ReplaceMatchMutator` can produce
   `G(child_a)` (surplus `child_b` dropped) and that the result type-checks.
4. **Expressiveness check:** confirm a nullary marker (e.g. `fn_encrypt_then_mac_extension`)
   can now replace a non-nullary `ClientExtension` (e.g. `fn_renegotiation_info_extension`,
   which takes a `PayloadU8`) — impossible under the exact-match rule.

## Scope / non-goals
- Only `ReplaceMatchMutator`'s `Application` arm changes. The `Variable` arm (already handles
  variable → constant) is untouched.
- Multiset selection is greedy/first-match; it does not try all assignments. That is
  sufficient (the invariant guarantees a valid assignment exists) and keeps the mutation O(n·m).
- **Not required for the Encrypt-then-MAC finding.** Empirically the fuzzer already inserts
  `fn_encrypt_then_mac_extension` abundantly under the exact-match rule (the base
  `seed_client_attacker12` carries two nullary `ClientExtension` slots — SCT and
  ec_point_formats — and DDYF rediscovered the EtM distinguisher within seconds). This
  change is a general mutation-power improvement, valuable on its own merits, not a fix for
  that specific case.
