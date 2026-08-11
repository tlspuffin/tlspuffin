//! Signature infrastructure: the [`Signature`] type and the
//! [`crate::declare_signature!`] / [`crate::define_signature!`] macro pair that populate it
//! at link time via [`linkme`] distributed slices.
//!
//! # Overview
//!
//! A [`Signature`] is a registry of [`DynamicFunction`]s, indexed by name and
//! return type. It is built lazily at start-up from all functions contributed
//! through [`crate::define_signature!`] calls anywhere in the linked binary.
//!
//! ## Workflow
//!
//! ### 1 – Declare once
//!
//! Call [`crate::declare_signature!`] once per signature, typically in the protocol
//! crate's root module:
//!
//! ```rust,ignore
//! declare_signature!(MY_SIGNATURE<MyProtocolTypes>);
//! ```
//!
//! This emits a `pub static MY_SIGNATURE: StaticSignature<MyProtocolTypes>` and
//! a companion [`linkme::distributed_slice`] `MY_SIGNATURE_FNDEFS` that collects
//! contributions from across the binary.
//!
//! ### 2 – Register from anywhere
//!
//! Call [`crate::define_signature!`] with the signature name from any module or crate.
//! The `_FNDEFS` suffix is appended automatically:
//!
//! ```rust,ignore
//! // Same module:
//! define_signature!(MY_SIGNATURE, MyProtocolTypes;
//!     fn_hello
//!     fn_world
//! );
//!
//! // Different module in the same crate:
//! define_signature!(crate::protocol::MY_SIGNATURE, MyProtocolTypes;
//!     fn_something_else [opaque]
//! );
//! ```
//!
//! All contributions are merged at link time; no central list is required.
//!
//! ## Function flags
//!
//! An optional `[flag]` annotation after each function name sets a field of
//! [`FunctionAttributes`]:
//!
//! | Flag | Effect |
//! |------|--------|
//! | `opaque` | [`FunctionAttributes::is_opaque`] |
//! | `list` | [`FunctionAttributes::is_list`] |
//! | `get` | [`FunctionAttributes::is_get`] |
//! | `no_gen` | [`FunctionAttributes::no_gen`] |
//! | `no_bit` | [`FunctionAttributes::no_bit`] |
//! | `no_det` | [`FunctionAttributes::no_det`] |

use std::any::TypeId;
use std::collections::HashMap;

use itertools::Itertools;
use libafl_bolts::rands::Rand;
use once_cell::sync::Lazy;

use super::atoms::Function;
use crate::algebra::atoms::Variable;
use crate::algebra::dynamic_function::{
    make_dynamic, DescribableFunction, DynamicFunction, DynamicFunctionShape, FunctionAttributes,
    TypeShape,
};
use crate::algebra::readable_types::{ReadableTypeDefinition, ReadableTypes};
use crate::algebra::Matcher;
use crate::error::Error;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};
use crate::trace::{Query, Source};

pub type FunctionDefinition<PT> = (DynamicFunctionShape<PT>, Box<dyn DynamicFunction<PT>>);

/// A factory function that produces a batch of [`FunctionDefinition`]s together with their
/// [`FunctionAttributes`]. One or more of these are stored in a [`linkme::distributed_slice`] so
/// that multiple crates / modules can register functions into the same [`Signature`] without all
/// being listed in a single macro call.
pub type SignatureDefinitionFactory<PT> = fn() -> Vec<(FunctionDefinition<PT>, FunctionAttributes)>;

/// Records a universe of functions.
///
/// Signatures are containers for types and function symbols. They hold
/// references to the concrete implementations of functions and the types of
/// variables.
///
/// In normal use you do not construct a `Signature` directly; instead use
/// [`crate::declare_signature!`] (which creates a lazily-initialised [`StaticSignature`])
/// and populate it with one or more [`crate::define_signature!`] calls.
pub struct Signature<PT: ProtocolTypes> {
    pub functions_by_name: HashMap<&'static str, FunctionDefinition<PT>>,
    pub functions_by_typ: HashMap<TypeShape<PT>, Vec<FunctionDefinition<PT>>>,
    pub functions: Vec<FunctionDefinition<PT>>,
    pub types_by_name: HashMap<&'static str, TypeShape<PT>>,
    pub attrs_by_name: HashMap<&'static str, FunctionAttributes>,
    /// The types of this signature a bitstring can be read back into, see
    /// [`Self::try_read_bytes`]. Filled in by [`Self::with_readable_types`].
    pub readable_types: ReadableTypes<PT>,
    /// Minimal generation depth and size per function symbol, see [`Self::min_gen_depth`] and
    /// [`Self::min_gen_size`].
    min_cost_by_name: HashMap<&'static str, Cost>,
    /// Minimal generation depth and size per type, see [`Self::min_gen_depth_of_type`] and
    /// [`Self::min_gen_size_of_type`].
    min_cost_by_typ: HashMap<TypeShape<PT>, Cost>,
    /// Per type, the symbols returning it, ordered by increasing minimal depth, see
    /// [`Self::choose_function_within`].
    functions_by_typ_by_depth: HashMap<TypeShape<PT>, DepthOrdered<PT>>,
}

/// What building the cheapest closed term rooted at a symbol (or of a type) costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cost {
    /// Levels needed, in the sense of the term zoo's depth budget: `1` for a constant.
    depth: u16,
    /// Nodes needed, in the sense of [`crate::algebra::TermType::size`]: `1` for a constant.
    size: usize,
}

/// The symbols returning one given type, ordered by increasing minimal generation depth, so that
/// the ones that fit a depth budget are a prefix of `functions`.
struct DepthOrdered<PT: ProtocolTypes> {
    functions: Vec<FunctionDefinition<PT>>,
    /// `costs[i]` is the minimal cost of `functions[i]`; sorted by increasing depth.
    costs: Vec<Cost>,
}

impl<PT: ProtocolTypes> DepthOrdered<PT> {
    /// Uniformly picks one of the symbols that can build a closed term within both budgets.
    fn choose_within<R: Rand>(
        &self,
        depth: u16,
        size: usize,
        rand: &mut R,
    ) -> Option<&FunctionDefinition<PT>> {
        // Deep enough is a prefix (the costs are sorted by depth). Select uniformly among those
        // also fitting the size budget, using reservoir sampling in one pass.
        let deep_enough = self.costs.partition_point(|cost| cost.depth <= depth);
        let mut seen = 0usize;
        let mut chosen: Option<usize> = None;
        for (index, cost) in self.costs[..deep_enough].iter().enumerate() {
            if cost.size <= size {
                seen += 1;
                if rand.below_or_zero(seen) == 0 {
                    chosen = Some(index);
                }
            }
        }
        chosen.map(|index| &self.functions[index])
    }
}

impl<PT: ProtocolTypes> std::fmt::Debug for Signature<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "functions; {:?}", self.functions)
    }
}

impl<PT: ProtocolTypes> Signature<PT> {
    /// Construct a `Signature` from the given [`FunctionDefinition`]s.
    #[must_use]
    pub fn new(mut definitions: Vec<(FunctionDefinition<PT>, FunctionAttributes)>) -> Self {
        // Order the symbols by name before anything derives from them.
        //
        // `definitions` arrives from a `linkme::distributed_slice`, whose order is decided by the
        // *linker*: it varies with the toolchain, the target triple, the enabled features and the
        // codegen-unit layout.
        // Sorting allow to make the signature tests deterministic given a fixed RNG seed
        definitions.sort_by(|(a, _), (b, _)| a.0.name.cmp(b.0.name));
        debug_assert!(
            definitions
                .windows(2)
                .all(|w| w[0].0 .0.name != w[1].0 .0.name),
            "duplicate function symbol name in the signature: sorting would not be a total order"
        );

        let attrs_by_name: HashMap<&'static str, FunctionAttributes> = definitions
            .clone()
            .iter()
            .map(|((shape, _dynamic_fn), attrs)| (shape.name, *attrs))
            .collect();
        let functions_by_name: HashMap<&'static str, FunctionDefinition<PT>> = definitions
            .clone()
            .into_iter()
            .map(|((shape, dynamic_fn), _attrs)| (shape.name, (shape, dynamic_fn)))
            .collect();

        let functions_by_typ: HashMap<TypeShape<PT>, Vec<FunctionDefinition<PT>>> = definitions
            .clone()
            .into_iter()
            .map(|(fd, _attrs)| fd)
            .into_group_map_by(|(shape, _dynamic_fn)| shape.return_type.clone());

        let types_by_name: HashMap<&'static str, TypeShape<PT>> = definitions
            .clone()
            .into_iter()
            .map(|((shape, _dynamic_fn), _attrs)| {
                let used_types: Vec<TypeShape<PT>> = shape // vector of the argument shapes + return type
                    .argument_types
                    .iter()
                    .cloned()
                    .chain(vec![shape.return_type])
                    .collect::<Vec<TypeShape<PT>>>();
                used_types
            })
            .unique()
            .flatten()
            .map(|typ| (typ.name, typ))
            .collect();

        let (min_cost_by_name, min_cost_by_typ) = Self::compute_min_costs(&definitions);

        let functions_by_typ_by_depth = functions_by_typ
            .iter()
            .map(|(typ, functions)| {
                // Symbols with no closed term at any depth are dropped: no budget makes them
                // usable, and keeping them would put them in the deep-enough prefix.
                let mut ordered: Vec<(Cost, FunctionDefinition<PT>)> = functions
                    .iter()
                    .filter_map(|function| {
                        min_cost_by_name
                            .get(function.0.name)
                            .map(|cost| (*cost, function.clone()))
                    })
                    .collect();
                ordered.sort_by_key(|(cost, _)| cost.depth);
                let (costs, functions) = ordered.into_iter().unzip();
                (typ.clone(), DepthOrdered { functions, costs })
            })
            .collect();

        Self {
            functions_by_name,
            functions_by_typ,
            functions: definitions.into_iter().map(|(fd, _attrs)| fd).collect(),
            types_by_name,
            attrs_by_name,
            min_cost_by_name,
            min_cost_by_typ,
            functions_by_typ_by_depth,
            readable_types: ReadableTypes::new(vec![]),
        }
    }

    /// Least fixed point of
    /// - `depth(f) = 1 + max { depth(t) | t argument type of f }` (so `1` for a constant),
    /// - `size(f) = 1 + sum { size(t) | t argument type of f }` (so `1` for a constant),
    /// - `cost(t) = the pointwise min over the symbols returning t`.
    ///
    /// Symbols with an argument type no function can build, and the types only such symbols
    /// return, are absent from the returned maps: no closed term exists for them at any cost.
    fn compute_min_costs(
        definitions: &[(FunctionDefinition<PT>, FunctionAttributes)],
    ) -> (HashMap<&'static str, Cost>, HashMap<TypeShape<PT>, Cost>) {
        use std::collections::hash_map::Entry;

        /// Records `cost` for `key`, keeping the best of each component. Returns whether the map
        /// changed.
        fn improve<K: Eq + std::hash::Hash>(
            map: &mut HashMap<K, Cost>,
            key: K,
            cost: Cost,
        ) -> bool {
            match map.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(cost);
                    true
                }
                Entry::Occupied(mut entry) => {
                    let best = Cost {
                        depth: entry.get().depth.min(cost.depth),
                        size: entry.get().size.min(cost.size),
                    };
                    let changed = best != *entry.get();
                    entry.insert(best);
                    changed
                }
            }
        }

        let mut by_name: HashMap<&'static str, Cost> = HashMap::new();
        let mut by_typ: HashMap<TypeShape<PT>, Cost> = HashMap::new();

        // Each round either adds an entry or strictly decreases one, and both components are
        // bounded below by 1, so this terminates. In practice it converges in as many rounds as
        // the deepest chain of types, and it runs once per signature at start-up.
        loop {
            let mut changed = false;

            for ((shape, _dynamic_fn), _attrs) in definitions {
                let mut cost = Cost { depth: 1, size: 1 };
                let mut buildable = true;
                for argument in &shape.argument_types {
                    match by_typ.get(argument) {
                        Some(argument_cost) => {
                            cost.depth = cost.depth.max(argument_cost.depth.saturating_add(1));
                            cost.size = cost.size.saturating_add(argument_cost.size);
                        }
                        None => {
                            // No closed term for that argument type (yet)
                            buildable = false;
                            break;
                        }
                    }
                }
                if !buildable {
                    continue;
                }

                changed |= improve(&mut by_name, shape.name, cost);
                changed |= improve(&mut by_typ, shape.return_type.clone(), cost);
            }

            if !changed {
                break;
            }
        }

        (by_name, by_typ)
    }

    /// The minimal depth at which the term zoo can build a closed term rooted at `name`: `1` for a
    /// constant, `1 + max` over the argument types otherwise. Matches the budget accounting of
    /// [`crate::fuzzer::term_zoo`], so a generation attempt for `name` with a budget below this can
    /// only fail.
    ///
    /// `None` when no closed term is rooted at `name` at any depth (some argument type has no
    /// closed term), which also means `name` is unknown to this signature.
    #[must_use]
    pub fn min_gen_depth(&self, name: &str) -> Option<u16> {
        self.min_cost_by_name.get(name).map(|cost| cost.depth)
    }

    /// The size, in nodes, of the smallest closed term rooted at `name`: `1` for a constant,
    /// `1 + sum` over the argument types otherwise. Same conventions as [`Self::min_gen_depth`].
    #[must_use]
    pub fn min_gen_size(&self, name: &str) -> Option<usize> {
        self.min_cost_by_name.get(name).map(|cost| cost.size)
    }

    /// Same as [`Self::min_gen_depth`], for the shallowest closed term of the given type.
    #[must_use]
    pub fn min_gen_depth_of_type(&self, typ: &TypeShape<PT>) -> Option<u16> {
        self.min_cost_by_typ.get(typ).map(|cost| cost.depth)
    }

    /// Same as [`Self::min_gen_size`], for the smallest closed term of the given type.
    ///
    /// Note this is a lower bound rather than an achievable cost: the shallowest and the smallest
    /// term of a type need not be the same one, and the two components are minimised separately.
    #[must_use]
    pub fn min_gen_size_of_type(&self, typ: &TypeShape<PT>) -> Option<usize> {
        self.min_cost_by_typ.get(typ).map(|cost| cost.size)
    }

    /// Uniformly picks a symbol of the given type that the term zoo can build a closed term for
    /// within `depth` levels and `size` nodes.
    ///
    /// `None` when the type is unknown or when no symbol of that type is that cheap.
    pub fn choose_function_within<R: Rand>(
        &self,
        typ: &TypeShape<PT>,
        depth: u16,
        size: usize,
        rand: &mut R,
    ) -> Option<&FunctionDefinition<PT>> {
        self.functions_by_typ_by_depth
            .get(typ)?
            .choose_within(depth, size, rand)
    }

    /// Attach the types a bitstring can be read back into, as collected by
    /// [`crate::define_readable_types!`] and by the `Constructor` derive.
    ///
    /// Called by [`crate::declare_signature!`]; a `Signature` built by hand has an empty registry,
    /// so [`Self::try_read_bytes`] fails on every type until this is called.
    #[must_use]
    pub fn with_readable_types(mut self, definitions: Vec<ReadableTypeDefinition<PT>>) -> Self {
        self.readable_types = ReadableTypes::new(definitions);
        self
    }

    /// Read `bitstring` as the type identified by `ty`, one of this signature's registered types.
    ///
    /// See [`ReadableTypes::try_read_bytes`] for the failure modes.
    pub fn try_read_bytes(
        &self,
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<PT>>, Error> {
        self.readable_types.try_read_bytes(bitstring, ty)
    }

    /// Create a new [`Function`] distinct from all existing [`Function`]s.
    pub fn new_function<F: 'static + DescribableFunction<PT, Types>, Types>(
        f: &'static F,
    ) -> Function<PT> {
        let (shape, dynamic_fn) = make_dynamic(f);

        Function::new(shape, dynamic_fn.clone())
    }

    #[must_use]
    pub fn new_var_with_type<T: 'static, M: Matcher>(
        source: Option<Source>,
        matcher: Option<M>,
        counter: u16,
        is_claim: bool,
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let type_shape = TypeShape::<PT>::of::<T>();
        Self::new_var(type_shape, source, matcher, counter, is_claim)
    }

    #[must_use]
    pub fn new_var<M: Matcher>(
        type_shape: TypeShape<PT>,
        source: Option<Source>,
        matcher: Option<M>,
        counter: u16,
        is_claim: bool,
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let query = Query {
            source,
            matcher,
            counter,
            is_claim,
        };
        Variable::new(type_shape, query)
    }
}

/// A [`Lazy`]-wrapped [`Signature`], suitable for use as a `pub static`.
///
/// Created by [`crate::declare_signature!`] or [`create_static_signature`].
pub type StaticSignature<PT> = Lazy<Signature<PT>>;

/// Construct a [`StaticSignature`] from an initialiser closure.
///
/// This is a low-level helper used internally by [`crate::declare_signature!`].
/// Prefer the macro in application code.
pub const fn create_static_signature<PT: ProtocolTypes>(
    init: fn() -> Signature<PT>,
) -> StaticSignature<PT> {
    Lazy::new(init)
}

/// Declare a distributed [`Signature`] that can be populated by any number of
/// independent [`crate::define_signature!`] calls, including from different modules or
/// crates.
///
/// # What this emits
///
/// Three `pub static` items are created in the calling module:
///
/// | Name | Type | Purpose |
/// |------|------|---------|
/// | `$name` | [`StaticSignature<$pt>`] | The lazily-initialised signature. |
/// | `${name}_FNDEFS` | `linkme::DistributedSlice<[SignatureDefinitionFactory<$pt>]>` | Collects all registered function factories at link time. |
/// | `${name}_TYPEDEFS` | `linkme::DistributedSlice<[ReadableTypeFactory<$pt>]>` | Collects the types a bitstring can be read back into, see [`Signature::try_read_bytes`]. |
///
/// Users of the signature only ever interact with `$name`. The `_FNDEFS` and `_TYPEDEFS` slices
/// are an implementation detail; they are referenced internally by [`crate::define_signature!`]
/// and [`crate::define_readable_types!`] respectively, which append the suffix automatically.
///
/// # When to call
///
/// Call **once** per signature, typically in the protocol crate's top-level module
/// or `mod.rs`, before any [`crate::define_signature!`] contribution that targets it.
///
/// # Example
///
/// ```rust,ignore
/// // my_crate/src/tls/mod.rs
/// declare_signature!(TLS_SIGNATURE<TLSProtocolTypes>);
///
/// // Same or different module — contributes at link time:
/// define_signature!(TLS_SIGNATURE, TLSProtocolTypes;
///     fn_client_hello
///     fn_server_hello
/// );
///
/// // Another module in the same crate:
/// define_signature!(crate::tls::TLS_SIGNATURE, TLSProtocolTypes;
///     fn_certificate [opaque]
///     fn_certificate_verify [opaque]
/// );
/// ```
#[macro_export]
macro_rules! declare_signature {
    ($name:ident < $pt:ident >) => {
        $crate::paste::paste! {
            /// Distributed slice that accumulates all
            /// [`SignatureDefinitionFactory`](puffin::algebra::signature::SignatureDefinitionFactory)
            /// entries contributed by [`define_signature!`] for this signature.
            #[allow(non_upper_case_globals)]
            #[$crate::linkme::distributed_slice]
            pub static [<$name _FNDEFS>]: [
                $crate::algebra::signature::SignatureDefinitionFactory<$pt>
            ] = [..];

            /// Distributed slice that accumulates all
            /// [`ReadableTypeFactory`](puffin::algebra::readable_types::ReadableTypeFactory)
            /// entries contributed by [`define_readable_types!`] — and by the `Constructor`
            /// derive — for this signature.
            #[allow(non_upper_case_globals)]
            #[$crate::linkme::distributed_slice]
            pub static [<$name _TYPEDEFS>]: [
                $crate::algebra::readable_types::ReadableTypeFactory<$pt>
            ] = [..];

            /// Lazily-initialised signature built from every
            /// [`define_signature!`] contribution that references `[<$name _FNDEFS>]`, with the
            /// readable types from every contribution that references `[<$name _TYPEDEFS>]`.
            pub static $name: $crate::algebra::signature::StaticSignature<$pt> =
                $crate::algebra::signature::create_static_signature(|| {
                    let definitions: ::std::vec::Vec<_> = [<$name _FNDEFS>]
                        .iter()
                        .flat_map(|f| f())
                        .collect();
                    let readable_types: ::std::vec::Vec<_> = [<$name _TYPEDEFS>]
                        .iter()
                        .flat_map(|f| f())
                        .collect();
                    $crate::algebra::signature::Signature::new(definitions)
                        .with_readable_types(readable_types)
                });
        }
    };
}

/// Register a batch of functions into a [`Signature`] declared by
/// [`crate::declare_signature!`].
///
/// All contributions from every call site in the linked binary are merged at
/// link time via [`linkme`]; no central list is required.
///
/// # Syntax
///
/// ```text
/// define_signature!([prefix::] NAME, ProtocolType;
///     fn_one
///     fn_two [flag]
///     fn_three
/// );
/// ```
///
/// `NAME` is the **signature name** as given to [`crate::declare_signature!`]; the
/// `_FNDEFS` suffix is appended automatically. An optional module path prefix
/// (e.g. `crate::tls::`) is supported for cross-module registrations.
///
/// # Examples
///
/// ```rust,ignore
/// // Declare once in tls/mod.rs:
/// declare_signature!(TLS_SIGNATURE<TLSProtocolTypes>);
///
/// // Register from the same module:
/// define_signature!(TLS_SIGNATURE, TLSProtocolTypes;
///     fn_true
///     fn_false
///     fn_large_bytes_vec [no_bit]
/// );
///
/// // Register from a different module in the same crate:
/// define_signature!(crate::tls::TLS_SIGNATURE, TLSProtocolTypes;
///     fn_certificate [opaque]
///     fn_certificate_verify [opaque]
/// );
/// ```
///
/// # Function flags
///
/// Append `[flag]` after a function name to set a field of
/// [`FunctionAttributes`]:
///
/// | Flag | Attribute field |
/// |------|-----------------|
/// | `opaque` | `is_opaque` |
/// | `list` | `is_list` |
/// | `get` | `is_get` |
/// | `no_gen` | `no_gen` |
/// | `no_bit` | `no_bit` |
/// | `no_det` | `no_det` |
///
/// # Constraints
///
/// Function names must be simple identifiers; bring module-qualified functions
/// into scope with `use` first. Within the same scope, the same set of function
/// names must not be registered twice for the same signature — that would
/// generate a duplicate static-name compile error.
#[macro_export]
macro_rules! define_signature {
    // Forwards to the tt-munching helper which:
    //   1. Walks any leading `segment ::` tokens into an accumulator.
    //   2. Appends `_FNDEFS` to the final identifier via paste! to form
    //      the distributed-slice path.
    //   3. Emits the static linkme registration.
    //
    // A single `$($prefix:tt ::)* $name:ident` pattern cannot be used here
    // because Rust's macro parser reports a local ambiguity when deciding
    // whether a bare identifier belongs to the repetition or to $name.
    ($($rest:tt)+) => {
        $crate::__puffin_define_sig_decentral!([] $($rest)+);
    };
}

/// Internal tt-munching helper for the decentralised arm of [`define_signature!`].
///
/// Walks the token stream one `segment ::` at a time, accumulating the module
/// prefix, until it reaches the terminal `NAME, PT; fn1 fn2 …` pattern. It
/// then appends `_FNDEFS` to `NAME` (via [`paste!`](puffin::paste)) to derive
/// the [`linkme::distributed_slice`] path and emits the static registration.
///
/// The tt-munching approach is necessary because a pattern like
/// `$($prefix:tt ::)* $name:ident` causes a *local ambiguity* error in
/// `macro_rules!`: the parser cannot decide whether a bare identifier belongs
/// to the repetition or to the terminal `$name` fragment without lookahead.
///
/// **Do not call this macro directly.** Use [`crate::define_signature!`] instead.
#[doc(hidden)]
#[macro_export]
macro_rules! __puffin_define_sig_decentral {
    // ------------------------------------------------------------------
    // Terminal arm.
    //
    // `$acc` contains every `segment ::` token consumed so far (the
    // module prefix, possibly empty). `$name` is the final path segment
    // — the signature identifier to which `_FNDEFS` is appended.
    // `$first_f` is separated from `$($f)*` so the static name only uses
    // the first function, keeping it short enough for the OS file-system.
    // ------------------------------------------------------------------
    // The static name uses only the first function to keep identifiers short.
    // Including every function name causes file-name-too-long errors when
    // rustdoc generates per-item HTML files on Linux (NAME_MAX = 255 bytes).
    ([$($acc:tt)*] $name:ident, $pt:ident; $first_f:ident $([$first_flags:expr])* $($f:ident $([$flags:expr])*)*) => {
        $crate::paste::paste! {
            #[allow(non_upper_case_globals)]
            #[$crate::linkme::distributed_slice($($acc)* [<$name _FNDEFS>])]
            static [< __puffin_sig_entry_ $name _ $first_f >]:
                $crate::algebra::signature::SignatureDefinitionFactory<$pt> =
            || {
                use $crate::algebra::dynamic_function::{make_dynamic, FunctionAttributes};
                vec![
                    {

                        let mut _attrs = FunctionAttributes::default();
                        $(
                            let flag = stringify!($first_flags);
                            match flag {
                                "opaque" => _attrs.is_opaque = true,
                                "list"   => _attrs.is_list = true,
                                "get"    => _attrs.is_get = true,
                                "no_gen" => _attrs.no_gen = true,
                                "no_bit" => _attrs.no_bit = true,
                                "no_det" => _attrs.no_det = true,
                                _ => {},
                            }
                        )*
                        (make_dynamic(&$first_f), _attrs)
                    }
                    $(
                        ,{
                            let mut _attrs = FunctionAttributes::default();
                            $(
                                let flag = stringify!($flags);
                                match flag {
                                    "opaque" => _attrs.is_opaque = true,
                                    "list"   => _attrs.is_list = true,
                                    "get"    => _attrs.is_get = true,
                                    "no_gen" => _attrs.no_gen = true,
                                    "no_bit" => _attrs.no_bit = true,
                                    "no_det" => _attrs.no_det = true,
                                    _ => {},
                                }
                            )*
                            (make_dynamic(&$f), _attrs)
                        }
                    )*
                ]
            };
        }
    };

    // ------------------------------------------------------------------
    // Recursive arm.
    //
    // Consume the leading `$seg ::` token pair, append it to the
    // accumulator, and recurse with the remaining tokens.
    // ------------------------------------------------------------------
    ([$($acc:tt)*] $seg:ident :: $($rest:tt)+) => {
        $crate::__puffin_define_sig_decentral!([$($acc)* $seg ::] $($rest)+);
    };
}
