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
use crate::algebra::Matcher;
use crate::protocol::ProtocolTypes;
use crate::trace::{Query, Source};

pub type FunctionDefinition<PT> = (DynamicFunctionShape<PT>, Box<dyn DynamicFunction<PT>>);

/// Records a universe of functions.
/// Signatures are containers for types and function symbols. They hold references to the concrete
/// implementations of functions and the types of variables.
pub struct Signature<PT: ProtocolTypes> {
    pub functions_by_name: HashMap<&'static str, FunctionDefinition<PT>>,
    pub functions_by_typ: HashMap<TypeShape<PT>, Vec<FunctionDefinition<PT>>>,
    pub functions: Vec<FunctionDefinition<PT>>,
    pub types_by_name: HashMap<&'static str, TypeShape<PT>>,
    pub attrs_by_name: HashMap<&'static str, FunctionAttributes>,
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
    pub fn new(definitions: Vec<(FunctionDefinition<PT>, FunctionAttributes)>) -> Self {
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
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let type_shape = TypeShape::<PT>::of::<T>();
        Self::new_var(type_shape, source, matcher, counter)
    }

    #[must_use]
    pub fn new_var<M: Matcher>(
        type_shape: TypeShape<PT>,
        source: Option<Source>,
        matcher: Option<M>,
        counter: u16,
    ) -> Variable<PT>
    where
        PT: ProtocolTypes<Matcher = M>,
    {
        let query = Query {
            source,
            matcher,
            counter,
        };
        Variable::new(type_shape, query)
    }
}

pub type StaticSignature<PT> = Lazy<Signature<PT>>;

pub const fn create_static_signature<PT: ProtocolTypes>(
    init: fn() -> Signature<PT>,
) -> StaticSignature<PT> {
    Lazy::new(init)
}

#[macro_export]
macro_rules! define_signature {
    ($name_signature:ident<$protocol_types:ident>, $($f:path $([$flags:expr])*)+) => {
        use $crate::algebra::signature::create_static_signature;
        use $crate::algebra::signature::StaticSignature;
        use $crate::algebra::signature::Signature;

        /// Signature which contains all functions defined in the `tls` module. A signature is responsible
        /// for linking function implementations to serialized data.
        ///
        /// Note: Changes in function symbols may cause deserialization of term to fail.
        #[allow(unused_mut)]
        pub static $name_signature: StaticSignature<$protocol_types> = create_static_signature(|| {

            let definitions = vec![
                $(
                    {
                        let mut attrs = FunctionAttributes::default();
                        {  // Process option attributes
                            $(
                                let flag = stringify!($flags);
                                match flag {
                                    "opaque" => attrs.is_opaque = true,
                                    "list" => attrs.is_list = true,
                                    "get" => attrs.is_get = true,
                                    "no_gen" => attrs.no_gen = true,
                                    "no_bit" => attrs.no_bit = true,
                                    "no_det" => attrs.no_det = true,
                                    _ => {},
                                }
                            )*
                        }
                        ($crate::algebra::dynamic_function::make_dynamic(&$f), attrs)
                    }
                ),+
            ];
            Signature::new(definitions)
        });
    };
}
