//! The `Vec<T>` types of a [`Signature`](super::signature::Signature) that the term algebra can
//! build directly, as a flat [`DYTerm::List`](crate::algebra::DYTerm::List) node: the
//! [`ListTypes`] registry and the [`crate::define_list_types!`] macro that fills it at link time
//! via [`linkme`] distributed slices.
//!
//! # Why
//!
//! A list used to be spelled out with two function symbols, an empty-list constant and an append
//! taking the list built so far — so a list of `n` elements was a chain of `n` nested
//! applications. A [`DYTerm::List`](crate::algebra::DYTerm::List) instead holds its elements as
//! direct children. Evaluating one means building a `Vec<T>` out of `n` values whose type is only
//! known at runtime, which is what this registry is for: it maps the [`TypeId`] of `Vec<T>` to
//! the element type and to a builder that downcasts the evaluated elements and collects them.
//!
//! # Workflow
//!
//! ## 1 – Declare the signature
//!
//! [`crate::declare_signature!`] emits the `MY_SIGNATURE_LISTDEFS`
//! [`linkme::distributed_slice`] alongside the function one; there is nothing extra to declare.
//!
//! ## 2 – Register from anywhere
//!
//! The `Constructor` derive registers a list type for every constructor argument that is a
//! `Vec<..>` -- a list exists to be taken by a symbol, so the symbols taking one are what define
//! the list types of a signature. Hand-written symbols register theirs explicitly:
//!
//! ```rust,ignore
//! define_list_types!(MY_SIGNATURE, MyProtocolTypes;
//!     Vec<Extension>,
//!     Vec<u8>,
//! );
//! ```

use std::any::TypeId;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::algebra::dynamic_function::TypeShape;
use crate::algebra::error::FnError;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};

/// Builds a `Vec<T>` out of the evaluated elements of a
/// [`DYTerm::List`](crate::algebra::DYTerm::List), for one specific `T`.
pub type BuildListFn<PT> =
    fn(&[Box<dyn EvaluatedTerm<PT>>]) -> Result<Box<dyn EvaluatedTerm<PT>>, FnError>;

/// One registered list type: the `Vec<T>` shape, the `T` shape and the builder.
pub type ListTypeDefinition<PT> = (TypeShape<PT>, TypeShape<PT>, BuildListFn<PT>);

/// A factory function that produces a batch of [`ListTypeDefinition`]s. One or more of these are
/// stored in a [`linkme::distributed_slice`] so that multiple crates / modules can register types
/// into the same [`ListTypes`] without all being listed in a single macro call.
pub type ListTypeFactory<PT> = fn() -> Vec<ListTypeDefinition<PT>>;

/// Builds the [`ListTypeDefinition`] of `Vec<T>` out of its element type `T`.
///
/// Reached through [`ListArgument`], which is what decides whether a type is a `Vec<T>` at all;
/// there is no reason to call it directly.
#[must_use]
pub fn list_type<PT: ProtocolTypes, T: EvaluatedTerm<PT> + Clone>() -> ListTypeDefinition<PT>
where
    Vec<T>: EvaluatedTerm<PT>,
{
    (
        TypeShape::of::<Vec<T>>(),
        TypeShape::of::<T>(),
        |elements: &[Box<dyn EvaluatedTerm<PT>>]| {
            let mut list: Vec<T> = Vec::with_capacity(elements.len());
            for (index, element) in elements.iter().enumerate() {
                let element = element.as_any().downcast_ref::<T>().ok_or_else(|| {
                    FnError::Malformed(format!(
                        "[build_list] Element #{index} of a list of {} evaluated to {} instead",
                        std::any::type_name::<T>(),
                        element.type_name(),
                    ))
                })?;
                list.push(element.clone());
            }
            Ok(Box::new(list) as Box<dyn EvaluatedTerm<PT>>)
        },
    )
}

/// Decides, for one argument type of a function symbol, whether it is a `Vec<T>` the term algebra
/// can build a list of.
///
/// A `TypeShape` is a [`TypeId`] and a name: nothing in it can *construct* a `Vec<T>`. The
/// argument type is a concrete Rust type exactly once, when the symbol is registered, so that is
/// where [`define_list_types!`](crate::define_list_types) captures the builder — through this
/// probe.
pub struct ListArgument<PT, A>(PhantomData<(PT, A)>);

impl<PT, A> Default for ListArgument<PT, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PT, A> ListArgument<PT, A> {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

/// The `Vec<T>` case. Selected over [`OtherArgumentType`] by the extra `&` at the call site: method
/// resolution reaches an impl on `&ListArgument` one step before one on `ListArgument`, and skips
/// it when its bounds do not hold -- which is how a `Vec<T>` whose elements are no
/// [`EvaluatedTerm`], or an argument type that is no `Vec` at all, falls through to the other
/// impl. (Stable Rust has no specialization; this is the usual autoref stand-in for it.)
pub trait ListArgumentType<PT: ProtocolTypes> {
    fn definition(&self) -> Option<ListTypeDefinition<PT>>;
}

impl<PT: ProtocolTypes, T: EvaluatedTerm<PT> + Clone> ListArgumentType<PT>
    for &ListArgument<PT, Vec<T>>
where
    Vec<T>: EvaluatedTerm<PT>,
{
    fn definition(&self) -> Option<ListTypeDefinition<PT>> {
        Some(list_type::<PT, T>())
    }
}

/// Every other argument type: no list to register.
pub trait OtherArgumentType<PT: ProtocolTypes> {
    fn definition(&self) -> Option<ListTypeDefinition<PT>>;
}

impl<PT: ProtocolTypes, A> OtherArgumentType<PT> for ListArgument<PT, A> {
    fn definition(&self) -> Option<ListTypeDefinition<PT>> {
        None
    }
}

/// Records the `Vec<T>` types a [`DYTerm::List`](crate::algebra::DYTerm::List) may have, indexed
/// by [`TypeId`].
///
/// In normal use you do not construct a `ListTypes` directly: every
/// [`Signature`](super::signature::Signature) declared with [`crate::declare_signature!`] owns
/// one, populated by the [`crate::define_list_types!`] calls targeting that signature.
pub struct ListTypes<PT: ProtocolTypes> {
    definitions: HashMap<TypeId, ListTypeDefinition<PT>>,
}

impl<PT: ProtocolTypes> std::fmt::Debug for ListTypes<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(self.definitions.values().map(|(list, _, _)| list.name))
            .finish()
    }
}

impl<PT: ProtocolTypes> ListTypes<PT> {
    /// Construct a `ListTypes` from the given [`ListTypeDefinition`]s.
    ///
    /// A type registered more than once keeps its first registration; the builders are identical
    /// anyway.
    #[must_use]
    pub fn new(definitions: Vec<ListTypeDefinition<PT>>) -> Self {
        let mut map = HashMap::with_capacity(definitions.len());

        for definition in definitions {
            map.entry(definition.0.clone().into()).or_insert(definition);
        }

        Self { definitions: map }
    }

    /// The element type of `list`, when `list` is a registered `Vec<T>`.
    #[must_use]
    pub fn element_type(&self, list: &TypeShape<PT>) -> Option<&TypeShape<PT>> {
        self.definitions
            .get(&list.clone().into())
            .map(|(_, element, _)| element)
    }

    /// Whether `list` is a registered `Vec<T>`.
    #[must_use]
    pub fn contains(&self, list: &TypeShape<PT>) -> bool {
        self.definitions.contains_key(&list.clone().into())
    }

    /// Build a value of the registered type `list` out of its evaluated `elements`.
    pub fn build(
        &self,
        list: &TypeShape<PT>,
        elements: &[Box<dyn EvaluatedTerm<PT>>],
    ) -> Result<Box<dyn EvaluatedTerm<PT>>, FnError> {
        let (_, _, build) = self.definitions.get(&list.clone().into()).ok_or_else(|| {
            FnError::Unknown(format!(
                "[build_list] {} is not a registered list type; see define_list_types!",
                list.name
            ))
        })?;

        build(elements)
    }

    /// Every registered `Vec<T>` shape, with its element shape.
    pub fn shapes(&self) -> impl Iterator<Item = (&TypeShape<PT>, &TypeShape<PT>)> + '_ {
        self.definitions
            .values()
            .map(|(list, element, _)| (list, element))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }
}

/// Register a batch of `Vec<T>` types into the [`ListTypes`] of a signature declared by
/// [`crate::declare_signature!`]. Only a registered `Vec<T>` can be built by a
/// [`DYTerm::List`](crate::algebra::DYTerm::List).
///
/// **A type deriving `Constructor` needs no call at all**: the derive registers a list type for
/// every constructor argument that is a `Vec<..>`, which is where a list is used in the first
/// place. This macro is for the symbols written by hand.
///
/// All contributions from every call site in the linked binary are merged at link time via
/// [`linkme`]; no central list is required, so a type is best registered in the module that
/// defines it.
///
/// # Syntax
///
/// ```text
/// define_list_types!([prefix::] SIGNATURE, ProtocolType;
///     Vec<Extension>,
///     Vec<u8>,
/// );
/// ```
///
/// `SIGNATURE` is the **signature name** as given to [`crate::declare_signature!`]; the
/// `_LISTDEFS` suffix is appended automatically. An optional module path prefix (e.g.
/// `crate::tls::`) is supported for cross-module registrations.
///
/// # Constraints
///
/// A listed type that is not a `Vec<T>` of an [`EvaluatedTerm`] + [`Clone`] `T` is *skipped*
/// rather than rejected -- see [`ListArgument`], which is what lets the derive list every
/// argument type it sees. `Signature` logs the `Vec` argument types that ended up unregistered,
/// so an omission is loud even though it is not a compile error.
#[macro_export]
macro_rules! define_list_types {
    // Forwards to the tt-munching helper which walks any leading `segment ::` tokens into an
    // accumulator, appends `_LISTDEFS` to the final identifier via paste! to form the
    // distributed-slice path, and emits the static linkme registration.
    ($($rest:tt)+) => {
        $crate::__puffin_define_list_types!([] $($rest)+);
    };
}

/// Internal tt-munching helper for [`define_list_types!`], mirroring
/// [`crate::__puffin_define_readable_types!`].
///
/// **Do not call this macro directly.** Use [`crate::define_list_types!`] instead.
#[doc(hidden)]
#[macro_export]
macro_rules! __puffin_define_list_types {
    ([$($acc:tt)*] $name:ident, $pt:ident; $($t:ty),+ $(,)?) => {
        const _: () = {
            $crate::paste::paste! {
                #[$crate::linkme::distributed_slice($($acc)* [<$name _LISTDEFS>])]
                static LIST_TYPES:
                    $crate::algebra::list_types::ListTypeFactory<$pt> =
                || {
                    use $crate::algebra::list_types::{
                        ListArgumentType as _, OtherArgumentType as _,
                    };
                    ::std::vec![
                        $(
                            (&&$crate::algebra::list_types::ListArgument::<$pt, $t>::new())
                                .definition()
                        ),+
                    ]
                    .into_iter()
                    .flatten()
                    .collect()
                };
            }
        };
    };

    ([$($acc:tt)*] $seg:ident :: $($rest:tt)+) => {
        $crate::__puffin_define_list_types!([$($acc)* $seg ::] $($rest)+);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::test_signature::{ClientExtension, TestProtocolTypes};

    /// The probe resolves to the `Vec<T>` impl for a list argument and to the fallback for
    /// everything else -- including a `Vec` whose elements are no `EvaluatedTerm`.
    #[test_log::test]
    fn probe_selects_the_vec_impl_for_list_arguments_only() {
        struct NotAnEvaluatedTerm;

        let list = (&&ListArgument::<TestProtocolTypes, Vec<ClientExtension>>::new()).definition();
        assert_eq!(
            list.map(|(typ, element, _)| (typ, element)),
            Some((
                TypeShape::of::<Vec<ClientExtension>>(),
                TypeShape::of::<ClientExtension>()
            ))
        );

        assert!((&&ListArgument::<TestProtocolTypes, u8>::new())
            .definition()
            .is_none());
        assert!(
            (&&ListArgument::<TestProtocolTypes, ClientExtension>::new())
                .definition()
                .is_none()
        );
        assert!(
            (&&ListArgument::<TestProtocolTypes, Vec<NotAnEvaluatedTerm>>::new())
                .definition()
                .is_none()
        );
    }
}
