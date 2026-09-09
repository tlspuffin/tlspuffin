//! The types of a [`Signature`](super::signature::Signature) that a bitstring can be read back
//! into: the [`ReadableTypes`] registry and the [`crate::define_readable_types!`] macro that fills
//! it at link time via [`linkme`] distributed slices.
//!
//! # Why
//!
//! [`ProtocolBehavior::try_read_bytes`](crate::protocol::ProtocolBehavior::try_read_bytes) has to
//! turn a bitstring into a `Box<dyn EvaluatedTerm<PT>>` knowing only the [`TypeId`] of the wanted
//! type. Since the value's type is not statically known there, the only way to call
//! [`Codec::read_bytes`] is to dispatch on the [`TypeId`] over a list of candidate types. That
//! list is collected exactly like the signature's function symbols are, and lives on the
//! signature itself: contributions come from *any* number of modules or crates, so each type is
//! registered next to where it is defined instead of in a single central list.
//!
//! # Workflow
//!
//! ## 1 – Declare the signature
//!
//! [`crate::declare_signature!`] emits the `MY_SIGNATURE_TYPEDEFS`
//! [`linkme::distributed_slice`] alongside the function one; there is nothing extra to declare.
//!
//! ## 2 – Register from anywhere
//!
//! Types deriving `Constructor` register themselves — the derive emits the call below unless the
//! type carries `#[constructor_no_try_read]`. Everything else is registered by hand:
//!
//! ```rust,ignore
//! // Same module as the signature:
//! define_readable_types!(MY_SIGNATURE, MyProtocolTypes;
//!     ClientHello,
//!     Vec<Extension>,
//! );
//!
//! // Different module in the same crate:
//! define_readable_types!(crate::protocol::MY_SIGNATURE, MyProtocolTypes;
//!     Alert,
//! );
//! ```
//!
//! ## 3 – Read
//!
//! ```rust,ignore
//! MY_SIGNATURE.try_read_bytes(bitstring, ty)
//! ```

use std::any::TypeId;
use std::collections::HashMap;

use crate::codec::Codec;
use crate::error::Error;
use crate::protocol::{EvaluatedTerm, ProtocolTypes};

/// Reads a bitstring into a boxed value of one specific type, as registered in
/// [`ReadableTypes`].
pub type ReadBytesFn<PT> = fn(&[u8]) -> Result<Box<dyn EvaluatedTerm<PT>>, Error>;

/// One registered type: its [`TypeId`], its [`std::any::type_name`] (for diagnostics) and the
/// reader.
pub type ReadableTypeDefinition<PT> = (TypeId, &'static str, ReadBytesFn<PT>);

/// A factory function that produces a batch of [`ReadableTypeDefinition`]s. One or more of these
/// are stored in a [`linkme::distributed_slice`] so that multiple crates / modules can register
/// types into the same [`ReadableTypes`] without all being listed in a single macro call.
pub type ReadableTypeFactory<PT> = fn() -> Vec<ReadableTypeDefinition<PT>>;

/// Builds the [`ReadableTypeDefinition`] of a single type.
///
/// Called by [`crate::define_readable_types!`] for each listed type; there is no reason to call it
/// directly.
#[must_use]
pub fn readable_type<PT: ProtocolTypes, T: Codec + EvaluatedTerm<PT>>() -> ReadableTypeDefinition<PT>
{
    (
        TypeId::of::<T>(),
        std::any::type_name::<T>(),
        |bitstring: &[u8]| {
            log::trace!("Type match TypeID {:?}...!", std::any::type_name::<T>());
            <T as Codec>::read_bytes(bitstring)
                .map(|v| Box::new(v) as Box<dyn EvaluatedTerm<PT>>)
                .ok_or_else(|| {
                    Error::Term(format!(
                        "[try_read_bytes] Failed to read to type {:?} the bitstring {:?}",
                        std::any::type_name::<T>(),
                        bitstring
                    ))
                })
        },
    )
}

/// Records the types a bitstring can be read back into, indexed by [`TypeId`].
///
/// In normal use you do not construct a `ReadableTypes` directly: every
/// [`Signature`](super::signature::Signature) declared with [`crate::declare_signature!`] owns
/// one, populated by the [`crate::define_readable_types!`] calls targeting that signature.
pub struct ReadableTypes<PT: ProtocolTypes> {
    readers: HashMap<TypeId, (&'static str, ReadBytesFn<PT>)>,
}

impl<PT: ProtocolTypes> std::fmt::Debug for ReadableTypes<PT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.type_names()).finish()
    }
}

impl<PT: ProtocolTypes> ReadableTypes<PT> {
    /// Construct a `ReadableTypes` from the given [`ReadableTypeDefinition`]s.
    ///
    /// A type registered more than once — the same type may legitimately be listed by two
    /// modules — keeps its first registration; the readers are identical anyway.
    #[must_use]
    pub fn new(definitions: Vec<ReadableTypeDefinition<PT>>) -> Self {
        let mut readers = HashMap::with_capacity(definitions.len());

        for (type_id, name, read_bytes) in definitions {
            readers.entry(type_id).or_insert((name, read_bytes));
        }

        Self { readers }
    }

    /// Read `bitstring` as the type identified by `ty`.
    ///
    /// Fails with [`Error::Term`] if the type is registered but its
    /// [`Codec::read_bytes`] rejects the bitstring — expected for many bitstrings, since a
    /// mutated one need not be a valid encoding — and with [`Error::TermBug`] if no type with
    /// that [`TypeId`] is registered, which means the type carries `#[constructor_no_try_read]`
    /// or is missing a [`crate::define_readable_types!`] entry.
    pub fn try_read_bytes(
        &self,
        bitstring: &[u8],
        ty: TypeId,
    ) -> Result<Box<dyn EvaluatedTerm<PT>>, Error> {
        log::trace!("Trying read...");

        let Some((_name, read_bytes)) = self.readers.get(&ty) else {
            log::warn!(
                "Failed to find a suitable type with typeID {ty:?} to read the bitstring \
                 {bitstring:?}"
            );
            return Err(Error::TermBug(format!(
                "[try_read_bytes] Failed to find a suitable type with typeID {ty:?} to read the \
                 bitstring {bitstring:?}"
            )));
        };

        read_bytes(bitstring)
    }

    /// Whether a type with this [`TypeId`] is registered.
    #[must_use]
    pub fn contains(&self, ty: TypeId) -> bool {
        self.readers.contains_key(&ty)
    }

    /// The [`std::any::type_name`] of every registered type.
    pub fn type_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.readers.values().map(|(name, _read_bytes)| *name)
    }

    /// The number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.readers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.readers.is_empty()
    }
}

/// Register a batch of types into the [`ReadableTypes`] of a signature declared by
/// [`crate::declare_signature!`], making them candidates for
/// [`Signature::try_read_bytes`](super::signature::Signature::try_read_bytes).
///
/// All contributions from every call site in the linked binary are merged at link time via
/// [`linkme`]; no central list is required, so a type is best registered in the module that
/// defines it. A type deriving `Constructor` needs no call at all: the derive emits one for it,
/// unless it carries `#[constructor_no_try_read]`.
///
/// # Syntax
///
/// ```text
/// define_readable_types!([prefix::] SIGNATURE, ProtocolType;
///     TypeOne,
///     Vec<TypeTwo>,
/// );
/// ```
///
/// `SIGNATURE` is the **signature name** as given to [`crate::declare_signature!`]; the
/// `_TYPEDEFS` suffix is appended automatically. An optional module path prefix (e.g.
/// `crate::tls::`) is supported for cross-module registrations, and is the simplest way to
/// register from a module that does not import the signature.
///
/// # Constraints
///
/// Every listed type must implement [`Codec`] and
/// [`EvaluatedTerm<ProtocolType>`](EvaluatedTerm) — a type whose `read` needs context the
/// bitstring does not carry, or whose `encode` / `read` do not round-trip, must *not* be
/// registered: reading it back would silently produce a different value.
///
/// # Examples
///
/// ```rust,ignore
/// // Declared once in tls/mod.rs:
/// declare_signature!(TLS_SIGNATURE<TLSProtocolTypes>);
///
/// // Register from the same module:
/// define_readable_types!(TLS_SIGNATURE, TLSProtocolTypes;
///     u8,
///     Vec<u8>,
/// );
///
/// // Register from a different module in the same crate:
/// define_readable_types!(crate::tls::TLS_SIGNATURE, TLSProtocolTypes;
///     HandshakeHash,
/// );
/// ```
#[macro_export]
macro_rules! define_readable_types {
    // Forwards to the tt-munching helper which walks any leading `segment ::` tokens into an
    // accumulator, appends `_TYPEDEFS` to the final identifier via paste! to form the
    // distributed-slice path, and emits the static linkme registration.
    ($($rest:tt)+) => {
        $crate::__puffin_define_readable_types!([] $($rest)+);
    };
}

/// Internal tt-munching helper for [`define_readable_types!`].
///
/// Walks the token stream one `segment ::` at a time, accumulating the module prefix, until it
/// reaches the terminal `SIGNATURE, PT; T1, T2, …` pattern. It then appends `_TYPEDEFS` to
/// `SIGNATURE` (via [`paste!`](puffin::paste)) to derive the [`linkme::distributed_slice`] path
/// and emits the static registration.
///
/// The registration is wrapped in a `const _: () = { … };` block, which keeps the name of the
/// generated static private to that block: unlike [`define_signature!`], which derives the static
/// name from the first function name, the listed types are `ty` fragments (`Vec<u8>`, …) that
/// cannot be pasted into an identifier. The anonymous const also means any number of
/// contributions may live in the same module.
///
/// **Do not call this macro directly.** Use [`crate::define_readable_types!`] instead.
#[doc(hidden)]
#[macro_export]
macro_rules! __puffin_define_readable_types {
    // ------------------------------------------------------------------
    // Terminal arm.
    //
    // `$acc` contains every `segment ::` token consumed so far (the module prefix, possibly
    // empty). `$name` is the final path segment — the signature identifier to which `_TYPEDEFS`
    // is appended.
    // ------------------------------------------------------------------
    ([$($acc:tt)*] $name:ident, $pt:ident; $($t:ty),+ $(,)?) => {
        const _: () = {
            $crate::paste::paste! {
                #[$crate::linkme::distributed_slice($($acc)* [<$name _TYPEDEFS>])]
                static READABLE_TYPES:
                    $crate::algebra::readable_types::ReadableTypeFactory<$pt> =
                || {
                    ::std::vec![
                        $($crate::algebra::readable_types::readable_type::<$pt, $t>()),+
                    ]
                };
            }
        };
    };

    // ------------------------------------------------------------------
    // Recursive arm.
    //
    // Consume the leading `$seg ::` token pair, append it to the accumulator, and recurse with
    // the remaining tokens.
    // ------------------------------------------------------------------
    ([$($acc:tt)*] $seg:ident :: $($rest:tt)+) => {
        $crate::__puffin_define_readable_types!([$($acc)* $seg ::] $($rest)+);
    };
}
