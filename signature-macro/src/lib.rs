//! The `#[signature]` attribute: everything a protocol message type needs to take part in the
//! term algebra, in one annotation.
//!
//! A type that the fuzzer can build, compare and extract knowledge from needs three
//! derives and two helper attributes. Writing them out per type is both
//! noise and an invitation to get the set wrong.
//!
//! See [`signature`] for the attribute itself.

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::Token;

/// Applies the whole set of derives a protocol message type needs, and their helper attributes.
///
/// ```ignore
/// #[signature(SSH_SIGNATURE, SshProtocolTypes)]
/// pub struct IgnoreMessage {
///     pub data: SshBytes,
/// }
/// ```
///
/// expands to the type with
///
/// ```ignore
/// #[derive(Clone, Debug, Comparable, Extractable, Constructor)]
/// #[extractable(SshProtocolTypes)]
/// #[constructor(SSH_SIGNATURE, SshProtocolTypes)]
/// ```
///
/// `Clone` and `Debug` are part of the set because the others require them: `Constructor` clones
/// each field into the value it builds,  and `Extractable` is declared over `Debug` types.
///
/// # Why an attribute and not a derive
///
/// A derive macro can only *append* items after the type; it cannot add derives to the type it is
/// applied to. Reaching `Comparable`, which comes from an external crate, is only possible by
/// emitting a `#[derive(Comparable)]` for the compiler to expand — so the meta has to rewrite the
/// item, which is what an attribute macro does.
///
/// # Composing with what is already there
///
/// **`#[signature]` has to be the type's first attribute.** Rust expands attributes top to
/// bottom, so anything above it is already gone by the time it runs: it would neither see a
/// `#[derive(Clone)]` written above it — and would then add a second, conflicting one — nor be
/// able to place its own derive ahead of a helper attribute written above it.
///
/// Below it, the attribute *merges* into the type's existing derives rather than replacing them,
/// and skips any trait already listed, so a type keeping its own `PartialEq` (or `Eq`, `Hash`,
/// ...) just writes it as usual:
///
/// ```ignore
/// #[signature(SSH_SIGNATURE, SshProtocolTypes)]
/// #[derive(PartialEq)]
/// pub struct SshBytes(pub Vec<u8>);
/// ```
///
/// Every helper attribute of the four derives —  `#[comparable_ignore]`,
/// `#[extractable_no_recursion]`, `#[constructor_list]`, ... — keeps working untouched, on the
/// type and on its fields and variants.
///
/// # Opting out
///
/// Not every type wants all four. Name the ones to leave out after the protocol types:
///
/// | Flag | Effect |
/// |------|--------|
/// | `no_extractable` | do not derive `Extractable`, and omit `#[extractable(..)]` |
/// | `no_constructor` | do not derive `Constructor`, and omit `#[constructor(..)]` |
/// | `no_comparable` | do not derive `Comparable` |
/// | `no_clone` / `no_debug` | do not add these, for a type implementing them by hand |
///
/// Opting out of a derive whose helper attributes the type still carries is a compile error from
/// the compiler ("cannot find attribute"), not a silent no-op — which is the intent: the flag and
/// the annotations have to agree.
///
/// # Requirements at the use site
///
/// The expansion names the derives by absolute path (`::comparable::Comparable` and friends), so
/// the crate needs `comparable`, `extractable-macro`, and `constructor-macro`  as
/// dependencies, but *no* `use` for any of them.
#[proc_macro_attribute]
pub fn signature(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = syn::parse_macro_input!(args as Args);
    let input = syn::parse_macro_input!(item as syn::DeriveInput);

    match expand(args, input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// `#[signature(SIGNATURE, ProtocolTypes, no_constructor, ...)]`
struct Args {
    /// The signature the generated constructors register into.
    signature: syn::Path,
    /// The protocol-types type of that signature.
    protocol_types: syn::Type,
    /// Which parts of the set were opted out of.
    disabled: Disabled,
}

/// One flag per member of the set, so that adding a member later is a field here and a row in the
/// table below, not a new parsing shape.
#[derive(Default)]
struct Disabled {
    clone: bool,
    debug: bool,
    comparable: bool,
    extractable: bool,
    constructor: bool,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let signature = input.parse::<syn::Path>()?;
        input.parse::<Token![,]>()?;
        let protocol_types = input.parse::<syn::Type>()?;

        let mut disabled = Disabled::default();
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            // Tolerate a trailing comma.
            if input.is_empty() {
                break;
            }

            let flag = input.parse::<syn::Ident>()?;
            let target = match flag.to_string().as_str() {
                "no_clone" => &mut disabled.clone,
                "no_debug" => &mut disabled.debug,
                "no_comparable" => &mut disabled.comparable,
                "no_extractable" => &mut disabled.extractable,
                "no_constructor" => &mut disabled.constructor,
                other => {
                    return Err(syn::Error::new(
                        flag.span(),
                        format!(
                            "unknown #[signature(...)] flag `{other}`, expected one of \
                             `no_clone`, `no_debug`, `no_comparable`, `no_extractable`, \
                             `no_constructor`"
                        ),
                    ))
                }
            };

            if *target {
                return Err(syn::Error::new(
                    flag.span(),
                    format!("duplicate flag `{flag}`"),
                ));
            }
            *target = true;
        }

        Ok(Self {
            signature,
            protocol_types,
            disabled,
        })
    }
}

fn expand(args: Args, mut input: syn::DeriveInput) -> syn::Result<TokenStream> {
    let existing = existing_derives(&input.attrs)?;
    let protocol_types = &args.protocol_types;
    let signature = &args.signature;

    // Absolute paths, so that the use site needs no `use` for any of the four.
    let mut derives: Vec<syn::Path> = Vec::new();
    let mut add = |disabled: bool, path: syn::Path, name: &str| {
        // Deriving a trait the type already derives is a duplicate-impl error, so the set is
        // merged with what is there rather than appended blindly.
        if !disabled && !existing.iter().any(|d| d == name) {
            derives.push(path);
        }
    };

    add(args.disabled.clone, syn::parse_quote!(Clone), "Clone");
    add(args.disabled.debug, syn::parse_quote!(Debug), "Debug");
    add(
        args.disabled.comparable,
        syn::parse_quote!(::comparable::Comparable),
        "Comparable",
    );
    add(
        args.disabled.extractable,
        syn::parse_quote!(::extractable_macro::Extractable),
        "Extractable",
    );
    add(
        args.disabled.constructor,
        syn::parse_quote!(::constructor_macro::Constructor),
        "Constructor",
    );

    if !derives.is_empty() {
        // At the *front*: a derive's helper attributes must come after the derive that
        // introduces them, and the type's own `#[extractable_no_recursion]` /
        // ... are already in this list.
        input
            .attrs
            .insert(0, syn::parse_quote!(#[derive(#(#derives),*)]));
    }

    // The two derives that need to be told which signature they belong to. Both are skipped when
    // the type already carries the attribute by hand, so an existing annotation always wins.
    if !args.disabled.extractable && !has_attr(&input.attrs, "extractable") {
        input
            .attrs
            .push(syn::parse_quote!(#[extractable(#protocol_types)]));
    }
    if !args.disabled.constructor && !has_attr(&input.attrs, "constructor") {
        input
            .attrs
            .push(syn::parse_quote!(#[constructor(#signature, #protocol_types)]));
    }

    Ok(quote! { #input })
}

/// The trait names the type already derives, by last path segment, so that both `Comparable` and
/// `::comparable::Comparable` are recognised as the same trait.
fn existing_derives(attrs: &[syn::Attribute]) -> syn::Result<Vec<String>> {
    let mut names = Vec::new();

    for attr in attrs.iter().filter(|a| a.path().is_ident("derive")) {
        let paths = attr.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)?;
        names.extend(
            paths
                .iter()
                .filter_map(|p| p.segments.last())
                .map(|s| s.ident.to_string()),
        );
    }

    Ok(names)
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}
