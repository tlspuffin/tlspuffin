use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{Token, Type};

/// Implements Extractable trait for structs, enums and unions
///
/// # Types requirements
///
/// All types must implement Clone, Debug and Codec
///
/// # Struct
///
/// Extractable can be used on struct with named or unnamed fields
///
/// ```ignore
/// # use extractable_macro::Extractable;
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// struct TestStruct {
///     a: u8,
///     b: f64,
/// }
/// ```
///
/// ## Ignore a field
///
/// The `#[extractable_ignore]` annotation allows to skip a field when extracting knowledges
///
/// ```ignore
/// # use extractable_macro::Extractable;
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// struct TestStruct {
///     a: u8,
///     #[extractable_ignore]
///     b: String, // this field won't be added to the knowledges
///     c: f64,
/// }
/// ```
///
/// ## Extract a field that doesn't implement Extractable
///
/// The `#[extractable_no_recursion]` annotation will add a field to the knowledge but won't call
/// `.extract_knowledge(...)` on this field. Use this on types that do no implement Extractable
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// struct TestStruct {
///     a: u8,
///     #[extractable_no_recursion]
///     b: CustomType,
/// }
/// ```
///
/// # Enums
///
/// Extractable can be used on enums with variant containing named or unnamed fields
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// enum TestEnum {
///     A,
///     B(String),
///     C{x: u8, y: u8},
/// }
/// ```
///
/// ## Ignore a field
///
/// The `#[extractable_ignore]` annotation allows to skip a field when extracting knowledges
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// enum TestEnum {
///     A,
///     B(#[extractable_ignore] String),
///     C{x: u8, y: u8},
/// }
/// ```
///
/// ## Extract a field that doesn't implement Extractable
///
/// The `#[extractable_no_recursion]` annotation will add a field to the knowledge but won't call
/// `.extract_knowledge(...)` on this field. Use this on types that do no implement Extractable
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// enum TestEnum {
///     A,
///     B(String),
///     C{x: u8,#[extractable_no_recursion] y: u8},
/// }
/// ```
///
/// # Unions
///
/// Union types can only extract `self` and do not support annotations
///
/// ```ignore
/// #[derive(Clone, Copy, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// union TestUnion {
///     x: u8,
///     y: char,
/// }
/// ```
///
/// # Providing a query matcher
///
///
/// ## On structs
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// #[extractable_matcher(Some(Matcher::Alert))]
/// struct Alert {
///     level: u8,
/// }
/// ```
///
/// ## On enums
///
/// ```ignore
/// #[derive(Clone, Debug, Extractable)]
/// #[extractable(TestProtocolTypes)]
/// enum Payload {
///     #[extractable_matcher(Some(Matcher::Handshake(Some(field_0.typ))))]
///     Handshake(HandshakeMessage),
///     #[extractable_matcher(None)]
///     ChangeCipherSpec(Ccs),
///     // No annotation: keeps the matcher it was given.
///     Other(Bytes),
/// }
/// ```
///
/// A variant annotation wins over one on the enum itself, which is then the default for the
/// variants that do not carry their own.
#[proc_macro_derive(
    Extractable,
    attributes(
        extractable,
        extractable_ignore,
        extractable_no_recursion,
        extractable_matcher,
    )
)]
pub fn extractable_macro(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let attribute = input
        .attrs
        .iter()
        .find(|a| a.path().segments.len() == 1 && a.path().segments[0].ident == "extractable")
        .expect("extractable attribute required for deriving Extractable!");

    let types = TypesParam::parse(attribute).expect(
        "failed parsing extractable attribute : expected #[attribute(ProtocolType, Matcher)]",
    );

    let matcher = match matcher_binding(&input) {
        Ok(matcher) => matcher,
        Err(err) => return err.to_compile_error().into(),
    };

    let fields = map_type_definition(&input, &types.protocol_types);

    generate_impl(
        &input.ident,
        &input.generics,
        &types.protocol_types,
        &matcher,
        &fields,
    )
    .into()
}

struct TypesParam {
    protocol_types: syn::Type,
}
impl TypesParam {
    fn parse(input: &syn::Attribute) -> syn::Result<Self> {
        let types_tokens =
            input.parse_args_with(Punctuated::<Type, Token![,]>::parse_terminated)?;
        let mut type_iter = types_tokens.iter();
        Ok(Self {
            protocol_types: type_iter
                .next()
                .expect("Missing ProtocolType type")
                .to_owned(),
        })
    }
}

fn generate_impl(
    name: &syn::Ident,
    generics: &syn::Generics,
    protocol_type: &syn::Type,
    matcher_binding: &TokenStream,
    fields: &TokenStream,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics puffin::protocol::Extractable<#protocol_type> for #name #ty_generics #where_clause {
            fn extract_knowledge<'a>(
                &'a self,
                knowledges: &mut Vec<puffin::trace::Knowledge<'a, #protocol_type>>,
                matcher: Option<<#protocol_type as puffin::protocol::ProtocolTypes>::Matcher>,
                source: &'a puffin::trace::Source,
            ) -> Result<(), puffin::error::Error> {
                // Shadows the parameter when the type provides its own matcher, so that both the
                // knowledge pushed below and the fields extracted after it use the new one.
                #matcher_binding

                knowledges.push(puffin::trace::Knowledge {
                    source,
                    matcher: matcher.clone(),
                    data: self,
                });

                #fields

                Ok(())
            }
        }
    }
}

/// The `#[extractable_matcher(...)]` expression on a type or a variant, if it carries one.
fn matcher_attr(attrs: &[syn::Attribute]) -> syn::Result<Option<syn::Expr>> {
    has_attr(attrs, "extractable_matcher")
        .map(syn::Attribute::parse_args::<syn::Expr>)
        .transpose()
}

/// The pattern binding a variant's fields, using the same names the field extraction uses so that
/// a `#[extractable_matcher(...)]` expression can name them.
fn variant_pattern(name: &syn::Ident, variant: &syn::Variant) -> TokenStream {
    let variant_name = &variant.ident;

    match &variant.fields {
        syn::Fields::Named(named) => {
            let fields = named.named.iter().map(|field| {
                field
                    .ident
                    .as_ref()
                    .expect("unnamed field in named variant")
            });
            quote! { #name::#variant_name { #(#fields),* } }
        }
        syn::Fields::Unnamed(unnamed) => {
            let fields = (0..unnamed.unnamed.len()).map(|idx| format_ident!("field_{}", idx));
            quote! { #name::#variant_name ( #(#fields),* ) }
        }
        syn::Fields::Unit => quote! { #name::#variant_name },
    }
}

/// The `let matcher = ...;` shadowing the parameter, or nothing when the type takes the matcher it
/// is given — which is the default, and what every type did before the attribute existed.
fn matcher_binding(input: &syn::DeriveInput) -> syn::Result<TokenStream> {
    let type_level = matcher_attr(&input.attrs)?;

    let mut arms = Vec::new();
    if let syn::Data::Enum(en) = &input.data {
        for variant in &en.variants {
            if let Some(expr) = matcher_attr(&variant.attrs)? {
                let pattern = variant_pattern(&input.ident, variant);
                arms.push(quote! { #pattern => #expr, });
            }
        }
    }

    // The enum's own annotation is what a variant without one falls back to; without either, the
    // matcher passed in is kept.
    let default = match &type_level {
        Some(expr) => quote! { #expr },
        None => quote! { matcher },
    };

    if arms.is_empty() {
        return Ok(match type_level {
            Some(_) => quote! { let matcher = #default; },
            None => quote! {},
        });
    }

    Ok(quote! {
        let matcher = {
            // A variant's fields are bound so the expression can name them, whether or not it
            // does; and the fallback arm is unreachable once every variant is annotated.
            #[allow(unused_variables, unreachable_patterns)]
            match self {
                #(#arms)*
                _ => #default,
            }
        };
    })
}

fn has_attr<'a>(attrs: &'a [syn::Attribute], attr_name: &str) -> Option<&'a syn::Attribute> {
    attrs.iter().find(|attr| attr.path().is_ident(attr_name))
}

fn extract_fields<'a>(
    fields: impl IntoIterator<Item = &'a syn::Field>,
    protocol_types: &syn::Type,
    f: impl Fn(usize, Option<syn::Ident>) -> TokenStream,
) -> Vec<TokenStream> {
    let mut result = vec![];

    for (idx, field) in fields.into_iter().enumerate() {
        if has_attr(&field.attrs, "extractable_ignore").is_none() {
            let field_name = f(idx, field.ident.clone());
            if has_attr(&field.attrs, "extractable_no_recursion").is_none() {
                result.push(quote! {
                    puffin::protocol::Extractable::<#protocol_types>::extract_knowledge(#field_name, knowledges, matcher.clone(), source)?;
                })
            } else {
                result.push(quote! {
                    knowledges.push(puffin::trace::Knowledge {
                        source,
                        matcher: matcher.clone(),
                        data: #field_name,
                    });
                })
            }
        }
    }
    result
}

fn extract_variants<'a>(
    name: &syn::Ident,
    protocol_types: &syn::Type,
    variants: impl IntoIterator<Item = &'a syn::Variant>,
) -> Vec<TokenStream> {
    let mut result = vec![];

    for variant in variants {
        let variant_name = &variant.ident;
        match &variant.fields {
            syn::Fields::Named(named) => {
                let field_extractions =
                    extract_fields(named.named.iter(), protocol_types, |_, idt| {
                        let name = idt.expect("unnamed field in named enum");
                        quote! {#name}
                    });
                let fields = named
                    .named
                    .iter()
                    .map(|x| {
                        let id = x.ident.as_ref().expect("unnamed field in named enum");
                        quote! {#id}
                    })
                    .collect::<Vec<_>>();

                result.push(quote! {
                    #name::#variant_name{#(#fields),*} => { #(#field_extractions)* }
                });
            }
            syn::Fields::Unnamed(unnamed) => {
                let field_extractions =
                    extract_fields(unnamed.unnamed.iter(), protocol_types, |idx, _| {
                        let name = format_ident!("field_{}", syn::Index::from(idx));
                        quote! {#name}
                    });
                let fields = unnamed
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(pos, _)| {
                        let id = format_ident!("field_{}", pos);
                        quote! {#id}
                    })
                    .collect::<Vec<_>>();

                result.push(quote! {
                    #name::#variant_name(#(#fields),*) => { #(#field_extractions)* }
                });
            }
            syn::Fields::Unit => {
                result.push(quote! {
                    #name::#variant_name => {}
                });
            }
        }
    }
    result
}

fn map_type_definition(input: &syn::DeriveInput, protocol_types: &syn::Type) -> TokenStream {
    let body = match &input.data {
        syn::Data::Struct(st) => match &st.fields {
            syn::Fields::Named(named) => {
                let field_extractions =
                    extract_fields(named.named.iter(), protocol_types, |_, idt| {
                        let name = idt.expect("unnamed field in named struct");
                        quote! {&self.#name}
                    });
                quote! {
                    #(#field_extractions )*
                }
            }
            syn::Fields::Unnamed(unnamed) => {
                let field_extractions =
                    extract_fields(unnamed.unnamed.iter(), protocol_types, |idx, _| {
                        let name = syn::Index::from(idx);
                        quote! {&self.#name}
                    });
                quote! {
                    #(#field_extractions )*
                }
            }
            syn::Fields::Unit => {
                quote! {}
            }
        },
        syn::Data::Enum(en) => {
            let variants_extractions =
                extract_variants(&input.ident, protocol_types, en.variants.iter());
            quote! {
                match &self {
                    #(#variants_extractions ),*
                    _ => ()
                }
            }
        }
        syn::Data::Union(_un) => {
            quote! {}
        }
    };
    quote! {
        #body
    }
}
