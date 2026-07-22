use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::Token;

/// Helper attribute marking a field that is *not* a constructor parameter and is instead
/// initialised from the expression it wraps: `#[constructor_default(EXPR)]`.
const DEFAULT_ATTR: &str = "constructor_default";

#[proc_macro_derive(Constructor, attributes(constructor, constructor_default))]
pub fn constructor_macro(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let attribute = input
        .attrs
        .iter()
        .find(|a| a.path().segments.len() == 1 && a.path().segments[0].ident == "constructor")
        .expect("constructor attribute required for deriving Constructor!");

    let signature_metadata = SigMetadata::parse(attribute).expect(
        "failed parsing extractable attribute : expected #[constructor(SIGNATURE, ProtocolTypes)]",
    );

    map_type_definition(&input.ident, &input.generics, &input, &signature_metadata).into()
}

/// Stores the metadata used to add a function to the signature
struct SigMetadata {
    /// The signature identifier, e.g. `MY_SIGNATURE` in `#[constructor(MY_SIGNATURE, MyTypes)]`.
    signature: syn::Ident,
    /// The protocol-types type, e.g. `MyTypes` in `#[constructor(MY_SIGNATURE, MyTypes)]`.
    protocol_types: syn::Type,
}
impl SigMetadata {
    fn parse(input: &syn::Attribute) -> syn::Result<Self> {
        input.parse_args_with(|stream: syn::parse::ParseStream| {
            let signature = stream.parse::<syn::Ident>()?;
            stream.parse::<Token![,]>()?;
            let protocol_types = stream.parse::<syn::Type>()?;
            Ok(Self {
                signature,
                protocol_types,
            })
        })
    }
}

fn add_to_signature(fn_name: &syn::Ident, signature_metadata: &SigMetadata) -> TokenStream {
    let signature_name = &signature_metadata.signature;
    let protocol_types = &signature_metadata.protocol_types;
    quote! {
        define_signature!(
            #signature_name,
            #protocol_types;
            #fn_name
        );
    }
}

fn has_attr<'a>(attrs: &'a [syn::Attribute], attr_name: &str) -> Option<&'a syn::Attribute> {
    attrs.iter().find(|attr| attr.path().is_ident(attr_name))
}

/// Returns the default expression from a `#[constructor_default(EXPR)]` attribute, if present.
///
/// The wrapped tokens are used verbatim as the field's value, so any expression is accepted:
/// a literal (`#[constructor_default(0)]`), a call (`#[constructor_default(my_default())]`), a
/// path (`#[constructor_default(Default::default())]`), etc.
fn default_expr(attrs: &[syn::Attribute]) -> Option<TokenStream> {
    has_attr(attrs, DEFAULT_ATTR).map(|attr| {
        attr.parse_args::<syn::Expr>()
            .expect("expected #[constructor_default(EXPR)] with a single expression")
            .into_token_stream()
    })
}

fn extract_fields<'a>(
    fields: impl IntoIterator<Item = &'a syn::Field>,
    f: impl Fn(usize, Option<syn::Ident>) -> TokenStream,
) -> Vec<TokenStream> {
    let mut result = vec![];

    for (idx, field) in fields.into_iter().enumerate() {
        // Fields with a `#[constructor_default(...)]` are filled in by the macro, so they are
        // not exposed as constructor parameters.
        if has_attr(&field.attrs, DEFAULT_ATTR).is_none() {
            let field_name = f(idx, field.ident.clone());
            let field_type = &field.ty;

            // push field name and type for the function definition
            result.push(quote! {
                #field_name: &#field_type
            });
        }
    }
    result
}

fn field_assignments<'a>(
    fields: impl IntoIterator<Item = &'a syn::Field>,
    f: impl Fn(usize, Option<syn::Ident>) -> TokenStream,
    named: bool,
) -> Vec<TokenStream> {
    let mut result = vec![];

    for (idx, field) in fields.into_iter().enumerate() {
        let field_name = f(idx, field.ident.clone());

        // A `#[constructor_default(EXPR)]` field is initialised from EXPR; every other field is
        // cloned from its (by-reference) constructor parameter.
        let value = match default_expr(&field.attrs) {
            Some(expr) => expr,
            None => quote! { #field_name.clone() },
        };

        if named {
            result.push(quote! {
                #field_name: #value
            });
        } else {
            result.push(quote! {
                #value
            });
        }
    }
    result
}

fn extract_variants<'a>(
    name: &syn::Ident,
    generics: &syn::Generics,
    sig_metadata: &SigMetadata,
    variants: impl IntoIterator<Item = &'a syn::Variant>,
) -> TokenStream {
    let mut result = vec![];

    for variant in variants {
        let variant_name = &variant.ident;
        let fn_name = format_ident!(
            "fn_{}_{}",
            name.to_string().to_lowercase(),
            variant_name.to_string().to_lowercase()
        );
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        let add_fn_to_sig = add_to_signature(&fn_name, sig_metadata);

        match &variant.fields {
            syn::Fields::Named(named) => {
                let field_extractions = extract_fields(named.named.iter(), |_, idt| {
                    let name = idt.expect("unnamed field in named enum");
                    quote! {#name}
                });

                let assignments = field_assignments(named.named.iter(), |_, idt| {
                    let name = idt.expect("unnamed field in named enum");
                    quote! {#name}
                }, true);

                result.push(quote! {
                    pub fn #fn_name #impl_generics (#(#field_extractions),*) -> Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                        Ok(#name::#variant_name {
                            #(#assignments),*
                        })
                    }

                    #add_fn_to_sig
                });
            }
            syn::Fields::Unnamed(unnamed) => {
                let field_extractions = extract_fields(unnamed.unnamed.iter(), |idx, _| {
                    let name = format_ident!("field_{}", syn::Index::from(idx));
                    quote! {#name}
                });
                let assignments = field_assignments(unnamed.unnamed.iter(), |idx, _| {
                    let name = format_ident!("field_{}", syn::Index::from(idx));
                    quote! {#name}
                }, false);
                result.push(quote! {
                    pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                        Ok(#name::#variant_name (
                            #(#assignments),*
                        ))
                    }

                    #add_fn_to_sig
                });
            }
            syn::Fields::Unit => result.push(quote! {
                pub fn #fn_name #impl_generics () ->  Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                    Ok(#name::#variant_name)
                }

                #add_fn_to_sig
            }),
        }
    }
    return quote! {
        #(#result)*
    };
}

fn map_type_definition(
    name: &syn::Ident,
    generics: &syn::Generics,
    input: &syn::DeriveInput,
    sig_metadata: &SigMetadata,
) -> TokenStream {
    match &input.data {
        syn::Data::Struct(st) => {
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
            let fn_name = format_ident!("fn_{}", name.to_string().to_lowercase());
            let add_fn_to_sig = add_to_signature(&fn_name, sig_metadata);

            match &st.fields {
                syn::Fields::Named(named) => {
                    let field_extractions = extract_fields(named.named.iter(), |_, idt| {
                        let name = idt.expect("unnamed field in named struct");
                        quote! {#name}
                    });
                    let assignments = field_assignments(
                        named.named.iter(),
                        |_, idt| {
                            let name = idt.expect("unnamed field in named struct");
                            quote! {#name}
                        },
                        true,
                    );

                    quote! {
                        pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                            Ok(#name {
                                #(#assignments),*
                            })
                        }

                        #add_fn_to_sig
                    }
                }
                syn::Fields::Unnamed(unnamed) => {
                    let field_extractions = extract_fields(unnamed.unnamed.iter(), |idx, _| {
                        let name = format_ident!("field_{}", syn::Index::from(idx));
                        quote! {#name}
                    });
                    let assignments = field_assignments(
                        unnamed.unnamed.iter(),
                        |idx, _| {
                            let name = format_ident!("field_{}", syn::Index::from(idx));
                            quote! {#name}
                        },
                        false,
                    );

                    quote! {
                        pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                            Ok(#name (
                                #(#assignments),*
                            ))
                        }

                        #add_fn_to_sig
                    }
                }
                syn::Fields::Unit => {
                    quote! {
                        pub fn #fn_name #impl_generics () ->  Result<#name #ty_generics #where_clause, puffin::algebra::error::FnError> {
                            Ok(#name {})
                        }

                        #add_fn_to_sig
                    }
                }
            }
        }
        syn::Data::Enum(en) => {
            extract_variants(&input.ident, generics, sig_metadata, en.variants.iter())
        }
        syn::Data::Union(_un) => {
            quote! {}
        }
    }
}
