use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::Token;

/// Helper attribute marking a field that is *not* a constructor parameter and is instead
/// initialised from the expression it wraps: `#[constructor_default(EXPR)]`.
const DEFAULT_ATTR: &str = "constructor_default";

/// Opt-in attribute requesting generation of the list constructors: `#[constructor_list]`.
///
/// For any type it generates the `Vec<Self>` constructors `fn_list_*_empty`,
/// `fn_list_*_append` and `fn_list_*_get_first`. For an **enum** it additionally generates one
/// finder per variant, `fn_list_*_find_<variant>`, returning the first list element belonging
/// to that variant. The variant is matched by shape (`matches!`), so it works for unit, tuple
/// and struct-like variants and never inspects the payload.
///
/// These functions operate on `Vec<Self>` and register it in the signature, which requires
/// `Vec<Self>: EvaluatedTerm` — i.e. `Self: Codec` (not merely `CodecP`) and `Vec<Self>: Codec`.
/// That only holds for genuine list *element* types, so list generation is off by default and
/// must be requested explicitly.
const LIST_ATTR: &str = "constructor_list";

/// Derives free constructor functions for a type and registers them into a puffin signature,
/// turning each struct / enum variant into a function symbol usable by the term algebra.
///
/// # Generated constructors
///
/// * For a **struct** `Foo`: one `fn_foo(&Field, ...) -> Result<Foo, FnError>` (no-arg for a unit
///   struct).
/// * For an **enum** `Foo`: one `fn_foo_<variant>(...) -> Result<Foo, FnError>` per variant.
///
/// Names are fully lower-cased (`HTTPResponse` → `fn_httpresponse`). Every field becomes a
/// by-reference parameter (`&FieldType`) that is cloned into the constructed value, unless it
/// carries `#[constructor_default(EXPR)]` (see below). The return type is always wrapped in
/// `Result<_, puffin::algebra::error::FnError>` so the functions satisfy `DescribableFunction`.
///
/// # Helper attributes
///
/// * `#[constructor(SIGNATURE, ProtocolTypes)]` — **required**, on the type. Names the signature
///   the generated functions are registered into (via `puffin::define_signature!`) and their
///   protocol-types type.
/// * `#[constructor_default(EXPR)]` — on a field. Excludes the field from the constructor
///   parameters and initialises it from `EXPR` (a literal, call, path, ...) instead.
/// * `#[constructor_list]` — on the type. Additionally generates, for a `Vec<Self>`,
///   `fn_list_*_empty`, `fn_list_*_append` and `fn_list_*_get_first`, plus (for enums) a
///   per-variant finder `fn_list_*_find_<variant>`.
#[proc_macro_derive(
    Constructor,
    attributes(constructor, constructor_default, constructor_list)
)]
pub fn constructor_macro(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let attribute = input
        .attrs
        .iter()
        .find(|a| a.path().segments.len() == 1 && a.path().segments[0].ident == "constructor")
        .expect("constructor attribute required for deriving Constructor!");

    let signature_metadata = SigMetadata::parse(attribute).expect(
        "failed parsing constructor attribute : expected #[constructor(SIGNATURE, ProtocolTypes)]",
    );

    let gen_list = has_attr(&input.attrs, LIST_ATTR).is_some();

    map_type_definition(
        &input.ident,
        &input.generics,
        &input,
        &signature_metadata,
        gen_list,
    )
    .into()
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
        puffin::define_signature!(
            #signature_name,
            #protocol_types;
            #fn_name
        );
    }
}

fn create_list_fn(
    name: &syn::Ident,
    generics: &syn::Generics,
    signature_metadata: &SigMetadata,
) -> TokenStream {
    let name_lower = name.to_string().to_lowercase();
    let create_list_fn_name = format_ident!("fn_list_{}_empty", name_lower);
    let append_list_fn_name = format_ident!("fn_list_{}_append", name_lower);
    let get_first_fn_name = format_ident!("fn_list_{}_get_first", name_lower);
    let signature_name = &signature_metadata.signature;
    let protocol_types = &signature_metadata.protocol_types;
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        pub fn #create_list_fn_name() -> Result<Vec<#name #ty_generics>, puffin::algebra::error::FnError>  #where_clause {
            Ok(vec![])
        }

        pub fn #append_list_fn_name(list: &Vec<#name #ty_generics>, e: &#name #ty_generics) -> Result<Vec<#name #ty_generics>, puffin::algebra::error::FnError> #where_clause {
            let mut new: Vec<#name #ty_generics> = list.clone();
            new.push(e.clone());
            Ok(new)
        }

        pub fn #get_first_fn_name(list: &Vec<#name #ty_generics>) -> Result<#name #ty_generics, puffin::algebra::error::FnError>  #where_clause {
            list.first().cloned().ok_or_else(|| puffin::algebra::error::FnError::Malformed("list is empty".to_string()))
        }

        impl puffin::codec::VecCodecWoSize for #name #ty_generics #where_clause {}

        puffin::define_signature!(
            #signature_name,
            #protocol_types;
            #create_list_fn_name
            #append_list_fn_name [list]
            #get_first_fn_name
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
    gen_list: bool,
    variants: impl IntoIterator<Item = &'a syn::Variant>,
) -> TokenStream {
    let mut result = vec![];

    let list_fn = if gen_list {
        create_list_fn(name, generics, sig_metadata)
    } else {
        quote! {}
    };

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
                    pub fn #fn_name #impl_generics (#(#field_extractions),*) -> Result<#name #ty_generics, puffin::algebra::error::FnError>  #where_clause {
                        Ok(#name::#variant_name {
                            #(#assignments),*
                        })
                    }
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
                    pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics, puffin::algebra::error::FnError> #where_clause {
                        Ok(#name::#variant_name (
                            #(#assignments),*
                        ))
                    }
                });
            }
            syn::Fields::Unit => result.push(quote! {
                pub fn #fn_name #impl_generics () ->  Result<#name #ty_generics , puffin::algebra::error::FnError> #where_clause {
                    Ok(#name::#variant_name)
                }
            }),
        }

        if gen_list {
            let get_variant_fn_name = format_ident!(
                "fn_list_{}_find_{}",
                name.to_string().to_lowercase(),
                variant_name.to_string().to_lowercase()
            );

            let add_find_variant_fn_to_sig = add_to_signature(&get_variant_fn_name, sig_metadata);

            let variant_pattern = match &variant.fields {
                syn::Fields::Named(_) => quote! { #name::#variant_name { .. } },
                syn::Fields::Unnamed(_) => quote! { #name::#variant_name ( .. ) },
                syn::Fields::Unit => quote! { #name::#variant_name },
            };

            // find the first element matching the variant and return it, or an error if none does
            result.push(quote! {
                pub fn #get_variant_fn_name(
                    list: &Vec<#name #ty_generics>,
                ) -> Result<#name #ty_generics, puffin::algebra::error::FnError> #where_clause {
                    let e = list
                        .iter()
                        .find(|x| matches!(x, #variant_pattern))
                        .ok_or(puffin::algebra::error::FnError::Malformed(
                            format!("Variant {}::{} not found in list", stringify!(#name), stringify!(#variant_name))
                        ))?;

                    Ok(e.clone())
                }

                #add_find_variant_fn_to_sig
            })
        }

        result.push(quote! {
            #add_fn_to_sig
        })
    }
    return quote! {
        #(#result)*

        #list_fn
    };
}

fn map_type_definition(
    name: &syn::Ident,
    generics: &syn::Generics,
    input: &syn::DeriveInput,
    sig_metadata: &SigMetadata,
    gen_list: bool,
) -> TokenStream {
    match &input.data {
        syn::Data::Struct(st) => {
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
            let fn_name = format_ident!("fn_{}", name.to_string().to_lowercase());
            let add_fn_to_sig = add_to_signature(&fn_name, sig_metadata);
            let create_list_fn = if gen_list {
                create_list_fn(name, generics, sig_metadata)
            } else {
                quote! {}
            };

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
                        pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics, puffin::algebra::error::FnError> #where_clause {
                            Ok(#name {
                                #(#assignments),*
                            })
                        }

                        #add_fn_to_sig
                        #create_list_fn
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
                        pub fn #fn_name #impl_generics (#(#field_extractions),*) ->  Result<#name #ty_generics, puffin::algebra::error::FnError>  #where_clause {
                            Ok(#name (
                                #(#assignments),*
                            ))
                        }

                        #add_fn_to_sig
                        #create_list_fn
                    }
                }
                syn::Fields::Unit => {
                    quote! {
                        pub fn #fn_name #impl_generics () ->  Result<#name #ty_generics, puffin::algebra::error::FnError>  #where_clause{
                            Ok(#name {})
                        }

                        #add_fn_to_sig
                        #create_list_fn
                    }
                }
            }
        }
        syn::Data::Enum(en) => extract_variants(
            &input.ident,
            generics,
            sig_metadata,
            gen_list,
            en.variants.iter(),
        ),
        syn::Data::Union(_un) => {
            quote! {}
        }
    }
}
