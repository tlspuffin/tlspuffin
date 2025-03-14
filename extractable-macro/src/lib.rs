use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{Token, Type};

#[proc_macro_derive(
    Extractable,
    attributes(extractable, extractable_ignore, extractable_no_recursion,)
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

    let fields = map_type_definition(&input, &types.protocol_types);

    generate_impl(
        &input.ident,
        &input.generics,
        &types.protocol_types,
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
