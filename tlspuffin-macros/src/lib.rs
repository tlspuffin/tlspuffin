use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{braced, parse_macro_input, parse_quote, spanned::Spanned};

// #[expand_cfg("openssl111k", and(tls12, tls13))] => #[cfg(and(tls12 = "openssl111k", tls13 = "openssl111k"))]
#[proc_macro_attribute]
pub fn expand_cfg(args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as syn::Item);
    let expansion = parse_macro_input!(args as Expansion);

    let output = if let Some(predicate) = expansion.predicate {
        let expanded = bind_value(&predicate, &expansion.bound_val);

        quote! {
            #[cfg( #expanded )]
            #item
        }
    } else {
        quote! { #item }
    };

    quote! { #output }.into()
}

#[derive(Clone)]
enum ConfigPredicate {
    All(Vec<ConfigPredicate>),
    Any(Vec<ConfigPredicate>),
    Not(Vec<ConfigPredicate>),
    BoundOption(syn::MetaNameValue),
    FreeOption(syn::Path),
}

impl syn::parse::Parse for ConfigPredicate {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let meta: syn::Meta = input.parse()?;
        match meta {
            // all(tls12, tls13, ...)
            syn::Meta::List(meta) if meta.path.is_ident("all") => {
                Ok(ConfigPredicate::All(meta.parse_args_with(
                    syn::punctuated::Punctuated::<ConfigPredicate, syn::Token![,]>::parse_terminated,
                )?.into_iter().collect()))
            }

            // any(tls12, tls13, ...)
            syn::Meta::List(meta) if meta.path.is_ident("any") => {
                Ok(ConfigPredicate::Any(meta.parse_args_with(
                    syn::punctuated::Punctuated::<ConfigPredicate, syn::Token![,]>::parse_terminated,
                )?.into_iter().collect()))
            }

            // not(tls12)
            syn::Meta::List(meta) if meta.path.is_ident("not") => {
                Ok(ConfigPredicate::Not(meta.parse_args_with(
                    syn::punctuated::Punctuated::<ConfigPredicate, syn::Token![,]>::parse_terminated,
                )?.into_iter().collect()))
            }

            syn::Meta::Path(path) => Ok(ConfigPredicate::FreeOption(path)),
            syn::Meta::NameValue(meta) => Ok(ConfigPredicate::BoundOption(meta)),

            _ => Err(syn::Error::new_spanned(meta, "unknown cfg predicate")),
        }
    }
}

impl quote::ToTokens for ConfigPredicate {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        match self {
            ConfigPredicate::All(predicates) => {
                quote! { all(#( #predicates ),*) }.to_tokens(tokens)
            }
            ConfigPredicate::Any(predicates) => {
                quote! { any(#( #predicates ),*) }.to_tokens(tokens)
            }
            ConfigPredicate::Not(predicates) => {
                quote! { not(#( #predicates ),*) }.to_tokens(tokens)
            }
            ConfigPredicate::BoundOption(meta) => meta.to_tokens(tokens),
            ConfigPredicate::FreeOption(path) => quote! { #path }.to_tokens(tokens),
        }
    }
}

fn bind_value(predicate: &ConfigPredicate, val: &syn::LitStr) -> ConfigPredicate {
    match predicate {
        ConfigPredicate::All(predicates) => {
            ConfigPredicate::All(predicates.iter().map(|p| bind_value(p, val)).collect())
        }
        ConfigPredicate::Any(predicates) => {
            ConfigPredicate::Any(predicates.iter().map(|p| bind_value(p, val)).collect())
        }
        ConfigPredicate::Not(predicates) => {
            ConfigPredicate::Not(predicates.iter().map(|p| bind_value(p, val)).collect())
        }
        ConfigPredicate::BoundOption(_) => predicate.clone(),
        ConfigPredicate::FreeOption(path) => {
            ConfigPredicate::BoundOption(parse_quote! { #path = #val })
        }
    }
}

struct Expansion {
    bound_val: syn::LitStr,
    predicate: Option<ConfigPredicate>,
}

impl syn::parse::Parse for Expansion {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        let bound_val: syn::LitStr = if lookahead.peek(syn::Ident) {
            let ident = input.parse::<syn::Ident>()?.to_string();
            syn::LitStr::new(ident.as_str(), ident.span())
        } else if lookahead.peek(syn::LitStr) {
            input.parse()?
        } else {
            return Err(lookahead.error());
        };

        let comma: Option<syn::Token![,]> = input.parse()?;
        let predicate: Option<ConfigPredicate> = if comma.is_some() {
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Expansion {
            bound_val,
            predicate,
        })
    }
}

// replace!(__PUT__ => openssl111k in [ fn __PUT__() { println!("{}", stringify!(__PUT__)) } ] );
//
// =>
//
// fn openssl111k() { println!("{}", stringify!(openssl111k)) }
#[proc_macro]
pub fn replace(input: TokenStream) -> TokenStream {
    parse_macro_input!(input as Replacement).render().into()
}

struct Replacement {
    old: syn::Ident,
    new: syn::Expr,
    body: proc_macro2::TokenStream,
}

impl Replacement {
    fn render(&self) -> proc_macro2::TokenStream {
        self.body
            .clone()
            .into_iter()
            .map(|tt| replace_ident(&self.old, &self.new, &tt))
            .collect()
    }
}

fn replace_ident(
    old: &syn::Ident,
    new: &syn::Expr,
    content: &proc_macro2::TokenTree,
) -> proc_macro2::TokenStream {
    match content {
        proc_macro2::TokenTree::Ident(ref ident) if ident == old => new.clone().to_token_stream(),

        proc_macro2::TokenTree::Group(ref group) => proc_macro2::Group::new(
            group.delimiter(),
            group
                .stream()
                .into_iter()
                .map(|inner_tt| replace_ident(old, new, &inner_tt))
                .collect(),
        )
        .to_token_stream(),

        other => other.clone().to_token_stream(),
    }
}

impl syn::parse::Parse for Replacement {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let old = input.parse()?;
        let _: syn::Token![=>] = input.parse()?;
        let new = input.parse()?;
        let _: syn::Token![in] = input.parse()?;

        let content;
        let _ = braced!(content in input);
        let body: proc_macro2::TokenStream = content.parse()?;

        Ok(Replacement { old, new, body })
    }
}

// #[apply(my_macro, arg1, arg2_1 => arg2_2)]
// fn the_function_name() {
//     [...]
// }
//
// =>
//
// #[allow(dead_code)]
// fn the_function_name() {
//     [...]
// }
//
// my_macro!(the_function_name, arg1, arg2_1 => arg2_2);
#[proc_macro_attribute]
pub fn apply(args: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as syn::ItemFn);
    let MacroCall {
        macro_name,
        macro_args,
    } = parse_macro_input!(args as MacroCall);
    let func = &item.sig.ident;

    if macro_args.is_some() {
        quote! {
            #[allow(dead_code)]
            #item

            #macro_name ! ( #func, #macro_args );
        }
        .into()
    } else {
        quote! {
            #[allow(dead_code)]
            #item

            #macro_name ! ( #func );
        }
        .into()
    }
}

struct MacroCall {
    macro_name: syn::Ident,
    macro_args: Option<proc_macro2::TokenStream>,
}

impl syn::parse::Parse for MacroCall {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let macro_name = input.parse()?;
        let comma: Option<syn::Token![,]> = input.parse()?;
        let macro_args: Option<proc_macro2::TokenStream> = if comma.is_some() {
            input.step(|cursor| Ok((Some(cursor.token_stream()), syn::buffer::Cursor::empty())))?
        } else {
            None
        };

        Ok(MacroCall {
            macro_name,
            macro_args,
        })
    }
}
