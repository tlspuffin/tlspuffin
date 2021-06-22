//! This module provides a DLS for writing[`Term`]swithin Rust.
//!
//! # Example
//!
//! ```rust
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::term;
//! use rustls::{ProtocolVersion, CipherSuite};
//! use rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use rustls::msgs::enums::Compression;
//!
//! let term = term! {
//!     fn_client_hello(
//!         ((0, 0)/ProtocolVersion),
//!         ((0, 0)/Random),
//!         ((0, 0)/SessionID),
//!         ((0, 0)/Vec<CipherSuite>),
//!         ((0, 0)/Vec<Compression>),
//!         ((0, 0)/Vec<ClientExtension>)
//!     )
//! };
//! ```

#[macro_export]
macro_rules! app_const {
    ($op:ident) => {
        Symbol::Application(Signature::new_function(&$op), vec![])
    };
}

#[macro_export]
macro_rules! app {
    ($op:ident, $($args:expr),*$(,)?) => {
        Symbol::Application(Signature::new_function(&$op),vec![$($args,)*])
    };
}

#[macro_export]
macro_rules! var {
    ($typ:ty, $id:expr) => {
        Symbol::Variable(Signature::new_var::<$typ>($id))
    };
}

#[macro_export]
macro_rules! _term {
// Variables
            ($symbols:ident, ($step:expr, $msg:expr) / $typ:ty) => {{
                let var = $crate::term::signature::Signature::new_var::<$typ>( ($step, $msg));
                let symbol =  $crate::term::Symbol::Variable(var);

                $symbols.push(symbol);
                $crate::term::TermIndex {
                    id: $symbols.len() - 1,
                    subterms: vec![]
                }
            }};

            // Constants
            ($symbols:ident, $func:ident) => {{
                let func = $crate::term::signature::Signature::new_function(&$func);
                let symbol = $crate::term::Symbol::Application(func);

                $symbols.push(symbol);
                $crate::term::TermIndex {
                    id: $symbols.len() - 1,
                    subterms: vec![]
                }
            }};

            // Function Applications
            ($symbols:ident, $func:ident ($($args:tt),*)) => {{
                let func = $crate::term::signature::Signature::new_function(&$func);
                let symbol = $crate::term::Symbol::Application(func);

                $symbols.push(symbol);
                $crate::term::TermIndex {
                    id: $symbols.len() - 1,
                    subterms: vec![$($crate::term_arg!($symbols, $args)),*]
                }
            }};

            // Insert Term
            ($symbols:ident, @$e:expr) => {{
                let mut new_index = $e.index.clone();
                new_index.shift_ids($symbols.len());
                $symbols.extend($e.symbols.clone());
                new_index
            }};
        }

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    ($($all:tt)*) => {{
        let mut symbols: Vec<$crate::term::Symbol> = Vec::new();
        let index = $crate::_term!(symbols, $($all)*);
        $crate::term::Term::new(symbols, index)
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ($symbols:ident, ( $($e:tt)* ) ) => ($crate::_term!($symbols, $($e)*));
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ($symbols:ident, $e:tt) => ($crate::_term!($symbols, $e));
}
