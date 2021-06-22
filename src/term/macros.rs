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
            ($nodes:ident, ($step:expr, $msg:expr) / $typ:ty) => {{
                let id = $nodes.len();
                let var = $crate::term::signature::Signature::new_var::<$typ>(($step, $msg));
                let symbol = $crate::term::Symbol::Variable(var);

                let node = $crate::term::TermNode {
                    symbol,
                    subterms: vec![]
                };

                $nodes.push(node);
                id
            }};

            // Constants
            ($nodes:ident, $func:ident) => {{
                let id = $nodes.len();
                let func = $crate::term::signature::Signature::new_function(&$func);
                let symbol = $crate::term::Symbol::Application(func);

                let node = $crate::term::TermNode {
                    symbol,
                    subterms: vec![]
                };

                $nodes.push(node);
                id
            }};

            // Function Applications
            ($nodes:ident, $func:ident ($($args:tt),*)) => {{
                let func = $crate::term::signature::Signature::new_function(&$func);
                let symbol = $crate::term::Symbol::Application(func);

                let node = $crate::term::TermNode {
                    symbol,
                    subterms: vec![$($crate::term_arg!($nodes, $args)),*]
                };

                let id = $nodes.len();
                $nodes.push(node);
                id
            }};

            // Insert Term
            ($nodes:ident, @$e:expr) => {{
                $e.extend_vec(&mut $nodes)
            }};
        }

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    ($($all:tt)*) => {{
        let mut nodes: Vec<$crate::term::TermNode> = Vec::new();
        let root = $crate::_term!(nodes, $($all)*);
        $crate::term::Term::new(nodes, root)
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
