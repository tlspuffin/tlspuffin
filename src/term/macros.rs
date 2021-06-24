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

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    // Variables
    (($step:expr, $msg:expr) / $typ:ty) => {{
        let var = $crate::term::signature::Signature::new_var::<$typ>( ($step, $msg));
        $crate::term::Term::Variable(var)
    }};

    // Constants
    ($func:ident) => {{
        let func = $crate::term::signature::Signature::new_function(&$func);
        $crate::term::Term::Application(func, vec![])
    }};

    // Function Applications
    ($func:ident ($($args:tt),*)) => {{
        let func = $crate::term::signature::Signature::new_function(&$func);
        $crate::term::Term::Application(func, vec![$($crate::term_arg!($args)),*])
    }};

    // Function Applications
    (@$e:ident) => {{
        let subterm: &$crate::term::Term = &$e;
        subterm.clone()
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ( ( $($e:tt)* ) ) => (term!($($e)*));
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ($e:tt) => (term!($e));
}
