//! This module provides a DLS for writing[`Term`]swithin Rust.
//!
//! # Example
//!
//! ```rust
//! use tlspuffin::tls::fn_impl::fn_client_hello;
//! use tlspuffin::term;
//! use tlspuffin::agent::AgentName;
//! use rustls::{ProtocolVersion, CipherSuite};
//! use rustls::msgs::handshake::{SessionID, Random, ClientExtension};
//! use rustls::msgs::enums::Compression;
//!
//! let client = AgentName::first();
//! let term = term! {
//!     fn_client_hello(
//!         ((client, 0)/ProtocolVersion),
//!         ((client, 0)/Random),
//!         ((client, 0)/SessionID),
//!         ((client, 0)/Vec<CipherSuite>),
//!         ((client, 0)/Vec<Compression>),
//!         ((client, 0)/Vec<ClientExtension>)
//!     )
//! };
//! ```





#[macro_export]
macro_rules! term {
    // Handshake Variable
    (($agent:expr, $counter:expr) / $typ:ty) => {{
        use crate::trace::TlsMessageType;

        let var = $crate::term::signature::Signature::new_var_by_type::<$typ>($agent, Some(TlsMessageType::Handshake(None)), $counter);
        $crate::term::Term::Variable(var)
    }};

    // Handshake Variable
    (($agent:expr, $counter:expr) [H] / $typ:ty) => {{
        use crate::trace::TlsMessageType;

        let var = $crate::term::signature::Signature::new_var_by_type::<$typ>($agent, Some(TlsMessageType::Handshake(None)), $counter);
        $crate::term::Term::Variable(var)
    }};

    // Handshake Variable
    (($agent:expr, $counter:expr) [H::$hs_type:expr] / $typ:ty) => {{
        use crate::trace::TlsMessageType;

        let var = $crate::term::signature::Signature::new_var_by_type::<$typ>($agent, Some(TlsMessageType::Handshake(Some($hs_type))), $counter);
        $crate::term::Term::Variable(var)
    }};

    // Application Data Variable
    (($agent:expr, $counter:expr) [A] / $typ:ty) => {{
        use crate::trace::TlsMessageType;

        let var = $crate::term::signature::Signature::new_var_by_type::<$typ>($agent, Some(TlsMessageType::ApplicationData), $counter);
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
