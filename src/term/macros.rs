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

use rustls::msgs::enums;
use std::any::TypeId;
use rustls::msgs::enums::HandshakeType;

fn hs_type(enu: TypeId) -> HandshakeType {
  panic!(); // TODO LH: I thought I could do this "coerce" automatically in the macro below, actually I would need to implement this function first :(
}

// todo we could improve performance by not recreating these
#[macro_export]
macro_rules! term {
    // Variables
    (($agent:expr, $counter:expr) / $typ:ty) => {{
        let var = $crate::term::signature::Signature::new_var_handshake::<$typ>($agent, hs_type($typ), $counter); // Hopefully, we can automatically "coerce" the type into a HandshakeType here
        $crate::term::Term::Variable(var)
    }};

     (($agent:expr, $counter:expr) H[$tls_typ:expr] / $typ:ty) => {{
        let var = $crate::term::signature::Signature::new_var_handshake::<$typ>($agent, $tls_typ, $counter); // explicitely giving an handshake type
        $crate::term::Term::Variable(var)
    }};

     (($agent:expr, $counter:expr) [tls_typ:expr] / $typ:ty) => {{
        let var = $crate::term::signature::Signature::new_var_no_handshake::<$typ>($agent, $tls_typ, $counter); // explicitely giving a non-handhskae ContentType
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
