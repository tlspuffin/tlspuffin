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
macro_rules! _term {
    // Variables
    ([$tree:ident, $behaviour:ident], ($step:expr, $msg:expr) / $typ:ty) => {{
        use $crate::term::signature::Signature;
        use $crate::term::Symbol;
        use id_tree::{Node, InsertBehavior};

        let var = Signature::new_var::<$typ>(($step, $msg));
        let symbol = Symbol::Variable(var);

        $tree.insert(Node::new(symbol), $behaviour)?
    }};

    // Constants
    ([$tree:ident, $behaviour:ident], $func:ident) => {{
        use $crate::term::signature::Signature;
        use $crate::term::Symbol;
        use id_tree::{Node, InsertBehavior};

        let func = Signature::new_function(&$func);
        let symbol = Symbol::Application(func);


        $tree.insert(Node::new(symbol), $behaviour)?
    }};

    // Function Applications
    ([$tree:ident, $behaviour:ident], $func:ident ($($args:tt),*)) => {{
        use $crate::term::signature::Signature;
        use $crate::term::Symbol;
        use id_tree::{Node, InsertBehavior};

        let func = Signature::new_function(&$func);
        let symbol = Symbol::Application(func);

        let node_id = $tree.insert(Node::new(symbol), $behaviour)?;

        $(
            let behaviour = InsertBehavior::UnderNode(&node_id);
            $crate::term_arg!([$tree, behaviour], $args);
        )*

        node_id
    }};

    // Insert Term
    ([$tree:ident, $behaviour:ident], @$e:expr) => {{
        $crate::term::insert_tree_at(&mut $tree, $behaviour, &$e.tree)?
    }};
}

#[macro_export]
macro_rules! term {
    ($($all_tokens:tt)*) => {{
        use $crate::term::Symbol;
        use $crate::error::Error;
        use id_tree::{Tree, TreeBuilder, Node, InsertBehavior};

        let mut tree: Tree<Symbol> = TreeBuilder::new()
            .with_node_capacity(30)
            .with_swap_capacity(10)
            .build();
        let behaviour = InsertBehavior::AsRoot;

        let build_tree = || -> Result<(), Error> {
            $crate::_term!([tree, behaviour], $($all_tokens)*);
            Ok(())
        };

        build_tree().unwrap();

        $crate::term::Term::new(tree)
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ([$tree:ident, $behaviour:ident], ( $($e:tt)* ) ) => ($crate::_term!([$tree, $behaviour], $($e)*));
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ([$tree:ident, $behaviour:ident], $e:tt) => ($crate::_term!([$tree, $behaviour], $e));
}
