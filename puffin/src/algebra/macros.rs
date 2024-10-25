//! This module provides a DLS for writing [`Term`](crate::algebra::Term)s within Rust.
//! See the tlspuffin crate for usage examples.

#[macro_export]
macro_rules! term {
    //
    // Handshake with QueryMatcher
    // `>$req_type:expr` must be the last part of the arm, even if it is not used.
    //
    ((!$precomp:literal, $counter:expr) / $typ:ty $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;

        // ignore $req_type as we are overriding it with $type
        Term::from(term!((!$precomp, $counter) > TypeShape::of::<$typ>()))
    }};
    (($agent:expr, $counter:expr) / $typ:ty $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;
        use $crate::algebra::Term;


        // ignore $req_type as we are overriding it with $type
        Term::from(term!(($agent, $counter) > TypeShape::of::<$typ>()))
    }};
    ((!$precomp:literal, $counter:expr) $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::Term;
        use $crate::trace::Source;

        let var = Signature::new_var($($req_type)?, Some(Source::Label(Some($precomp.into()))), None, $counter); // TODO: verify hat using here None is fine. Before a refactor it was: Some(TlsMessageType::Handshake(None))
        Term::from(DYTerm::Variable(var))
    }};
    (($agent:expr, $counter:expr) $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::{DYTerm,Term};
        use $crate::trace::Source;

        let var = Signature::new_var($($req_type)?, Some(Source::Agent($agent)), None, $counter); // TODO: verify hat using here None is fine. Before a refactor it was: Some(TlsMessageType::Handshake(None))
        Term::from(DYTerm::Variable(var))
    }};

    //
    // Handshake TlsMessageType with `$message_type` as `TlsMessageType`
    //
    ((!$precomp:literal, $counter:expr) [$message_type:expr] / $typ:ty $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;

        // ignore $req_type as we are overriding it with $type
       Term::from(term!((!$precomp, $counter) [$message_type] > TypeShape::of::<$typ>()))
    }};
    (($agent:expr, $counter:expr) [$message_type:expr] / $typ:ty $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;

        // ignore $req_type as we are overriding it with $type
        Term::from(term!(($agent, $counter) [$message_type] > TypeShape::of::<$typ>()))
    }};
    // Extended with custom $type
    ((!$precomp:literal, $counter:expr) [$message_type:expr] $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::Term;
        use $crate::trace::Source;

        let var = Signature::new_var($($req_type)?, Some(Source::Label(Some($precomp.into()))), $message_type, $counter);
        Term::from(DYTerm::Variable(var))
    }};
    (($agent:expr, $counter:expr) [$message_type:expr] $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::{DYTerm,Term};
        use $crate::trace::Source;

        let var = Signature::new_var($($req_type)?, Some(Source::Agent($agent)), $message_type, $counter);
        Term::from(DYTerm::Variable(var))
    }};

    //
    // Function Applications
    //
    ($func:ident ($($args:tt),*) $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::{DYTerm,Term};

        let func = Signature::new_function(&$func);
        #[allow(unused_assignments, unused_variables, unused_mut)]
        let mut i = 0;

        #[allow(unused_assignments)]
        #[allow(clippy::mixed_read_write_in_expression)]
        let arguments = vec![$({
            #[allow(unused)]
            if let Some(argument) = func.shape().argument_types.get(i) {
                i += 1;
                Term::from($crate::term_arg!($args > argument.clone()))
            } else {
                panic!("too many arguments specified for function {}", func)
            }
        }),*];

        Term::from(DYTerm::Application(func, arguments))
    }};
    // Shorthand for constants
    ($func:ident $(>$req_type:expr)?) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::{DYTerm,Term};


        let func = Signature::new_function(&$func);
        Term::from(DYTerm::Application(func, vec![]))
    }};

    //
    // Allows to use variables which already contain a term by starting with a `@`
    //
    (@$e:ident $(>$req_type:expr)?) => {{
        use $crate::algebra::{DYTerm,Term};

        let subterm: &Term<_> = &$e;
        Term::from(subterm.clone())
    }};
}

#[macro_export]
macro_rules! term_arg {
    // Somehow the following rules is very important
    ( ( $($e:tt)* ) $(>$req_type:expr)?) => {{
        use $crate::algebra::{DYTerm,Term};

        Term::from(term!($($e)* $(>$req_type)?))
    }};
    // not sure why I should need this
    // ( ( $e:tt ) ) => (ast!($e));
    ($e:tt $(>$req_type:expr)?) => {{
        Term::from(term!($e $(>$req_type)?))
    }};
}
