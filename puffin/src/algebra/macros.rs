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
    // Deconstructor: `D(term, [matcher] / Type)`, `D(term, Type)` or `D(term)`, each with an
    // optional trailing counter `, N` selecting the N-th matching sub-value (default 0).
    //
    // Evaluates `term` (the source), then extracts out of it a sub-value of `Type`, selected by the
    // optional `matcher` (an `Option<Matcher>` expression, like the variable `[...]` syntax). These
    // arms must come before the function-application arm, otherwise `D(term, Type)` would be parsed
    // as an application of a function symbol named `D`.
    //
    // The type-less form `D(term)` is only valid as a function argument: the target type is then
    // inferred from the enclosing function's argument type (threaded in through `> $req_type`).
    //
    // The explicit-type arms come first (they are more specific), then the inferred-type arm, and
    // finally a `compile_error!` catch-all for a standalone `D(term)` that has no type to infer.
    (D( $st:tt $( ( $($inner:tt)* ) )? , [$matcher:expr] / $typ:ty $(, $counter:expr)? ) $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;
        use $crate::algebra::{DYTerm, Term};
        use $crate::trace::Query;

        Term::from(DYTerm::Deconstructor(
            TypeShape::of::<$typ>(),
            Box::new($crate::term_arg!($st $( ( $($inner)* ) )?)),
            Query {
                source: None,
                matcher: $matcher,
                counter: $crate::term_counter!($($counter)?),
            },
        ))
    }};
    (D( $st:tt $( ( $($inner:tt)* ) )? , $typ:ty $(, $counter:expr)? ) $(>$req_type:expr)?) => {{
        use $crate::algebra::dynamic_function::TypeShape;
        use $crate::algebra::{DYTerm, Term};
        use $crate::trace::Query;

        Term::from(DYTerm::Deconstructor(
            TypeShape::of::<$typ>(),
            Box::new($crate::term_arg!($st $( ( $($inner)* ) )?)),
            Query {
                source: None,
                matcher: None,
                counter: $crate::term_counter!($($counter)?),
            },
        ))
    }};
    (D( $st:tt $( ( $($inner:tt)* ) )? $(, $counter:expr)? ) > $req_type:expr) => {{
        use $crate::algebra::{DYTerm, Term};
        use $crate::trace::Query;

        Term::from(DYTerm::Deconstructor(
            $req_type,
            Box::new($crate::term_arg!($st $( ( $($inner)* ) )?)),
            Query {
                source: None,
                matcher: None,
                counter: $crate::term_counter!($($counter)?),
            },
        ))
    }};
    (D( $st:tt $( ( $($inner:tt)* ) )? $(, $counter:expr)? )) => {{
        compile_error!(
            "`D(term)` without an explicit type is only allowed as a function argument (where the \
             argument type is inferred); use `D(term, Type)` otherwise"
        )
    }};

    //
    // Function Applications
    ($func:ident ( $( $arg:tt $( ( $($inner:tt)* ) )? ),* ) $(>$req_type:expr)?) => {{
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
                Term::from($crate::term_arg!($arg $( ( $($inner)* ) )? > argument.clone()))
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
    // Parenthesized nested term (unwrap the parentheses and re-parse the content).
    // e.g. `(fn_f())`. This path is kept for backward compatibility when double parentheses were mandatory
    ( ( $($e:tt)* ) $(>$req_type:expr)?) => {{
        use $crate::algebra::Term;

        Term::from(term!($($e)* $(>$req_type)?))
    }};
    // Nested application without wrapping parentheses: `fn_f(...)`.
    ( $f:ident ( $($inner:tt)* ) $(>$req_type:expr)?) => {{
        use $crate::algebra::Term;

        Term::from(term!($f ( $($inner)* ) $(>$req_type)?))
    }};
    // Any single token tree (constant, variable, ...).
    ($e:tt $(>$req_type:expr)?) => {{
        Term::from(term!($e $(>$req_type)?))
    }};
}

/// Internal helper used by [`term!`]'s `D(...)` deconstructor arms to turn an optional trailing
/// counter into a value: absent means `0`, present means the given expression.
#[macro_export]
#[doc(hidden)]
macro_rules! term_counter {
    () => {
        0
    };
    ($counter:expr) => {
        $counter
    };
}
