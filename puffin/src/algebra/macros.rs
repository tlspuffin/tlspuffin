//! This module provides a DLS for writing [`Term`](crate::algebra::Term)s within Rust.
//! See the tlspuffin crate for usage examples.

#[macro_export]
macro_rules! term {
    //
    // Knowledge query: `K((source, counter) [matcher] / Type)`
    //
    // Looks the value up in the knowledge learned during the execution of the trace. The `source`
    // is either an agent (`K((server, 0) / Random)`) or the label of a precomputation, written with
    // a leading `!` (`K((!"decrypted_extensions", 0) / MessageFlight)`). The `[matcher]` part is an
    // `Option<Matcher>` expression restricting which messages are searched, and `counter` selects
    // the `counter`-th matching sub-value.
    //
    // Both the `[matcher]` and the `/ Type` parts are optional. Omitting the type is only valid as a
    // function argument: the target type is then inferred from the enclosing function's argument
    // type (threaded in through `> $req_type`).
    //
    // As for `D(...)` below, these arms must come before the function-application arm, otherwise
    // `K(...)` would be parsed as an application of a function symbol named `K`.
    //
    (K( (!$precomp:literal, $counter:expr) [$matcher:expr] / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Label(Some($precomp.into()))),
            $matcher, $counter, false
        )
    };
    (K( (!$precomp:literal, $counter:expr) / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Label(Some($precomp.into()))),
            None, $counter, false
        )
    };
    (K( (!$precomp:literal, $counter:expr) [$matcher:expr] ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Label(Some($precomp.into()))),
            $matcher, $counter, false
        )
    };
    (K( (!$precomp:literal, $counter:expr) ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Label(Some($precomp.into()))),
            None, $counter, false
        )
    };
    (K( ($agent:expr, $counter:expr) [$matcher:expr] / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Agent($agent)),
            $matcher, $counter, false
        )
    };
    (K( ($agent:expr, $counter:expr) / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Agent($agent)),
            None, $counter, false
        )
    };
    (K( ($agent:expr, $counter:expr) [$matcher:expr] ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Agent($agent)),
            $matcher, $counter, false
        )
    };
    (K( ($agent:expr, $counter:expr) ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Agent($agent)),
            None, $counter, false
        )
    };
    (K( $($rest:tt)* ) $(>$req_type:expr)?) => {{
        compile_error!(
            "malformed knowledge query: expected `K((source, counter) [matcher] / Type)`, where \
             `source` is an agent or a `!\"label\"` precomputation and where `[matcher]` and \
             `/ Type` are optional (the type can only be omitted in a function argument, where it \
             is inferred)"
        )
    }};

    //
    // Claim query: `C((agent, counter) [matcher] / Type)`
    //
    // Same syntax as the knowledge query `K(...)` above, but the value is looked up in the claims
    // made by the agent rather than in the knowledge learned from its messages. Claims are only
    // ever produced by agents, so a precomputation label is not a valid source here.
    //
    (C( (!$precomp:literal, $counter:expr) $($rest:tt)* ) $(>$req_type:expr)?) => {{
        compile_error!(
            "a claim query `C(...)` cannot have a precomputation label as source: claims are only \
             produced by agents, so use `C((agent, counter) ...)`"
        )
    }};
    (C( ($agent:expr, $counter:expr) [$matcher:expr] / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Agent($agent)),
            $matcher, $counter, true
        )
    };
    (C( ($agent:expr, $counter:expr) / $typ:ty ) $(>$req_type:expr)?) => {
        // ignore $req_type as we are overriding it with $typ
        $crate::term_query!(
            $crate::algebra::dynamic_function::TypeShape::of::<$typ>(),
            Some($crate::trace::Source::Agent($agent)),
            None, $counter, true
        )
    };
    (C( ($agent:expr, $counter:expr) [$matcher:expr] ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Agent($agent)),
            $matcher, $counter, true
        )
    };
    (C( ($agent:expr, $counter:expr) ) > $req_type:expr) => {
        $crate::term_query!(
            $req_type,
            Some($crate::trace::Source::Agent($agent)),
            None, $counter, true
        )
    };
    (C( $($rest:tt)* ) $(>$req_type:expr)?) => {{
        compile_error!(
            "malformed claim query: expected `C((agent, counter) [matcher] / Type)`, where \
             `[matcher]` and `/ Type` are optional (the type can only be omitted in a function \
             argument, where it is inferred)"
        )
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
                is_claim: false,
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
                is_claim: false,
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
                is_claim: false,
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

/// Internal helper used by [`term!`]'s `K(...)` and `C(...)` arms to build a variable term out of
/// an already resolved [`crate::algebra::dynamic_function::TypeShape`], source, matcher, counter
/// and `is_claim` flag.
#[macro_export]
#[doc(hidden)]
macro_rules! term_query {
    ($type_shape:expr, $source:expr, $matcher:expr, $counter:expr, $is_claim:expr) => {{
        use $crate::algebra::signature::Signature;
        use $crate::algebra::{DYTerm, Term};

        let var = Signature::new_var($type_shape, $source, $matcher, $counter, $is_claim);
        Term::from(DYTerm::Variable(var))
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
