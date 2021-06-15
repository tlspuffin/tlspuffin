#[cfg(test)]
mod macros {
    use rustls::ProtocolVersion;

    use crate::term;
    use crate::tls::fn_impl::*;

    fn test_compilation() {
        // reminds me of Lisp, lol
        let _test_nested_with_variable = term! {
           fn_client_hello(
                (fn_client_hello(
                    fn_protocol_version12,
                    fn_new_random,
                    (fn_client_hello(fn_protocol_version12,
                        fn_new_random,
                        fn_new_random,
                        ((0,0)/ProtocolVersion)
                    ))
                )),
                fn_new_random
            )
        };

        let _set_simple_function2 = term! {
           fn_client_hello((fn_protocol_version12()), fn_new_random, fn_new_random)
        };

        let _test_simple_function1 = term! {
           fn_protocol_version12
        };
        let _test_simple_function = term! {
           fn_new_random(((0,0)/ProtocolVersion))
        };
        let _test_variable = term! {
            (0,0)/ProtocolVersion
        };
        let _set_nested_function = term! {
           fn_client_extensions_append(
                (fn_client_extensions_append(
                    fn_client_extensions_new,
                    fn_SECP384R1_support_group_extension
                )),
                fn_SECP384R1_support_group_extension
            )
        };
    }
}

#[cfg(test)]
mod term {
    use std::any::{Any, TypeId};

    use itertools::Itertools;
    use rustls::internal::msgs::handshake::SessionID;

    use crate::term::Signature;
    use crate::tls::fn_impl::{fn_client_hello, fn_hmac256, fn_hmac256_new_key, fn_new_session_id};
    use crate::tls::{error::FnError, SIGNATURE};
    use crate::{term::Term, trace::TraceContext};

    fn example_op_c(a: &u8) -> Result<u16, FnError> {
        Ok((a + 1) as u16)
    }

    #[test]
    fn example() {
        let hmac256_new_key = Signature::new_function(&fn_hmac256_new_key);
        let hmac256 = Signature::new_function(&fn_hmac256);
        let _client_hello = Signature::new_function(&fn_client_hello);

        let data = "hello".as_bytes().to_vec();

        println!("TypeId of vec array {:?}", data.type_id());

        let variable = Signature::new_var::<Vec<u8>>((0, 0));

        let generated_term = Term::Application(
            hmac256,
            vec![
                Term::Application(hmac256_new_key, vec![]),
                Term::Variable(variable),
            ],
        );

        println!("{}", generated_term);
        let mut context = TraceContext::new();
        context.add_variable((0, 0), Box::new(data));

        println!(
            "{:?}",
            generated_term
                .evaluate(&context)
                .as_ref()
                .unwrap()
                .downcast_ref::<Vec<u8>>()
        );
    }

    #[test]
    fn playground() {
        let var_data = fn_new_session_id();

        println!("vec {:?}", TypeId::of::<Vec<u8>>());
        println!("vec {:?}", TypeId::of::<Vec<u16>>());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.type_id());

        let func = Signature::new_function(&example_op_c).clone();
        let dynamic_fn = func.dynamic_fn();
        println!(
            "{:?}",
            dynamic_fn(&vec![Box::new(1u8)])
                .unwrap()
                .downcast_ref::<u16>()
                .unwrap()
        );
        println!("{}", Signature::new_function(&example_op_c).shape());

        let constructed_term = Term::Application(
            Signature::new_function(&example_op_c),
            vec![
                Term::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        Term::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                Term::Application(Signature::new_function(&example_op_c), vec![]),
                                Term::Variable(Signature::new_var::<SessionID>((0, 0))),
                            ],
                        ),
                        Term::Variable(Signature::new_var::<SessionID>((0, 0))),
                    ],
                ),
                Term::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        Term::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                Term::Variable(Signature::new_var::<SessionID>((0, 0))),
                                Term::Application(Signature::new_function(&example_op_c), vec![]),
                            ],
                        ),
                        Term::Variable(Signature::new_var::<SessionID>((0, 0))),
                    ],
                ),
            ],
        );

        println!("{}", constructed_term);
        println!("{}", constructed_term.dot_subgraph(true, 0, "test"));
    }

    #[test]
    fn test_static_functions() {
        println!(
            "{}",
            SIGNATURE
                .functions_by_name
                .iter()
                .map(|tuple| tuple.0)
                .join("\n")
        );
        println!(
            "{}",
            SIGNATURE
                .types_by_name
                .iter()
                .map(|tuple| tuple.0.to_string())
                .join("\n")
        );
    }
}
