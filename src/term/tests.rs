#[cfg(test)]
mod macros {
    use rustls::ProtocolVersion;

    use crate::term;
    use crate::tls::fn_impl::*;

    fn test_compilation() {
        // reminds me of Lisp, lol
        let test_nested_with_variable = term! {
           fn_client_hello(
                (fn_client_hello(
                    fn_protocol_version12,
                    fn_random,
                    (fn_client_hello(fn_protocol_version12,
                        fn_random,
                        fn_random,
                        ((0,0)/ProtocolVersion)
                    ))
                )),
                fn_random
            )
        };

        let set_simple_function2 = term! {
           fn_client_hello(fn_protocol_version12, fn_random, fn_random)
        };

        let test_simple_function1 = term! {
           fn_protocol_version12()
        };
        let test_simple_function = term! {
           fn_random(((0,0)/ProtocolVersion))
        };
        let test_variable = term! {
            (0,0)/ProtocolVersion
        };
        let set_nested_function = term! {
           fn_extensions_append(
                (fn_extensions_append(
                    fn_extensions_new,
                    fn_x25519_support_group_extension
                )),
                fn_x25519_support_group_extension
            )
        };
    }
}

#[cfg(test)]
mod term {
    use std::any::{Any, TypeId};

    use itertools::Itertools;
    use rustls::internal::msgs::handshake::SessionID;

    use crate::tls::fn_impl::{fn_client_hello, fn_hmac256, fn_hmac256_new_key, fn_session_id};
    use crate::tls::{FnError, REGISTERED_FN, REGISTERED_TYPES};
    use crate::{
        term::{Signature, Term},
        trace::TraceContext,
    };

    fn example_op_c(a: &u8) -> Result<u16, FnError> {
        Ok((a + 1) as u16)
    }

    #[test]
    fn example() {
        let mut sig = Signature::default();

        let hmac256_new_key = sig.new_function(&fn_hmac256_new_key);
        let hmac256 = sig.new_function(&fn_hmac256);
        let _client_hello = sig.new_function(&fn_client_hello);

        let data = "hello".as_bytes().to_vec();

        println!("TypeId of vec array {:?}", data.type_id());

        let variable = sig.new_var::<Vec<u8>>((0, 0));

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
        let mut sig = Signature::default();

        let example = sig.new_function(&example_op_c);
        let example1 = sig.new_function(&example_op_c);

        let var_data = fn_session_id();

        let k = sig.new_var::<SessionID>((0, 0));

        println!("vec {:?}", TypeId::of::<Vec<u8>>());
        println!("vec {:?}", TypeId::of::<Vec<u16>>());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.type_id());

        let func = example.clone();
        let dynamic_fn = func.dynamic_fn();
        println!(
            "{:?}",
            dynamic_fn(&vec![Box::new(1u8)])
                .unwrap()
                .downcast_ref::<u16>()
                .unwrap()
        );
        println!("{}", example.shape());

        let constructed_term = Term::Application(
            example1.clone(),
            vec![
                Term::Application(
                    example1.clone(),
                    vec![
                        Term::Application(
                            example1.clone(),
                            vec![
                                Term::Application(example1.clone(), vec![]),
                                Term::Variable(k.clone()),
                            ],
                        ),
                        Term::Variable(k.clone()),
                    ],
                ),
                Term::Application(
                    example1.clone(),
                    vec![
                        Term::Application(
                            example1.clone(),
                            vec![
                                Term::Variable(k.clone()),
                                Term::Application(example.clone(), vec![]),
                            ],
                        ),
                        Term::Variable(k.clone()),
                    ],
                ),
            ],
        );

        println!("{}", constructed_term);
    }

    #[test]
    fn test_static_functions() {
        println!("{}", REGISTERED_FN.iter().map(|tuple| tuple.0).join("\n"));
        println!(
            "{}",
            REGISTERED_TYPES
                .iter()
                .map(|tuple| tuple.0.to_string())
                .join("\n")
        );
    }
}
