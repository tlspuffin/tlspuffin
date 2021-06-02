#[cfg(test)]
mod term {
    use std::any::{Any, TypeId};

    use itertools::Itertools;
    use rustls::internal::msgs::handshake::SessionID;

    use crate::{
        term::{
            Signature, Term,
        },
        trace::TraceContext,
    };
    use crate::tls::op_impl::{REGISTERED_FN, REGISTERED_TYPES};
    use crate::tls::op_impl::{op_client_hello, op_hmac256, op_hmac256_new_key, op_session_id};

    fn example_op_c(a: &u8) -> u16 {
        (a + 1) as u16
    }

    #[test]
    fn example() {
        let mut sig = Signature::default();

        let hmac256_new_key = sig.new_op(&op_hmac256_new_key);
        let hmac256 = sig.new_op(&op_hmac256);
        let _client_hello = sig.new_op(&op_client_hello);

        let data = "hello".as_bytes().to_vec();

        println!("dd {:?}", data.type_id());

        let variable = sig.new_var::<Vec<u8>>((0, 0));

        let generated_term = Term::Application {
            op: hmac256,
            args: vec![
                Term::Application {
                    op: hmac256_new_key,
                    args: vec![],
                },
                Term::Variable(variable),
            ],
        };

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

        let app = sig.new_op(&example_op_c);
        let s = sig.new_op(&example_op_c);

        let var_data = op_session_id();

        let k = sig.new_var::<SessionID>((0, 0));

        println!("vec {:?}", TypeId::of::<Vec<u8>>());
        println!("vec {:?}", TypeId::of::<Vec<u16>>());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.type_id());

        let operator = s.clone();
        let dynamic_fn = operator.dynamic_fn();
        println!(
            "{:?}",
            dynamic_fn(&vec![Box::new(1u8)])
                .downcast_ref::<u16>()
                .unwrap()
        );
        println!("{}", s.shape());

        let constructed_term = Term::Application {
            op: app.clone(),
            args: vec![
                Term::Application {
                    op: app.clone(),
                    args: vec![
                        Term::Application {
                            op: app.clone(),
                            args: vec![
                                Term::Application {
                                    op: s.clone(),
                                    args: vec![],
                                },
                                Term::Variable(k.clone()),
                            ],
                        },
                        Term::Variable(k.clone()),
                    ],
                },
                Term::Application {
                    op: app.clone(),
                    args: vec![
                        Term::Application {
                            op: app.clone(),
                            args: vec![
                                Term::Variable(k.clone()),
                                Term::Application {
                                    op: s.clone(),
                                    args: vec![],
                                },
                            ],
                        },
                        Term::Variable(k.clone()),
                    ],
                },
            ],
        };

        println!("{}", constructed_term);
    }

    #[test]
    fn test_static_functions() {
        println!("{}", REGISTERED_FN.iter().map(|tuple| tuple.0).join("\n"));
        println!("{}", REGISTERED_TYPES.iter().map(|tuple| tuple.0.to_string()).join("\n"));
    }
}
