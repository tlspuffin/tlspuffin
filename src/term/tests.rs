#[cfg(test)]
mod term {
    use std::any::{Any, TypeId};

    use rustls::internal::msgs::handshake::SessionID;

    use crate::{
        term::{
            op_impl::{op_client_hello, op_hmac256, op_hmac256_new_key, op_random_session_id},
            Signature, Term, Variable, VariableContext,
        },
        trace::TraceContext,
        variable_data::{AsAny, VariableData},
    };
    use crate::term::op_impl::{OP_FUNCTIONS, OP_TYPES};
    use std::ops::Deref;
    use itertools::Itertools;

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

        println!("{}", generated_term.pretty());
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

        let var_data = op_random_session_id();

        let k = sig.new_var::<SessionID>((0, 0));

        println!("vec {:?}", TypeId::of::<Vec<u8>>());
        println!("vec {:?}", TypeId::of::<Vec<u16>>());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.type_id());

        let dynamic_fn = s.clone().dynamic_fn;
        println!(
            "{:?}",
            dynamic_fn(&vec![Box::new(1u8)])
                .downcast_ref::<u16>()
                .unwrap()
        );
        println!("{}", s.shape);

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

        println!("{}", constructed_term.pretty());
    }

    #[test]
    fn test_static_functions() {
        println!("{}", OP_FUNCTIONS.iter().map(|tuple| tuple.0).join("\n"));
        println!("{}", OP_TYPES.iter().map(|typ| typ.to_string()).join("\n"));
    }
}
