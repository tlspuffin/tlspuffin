#[cfg(test)]
mod term {
    use std::any::{Any, TypeId};

    use rustls::internal::msgs::handshake::SessionID;

    use crate::agent::AgentName;
    use crate::term::{Signature, Term, Variable, VariableContext};
    use crate::term::op_impl::{op_client_hello, op_hmac256, op_hmac256_new_key};
    use crate::variable_data::{
        AsAny, Metadata, SessionIDData, VariableData,
    };

    fn example_op_c(a: &u8) -> u16 {
        (a + 1) as u16
    }

    struct MockVariableContext {
        data: Vec<Box<dyn VariableData>>,
    }

    #[derive(Clone)]
    pub struct DataVariable {
        pub metadata: Metadata,
        pub data: Vec<u8>,
    }

    impl VariableData for DataVariable {
        fn get_metadata(&self) -> &Metadata {
            &self.metadata
        }

        fn get_data(&self) -> &dyn Any {
            self.data.as_any()
        }

        fn random_value(owner: AgentName) -> Self
            where
                Self: Sized,
        {
            todo!()
        }

        fn clone_data(&self) -> Box<dyn Any> {
            Box::new(self.data.clone())
        }
    }

    impl<'a> VariableContext for MockVariableContext {
        fn find_variable_data(&self, variable: &Variable) -> Option<&dyn VariableData> {
            for d in &self.data {
                if d.get_type_id() == variable.typ {
                    return Some(d.as_ref());
                }
            }

            return None;
        }
    }

    #[test]
    fn example() {
        let mut sig = Signature::default();

        let hmac256_new_key = sig.new_op("hmac256_new_key", &op_hmac256_new_key);
        let hmac256 = sig.new_op("op_hmac256", &op_hmac256);
        let client_hello = sig.new_op("op_client_hello", &op_client_hello);

        let variable_data = "hello".as_bytes().to_vec();

        let data = sig.new_var(variable_data.type_id());

        let generated_term = Term::Application {
            op: hmac256,
            args: vec![
                Term::Application {
                    op: hmac256_new_key,
                    args: vec![],
                },
                Term::Variable(data),
            ],
        };

        println!("{}", generated_term.pretty());
        let x = Box::new(DataVariable {
            metadata: Metadata {
                owner: AgentName::none(),
            },
            data: vec![5u8],
        });

        let context = MockVariableContext {
            data: vec![x],
        };
        println!("{:?}", generated_term.evaluate(&context).as_ref().downcast_ref::<Vec<u8>>());
    }

    #[test]
    fn playground() {
        let mut sig = Signature::default();

        let app = sig.new_op("app", &example_op_c);
        let s = sig.new_op("example_op_c", &example_op_c);
        let k = sig.new_op("example_op_c", &example_op_c);

        let var_data = SessionIDData::random_value(AgentName::random());

        let k = sig.new_var(var_data.type_id());

        println!("vec {:?}", TypeId::of::<Vec<u8>>());
        println!("vec {:?}", TypeId::of::<Vec<u16>>());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.get_type_id());

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
}
