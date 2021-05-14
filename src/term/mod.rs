// Code in this directory is derived from https://github.com/joshrule/term-rewriting-rs/
// and is licensed under:
//
// The MIT License (MIT)
// Copyright (c) 2018--2021
// Maximilian Ammann <max@maxammann.org>, Joshua S. Rule <joshua.s.rule@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub use self::atoms::*;
pub use self::signature::*;
pub use self::term::*;

mod atoms;
mod op_impl;
mod pretty;
mod signature;
mod term;
mod type_helper;

#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};
    use std::env::var;

    use rustls::internal::msgs::handshake::SessionID;

    use crate::agent::{Agent, AgentName};
    use crate::term::op_impl::{op_hmac256, op_hmac256_new_key};
    use crate::term::type_helper::{function_shape, make_dynamic, print_type_of};
    use crate::term::{Operator, Signature, Term, Variable, VariableContext};
    use crate::variable_data::{
        AgreedCipherSuiteData, AsAny, Metadata, SessionIDData, VariableData,
    };

    fn example_op_c(a: &u8) -> u16 {
        (a + 1) as u16
    }

    struct MockVariableContext {
        data: Vec<Box<dyn VariableData>>,
    }

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
        let context = MockVariableContext {
            data: vec![Box::new(DataVariable {
                metadata: Metadata {
                    owner: AgentName::none(),
                },
                data: vec![5u8],
            })],
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

        let closure_inferred = |i: &u64, d: &u32| i + 1;
        function_shape(&closure_inferred);
        function_shape(example_op_c);
        //inspect_function(&SessionIDData::get_metadata);

        let dynamic_fn = s.clone().dynamic_fn;
        println!(
            "{:?}",
            dynamic_fn(&vec![Box::new(1u8.as_any())])
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
