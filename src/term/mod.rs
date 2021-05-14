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
mod pretty;
mod signature;
mod term;
mod type_helper;

#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};

    use crate::agent::{Agent, AgentName};
    use crate::term::{Signature, Term, Operator};
    use crate::variable_data::{AgreedCipherSuiteData, AsAny, SessionIDData, VariableData};
    use crate::term::type_helper::{function_shape, print_type_of, make_dynamic};
    use rustls::internal::msgs::handshake::SessionID;


    fn example_op_c(a: &u8) -> u16 {
        (a + 1) as u16
    }

    #[test]
    fn example() {
        let mut sig = Signature::default();

        let app = sig.new_op("app", &example_op_c);
        let s = sig.new_op("example_op_c", &example_op_c);
        let k = sig.new_op("example_op_c", &example_op_c);

        let var_data = SessionIDData::random_value(AgentName::random());

        let k = sig.new_var(var_data.type_id());

        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.get_type_id());

        let closure_inferred = |i:&u64, d:&u32| i + 1;
        function_shape(&closure_inferred);
        function_shape(example_op_c);
        //inspect_function(&SessionIDData::get_metadata);

        let dynamic_fn = s.clone().dynamic_fn;
        println!("{:?}", dynamic_fn(vec![1u8.as_any()]).downcast_ref::<u8>().unwrap());
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
