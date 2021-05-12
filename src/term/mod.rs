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
    use crate::variable::{AgreedCipherSuiteData, AsAny, SessionIDData, VariableData};
    use crate::term::type_helper::{inspect_function, inspect_any, print_type_of, wrap_function};
    use rustls::internal::msgs::handshake::SessionID;


    fn example_op_c(a: &u8) -> u8 {
        a + 1
    }

    fn example_op(args: Vec<&dyn Any>) -> Box<dyn Any> {
        let ret = args[0].downcast_ref::<u64>().unwrap() + 1;
        return Box::new(ret);
    }



    #[test]
    fn example() {
        let mut sig = Signature::default();
        //let app = sig.new_op(2, "senc");
        //let s = sig.new_op(0, "s");
        //let k = sig.new_op(0, Some("k".to_string()));

        let var_data = SessionIDData::random_value(AgentName::random());

        let k = sig.new_var(var_data.type_id(), Some("k".to_string()));

        let x = var_data.data.as_any();

        let closure_inferred = |i:&u64, d:&u32| i + 1;


        println!("{:?}", TypeId::of::<SessionID>());
        println!("{:?}", var_data.get_type_id());
        print_type_of(&closure_inferred);
        inspect_function(&closure_inferred);
        //inspect_function(&SessionIDData::get_metadata);

        let (shape, dynamic_fn) = wrap_function(&example_op_c);
        println!("{:?}", dynamic_fn(vec![1u8.as_any()]).downcast_ref::<u8>().unwrap());
        println!("{:?}", shape);
        let op = Operator {
            name: "example_op",
            arity: 2,
            shape,
            dynamic_fn,
        };




        println!(
            "{}",
            example_op(vec![1u64.as_any()])
                .downcast_ref::<u64>()
                .unwrap()
        );

       /* let constructed_term = Term::Application {
            op: app,
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
        };*/

        //println!("{}", constructed_term.pretty());
    }
}
