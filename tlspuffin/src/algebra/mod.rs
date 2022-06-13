//! The *term* module defines typed[`Term`]sof the form `fn_add(x: u8, fn_square(y: u16)) → u16`.
//! Each function like `fn_add` or `fn_square` has a shape. The variables `x` and `y` each have a
//! type. These types allow type checks during the runtime of the fuzzer.
//! These checks restrict how[`Term`]scan be mutated in the *fuzzer* module.

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

pub use self::term::*;

pub mod atoms;
pub mod dynamic_function;
pub mod macros;
pub mod signature;
mod term;

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use ring::{hmac, hmac::Key, test::rand::FixedByteRandom};
    use rustls::{msgs::handshake::SessionID, ProtocolVersion};

    use crate::{
        agent::AgentName,
        algebra::{signature::Signature, Term},
        term,
        tls::{
            error::FnError,
            fn_impl::{fn_client_hello, fn_new_session_id, *},
            SIGNATURE,
        },
        trace::{Knowledge, Query, TraceContext},
    };

    pub fn fn_hmac256_new_key() -> Result<Key, FnError> {
        let random = FixedByteRandom { byte: 12 };
        Ok(hmac::Key::generate(hmac::HMAC_SHA256, &random)?)
    }

    #[allow(clippy::ptr_arg)]
    pub fn fn_hmac256(key: &Key, msg: &Vec<u8>) -> Result<Vec<u8>, FnError> {
        let tag = hmac::sign(key, msg);
        Ok(Vec::from(tag.as_ref()))
    }

    #[allow(dead_code)]
    fn test_compilation() {
        // reminds me of Lisp, lol
        let client = AgentName::first();
        let _test_nested_with_variable = term! {
           fn_client_hello(
                (fn_client_hello(
                    fn_protocol_version12,
                    fn_new_random,
                    (fn_client_hello(fn_protocol_version12,
                        fn_new_random,
                        fn_new_random,
                        ((client,0)/ProtocolVersion)
                    ))
                )),
                fn_new_random
            )
        };

        let _set_simple_function2 = term! {
           fn_client_hello((fn_protocol_version12()), fn_new_random, fn_new_random)
        };

        let _test_simple_function2 = term! {
           fn_new_random(((client,0)))
        };
        let _test_simple_function1 = term! {
           fn_protocol_version12
        };
        let _test_simple_function = term! {
           fn_new_random(((client,0)/ProtocolVersion))
        };
        let _test_variable = term! {
            (client,0)/ProtocolVersion
        };
        let _set_nested_function = term! {
           fn_client_extensions_append(
                (fn_client_extensions_append(
                    fn_client_extensions_new,
                    fn_secp384r1_support_group_extension
                )),
                fn_secp384r1_support_group_extension
            )
        };
    }

    fn example_op_c(a: &u8) -> Result<u16, FnError> {
        Ok((a + 1) as u16)
    }

    #[test]
    fn example() {
        let hmac256_new_key = Signature::new_function(&fn_hmac256_new_key);
        let hmac256 = Signature::new_function(&fn_hmac256);
        let _client_hello = Signature::new_function(&fn_client_hello);

        let data = "hello".as_bytes().to_vec();

        //println!("TypeId of vec array {:?}", data.type_id());

        let query = Query {
            agent_name: AgentName::first(),
            tls_message_type: None,
            counter: 0,
        };
        let variable = Signature::new_var::<Vec<u8>>(query);

        let generated_term = Term::Application(
            hmac256,
            vec![
                Term::Application(hmac256_new_key, vec![]),
                Term::Variable(variable),
            ],
        );

        //println!("{}", generated_term);
        let mut context = TraceContext::new();
        context.add_knowledge(Knowledge {
            agent_name: AgentName::first(),
            tls_message_type: None,
            data: Box::new(data),
        });

        let _string = generated_term
            .evaluate(&context)
            .as_ref()
            .unwrap()
            .downcast_ref::<Vec<u8>>();
        //println!("{:?}", string);
    }

    #[test]
    fn playground() {
        let _var_data = fn_new_session_id();

        //println!("vec {:?}", TypeId::of::<Vec<u8>>());
        //println!("vec {:?}", TypeId::of::<Vec<u16>>());

        ////println!("{:?}", var_data.type_id());

        let func = Signature::new_function(&example_op_c);
        let dynamic_fn = func.dynamic_fn();
        let _string = dynamic_fn(&vec![Box::new(1u8)])
            .unwrap()
            .downcast_ref::<u16>()
            .unwrap();
        //println!("{:?}", string);
        let _string = Signature::new_function(&example_op_c).shape();
        //println!("{}", string);

        let query = Query {
            agent_name: AgentName::first(),
            tls_message_type: None,
            counter: 0,
        };
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
                                Term::Variable(Signature::new_var::<SessionID>(query)),
                            ],
                        ),
                        Term::Variable(Signature::new_var::<SessionID>(query)),
                    ],
                ),
                Term::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        Term::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                Term::Variable(Signature::new_var::<SessionID>(query)),
                                Term::Application(Signature::new_function(&example_op_c), vec![]),
                            ],
                        ),
                        Term::Variable(Signature::new_var::<SessionID>(query)),
                    ],
                ),
            ],
        );

        //println!("{}", constructed_term);
        let _graph = constructed_term.dot_subgraph(true, 0, "test");
        //println!("{}", graph);
    }

    #[test]
    fn test_static_functions() {
        let _functions = SIGNATURE
            .functions_by_name
            .iter()
            .map(|tuple| tuple.0)
            .join("\n");
        //println!("{}", functions);
        let _types = SIGNATURE
            .types_by_name
            .iter()
            .map(|tuple| tuple.0.to_string())
            .join("\n");
        //println!("{}", types);
    }
}
