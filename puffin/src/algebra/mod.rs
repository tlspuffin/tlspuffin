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

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
};

use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub use self::term::*;
use crate::{
    algebra::signature::Signature,
    error::Error,
    protocol::{MessageResult, OpaqueProtocolMessage, ProtocolMessage},
};

pub mod atoms;
pub mod dynamic_function;
pub mod error;
pub mod macros;
pub mod signature;
pub mod term;

static DESERIALIZATION_SIGNATURE: OnceCell<&'static Signature> = OnceCell::new();

/// Returns the current signature which is used during deserialization.
pub fn deserialize_signature() -> &'static Signature {
    DESERIALIZATION_SIGNATURE
        .get()
        .expect("current signature needs to be set")
}

pub fn set_deserialize_signature(signature: &'static Signature) -> Result<(), ()> {
    DESERIALIZATION_SIGNATURE.set(signature).map_err(|_err| ())
}

impl<T> Matcher for Option<T>
where
    T: Matcher,
{
    fn matches(&self, matcher: &Self) -> bool {
        match (self, matcher) {
            (Some(inner), Some(inner_matcher)) => inner.matches(inner_matcher),
            (Some(_), None) => true, // None matches everything as query -> True
            (None, None) => true,    // None == None => True
            (None, Some(_)) => false, // None != Some => False
        }
    }

    fn specificity(&self) -> u32 {
        if let Some(matcher) = self {
            1 + matcher.specificity()
        } else {
            0
        }
    }
}

/// Determines whether two instances match. We can also ask it how specific it is.
pub trait Matcher: Debug + Clone + Hash + serde::Serialize + DeserializeOwned + PartialEq {
    fn matches(&self, matcher: &Self) -> bool;

    fn specificity(&self) -> u32;
}

#[derive(Debug, Clone, Hash, PartialEq, Serialize, Deserialize)]
pub struct AnyMatcher;

impl Matcher for AnyMatcher {
    fn matches(&self, _matcher: &Self) -> bool {
        true
    }

    fn specificity(&self) -> u32 {
        0
    }
}

impl<M: ProtocolMessage<O>, O: OpaqueProtocolMessage> TryFrom<&MessageResult<M, O>> for AnyMatcher {
    type Error = Error;

    fn try_from(_: &MessageResult<M, O>) -> Result<Self, Self::Error> {
        Ok(AnyMatcher)
    }
}

#[cfg(test)]
#[allow(clippy::ptr_arg)]
pub mod test_signature {
    use std::{
        any::{Any, TypeId},
        fmt::{Debug, Formatter},
        io::Read,
    };

    use crate::algebra::{ConcreteMessage, TermEval};
    use crate::{
        agent::{AgentDescriptor, AgentName, TLSVersion},
        algebra::{dynamic_function::TypeShape, error::FnError, AnyMatcher, Term},
        claims::{Claim, SecurityViolationPolicy},
        codec::{Codec, Reader},
        define_signature,
        error::Error,
        protocol::{
            OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer,
        },
        put::{Put, PutName},
        put_registry::{Factory, PutRegistry},
        term,
        trace::{Action, InputAction, Step, Trace, TraceContext},
        variable_data::VariableData,
    };

    pub struct HmacKey;
    pub struct HandshakeMessage;
    pub struct Encrypted;
    pub struct ProtocolVersion;
    pub struct Random;
    pub struct ClientExtension;
    pub struct ClientExtensions;
    pub struct Group;
    pub struct SessionID;
    pub struct CipherSuites;
    pub struct CipherSuite;
    pub struct Compression;
    pub struct Compressions;

    pub fn fn_hmac256_new_key() -> Result<HmacKey, FnError> {
        Ok(HmacKey)
    }

    pub fn fn_hmac256(_key: &HmacKey, _msg: &Vec<u8>) -> Result<Vec<u8>, FnError> {
        Ok(Vec::new())
    }

    pub fn fn_client_hello(
        _version: &ProtocolVersion,
        _random: &Random,
        _id: &SessionID,
        _suites: &CipherSuites,
        _compressions: &Compressions,
        _extensions: &ClientExtensions,
    ) -> Result<HandshakeMessage, FnError> {
        Ok(HandshakeMessage)
    }

    pub fn fn_finished() -> Result<HandshakeMessage, FnError> {
        Ok(HandshakeMessage)
    }

    pub fn fn_protocol_version12() -> Result<ProtocolVersion, FnError> {
        Ok(ProtocolVersion)
    }
    pub fn fn_new_session_id() -> Result<SessionID, FnError> {
        Ok(SessionID)
    }

    pub fn fn_new_random() -> Result<Random, FnError> {
        Ok(Random)
    }

    pub fn fn_client_extensions_append(
        _extensions: &ClientExtensions,
        _extension: &ClientExtension,
    ) -> Result<ClientExtensions, FnError> {
        Ok(ClientExtensions)
    }

    pub fn fn_client_extensions_new() -> Result<ClientExtensions, FnError> {
        Ok(ClientExtensions)
    }
    pub fn fn_support_group_extension(_group: &Group) -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }

    pub fn fn_signature_algorithm_extension() -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }
    pub fn fn_ec_point_formats_extension() -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }
    pub fn fn_signed_certificate_timestamp_extension() -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }
    pub fn fn_renegotiation_info_extension(_info: &Vec<u8>) -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }
    pub fn fn_signature_algorithm_cert_extension() -> Result<ClientExtension, FnError> {
        Ok(ClientExtension)
    }

    pub fn fn_empty_bytes_vec() -> Result<Vec<u8>, FnError> {
        Ok(Vec::new())
    }

    pub fn fn_named_group_secp384r1() -> Result<Group, FnError> {
        Ok(Group)
    }

    pub fn fn_client_key_exchange() -> Result<HandshakeMessage, FnError> {
        Ok(HandshakeMessage)
    }

    pub fn fn_new_cipher_suites() -> Result<CipherSuites, FnError> {
        Ok(CipherSuites)
    }

    pub fn fn_append_cipher_suite(
        _suites: &CipherSuites,
        _suite: &CipherSuite,
    ) -> Result<CipherSuites, FnError> {
        Ok(CipherSuites)
    }
    pub fn fn_cipher_suite12() -> Result<CipherSuite, FnError> {
        Ok(CipherSuite)
    }

    pub fn fn_compressions() -> Result<Compressions, FnError> {
        Ok(Compressions)
    }

    pub fn fn_encrypt12(_finished: &HandshakeMessage, _seq: &u32) -> Result<Encrypted, FnError> {
        Ok(Encrypted)
    }

    pub fn fn_seq_0() -> Result<u32, FnError> {
        Ok(0)
    }

    pub fn fn_seq_1() -> Result<u32, FnError> {
        Ok(1)
    }

    pub fn example_op_c(a: &u8) -> Result<u16, FnError> {
        Ok((a + 1) as u16)
    }

    fn create_client_hello() -> TestTerm {
        term! {
              fn_client_hello(
                fn_protocol_version12,
                fn_new_random,
                fn_new_session_id,
                (fn_append_cipher_suite(
                    (fn_new_cipher_suites()),
                    fn_cipher_suite12
                )),
                fn_compressions,
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    (fn_client_extensions_append(
                                        fn_client_extensions_new,
                                        (fn_support_group_extension(fn_named_group_secp384r1))
                                    )),
                                    fn_signature_algorithm_extension
                                )),
                                fn_ec_point_formats_extension
                            )),
                            fn_signed_certificate_timestamp_extension
                        )),
                         // Enable Renegotiation
                        (fn_renegotiation_info_extension(fn_empty_bytes_vec))
                    )),
                    // Add signature cert extension
                    fn_signature_algorithm_cert_extension
                ))
            )
        }
    }

    pub fn setup_simple_trace() -> TestTrace {
        let server = AgentName::first();
        let client_hello = create_client_hello();

        Trace {
            prior_traces: vec![],
            descriptors: vec![AgentDescriptor::new_server(server, TLSVersion::V1_2)],
            steps: vec![
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        recipe: client_hello,
                    }),
                },
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        recipe: term! {
                            fn_client_key_exchange
                        },
                    }),
                },
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        recipe: term! {
                            fn_encrypt12(fn_finished, fn_seq_0)
                        },
                    }),
                },
            ],
        }
    }

    define_signature!(
        TEST_SIGNATURE,
        fn_hmac256_new_key
        fn_hmac256
        fn_client_hello
        fn_finished
        fn_protocol_version12
        fn_new_session_id
        fn_new_random
        fn_client_extensions_append
        fn_client_extensions_new
        fn_support_group_extension
        fn_signature_algorithm_extension
        fn_ec_point_formats_extension
        fn_signed_certificate_timestamp_extension
        fn_renegotiation_info_extension
        fn_signature_algorithm_cert_extension
        fn_empty_bytes_vec
        fn_named_group_secp384r1
        fn_client_key_exchange
        fn_new_cipher_suites
        fn_append_cipher_suite
        fn_cipher_suite12
        fn_compressions
        fn_encrypt12
        fn_seq_0
        fn_seq_1
    );

    pub type TestTrace = Trace<AnyMatcher>;
    pub type TestTerm = TermEval<AnyMatcher>;

    pub struct TestClaim;

    impl VariableData for TestClaim {
        fn boxed(&self) -> Box<dyn VariableData> {
            panic!("Not implemented for test stub");
        }

        fn boxed_any(&self) -> Box<dyn Any> {
            panic!("Not implemented for test stub");
        }

        fn type_id(&self) -> TypeId {
            panic!("Not implemented for test stub");
        }

        fn type_name(&self) -> &'static str {
            panic!("Not implemented for test stub");
        }
    }

    impl Debug for TestClaim {
        fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl Claim for TestClaim {
        fn agent_name(&self) -> AgentName {
            panic!("Not implemented for test stub");
        }

        fn id(&self) -> TypeShape {
            panic!("Not implemented for test stub");
        }

        fn inner(&self) -> Box<dyn Any> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestOpaqueMessage;

    impl Clone for TestOpaqueMessage {
        fn clone(&self) -> Self {
            panic!("Not implemented for test stub");
        }
    }

    impl Debug for TestOpaqueMessage {
        fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl Codec for TestOpaqueMessage {
        fn encode(&self, _bytes: &mut Vec<u8>) {
            panic!("Not implemented for test stub");
        }

        fn read(_: &mut Reader) -> Option<Self> {
            panic!("Not implemented for test stub");
        }
    }

    impl OpaqueProtocolMessage for TestOpaqueMessage {
        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }

        fn extract_knowledge(&self) -> Result<Vec<Box<dyn VariableData>>, Error> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestMessage;

    impl Clone for TestMessage {
        fn clone(&self) -> Self {
            panic!("Not implemented for test stub");
        }
    }

    impl Debug for TestMessage {
        fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl Codec for TestMessage {
        fn encode(&self, _bytes: &mut Vec<u8>) {
            panic!("Not implemented for test stub");
        }

        fn read(_: &mut Reader) -> Option<Self> {
            panic!("Not implemented for test stub");
        }
    }

    impl ProtocolMessage<TestOpaqueMessage> for TestMessage {
        fn create_opaque(&self) -> TestOpaqueMessage {
            panic!("Not implemented for test stub");
        }

        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }

        fn extract_knowledge(&self) -> Result<Vec<Box<dyn VariableData>>, Error> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestMessageDeframer;

    impl ProtocolMessageDeframer for TestMessageDeframer {
        type OpaqueProtocolMessage = TestOpaqueMessage;

        fn pop_frame(&mut self) -> Option<TestOpaqueMessage> {
            panic!("Not implemented for test stub");
        }

        fn read(&mut self, _rd: &mut dyn Read) -> std::io::Result<usize> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestSecurityViolationPolicy;
    impl SecurityViolationPolicy<TestClaim> for TestSecurityViolationPolicy {
        fn check_violation(_claims: &[TestClaim]) -> Option<&'static str> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestProtocolBehavior;

    impl ProtocolBehavior for TestProtocolBehavior {
        type Claim = TestClaim;
        type SecurityViolationPolicy = TestSecurityViolationPolicy;
        type ProtocolMessage = TestMessage;
        type OpaqueProtocolMessage = TestOpaqueMessage;
        type Matcher = AnyMatcher;

        fn signature() -> &'static Signature {
            panic!("Not implemented for test stub");
        }

        fn registry() -> &'static PutRegistry<Self> {
            panic!("Not implemented for test stub");
        }

        fn create_corpus() -> Vec<(Trace<Self::Matcher>, &'static str)> {
            panic!("Not implemented for test stub");
        }

        fn any_get_encoding(message: Box<dyn Any>) -> Result<ConcreteMessage, Error> {
            panic!("Not implemented for test stub");
        }

        fn try_read_bytes(bitstring: ConcreteMessage, ty: TypeId) -> Result<Box<dyn Any>, Error> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestFactory;

    impl Factory<TestProtocolBehavior> for TestFactory {
        fn create(
            &self,
            _context: &TraceContext<TestProtocolBehavior>,
            _agent_descriptor: &AgentDescriptor,
        ) -> Result<Box<dyn Put<TestProtocolBehavior>>, Error> {
            panic!("Not implemented for test stub");
        }

        fn name(&self) -> PutName {
            panic!("Not implemented for test stub");
        }

        fn version(&self) -> String {
            panic!("Not implemented for test stub");
        }
    }
}

#[cfg(test)]
mod tests {

    use super::test_signature::*;
    use crate::algebra::term::TermType;
    use crate::algebra::TermEval;
    use crate::{
        agent::AgentName,
        algebra::{
            atoms::Variable, dynamic_function::TypeShape, signature::Signature, AnyMatcher, Term,
        },
        put::PutOptions,
        put_registry::{Factory, PutRegistry},
        term,
        trace::{Knowledge, TraceContext},
    };

    #[allow(dead_code)]
    fn test_compilation() {
        // reminds me of Lisp, lol
        let client = AgentName::first();
        let _test_nested_with_variable: TestTerm = term! {
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

        let _set_simple_function2: TestTerm = term! {
           fn_client_hello((fn_protocol_version12()), fn_new_random, fn_new_random)
        };

        let _test_simple_function2: TestTerm = term! {
           fn_new_random(((client,0)))
        };
        let _test_simple_function1: TestTerm = term! {
           fn_protocol_version12
        };
        let _test_simple_function: TestTerm = term! {
           fn_new_random(((client,0)/ProtocolVersion))
        };
        let _test_variable: TestTerm = term! {
            (client,0)/ProtocolVersion
        };
        let _set_nested_function: TestTerm = term! {
           fn_client_extensions_append(
                (fn_client_extensions_append(
                    fn_client_extensions_new,
                    (fn_support_group_extension(fn_named_group_secp384r1))
                )),
                (fn_support_group_extension(fn_named_group_secp384r1))
            )
        };
    }

    #[test]
    fn example() {
        let hmac256_new_key = Signature::new_function(&fn_hmac256_new_key);
        let hmac256 = Signature::new_function(&fn_hmac256);
        let _client_hello = Signature::new_function(&fn_client_hello);

        let data = "hello".as_bytes().to_vec();

        //println!("TypeId of vec array {:?}", data.type_id());

        let variable: Variable<AnyMatcher> =
            Signature::new_var(TypeShape::of::<Vec<u8>>(), AgentName::first(), None, 0);

        let generated_term = TermEval::from(Term::Application(
            hmac256,
            vec![
                TermEval::from(Term::Application(hmac256_new_key, vec![])),
                TermEval::from(Term::Variable(variable)),
            ],
        ));

        //println!("{}", generated_term);

        fn dummy_factory() -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory)
        }

        let mut context = TraceContext::new(
            &PutRegistry::<TestProtocolBehavior> {
                factories: &[dummy_factory],
                default: dummy_factory,
            },
            PutOptions::default(),
        );
        context.add_knowledge(Knowledge {
            agent_name: AgentName::first(),
            matcher: None,
            data: Box::new(data),
        });

        let eval = generated_term.evaluate_lazy(&context);
        let _string = eval.as_ref().unwrap().downcast_ref::<Vec<u8>>().clone();
        assert_eq!(_string, generated_term.evaluate(&context).as_ref().ok());
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

        let constructed_term = TermEval::from(Term::Application(
            Signature::new_function(&example_op_c),
            vec![
                TermEval::from(Term::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        TermEval::from(Term::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                TermEval::from(Term::Application(
                                    Signature::new_function(&example_op_c),
                                    vec![],
                                )),
                                TermEval::from(Term::Variable(Signature::new_var_with_type::<
                                    SessionID,
                                    AnyMatcher,
                                >(
                                    AgentName::first(), None, 0
                                ))),
                            ],
                        )),
                        TermEval::from(Term::Variable(Signature::new_var_with_type::<
                            SessionID,
                            AnyMatcher,
                        >(
                            AgentName::first(), None, 0
                        ))),
                    ],
                )),
                TermEval::from(Term::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        TermEval::from(Term::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                TermEval::from(Term::Variable(Signature::new_var_with_type::<
                                    SessionID,
                                    _,
                                >(
                                    AgentName::first(), None, 0
                                ))),
                                TermEval::from(Term::Application(
                                    Signature::new_function(&example_op_c),
                                    vec![],
                                )),
                            ],
                        )),
                        TermEval::from(Term::Variable(
                            Signature::new_var_with_type::<SessionID, _>(
                                AgentName::first(),
                                None,
                                0,
                            ),
                        )),
                    ],
                )),
            ],
        ));

        //println!("{}", constructed_term);
        let _graph = constructed_term.term.dot_subgraph(true, 0, "test");
        //println!("{}", graph);
    }
}
