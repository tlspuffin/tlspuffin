//! The *term* module defines typed[`DYTerm`]s of the form `fn_add(x: u8, fn_square(y: u16)) → u16`.
//!
//! Each function like `fn_add` or `fn_square` has a shape. The variables `x` and `y` each have a
//! type. These types allow type checks during the runtime of the fuzzer.
//! These checks restrict how[`DYTerm`]scan be mutated in the *fuzzer* module.

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

use std::fmt;
use std::hash::Hash;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use self::term::*;

pub mod atoms;
pub mod bitstrings;
pub mod dynamic_function;
pub mod error;
pub mod macros;
pub mod signature;
pub mod term;

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
pub trait Matcher:
    fmt::Debug + Clone + Hash + serde::Serialize + DeserializeOwned + PartialEq
{
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

#[cfg(test)]
#[allow(clippy::ptr_arg)]
pub mod test_signature {
    use std::any::TypeId;
    use std::fmt;
    use std::io::Read;

    use puffin_build::puffin;
    use serde::{Deserialize, Serialize};

    use crate::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
    use crate::algebra::dynamic_function::{FunctionAttributes, TypeShape};
    use crate::algebra::error::FnError;
    use crate::algebra::{AnyMatcher, Term};
    use crate::claims::{Claim, GlobalClaimList, SecurityViolationPolicy};
    use crate::codec::{CodecP, Reader};
    use crate::error::Error;
    use crate::protocol::{
        EvaluatedTerm, Extractable, OpaqueProtocolMessage, OpaqueProtocolMessageFlight,
        ProtocolBehavior, ProtocolMessage, ProtocolMessageDeframer, ProtocolMessageFlight,
        ProtocolTypes,
    };
    use crate::put::{Put, PutDescriptor, PutOptions};
    use crate::put_registry::Factory;
    use crate::trace::{Action, InputAction, Knowledge, Source, Step, Trace};
    use crate::{
        codec, define_signature, dummy_codec, dummy_extract_knowledge,
        dummy_extract_knowledge_codec, term,
    };

    #[derive(Debug, Clone)]
    pub struct HmacKey;
    #[derive(Debug, Clone)]
    pub struct HandshakeMessage;
    #[derive(Debug, Clone)]
    pub struct Encrypted;
    #[derive(Debug, Clone)]
    pub struct ProtocolVersion;
    #[derive(Debug, Clone)]
    pub struct Random;
    #[derive(Debug, Clone)]
    pub struct ClientExtension;
    #[derive(Debug, Clone)]
    pub struct ClientExtensions;
    #[derive(Debug, Clone)]
    pub struct Group;
    #[derive(Debug, Clone)]
    pub struct SessionID;
    #[derive(Debug, Clone)]
    pub struct CipherSuites;
    #[derive(Debug, Clone)]
    pub struct CipherSuite;
    #[derive(Debug, Clone)]
    pub struct Compression;
    #[derive(Debug, Clone)]
    pub struct Compressions;

    dummy_extract_knowledge_codec!(TestProtocolTypes, HmacKey);
    dummy_extract_knowledge_codec!(TestProtocolTypes, HandshakeMessage);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Encrypted);
    dummy_extract_knowledge_codec!(TestProtocolTypes, ProtocolVersion);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Random);
    dummy_extract_knowledge_codec!(TestProtocolTypes, ClientExtension);
    dummy_extract_knowledge_codec!(TestProtocolTypes, ClientExtensions);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Group);
    dummy_extract_knowledge_codec!(TestProtocolTypes, SessionID);
    dummy_extract_knowledge_codec!(TestProtocolTypes, CipherSuites);
    dummy_extract_knowledge_codec!(TestProtocolTypes, CipherSuite);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Compression);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Compressions);
    dummy_extract_knowledge!(TestProtocolTypes, u8);
    dummy_extract_knowledge!(TestProtocolTypes, u16);
    dummy_extract_knowledge!(TestProtocolTypes, u32);
    dummy_extract_knowledge!(TestProtocolTypes, u64);

    impl<T: std::fmt::Debug + Clone + 'static + CodecP> Extractable<TestProtocolTypes> for Vec<T>
    where
        Vec<T>: CodecP,
    {
        fn extract_knowledge<'a>(
            &'a self,
            knowledges: &mut Vec<Knowledge<'a, TestProtocolTypes>>,
            matcher: Option<<TestProtocolTypes as ProtocolTypes>::Matcher>,
            source: &'a Source,
        ) -> Result<(), Error> {
            knowledges.push(Knowledge {
                source,
                matcher,
                data: self,
            });

            Ok(())
        }
    }

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
        Ok(u16::from(a + 1))
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

    #[must_use]
    pub fn setup_simple_trace() -> TestTrace {
        let server = AgentName::first();
        let client_hello = create_client_hello();

        Trace {
            prior_traces: vec![],
            descriptors: vec![AgentDescriptor::from_name(server)],
            steps: vec![
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        precomputations: vec![],
                        recipe: client_hello,
                    }),
                },
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        precomputations: vec![],
                        recipe: term! {fn_client_key_exchange},
                    }),
                },
                Step {
                    agent: server,
                    action: Action::Input(InputAction {
                        precomputations: vec![],
                        recipe: term! {fn_encrypt12(fn_finished,fn_seq_0)},
                    }),
                },
            ],
        }
    }

    define_signature!(
        TEST_SIGNATURE<TestProtocolTypes>,
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

    pub type TestTrace = Trace<TestProtocolTypes>;
    pub type TestTerm = Term<TestProtocolTypes>;

    #[derive(Clone)]
    pub struct TestClaim;

    dummy_extract_knowledge_codec!(TestProtocolTypes, TestClaim);

    impl fmt::Debug for TestClaim {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl Claim for TestClaim {
        type PT = TestProtocolTypes;

        fn agent_name(&self) -> AgentName {
            panic!("Not implemented for test stub");
        }

        fn id(&self) -> TypeShape<TestProtocolTypes> {
            panic!("Not implemented for test stub");
        }

        fn inner(&self) -> Box<dyn EvaluatedTerm<TestProtocolTypes>> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestOpaqueMessage;

    impl Clone for TestOpaqueMessage {
        fn clone(&self) -> Self {
            panic!("Not implemented for test stub");
        }
    }

    impl fmt::Debug for TestOpaqueMessage {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl CodecP for TestOpaqueMessage {
        fn encode(&self, _bytes: &mut Vec<u8>) {
            panic!("Not implemented for test stub");
        }

        fn read(&mut self, _: &mut Reader) -> Result<(), Error> {
            panic!("Not implemented for test stub");
        }
    }

    impl OpaqueProtocolMessage<TestProtocolTypes> for TestOpaqueMessage {
        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }
    }

    dummy_extract_knowledge!(TestProtocolTypes, TestOpaqueMessage);

    pub struct TestMessage;

    impl Clone for TestMessage {
        fn clone(&self) -> Self {
            panic!("Not implemented for test stub");
        }
    }

    impl fmt::Debug for TestMessage {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("Not implemented for test stub");
        }
    }

    impl ProtocolMessage<TestProtocolTypes, TestOpaqueMessage> for TestMessage {
        fn create_opaque(&self) -> TestOpaqueMessage {
            panic!("Not implemented for test stub");
        }

        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }
    }

    dummy_extract_knowledge_codec!(TestProtocolTypes, TestMessage);

    pub struct TestMessageDeframer;

    impl ProtocolMessageDeframer<TestProtocolTypes> for TestMessageDeframer {
        type OpaqueProtocolMessage = TestOpaqueMessage;

        fn pop_frame(&mut self) -> Option<TestOpaqueMessage> {
            panic!("Not implemented for test stub");
        }

        fn read(&mut self, _rd: &mut dyn Read) -> std::io::Result<usize> {
            panic!("Not implemented for test stub");
        }
    }

    pub struct TestSecurityViolationPolicy;
    impl SecurityViolationPolicy for TestSecurityViolationPolicy {
        type C = TestClaim;

        fn check_violation(_claims: &[TestClaim]) -> Option<&'static str> {
            panic!("Not implemented for test stub");
        }
    }

    #[derive(Debug, Clone)]
    pub struct TestMessageFlight;

    impl
        ProtocolMessageFlight<
            TestProtocolTypes,
            TestMessage,
            TestOpaqueMessage,
            TestOpaqueMessageFlight,
        > for TestMessageFlight
    {
        fn new() -> Self {
            Self {}
        }

        fn push(&mut self, _msg: TestMessage) {
            panic!("Not implemented for test stub");
        }

        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }
    }

    impl TryFrom<TestOpaqueMessageFlight> for TestMessageFlight {
        type Error = ();

        fn try_from(_value: TestOpaqueMessageFlight) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    dummy_extract_knowledge_codec!(TestProtocolTypes, TestMessageFlight);

    impl From<TestMessage> for TestMessageFlight {
        fn from(_value: TestMessage) -> Self {
            Self {}
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct TestOpaqueMessageFlight;

    impl OpaqueProtocolMessageFlight<TestProtocolTypes, TestOpaqueMessage> for TestOpaqueMessageFlight {
        fn new() -> Self {
            Self {}
        }

        fn push(&mut self, _msg: TestOpaqueMessage) {
            panic!("Not implemented for test stub");
        }

        fn debug(&self, _info: &str) {
            panic!("Not implemented for test stub");
        }
    }

    dummy_extract_knowledge!(TestProtocolTypes, TestOpaqueMessageFlight);

    impl From<TestOpaqueMessage> for TestOpaqueMessageFlight {
        fn from(_value: TestOpaqueMessage) -> Self {
            Self {}
        }
    }

    impl codec::Codec for TestOpaqueMessageFlight {
        fn encode(&self, _bytes: &mut Vec<u8>) {
            panic!("Not implemented for test stub");
        }

        fn read(_: &mut Reader) -> Option<Self> {
            panic!("Not implemented for test stub");
        }
    }

    impl From<TestMessageFlight> for TestOpaqueMessageFlight {
        fn from(_value: TestMessageFlight) -> Self {
            Self {}
        }
    }

    #[derive(Clone, Debug, Hash, Serialize, Deserialize)]
    pub struct TestProtocolTypes;

    impl ProtocolTypes for TestProtocolTypes {
        type Matcher = AnyMatcher;
        type PUTConfig = TestPUTConfig;

        fn signature() -> &'static Signature<Self> {
            &TEST_SIGNATURE
        }
    }

    #[derive(Default, Clone, Debug, Hash, Serialize, Deserialize)]
    pub struct TestPUTConfig;

    impl ProtocolDescriptorConfig for TestPUTConfig {
        fn is_reusable_with(&self, _other: &Self) -> bool {
            false
        }
    }

    impl fmt::Display for TestProtocolTypes {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "")
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct TestProtocolBehavior;

    impl ProtocolBehavior for TestProtocolBehavior {
        type Claim = TestClaim;
        type OpaqueProtocolMessage = TestOpaqueMessage;
        type OpaqueProtocolMessageFlight = TestOpaqueMessageFlight;
        type ProtocolMessage = TestMessage;
        type ProtocolMessageFlight = TestMessageFlight;
        type ProtocolTypes = TestProtocolTypes;
        type SecurityViolationPolicy = TestSecurityViolationPolicy;

        fn create_corpus(_put: PutDescriptor) -> Vec<(Trace<Self::ProtocolTypes>, &'static str)> {
            panic!("Not implemented for test stub");
        }

        fn try_read_bytes(
            _bitstring: &[u8],
            _ty: TypeId,
        ) -> Result<Box<dyn EvaluatedTerm<Self::ProtocolTypes>>, Error> {
            Err(Error::Term("try_read_bytes not implemented".to_owned()))
        }
    }

    pub struct TestFactory;

    impl Factory<TestProtocolBehavior> for TestFactory {
        fn create(
            &self,
            _agent_descriptor: &AgentDescriptor<TestPUTConfig>,
            _claims: &GlobalClaimList<<TestProtocolBehavior as ProtocolBehavior>::Claim>,
            _options: &PutOptions,
        ) -> Result<Box<dyn Put<TestProtocolBehavior>>, Error> {
            panic!("Not implemented for test stub");
        }

        fn name(&self) -> String {
            String::from("TESTSTUB_RUST_PUT")
        }

        fn versions(&self) -> Vec<(String, String)> {
            vec![(
                "harness".to_string(),
                format!("{} {}", self.name(), puffin::full_version()),
            )]
        }

        fn supports(&self, _capability: &str) -> bool {
            false
        }

        fn clone_factory(&self) -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory {})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_signature::*;
    use crate::agent::AgentName;
    use crate::algebra::atoms::Variable;
    use crate::algebra::dynamic_function::TypeShape;
    use crate::algebra::signature::Signature;
    use crate::algebra::term::TermType;
    use crate::algebra::{AnyMatcher, DYTerm, Term};
    use crate::put_registry::{Factory, PutRegistry};
    use crate::term;
    use crate::trace::{Source, Spawner, TraceContext};

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

    #[test_log::test]
    fn example() {
        let hmac256_new_key = Signature::new_function(&fn_hmac256_new_key);
        let hmac256 = Signature::new_function(&fn_hmac256);
        let _client_hello = Signature::new_function(&fn_client_hello);

        let data = "hello".as_bytes().to_vec();

        // log::debug!("TypeId of vec array {:?}", data.type_id());

        let variable: Variable<TestProtocolTypes> = Signature::new_var(
            TypeShape::of::<Vec<u8>>(),
            Some(Source::Agent(AgentName::first())),
            None,
            0,
        );

        let generated_term = Term::from(DYTerm::Application(
            hmac256,
            vec![
                Term::from(DYTerm::Application(hmac256_new_key, vec![])),
                Term::from(DYTerm::Variable(variable)),
            ],
        ));

        log::debug!("{}", generated_term);

        fn dummy_factory() -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory)
        }

        let registry =
            PutRegistry::<TestProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");

        let spawner = Spawner::new(registry);
        let mut context = TraceContext::new(spawner);
        context
            .knowledge_store
            .add_raw_knowledge(data, Source::Agent(AgentName::first()), None);

        log::debug!("{:?}", context.knowledge_store);

        let _string = generated_term
            .evaluate_dy(&context)
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<Vec<u8>>()
            .unwrap();
        // log::debug!("{:?}", string);
    }

    #[test_log::test]
    fn playground() {
        let _var_data = fn_new_session_id();

        //println!("vec {:?}", TypeId::of::<Vec<u8>>());
        //println!("vec {:?}", TypeId::of::<Vec<u16>>());

        ////println!("{:?}", var_data.type_id());

        let func = Signature::new_function(&example_op_c);
        let dynamic_fn = func.dynamic_fn();
        let _string = dynamic_fn(&vec![Box::new(1u8)])
            .unwrap()
            .as_any()
            .downcast_ref::<u16>()
            .unwrap();
        //println!("{:?}", string);
        let _string = Signature::new_function(&example_op_c).shape();
        //println!("{}", string);

        let constructed_term = Term::<TestProtocolTypes>::from(DYTerm::Application(
            Signature::new_function(&example_op_c),
            vec![
                Term::from(DYTerm::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        Term::from(DYTerm::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                Term::from(DYTerm::Application(
                                    Signature::new_function(&example_op_c),
                                    vec![],
                                )),
                                Term::from(DYTerm::Variable(Signature::new_var_with_type::<
                                    SessionID,
                                    AnyMatcher,
                                >(
                                    Some(Source::Agent(AgentName::first())),
                                    None,
                                    0,
                                ))),
                            ],
                        )),
                        Term::from(DYTerm::Variable(Signature::new_var_with_type::<
                            SessionID,
                            AnyMatcher,
                        >(
                            Some(Source::Agent(AgentName::first())),
                            None,
                            0,
                        ))),
                    ],
                )),
                Term::from(DYTerm::Application(
                    Signature::new_function(&example_op_c),
                    vec![
                        Term::from(DYTerm::Application(
                            Signature::new_function(&example_op_c),
                            vec![
                                Term::from(DYTerm::Variable(Signature::new_var_with_type::<
                                    SessionID,
                                    _,
                                >(
                                    Some(Source::Agent(AgentName::first())),
                                    None,
                                    0,
                                ))),
                                Term::from(DYTerm::Application(
                                    Signature::new_function(&example_op_c),
                                    vec![],
                                )),
                            ],
                        )),
                        Term::from(DYTerm::Variable(
                            Signature::new_var_with_type::<SessionID, _>(
                                Some(Source::Agent(AgentName::first())),
                                None,
                                0,
                            ),
                        )),
                    ],
                )),
            ],
        ));

        //println!("{}", constructed_term);
        let _graph = constructed_term.dot_subgraph(true, 0, "test");
        //println!("{}", graph);
    }
}
