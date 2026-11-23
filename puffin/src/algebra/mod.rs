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
pub mod list_types;
pub mod macros;
pub mod readable_types;
pub mod sharing;
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

    use comparable::Comparable;
    use puffin_build::puffin;
    use serde::{Deserialize, Serialize};

    use crate::agent::{AgentDescriptor, AgentName, ProtocolDescriptorConfig};
    use crate::algebra::dynamic_function::TypeShape;
    use crate::algebra::error::FnError;
    use crate::algebra::signature::Signature;
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
    use crate::trace::{Action, InputAction, Knowledge, Source, Step, StepNumber, Trace};
    use crate::{
        codec, declare_signature, define_list_types, define_signature, dummy_codec,
        dummy_extract_knowledge, dummy_extract_knowledge_codec, term,
    };

    #[derive(Debug, Clone, Comparable)]
    pub struct HmacKey;
    #[derive(Debug, Clone, Comparable)]
    pub struct HandshakeMessage;
    #[derive(Debug, Clone, Comparable)]
    pub struct Encrypted;
    #[derive(Debug, Clone, Comparable)]
    pub struct ProtocolVersion;
    #[derive(Debug, Clone, Comparable)]
    pub struct Random;
    #[derive(Debug, Clone, Comparable, PartialEq)]
    pub struct ClientExtension;
    #[derive(Debug, Clone, Comparable)]
    pub struct Group;
    #[derive(Debug, Clone, Comparable)]
    pub struct SessionID;
    #[derive(Debug, Clone, Comparable)]
    pub struct CipherSuites;
    #[derive(Debug, Clone, Comparable)]
    pub struct CipherSuite;
    #[derive(Debug, Clone, Comparable)]
    pub struct Compression;
    #[derive(Debug, Clone, Comparable)]
    pub struct Compressions;

    dummy_extract_knowledge_codec!(TestProtocolTypes, HmacKey);
    dummy_extract_knowledge_codec!(TestProtocolTypes, HandshakeMessage);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Encrypted);
    dummy_extract_knowledge_codec!(TestProtocolTypes, ProtocolVersion);
    dummy_extract_knowledge_codec!(TestProtocolTypes, Random);
    dummy_extract_knowledge!(TestProtocolTypes, ClientExtension);

    // A list element type needs a real `Codec` (and a `Vec<Self>` one), unlike the dummy types
    // above: `Vec<ClientExtension>` is what the list terms of the test signature evaluate to.
    impl codec::Codec for ClientExtension {
        fn encode(&self, bytes: &mut Vec<u8>) {
            bytes.push(0);
        }

        fn read(r: &mut Reader) -> Option<Self> {
            r.take(1).map(|_| Self)
        }
    }
    impl codec::VecCodecWoSize for ClientExtension {}
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
        _extensions: &Vec<ClientExtension>,
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

    thread_local! {
        /// Number of calls of [`fn_counted_extension`] on this thread.
        pub static COUNTED_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Counts its own evaluations, to check that a shared node is evaluated only once.
    pub fn fn_counted_extension() -> Result<ClientExtension, FnError> {
        COUNTED_CALLS.with(|calls| calls.set(calls.get() + 1));
        Ok(ClientExtension)
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

    /// A container holding an inner `Vec<u8>`, used to exercise the [`DYTerm::Deconstructor`]
    /// mechanism: its `extract_knowledge` exposes both itself and its inner `Vec<u8>` sub-value.
    #[derive(Debug, Clone, Comparable)]
    pub struct TestByteContainer(pub Vec<u8>);

    impl Extractable<TestProtocolTypes> for TestByteContainer {
        fn extract_knowledge<'a>(
            &'a self,
            knowledges: &mut Vec<Knowledge<'a, TestProtocolTypes>>,
            matcher: Option<AnyMatcher>,
            source: &'a Source,
        ) -> Result<(), Error> {
            knowledges.push(Knowledge {
                source,
                matcher: matcher.clone(),
                data: self,
            });
            // Expose the inner bytes as an extractable sub-value, tagged with a matcher so the
            // `D(term, [matcher] / Type)` deconstructor syntax can select them.
            self.0
                .extract_knowledge(knowledges, Some(AnyMatcher), source)
        }
    }

    dummy_codec!(TestProtocolTypes, TestByteContainer);

    /// Builds a concretized [`TestByteContainer`]; used as the *source* term of a deconstructor.
    pub fn fn_make_byte_container() -> Result<TestByteContainer, FnError> {
        Ok(TestByteContainer(vec![4, 2]))
    }

    /// A container exposing two `Vec<u8>` sub-values, used to exercise the deconstructor counter
    /// (the N-th matching sub-value).
    #[derive(Debug, Clone, Comparable)]
    pub struct TestBytePair(pub Vec<u8>, pub Vec<u8>);

    impl Extractable<TestProtocolTypes> for TestBytePair {
        fn extract_knowledge<'a>(
            &'a self,
            knowledges: &mut Vec<Knowledge<'a, TestProtocolTypes>>,
            matcher: Option<AnyMatcher>,
            source: &'a Source,
        ) -> Result<(), Error> {
            knowledges.push(Knowledge {
                source,
                matcher: matcher.clone(),
                data: self,
            });
            // Exposed in order: counter 0 selects the first, counter 1 the second.
            self.0
                .extract_knowledge(knowledges, Some(AnyMatcher), source)?;
            self.1
                .extract_knowledge(knowledges, Some(AnyMatcher), source)
        }
    }

    dummy_codec!(TestProtocolTypes, TestBytePair);

    /// Builds a concretized [`TestBytePair`]; used as the *source* term of a deconstructor.
    pub fn fn_make_byte_pair() -> Result<TestBytePair, FnError> {
        Ok(TestBytePair(vec![1, 1], vec![2, 2]))
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
                [
                    (fn_support_group_extension(fn_named_group_secp384r1)),
                    fn_signature_algorithm_extension,
                    fn_ec_point_formats_extension,
                    fn_signed_certificate_timestamp_extension,
                    // Enable Renegotiation
                    (fn_renegotiation_info_extension(fn_empty_bytes_vec)),
                    // Add signature cert extension
                    fn_signature_algorithm_cert_extension
                ]
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
            ..Default::default()
        }
    }

    declare_signature!(TEST_SIGNATURE<TestProtocolTypes>);

    // `fn_client_hello` is written by hand, so its list argument is registered by hand.
    define_list_types!(TEST_SIGNATURE, TestProtocolTypes; Vec<ClientExtension>);

    define_signature!(
        TEST_SIGNATURE,
        TestProtocolTypes;
        fn_hmac256_new_key
        fn_hmac256
        fn_client_hello
        fn_finished
        fn_protocol_version12
        fn_new_session_id
        fn_new_random
        fn_support_group_extension
        fn_signature_algorithm_extension
        fn_counted_extension
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
        fn_make_byte_container
        fn_make_byte_pair
    );

    pub type TestTrace = Trace<TestProtocolTypes>;
    pub type TestTerm = Term<TestProtocolTypes>;

    #[derive(Clone, Comparable, PartialEq)]
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

        fn set_step(&mut self, _step: Option<StepNumber>) {}

        fn get_step(&self) -> Option<StepNumber> {
            None
        }
    }

    #[derive(Comparable)]
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

    #[derive(Comparable)]
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

    #[derive(Debug, Clone, Comparable)]
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

    #[derive(Debug, Clone, Default, Comparable)]
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

    #[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
    pub struct TestProtocolTypes;

    impl ProtocolTypes for TestProtocolTypes {
        type Matcher = AnyMatcher;
        type PUTConfig = TestPUTConfig;

        fn signature() -> &'static Signature<Self> {
            &TEST_SIGNATURE
        }

        fn differential_fuzzing_whitelist() -> Option<Vec<TypeId>> {
            None
        }

        fn differential_fuzzing_terms_to_eval(
            _agents: &Vec<AgentDescriptor<Self::PUTConfig>>,
        ) -> Vec<crate::algebra::Term<Self>> {
            vec![]
        }

        fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
            None
        }

        fn differential_fuzzing_uniformise_put_config(trace: Trace<Self>) -> Trace<Self> {
            trace
        }

        fn differential_fuzzing_filter_diff(_diff: &crate::differential::TraceDifference) -> bool {
            true
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
            Err(Error::Codec("try_read_bytes not implemented".to_owned()))
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
    use crate::algebra::dynamic_function::{DescribableFunction, TypeShape};
    use crate::algebra::signature::Signature;
    use crate::algebra::term::TermType;
    use crate::algebra::{AnyMatcher, DYTerm, Term, TermDAG, TermTree};
    use crate::put::{PutDescriptor, PutOptions};
    use crate::put_registry::{Factory, PutRegistry};
    use crate::term;
    use crate::trace::{Query, Source, Spawner, TraceContext};

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
                        K((client,0)/ProtocolVersion)
                    ))
                )),
                fn_new_random
            )
        };

        let _set_simple_function2: TestTerm = term! {
           fn_client_hello((fn_protocol_version12()), fn_new_random, fn_new_random)
        };

        let _test_simple_function2: TestTerm = term! {
           fn_new_random(K((client,0)))
        };
        let _test_simple_function1: TestTerm = term! {
           fn_protocol_version12
        };
        let _test_simple_function: TestTerm = term! {
           fn_new_random(K((client,0)/ProtocolVersion))
        };
        let _test_variable: TestTerm = term! {
            K((client,0)/ProtocolVersion)
        };
        let _set_nested_function: TestTerm = term! {
           fn_hmac256(
                fn_hmac256_new_key,
                (fn_hmac256(fn_hmac256_new_key, fn_empty_bytes_vec))
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
            false,
        );

        let generated_term = Term::from(DYTerm::Application(
            hmac256,
            vec![
                Term::from(DYTerm::Application(hmac256_new_key, vec![])),
                Term::from(DYTerm::Variable(variable)),
            ],
        ));

        log::debug!("Generated term: {}", generated_term);

        fn dummy_factory() -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory)
        }

        let registry = PutRegistry::<TestProtocolBehavior>::new(
            [("teststub", dummy_factory())],
            PutDescriptor::new("teststub", PutOptions::empty()),
        );

        let spawner = Spawner::new(registry);
        let mut context = TraceContext::new(spawner);
        context.knowledge_store.add_raw_knowledge(
            data,
            None,
            Source::Agent(AgentName::first()),
            None,
        );

        log::trace!("New knowledge: {:?}", context.knowledge_store);

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
                                    false,
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
                            false,
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
                                    false,
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
                                false,
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

    /// The `term!` macro accepts nested applications both with wrapping parentheses (legacy) and
    /// without, and both spellings produce structurally equal terms.
    #[test_log::test]
    fn term_macro_optional_parentheses() {
        let with_parens: TestTerm = term! {
            fn_hmac256(
                fn_hmac256_new_key,
                (fn_hmac256(
                    fn_hmac256_new_key,
                    (fn_hmac256(fn_hmac256_new_key, fn_empty_bytes_vec))
                ))
            )
        };
        let without_parens: TestTerm = term! {
            fn_hmac256(
                fn_hmac256_new_key,
                fn_hmac256(
                    fn_hmac256_new_key,
                    fn_hmac256(fn_hmac256_new_key, fn_empty_bytes_vec)
                )
            )
        };
        // Legacy and new spelling can also be freely mixed.
        let mixed: TestTerm = term! {
            fn_hmac256(
                fn_hmac256_new_key,
                (fn_hmac256(
                    fn_hmac256_new_key,
                    fn_hmac256(fn_hmac256_new_key, fn_empty_bytes_vec)
                ))
            )
        };

        assert_eq!(with_parens, without_parens);
        assert_eq!(with_parens, mixed);
        assert_eq!(
            TermTree::size(&with_parens),
            TermTree::size(&without_parens)
        );
    }

    /// Nested applications without wrapping parentheses still work next to variable and constant
    /// arguments (variables keep their parentheses), and empty argument lists are accepted.
    #[test_log::test]
    fn term_macro_mixed_argument_kinds() {
        let client = AgentName::first();
        let term: TestTerm = term! {
            fn_client_hello(
                fn_protocol_version12(),
                K((client, 0) / Random),
                fn_new_session_id,
                fn_append_cipher_suite(fn_new_cipher_suites(), fn_cipher_suite12),
                fn_compressions,
                [fn_support_group_extension(fn_named_group_secp384r1)]
            )
        };

        // fn_client_hello has 6 arguments, one of which is a variable.
        assert_eq!(term.get(&[0]).unwrap().name(), fn_protocol_version12.name());
        assert!(term.has_variable());
    }

    /// The query of the variable at the root of `term`, which must be one.
    fn root_query(term: &TestTerm) -> &Query<AnyMatcher> {
        match &term.term {
            DYTerm::Variable(variable) => &variable.query,
            other => panic!("expected a variable at the root, got {other}"),
        }
    }

    /// `K(...)` searches the knowledge, `C(...)` searches the claims: both build a variable, the
    /// only difference being the `is_claim` flag of their query.
    #[test_log::test]
    fn term_macro_knowledge_and_claim_queries() {
        let client = AgentName::first();

        let knowledge: TestTerm = term! { K((client, 3)[Some(AnyMatcher)] / Random) };
        let claim: TestTerm = term! { C((client, 3)[Some(AnyMatcher)] / Random) };

        for term in [&knowledge, &claim] {
            let query = root_query(term);
            assert_eq!(query.source, Some(Source::Agent(client)));
            assert_eq!(query.matcher, Some(AnyMatcher));
            assert_eq!(query.counter, 3);
            assert_eq!(term.get_type_shape(), &TypeShape::of::<Random>());
        }

        assert!(!root_query(&knowledge).is_claim);
        assert!(root_query(&claim).is_claim);
    }

    /// A knowledge query can also read a precomputation, selected by its label. Claims are only
    /// produced by agents, so `C(...)` has no such form.
    #[test_log::test]
    fn term_macro_knowledge_query_on_precomputation() {
        let term: TestTerm = term! { K((!"precomputed", 0) / Random) };
        let query = root_query(&term);

        assert_eq!(
            query.source,
            Some(Source::Label(Some("precomputed".to_owned())))
        );
        assert_eq!(query.matcher, None);
        assert!(!query.is_claim);
    }

    /// Both query kinds may omit their type when used as a function argument: it is then inferred
    /// from the type of the argument they are passed as.
    #[test_log::test]
    fn term_macro_queries_infer_their_type_from_the_argument() {
        let client = AgentName::first();

        let knowledge: TestTerm = term! { fn_renegotiation_info_extension(K((client, 0))) };
        let claim: TestTerm =
            term! { fn_renegotiation_info_extension(C((client, 0)[Some(AnyMatcher)])) };

        for (term, is_claim) in [(&knowledge, false), (&claim, true)] {
            let argument = term
                .get(&[0])
                .expect("fn_renegotiation_info_extension takes one argument");
            assert_eq!(argument.get_type_shape(), &TypeShape::of::<Vec<u8>>());
            assert_eq!(root_query(argument).is_claim, is_claim);
        }
    }

    // ---- `DYTerm::Deconstructor` mechanism ----

    fn empty_context() -> TraceContext<TestProtocolBehavior> {
        fn dummy_factory() -> Box<dyn Factory<TestProtocolBehavior>> {
            Box::new(TestFactory)
        }
        let registry = PutRegistry::<TestProtocolBehavior>::new(
            [("teststub", dummy_factory())],
            PutDescriptor::new("teststub", PutOptions::empty()),
        );
        TraceContext::new(Spawner::new(registry))
    }

    /// Builds `deconstruct[query]<Vec<u8>>(fn_make_byte_container)`: it concretizes a
    /// [`TestByteContainer`] and extracts the inner `Vec<u8>` selected by `query`.
    fn byte_container_deconstructor(counter: u16) -> TestTerm {
        Term::from(DYTerm::Deconstructor(
            TypeShape::of::<Vec<u8>>(),
            Box::new(Term::from(DYTerm::Application(
                Signature::new_function(&fn_make_byte_container),
                vec![],
            ))),
            Query {
                source: None,
                matcher: None,
                counter,
                is_claim: false,
            },
        ))
    }

    /// The deconstructor concretizes its source term and extracts the inner `Vec<u8>` sub-value.
    #[test_log::test]
    fn deconstructor_extracts_inner_value() {
        let context = empty_context();
        let deconstructor = byte_container_deconstructor(0);

        let evaluated = deconstructor
            .evaluate_dy(&context)
            .expect("deconstructor evaluation should succeed");
        let extracted = evaluated
            .as_any()
            .downcast_ref::<Vec<u8>>()
            .expect("deconstructor should extract a Vec<u8>");

        assert_eq!(extracted, &vec![4u8, 2u8]);
    }

    /// A deconstructor's result type is the stored `TypeShape`, and its single source term is
    /// exposed as a regular subterm.
    #[test_log::test]
    fn deconstructor_structure_and_display() {
        let deconstructor = byte_container_deconstructor(0);

        // The result type is the stored TypeShape.
        assert_eq!(deconstructor.get_type_shape(), &TypeShape::of::<Vec<u8>>());
        assert_eq!(
            deconstructor.name(),
            TypeShape::<TestProtocolTypes>::of::<Vec<u8>>().name
        );

        // The source term is a real subterm: size counts it and `get` reaches it.
        assert_eq!(TermTree::size(&deconstructor), 2);
        assert_eq!(
            deconstructor.get(&[0]).unwrap().name(),
            fn_make_byte_container.name()
        );
        // Iteration visits the source term and the deconstructor node itself.
        assert_eq!(deconstructor.into_iter().count(), 2);

        // Display marks the node as a deconstructor.
        assert!(deconstructor.to_string().contains("deconstruct"));
    }

    /// The `D(...)` `term!` operator builds a deconstructor, with or without an explicit matcher,
    /// and accepts the same source-term spellings as a normal function argument.
    #[test_log::test]
    fn deconstructor_macro_syntax() {
        let context = empty_context();

        // `D(term, Type)` — no matcher — is equivalent to the manually built deconstructor.
        let without_matcher: TestTerm = term! { D(fn_make_byte_container, Vec<u8>) };
        assert_eq!(without_matcher, byte_container_deconstructor(0));

        // The source term can also be written as an application (with or without parentheses).
        let app_source: TestTerm = term! { D(fn_make_byte_container(), Vec<u8>) };
        assert_eq!(app_source, byte_container_deconstructor(0));

        // `D(term, [matcher] / Type)` — explicit matcher.
        let with_matcher: TestTerm =
            term! { D(fn_make_byte_container, [Some(AnyMatcher)] / Vec<u8>) };

        // All spellings evaluate by extracting the inner Vec<u8>.
        for deconstructor in [without_matcher, app_source, with_matcher] {
            let evaluated = deconstructor.evaluate_dy(&context).unwrap();
            assert_eq!(
                evaluated.as_any().downcast_ref::<Vec<u8>>().unwrap(),
                &vec![4u8, 2u8]
            );
        }
    }

    /// `fn_myfn(D(term))` infers the deconstructor's target type from the enclosing function's
    /// argument type.
    #[test_log::test]
    fn deconstructor_macro_infers_argument_type() {
        // fn_renegotiation_info_extension expects a `Vec<u8>` argument.
        let term: TestTerm = term! {
            fn_renegotiation_info_extension(D(fn_make_byte_container))
        };

        let arg = term.get(&[0]).unwrap();
        assert!(matches!(&arg.term, DYTerm::Deconstructor(..)));
        // The target type was inferred to be `Vec<u8>` (the argument type), not spelled out.
        assert_eq!(arg.get_type_shape(), &TypeShape::of::<Vec<u8>>());

        // It also evaluates: the inner Vec<u8> is extracted and fed to the function.
        let context = empty_context();
        assert!(term.evaluate_dy(&context).is_ok());
    }

    /// The optional trailing counter selects the N-th matching sub-value.
    #[test_log::test]
    fn deconstructor_macro_counter_selects_nth() {
        let context = empty_context();

        let first: TestTerm = term! { D(fn_make_byte_pair, Vec<u8>, 0) };
        let second: TestTerm = term! { D(fn_make_byte_pair, Vec<u8>, 1) };

        let eval_first = first.evaluate_dy(&context).unwrap();
        assert_eq!(
            eval_first.as_any().downcast_ref::<Vec<u8>>().unwrap(),
            &vec![1u8, 1u8]
        );
        let eval_second = second.evaluate_dy(&context).unwrap();
        assert_eq!(
            eval_second.as_any().downcast_ref::<Vec<u8>>().unwrap(),
            &vec![2u8, 2u8]
        );

        // Omitting the counter defaults to 0.
        let default: TestTerm = term! { D(fn_make_byte_pair, Vec<u8>) };
        assert_eq!(default, first);

        // The counter also works with the matcher form and the inferred-type argument form.
        let with_matcher: TestTerm =
            term! { D(fn_make_byte_pair, [Some(AnyMatcher)] / Vec<u8>, 1) };
        assert_eq!(
            with_matcher
                .evaluate_dy(&context)
                .unwrap()
                .as_any()
                .downcast_ref::<Vec<u8>>()
                .unwrap(),
            &vec![2u8, 2u8]
        );

        let inferred: TestTerm = term! { fn_renegotiation_info_extension(D(fn_make_byte_pair, 1)) };
        let arg = inferred.get(&[0]).unwrap();
        assert_eq!(arg.get_type_shape(), &TypeShape::of::<Vec<u8>>());
        assert!(inferred.evaluate_dy(&context).is_ok());
    }

    /// Requesting a counter beyond the number of matching sub-values fails cleanly (no panic).
    #[test_log::test]
    fn deconstructor_missing_value_errors() {
        let context = empty_context();
        // There is a single `Vec<u8>` reachable from the container, so counter 1 has no match.
        let deconstructor = byte_container_deconstructor(1);

        assert!(deconstructor.evaluate_dy(&context).is_err());
    }

    // ---- `DYTerm::List` mechanism ----

    /// The `[t1, t2]` `term!` syntax builds a list, of the type spelled out after `/` when there
    /// is no enclosing argument to take it from.
    #[test_log::test]
    fn list_macro_builds_and_evaluates() {
        let context = empty_context();
        let list: TestTerm = term! {
            [fn_signature_algorithm_extension, fn_ec_point_formats_extension]
                / Vec<ClientExtension>
        };

        assert_eq!(
            list.get_type_shape(),
            &TypeShape::of::<Vec<ClientExtension>>()
        );
        // The elements are regular subterms: size counts them and `get` reaches them.
        assert_eq!(TermTree::size(&list), 3);
        assert_eq!(
            list.get(&[1]).unwrap().name(),
            fn_ec_point_formats_extension.name()
        );

        let evaluated = list.evaluate_dy(&context).unwrap();
        assert_eq!(
            evaluated
                .as_any()
                .downcast_ref::<Vec<ClientExtension>>()
                .unwrap()
                .len(),
            2
        );
    }

    /// As a function argument, the list type is the argument type, so the empty list is writable
    /// and the elements need no type of their own.
    #[test_log::test]
    fn list_macro_infers_argument_type() {
        let context = empty_context();
        let client_hello: TestTerm = term! {
            fn_client_hello(
                fn_protocol_version12,
                fn_new_random,
                fn_new_session_id,
                fn_new_cipher_suites,
                fn_compressions,
                []
            )
        };

        let extensions = client_hello.get(&[5]).unwrap();
        assert!(matches!(&extensions.term, DYTerm::List(_, elements) if elements.is_empty()));
        assert_eq!(
            extensions.get_type_shape(),
            &TypeShape::of::<Vec<ClientExtension>>()
        );
        assert!(client_hello.evaluate_dy(&context).is_ok());
    }

    /// Every element of a list must have the element type of the list type.
    #[test_log::test]
    fn list_rejects_elements_of_another_type() {
        let well_typed = DYTerm::<TestProtocolTypes>::list(
            TypeShape::of::<Vec<ClientExtension>>(),
            vec![term! { fn_signature_algorithm_extension }],
        );
        assert!(well_typed.is_ok());

        // `fn_new_random` returns a `Random`, not a `ClientExtension`.
        let ill_typed = DYTerm::<TestProtocolTypes>::list(
            TypeShape::of::<Vec<ClientExtension>>(),
            vec![
                term! { fn_signature_algorithm_extension },
                term! { fn_new_random },
            ],
        );
        assert!(ill_typed.is_err());

        // Only a `Vec<T>` registered with `define_list_types!` is a list type.
        let unregistered = DYTerm::<TestProtocolTypes>::list(TypeShape::of::<Vec<u8>>(), vec![]);
        assert!(unregistered.is_err());
    }

    /// A list is a list term, is neither opaque nor a leaf unless empty, and displays its
    /// elements.
    #[test_log::test]
    fn list_structure_and_display() {
        let empty: TestTerm =
            Term::from(DYTerm::list(TypeShape::of::<Vec<ClientExtension>>(), vec![]).unwrap());
        let filled: TestTerm = term! { [fn_signature_algorithm_extension] / Vec<ClientExtension> };

        assert!(empty.is_list() && filled.is_list());
        assert!(!filled.is_opaque() && !filled.is_get());
        assert!(empty.is_leaf() && !filled.is_leaf());
        assert_eq!(TermTree::size(&empty), 1);

        // Iteration visits the elements and the list node itself.
        assert_eq!(filled.into_iter().count(), 2);
        assert!(empty.to_string().contains("[]"));
        assert!(filled.to_string().contains("signature_algorithm_extension"));
    }

    /// Cloning a term shares its node (DAG), and the same sub-term can appear several times in
    /// a term without being copied.
    #[test_log::test]
    fn shared_subterm_in_several_places() {
        let context = empty_context();
        let extension: TestTerm = term! { fn_signature_algorithm_extension };
        let shared_list: TestTerm = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                vec![extension.share(), extension.share(), extension.share()],
            )
            .unwrap(),
        );
        let unshared_list: TestTerm = term! {
            [fn_signature_algorithm_extension, fn_signature_algorithm_extension,
             fn_signature_algorithm_extension] / Vec<ClientExtension>
        };

        let elements = (0..3)
            .map(|i| shared_list.get(&[i]).unwrap())
            .collect::<Vec<_>>();
        assert!(elements.iter().all(|e| e.is_shared_with(&extension)));
        assert!(extension.is_shared());
        assert!(!unshared_list
            .get(&[0])
            .unwrap()
            .is_shared_with(unshared_list.get(&[1]).unwrap()));

        // Sharing is only a representation: both terms denote the same value.
        assert_eq!(shared_list, unshared_list);
        assert_eq!(TermTree::size(&shared_list), TermTree::size(&unshared_list));
        assert_eq!(
            shared_list.evaluate_symbolic(&context).unwrap(),
            unshared_list.evaluate_symbolic(&context).unwrap()
        );
    }

    /// Mutating one occurrence of a shared node copies it (copy-on-write): the other occurrences
    /// are left untouched, and the untouched sub-terms stay shared.
    #[test_log::test]
    fn mutating_a_shared_term_does_not_affect_other_occurrences() {
        let original: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let mut copy = original.share();
        assert!(copy.is_shared_with(&original));

        let DYTerm::Application(_, args) = copy.dy_mut() else {
            panic!("expected an application");
        };
        args[1] = term! { fn_seq_1 };

        assert!(!copy.is_shared_with(&original));
        assert_ne!(copy, original);
        assert!(original.to_string().contains("seq_0"));
        assert!(copy.to_string().contains("seq_1"));
        // Only the modified node was copied.
        assert!(copy
            .get(&[0])
            .unwrap()
            .is_shared_with(original.get(&[0]).unwrap()));
    }

    /// The payload belongs to the shared node: every occurrence of a shared node has the same
    /// payload. Changing the payload through one occurrence copies the node (copy-on-write), so
    /// that the other occurrences keep theirs.
    #[test_log::test]
    fn payloads_are_shared_with_the_node() {
        let mut extension: TestTerm = term! { fn_signature_algorithm_extension };
        extension.add_payload(vec![1, 2, 3]);
        assert!(!extension.is_symbolic());

        let list: TestTerm = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                vec![extension.share(), extension.share()],
            )
            .unwrap(),
        );
        let (first, second) = (list.get(&[0]).unwrap(), list.get(&[1]).unwrap());
        assert!(first.is_shared_with(second));
        assert!(!first.is_symbolic() && !second.is_symbolic());
        assert!(std::ptr::eq(
            first.payloads.as_ref().unwrap(),
            second.payloads.as_ref().unwrap()
        ));
        // Both occurrences are listed, though they hold a single payload.
        assert_eq!(list.all_payloads().len(), 2);

        // A copy of the term keeps sharing the payload too.
        let copy = list.share();
        assert!(copy.get(&[0]).unwrap().is_shared_with(first));

        // Changing the payload of one occurrence does not change the others.
        let mut copy = list.clone();
        let DYTerm::List(_, elements) = copy.dy_mut() else {
            panic!("expected a list");
        };
        elements[0].make_symbolic();
        assert!(elements[0].is_symbolic());
        assert!(!elements[1].is_symbolic());
        assert!(!elements[0].is_shared_with(&elements[1]));
        assert!(!first.is_symbolic());
    }

    /// Erasing payloads under a shared sub-term only copies what carries payloads.
    #[test_log::test]
    fn erasing_payloads_keeps_untouched_nodes_shared() {
        let original: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let mut copy = original.share();
        copy.make_symbolic();
        assert!(copy.is_shared_with(&original));

        let mut with_payload = original.share();
        let DYTerm::Application(_, args) = with_payload.dy_mut() else {
            panic!("expected an application");
        };
        args[1].add_payload(vec![0]);
        assert_eq!(with_payload.all_payloads().len(), 1);
        assert!(original.all_payloads().is_empty());

        with_payload.make_symbolic();
        assert!(with_payload.all_payloads().is_empty());
        assert!(with_payload
            .get(&[0])
            .unwrap()
            .is_shared_with(original.get(&[0]).unwrap()));
    }

    /// Serialization flattens the DAG, but the denoted term is preserved.
    #[test_log::test]
    fn shared_term_roundtrips_through_serde() {
        let extension: TestTerm = term! { fn_signature_algorithm_extension };
        let list: TestTerm = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                vec![extension.share(), extension],
            )
            .unwrap(),
        );

        let serialized = serde_json::to_string(&list).unwrap();
        let deserialized: TestTerm = serde_json::from_str(&serialized).unwrap();
        assert_eq!(list, deserialized);
    }

    fn shared_extension_list(count: usize) -> (TestTerm, TestTerm) {
        let extension: TestTerm = term! { fn_counted_extension };
        let list = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                (0..count).map(|_| extension.share()).collect(),
            )
            .unwrap(),
        );
        (extension, list)
    }

    /// The sharing is kept by the serialization (the nodes are not duplicated), for a text and
    /// for a binary format, and the nodes which were not shared stay separate.
    #[test_log::test]
    fn sharing_is_kept_through_serialization() {
        fn check(list: &TestTerm) {
            let (first, second, third) = (
                list.get(&[0]).unwrap(),
                list.get(&[1]).unwrap(),
                list.get(&[2]).unwrap(),
            );
            assert!(first.is_shared_with(second));
            assert!(!first.is_shared_with(third));
        }

        let (_, shared) = shared_extension_list(2);
        let DYTerm::List(typ, elements) = &shared.term else {
            panic!("expected a list");
        };
        let mut elements = elements.iter().map(Term::share).collect::<Vec<_>>();
        elements.push(term! { fn_counted_extension });
        let list: TestTerm = Term::from(DYTerm::list(typ.clone(), elements).unwrap());
        check(&list);

        let json: TestTerm = serde_json::from_str(&serde_json::to_string(&list).unwrap()).unwrap();
        check(&json);
        assert_eq!(json, list);

        let bytes: TestTerm = postcard::from_bytes(&postcard::to_allocvec(&list).unwrap()).unwrap();
        check(&bytes);
        assert_eq!(bytes, list);

        // A node which is shared is written once: the encoding is smaller than the unshared one.
        let (_, shared_five) = shared_extension_list(5);
        let unshared_five: TestTerm = term! {
            [fn_counted_extension, fn_counted_extension, fn_counted_extension,
             fn_counted_extension, fn_counted_extension] / Vec<ClientExtension>
        };
        assert!(
            postcard::to_allocvec(&shared_five).unwrap().len()
                < postcard::to_allocvec(&unshared_five).unwrap().len()
        );
    }

    /// The sharing is also kept between the terms of a trace, including the prior traces.
    #[test_log::test]
    fn sharing_is_kept_through_trace_serialization() {
        use crate::trace::{Action, InputAction, Step, Trace};

        let agent = AgentName::first();
        let shared: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let step = |recipe: TestTerm| Step {
            agent,
            action: Action::Input(InputAction {
                precomputations: vec![],
                recipe,
            }),
        };
        let trace = Trace {
            prior_traces: vec![Trace {
                steps: vec![step(shared.share())],
                ..Default::default()
            }],
            steps: vec![step(shared.share()), step(shared.share())],
            ..Default::default()
        };

        fn recipes(trace: &TestTrace) -> Vec<&TestTerm> {
            trace
                .prior_traces
                .iter()
                .flat_map(|t| t.steps.iter())
                .chain(trace.steps.iter())
                .map(|step| match &step.action {
                    Action::Input(input) => &input.recipe,
                    Action::Output(_) => unreachable!(),
                })
                .collect()
        }
        let check = |trace: &TestTrace| {
            let recipes = recipes(trace);
            assert_eq!(recipes.len(), 3);
            assert!(recipes.iter().all(|r| r.is_shared_with(recipes[0])));
        };
        check(&trace);

        let json: TestTrace =
            serde_json::from_str(&serde_json::to_string(&trace).unwrap()).unwrap();
        check(&json);
        let bytes: TestTrace =
            postcard::from_bytes(&postcard::to_allocvec(&trace).unwrap()).unwrap();
        check(&bytes);
    }

    /// A node can never be reached from its own descendants: mutating through `dy_mut` first
    /// detaches the node if another handle exists, so "putting a term inside itself" builds a
    /// new node over the old one instead of closing a loop.
    #[test_log::test]
    fn mutation_cannot_create_a_cycle() {
        /// Panics if a node is met again below itself.
        fn assert_acyclic(term: &TestTerm, path: &mut Vec<usize>) {
            assert!(!path.contains(&term.node_id()), "cycle found");
            path.push(term.node_id());
            match &term.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, subterms) | DYTerm::List(_, subterms) => {
                    subterms.iter().for_each(|t| assert_acyclic(t, path));
                }
                DYTerm::Deconstructor(_, inner, _) => assert_acyclic(inner, path),
            }
            path.pop();
        }

        let mut x: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let before = x.node_id();
        let old = x.share(); // another handle on the node we are going to mutate
        let old_copy = x.clone_detached();
        assert!(x.is_shared());

        // Try to put the term inside itself: the argument is a handle on the node being mutated.
        let DYTerm::Application(_, args) = x.dy_mut() else {
            panic!("expected an application");
        };
        args[0] = old.share();

        // `x` was detached before the change: it is a new node, which only this place refers to...
        assert_ne!(x.node_id(), before);
        assert!(!x.is_shared());
        // ...and the argument is the previous node, which is untouched and does not contain `x`.
        assert!(x.get(&[0]).unwrap().is_shared_with(&old));
        assert_eq!(old, old_copy);
        assert_acyclic(&x, &mut vec![]);
        assert_acyclic(&old, &mut vec![]);

        // Same when the node is unshared: no other handle exists, so none can be put inside it.
        let mut y: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let before = y.node_id();
        assert!(!y.is_shared());
        let DYTerm::Application(_, args) = y.dy_mut() else {
            panic!("expected an application");
        };
        args[0] = term! { fn_seq_1 };
        assert_eq!(y.node_id(), before, "an unshared node is mutated in place");
        assert_acyclic(&y, &mut vec![]);
    }

    /// A shared node is evaluated once per evaluation, however many places refer to it.
    #[test_log::test]
    fn shared_node_is_evaluated_once() {
        let context = empty_context();

        COUNTED_CALLS.with(|calls| calls.set(0));
        let (_, shared) = shared_extension_list(3);
        shared.evaluate(&context).unwrap();
        assert_eq!(COUNTED_CALLS.with(std::cell::Cell::get), 1);

        // Not shared: evaluated at every place.
        COUNTED_CALLS.with(|calls| calls.set(0));
        let unshared: TestTerm = term! {
            [fn_counted_extension, fn_counted_extension, fn_counted_extension]
                / Vec<ClientExtension>
        };
        unshared.evaluate(&context).unwrap();
        assert_eq!(COUNTED_CALLS.with(std::cell::Cell::get), 3);

        // The cache lives as long as the context: the next evaluations get the same value.
        COUNTED_CALLS.with(|calls| calls.set(0));
        shared.evaluate(&context).unwrap();
        shared.evaluate(&context).unwrap();
        assert_eq!(COUNTED_CALLS.with(std::cell::Cell::get), 0);
    }

    /// A shared node is evaluated once for all the terms evaluated with the same context (what the
    /// execution of a trace does).
    #[test_log::test]
    fn shared_node_is_evaluated_once_across_terms() {
        let context = empty_context();
        let (extension, _) = shared_extension_list(1);
        let first: TestTerm = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                vec![extension.share()],
            )
            .unwrap(),
        );
        let second = first.share();
        let other: TestTerm = Term::from(
            DYTerm::list(
                TypeShape::of::<Vec<ClientExtension>>(),
                vec![extension.share(), extension.share()],
            )
            .unwrap(),
        );

        COUNTED_CALLS.with(|calls| calls.set(0));
        first.evaluate(&context).unwrap();
        second.evaluate(&context).unwrap();
        other.evaluate(&context).unwrap();
        assert_eq!(COUNTED_CALLS.with(std::cell::Cell::get), 1);
    }

    /// A trace is a unit of sharing: cloning it keeps its internal structure (including the
    /// prior traces) but gives fresh nodes, shared with nothing in the original.
    #[test_log::test]
    fn cloning_a_trace_shares_nothing_with_the_original() {
        use std::collections::HashSet;

        use crate::trace::{Action, InputAction, Step, Trace};

        fn collect_ids(term: &TestTerm, ids: &mut HashSet<usize>) {
            ids.insert(term.node_id());
            match &term.term {
                DYTerm::Variable(_) => {}
                DYTerm::Application(_, subterms) | DYTerm::List(_, subterms) => {
                    subterms.iter().for_each(|t| collect_ids(t, ids));
                }
                DYTerm::Deconstructor(_, inner, _) => collect_ids(inner, ids),
            }
        }
        fn recipes(trace: &TestTrace) -> Vec<&TestTerm> {
            trace
                .prior_traces
                .iter()
                .flat_map(|t| t.steps.iter())
                .chain(trace.steps.iter())
                .map(|step| match &step.action {
                    Action::Input(input) => &input.recipe,
                    Action::Output(_) => unreachable!(),
                })
                .collect()
        }
        fn ids(trace: &TestTrace) -> HashSet<usize> {
            let mut ids = HashSet::new();
            recipes(trace).iter().for_each(|r| collect_ids(r, &mut ids));
            ids
        }

        let agent = AgentName::first();
        let shared: TestTerm = term! { fn_encrypt12(fn_finished, fn_seq_0) };
        let step = |recipe: TestTerm| Step {
            agent,
            action: Action::Input(InputAction {
                precomputations: vec![],
                recipe,
            }),
        };
        let original = Trace {
            prior_traces: vec![Trace {
                steps: vec![step(shared.share())],
                ..Default::default()
            }],
            steps: vec![step(shared.share()), step(term! { fn_seq_1 })],
            ..Default::default()
        };
        let mut copy = original.clone();

        // Same structure, and the sharing inside the trace is kept.
        let (originals, copies) = (recipes(&original), recipes(&copy));
        assert_eq!(originals.len(), copies.len());
        for (a, b) in originals.iter().zip(&copies) {
            assert_eq!(a, b);
        }
        assert!(copies[0].is_shared_with(copies[1]));
        assert!(!copies[0].is_shared_with(copies[2]));

        // Nothing is shared between the two traces.
        assert!(ids(&original).is_disjoint(&ids(&copy)));
        assert!(!shared.is_shared_with(copies[0]));

        // So changing the copy leaves the original untouched.
        let Action::Input(input) = &mut copy.steps[0].action else {
            unreachable!()
        };
        let DYTerm::Application(_, args) = input.recipe.dy_mut() else {
            panic!("expected an application");
        };
        args[1] = term! { fn_seq_1 };
        assert_eq!(recipes(&original)[0], &shared);
        assert_ne!(recipes(&copy)[1], &shared);
    }

    /// `clone_detached` keeps the sharing inside the term, but shares nothing with its source.
    #[test_log::test]
    fn clone_detached_keeps_internal_sharing_only() {
        let (_, list) = shared_extension_list(3);
        let copy = list.clone_detached();
        assert_eq!(copy, list);

        let (first, second) = (copy.get(&[0]).unwrap(), copy.get(&[1]).unwrap());
        assert!(first.is_shared_with(second));
        assert!(!copy.is_shared_with(&list));
        assert!(!first.is_shared_with(list.get(&[0]).unwrap()));

        // `share` is the same node, whereas `clone` copies it.
        assert!(list.share().is_shared_with(&list));
        assert!(!list.clone().is_shared_with(&list));
    }

    /// `Step::clone_detached` is what the repeat mutation uses: the repeated step is evaluated
    /// again rather than sharing its nodes with the original step.
    #[test_log::test]
    fn step_clone_detached_shares_nothing_with_the_source() {
        use crate::trace::{Action, InputAction, Step};

        let step = Step {
            agent: AgentName::first(),
            action: Action::Input(InputAction {
                precomputations: vec![],
                recipe: term! { fn_encrypt12(fn_finished, fn_seq_0) },
            }),
        };
        let (Action::Input(original), Action::Input(detached)) =
            (&step.action, &step.clone_detached().action)
        else {
            unreachable!()
        };
        assert!(!detached.recipe.is_shared_with(&original.recipe));
        assert_eq!(detached.recipe, original.recipe);
    }

    /// In `term!`, a `@variable` is the very same node at each place it is used, and the equal
    /// `K`/`C` queries are one shared node.
    #[test_log::test]
    fn term_macro_shares_variables() {
        let extension: TestTerm = term! { fn_signature_algorithm_extension };
        let with_at: TestTerm = term! {
            [(@extension), (@extension)] / Vec<ClientExtension>
        };
        assert!(with_at
            .get(&[0])
            .unwrap()
            .is_shared_with(with_at.get(&[1]).unwrap()));
        assert!(with_at.get(&[0]).unwrap().is_shared_with(&extension));
    }
}
