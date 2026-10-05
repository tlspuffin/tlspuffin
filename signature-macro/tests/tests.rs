//! Integration tests for the `#[signature]` attribute.
//!
//! What is worth testing about a meta-annotation is not that it compiles but that each of the four
//! derives it stands for is *actually applied* — so every test below calls into the trait the
//! derive provides, and the opt-out tests check the hand-written version is the one that survives.

use std::any::TypeId;

use puffin::agent::ProtocolDescriptorConfig;
use puffin::algebra::signature::Signature;
use puffin::algebra::AnyMatcher;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, codec, declare_signature};
use serde::{Deserialize, Serialize};
use signature_macro::signature;

// ── minimal protocol scaffolding ─────────────────────────────────────────────

#[derive(Default, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct TestConfig {}

impl ProtocolDescriptorConfig for TestConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct TestProtocolTypes {}

impl std::fmt::Display for TestProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl ProtocolTypes for TestProtocolTypes {
    type Matcher = AnyMatcher;
    type PUTConfig = TestConfig;

    fn signature() -> &'static Signature<Self> {
        &TEST_SIGNATURE
    }

    fn differential_fuzzing_whitelist() -> Option<Vec<TypeId>> {
        todo!()
    }

    fn differential_fuzzing_claims_blacklist() -> Option<Vec<TypeId>> {
        todo!()
    }

    fn differential_fuzzing_terms_to_eval(
        _agents: &Vec<puffin::agent::AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        todo!()
    }

    fn differential_fuzzing_uniformise_put_config(
        _trace: puffin::trace::Trace<Self>,
    ) -> puffin::trace::Trace<Self> {
        todo!()
    }

    fn differential_fuzzing_filter_diff(_diff: &puffin::differential::TraceDifference) -> bool {
        todo!()
    }
}

declare_signature!(TEST_SIGNATURE<TestProtocolTypes>);

atom_extract_knowledge!(TestProtocolTypes, u8);
atom_extract_knowledge!(TestProtocolTypes, u16);

// ── the whole set at once ────────────────────────────────────────────────────

// `Codec` is not part of the set: the types below write their own, as any protocol message type
// does. `Constructor` needs a *real* one (not just `CodecP`) to register the type as readable.
#[signature(TEST_SIGNATURE, TestProtocolTypes)]
#[derive(PartialEq)]
pub struct Inner {
    pub a: u8,
}

impl codec::Codec for Inner {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::Codec::encode(&self.a, bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <u8 as codec::Codec>::read(r).map(|a| Self { a })
    }
}

#[signature(TEST_SIGNATURE, TestProtocolTypes)]
#[derive(PartialEq)]
pub struct Whole {
    pub first: u16,
    pub inner: Inner,
}

impl codec::Codec for Whole {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::Codec::encode(&self.first, bytes);
        codec::Codec::encode(&self.inner, bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(Self {
            first: <u16 as codec::Codec>::read(r)?,
            inner: <Inner as codec::Codec>::read(r)?,
        })
    }
}

#[test]
fn extractable_is_derived() {
    let value = Whole {
        first: 7,
        inner: Inner { a: 9 },
    };
    let source = Source::Label(None);
    let mut knowledges: Vec<Knowledge<TestProtocolTypes>> = Vec::new();
    Extractable::<TestProtocolTypes>::extract_knowledge(&value, &mut knowledges, None, &source)
        .expect("extract_knowledge");

    // Whole, its u16, Inner, and Inner's u8.
    assert_eq!(knowledges.len(), 4);
    assert!(knowledges
        .iter()
        .any(|k| k.data.type_id() == TypeId::of::<u8>()));
}

#[test]
fn constructor_is_derived_and_registered() {
    // The generated constructor is a free function named after the type...
    let built = fn_whole(&5u16, &Inner { a: 6 }).unwrap();
    assert_eq!(built.first, 5);

    // ... and it is registered into the signature it was given.
    assert!(TEST_SIGNATURE
        .functions_by_name
        .keys()
        .any(|name| name.ends_with("fn_whole")));
}

#[test]
fn comparable_is_derived() {
    use comparable::Comparable;

    let a = Inner { a: 1 };
    let b = Inner { a: 2 };
    assert!(!a.comparison(&b).is_unchanged());
    assert!(a.comparison(&a).is_unchanged());
}

#[test]
fn clone_and_debug_are_part_of_the_set() {
    let value = Inner { a: 1 };
    #[allow(clippy::redundant_clone)]
    let cloned = value.clone();
    assert!(format!("{cloned:?}").contains("Inner"));
}

// ── opting out ───────────────────────────────────────────────────────────────

/// `no_constructor`: the type is still a message, but no function symbol builds it.
#[signature(TEST_SIGNATURE, TestProtocolTypes, no_constructor)]
#[derive(PartialEq)]
pub struct NoSymbol {
    pub value: u8,
}

impl codec::Codec for NoSymbol {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::Codec::encode(&self.value, bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <u8 as codec::Codec>::read(r).map(|value| Self { value })
    }
}

#[test]
fn no_constructor_registers_no_symbol() {
    assert!(!TEST_SIGNATURE
        .functions_by_name
        .keys()
        .any(|name| name.ends_with("fn_nosymbol")));

    // The rest of the set is untouched by the flag.
    let source = Source::Label(None);
    let mut knowledges: Vec<Knowledge<TestProtocolTypes>> = Vec::new();
    Extractable::<TestProtocolTypes>::extract_knowledge(
        &NoSymbol { value: 3 },
        &mut knowledges,
        None,
        &source,
    )
    .expect("extract_knowledge");
    assert_eq!(knowledges.len(), 2);
}
