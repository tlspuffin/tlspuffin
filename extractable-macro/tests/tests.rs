use std::any::{Any, TypeId};

use comparable::Comparable;
use extractable_macro::Extractable;
use puffin::agent::ProtocolDescriptorConfig;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::Matcher;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, codec, define_signature, dummy_codec};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct TestProtocolDescriptorConfig {}

impl ProtocolDescriptorConfig for TestProtocolDescriptorConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {
        true
    }
}

/// A matcher whose values are distinguishable, so that a test can assert *which* matcher a
/// knowledge was recorded under. `puffin`'s `AnyMatcher` matches everything and would make every
/// assertion below pass regardless.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
enum TestMatcher {
    Alert,
    Handshake(u8),
    Other,
}

impl Matcher for TestMatcher {
    fn matches(&self, matcher: &Self) -> bool {
        self == matcher
    }

    fn specificity(&self) -> u32 {
        0
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
    type Matcher = TestMatcher;
    type PUTConfig = TestProtocolDescriptorConfig;

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

#[derive(Debug, Clone, Comparable)]
struct Void();

fn fn_void() -> Result<Void, puffin::algebra::error::FnError> {
    Ok(Void())
}

define_signature!(TEST_SIGNATURE<TestProtocolTypes>, fn_void);
dummy_codec!(TestProtocolTypes, Void);
atom_extract_knowledge!(TestProtocolTypes, Void);
atom_extract_knowledge!(TestProtocolTypes, u8);

#[test]
fn extractable_unit_struct() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {}

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct {};

    let _ = a.extract_knowledge(&mut store, None, &Source::Label(None));

    assert_eq!(store.len(), 1);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
}

#[test]
fn extractable_no_recursion_named_struct() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        #[extractable_no_recursion]
        a: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: Void() };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
}

#[test]
fn extractable_named_struct() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: Void() };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
}

#[test]
fn extractable_named_struct_multiple_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: Void,
        b: Void,
        c: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct {
        a: Void(),
        b: Void(),
        c: Void(),
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 4);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.b));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.c));
}

#[test]
fn extractable_named_struct_ignored_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        #[extractable_ignore]
        _a: Void,
        b: u8,
        #[extractable_ignore]
        _c: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct {
        _a: Void(),
        b: 0,
        _c: Void(),
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.b));
}

#[test]
fn extractable_named_struct_recursive() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: Void,
        b: OtherStruct,
        c: Void,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct OtherStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);
    dummy_codec!(TestProtocolTypes, OtherStruct);

    let mut store = vec![];
    let a = TestStruct {
        a: Void(),
        b: OtherStruct { x: 1, y: 2 },
        c: Void(),
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 6);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.b));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.b.x));
    assert_eq!(store[4].data.as_any().type_id(), Any::type_id(&a.b.y));
    assert_eq!(store[5].data.as_any().type_id(), Any::type_id(&a.c));
}

#[test]
fn extractable_no_recursion_unnamed_struct() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(#[extractable_no_recursion] Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
}

#[test]
fn extractable_unnamed_struct() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
}

#[test]
fn extractable_unnamed_struct_multiple_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void, Void, Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), Void(), Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 4);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.1));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.2));
}

#[test]
fn extractable_unnamed_struct_ignored_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(#[extractable_ignore] Void, u8, #[extractable_ignore] Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), 0, Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.1));
}

#[test]
fn extractable_unnamed_struct_recursive() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void, OtherStruct, Void);

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct OtherStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);
    dummy_codec!(TestProtocolTypes, OtherStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), OtherStruct { x: 1, y: 2 }, Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 6);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.1));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.1.x));
    assert_eq!(store[4].data.as_any().type_id(), Any::type_id(&a.1.y));
    assert_eq!(store[5].data.as_any().type_id(), Any::type_id(&a.2));
}

#[test]
fn extractable_enum_no_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A,
        _B,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);

    let mut store = vec![];
    let a = TestEnum::_A;

    let _ = a.extract_knowledge(&mut store, None, &Source::Label(None));

    assert_eq!(store.len(), 1);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
}
#[test]
fn extractable_enum_no_recursion_named_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A {
            #[extractable_no_recursion]
            x: TestStruct,
        },
        _B,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A {
        x: TestStruct { x: 0, y: 1 },
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
}

#[test]
fn extractable_enum_ignore_named_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A {
            x: Void,
            #[extractable_ignore]
            _y: TestStruct,
            z: Void,
        },
        _B,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A {
        x: Void(),
        _y: TestStruct { x: 0, y: 1 },
        z: Void(),
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 3);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
    assert_eq!(
        store[2].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
}

#[test]
fn extractable_enum_named_fields_recursive() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A { a: TestStruct, b: Void },
        _B,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A {
        a: TestStruct { x: 0, y: 1 },
        b: Void(),
    };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 5);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
    assert_eq!(
        store[2].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[3].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[4].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
}

#[test]
fn extractable_enum_ignore_unnamed_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A(Void, #[extractable_ignore] TestStruct, Void),
        _B,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A(Void(), TestStruct { x: 0, y: 1 }, Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 3);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
    assert_eq!(
        store[2].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
}

#[test]
fn extractable_enum_unnamed_fields_recursive() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A(TestStruct, Void),
        _B,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A(TestStruct { x: 0, y: 1 }, Void());

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 5);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
    assert_eq!(
        store[2].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[3].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[4].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
}

#[test]
fn extractable_enum_named_unnamed_fields_recursive() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        A(TestStruct, Void, TestStruct),
        _B,
        C { a: Void, b: TestStruct },
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::A(
        TestStruct { x: 0, y: 1 },
        Void(),
        TestStruct { x: 42, y: 42 },
    );

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 8);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
    assert_eq!(
        store[2].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[3].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[4].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
    assert_eq!(
        store[5].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
    assert_eq!(
        store[6].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        store[7].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );

    let mut other_store = vec![];

    let b = TestEnum::C {
        a: Void(),
        b: TestStruct { x: 3, y: 4 },
    };

    let _ = b.extract_knowledge(
        &mut other_store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(other_store.len(), 5);
    assert_eq!(other_store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        other_store[1].data.as_any().type_id(),
        std::any::TypeId::of::<Void>()
    );
    assert_eq!(
        other_store[2].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
    assert_eq!(
        other_store[3].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
    assert_eq!(
        other_store[4].data.as_any().type_id(),
        std::any::TypeId::of::<u8>()
    );
}

#[test]
fn extractable_union() {
    #[derive(Clone, Copy, Extractable)]
    #[extractable(TestProtocolTypes)]
    union TestUnion {
        _x: u8,
        _y: char,
    }

    // Dummy implementation because comparable is not derivable for unions
    impl Comparable for TestUnion {
        type Change = ();
        type Desc = ();

        fn describe(&self) -> Self::Desc {
            todo!()
        }

        fn comparison(&self, _other: &Self) -> comparable::Changed<Self::Change> {
            todo!()
        }
    }

    impl std::fmt::Debug for TestUnion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestUnion")
        }
    }

    dummy_codec!(TestProtocolTypes, TestUnion);

    let mut store = vec![];
    let a = TestUnion { _x: 64 };

    let _ = a.extract_knowledge(
        &mut store,
        None as Option<TestMatcher>,
        &Source::Label(None),
    );

    assert_eq!(store.len(), 1);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
}

// ── #[extractable_matcher(...)] ──────────────────────────────────────────────
//
// The assertions are on `Knowledge::matcher` rather than on the number of knowledges: what the
// attribute changes is which query finds a message, and nothing else.

#[test]
fn matcher_on_a_type_replaces_the_one_passed_in() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    #[extractable_matcher(Some(TestMatcher::Alert))]
    struct TestStruct {
        a: u8,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: 1 };

    let _ = a.extract_knowledge(&mut store, Some(TestMatcher::Other), &Source::Label(None));

    // The type's own knowledge and its field are both recorded under the type's matcher, not
    // under the `Other` it was called with.
    assert_eq!(store.len(), 2);
    assert!(store.iter().all(|k| k.matcher == Some(TestMatcher::Alert)));
}

#[test]
fn matcher_on_a_type_reaches_nested_types() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    #[extractable_matcher(Some(TestMatcher::Alert))]
    struct Outer {
        inner: Inner,
    }

    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct Inner {
        a: u8,
    }

    dummy_codec!(TestProtocolTypes, Outer);
    dummy_codec!(TestProtocolTypes, Inner);

    let mut store = vec![];
    let a = Outer {
        inner: Inner { a: 1 },
    };

    let _ = a.extract_knowledge(&mut store, None, &Source::Label(None));

    // Outer, Inner and Inner's u8 — the matcher is passed down, not applied only at the top.
    assert_eq!(store.len(), 3);
    assert!(store.iter().all(|k| k.matcher == Some(TestMatcher::Alert)));
}

#[test]
fn matcher_on_a_variant_can_read_the_variants_fields() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        #[extractable_matcher(Some(TestMatcher::Handshake(*field_0)))]
        Handshake(u8),
        #[extractable_matcher(Some(TestMatcher::Alert))]
        Alert(u8),
        #[extractable_matcher(None)]
        Ccs(u8),
        Other(u8),
    }

    dummy_codec!(TestProtocolTypes, TestEnum);

    let matcher_of = |value: TestEnum| {
        let mut store = vec![];
        let _ = value.extract_knowledge(&mut store, Some(TestMatcher::Other), &Source::Label(None));
        // Both the enum and its payload land under the same matcher.
        assert_eq!(store.len(), 2);
        assert_eq!(store[0].matcher, store[1].matcher);
        store[0].matcher
    };

    // The expression sees the variant's field, so the matcher depends on the message content.
    assert_eq!(
        matcher_of(TestEnum::Handshake(7)),
        Some(TestMatcher::Handshake(7))
    );
    assert_eq!(
        matcher_of(TestEnum::Handshake(9)),
        Some(TestMatcher::Handshake(9))
    );
    assert_eq!(matcher_of(TestEnum::Alert(0)), Some(TestMatcher::Alert));
    // A variant is free to say it carries no matcher at all.
    assert_eq!(matcher_of(TestEnum::Ccs(0)), None);
    // Without an annotation, the matcher passed in is kept.
    assert_eq!(matcher_of(TestEnum::Other(0)), Some(TestMatcher::Other));
}

#[test]
fn matcher_on_a_variant_wins_over_the_one_on_the_enum() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    #[extractable_matcher(Some(TestMatcher::Other))]
    enum TestEnum {
        #[extractable_matcher(Some(TestMatcher::Alert))]
        Alert(u8),
        // No annotation of its own: the enum's is the default.
        Unannotated(u8),
    }

    dummy_codec!(TestProtocolTypes, TestEnum);

    let matcher_of = |value: TestEnum| {
        let mut store = vec![];
        let _ = value.extract_knowledge(
            &mut store,
            Some(TestMatcher::Handshake(1)),
            &Source::Label(None),
        );
        store[0].matcher
    };

    assert_eq!(matcher_of(TestEnum::Alert(0)), Some(TestMatcher::Alert));
    assert_eq!(
        matcher_of(TestEnum::Unannotated(0)),
        Some(TestMatcher::Other)
    );
}

#[test]
fn matcher_on_a_named_variant_binds_fields_by_name() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        #[extractable_matcher(Some(TestMatcher::Handshake(*typ)))]
        Handshake { typ: u8 },
    }

    dummy_codec!(TestProtocolTypes, TestEnum);

    let mut store = vec![];
    let _ =
        TestEnum::Handshake { typ: 3 }.extract_knowledge(&mut store, None, &Source::Label(None));

    assert_eq!(store[0].matcher, Some(TestMatcher::Handshake(3)));
}

#[test]
fn without_the_attribute_the_matcher_is_passed_through() {
    #[derive(Clone, Debug, Comparable, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: u8,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: 1 };

    let _ = a.extract_knowledge(&mut store, Some(TestMatcher::Other), &Source::Label(None));

    assert!(store.iter().all(|k| k.matcher == Some(TestMatcher::Other)));
}
