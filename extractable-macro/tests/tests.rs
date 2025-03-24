use std::any::Any;

use extractable_macro::Extractable;
use puffin::agent::ProtocolDescriptorConfig;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::AnyMatcher;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, codec, define_signature, dummy_codec};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Hash, Serialize, Deserialize)]
struct TestProtocolDescriptorConfig {}

impl ProtocolDescriptorConfig for TestProtocolDescriptorConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
struct TestProtocolTypes {}

impl std::fmt::Display for TestProtocolTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl ProtocolTypes for TestProtocolTypes {
    type Matcher = AnyMatcher;
    type PUTConfig = TestProtocolDescriptorConfig;

    fn signature() -> &'static Signature<Self> {
        &TEST_SIGNATURE
    }
}

#[derive(Debug, Clone)]
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
    #[derive(Clone, Debug, Extractable)]
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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        #[extractable_no_recursion]
        a: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: Void() };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
}

#[test]
fn extractable_named_struct() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: Void,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct { a: Void() };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
}

#[test]
fn extractable_named_struct_multiple_fields() {
    #[derive(Clone, Debug, Extractable)]
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

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 4);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.a));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.b));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.c));
}

#[test]
fn extractable_named_struct_ignored_fields() {
    #[derive(Clone, Debug, Extractable)]
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

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.b));
}

#[test]
fn extractable_named_struct_recursive() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        a: Void,
        b: OtherStruct,
        c: Void,
    }

    #[derive(Clone, Debug, Extractable)]
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

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(#[extractable_no_recursion] Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
}

#[test]
fn extractable_unnamed_struct() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
}

#[test]
fn extractable_unnamed_struct_multiple_fields() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void, Void, Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), Void(), Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 4);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.0));
    assert_eq!(store[2].data.as_any().type_id(), Any::type_id(&a.1));
    assert_eq!(store[3].data.as_any().type_id(), Any::type_id(&a.2));
}

#[test]
fn extractable_unnamed_struct_ignored_fields() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(#[extractable_ignore] Void, u8, #[extractable_ignore] Void);

    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), 0, Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(store[1].data.as_any().type_id(), Any::type_id(&a.1));
}

#[test]
fn extractable_unnamed_struct_recursive() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct(Void, OtherStruct, Void);

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct OtherStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestStruct);
    dummy_codec!(TestProtocolTypes, OtherStruct);

    let mut store = vec![];
    let a = TestStruct(Void(), OtherStruct { x: 1, y: 2 }, Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A {
            #[extractable_no_recursion]
            x: TestStruct,
        },
        _B,
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A {
        x: TestStruct { x: 0, y: 1 },
    };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 2);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
    assert_eq!(
        store[1].data.as_any().type_id(),
        std::any::TypeId::of::<TestStruct>()
    );
}

#[test]
fn extractable_enum_ignore_named_fields() {
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A {
            x: Void,
            #[extractable_ignore]
            _y: TestStruct,
            z: Void,
        },
        _B,
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A {
        x: Void(),
        _y: TestStruct { x: 0, y: 1 },
        z: Void(),
    };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A { a: TestStruct, b: Void },
        _B,
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A {
        a: TestStruct { x: 0, y: 1 },
        b: Void(),
    };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A(Void, #[extractable_ignore] TestStruct, Void),
        _B,
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A(Void(), TestStruct { x: 0, y: 1 }, Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A(TestStruct, Void),
        _B,
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A(TestStruct { x: 0, y: 1 }, Void());

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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
    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    enum TestEnum {
        _A(TestStruct, Void, TestStruct),
        _B,
        _C { a: Void, b: TestStruct },
    }

    #[derive(Clone, Debug, Extractable)]
    #[extractable(TestProtocolTypes)]
    struct TestStruct {
        x: u8,
        y: u8,
    }

    dummy_codec!(TestProtocolTypes, TestEnum);
    dummy_codec!(TestProtocolTypes, TestStruct);

    let mut store = vec![];
    let a = TestEnum::_A(
        TestStruct { x: 0, y: 1 },
        Void(),
        TestStruct { x: 42, y: 42 },
    );

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

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

    let b = TestEnum::_C {
        a: Void(),
        b: TestStruct { x: 3, y: 4 },
    };

    let _ = b.extract_knowledge(
        &mut other_store,
        None as Option<AnyMatcher>,
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

    impl std::fmt::Debug for TestUnion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestUnion")
        }
    }

    dummy_codec!(TestProtocolTypes, TestUnion);

    let mut store = vec![];
    let a = TestUnion { _x: 64 };

    let _ = a.extract_knowledge(&mut store, None as Option<AnyMatcher>, &Source::Label(None));

    assert_eq!(store.len(), 1);
    assert_eq!(store[0].data.as_any().type_id(), Any::type_id(&a));
}
