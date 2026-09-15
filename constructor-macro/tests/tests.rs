/// Integration tests for the `Constructor` derive macro.
///
/// For every struct (or enum variant) it is applied to, the macro generates a free
/// `pub fn fn_<lowercase_name>[_<lowercase_variant>](...) -> Result<Self, FnError>`
/// constructor function and registers it into the signature named by the mandatory
/// `#[constructor(SIGNATURE, ProtocolTypes)]` helper attribute.
///
/// Because the generated functions are registered through `define_signature!`, they must
/// satisfy `DescribableFunction`: every field becomes a **by-reference** parameter
/// (`&FieldType`) that is cloned into the constructed value, and the return type is
/// wrapped in `Result<_, FnError>`. The tests below therefore call the constructors with
/// references and `unwrap()` the result.
///
/// The scaffolding (a minimal `TestProtocolTypes` + `TEST_SIGNATURE`) mirrors the style of
/// the `extractable-macro` integration tests.
use std::any::TypeId;

use comparable::Comparable;
use constructor_macro::Constructor;
use puffin::agent::ProtocolDescriptorConfig;
use puffin::algebra::signature::Signature;
use puffin::algebra::AnyMatcher;
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{atom_extract_knowledge, codec, declare_signature, dummy_codec};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct TestProtocolDescriptorConfig {}

impl ProtocolDescriptorConfig for TestProtocolDescriptorConfig {
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

declare_signature!(TEST_SIGNATURE<TestProtocolTypes>);
atom_extract_knowledge!(TestProtocolTypes, u8);
atom_extract_knowledge!(TestProtocolTypes, u16);
atom_extract_knowledge!(TestProtocolTypes, u32);
atom_extract_knowledge!(TestProtocolTypes, u64);
atom_extract_knowledge!(TestProtocolTypes, bool);
atom_extract_knowledge!(TestProtocolTypes, String);

// ============================================================
// Named structs
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Point {
    x: u8,
    y: u8,
}
dummy_codec!(TestProtocolTypes, Point);
atom_extract_knowledge!(TestProtocolTypes, Point);

#[test]
fn named_struct_generates_fn_with_all_fields_as_params() {
    let p = fn_point(&3, &4).unwrap();
    assert_eq!(p, Point { x: 3, y: 4 });
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Person {
    name: String,
    age: u32,
    active: bool,
}
dummy_codec!(TestProtocolTypes, Person);
atom_extract_knowledge!(TestProtocolTypes, Person);

#[test]
fn named_struct_multiple_heterogeneous_fields() {
    let p = fn_person(&"Alice".to_string(), &30, &true).unwrap();
    assert_eq!(
        p,
        Person {
            name: "Alice".to_string(),
            age: 30,
            active: true,
        }
    );
}

// ============================================================
// Tuple structs
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Pair(u32, u64);
dummy_codec!(TestProtocolTypes, Pair);
atom_extract_knowledge!(TestProtocolTypes, Pair);

#[test]
fn tuple_struct_two_fields_passes_args_correctly() {
    let p = fn_pair(&42, &100).unwrap();
    assert_eq!(p, Pair(42, 100));
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Single(String);
dummy_codec!(TestProtocolTypes, Single);
atom_extract_knowledge!(TestProtocolTypes, Single);

#[test]
fn tuple_struct_single_field() {
    let s = fn_single(&"hello".to_string()).unwrap();
    assert_eq!(s, Single("hello".to_string()));
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Triple(u8, bool, String);
dummy_codec!(TestProtocolTypes, Triple);
atom_extract_knowledge!(TestProtocolTypes, Triple);

#[test]
fn tuple_struct_three_heterogeneous_fields() {
    let t = fn_triple(&7, &true, &"world".to_string()).unwrap();
    assert_eq!(t, Triple(7, true, "world".to_string()));
}

// ============================================================
// Unit structs
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct Empty {}
dummy_codec!(TestProtocolTypes, Empty);
atom_extract_knowledge!(TestProtocolTypes, Empty);

#[test]
fn unit_struct_generates_no_arg_constructor() {
    let e = fn_empty().unwrap();
    assert_eq!(e, Empty {});
}

// ============================================================
// `#[constructor_default(EXPR)]` fields
//
// A field annotated with `#[constructor_default(EXPR)]` is excluded from the constructor
// parameters and is instead initialised from EXPR (a literal, a function call, ...).
// ============================================================

fn forty_two() -> u32 {
    42
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct WithDefaults {
    payload: u8,
    #[constructor_default(0)]
    cached: u8,
    #[constructor_default(forty_two())]
    computed: u32,
}
dummy_codec!(TestProtocolTypes, WithDefaults);
atom_extract_knowledge!(TestProtocolTypes, WithDefaults);

#[test]
fn constructor_default_field_is_not_a_parameter_and_uses_the_expression() {
    // Only `payload` is a parameter; `cached`/`computed` come from their default expressions.
    let w = fn_withdefaults(&9).unwrap();
    assert_eq!(
        w,
        WithDefaults {
            payload: 9,
            cached: 0,
            computed: 42,
        }
    );
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct TupleWithDefault(u8, #[constructor_default(7)] u8);
dummy_codec!(TestProtocolTypes, TupleWithDefault);
atom_extract_knowledge!(TestProtocolTypes, TupleWithDefault);

#[test]
fn constructor_default_works_on_tuple_fields() {
    let t = fn_tuplewithdefault(&1).unwrap();
    assert_eq!(t, TupleWithDefault(1, 7));
}

// ============================================================
// Enums – tuple variants
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
enum Shape {
    Circle(u32),
    Rectangle(u32, u32),
    Segment(u32, u32, u32),
}
dummy_codec!(TestProtocolTypes, Shape);
atom_extract_knowledge!(TestProtocolTypes, Shape);

#[test]
fn enum_tuple_variant_single_field() {
    let c = fn_shape_circle(&3).unwrap();
    assert_eq!(c, Shape::Circle(3));
}

#[test]
fn enum_tuple_variant_two_fields() {
    let r = fn_shape_rectangle(&4, &5).unwrap();
    assert_eq!(r, Shape::Rectangle(4, 5));
}

#[test]
fn enum_tuple_variant_preserves_argument_order() {
    let s = fn_shape_segment(&1, &2, &3).unwrap();
    assert_eq!(s, Shape::Segment(1, 2, 3));
}

// ============================================================
// Enums – named variants
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
enum Color {
    Rgb { r: u8, g: u8, b: u8 },
    Grayscale { intensity: u8 },
}
dummy_codec!(TestProtocolTypes, Color);
atom_extract_knowledge!(TestProtocolTypes, Color);

#[test]
fn enum_named_variant_multiple_fields() {
    let c = fn_color_rgb(&255, &128, &0).unwrap();
    assert_eq!(
        c,
        Color::Rgb {
            r: 255,
            g: 128,
            b: 0
        }
    );
}

#[test]
fn enum_named_variant_single_field() {
    let g = fn_color_grayscale(&200).unwrap();
    assert_eq!(g, Color::Grayscale { intensity: 200 });
}

// ============================================================
// Enums – unit variants
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
enum Direction {
    North,
    South,
    East,
    West,
}
dummy_codec!(TestProtocolTypes, Direction);
atom_extract_knowledge!(TestProtocolTypes, Direction);

#[test]
fn enum_unit_variant_generates_no_arg_constructor() {
    assert_eq!(fn_direction_north().unwrap(), Direction::North);
    assert_eq!(fn_direction_south().unwrap(), Direction::South);
    assert_eq!(fn_direction_east().unwrap(), Direction::East);
    assert_eq!(fn_direction_west().unwrap(), Direction::West);
}

// ============================================================
// Enums – mixed variant kinds
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
enum Command {
    Quit,
    Move { dx: u32, dy: u32 },
    Write(String),
}
dummy_codec!(TestProtocolTypes, Command);
atom_extract_knowledge!(TestProtocolTypes, Command);

#[test]
fn mixed_enum_unit_variant() {
    assert_eq!(fn_command_quit().unwrap(), Command::Quit);
}

#[test]
fn mixed_enum_named_variant() {
    let cmd = fn_command_move(&5, &3).unwrap();
    assert_eq!(cmd, Command::Move { dx: 5, dy: 3 });
}

#[test]
fn mixed_enum_tuple_variant() {
    let cmd = fn_command_write(&"hello".to_string()).unwrap();
    assert_eq!(cmd, Command::Write("hello".to_string()));
}

// ============================================================
// Naming conventions – the type/variant name is fully lowercased
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
struct HTTPResponse {
    status: u16,
    body: String,
}
dummy_codec!(TestProtocolTypes, HTTPResponse);
atom_extract_knowledge!(TestProtocolTypes, HTTPResponse);

#[test]
fn naming_struct_name_is_fully_lowercased() {
    // "HTTPResponse" -> fn_httpresponse
    let r = fn_httpresponse(&200, &"OK".to_string()).unwrap();
    assert_eq!(
        r,
        HTTPResponse {
            status: 200,
            body: "OK".to_string(),
        }
    );
}

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
enum APIStatus {
    NotFound(u32),
    ServerError { code: u16, message: String },
}
dummy_codec!(TestProtocolTypes, APIStatus);
atom_extract_knowledge!(TestProtocolTypes, APIStatus);

#[test]
fn naming_enum_and_tuple_variant_are_fully_lowercased() {
    // "APIStatus::NotFound" -> fn_apistatus_notfound
    let s = fn_apistatus_notfound(&404).unwrap();
    assert_eq!(s, APIStatus::NotFound(404));
}

#[test]
fn naming_enum_and_named_variant_are_fully_lowercased() {
    // "APIStatus::ServerError" -> fn_apistatus_servererror
    let s = fn_apistatus_servererror(&500, &"Internal".to_string()).unwrap();
    assert_eq!(
        s,
        APIStatus::ServerError {
            code: 500,
            message: "Internal".to_string(),
        }
    );
}

// ============================================================
// The generated constructors are registered into the signature
// ============================================================

#[test]
fn generated_constructors_are_registered_in_the_signature() {
    let names: Vec<&str> = TEST_SIGNATURE
        .functions
        .iter()
        .map(|(shape, _)| shape.name)
        .collect();

    // The registered name is the fully-qualified path of the generated function.
    let is_registered = |suffix: &str| names.iter().any(|n| n.ends_with(suffix));

    assert!(is_registered("fn_point"));
    assert!(is_registered("fn_shape_circle"));
    assert!(is_registered("fn_color_rgb"));
    assert!(is_registered("fn_direction_north"));
}

// ============================================================
// `#[constructor_list]` – list constructors
//
// On top of the usual element constructor, `#[constructor_list]` generates three functions
// operating on `Vec<Self>`:
//   * `fn_list_<name>_empty()               -> Vec<Self>`   (an empty list)
//   * `fn_list_<name>_append(&Vec, &Self)   -> Vec<Self>`   (a clone of the list with the element
//     pushed at the end)
//   * `fn_list_<name>_get_first(&Vec)       -> Self`        (the first element, or an error on an
//     empty list)
// It also emits `impl VecCodecWoSize for Self` so that `Vec<Self>: Codec`, and registers the
// three functions into the signature.
//
// Because the functions register `Vec<Self>`, that type must be an `EvaluatedTerm`, which
// requires a *real* `Codec` on the element type (the `dummy_codec!` used elsewhere only
// provides `CodecP`) and `Extractable` on the element type (`Vec<T>: Extractable` then follows
// from a blanket impl).
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
#[constructor_list]
struct Item(u8);

impl codec::Codec for Item {
    fn encode(&self, bytes: &mut Vec<u8>) {
        codec::Codec::encode(&self.0, bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        <u8 as codec::Codec>::read(r).map(Item)
    }
}
atom_extract_knowledge!(TestProtocolTypes, Item);

#[test]
fn constructor_list_empty_returns_an_empty_vec() {
    let list = fn_list_item_empty().unwrap();
    assert_eq!(list, Vec::<Item>::new());
}

#[test]
fn constructor_list_append_pushes_the_element_at_the_end() {
    let list = fn_list_item_empty().unwrap();
    let list = fn_list_item_append(&list, &Item(1)).unwrap();
    let list = fn_list_item_append(&list, &Item(2)).unwrap();
    assert_eq!(list, vec![Item(1), Item(2)]);
}

#[test]
fn constructor_list_append_does_not_mutate_its_input() {
    let original = fn_list_item_append(&vec![], &Item(9)).unwrap();
    // `append` clones the list, so the list passed in is left untouched.
    let _extended = fn_list_item_append(&original, &Item(10)).unwrap();
    assert_eq!(original, vec![Item(9)]);
}

#[test]
fn constructor_list_get_first_returns_the_first_element() {
    let list = vec![Item(7), Item(8), Item(9)];
    assert_eq!(fn_list_item_get_first(&list).unwrap(), Item(7));
}

#[test]
fn constructor_list_get_first_on_an_empty_list_is_an_error() {
    let empty: Vec<Item> = vec![];
    assert!(fn_list_item_get_first(&empty).is_err());
}

#[test]
fn constructor_list_functions_are_registered_in_the_signature() {
    let names: Vec<&str> = TEST_SIGNATURE
        .functions
        .iter()
        .map(|(shape, _)| shape.name)
        .collect();
    let is_registered = |suffix: &str| names.iter().any(|n| n.ends_with(suffix));

    assert!(is_registered("fn_list_item_empty"));
    assert!(is_registered("fn_list_item_append"));
    assert!(is_registered("fn_list_item_get_first"));
    // The plain element constructor is still generated alongside the list ones.
    assert!(is_registered("fn_item"));
}

#[test]
fn constructor_list_is_opt_in_and_absent_without_the_attribute() {
    let names: Vec<&str> = TEST_SIGNATURE
        .functions
        .iter()
        .map(|(shape, _)| shape.name)
        .collect();

    // `Point` does not carry `#[constructor_list]`, so no list constructors exist for it.
    assert!(!names.iter().any(|n| n.contains("fn_list_point")));
}

// ============================================================
// `#[constructor_list]` on an enum – per-variant `find` constructors
//
// For a `#[constructor_list]` enum, each variant additionally gets a
//   `fn_list_<name>_find_<variant>(&Vec<Self>) -> Self`
// returning the *first* list element belonging to that variant, or an error if none does. The
// match is by variant *shape* (`matches!(x, Self::Variant { .. } / (..) / )`), so it works for
// unit, tuple and struct-like variants alike and never inspects the payload.
// ============================================================

#[derive(Constructor, Debug, Clone, Comparable, PartialEq)]
#[constructor(TEST_SIGNATURE, TestProtocolTypes)]
#[constructor_list]
enum Signal {
    Off,                // unit variant
    Level(u8),          // tuple variant (carries data)
    Named { code: u8 }, // struct-like variant (carries data)
}

impl codec::Codec for Signal {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Signal::Off => codec::Codec::encode(&0u8, bytes),
            Signal::Level(v) => {
                codec::Codec::encode(&1u8, bytes);
                codec::Codec::encode(v, bytes);
            }
            Signal::Named { code } => {
                codec::Codec::encode(&2u8, bytes);
                codec::Codec::encode(code, bytes);
            }
        }
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        match <u8 as codec::Codec>::read(r)? {
            0 => Some(Signal::Off),
            1 => Some(Signal::Level(<u8 as codec::Codec>::read(r)?)),
            2 => Some(Signal::Named {
                code: <u8 as codec::Codec>::read(r)?,
            }),
            _ => None,
        }
    }
}
atom_extract_knowledge!(TestProtocolTypes, Signal);

#[test]
fn constructor_list_find_variant_returns_the_first_matching_variant() {
    let list = vec![
        Signal::Off,
        Signal::Level(3),
        Signal::Level(7),
        Signal::Named { code: 9 },
    ];
    // Each finder matches on the variant regardless of payload and returns the first occurrence.
    assert_eq!(fn_list_signal_find_off(&list).unwrap(), Signal::Off);
    assert_eq!(fn_list_signal_find_level(&list).unwrap(), Signal::Level(3));
    assert_eq!(
        fn_list_signal_find_named(&list).unwrap(),
        Signal::Named { code: 9 }
    );
}

#[test]
fn constructor_list_find_variant_skips_non_matching_leading_elements() {
    // The `Level` variant only appears after a non-matching element; `find` still locates it.
    let list = vec![Signal::Off, Signal::Level(5)];
    assert_eq!(fn_list_signal_find_level(&list).unwrap(), Signal::Level(5));
}

#[test]
fn constructor_list_find_variant_errors_when_the_variant_is_absent() {
    let list = vec![Signal::Off, Signal::Off];
    assert!(fn_list_signal_find_level(&list).is_err());
}

#[test]
fn constructor_list_find_variant_on_an_empty_list_is_an_error() {
    let empty: Vec<Signal> = vec![];
    assert!(fn_list_signal_find_off(&empty).is_err());
}

#[test]
fn constructor_list_find_variant_functions_are_registered_in_the_signature() {
    let names: Vec<&str> = TEST_SIGNATURE
        .functions
        .iter()
        .map(|(shape, _)| shape.name)
        .collect();
    let is_registered = |suffix: &str| names.iter().any(|n| n.ends_with(suffix));

    // One finder is generated per variant, covering all three variant kinds.
    assert!(is_registered("fn_list_signal_find_off"));
    assert!(is_registered("fn_list_signal_find_level"));
    assert!(is_registered("fn_list_signal_find_named"));
}
