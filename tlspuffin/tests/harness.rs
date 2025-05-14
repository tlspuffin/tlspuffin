use core::panic;

use puffin::algebra::dynamic_function::TypeShape;
use puffin::trace::Query;
use tlspuffin::test_utils::prelude::*;
use tlspuffin::tls::rustls::msgs::enums::NamedGroup;

#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts, filter = all(tls13))]
fn test_group_selection_secp384r1(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    trace.descriptors[0].protocol_config.groups = Some(
        String::from("P-384"), // secp384r1
    );

    let ctx_1 = runner.execute(&trace).unwrap();

    let first_group = ctx_1.find_variable(
        TypeShape::of::<NamedGroup>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_group {
        let group = term.as_any().downcast_ref::<NamedGroup>().unwrap();
        assert_eq!(
            group.get_u16(),
            24 // secp384r1
        );
    } else {
        panic!("no named group");
    }
}

#[cfg(not(feature = "wolfssl430"))]
#[apply(test_puts,  filter = tls13)]
fn test_group_selection_secp256r1(put: &str) {
    use tlspuffin::tls::seeds::seed_successful;

    let runner = default_runner_for(put);
    let mut trace = seed_successful.build_trace();

    // Test with secp256r1

    trace.descriptors[0].protocol_config.groups = Some(
        String::from("P-256"), // secp256r1
    );

    let ctx_1 = runner.execute(&trace).unwrap();

    let first_group = ctx_1.find_variable(
        TypeShape::of::<NamedGroup>(),
        &Query {
            source: None,
            matcher: None,
            counter: 0,
        },
    );

    if let Some(term) = first_group {
        let group = term.as_any().downcast_ref::<NamedGroup>().unwrap();
        assert_eq!(
            group.get_u16(),
            23 // secp256r1
        );
    } else {
        panic!("no named group");
    }
}
