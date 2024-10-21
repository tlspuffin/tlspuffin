#[test]
#[cfg(all(
    feature = "deterministic",
feature = "boringssl-binding", // only fully deterministic PUT yet, openssl has still some timestamps
    feature = "tls13",
))]
fn test_attacker_full_det_recreate() {
    // Fail without global rand reset and reseed, BEFORE tracecontext are created (at least for
    // OpenSSL)!
    use puffin::put::PutOptions;
    use puffin::trace::TraceContext;

    use crate::put_registry::tls_registry;
    use crate::tls::seeds::seed_client_attacker_full;
    use crate::tls::trace_helper::TraceHelper;

    let put_registry = tls_registry();

    put_registry.determinism_set_reseed_all_factories();

    let trace = seed_client_attacker_full.build_trace();

    let mut ctx_1 = TraceContext::new(&put_registry, PutOptions::default());
    trace.execute(&mut ctx_1);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let mut ctx_2 = TraceContext::new(&put_registry, PutOptions::default());
        trace.execute(&mut ctx_2);
        assert_eq!(ctx_1, ctx_2);
    }

    // For debugging, knowledge by knowledge:
    // let server = AgentName::mew();
    // for i in 0..7 {
    //     let app_data = term!((server, i)[None] > TypeShape::of::<OpaqueMessage>());
    //     let e_1 = app_data.evaluate(&ctx_1).unwrap();
    //     println!("[{i}] Enc{i} OpaqueMessage: {:?}", e_1);
    //     if let Some(msg_1) = e_1
    //         .as_ref()
    //         .downcast_ref::<<TLSProtocolBehavior as ProtocolBehavior>::OpaqueProtocolMessage>(
    //         ) {
    //         let data_1 = msg_1.clone().encode();
    //         println!(
    //             "    Enc{i} OpaqueMessage data length/data in ctx3: {} / {:?}",
    //             data_1.len(),
    //             data_1
    //         );
    //         let e_2 = app_data.evaluate(&ctx_2).unwrap();
    //         if let Some(msg_2) = e_2.as_ref().downcast_ref::<<TLSProtocolBehavior as
    // ProtocolBehavior>::OpaqueProtocolMessage>() {             let data_2 =
    // msg_2.clone().encode();             assert_eq!(data_1, data_2);
    //         } else {
    //             panic!("Failed to encode enc{i} OpaqueMessage in ctx_2");
    //         }
    //     } else {
    //         panic!("Failed to encode enc{i} OpaqueMessage in ctx_1");
    //     }
    // }
}
