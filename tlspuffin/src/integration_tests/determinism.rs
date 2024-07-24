#[test_log::test]
#[cfg(all(
    feature = "deterministic",
    feature = "boringssl-binding",
    feature = "tls13",
))]
fn test_attacker_full_det_recreate() {
    use crate::test_utils::prelude::*;
    use crate::tls::seeds::seed_client_attacker_full;

    let runner = default_runner_for(tls_registry().default().name());
    let trace = seed_client_attacker_full.build_trace();

    let ctx_1 = runner.execute(&trace);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx_2 = runner.execute(&trace);
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
