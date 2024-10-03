#[test_log::test]
#[cfg(all(
    feature = "deterministic",
    feature = "boringssl-binding",
    feature = "tls13",
))]
fn test_attacker_full_det_recreate() {
    use tlspuffin::test_utils::prelude::*;
    use tlspuffin::tls::seeds::seed_client_attacker_full;

    let runner = default_runner_for(tls_registry().default().name());
    let trace = seed_client_attacker_full.build_trace();

    let ctx_1 = runner.execute(&trace);

    for i in 0..200 {
        println!("Attempt #{i}...");
        let ctx_2 = runner.execute(&trace);
        assert_eq!(ctx_1, ctx_2);
    }
}
