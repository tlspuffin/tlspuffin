use boringssl_sys::RAND_reset_for_fuzzing;

/// Reset BoringSSL PRNG
pub fn reset_rand() {
    unsafe {
        RAND_reset_for_fuzzing();
    }
}

#[cfg(test)]
mod tests {
    use crate::boringssl::deterministic::reset_rand;
    use crate::put_registry::TLS_PUT_REGISTRY;
    use crate::tls::seeds::{create_corpus, seed_client_attacker_boring};
    use crate::tls::trace_helper::TraceHelper;
    use puffin::put::PutOptions;
    use puffin::trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext};
    use std::fmt::format;

    #[test]
    fn test_boringssl_no_randomness_full() {
        let trace = seed_client_attacker_boring.build_trace();
        let mut ctx1 = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        ctx1.set_deterministic(true);
        trace.execute(&mut ctx1);
        let mut ctx2 = TraceContext::new(&TLS_PUT_REGISTRY, PutOptions::default());
        ctx2.set_deterministic(true);
        trace.execute(&mut ctx2);

        // println!("Left: {:#?}\n", ctx1);
        // println!("Right: {:#?}\n", ctx2);
        assert_eq!(ctx1, ctx2);
    }
}
