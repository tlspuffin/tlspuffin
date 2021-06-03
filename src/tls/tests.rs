#[cfg(test)]
pub mod tests {
    use crate::tls::key_exchange::deterministic_key_exchange;
    use rustls::kx_group::X25519;
    use test_env_log::test;

    #[test]
    fn test_deterministic_key() {
        let a = deterministic_key_exchange(&X25519).unwrap();
        let b = deterministic_key_exchange(&X25519).unwrap();

        assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
    }
}
