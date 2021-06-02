#[cfg(test)]
pub mod tests {
    use rustls::kx_group::X25519;
    use test_env_log::test;
    use crate::tls::key_exchange::deterministic_key_exchange;

    #[test]
    fn test_deterministic_key() {
        let a = deterministic_key_exchange(&X25519);
        let b = deterministic_key_exchange(&X25519);

        assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
    }
}
