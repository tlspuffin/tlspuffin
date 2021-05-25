#[cfg(test)]
pub mod tests {
    use openssl::rand::rand_bytes;
    use crate::fuzzer::openssl_unsafe::make_openssl_deterministic_safe;

    #[test]
    fn test_openssl_no_randomness() {
        make_openssl_deterministic_safe();
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1).unwrap();
        assert_eq!(buf1, [103, 198]);
    }
}