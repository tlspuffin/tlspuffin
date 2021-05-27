#[cfg(test)]
pub mod tests {
    use openssl::rand::rand_bytes;
    use crate::openssl_binding::make_deterministic;

    #[test]
    fn test_openssl_no_randomness() {
        make_deterministic();
        let mut buf1 = [0; 2];
        rand_bytes(&mut buf1).unwrap();
        assert_eq!(buf1, [70, 100]);
    }
}