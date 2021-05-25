extern "C" {
    pub fn make_openssl_deterministic();
}

pub fn make_openssl_deterministic_safe() {
    warn!("OpenSSL is no longer random!");
    unsafe {
        make_openssl_deterministic();
    }
}
