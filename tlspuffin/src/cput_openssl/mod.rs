use crate::protocol::TLSProtocolBehavior;
use puffin::put_registry::Factory;

pub fn new_cput_openssl_factory() -> Box<dyn Factory<TLSProtocolBehavior>> {
    panic!("not implemented")
}

#[cfg(test)]
mod tests {
    use super::new_cput_openssl_factory;

    #[test]
    fn create_cput_openssl_factory() {
        new_cput_openssl_factory();
        return;
    }
}
