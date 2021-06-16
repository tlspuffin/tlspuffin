use rustls::kx_group::SECP384R1;
use rustls::msgs::handshake::ClientExtension;
use test_env_log::test;

use crate::tls::fn_extensions::fn_server_name_extension;
use crate::tls::key_exchange::deterministic_key_exchange;

#[test]
fn test_deterministic_key() {
    let a = deterministic_key_exchange(&SECP384R1).unwrap();
    let b = deterministic_key_exchange(&SECP384R1).unwrap();

    assert_eq!(a.pubkey.as_ref(), b.pubkey.as_ref())
}
