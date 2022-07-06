//!
//! ```bash
//! openssl req -x509 -newkey rsa:2048 -keyout bob-key.pem -out bob.pem -days 365 -nodes
//! openssl req -x509 -newkey rsa:2048 -keyout alice-key.pem -out alice.pem -days 365 -nodes
//! openssl x509 -outform der -in bob.pem -out bob.der
//! openssl x509 -outform der -in alice.pem -out alice.der
//! openssl rsa -outform der -in bob-key.pem -out bob-key.der
//! openssl rsa -outform der -in alice-key.pem -out alice-key.der
//! ```

pub const ALICE_PRIVATE_KEY: &str = include_str!("../assets/alice-key.pem");
pub const ALICE_PRIVATE_KEY_DER: &[u8] = include_bytes!("../assets/alice-key.der");

pub const ALICE_CERT: &str = include_str!("../assets/alice.pem");
pub const ALICE_CERT_DER: &[u8] = include_bytes!("../assets/alice.der");

pub const BOB_PRIVATE_KEY: &str = include_str!("../assets/bob-key.pem");
pub const BOB_PRIVATE_KEY_DER: &[u8] = include_bytes!("../assets/bob-key.der");

pub const BOB_CERT: &str = include_str!("../assets/bob.pem");
pub const BOB_CERT_DER: &[u8] = include_bytes!("../assets/bob.der");

pub const EVE_PRIVATE_KEY: &str = include_str!("../assets/eve-key.pem");
pub const EVE_PRIVATE_KEY_DER: &[u8] = include_bytes!("../assets/eve-key.der");

pub const EVE_CERT: &str = include_str!("../assets/eve.pem");
pub const EVE_CERT_DER: &[u8] = include_bytes!("../assets/eve.der");
