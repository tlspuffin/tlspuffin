
pub type PEMDER = (&'static str, &'static [u8]);

/// Private key and certificate usually used for the client
pub const ALICE_PRIVATE_KEY_AND_CERTIFICATE: PEMDER = (
    include_str!("../assets/alice-key.pem"),
    include_bytes!("../assets/alice.der")
);

/// Private key and certificate usually used for the server
pub const BOB_PRIVATE_KEY_AND_CERTIFICATE: PEMDER = (
    include_str!("../assets/bob-key.pem"),
    include_bytes!("../assets/bob.der")
);