

pub type PEMDER = (&'static str, &'static [u8]);

/// Private key and certificate usually used for the client
pub const ALICE_PRIVATE_KEY_AND_CERTIFICATE: PEMDER = (
    include_str!("../assets/UAExpert_key.pem"),
    include_bytes!("../assets/UAExpert.der")
);

/// Private key and certificate usually used for the server
pub const BOB_PRIVATE_KEY_AND_CERTIFICATE: PEMDER = (
    include_str!("../assets/SimulationServer@PenDuick_2048.pem"),
    include_bytes!("../assets/SimulationServer@PenDuick_2048.der")
);