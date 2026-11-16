//!
//! ```bash
//! openssl req -x509 -newkey rsa:2048 -keyout bob-key.pem -out bob.pem -days 365 -nodes
//! openssl req -x509 -newkey rsa:2048 -keyout alice-key.pem -out alice.pem -days 365 -nodes
//! openssl x509 -outform der -in bob.pem -out bob.der
//! openssl x509 -outform der -in alice.pem -out alice.der
//! openssl rsa -outform der -in bob-key.pem -out bob-key.der
//! openssl rsa -outform der -in alice-key.pem -out alice-key.der
//!
//! openssl ecparam -genkey -name prime256v1 -noout -out random-key.pem
//! openssl req -new -key random_ec_key.pem -x509 -nodes -days 365 -out random.pem
//! openssl pkcs8 -topk8 -in random-key.pem -out random-key.pkcs8 -nocrypt
//!
//! # EC (prime256v1) counterparts of Alice/Bob/Eve's RSA identities, same subject per name:
//! for name in alice bob eve; do
//!     openssl ecparam -genkey -name prime256v1 -noout -out "${name}-ec-key.pem"
//!     openssl req -new -key "${name}-ec-key.pem" -x509 -nodes -days 3650 -out "${name}-ec.pem" -subj "/CN=${name}-ec"
//!     openssl pkcs8 -topk8 -in "${name}-ec-key.pem" -outform der -out "${name}-ec-key.pkcs8.der" -nocrypt
//!     openssl x509 -outform der -in "${name}-ec.pem" -out "${name}-ec.der"
//! done
//! ```

pub type PEMDER = (&'static str, &'static [u8]);

/// Private key usually used for the server
pub const ALICE_PRIVATE_KEY: PEMDER = (
    include_str!("../assets/alice-key.pem"),
    include_bytes!("../assets/alice-key.der"),
);

/// Certificate for [`ALICE_PRIVATE_KEY`]
pub const ALICE_CERT: PEMDER = (
    include_str!("../assets/alice.pem"),
    include_bytes!("../assets/alice.der"),
);

/// EC (prime256v1) counterpart of [`ALICE_PRIVATE_KEY`] - same identity, usable where an
/// ECDSA-compatible key is required. Encoded using PKCS8.
pub const ALICE_EC_PRIVATE_KEY: PEMDER = (
    include_str!("../assets/alice-ec-key.pem"),
    include_bytes!("../assets/alice-ec-key.pkcs8.der"),
);

/// Certificate for [`ALICE_EC_PRIVATE_KEY`]
pub const ALICE_EC_CERT: PEMDER = (
    include_str!("../assets/alice-ec.pem"),
    include_bytes!("../assets/alice-ec.der"),
);

/// Private key usually used for the client
pub const BOB_PRIVATE_KEY: PEMDER = (
    include_str!("../assets/bob-key.pem"),
    include_bytes!("../assets/bob-key.der"),
);

/// Certificate for [`BOB_PRIVATE_KEY`]
pub const BOB_CERT: PEMDER = (
    include_str!("../assets/bob.pem"),
    include_bytes!("../assets/bob.der"),
);

/// EC (prime256v1) counterpart of [`BOB_PRIVATE_KEY`] - same identity, usable where an
/// ECDSA-compatible key is required. Encoded using PKCS8.
pub const BOB_EC_PRIVATE_KEY: PEMDER = (
    include_str!("../assets/bob-ec-key.pem"),
    include_bytes!("../assets/bob-ec-key.pkcs8.der"),
);

/// Certificate for [`BOB_EC_PRIVATE_KEY`]
pub const BOB_EC_CERT: PEMDER = (
    include_str!("../assets/bob-ec.pem"),
    include_bytes!("../assets/bob-ec.der"),
);

/// Private key usually which identifies the attacker. This should not be accessible by the attacker
/// though! Else the security violation gives false-positives!
pub const EVE_PRIVATE_KEY: (&str, Option<&'static [u8]>) = (
    include_str!("../assets/eve-key.pem"),
    Some(include_bytes!("../assets/eve-key.der")),
);

/// Certificate for [`EVE_PRIVATE_KEY`]
pub const EVE_CERT: PEMDER = (
    include_str!("../assets/eve.pem"),
    include_bytes!("../assets/eve.der"),
);

/// EC (prime256v1) counterpart of [`EVE_PRIVATE_KEY`] - same "should not be accessible by the
/// attacker" caveat applies; deliberately not exposed through any Mapper signing function (see
/// [`EVE_EC_CERT`] for the one that is).
pub const EVE_EC_PRIVATE_KEY: (&str, Option<&'static [u8]>) = (
    include_str!("../assets/eve-ec-key.pem"),
    Some(include_bytes!("../assets/eve-ec-key.pkcs8.der")),
);

/// Certificate for [`EVE_EC_PRIVATE_KEY`]
pub const EVE_EC_CERT: PEMDER = (
    include_str!("../assets/eve-ec.pem"),
    include_bytes!("../assets/eve-ec.der"),
);

/// Random EC (prime256v1) key with no specific use. Encoded using PKCS8.
pub const RANDOM_EC_PRIVATE_KEY_PKCS8: PEMDER = (
    include_str!("../assets/random-ec-key.pem"),
    include_bytes!("../assets/random-ec-key.pkcs8.der"),
);

/// Certificate for [`RANDOM_EC_PRIVATE_KEY_PKCS8`]
pub const RANDOM_EC_CERT: PEMDER = (
    include_str!("../assets/random-ec.pem"),
    include_bytes!("../assets/random-ec.der"),
);
