#[cfg(not(any(
    feature = "libressl",
    feature = "openssl101f",
    feature = "openssl102u",
    feature = "openssl111k",
    feature = "openssl111j",
    feature = "openssl111u",
    feature = "openssl312"
)))]
compile_error!(concat!(
    "You need to select one feature in [",
    "'libressl', ",
    "'openssl101f', ",
    "'openssl102u', ",
    "'openssl111k', ",
    "'openssl111j', ",
    "'openssl111u', ",
    "'openssl312'",
    "]"
));

#[cfg(any(
    all(feature = "libressl", feature = "openssl101f"),
    all(feature = "libressl", feature = "openssl102u"),
    all(feature = "libressl", feature = "openssl111k"),
    all(feature = "libressl", feature = "openssl111j"),
    all(feature = "libressl", feature = "openssl111u"),
    all(feature = "libressl", feature = "openssl312"),
    all(feature = "openssl101f", feature = "openssl102u"),
    all(feature = "openssl101f", feature = "openssl111k"),
    all(feature = "openssl101f", feature = "openssl111j"),
    all(feature = "openssl101f", feature = "openssl111u"),
    all(feature = "openssl101f", feature = "openssl312"),
    all(feature = "openssl102u", feature = "openssl111k"),
    all(feature = "openssl102u", feature = "openssl111j"),
    all(feature = "openssl102u", feature = "openssl111u"),
    all(feature = "openssl102u", feature = "openssl312"),
    all(feature = "openssl111k", feature = "openssl111j"),
    all(feature = "openssl111k", feature = "openssl111u"),
    all(feature = "openssl111k", feature = "openssl312"),
    all(feature = "openssl111j", feature = "openssl111u"),
    all(feature = "openssl111j", feature = "openssl312"),
    all(feature = "openssl111u", feature = "openssl312"),
))]
compile_error!(concat!(
    "Incompatible features requested. Only one of [",
    "'libressl', ",
    "'openssl101f', ",
    "'openssl102u', ",
    "'openssl111k', ",
    "'openssl111j', ",
    "'openssl111u', ",
    "'openssl312'",
    "] can be enabled at the same time."
));

#[cfg_attr(feature = "libressl", path = "libressl.rs")]
mod openssl;

pub use openssl::*;
