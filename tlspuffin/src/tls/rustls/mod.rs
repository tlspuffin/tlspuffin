pub mod anchors;
pub mod cipher;
pub mod conn;
pub mod error;
pub mod hash_hs;
pub mod key;
pub mod key_log;
pub mod kx;
pub mod limited_cache;
pub mod msgs;
pub mod rand;
pub mod record_layer;
/// Message signing interfaces and implementations.
pub mod sign;
pub mod suites;
pub mod ticketer;
pub mod tls12;
pub mod tls13;
pub mod vecbuf;
pub mod verify;
pub mod versions;
pub mod x509;

#[macro_use]
mod log {
    macro_rules! trace    ( ($($tt:tt)*) => {{}} );
    macro_rules! debug    ( ($($tt:tt)*) => {{}} );
    macro_rules! warn     ( ($($tt:tt)*) => {{}} );
    macro_rules! error    ( ($($tt:tt)*) => {{}} );
}

/// Items for use in a client.
pub mod client {
    pub mod client_conn;
}

/// Items for use in a server.
pub mod server {
    pub mod server_conn;
}

/// APIs for implementing QUIC TLS
pub mod quic;
