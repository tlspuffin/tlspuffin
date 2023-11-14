use crate::tls::rustls::msgs::handshake::Random;

#[derive(Debug)]
pub struct ConnectionRandoms {
    pub client: [u8; 32],
    pub server: [u8; 32],
}

/// How many ChangeCipherSpec messages we accept and drop in TLS1.3 handshakes.
/// The spec says 1, but implementations (namely the boringssl test suite) get
/// this wrong.  BoringSSL itself accepts up to 32.
static TLS13_MAX_DROPPED_CCS: u8 = 2u8;

impl ConnectionRandoms {
    pub fn new(client: Random, server: Random) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Side {
    Client,
    Server,
}

/// Data specific to the peer's side (client or server).
pub trait SideData {}
