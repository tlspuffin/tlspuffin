use crate::tls::rustls::msgs::handshake::Random;

#[derive(Debug)]
pub struct ConnectionRandoms {
    pub client: [u8; 32],
    pub server: [u8; 32],
}

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
