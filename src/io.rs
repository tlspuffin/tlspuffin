use std::io;
use std::io::{Read, Write};

use openssl::ssl::SslStream;

use crate::openssl_server;
#[allow(unused)] // used in docs
use crate::agent::Agent;

pub trait Stream: std::io::Read + std::io::Write {
    fn add_to_inbound(&mut self, data: &[u8]);
    fn take_from_outbound(&mut self) -> Option<Vec<u8>>;
}

/// Describes in- or outbound channels of an [`Agent`]. Each [`Agent`] can send and receive data.
/// This is modeled by two separate Channels in [`MemoryStream`]. Internally a Channel is just an
/// in-memory seekable buffer.
pub type Channel = io::Cursor<Vec<u8>>;

/// A MemoryStream has two [`Channel`]s. The Stream also implements the [`Write`] and [`Read`] trait.
/// * When writing to a MemoryStream its outbound channel gets filled.
/// * When reading from a MemoryStream data is taken from the inbound channel.
///
/// This makes it possible for an Agent to treat a [`MemoryStream`] like a TLS socket! By writing
/// to this socket you are sending data out. By reading from it you receive data.
///
/// **Note: There need to be two separate buffer! Else for example a TLS socket would read and write
/// into the same buffer**
pub struct MemoryStream {
    inbound: Channel,
    outbound: Channel,
}

/// A MemoryStream which wraps an SslStream.
pub struct OpenSSLStream {
    openssl_stream: SslStream<MemoryStream>,
    server: bool
}

impl Stream for OpenSSLStream {
    fn add_to_inbound(&mut self, data: &[u8]) {
        self.openssl_stream.get_mut().add_to_inbound(data)
    }

    fn take_from_outbound(&mut self) -> Option<Vec<u8>> {
        let openssl_stream = &mut self.openssl_stream;

        if self.server {
            openssl_server::server_accept(openssl_stream)
        } else {
            openssl_server::client_connect(openssl_stream)
        }
    }
}

impl Read for OpenSSLStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.openssl_stream.get_mut().read(buf)
    }
}

impl Write for OpenSSLStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.openssl_stream.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.openssl_stream.get_mut().flush()
    }
}

impl OpenSSLStream {
    pub fn new(server: bool) -> Self {
        let memory_stream = MemoryStream::new();
        OpenSSLStream {
            openssl_stream: if server {
                let (cert, pkey) = openssl_server::generate_cert();
                openssl_server::create_openssl_server(memory_stream, &cert, &pkey)
            } else {
                openssl_server::create_openssl_client(memory_stream)
            },
            server
        }
    }
}

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            inbound: io::Cursor::new(Vec::new()),
            outbound: io::Cursor::new(Vec::new()),
        }
    }
}

impl Stream for MemoryStream {
    fn add_to_inbound(&mut self, data: &[u8]) {
        self.inbound.get_mut().extend_from_slice(data);
    }

    fn take_from_outbound(&mut self) -> Option<Vec<u8>> {
        return Some(self.outbound.get_ref().clone()) // Copy of outbound
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inbound.read(buf)?;

        // Clear as soon as we read all data
        if self.inbound.position() == self.inbound.get_ref().len() as u64 {
            self.inbound.set_position(0);
            self.inbound.get_mut().clear();
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data available",
            ));
        }
        Ok(n)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
