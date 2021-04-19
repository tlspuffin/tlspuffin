use std::io;
use std::io::{Read, Write};

use openssl::ssl::SslStream;

use crate::openssl_server;

pub trait Stream: std::io::Read + std::io::Write {
    fn extend_incoming(&mut self, data: &[u8]);
    fn take_outgoing(&mut self) -> Outgoing<'_>;
}

#[derive(Debug)]
pub struct MemoryStream {
    incoming: io::Cursor<Vec<u8>>,
    outgoing: Vec<u8>,
}

pub struct OpenSSLStream {
    openssl_stream: SslStream<MemoryStream>,
}

impl Stream for OpenSSLStream {
    fn extend_incoming(&mut self, data: &[u8]) {
        self.openssl_stream.get_mut().extend_incoming(data)
    }

    fn take_outgoing(&mut self) -> Outgoing<'_> {
        let openssl_stream = &mut self.openssl_stream;
        openssl_server::process(openssl_stream).unwrap()
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

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            incoming: io::Cursor::new(Vec::new()),
            outgoing: Vec::new(),
        }
    }
}

impl OpenSSLStream {
    pub fn new() -> Self {
        let (cert, pkey) = openssl_server::generate_cert();

        let memory_stream = MemoryStream::new();
        OpenSSLStream {
            openssl_stream: openssl_server::create_openssl_server(memory_stream, &cert, &pkey),
        }
    }
}

impl Stream for MemoryStream {
    fn extend_incoming(&mut self, data: &[u8]) {
        self.incoming.get_mut().extend_from_slice(data);
    }

    fn take_outgoing(&mut self) -> Outgoing<'_> {
        Outgoing(&mut self.outgoing)
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.read(buf)?;

        if self.incoming.position() == self.incoming.get_ref().len() as u64 {
            self.incoming.set_position(0);
            self.incoming.get_mut().clear();
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
        self.outgoing.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Outgoing<'a>(&'a mut Vec<u8>);

impl<'a> Drop for Outgoing<'a> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<'a> ::std::ops::Deref for Outgoing<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for Outgoing<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
