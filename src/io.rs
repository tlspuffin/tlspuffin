use std::io;
use std::io::{Read, Write, Cursor, Seek, SeekFrom};

use openssl::ssl::SslStream;

use crate::openssl_server;

pub trait Stream: std::io::Read + std::io::Write {
    fn send(&mut self, data: &[u8]);
    fn receive(&mut self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct MemoryStream {
    read_position: u64,
    write_position: u64,
    buffer: io::Cursor<Vec<u8>>,
}

pub struct OpenSSLStream {
    openssl_stream: SslStream<MemoryStream>,
    server: bool
}

impl Stream for OpenSSLStream {
    fn send(&mut self, data: &[u8]) {
        self.openssl_stream.get_mut().send(data)
    }

    fn receive(&mut self) -> Vec<u8> {
        let openssl_stream = &mut self.openssl_stream;

        let mut buffer: Vec<u8> = Vec::new();

        if self.server {
            buffer.extend(openssl_server::server_accept(openssl_stream).unwrap())
        } else {
            buffer.extend(openssl_server::client_connect(openssl_stream).unwrap())
        }

        buffer
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
            read_position: 0,
            write_position: 0,
            buffer: io::Cursor::new(Vec::new())
        }
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

impl Stream for MemoryStream {
    fn send(&mut self, data: &[u8]) {
        self.write(data).unwrap();
    }

    fn receive(&mut self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; self.buffer.get_ref().len() as usize];
        self.read_exact(&mut buffer).unwrap();
        return buffer;
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.set_position(self.read_position);
        let n = self.buffer.read(buf).unwrap();
        self.read_position = self.buffer.position();

        //if self.buffer.position() == self.buffer.get_ref().len() as u64 {
        //    self.buffer.set_position(0);
        //    self.buffer.get_mut().clear();
        //}
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
        self.buffer.set_position(self.write_position);
        let result = self.buffer.write(buf);
        self.write_position = self.buffer.position();
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Outgoing<'a>(pub &'a mut Vec<u8>);

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
