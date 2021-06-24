//!  These are currently implemented by using an in-memory buffer.
//! One might ask why we want two channel There two very practical reasons
//! for thi Note that these are advantages for the implementation and are not
//! strictly required from a theoretical point of view.
//!
//! * Having two buffers resembles how networking works in reality: Each computer has an input and an
//!   output buffer. In case of TCP the input buffer can become full and therefore the transmission
//!   is throttled.
//! * It is beneficial to model each agent with two buffers according to the Single-responsibility
//!   principle. When sending or receiving data each agent only has to look at its own two buffer.
//!   If each agent had only one buffer, then you would need to read from another agent which
//! has the data you want. Or if you design it the other way around you would need to write to
//! the buffer of the agent to which you want to send data.
//!
//! The [`Agent`] Alice can add data to the *inbound channel* of Bob.
//! Bob can then read the data from his *inbound channel* and put data in his *outbound channel*.
//! If Bob is an [`Agent`], which has an underlying *OpenSSLStream* then OpenSSL may write into the
//! *outbound channel* of Bob.

use std::convert::TryFrom;
use std::{
    io,
    io::{Read, Write},
};

use openssl::ssl::SslStream;
use rustls::msgs::message::{OpaqueMessage, MessagePayload};
use rustls::msgs::handshake::HandshakePayload;
use rustls::msgs::{codec::Codec, deframer::MessageDeframer, message::Message};
use crate::agent::TLSVersion;
use crate::debug::debug_opaque_message_with_info;
use crate::error::Error;
use crate::openssl_binding;

pub trait Stream: std::io::Read + std::io::Write {
    fn add_to_inbound(&mut self, result: &MessageResult);

    /// Takes a single TLS message from the outbound channel
    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error>;
}

/// Describes in- or outbound channels of an [`crate::agent::Agent`]. Each [`crate::agent::Agent`] can send and receive data.
/// This is modeled by two separate Channels in [`MemoryStream`]. Internally a Channel is just an
/// in-memory seekable buffer.
pub type Channel = io::Cursor<Vec<u8>>;

/// A MemoryStream has two [`Channel`]s. The Stream also implements the [`Write`] and [`Read`] trait.
/// * When writing to a MemoryStream its outbound channel gets filled.
/// * When reading from a MemoryStream data is taken from the inbound channel.
///
/// This makes it possible for an [`crate::agent::Agent`] to treat a [`MemoryStream`] like a TLS socket! By writing
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
    openssl_stream: SslStream<MemoryStream>
}

impl Stream for OpenSSLStream {
    fn add_to_inbound(&mut self, result: &MessageResult) {
        self.openssl_stream.get_mut().add_to_inbound(result)
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        self.openssl_stream.get_mut().take_message_from_outbound()
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
    pub fn new(server: bool, tls_version: &TLSVersion) -> Result<Self, Error> {
        let memory_stream = MemoryStream::new();
        let openssl_stream = if server {
            //let (cert, pkey) = openssl_binding::generate_cert();
            let (cert, pkey) = openssl_binding::static_rsa_cert()?;
            openssl_binding::create_openssl_server(memory_stream, &cert, &pkey, tls_version)?
        } else {
            openssl_binding::create_openssl_client(memory_stream, tls_version)?
        };

        Ok(OpenSSLStream {
            openssl_stream
        })
    }

    pub fn describe_state(&self) -> &'static str {
        // Very useful for nonblocking according to docs:
        // https://www.openssl.org/docs/manmaster/man3/SSL_state_string.html
        // When using nonblocking sockets, the function call performing the handshake may return
        // with SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition,
        // so that SSL_state_string[_long]() may be called.
        self.openssl_stream.ssl().state_string_long()
    }

    pub fn next_state(&mut self) -> Result<(), Error> {
        let stream = &mut self.openssl_stream;
        Ok(openssl_binding::do_handshake(stream)?)
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

pub enum MessageResult {
    Message(Message),
    OpaqueMessage(OpaqueMessage),
}

impl Stream for MemoryStream {
    fn add_to_inbound(&mut self, result: &MessageResult) {
        let out: Vec<u8> = match result {
            MessageResult::Message(message) => {
                let mut out: Vec<u8> = Vec::new();
                out.append(&mut OpaqueMessage::from(message.clone()).encode());
                out
            }
            MessageResult::OpaqueMessage(opaque_message) => {
                let mut out: Vec<u8> = Vec::new();
                out.append(&mut opaque_message.clone().encode());
                out
            }
        };
        self.inbound.get_mut().extend_from_slice(&out);
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        let mut deframer = MessageDeframer::new();
        if let Ok(_) = deframer.read(&mut self.outbound.get_ref().as_slice()) {
            let mut rest_buffer: Vec<u8> = Vec::new();
            let mut frames = deframer.frames;

            let first_message = frames.pop_front();

            for message in frames {
                rest_buffer.append(&mut message.encode());
            }

            self.outbound.set_position(0);
            self.outbound.get_mut().clear();
            self.outbound.write_all(&rest_buffer).map_err(|err| {
                Error::Stream(format!("Failed to write into outbound buffer: {}", err))
            })?;

            if let Some(opaque_message) = first_message {
                debug_opaque_message_with_info(
                    format!("Processing message").as_str(),
                    &opaque_message,
                );

                Ok(Some(match Message::try_from(opaque_message.clone()) {
                    Ok(message) => {

                        match &message.payload {
                            // this check is for TLS 1.2 encrypted handshake messages,
                            // the current parser will return a Handshake of
                            // type HandshakePayload::Unknown.
                            // https://github.com/maxammann/rustls/blob/8f85f586686acf3fbd9ee8315d49a7fbcef2e127/rustls/src/msgs/handshake.rs#L2199
                            MessagePayload::Handshake(hs)  => {
                                if matches!(&hs.payload, HandshakePayload::Unknown(_)) {
                                    MessageResult::OpaqueMessage(opaque_message)
                                } else {
                                    MessageResult::Message(message)
                                }
                            }
                            _ => {
                                MessageResult::Message(message)
                            }
                        }
                    },
                    Err(err) => {
                        error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}: {}", err, hex::encode(opaque_message.clone().encode()));
                        MessageResult::OpaqueMessage(opaque_message)
                    }
                }))
            } else {
                // no message to return
                Ok(None)
            }
        } else {
            // Unable to deframe
            Err(Error::Stream("Failed to deframe bianry buffer".to_string()))
        }
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
