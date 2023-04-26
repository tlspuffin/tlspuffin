//!  These are currently implemented by using an in-memory buffer.
//! One might ask why we want two channels. There two very practical reasons
//! for this. Note that these are advantages for the implementation and are not
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
//! If Bob is an [`Agent`], which has an underlying *PUTState* then OpenSSL may write into the
//! *outbound channel* of Bob.

use std::{
    io,
    io::{ErrorKind, Read, Write},
};

use log::error;

use crate::{
    codec::Codec,
    error::Error,
    protocol::{MessageResult, OpaqueProtocolMessage, ProtocolMessage, ProtocolMessageDeframer},
};

pub trait Stream<M: ProtocolMessage<O>, O: OpaqueProtocolMessage> {
    fn add_to_inbound(&mut self, opaque_message: &O);

    /// Takes a single TLS message from the outbound channel
    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult<M, O>>, Error>;
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
pub struct MemoryStream<D: ProtocolMessageDeframer> {
    inbound: Channel,
    outbound: Channel,
    deframer: D,
}

impl<D: ProtocolMessageDeframer> MemoryStream<D> {
    pub fn new(deframer: D) -> Self {
        Self {
            inbound: io::Cursor::new(Vec::new()),
            outbound: io::Cursor::new(Vec::new()),
            deframer,
        }
    }
}

impl<M, D: ProtocolMessageDeframer, E> Stream<M, D::OpaqueProtocolMessage> for MemoryStream<D>
where
    M: ProtocolMessage<D::OpaqueProtocolMessage>,
    D::OpaqueProtocolMessage: TryInto<M, Error = E>,
    E: Into<Error>,
    M: TryInto<M>,
{
    fn add_to_inbound(&mut self, opaque_message: &D::OpaqueProtocolMessage) {
        opaque_message.encode(self.inbound.get_mut());
    }

    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<M, D::OpaqueProtocolMessage>>, Error> {
        // Retry to read if no more frames in the deframer buffer
        let opaque_message = loop {
            if let Some(opaque_message) = self.deframer.pop_frame() {
                break Some(opaque_message);
            } else {
                match self.deframer.read(&mut self.outbound.get_ref().as_slice()) {
                    Ok(v) => {
                        self.outbound.set_position(0);
                        self.outbound.get_mut().clear();
                        if v == 0 {
                            break None;
                        }
                    }
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            // This is not a hard error. It just means we will should read again from
                            // the TCPStream in the next steps.
                            break None;
                        }
                        _ => return Err(err.into()),
                    },
                }
            }
        };

        if let Some(opaque_message) = opaque_message {
            let message = match opaque_message.clone().try_into() {
                Ok(message) => Some(message),
                Err(err) => {
                    error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}", err.into());
                    None
                }
            };

            Ok(Some(MessageResult(message, opaque_message)))
        } else {
            // no message to return
            Ok(None)
        }
    }
}

impl<D: ProtocolMessageDeframer> Read for MemoryStream<D> {
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

impl<D: ProtocolMessageDeframer> Write for MemoryStream<D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
