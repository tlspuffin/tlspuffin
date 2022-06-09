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
    convert::TryFrom,
    io,
    io::{Read, Write},
};

use log::error;
use rustls::msgs::{
    deframer::MessageDeframer,
    message::{Message, OpaqueMessage},
};

use crate::error::Error;

pub trait Stream: Read + Write {
    fn add_to_inbound(&mut self, result: &OpaqueMessage);

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

pub struct MessageResult(pub Option<Message>, pub OpaqueMessage);

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            inbound: io::Cursor::new(Vec::new()),
            outbound: io::Cursor::new(Vec::new()),
        }
    }
}

impl Stream for MemoryStream {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        let mut out: Vec<u8> = Vec::new();
        out.append(&mut opaque_message.clone().encode());
        self.inbound.get_mut().extend_from_slice(&out);
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        let mut deframer = MessageDeframer::new();
        if deframer
            .read(&mut self.outbound.get_ref().as_slice())
            .is_ok()
        {
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
                let message = match Message::try_from(opaque_message.clone().into_plain_message()) {
                    Ok(message) => Some(message),
                    Err(err) => {
                        error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}", err);
                        None
                    }
                };

                Ok(Some(MessageResult(message, opaque_message)))
            } else {
                // no message to return
                Ok(None)
            }
        } else {
            // Unable to deframe
            Err(Error::Stream("Failed to deframe binary buffer".to_string()))
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
