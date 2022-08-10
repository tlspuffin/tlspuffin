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
    io::{Read, Write},
    marker::PhantomData,
};

use log::error;

use crate::{
    codec::Codec,
    error::Error,
    protocol::{
        MessageResult, OpaqueProtocolMessage, ProtocolBehavior, ProtocolMessage,
        ProtocolMessageDeframer,
    },
};

pub trait Stream<PB: ProtocolBehavior> {
    fn add_to_inbound(&mut self, opaque_message: &PB::OpaqueProtocolMessage);

    /// Takes a single TLS message from the outbound channel
    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<PB::ProtocolMessage, PB::OpaqueProtocolMessage>>, Error>;
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
pub struct MemoryStream<PB> {
    inbound: Channel,
    outbound: Channel,
    phantom: PhantomData<PB>,
}

impl<PB: ProtocolBehavior> MemoryStream<PB> {
    pub fn new() -> Self {
        Self {
            inbound: io::Cursor::new(Vec::new()),
            outbound: io::Cursor::new(Vec::new()),
            phantom: PhantomData::default(),
        }
    }
}

impl<PB: ProtocolBehavior, E> Stream<PB> for MemoryStream<PB>
where
    PB::OpaqueProtocolMessage: TryInto<PB::ProtocolMessage, Error = E>,
    E: Into<Error>,
{
    fn add_to_inbound(&mut self, opaque_message: &PB::OpaqueProtocolMessage) {
        opaque_message.encode(self.inbound.get_mut());
    }

    // TODO: Refactor like in tcp module to avoid rest_buffer
    fn take_message_from_outbound(
        &mut self,
    ) -> Result<Option<MessageResult<PB::ProtocolMessage, PB::OpaqueProtocolMessage>>, Error> {
        let mut deframer = PB::ProtocolMessageDeframer::new();
        if deframer
            .read(&mut self.outbound.get_ref().as_slice())
            .is_ok()
        {
            let first_message = deframer.pop_frame();

            let rest_buffer: Vec<u8> = deframer.encode();

            self.outbound.set_position(0);
            self.outbound.get_mut().clear();
            self.outbound.write_all(&rest_buffer).map_err(|err| {
                Error::Stream(format!("Failed to write into outbound buffer: {}", err))
            })?;

            if let Some(opaque_message) = first_message {
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
        } else {
            // Unable to deframe
            Err(Error::Stream("Failed to deframe binary buffer".to_string()))
        }
    }
}

impl<PB: ProtocolBehavior> Read for MemoryStream<PB> {
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

impl<PB: ProtocolBehavior> Write for MemoryStream<PB> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
