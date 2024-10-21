//! The communication streams between [`Agent`](crate::agent::Agent)s.
//!
//! These are currently implemented by using an in-memory buffer.
//!
//! One might ask why we want two channels. There two very practical reasons
//! for this. Note that these are advantages for the implementation and are not
//! strictly required from a theoretical point of view.
//!
//! * Having two buffers resembles how networking works in reality: Each computer has an input and
//!   an output buffer. In case of TCP the input buffer can become full and therefore the
//!   transmission is throttled.
//! * It is beneficial to model each agent with two buffers according to the Single-responsibility
//!   principle. When sending or receiving data each agent only has to look at its own two buffer.
//!   If each agent had only one buffer, then you would need to read from another agent which has
//!   the data you want. Or if you design it the other way around you would need to write to the
//!   buffer of the agent to which you want to send data.
//!
//! The [`Agent`](crate::agent::Agent) Alice can add data to the *inbound channel* of Bob.
//! Bob can then read the data from his *inbound channel* and put data in his *outbound channel*.
//! If Bob is an [`Agent`](crate::agent::Agent), which has an underlying *PUT state* then OpenSSL
//! may write into the *outbound channel* of Bob.

use std::io::{self, Read, Write};

use crate::algebra::{ConcreteMessage, Matcher};
use crate::codec::Codec;
use crate::error::Error;
use crate::protocol::{OpaqueProtocolMessage, OpaqueProtocolMessageFlight, ProtocolMessage};

pub trait Stream<
    Mt: Matcher,
    M: ProtocolMessage<Mt, O>,
    O: OpaqueProtocolMessage<Mt>,
    OF: OpaqueProtocolMessageFlight<Mt, O>,
>
{
    fn add_to_inbound(&mut self, message: &ConcreteMessage);

    /// Takes a single TLS message from the outbound channel
    fn take_message_from_outbound(&mut self) -> Result<Option<OF>, Error>;
}

/// Describes in- or outbound channels of an [`crate::agent::Agent`].
///
/// Each [`crate::agent::Agent`] can send and receive data. This is modeled by two separate Channels
/// in [`MemoryStream`]. Internally a Channel is just an in-memory seekable buffer.
pub type Channel = io::Cursor<Vec<u8>>;

/// A MemoryStream has two [`Channel`]s. The Stream also implements the [`Write`] and [`Read`]
/// trait.
/// * When writing to a MemoryStream its outbound channel gets filled.
/// * When reading from a MemoryStream data is taken from the inbound channel.
///
/// This makes it possible for an [`crate::agent::Agent`] to treat a [`MemoryStream`] like a TLS
/// socket! By writing to this socket you are sending data out. By reading from it you receive data.
///
/// **Note: There need to be two separate buffer! Else for example a TLS socket would read and write
/// into the same buffer**
#[derive(Default, Debug)]
pub struct MemoryStream {
    inbound: Channel,
    outbound: Channel,
}

impl MemoryStream {
    pub fn new() -> Self {
        Self {
            inbound: io::Cursor::new(Vec::new()),
            outbound: io::Cursor::new(Vec::new()),
        }
    }
}

impl<
        Mt: Matcher,
        M: ProtocolMessage<Mt, O>,
        O: OpaqueProtocolMessage<Mt>,
        OF: OpaqueProtocolMessageFlight<Mt, O>,
    > Stream<Mt, M, O, OF> for MemoryStream
{
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        message.encode(self.inbound.get_mut());
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<OF>, Error> {
        let flight = OF::read_bytes(self.outbound.get_ref().as_slice());
        self.outbound.set_position(0);
        self.outbound.get_mut().clear();

        Ok(flight)
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
