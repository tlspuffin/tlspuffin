use std::collections::VecDeque;
use std::io;

use puffin::codec;
use puffin::codec::Codec;
use puffin::protocol::ProtocolMessageDeframer;

use crate::protocol::SshProtocolTypes;
use crate::ssh::message::{OnWireData, RawSshMessage};

const MAX_WIRE_SIZE: usize = 35000;

/// This deframer works to reconstruct SSH messages
/// from arbitrary-sized reads, buffering as necessary.
/// The input is `read()`, the output is the `frames` deque.
pub struct SshMessageDeframer {
    /// Completed frames for output.
    pub frames: VecDeque<RawSshMessage>,

    /// Set to true if the peer is not talking SSH, but some other
    /// protocol.  The caller should abort the connection, because
    /// the deframer cannot recover.
    pub desynced: bool,

    /// A fixed-size buffer containing the currently-accumulating
    /// TLS message.
    buf: Box<[u8; MAX_WIRE_SIZE]>,

    /// What size prefix of `buf` is used.
    used: usize,
}

enum BufferContents {
    /// Contains an invalid message as a header.
    Invalid,

    /// Might contain a valid message if we receive more.
    /// Perhaps totally empty!
    Partial,

    /// Contains a valid frame as a prefix.
    Valid,
}

impl Default for SshMessageDeframer {
    fn default() -> Self {
        Self::new()
    }
}

impl SshMessageDeframer {
    pub fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            desynced: false,
            buf: Box::new([0u8; MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Read some bytes from `rd`, and add them to our internal
    /// buffer.  If this means our internal buffer contains
    /// full messages, decode them all.
    pub fn read(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        // Try to do the largest reads possible.  Note that if
        // we get a message with a length field out of range here,
        // we do a zero length read.  That looks like an EOF to
        // the next layer up, which is fine.
        debug_assert!(self.used <= MAX_WIRE_SIZE);
        let new_bytes = rd.read(&mut self.buf[self.used..])?;

        self.used += new_bytes;

        loop {
            if self.used == 0 {
                break;
            }

            match self.try_deframe_one() {
                BufferContents::Invalid => {
                    println!("ufferContents::Invalid");
                    self.desynced = true;
                    break;
                }
                BufferContents::Valid => continue,
                BufferContents::Partial => break,
            }
        }

        Ok(new_bytes)
    }

    /// Returns true if we have messages for the caller
    /// to process, either whole messages in our output
    /// queue or partial messages in our buffer.
    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || self.used > 0
    }

    /// Does our `buf` contain a full message?  It does if it is big enough to
    /// contain a header, and that header has a length which falls within `buf`.
    /// If so, deframe it and place the message onto the frames output queue.
    fn try_deframe_one(&mut self) -> BufferContents {
        // Try to decode a message off the front of buf.
        let mut rd = codec::Reader::init(&self.buf[..self.used]);

        match RawSshMessage::read(&mut rd) {
            Some(m) => {
                let used = rd.used();
                self.frames.push_back(m);
                self.buf_consume(used);
                BufferContents::Valid
            }
            None => {
                // Unparseable bytes = an ENCRYPTED (post-NewKeys) packet. To keep
                // one BPP packet per `OnWire` frame — so a packet is never split
                // across reads / OutputActions and the differential decryption
                // can compare whole messages regardless of how the peer batched
                // its socket writes — we frame by the AES-GCM plaintext length
                // prefix (RFC 5647: the 4-byte packet_length is sent in the clear
                // as AEAD associated data). On-wire size = 4 (length) + enc_len
                // (ciphertext) + 16 (GCM tag). If the buffer doesn't yet hold a
                // full packet we return `Partial` so the deframer keeps the bytes
                // and waits for more (the buffer persists across OutputActions).
                //
                // Fallback: if the length prefix is missing or implausible (e.g.
                // a non-GCM cipher where the length is encrypted, or garbage),
                // emit the whole buffer as one opaque frame as before, so we never
                // stall or buffer unboundedly.
                if self.used < 4 {
                    return BufferContents::Partial;
                }
                let enc_len = u32::from_be_bytes(self.buf[0..4].try_into().unwrap()) as usize;
                let total = 4usize.saturating_add(enc_len).saturating_add(16);
                let plausible = enc_len >= 2 && total <= MAX_WIRE_SIZE;
                if plausible && self.used < total {
                    return BufferContents::Partial; // wait for the rest of the packet
                }
                let take = if plausible { total } else { self.used };
                self.frames
                    .push_back(RawSshMessage::OnWire(OnWireData(Vec::from(
                        &self.buf[..take],
                    ))));
                self.buf_consume(take);
                BufferContents::Valid
            }
        }
    }

    #[allow(clippy::comparison_chain)]
    fn buf_consume(&mut self, taken: usize) {
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf.copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken == self.used {
            self.used = 0;
        }
    }
}

impl ProtocolMessageDeframer<SshProtocolTypes> for SshMessageDeframer {
    type OpaqueProtocolMessage = RawSshMessage;

    fn pop_frame(&mut self) -> Option<RawSshMessage> {
        self.frames.pop_front()
    }

    fn read(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.read(rd)
    }
}
