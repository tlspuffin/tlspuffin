//! Aligned decrypted-transcript comparison.
//!
//! The differential compares the two stacks' *decrypted* server output. The hard
//! part is that libssh and wolfSSH packetize / pipeline / number their replies
//! differently, so a positional message-by-message comparison compares unrelated
//! messages and manufactures spurious "divergences" (this is what the earlier
//! `differential_fuzzing_alignment_key` puffin hook tried to paper over).
//!
//! This module moves that alignment ENTIRELY into sshpuffin (puffin stays
//! upstream). A fold recipe (`fn_fold_s2c_transcript`) reduces a stack's whole
//! server flight — plaintext pre-NewKeys packets AND decrypted post-NewKeys
//! packets — into ONE [`AlignedTranscript`]: a `BTreeMap` keyed by a semantic
//! coordinate ([`AlignmentKey`]) rather than by wire position. The two PUTs each
//! emit exactly one such map, and puffin's default positional compare (one
//! whitelisted knowledge per side) hands the real work to the `comparable`
//! crate's **key-based** `BTreeMap` diff:
//!
//!   * a key present on both sides -> its two messages are compared for CONTENT (a genuine byte
//!     divergence in a decrypted message surfaces here — the strongest bug signal), and
//!   * a key present on ONE side only -> a presence difference (fail-closed: a security message one
//!     stack emits and the other does not is an objective, never silently dropped).
//!
//! Because alignment is by key and not by position, a benign framing difference
//! (one stack pipelines SERVICE_ACCEPT into the next packet, or picks a different
//! server channel number) no longer shifts every following message and cascades
//! into false positives: the shared messages still align on their keys, and only
//! the genuinely single-sided message stands out.
//!
//! ## What the key encodes (and why)
//!
//! [`AlignmentKey`] = `(channel, msg_number, ordinal)`:
//!   * `msg_number` — the SSH message number (RFC 4250 §4.1.2). It is intrinsic to the message
//!     *kind*, so like-with-like are compared regardless of where each stack placed the packet. The
//!     RFC number ranges also implicitly encode the protocol phase (1–19 transport, 20–49 kex,
//!     50–79 userauth, 80–127 connection), so a message can only ever align against the same kind.
//!   * `channel` — a CANONICAL channel id (order of first appearance), so the server's arbitrary
//!     channel-number choice (libssh picks 43, wolfSSH picks 0) does not misalign the per-channel
//!     replies. Non-channel messages use 0.
//!   * `ordinal` — occurrence index among messages sharing `(channel,msg_number)`, so repeated
//!     same-kind messages (e.g. two CHANNEL_DATA, or the second KEXINIT of a rekey) stay distinct
//!     and align pairwise in emission order.
//!
//! ## What this deliberately does NOT do
//!
//! * It does not PROJECT the messages onto a hand-written "security summary": the full decoded
//!   `SshMessage` is kept as the map value, so every field of every message stays under comparison
//!   (no unmodeled byte is silently dropped). The only benign noise removed is (a) the
//!   channel-number choice, handled in the key above, and (b) within-message implementation
//!   latitude, handled where it already was — `#[comparable_ignore]` / `#[comparable_synthetic]` on
//!   the message fields.
//! * It does not canonicalize *emission order* across kinds. Insert/delete-shaped divergences (the
//!   Terrapin family) surface as presence differences and are caught; pure same-set transposition
//!   is a documented follow-up refinement.

use std::collections::BTreeMap;

use comparable::Comparable;
use puffin::atom_extract_knowledge;
use puffin::codec::{Codec, Reader};
// Imports required by the `atom_extract_knowledge!` macro expansion.
use puffin::error::Error;
use puffin::protocol::{Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};

use crate::protocol::SshProtocolTypes;
use crate::ssh::message::SshMessage;

/// Semantic coordinate a decrypted message is aligned on. See the module docs for
/// the rationale of each field. `Ord` (derived, field order significant) gives the
/// deterministic `BTreeMap` iteration the `comparable` diff relies on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlignmentKey {
    /// Canonical channel id (order of first appearance); 0 for non-channel messages.
    pub channel: u32,
    /// SSH message number (RFC 4250 §4.1.2), i.e. the first byte of the encoding.
    pub msg_number: u8,
    /// Occurrence index among messages sharing `(channel, msg_number)`.
    pub ordinal: u32,
}

/// One stack's whole decrypted server transcript, keyed for semantic alignment.
///
/// Exactly one of these is emitted per PUT by `fn_fold_s2c_transcript` and is the
/// SOLE whitelisted comparison knowledge, so the two are compared 1:1 and all the
/// alignment happens inside the `comparable` `BTreeMap` diff (see module docs).
#[derive(Clone, Debug, PartialEq, Comparable)]
pub struct AlignedTranscript(pub BTreeMap<AlignmentKey, SshMessage>);

// Extract as a single atomic knowledge of its own type (do NOT recurse into the
// inner SshMessages): the whole point is that the ONE map is what gets compared.
atom_extract_knowledge!(SshProtocolTypes, AlignedTranscript);

impl AlignedTranscript {
    /// Fold an in-order message list into the keyed map: canonicalize channel
    /// numbers (order of first appearance) and assign per-`(channel,kind)`
    /// ordinals in emission order.
    pub fn from_messages(messages: Vec<SshMessage>) -> Self {
        let mut chan_canon: BTreeMap<u32, u32> = BTreeMap::new();
        let mut next_logical: u32 = 0;
        let mut occ: BTreeMap<(u32, u8), u32> = BTreeMap::new();
        let mut map: BTreeMap<AlignmentKey, SshMessage> = BTreeMap::new();

        for m in messages {
            let msg_number = ssh_msg_number(&m);
            let channel = match recipient_channel(&m) {
                Some(raw) => *chan_canon.entry(raw).or_insert_with(|| {
                    let logical = next_logical;
                    next_logical += 1;
                    logical
                }),
                None => 0,
            };
            let ordinal = {
                let e = occ.entry((channel, msg_number)).or_insert(0);
                let v = *e;
                *e += 1;
                v
            };
            map.insert(
                AlignmentKey {
                    channel,
                    msg_number,
                    ordinal,
                },
                m,
            );
        }

        AlignedTranscript(map)
    }
}

/// SSH message number = first byte of the wire encoding (RFC 4250 §4.1.2).
fn ssh_msg_number(m: &SshMessage) -> u8 {
    let mut b = Vec::with_capacity(1);
    m.encode(&mut b);
    b.first().copied().unwrap_or(0)
}

/// The `recipient_channel` a server-to-client channel message is addressed to
/// (the peer's channel id), used to canonicalize per-channel alignment. `None`
/// for non-channel messages.
fn recipient_channel(m: &SshMessage) -> Option<u32> {
    use SshMessage::*;
    match m {
        ChannelOpenConfirmation(x) => Some(x.recipient_channel),
        ChannelOpenFailure(x) => Some(x.recipient_channel),
        ChannelWindowAdjust(x) => Some(x.recipient_channel),
        ChannelData(x) => Some(x.recipient_channel),
        ChannelExtendedData(x) => Some(x.recipient_channel),
        ChannelEof(x) => Some(x.recipient_channel),
        ChannelClose(x) => Some(x.recipient_channel),
        ChannelRequest(x) => Some(x.recipient_channel),
        ChannelSuccess(x) => Some(x.recipient_channel),
        ChannelFailure(x) => Some(x.recipient_channel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use comparable::{Changed, Comparable};

    use super::*;
    use crate::ssh::message::{ChannelOpenConfirmationMessage, ServiceAcceptMessage, SshBytes};

    fn changed(a: &AlignedTranscript, b: &AlignedTranscript) -> bool {
        // Use the Comparable view (respects #[comparable_ignore]), NOT PartialEq
        // (which would also compare ignored implementation-latitude fields).
        matches!(a.comparison(b), Changed::Changed(_))
    }

    fn coc(recipient: u32, sender: u32) -> SshMessage {
        SshMessage::ChannelOpenConfirmation(ChannelOpenConfirmationMessage {
            recipient_channel: recipient,
            sender_channel: sender,
            initial_window_size: 0,
            maximum_packet_size: 0,
            channel_data: vec![],
        })
    }

    fn svc(name: &[u8]) -> SshMessage {
        SshMessage::ServiceAccept(ServiceAcceptMessage {
            service_name: SshBytes(name.to_vec()),
        })
    }

    /// Gate B (benign, must NOT fire): the concrete "libssh picks channel 43,
    /// wolfSSH picks 0" case. Same client channel (recipient), different
    /// server-chosen sender_channel — canonical keying aligns them and the ignored
    /// sender_channel makes the content equal.
    #[test]
    fn channel_number_choice_is_benign() {
        let libssh = AlignedTranscript::from_messages(vec![coc(0, 43)]);
        let wolfssh = AlignedTranscript::from_messages(vec![coc(0, 0)]);
        assert!(
            !changed(&libssh, &wolfssh),
            "the server's arbitrary sender_channel choice must not be a difference"
        );
    }

    /// Gate A (must fire): a divergence in the MEANINGFUL channel field
    /// (recipient_channel, which both servers must echo identically) surfaces even
    /// though the two confirmations canonicalize to the same logical channel.
    #[test]
    fn recipient_channel_divergence_fires() {
        let a = AlignedTranscript::from_messages(vec![coc(0, 7)]);
        let b = AlignedTranscript::from_messages(vec![coc(5, 7)]);
        assert!(
            changed(&a, &b),
            "a divergent echoed recipient_channel must surface"
        );
    }

    /// Gate A (must fire): a content byte divergence in a same-kind message
    /// (different SERVICE_ACCEPT service name).
    #[test]
    fn content_divergence_fires() {
        let a = AlignedTranscript::from_messages(vec![svc(b"ssh-userauth")]);
        let b = AlignedTranscript::from_messages(vec![svc(b"ssh-connection")]);
        assert!(changed(&a, &b), "a differing message body must surface");
    }

    /// No false positive: batching / pipelining that does not change the message
    /// SET aligns cleanly. Here both stacks emit ServiceAccept then
    /// UserAuthSuccess; identical transcripts must compare equal regardless of how
    /// they were folded.
    #[test]
    fn same_message_set_is_equal() {
        let a = AlignedTranscript::from_messages(vec![
            svc(b"ssh-userauth"),
            SshMessage::UserAuthSuccess,
        ]);
        let b = AlignedTranscript::from_messages(vec![
            svc(b"ssh-userauth"),
            SshMessage::UserAuthSuccess,
        ]);
        assert!(!changed(&a, &b));
    }

    /// Codec round-trips (needed for the type to serialize as a term output).
    #[test]
    fn codec_roundtrips() {
        let t = AlignedTranscript::from_messages(vec![
            svc(b"ssh-userauth"),
            SshMessage::UserAuthSuccess,
            coc(0, 43),
        ]);
        let mut buf = Vec::new();
        t.encode(&mut buf);
        let back = AlignedTranscript::read(&mut Reader::init(&buf)).expect("decode");
        assert_eq!(t, back);
    }
}

impl Codec for AlignedTranscript {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.0.len() as u32).encode(bytes);
        for (k, v) in &self.0 {
            k.channel.encode(bytes);
            k.msg_number.encode(bytes);
            k.ordinal.encode(bytes);
            // length-prefix each message so read() can bound its parse
            let mut mb = Vec::new();
            v.encode(&mut mb);
            (mb.len() as u32).encode(bytes);
            bytes.extend_from_slice(&mb);
        }
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let n = u32::read(reader)?;
        let mut map = BTreeMap::new();
        for _ in 0..n {
            let channel = u32::read(reader)?;
            let msg_number = u8::read(reader)?;
            let ordinal = u32::read(reader)?;
            let len = u32::read(reader)? as usize;
            let mut sub = Reader::init(reader.take(len)?);
            let msg = SshMessage::read(&mut sub)?;
            map.insert(
                AlignmentKey {
                    channel,
                    msg_number,
                    ordinal,
                },
                msg,
            );
        }
        Some(AlignedTranscript(map))
    }
}
