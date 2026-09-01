//! fn_crypto.rs — DY mapper functions for SSH key exchange cryptography.
//!
//! Implements curve25519-sha256 ECDH, RFC 4253 key derivation, and
//! ChaCha20-Poly1305@openssh.com packet encryption using pure Rust crates.
//! All values are returned as DY terms the fuzzer can extract, mutate and
//! compose.

#![allow(clippy::ptr_arg)]

use puffin::algebra::error::FnError;
use puffin::codec::Codec;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::claim::SshClaimInner;
use crate::protocol::{RawSshMessageFlight, SshMessageFlight};
use crate::ssh::message::{
    ExchangeHash, KexEcdhReplyMessage, OnWireData, RawSshMessage, SessionId, SharedSecret,
    SshBytes, SshMessage, SshPublicKey, SshSignature,
};
use crate::ssh::transcript::AlignedTranscript;

// ── Deterministic client ECDH seed ───────────────────────────────────────────
//
// Fixed 32-byte seed so the fuzzer can construct the exchange hash from terms
// without any hidden RNG state.

const CLIENT_ECDH_SEED: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
];

// ── ECDH ─────────────────────────────────────────────────────────────────────

/// Fixed X25519 private key (seed) for the DY fuzzer's client role.
pub fn fn_client_ecdh_privkey() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(CLIENT_ECDH_SEED.to_vec()))
}

/// X25519 public key corresponding to `fn_client_ecdh_privkey`.
pub fn fn_client_ecdh_pubkey() -> Result<SshBytes, FnError> {
    let sk = StaticSecret::from(CLIENT_ECDH_SEED);
    let pk = PublicKey::from(&sk);
    Ok(SshBytes::new(pk.as_bytes().to_vec()))
}

/// X25519 Diffie-Hellman: ECDH(priv, peer_pub) → 32 raw bytes.
///
/// The output is in the same byte order that OpenSSL's EVP_PKEY_derive
/// returns (and that libssh passes to `bignum_bin2bn` treating it as
/// big-endian), so it can be fed directly into `fn_kex_exchange_hash`.
pub fn fn_ecdh_shared_secret(
    priv_key: &SshBytes,
    peer_pub: &SshBytes,
) -> Result<SharedSecret, FnError> {
    if priv_key.0.len() != 32 {
        return Err(FnError::Malformed("private key must be 32 bytes".into()));
    }
    if peer_pub.0.len() != 32 {
        return Err(FnError::Malformed(
            "peer public key must be 32 bytes".into(),
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&priv_key.0);
    let sk = StaticSecret::from(seed);

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&peer_pub.0);
    let pk = PublicKey::from(pub_bytes);

    let shared = sk.diffie_hellman(&pk);
    Ok(SharedSecret::new(shared.as_bytes().to_vec()))
}

// ── Message extraction helpers ────────────────────────────────────────────────

/// Extract the banner identification string without the trailing `\r\n`.
pub fn fn_banner_id(raw: &RawSshMessage) -> Result<SshBytes, FnError> {
    match raw {
        RawSshMessage::Banner(s) => {
            let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
            Ok(SshBytes::new(trimmed.as_bytes().to_vec()))
        }
        _ => Err(FnError::Malformed("Expected RawSshMessage::Banner".into())),
    }
}

/// Encode a `KexInit` message to its SSH wire payload (type byte 20 + fields).
/// This matches what libssh stores in its internal `in_hashbuf` / `out_hashbuf`.
pub fn fn_kexinit_payload(msg: &SshMessage) -> Result<SshBytes, FnError> {
    match msg {
        SshMessage::KexInit(_) => Ok(SshBytes::new(msg.get_encoding())),
        _ => Err(FnError::Malformed("Expected SshMessage::KexInit".into())),
    }
}

/// Extract the server's ephemeral X25519 public key (Q_S) from a KexEcdhReply.
pub fn fn_server_ecdh_pubkey(msg: &SshMessage) -> Result<SshBytes, FnError> {
    match msg {
        SshMessage::KexEcdhReply(KexEcdhReplyMessage {
            ephemeral_public_key,
            ..
        }) => Ok(ephemeral_public_key.clone()),
        _ => Err(FnError::Malformed(
            "Expected SshMessage::KexEcdhReply".into(),
        )),
    }
}

/// Extract the server's host public key (K_S) from a KexEcdhReply.
pub fn fn_server_hostkey(msg: &SshMessage) -> Result<SshPublicKey, FnError> {
    match msg {
        SshMessage::KexEcdhReply(KexEcdhReplyMessage {
            public_host_key, ..
        }) => Ok(public_host_key.clone()),
        _ => Err(FnError::Malformed(
            "Expected SshMessage::KexEcdhReply".into(),
        )),
    }
}

/// Extract the raw K_S wire bytes from a KexEcdhReply `RawSshMessage::Packet`.
///
/// K_S is an SSH outer string (`[u32 len][inner blob]`) where the inner blob
/// contains `[string algo][key material...]`.  This function returns the full
/// outer-string bytes (length prefix included), which is what libssh appends
/// verbatim to the exchange hash buffer.
pub fn fn_server_hostkey_raw(raw: &RawSshMessage) -> Result<SshBytes, FnError> {
    use puffin::codec::Reader;

    match raw {
        RawSshMessage::Packet(packet) => {
            let payload = packet.payload();
            // payload[0] = message type (31 = SSH_MSG_KEX_ECDH_REPLY)
            if payload.is_empty() || payload[0] != 31 {
                return Err(FnError::Malformed(
                    "Expected KexEcdhReply packet (type 31)".into(),
                ));
            }
            let mut reader = Reader::init(&payload[1..]); // skip type byte
            let ks_len = u32::read(&mut reader)
                .ok_or_else(|| FnError::Malformed("Failed to read K_S length".into()))?
                as usize;
            // The K_S outer string starts at payload[1] and spans 4 + ks_len bytes.
            let raw_start = 1usize;
            if raw_start + 4 + ks_len > payload.len() {
                return Err(FnError::Malformed("K_S truncated in KexEcdhReply".into()));
            }
            Ok(SshBytes::new(
                payload[raw_start..raw_start + 4 + ks_len].to_vec(),
            ))
        }
        _ => Err(FnError::Malformed(
            "Expected RawSshMessage::Packet for KexEcdhReply".into(),
        )),
    }
}

// ── Exchange hash ─────────────────────────────────────────────────────────────

/// Encode bytes as an SSH string: `[u32 BE length][data]`.
fn push_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode the X25519 shared secret as an SSH mpint (RFC 4251 §5).
///
/// The 32-byte output from x25519-dalek is in the same format as OpenSSL's
/// EVP_PKEY_derive output.  libssh passes this directly to `bignum_bin2bn`
/// which interprets it as big-endian, so we do the same: strip leading
/// zeros (big-endian perspective), prepend 0x00 if the high bit is set, then
/// prepend the 4-byte BE length.
fn to_mpint(raw: &[u8]) -> Vec<u8> {
    let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
    let stripped = &raw[start..];

    let mut data = Vec::with_capacity(stripped.len() + 1);
    if !stripped.is_empty() && (stripped[0] & 0x80) != 0 {
        data.push(0x00);
    }
    data.extend_from_slice(stripped);

    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&data);
    out
}

/// Compute the SSH exchange hash for `curve25519-sha256`:
///
/// ```text
/// H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
/// ```
///
/// * `v_c` — client banner WITHOUT `\r\n` (use `fn_banner_id`)
/// * `v_s` — server banner WITHOUT `\r\n`
/// * `i_c` — client kexinit payload (type byte + fields; use `fn_kexinit_payload`)
/// * `i_s` — server kexinit payload
/// * `k_s` — server host key as raw SSH outer-string bytes (use `fn_server_hostkey_raw` OR
///   `fn_server_rsa_pubkey_bytes` for the server-attacker seed)
/// * `q_c` — client ephemeral X25519 public key (32 bytes)
/// * `q_s` — server ephemeral X25519 public key (32 bytes)
/// * `shared_secret` — 32-byte output of `fn_ecdh_shared_secret`
pub fn fn_kex_exchange_hash(
    v_c: &SshBytes,
    v_s: &SshBytes,
    i_c: &SshBytes,
    i_s: &SshBytes,
    k_s: &SshBytes, // raw outer SSH-string bytes (includes 4-byte length prefix)
    q_c: &SshBytes,
    q_s: &SshBytes,
    shared_secret: &SharedSecret,
) -> Result<ExchangeHash, FnError> {
    let mut buf = Vec::new();

    push_ssh_string(&mut buf, &v_c.0); // V_C
    push_ssh_string(&mut buf, &v_s.0); // V_S
    push_ssh_string(&mut buf, &i_c.0); // I_C
    push_ssh_string(&mut buf, &i_s.0); // I_S
    buf.extend_from_slice(&k_s.0); // K_S (already outer-string encoded)
    push_ssh_string(&mut buf, &q_c.0); // Q_C
    push_ssh_string(&mut buf, &q_s.0); // Q_S
    buf.extend_from_slice(&to_mpint(&shared_secret.0)); // K

    let hash = Sha256::digest(&buf);
    Ok(ExchangeHash::new(hash.to_vec()))
}

/// Derive the SESSION ID from an exchange hash.
///
/// On the first key exchange the session id equals the exchange hash H (RFC 4253
/// §7.2), so this is a byte-for-byte copy. But the two are semantically distinct
/// and this conversion is EXPLICIT so the DY fuzzer can express the confusion: the
/// session id MUST stay the first H for the whole connection, whereas H changes on
/// every rekey. Feeding the NEW (rekey) `ExchangeHash` here yields a wrong-but-
/// well-typed `SessionId` — the session-id-confusion / Terrapin-shaped mutation,
/// now reachable in a single typed step.
pub fn fn_session_id_from_hash(h: &ExchangeHash) -> Result<SessionId, FnError> {
    Ok(SessionId::new(h.0.clone()))
}

/// Exchange hash H sourced from the server's completion CLAIM (its SSH session
/// id) instead of reconstructed from the wire. The PUT computed H from the
/// KEXINIT it ACTUALLY negotiated, so this is correct for every seed — including
/// ext_info (curve25519 + ext-info-c), whose KEXINIT differs from the plain
/// AES-GCM offer — and, crucially, it stays correct under negotiation/downgrade
/// mutation, where a hard-coded reconstructed `I_C` would desync from the mutated
/// KEXINIT and silently break s2c decryption. `session_id` is the first-KEX H
/// (== session id, RFC 4253 §7.2), exactly what the auth-complete s2c key
/// schedule needs. An empty `session_id` (PUT not built with claimer
/// instrumentation, so no H is exposed) is an error, so the fold fails loudly
/// rather than decrypting with a wrong key and producing garbage.
///
/// The argument is `&Box<SshClaimInner>` (not `&SshClaimInner`) ON PURPOSE: a
/// decryption-recipe `Variable` resolves against a claim via
/// `TraceContext::find_claim`, which matches on `SshClaim::id()` and yields
/// `SshClaim::inner()` — both of which are `Box<SshClaimInner>` (the registered
/// `EvaluatedTerm` type). The DY function's parameter type must equal that
/// concrete type exactly or the term fails its type-shape check. Hence the box.
#[allow(clippy::borrowed_box)]
pub fn fn_claim_exchange_hash(claim: &Box<SshClaimInner>) -> Result<ExchangeHash, FnError> {
    if claim.session_id.is_empty() {
        return Err(FnError::Malformed(
            "claim carries no session_id (PUT not built with claimer instrumentation?)".into(),
        ));
    }
    Ok(ExchangeHash::new(claim.session_id.clone()))
}

// ── Key derivation (RFC 4253 §7) ─────────────────────────────────────────────

// Takes raw byte slices (not the role newtypes) so every caller — AES-GCM, CTR,
// MAC, ChaCha — passes its own `.0` and the derived bytes are identical to before
// the type-directed refactor.
fn derive_key(shared: &[u8], h: &[u8], sid: &[u8], id: u8, needed: usize) -> SshBytes {
    let k_mpint = to_mpint(shared);

    // K1 = SHA-256(K || H || id || session_id)
    let k1: Vec<u8> = Sha256::new()
        .chain_update(&k_mpint)
        .chain_update(h)
        .chain_update([id])
        .chain_update(sid)
        .finalize()
        .to_vec();

    if needed <= 32 {
        return SshBytes::new(k1[..needed].to_vec());
    }

    let mut out = k1;
    while out.len() < needed {
        let kn: Vec<u8> = Sha256::new()
            .chain_update(&k_mpint)
            .chain_update(h)
            .chain_update(&out)
            .finalize()
            .to_vec();
        out.extend_from_slice(&kn);
    }
    out.truncate(needed);
    SshBytes::new(out)
}

/// Client-to-server encryption key (id = `'C'`), 64 bytes for ChaCha20-Poly1305.
pub fn fn_derive_enc_key_c2s(
    shared: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&shared.0, &h.0, &sid.0, b'C', 64))
}

/// Server-to-client encryption key (id = `'D'`), 64 bytes for ChaCha20-Poly1305.
pub fn fn_derive_enc_key_s2c(
    shared: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&shared.0, &h.0, &sid.0, b'D', 64))
}

// ── AES-256-GCM key/IV derivation (RFC 5647) ─────────────────────────────────
//
// aes256-gcm@openssh.com uses a 32-byte encryption key (id 'C'/'D') and a
// 12-byte initial IV (id 'A'/'B'). The IV is fixed_salt(4) || invocation
// counter(8); the counter starts at the derived value and increments per packet.

/// Client-to-server AES-256-GCM key (id `'C'`, 32 bytes).
pub fn fn_derive_aes_key_c2s(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'C', 32))
}
/// Server-to-client AES-256-GCM key (id `'D'`, 32 bytes).
pub fn fn_derive_aes_key_s2c(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'D', 32))
}
/// Client-to-server initial IV (id `'A'`, 12 bytes).
pub fn fn_derive_iv_c2s(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'A', 12))
}
/// Server-to-client initial IV (id `'B'`, 12 bytes).
pub fn fn_derive_iv_s2c(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'B', 12))
}

// ── AES-256-GCM packet encryption (aes256-gcm@openssh.com, RFC 5647) ──────────
//
// Wire format: [uint32 packet_length (cleartext, used as AAD)]
//              [AES-GCM ciphertext of: padding_length(1) || payload || padding]
//              [16-byte GCM tag]
// The encrypted plaintext length (1 + payload + padding) MUST be a multiple of
// 16 (the AES block size); the 4-byte length field is NOT counted. Nonce =
// iv[0..4] || be64(be64(iv[4..12]) + invocation_counter).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

fn aesgcm_nonce(iv: &[u8], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&iv[0..4]);
    let base = u64::from_be_bytes(iv[4..12].try_into().unwrap());
    nonce[4..12].copy_from_slice(&base.wrapping_add(counter).to_be_bytes());
    nonce
}

/// Encrypt one SSH message as an aes256-gcm@openssh.com binary packet.
/// `iv` is the 12-byte initial IV; `counter` is the per-direction packet index
/// since NewKeys (0 for the first encrypted packet). Returns `RawSshMessage::OnWire`.
pub fn fn_encrypt_packet_aesgcm(
    msg: &SshMessage,
    key: &SshBytes,
    iv: &SshBytes,
    counter: &u32,
) -> Result<RawSshMessage, FnError> {
    if key.0.len() != 32 {
        return Err(FnError::Malformed("AES-GCM key must be 32 bytes".into()));
    }
    if iv.0.len() != 12 {
        return Err(FnError::Malformed("AES-GCM IV must be 12 bytes".into()));
    }

    let plaintext = msg.get_encoding();
    // (1 + payload + pad) % 16 == 0, pad >= 4
    let block = 16usize;
    let unpadded = 1 + plaintext.len();
    let mut pad = block - (unpadded % block);
    if pad < 4 {
        pad += block;
    }
    let enc_len = 1 + plaintext.len() + pad; // length field value (== plaintext to encrypt)

    let mut pt = Vec::with_capacity(enc_len);
    pt.push(pad as u8);
    pt.extend_from_slice(&plaintext);
    pt.resize(enc_len, 0u8);

    let nonce = aesgcm_nonce(&iv.0, *counter as u64);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key.0));
    let len_be = (enc_len as u32).to_be_bytes();
    let ct = cipher
        .encrypt(
            AesNonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &len_be,
            },
        )
        .map_err(|_| FnError::Malformed("AES-GCM encryption failed".into()))?;
    // ct = ciphertext || 16-byte tag (the aes-gcm crate appends the tag)

    let mut out = Vec::with_capacity(4 + ct.len());
    out.extend_from_slice(&len_be);
    out.extend_from_slice(&ct);
    Ok(RawSshMessage::OnWire(OnWireData(out)))
}

/// Decrypt an aes256-gcm@openssh.com packet back into an `SshMessage`.
pub fn fn_decrypt_packet_aesgcm(
    data: &OnWireData,
    key: &SshBytes,
    iv: &SshBytes,
    counter: &u32,
) -> Result<SshMessage, FnError> {
    use puffin::codec::Reader;

    if key.0.len() != 32 || iv.0.len() != 12 {
        return Err(FnError::Malformed("AES-GCM key/IV size".into()));
    }
    let wire = &data.0;
    if wire.len() < 4 + 16 {
        return Err(FnError::Malformed("packet too short".into()));
    }
    let len_be: [u8; 4] = wire[0..4].try_into().unwrap();
    let enc_len = u32::from_be_bytes(len_be) as usize;
    if wire.len() < 4 + enc_len + 16 {
        return Err(FnError::Malformed("declared length exceeds packet".into()));
    }
    let ct_and_tag = &wire[4..4 + enc_len + 16];

    let nonce = aesgcm_nonce(&iv.0, *counter as u64);
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key.0));
    let pt = cipher
        .decrypt(
            AesNonce::from_slice(&nonce),
            Payload {
                msg: ct_and_tag,
                aad: &len_be,
            },
        )
        .map_err(|_| FnError::Malformed("AES-GCM tag mismatch".into()))?;

    if pt.is_empty() {
        return Err(FnError::Malformed("empty plaintext".into()));
    }
    let pad = pt[0] as usize;
    if 1 + pad > pt.len() {
        return Err(FnError::Malformed("invalid padding".into()));
    }
    let payload = &pt[1..pt.len() - pad];
    let mut reader = Reader::init(payload);
    SshMessage::read(&mut reader)
        .ok_or_else(|| FnError::Malformed("failed to parse decrypted SshMessage".into()))
}

/// Concatenate two raw s2c flights (drains) into one. Puffin captures the
/// server's output as a separate `RawSshMessageFlight` after every input step,
/// so a single logical message sequence is spread across many drains. Chaining
/// this lets a recipe merge all drains into ONE flight and decrypt the whole
/// post-NewKeys s2c stream from counter 0 in a single peel — recovering every
/// encrypted packet regardless of how the peer batched them across drains. This
/// removes the under-decoding that a per-drain, fixed-counter-window recipe
/// suffers (which could miss e.g. a rekey KEXINIT and manufacture a spurious
/// presence divergence).
pub fn fn_concat_raw_flights(
    a: &RawSshMessageFlight,
    b: &RawSshMessageFlight,
) -> Result<RawSshMessageFlight, FnError> {
    let mut messages = Vec::with_capacity(a.messages.len() + b.messages.len());
    messages.extend_from_slice(&a.messages);
    messages.extend_from_slice(&b.messages);
    Ok(RawSshMessageFlight { messages })
}

/// Decrypt an ENTIRE AES-256-GCM s2c FLIGHT into a flight of messages.
///
/// This mirrors the TLS `fn_decrypt_handshake_flight`: it takes the whole
/// `RawSshMessageFlight` a server produced (one OutputAction's worth of raw
/// output) and recovers ALL its plaintext messages, independent of how the peer
/// framed them. The server's post-NewKeys output is opaque `OnWire` chunks, and
/// two implementations chop the same message sequence into chunks/socket-writes
/// differently (libssh batches, wolfSSH does not). We therefore CONCATENATE every
/// `OnWire` chunk in the flight into one byte stream and peel BPP packets off it
/// one at a time, decrypting each with a consecutive GCM counter starting at
/// `start_counter` (the s2c sequence number of the flight's first packet, which
/// resets to 0 at NewKeys). The recovered message sequence is thus independent of
/// the peer's chunking — the SSH analogue of "decrypt(flight) == flight of
/// decrypt(packet)". If the FIRST packet fails its tag the whole flight errors
/// (wrong `start_counter` guess, skipped by the engine); a later failure stops
/// the peel and returns the successfully decrypted prefix.
pub fn fn_decrypt_flight_aesgcm(
    flight: &RawSshMessageFlight,
    key: &SshBytes,
    iv: &SshBytes,
    start_counter: &u32,
) -> Result<SshMessageFlight, FnError> {
    use puffin::codec::Reader;

    if key.0.len() != 32 || iv.0.len() != 12 {
        return Err(FnError::Malformed("AES-GCM key/IV size".into()));
    }

    // Concatenate every opaque OnWire chunk in the flight into one ciphertext
    // stream, so packets that the peer split across chunks/writes are recovered.
    let mut wire: Vec<u8> = Vec::new();
    for m in &flight.messages {
        if let RawSshMessage::OnWire(od) = m {
            wire.extend_from_slice(&od.0);
        }
    }

    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key.0));
    let mut messages = Vec::new();
    let mut off = 0usize;
    let mut counter = *start_counter;

    while off + 4 + 16 <= wire.len() {
        let len_be: [u8; 4] = wire[off..off + 4].try_into().unwrap();
        let enc_len = u32::from_be_bytes(len_be) as usize;
        if off + 4 + enc_len + 16 > wire.len() {
            break; // truncated / not a packet boundary
        }
        let ct_and_tag = &wire[off + 4..off + 4 + enc_len + 16];
        let nonce = aesgcm_nonce(&iv.0, counter as u64);
        let pt = match cipher.decrypt(
            AesNonce::from_slice(&nonce),
            Payload {
                msg: ct_and_tag,
                aad: &len_be,
            },
        ) {
            Ok(pt) => pt,
            Err(_) => {
                if messages.is_empty() {
                    return Err(FnError::Malformed("AES-GCM tag mismatch".into()));
                }
                break;
            }
        };
        if !pt.is_empty() {
            let pad = pt[0] as usize;
            if 1 + pad <= pt.len() {
                let payload = &pt[1..pt.len() - pad];
                if let Some(msg) = SshMessage::read(&mut Reader::init(payload)) {
                    messages.push(msg);
                }
            }
        }
        off += 4 + enc_len + 16;
        counter += 1;
    }

    if messages.is_empty() {
        return Err(FnError::Malformed("no packet decrypted in flight".into()));
    }
    Ok(SshMessageFlight { messages })
}

/// Fold an ENTIRE server flight into one [`AlignedTranscript`] for differential
/// comparison.
///
/// This is the single comparison recipe of the AES-GCM decryption differential
/// (it replaces the per-message decryption recipes + the puffin `alignment_key`
/// bucketing hook). It recovers the server's *whole* transcript, plaintext and
/// encrypted alike, in emission order:
///
///   * `RawSshMessage::Packet` — the pre-NewKeys plaintext packets (KEXINIT,
///     KEX_ECDH_REPLY, NEWKEYS). Parsed directly; carries the negotiation /
///     downgrade signal.
///   * `RawSshMessage::OnWire` — the post-NewKeys AES-256-GCM ciphertext. Every
///     opaque chunk in the flight is concatenated and peeled packet-by-packet
///     from GCM counter 0 (which is where the s2c sequence resets at NewKeys), so
///     capture is independent of how the peer batched its socket writes.
///
/// The recovered in-order message list is then folded into the key-aligned map
/// (see [`AlignedTranscript::from_messages`]). Decryption is BEST-EFFORT: the
/// plaintext prefix is always captured even if the key/IV are wrong (e.g. a
/// mutated handshake), and GCM peeling stops at the first packet that fails its
/// tag, keeping whatever decrypted cleanly. Only a completely empty transcript is
/// an error (so the term is skipped by the differential engine).
pub fn fn_fold_s2c_transcript(
    flight: &RawSshMessageFlight,
    key: &SshBytes,
    iv: &SshBytes,
) -> Result<AlignedTranscript, FnError> {
    use puffin::codec::Reader;

    let mut messages: Vec<SshMessage> = Vec::new();
    let mut wire: Vec<u8> = Vec::new();
    for m in &flight.messages {
        match m {
            // Pre-NewKeys plaintext packet: parse directly (key-independent).
            RawSshMessage::Packet(bp) => {
                if let Ok(msg) = SshMessage::try_from(bp) {
                    messages.push(msg);
                }
            }
            // Post-NewKeys ciphertext: accumulate for one GCM peel below.
            RawSshMessage::OnWire(od) => wire.extend_from_slice(&od.0),
            RawSshMessage::Banner(_) => {}
        }
    }

    // Peel the encrypted stream from counter 0, best-effort. A wrong key/IV or a
    // truncated packet just stops the peel; the plaintext prefix already gathered
    // above is kept, so the negotiation signal never depends on decryption.
    if key.0.len() == 32 && iv.0.len() == 12 && !wire.is_empty() {
        let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(&key.0));
        let mut off = 0usize;
        let mut counter = 0u64;
        while off + 4 + 16 <= wire.len() {
            let len_be: [u8; 4] = wire[off..off + 4].try_into().unwrap();
            let enc_len = u32::from_be_bytes(len_be) as usize;
            if off + 4 + enc_len + 16 > wire.len() {
                break; // truncated / not a packet boundary
            }
            let ct_and_tag = &wire[off + 4..off + 4 + enc_len + 16];
            let nonce = aesgcm_nonce(&iv.0, counter);
            match cipher.decrypt(
                AesNonce::from_slice(&nonce),
                Payload {
                    msg: ct_and_tag,
                    aad: &len_be,
                },
            ) {
                Ok(pt) => {
                    if !pt.is_empty() {
                        let pad = pt[0] as usize;
                        if 1 + pad <= pt.len() {
                            let payload = &pt[1..pt.len() - pad];
                            if let Some(msg) = SshMessage::read(&mut Reader::init(payload)) {
                                messages.push(msg);
                            }
                        }
                    }
                }
                Err(_) => break,
            }
            off += 4 + enc_len + 16;
            counter += 1;
        }
    }

    if messages.is_empty() {
        return Err(FnError::Malformed("empty s2c transcript".into()));
    }
    Ok(AlignedTranscript::from_messages(messages))
}

// ── AES-256-CTR + HMAC-SHA2-256 (RFC 4253 §6, Encrypt-and-MAC) ────────────────
//
// The classic non-AEAD SSH suite, supported by both libssh and wolfSSH. Unlike
// the AEAD ciphers, this exercises the separate-cipher + separate-MAC code path:
//   * AES-256-CTR over the WHOLE cleartext packet (the 4-byte length field is encrypted too), with
//     a 128-bit big-endian counter that starts at the IV and increments per 16-byte block,
//     continuously across packets.
//   * HMAC-SHA-256 computed over (uint32 sequence_number || cleartext packet), appended after the
//     ciphertext (Encrypt-and-MAC).
//
// Key material (RFC 4253 §7.2): IV id 'A'/'B' (16 B), enc key 'C'/'D' (32 B),
// integrity/MAC key 'E'/'F' (32 B).

use aes::Aes256;
use hmac::{Hmac, Mac};
// AES-CTR uses the same `cipher` crate traits (KeyIvInit / StreamCipher /
// StreamCipherSeek) that the ChaCha20 section imports below from
// `chacha20::cipher`; they are re-exports of the same crate, so we reuse them
// rather than importing aliases (which would make the trait methods ambiguous).

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Client-to-server AES-CTR encryption key (id `'C'`, 32 bytes).
pub fn fn_derive_ctr_key_c2s(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'C', 32))
}
/// Server-to-client AES-CTR encryption key (id `'D'`, 32 bytes).
pub fn fn_derive_ctr_key_s2c(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'D', 32))
}
/// Client-to-server AES-CTR initial counter / IV (id `'A'`, 16 bytes).
pub fn fn_derive_ctr_iv_c2s(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'A', 16))
}
/// Server-to-client AES-CTR initial counter / IV (id `'B'`, 16 bytes).
pub fn fn_derive_ctr_iv_s2c(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'B', 16))
}
/// Client-to-server HMAC integrity key (id `'E'`, 32 bytes for hmac-sha2-256).
pub fn fn_derive_mac_key_c2s(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'E', 32))
}
/// Server-to-client HMAC integrity key (id `'F'`, 32 bytes for hmac-sha2-256).
pub fn fn_derive_mac_key_s2c(
    s: &SharedSecret,
    h: &ExchangeHash,
    sid: &SessionId,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(&s.0, &h.0, &sid.0, b'F', 32))
}

/// Encrypt one SSH message as an aes256-ctr + hmac-sha2-256 binary packet.
/// `block_offset` = number of 16-byte cipher blocks already consumed on this
/// direction since NewKeys (0 for the first encrypted packet); `seqno` = the
/// packet's SSH sequence number (counts every packet since the start, so the
/// first post-NewKeys packet is usually 3). Returns `RawSshMessage::OnWire`.
pub fn fn_encrypt_packet_ctr(
    msg: &SshMessage,
    enc_key: &SshBytes,
    iv: &SshBytes,
    mac_key: &SshBytes,
    block_offset: &u32,
    seqno: &u32,
) -> Result<RawSshMessage, FnError> {
    if enc_key.0.len() != 32 {
        return Err(FnError::Malformed("AES-CTR key must be 32 bytes".into()));
    }
    if iv.0.len() != 16 {
        return Err(FnError::Malformed("AES-CTR IV must be 16 bytes".into()));
    }

    let plaintext = msg.get_encoding();
    // (length_field(4) + padlen(1) + payload + pad) % 16 == 0, pad >= 4
    let block = 16usize;
    let unpadded = 4 + 1 + plaintext.len();
    let mut pad = block - (unpadded % block);
    if pad < 4 {
        pad += block;
    }
    let packet_len = 1 + plaintext.len() + pad; // value of the length field

    let mut clear = Vec::with_capacity(4 + packet_len);
    clear.extend_from_slice(&(packet_len as u32).to_be_bytes());
    clear.push(pad as u8);
    clear.extend_from_slice(&plaintext);
    clear.resize(4 + packet_len, 0u8);

    // AES-256-CTR over the whole cleartext, starting at the right block.
    let mut ct = clear.clone();
    let mut cipher = Aes256Ctr::new_from_slices(&enc_key.0, &iv.0)
        .map_err(|_| FnError::Malformed("AES-CTR init failed".into()))?;
    cipher.seek((*block_offset as u64) * block as u64);
    cipher.apply_keystream(&mut ct);

    // HMAC-SHA-256(mac_key, seqno || cleartext) appended after the ciphertext.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key.0)
        .map_err(|_| FnError::Malformed("HMAC key error".into()))?;
    mac.update(&seqno.to_be_bytes());
    mac.update(&clear);
    let tag = mac.finalize().into_bytes();

    let mut out = ct;
    out.extend_from_slice(&tag);
    Ok(RawSshMessage::OnWire(OnWireData(out)))
}

/// Decrypt an aes256-ctr + hmac-sha2-256 packet back into an `SshMessage`,
/// verifying the HMAC. Inverse of `fn_encrypt_packet_ctr`.
pub fn fn_decrypt_packet_ctr(
    data: &OnWireData,
    enc_key: &SshBytes,
    iv: &SshBytes,
    mac_key: &SshBytes,
    block_offset: &u32,
    seqno: &u32,
) -> Result<SshMessage, FnError> {
    use puffin::codec::Reader;

    if enc_key.0.len() != 32 || iv.0.len() != 16 {
        return Err(FnError::Malformed("AES-CTR key/IV size".into()));
    }
    let wire = &data.0;
    let mac_len = 32usize;
    if wire.len() < 16 + mac_len {
        return Err(FnError::Malformed("packet too short".into()));
    }
    let ct = &wire[..wire.len() - mac_len];
    let tag = &wire[wire.len() - mac_len..];
    if ct.len() % 16 != 0 {
        return Err(FnError::Malformed("ciphertext not block-aligned".into()));
    }

    let mut clear = ct.to_vec();
    let mut cipher = Aes256Ctr::new_from_slices(&enc_key.0, &iv.0)
        .map_err(|_| FnError::Malformed("AES-CTR init failed".into()))?;
    cipher.seek((*block_offset as u64) * 16u64);
    cipher.apply_keystream(&mut clear);

    // Verify HMAC over seqno || cleartext.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key.0)
        .map_err(|_| FnError::Malformed("HMAC key error".into()))?;
    mac.update(&seqno.to_be_bytes());
    mac.update(&clear);
    mac.verify_slice(tag)
        .map_err(|_| FnError::Malformed("HMAC verification failed".into()))?;

    let packet_len = u32::from_be_bytes(clear[0..4].try_into().unwrap()) as usize;
    if 4 + packet_len > clear.len() || packet_len < 2 {
        return Err(FnError::Malformed("invalid packet length".into()));
    }
    let pad = clear[4] as usize;
    if 1 + pad > packet_len {
        return Err(FnError::Malformed("invalid padding".into()));
    }
    let payload = &clear[5..4 + packet_len - pad];
    let mut reader = Reader::init(payload);
    SshMessage::read(&mut reader)
        .ok_or_else(|| FnError::Malformed("failed to parse decrypted SshMessage".into()))
}

// ── ChaCha20-Poly1305@openssh.com packet encryption ──────────────────────────
//
// Two 32-byte keys (per PROTOCOL.chacha20poly1305 from OpenSSH):
//   k2 = key[0..32]  — body key (encryption + MAC key generation)
//   k1 = key[32..64] — length key (encrypts the 4-byte packet_length field)
//
// Nonce: 8-byte big-endian sequence number (libssh uses CHACHA_NONCELEN=8).
// libssh's chacha20 uses an 8-byte nonce and an 8-byte counter.
// x25519-dalek's chacha20 crate uses a 12-byte nonce (RFC 8439); we construct
// the OpenSSH variant by using the legacy 64-bit nonce interface.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20Legacy, LegacyNonce}; // 64-bit nonce, matching OpenSSH

/// Encrypt one SSH message as a complete ChaCha20-Poly1305 binary packet.
/// Returns `RawSshMessage::OnWire` with the full encrypted packet bytes.
pub fn fn_encrypt_packet(
    msg: &SshMessage,
    key: &SshBytes,
    seqno: &u32,
) -> Result<RawSshMessage, FnError> {
    if key.0.len() != 64 {
        return Err(FnError::Malformed("encryption key must be 64 bytes".into()));
    }

    let plaintext = msg.get_encoding(); // type byte + fields, no framing

    // Compute padding: (1 + payload_len + pad) % 8 == 0, pad >= 4
    let block = 8usize;
    let unpadded = 1 + plaintext.len();
    let mut pad = block - (unpadded % block);
    if pad < 4 {
        pad += block;
    }
    let packet_len = 1 + plaintext.len() + pad; // excludes the 4-byte length field

    // Build plaintext body: [pad_len: u8][payload][zero padding]
    let mut body = Vec::with_capacity(packet_len);
    body.push(pad as u8);
    body.extend_from_slice(&plaintext);
    body.resize(packet_len, 0u8);

    // Keys
    let k2 = chacha20::Key::from_slice(&key.0[0..32]);
    let k1 = chacha20::Key::from_slice(&key.0[32..64]);

    // Nonce: 8-byte big-endian seqno
    let nonce_bytes: [u8; 8] = (*seqno as u64).to_be_bytes();
    let nonce = LegacyNonce::from_slice(&nonce_bytes);

    // Step 1: generate 32-byte Poly1305 key from k2, counter=0
    let mut cipher_k2 = ChaCha20Legacy::new(k2, nonce);
    let mut poly_key = [0u8; 32];
    cipher_k2.apply_keystream(&mut poly_key);

    // Step 2: encrypt the 4-byte packet_length with k1, counter=0
    let mut cipher_k1 = ChaCha20Legacy::new(k1, nonce);
    let mut enc_len = (packet_len as u32).to_be_bytes();
    cipher_k1.apply_keystream(&mut enc_len);

    // Step 3: encrypt body with k2 starting at counter=1 (byte offset 64).
    // OpenSSH reserves block 0 of k2 for the Poly1305 key and encrypts the
    // payload from block 1 onward.
    let mut enc_body = body;
    cipher_k2.seek(64u64);
    cipher_k2.apply_keystream(&mut enc_body);

    // Step 4: Poly1305 MAC over [enc_len || enc_body]
    use poly1305::universal_hash::{KeyInit, UniversalHash};
    use poly1305::{Key as Poly1305Key, Poly1305};
    let poly = Poly1305::new(Poly1305Key::from_slice(&poly_key));
    let mut mac_input = Vec::with_capacity(4 + enc_body.len());
    mac_input.extend_from_slice(&enc_len);
    mac_input.extend_from_slice(&enc_body);
    let tag = poly.compute_unpadded(&mac_input);

    // Assemble output
    let mut out = Vec::with_capacity(4 + enc_body.len() + 16);
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&enc_body);
    out.extend_from_slice(&tag);

    Ok(RawSshMessage::OnWire(OnWireData(out)))
}

/// Decrypt a ChaCha20-Poly1305@openssh packet (the inverse of
/// `fn_encrypt_packet`) and parse the plaintext payload back into an
/// `SshMessage`.
///
/// Used by differential fuzzing's `terms_to_eval`: a PUT's encrypted
/// record-layer output is opaque `OnWire` bytes, so to compare two PUTs
/// structurally we decrypt with the derived key + sequence number and parse
/// the cleartext into a typed `SshMessage`.
///
/// `data` is the raw on-wire packet: `[enc_len(4)][enc_body(packet_len)][tag(16)]`.
pub fn fn_decrypt_packet(
    data: &OnWireData,
    key: &SshBytes,
    seqno: &u32,
) -> Result<SshMessage, FnError> {
    use puffin::codec::Reader;

    if key.0.len() != 64 {
        return Err(FnError::Malformed("decryption key must be 64 bytes".into()));
    }
    let wire = &data.0;
    if wire.len() < 4 + 16 {
        return Err(FnError::Malformed("packet too short to decrypt".into()));
    }

    let k2 = chacha20::Key::from_slice(&key.0[0..32]);
    let k1 = chacha20::Key::from_slice(&key.0[32..64]);

    let nonce_bytes: [u8; 8] = (*seqno as u64).to_be_bytes();
    let nonce = LegacyNonce::from_slice(&nonce_bytes);

    // Step 1: regenerate the Poly1305 key from k2 at counter 0.
    let mut cipher_k2 = ChaCha20Legacy::new(k2, nonce);
    let mut poly_key = [0u8; 32];
    cipher_k2.apply_keystream(&mut poly_key);

    // Step 2: decrypt the 4-byte length field with k1 at counter 0.
    let mut cipher_k1 = ChaCha20Legacy::new(k1, nonce);
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&wire[0..4]);
    cipher_k1.apply_keystream(&mut len_buf);
    let packet_len = u32::from_be_bytes(len_buf) as usize;

    // Bounds: wire must hold enc_len(4) + enc_body(packet_len) + tag(16).
    if wire.len() < 4 + packet_len + 16 {
        return Err(FnError::Malformed(
            "declared packet length exceeds available bytes".into(),
        ));
    }
    let enc_body = &wire[4..4 + packet_len];
    let tag_bytes = &wire[4 + packet_len..4 + packet_len + 16];

    // Step 3: verify the Poly1305 tag over [enc_len || enc_body].
    use poly1305::universal_hash::{KeyInit, UniversalHash};
    use poly1305::{Key as Poly1305Key, Poly1305};
    let poly = Poly1305::new(Poly1305Key::from_slice(&poly_key));
    let mut mac_input = Vec::with_capacity(4 + packet_len);
    mac_input.extend_from_slice(&wire[0..4]);
    mac_input.extend_from_slice(enc_body);
    let expected = poly.compute_unpadded(&mac_input);
    if expected.as_slice() != tag_bytes {
        return Err(FnError::Malformed("Poly1305 tag mismatch".into()));
    }

    // Step 4: decrypt the body with k2 at counter 1 (byte offset 64).
    let mut body = enc_body.to_vec();
    cipher_k2.seek(64u64);
    cipher_k2.apply_keystream(&mut body);

    // body = [pad_len: u8][payload][padding]; strip framing and parse payload.
    if body.is_empty() {
        return Err(FnError::Malformed("empty decrypted body".into()));
    }
    let pad_len = body[0] as usize;
    if 1 + pad_len > body.len() {
        return Err(FnError::Malformed("invalid padding length".into()));
    }
    let payload = &body[1..body.len() - pad_len];

    let mut reader = Reader::init(payload);
    SshMessage::read(&mut reader)
        .ok_or_else(|| FnError::Malformed("failed to parse decrypted SshMessage".into()))
}

// ── Server-attacker helpers ───────────────────────────────────────────────────

/// The embedded server RSA private key in OpenSSH format (same key as put.c).
const SERVER_HOST_KEY_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----";

// ── Client identity keys ─────────────────────────────────────────────────────
//
// Distinct client credentials the fuzzer can present. Identity A reuses the
// server host key (historical, keeps the pubkey seeds stable); identities B and
// C are their own RSA-3072 keypairs. The harness authorized-keys allow-list
// (both PUTs) grants A and B; C is deliberately NOT authorized, so presenting
// C's key is the "unauthorized key" attack. Mutations that swap a username, a
// pubkey blob, and/or a signature across identities are the credential-confusion
// / impersonation surface — a cross-vendor accept/reject asymmetry is a finding.
const CLIENT_B_KEY_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----";

const CLIENT_C_KEY_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----";

fn load_server_key() -> Result<ssh_key::PrivateKey, FnError> {
    ssh_key::PrivateKey::from_openssh(SERVER_HOST_KEY_OPENSSH)
        .map_err(|e| FnError::Malformed(format!("failed to parse server key: {e}")))
}

fn load_openssh_key(pem: &str, label: &str) -> Result<ssh_key::PrivateKey, FnError> {
    ssh_key::PrivateKey::from_openssh(pem)
        .map_err(|e| FnError::Malformed(format!("failed to parse {label} key: {e}")))
}

/// Return the server RSA public key as a `SshPublicKey` (for use in `fn_kex_ecdh_reply`).
pub fn fn_server_rsa_pubkey() -> Result<SshPublicKey, FnError> {
    let key = load_server_key()?;
    // Encode using ssh-key's wire format then parse into our SshPublicKey
    let pubkey = key.public_key();
    let wire = pubkey
        .to_bytes()
        .map_err(|e| FnError::Malformed(format!("pubkey encoding failed: {e}")))?;

    // ssh-key's to_bytes() returns the key blob WITHOUT an outer length prefix:
    //   wire = [string algo]["ssh-rsa"][mpint e][mpint n]
    // Parse into SshPublicKey { algorithm, key_data = raw [e][n] }.
    use puffin::codec::Reader;
    let mut r = Reader::init(&wire);
    let algorithm = SshBytes::read(&mut r).ok_or_else(|| FnError::Malformed("bad algo".into()))?;
    let key_data = SshBytes::new(r.rest().to_vec());

    Ok(SshPublicKey {
        algorithm,
        key_data,
    })
}

/// Return the server RSA public key as raw outer-SSH-string bytes for use in
/// the K_S position of the exchange hash.
pub fn fn_server_rsa_pubkey_bytes() -> Result<SshBytes, FnError> {
    let key = load_server_key()?;
    let wire = key
        .public_key()
        .to_bytes()
        .map_err(|e| FnError::Malformed(format!("pubkey encoding failed: {e}")))?;
    // K_S in the exchange hash is the full outer SSH string: [u32 len][blob].
    // ssh-key's to_bytes() omits the outer length, so we prepend it here to
    // match what SshPublicKey::encode produces when we send the KexEcdhReply.
    let mut out = Vec::with_capacity(4 + wire.len());
    out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    out.extend_from_slice(&wire);
    Ok(SshBytes::new(out))
}

/// Sign the exchange hash with the embedded server RSA private key using rsa-sha2-256.
/// Returns the raw PKCS#1v1.5 signature bytes (without algorithm wrapper).
pub fn fn_sign_exchange_hash(h: &ExchangeHash) -> Result<SshBytes, FnError> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::{BigUint, RsaPrivateKey};
    use sha2::Sha256;

    let key = load_server_key()?;
    let rsa_keypair = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(r) => r,
        _ => return Err(FnError::Malformed("server key is not RSA".into())),
    };

    // Build the rsa-crate private key from the raw mpint components. BigUint
    // tolerates leading zero bytes, so the raw mpint encoding is fine.
    let n = BigUint::from_bytes_be(rsa_keypair.public.n.as_bytes());
    let e = BigUint::from_bytes_be(rsa_keypair.public.e.as_bytes());
    let d = BigUint::from_bytes_be(rsa_keypair.private.d.as_bytes());
    let p = BigUint::from_bytes_be(rsa_keypair.private.p.as_bytes());
    let q = BigUint::from_bytes_be(rsa_keypair.private.q.as_bytes());
    let priv_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| FnError::Malformed(format!("RSA key conversion failed: {e}")))?;

    // rsa-sha2-256 = RSASSA-PKCS1-v1_5 over SHA-256.
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let signature = signing_key
        .try_sign(h.0.as_slice())
        .map_err(|e| FnError::Malformed(format!("signing failed: {e}")))?;

    Ok(SshBytes::new(signature.to_bytes().to_vec()))
}

/// Build a `SshSignature` with algorithm `"rsa-sha2-256"` and the given signature bytes.
pub fn fn_rsa_sha2_256_signature(sig_data: &SshBytes) -> Result<SshSignature, FnError> {
    Ok(SshSignature {
        algorithm: SshBytes::new(b"rsa-sha2-256".to_vec()),
        signature_data: sig_data.clone(),
    })
}

/// Encode a private key's public half as the publickey blob carried in a
/// USERAUTH_REQUEST (`["ssh-rsa"][mpint e][mpint n]`, no outer length prefix).
fn pubkey_blob_of(key: &ssh_key::PrivateKey) -> Result<SshBytes, FnError> {
    // ssh-key's to_bytes() returns the inner blob without an outer length prefix,
    // which is exactly the publickey-blob format used in USERAUTH_REQUEST.
    let wire = key
        .public_key()
        .to_bytes()
        .map_err(|e| FnError::Malformed(format!("pubkey encoding failed: {e}")))?;
    Ok(SshBytes::new(wire))
}

/// Sign a publickey USERAUTH_REQUEST with the given RSA private key. Produces the
/// raw rsa-sha2-256 signature over the RFC 4252 §7 blob:
///   string session id, byte 50, string user, string service, string "publickey",
///   boolean TRUE, string "rsa-sha2-256", string public-key blob.
fn sign_userauth_with(
    key: &ssh_key::PrivateKey,
    session_id: &SessionId,
    user: &SshBytes,
    service: &SshBytes,
    pubkey_blob: &SshBytes,
) -> Result<SshBytes, FnError> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::{BigUint, RsaPrivateKey};
    use sha2::Sha256;

    let mut data = Vec::new();
    push_ssh_string(&mut data, &session_id.0);
    data.push(50u8); // SSH_MSG_USERAUTH_REQUEST
    push_ssh_string(&mut data, &user.0);
    push_ssh_string(&mut data, &service.0);
    push_ssh_string(&mut data, b"publickey");
    data.push(0x01); // has-signature = TRUE
    push_ssh_string(&mut data, b"rsa-sha2-256");
    push_ssh_string(&mut data, &pubkey_blob.0);

    let rsa_keypair = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(r) => r,
        _ => return Err(FnError::Malformed("client key is not RSA".into())),
    };
    let n = BigUint::from_bytes_be(rsa_keypair.public.n.as_bytes());
    let e = BigUint::from_bytes_be(rsa_keypair.public.e.as_bytes());
    let d = BigUint::from_bytes_be(rsa_keypair.private.d.as_bytes());
    let p = BigUint::from_bytes_be(rsa_keypair.private.p.as_bytes());
    let q = BigUint::from_bytes_be(rsa_keypair.private.q.as_bytes());
    let priv_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| FnError::Malformed(format!("RSA key conversion failed: {e}")))?;
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let signature = signing_key
        .try_sign(&data)
        .map_err(|e| FnError::Malformed(format!("userauth signing failed: {e}")))?;
    Ok(SshBytes::new(signature.to_bytes().to_vec()))
}

/// Client identity key A's public key blob (reuses the embedded server RSA key).
/// This is the blob carried in a publickey USERAUTH_REQUEST and hashed (SHA-256)
/// to the fingerprint the server records — the harness allow-list authorizes A.
pub fn fn_client_a_pubkey_blob() -> Result<SshBytes, FnError> {
    pubkey_blob_of(&load_server_key()?)
}

/// Client identity key B's public key blob. B is a distinct RSA-3072 key that the
/// harness allow-list also authorizes — the swap target for impersonation tests.
pub fn fn_client_b_pubkey_blob() -> Result<SshBytes, FnError> {
    pubkey_blob_of(&load_openssh_key(CLIENT_B_KEY_OPENSSH, "client B")?)
}

/// Client identity key C's public key blob. C is a distinct RSA-3072 key that is
/// deliberately NOT in the harness allow-list — the "unauthorized key" attack.
pub fn fn_client_c_pubkey_blob() -> Result<SshBytes, FnError> {
    pubkey_blob_of(&load_openssh_key(CLIENT_C_KEY_OPENSSH, "client C")?)
}

/// Sign a publickey USERAUTH_REQUEST with client identity key A.
pub fn fn_sign_userauth(
    session_id: &SessionId,
    user: &SshBytes,
    service: &SshBytes,
    pubkey_blob: &SshBytes,
) -> Result<SshBytes, FnError> {
    sign_userauth_with(&load_server_key()?, session_id, user, service, pubkey_blob)
}

/// Sign a publickey USERAUTH_REQUEST with client identity key B.
pub fn fn_sign_userauth_b(
    session_id: &SessionId,
    user: &SshBytes,
    service: &SshBytes,
    pubkey_blob: &SshBytes,
) -> Result<SshBytes, FnError> {
    sign_userauth_with(
        &load_openssh_key(CLIENT_B_KEY_OPENSSH, "client B")?,
        session_id,
        user,
        service,
        pubkey_blob,
    )
}

/// Sign a publickey USERAUTH_REQUEST with client identity key C.
pub fn fn_sign_userauth_c(
    session_id: &SessionId,
    user: &SshBytes,
    service: &SshBytes,
    pubkey_blob: &SshBytes,
) -> Result<SshBytes, FnError> {
    sign_userauth_with(
        &load_openssh_key(CLIENT_C_KEY_OPENSSH, "client C")?,
        session_id,
        user,
        service,
        pubkey_blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::message::{ServiceRequestMessage, SshMessage};

    #[test]
    fn client_identities_load_and_are_distinct() {
        // Guards against a copy-paste error in the embedded B/C PEMs: each key
        // must parse, yield an ssh-rsa publickey blob, and be distinct from the
        // others (A reuses the server key, B and C are their own keypairs).
        let a = fn_client_a_pubkey_blob().expect("A blob");
        let b = fn_client_b_pubkey_blob().expect("B blob");
        let c = fn_client_c_pubkey_blob().expect("C blob");
        for (name, blob) in [("A", &a), ("B", &b), ("C", &c)] {
            assert!(
                blob.0.windows(7).any(|w| w == b"ssh-rsa"),
                "identity {name} blob is not an ssh-rsa key"
            );
        }
        assert_ne!(a.0, b.0, "A and B must differ");
        assert_ne!(a.0, c.0, "A and C must differ");
        assert_ne!(b.0, c.0, "B and C must differ");

        // Each identity signs the RFC 4252 §7 blob with its own key without error.
        let sid = SessionId::new(vec![7u8; 32]);
        let user = SshBytes::new(b"user".to_vec());
        let svc = SshBytes::new(b"ssh-connection".to_vec());
        assert!(fn_sign_userauth(&sid, &user, &svc, &a).is_ok());
        assert!(fn_sign_userauth_b(&sid, &user, &svc, &b).is_ok());
        assert!(fn_sign_userauth_c(&sid, &user, &svc, &c).is_ok());
    }

    /// Byte-identity guard for the type-directed crypto refactor: wrapping the KEX
    /// quantities in role newtypes (SharedSecret / ExchangeHash / SessionId) must
    /// NOT change any derived byte — otherwise the handshake would break. The typed
    /// derivation must equal the raw `derive_key` over the same bytes, and
    /// `fn_session_id_from_hash` must be a byte-copy of the (first) exchange hash.
    #[test]
    fn crypto_newtypes_preserve_derived_bytes() {
        let shared_raw = vec![0x11u8; 32];
        let h_raw = vec![0x22u8; 32];
        let shared = SharedSecret::new(shared_raw.clone());
        let h = ExchangeHash::new(h_raw.clone());

        let sid = fn_session_id_from_hash(&h).unwrap();
        assert_eq!(
            sid.0, h_raw,
            "session id must be a byte-copy of the first H"
        );

        // Typed key/IV derivation == raw derive_key over the identical bytes.
        let key = fn_derive_aes_key_s2c(&shared, &h, &sid).unwrap();
        assert_eq!(
            key.0,
            derive_key(&shared_raw, &h_raw, &h_raw, b'D', 32).0,
            "typed AES-GCM key derivation changed the derived bytes"
        );
        let iv = fn_derive_iv_s2c(&shared, &h, &sid).unwrap();
        assert_eq!(
            iv.0,
            derive_key(&shared_raw, &h_raw, &h_raw, b'B', 12).0,
            "typed AES-GCM IV derivation changed the derived bytes"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // A 64-byte key (two ChaCha20 keys) and a couple of sequence numbers.
        let key = SshBytes::new((0u8..64).collect::<Vec<u8>>());
        let msg = SshMessage::ServiceRequest(ServiceRequestMessage {
            service_name: SshBytes::new(b"ssh-userauth".to_vec()),
        });

        for seqno in [0u32, 1, 7, 42] {
            let encrypted = fn_encrypt_packet(&msg, &key, &seqno).expect("encrypt");
            let onwire = match encrypted {
                RawSshMessage::OnWire(d) => d,
                _ => panic!("expected OnWire"),
            };
            let decrypted = fn_decrypt_packet(&onwire, &key, &seqno).expect("decrypt");
            assert_eq!(decrypted, msg, "roundtrip mismatch at seqno {seqno}");
        }
    }

    #[test]
    fn test_aesgcm_encrypt_decrypt_roundtrip() {
        let key = SshBytes::new((0u8..32).collect::<Vec<u8>>()); // 32-byte AES-256 key
        let iv = SshBytes::new((0u8..12).collect::<Vec<u8>>()); // 12-byte IV
        let msg = SshMessage::ServiceRequest(ServiceRequestMessage {
            service_name: SshBytes::new(b"ssh-userauth".to_vec()),
        });
        for counter in [0u32, 1, 5, 99] {
            let enc = fn_encrypt_packet_aesgcm(&msg, &key, &iv, &counter).expect("aesgcm encrypt");
            let onwire = match enc {
                RawSshMessage::OnWire(d) => d,
                _ => panic!("expected OnWire"),
            };
            let dec =
                fn_decrypt_packet_aesgcm(&onwire, &key, &iv, &counter).expect("aesgcm decrypt");
            assert_eq!(dec, msg, "aes-gcm roundtrip mismatch at counter {counter}");
        }
        // Wrong counter (nonce) must fail the GCM tag.
        let enc = fn_encrypt_packet_aesgcm(&msg, &key, &iv, &0).unwrap();
        let onwire = match enc {
            RawSshMessage::OnWire(d) => d,
            _ => unreachable!(),
        };
        assert!(fn_decrypt_packet_aesgcm(&onwire, &key, &iv, &1).is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = SshBytes::new((0u8..64).collect::<Vec<u8>>());
        let wrong = SshBytes::new((1u8..65).collect::<Vec<u8>>());
        let msg = SshMessage::NewKeys;
        let encrypted = fn_encrypt_packet(&msg, &key, &0).expect("encrypt");
        let onwire = match encrypted {
            RawSshMessage::OnWire(d) => d,
            _ => panic!("expected OnWire"),
        };
        // Wrong key must fail the Poly1305 tag check.
        assert!(fn_decrypt_packet(&onwire, &wrong, &0).is_err());
    }
}
