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

use crate::ssh::message::{
    KexEcdhReplyMessage, OnWireData, RawSshMessage, SshBytes, SshMessage, SshPublicKey,
    SshSignature,
};

// ── Deterministic client ECDH seed ───────────────────────────────────────────
//
// Fixed 32-byte seed so the fuzzer can construct the exchange hash from terms
// without any hidden RNG state.

const CLIENT_ECDH_SEED: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
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
) -> Result<SshBytes, FnError> {
    if priv_key.0.len() != 32 {
        return Err(FnError::Unknown("private key must be 32 bytes".into()));
    }
    if peer_pub.0.len() != 32 {
        return Err(FnError::Unknown("peer public key must be 32 bytes".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&priv_key.0);
    let sk = StaticSecret::from(seed);

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&peer_pub.0);
    let pk = PublicKey::from(pub_bytes);

    let shared = sk.diffie_hellman(&pk);
    Ok(SshBytes::new(shared.as_bytes().to_vec()))
}

// ── Message extraction helpers ────────────────────────────────────────────────

/// Extract the banner identification string without the trailing `\r\n`.
pub fn fn_banner_id(raw: &RawSshMessage) -> Result<SshBytes, FnError> {
    match raw {
        RawSshMessage::Banner(s) => {
            let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
            Ok(SshBytes::new(trimmed.as_bytes().to_vec()))
        }
        _ => Err(FnError::Unknown("Expected RawSshMessage::Banner".into())),
    }
}

/// Encode a `KexInit` message to its SSH wire payload (type byte 20 + fields).
/// This matches what libssh stores in its internal `in_hashbuf` / `out_hashbuf`.
pub fn fn_kexinit_payload(msg: &SshMessage) -> Result<SshBytes, FnError> {
    match msg {
        SshMessage::KexInit(_) => Ok(SshBytes::new(msg.get_encoding())),
        _ => Err(FnError::Unknown("Expected SshMessage::KexInit".into())),
    }
}

/// Extract the server's ephemeral X25519 public key (Q_S) from a KexEcdhReply.
pub fn fn_server_ecdh_pubkey(msg: &SshMessage) -> Result<SshBytes, FnError> {
    match msg {
        SshMessage::KexEcdhReply(KexEcdhReplyMessage {
            ephemeral_public_key,
            ..
        }) => Ok(ephemeral_public_key.clone()),
        _ => Err(FnError::Unknown("Expected SshMessage::KexEcdhReply".into())),
    }
}

/// Extract the server's host public key (K_S) from a KexEcdhReply.
pub fn fn_server_hostkey(msg: &SshMessage) -> Result<SshPublicKey, FnError> {
    match msg {
        SshMessage::KexEcdhReply(KexEcdhReplyMessage {
            public_host_key, ..
        }) => Ok(public_host_key.clone()),
        _ => Err(FnError::Unknown("Expected SshMessage::KexEcdhReply".into())),
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
                return Err(FnError::Unknown(
                    "Expected KexEcdhReply packet (type 31)".into(),
                ));
            }
            let mut reader = Reader::init(&payload[1..]); // skip type byte
            let ks_len = u32::read(&mut reader)
                .ok_or_else(|| FnError::Unknown("Failed to read K_S length".into()))?
                as usize;
            // The K_S outer string starts at payload[1] and spans 4 + ks_len bytes.
            let raw_start = 1usize;
            if raw_start + 4 + ks_len > payload.len() {
                return Err(FnError::Unknown("K_S truncated in KexEcdhReply".into()));
            }
            Ok(SshBytes::new(
                payload[raw_start..raw_start + 4 + ks_len].to_vec(),
            ))
        }
        _ => Err(FnError::Unknown(
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
/// * `k_s` — server host key as raw SSH outer-string bytes (use `fn_server_hostkey_raw`
///            OR `fn_server_rsa_pubkey_bytes` for the server-attacker seed)
/// * `q_c` — client ephemeral X25519 public key (32 bytes)
/// * `q_s` — server ephemeral X25519 public key (32 bytes)
/// * `shared_secret` — 32-byte output of `fn_ecdh_shared_secret`
pub fn fn_kex_exchange_hash(
    v_c: &SshBytes,
    v_s: &SshBytes,
    i_c: &SshBytes,
    i_s: &SshBytes,
    k_s: &SshBytes,       // raw outer SSH-string bytes (includes 4-byte length prefix)
    q_c: &SshBytes,
    q_s: &SshBytes,
    shared_secret: &SshBytes,
) -> Result<SshBytes, FnError> {
    let mut buf = Vec::new();

    push_ssh_string(&mut buf, &v_c.0);     // V_C
    push_ssh_string(&mut buf, &v_s.0);     // V_S
    push_ssh_string(&mut buf, &i_c.0);     // I_C
    push_ssh_string(&mut buf, &i_s.0);     // I_S
    buf.extend_from_slice(&k_s.0);          // K_S (already outer-string encoded)
    push_ssh_string(&mut buf, &q_c.0);     // Q_C
    push_ssh_string(&mut buf, &q_s.0);     // Q_S
    buf.extend_from_slice(&to_mpint(&shared_secret.0)); // K

    let hash = Sha256::digest(&buf);
    Ok(SshBytes::new(hash.to_vec()))
}

// ── Key derivation (RFC 4253 §7) ─────────────────────────────────────────────

fn derive_key(shared: &SshBytes, h: &SshBytes, sid: &SshBytes, id: u8, needed: usize)
    -> SshBytes
{
    let k_mpint = to_mpint(&shared.0);

    // K1 = SHA-256(K || H || id || session_id)
    let k1: Vec<u8> = Sha256::new()
        .chain_update(&k_mpint)
        .chain_update(&h.0)
        .chain_update([id])
        .chain_update(&sid.0)
        .finalize()
        .to_vec();

    if needed <= 32 {
        return SshBytes::new(k1[..needed].to_vec());
    }

    let mut out = k1;
    while out.len() < needed {
        let kn: Vec<u8> = Sha256::new()
            .chain_update(&k_mpint)
            .chain_update(&h.0)
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
    shared: &SshBytes,
    h: &SshBytes,
    sid: &SshBytes,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(shared, h, sid, b'C', 64))
}

/// Server-to-client encryption key (id = `'D'`), 64 bytes for ChaCha20-Poly1305.
pub fn fn_derive_enc_key_s2c(
    shared: &SshBytes,
    h: &SshBytes,
    sid: &SshBytes,
) -> Result<SshBytes, FnError> {
    Ok(derive_key(shared, h, sid, b'D', 64))
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
        return Err(FnError::Unknown("encryption key must be 64 bytes".into()));
    }

    let plaintext = msg.get_encoding(); // type byte + fields, no framing

    // Compute padding: (1 + payload_len + pad) % 8 == 0, pad >= 4
    let block = 8usize;
    let unpadded = 1 + plaintext.len();
    let mut pad = block - (unpadded % block);
    if pad < 4 { pad += block; }
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
    use poly1305::{Key as Poly1305Key, Poly1305};
    use poly1305::universal_hash::{KeyInit, UniversalHash};
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

// ── Server-attacker helpers ───────────────────────────────────────────────────

/// The embedded server RSA private key in OpenSSH format (same key as put.c).
const SERVER_HOST_KEY_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----";

fn load_server_key() -> Result<ssh_key::PrivateKey, FnError> {
    ssh_key::PrivateKey::from_openssh(SERVER_HOST_KEY_OPENSSH)
        .map_err(|e| FnError::Unknown(format!("failed to parse server key: {e}")))
}

/// Return the server RSA public key as a `SshPublicKey` (for use in `fn_kex_ecdh_reply`).
pub fn fn_server_rsa_pubkey() -> Result<SshPublicKey, FnError> {
    let key = load_server_key()?;
    // Encode using ssh-key's wire format then parse into our SshPublicKey
    let pubkey = key.public_key();
    let wire = pubkey.to_bytes()
        .map_err(|e| FnError::Unknown(format!("pubkey encoding failed: {e}")))?;

    // ssh-key's to_bytes() returns the key blob WITHOUT an outer length prefix:
    //   wire = [string algo]["ssh-rsa"][mpint e][mpint n]
    // Parse into SshPublicKey { algorithm, key_data = raw [e][n] }.
    use puffin::codec::Reader;
    let mut r = Reader::init(&wire);
    let algorithm = SshBytes::read(&mut r)
        .ok_or_else(|| FnError::Unknown("bad algo".into()))?;
    let key_data = SshBytes::new(r.rest().to_vec());

    Ok(SshPublicKey { algorithm, key_data })
}

/// Return the server RSA public key as raw outer-SSH-string bytes for use in
/// the K_S position of the exchange hash.
pub fn fn_server_rsa_pubkey_bytes() -> Result<SshBytes, FnError> {
    let key = load_server_key()?;
    let wire = key.public_key().to_bytes()
        .map_err(|e| FnError::Unknown(format!("pubkey encoding failed: {e}")))?;
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
pub fn fn_sign_exchange_hash(h: &SshBytes) -> Result<SshBytes, FnError> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    use rsa::BigUint;

    let key = load_server_key()?;
    let rsa_keypair = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(r) => r,
        _ => return Err(FnError::Unknown("server key is not RSA".into())),
    };

    // Build the rsa-crate private key from the raw mpint components. BigUint
    // tolerates leading zero bytes, so the raw mpint encoding is fine.
    let n = BigUint::from_bytes_be(rsa_keypair.public.n.as_bytes());
    let e = BigUint::from_bytes_be(rsa_keypair.public.e.as_bytes());
    let d = BigUint::from_bytes_be(rsa_keypair.private.d.as_bytes());
    let p = BigUint::from_bytes_be(rsa_keypair.private.p.as_bytes());
    let q = BigUint::from_bytes_be(rsa_keypair.private.q.as_bytes());
    let priv_key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| FnError::Unknown(format!("RSA key conversion failed: {e}")))?;

    // rsa-sha2-256 = RSASSA-PKCS1-v1_5 over SHA-256.
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let signature = signing_key
        .try_sign(h.0.as_slice())
        .map_err(|e| FnError::Unknown(format!("signing failed: {e}")))?;

    Ok(SshBytes::new(signature.to_bytes().to_vec()))
}

/// Build a `SshSignature` with algorithm `"rsa-sha2-256"` and the given signature bytes.
pub fn fn_rsa_sha2_256_signature(sig_data: &SshBytes) -> Result<SshSignature, FnError> {
    Ok(SshSignature {
        algorithm: SshBytes::new(b"rsa-sha2-256".to_vec()),
        signature_data: sig_data.clone(),
    })
}
