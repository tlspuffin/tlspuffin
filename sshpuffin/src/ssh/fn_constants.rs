#![allow(clippy::ptr_arg)]
#![allow(dead_code)]

use puffin::algebra::error::FnError;

use crate::ssh::message::SshBytes;

pub fn fn_true() -> Result<bool, FnError> {
    Ok(true)
}
pub fn fn_false() -> Result<bool, FnError> {
    Ok(false)
}

pub fn fn_seq_0() -> Result<u64, FnError> {
    Ok(0)
}
pub fn fn_seq_1() -> Result<u64, FnError> {
    Ok(1)
}
pub fn fn_seq_2() -> Result<u64, FnError> {
    Ok(2)
}
pub fn fn_seq_3() -> Result<u64, FnError> {
    Ok(3)
}
pub fn fn_seq_4() -> Result<u64, FnError> {
    Ok(4)
}
pub fn fn_seq_5() -> Result<u64, FnError> {
    Ok(5)
}
pub fn fn_seq_6() -> Result<u64, FnError> {
    Ok(6)
}
pub fn fn_seq_7() -> Result<u64, FnError> {
    Ok(7)
}
pub fn fn_seq_8() -> Result<u64, FnError> {
    Ok(8)
}
pub fn fn_seq_9() -> Result<u64, FnError> {
    Ok(9)
}
pub fn fn_seq_10() -> Result<u64, FnError> {
    Ok(10)
}
pub fn fn_seq_11() -> Result<u64, FnError> {
    Ok(11)
}
pub fn fn_seq_12() -> Result<u64, FnError> {
    Ok(12)
}
pub fn fn_seq_13() -> Result<u64, FnError> {
    Ok(13)
}
pub fn fn_seq_14() -> Result<u64, FnError> {
    Ok(14)
}
pub fn fn_seq_15() -> Result<u64, FnError> {
    Ok(15)
}
pub fn fn_seq_16() -> Result<u64, FnError> {
    Ok(16)
}

pub fn fn_empty_bytes_vec() -> Result<Vec<u8>, FnError> {
    Ok(vec![])
}

// ── u32 constants (channel IDs, reason codes, window sizes) ─────────────────

pub fn fn_u32_0() -> Result<u32, FnError> {
    Ok(0)
}
pub fn fn_u32_1() -> Result<u32, FnError> {
    Ok(1)
}
pub fn fn_u32_2() -> Result<u32, FnError> {
    Ok(2)
}

// ── SSH service names (SshBytes so they can be used directly in messages) ────

pub fn fn_ssh_userauth() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ssh-userauth".to_vec()))
}
pub fn fn_ssh_connection() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ssh-connection".to_vec()))
}

// ── Auth method names ────────────────────────────────────────────────────────

pub fn fn_method_password() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"password".to_vec()))
}
pub fn fn_method_publickey() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"publickey".to_vec()))
}
pub fn fn_method_none() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"none".to_vec()))
}

// ── Common field values ──────────────────────────────────────────────────────

pub fn fn_username() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"user".to_vec()))
}
// method_data is raw bytes (not SSH-format string), so Vec<u8>
pub fn fn_password() -> Result<Vec<u8>, FnError> {
    Ok(b"test".to_vec())
}

pub fn fn_u32_3() -> Result<u32, FnError> {
    Ok(3)
}
pub fn fn_u32_4() -> Result<u32, FnError> {
    Ok(4)
}
pub fn fn_u32_5() -> Result<u32, FnError> {
    Ok(5)
}
pub fn fn_u32_6() -> Result<u32, FnError> {
    Ok(6)
}

/// "SSH-2.0-puffin" as SshBytes (no \\r\\n) — used as the attacker's banner ID.
pub fn fn_puffin_id() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"SSH-2.0-puffin".to_vec()))
}
pub fn fn_channel_session() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"session".to_vec()))
}

// ── A non-empty placeholder for ECDH keys / opaque byte blobs ───────────────
//
// 32 bytes of non-zero data so the fuzzer can build a KexEcdhInit that passes
// the "empty key" guard in libssh and reaches the actual key-validation logic.

// ── SSH algorithm name constants ──────────────────────────────────────────────
//
// Having realistic algorithm strings (not just random bytes) lets the attacker
// seeds get past the early algorithm-name validation and exercise deeper code
// paths in key verification and signature checking.

pub fn fn_algo_ssh_ed25519() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ssh-ed25519".to_vec()))
}
pub fn fn_algo_ecdsa_sha2_nistp256() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ecdsa-sha2-nistp256".to_vec()))
}
pub fn fn_algo_rsa_sha2_256() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"rsa-sha2-256".to_vec()))
}
pub fn fn_algo_curve25519_sha256() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"curve25519-sha256".to_vec()))
}
pub fn fn_algo_aes256_gcm() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"aes256-gcm@openssh.com".to_vec()))
}

// ── Additional algorithm-name atoms ──────────────────────────────────────────
//
// These give the DY mutator a rich pool of algorithm names to splice into the
// negotiation lists built by `fn_kex_init` (via `fn_namelist_*` + the typed
// list wrappers). They cover ciphers/MACs/KEX/host-key schemes we do NOT
// implement crypto for: offering them lets the fuzzer exercise the PUTs'
// negotiation / downgrade / algorithm-confusion handling even though a handshake
// on the alternative suite would not complete.

pub fn fn_algo_aes128_gcm() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"aes128-gcm@openssh.com".to_vec()))
}
pub fn fn_algo_aes128_ctr() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"aes128-ctr".to_vec()))
}
pub fn fn_algo_aes256_ctr() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"aes256-ctr".to_vec()))
}
pub fn fn_algo_3des_cbc() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"3des-cbc".to_vec()))
}
pub fn fn_algo_chacha20_poly1305() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"chacha20-poly1305@openssh.com".to_vec()))
}
pub fn fn_algo_hmac_sha2_256() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"hmac-sha2-256".to_vec()))
}
pub fn fn_algo_hmac_sha2_512() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"hmac-sha2-512".to_vec()))
}
pub fn fn_algo_hmac_sha1() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"hmac-sha1".to_vec()))
}
pub fn fn_algo_none() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"none".to_vec()))
}
pub fn fn_algo_dh_group14_sha256() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"diffie-hellman-group14-sha256".to_vec()))
}
pub fn fn_algo_ssh_rsa() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ssh-rsa".to_vec()))
}
pub fn fn_algo_rsa_sha2_512() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"rsa-sha2-512".to_vec()))
}
/// Terrapin / strict-KEX negotiation marker (sent as a pseudo-algorithm in the
/// KEXINIT lists). Lets the fuzzer add/remove strict-kex from the offer.
pub fn fn_algo_kex_strict_c() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"kex-strict-c-v00@openssh.com".to_vec()))
}
pub fn fn_algo_kex_strict_s() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"kex-strict-s-v00@openssh.com".to_vec()))
}
/// An unrecognized algorithm name, for exercising unknown-algorithm handling.
pub fn fn_algo_unknown() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"x-unknown-algo@puffin".to_vec()))
}
/// RFC 8308 ext-info-c marker: included in the client KEXINIT to advertise
/// EXT_INFO support, so the server will then accept a client SSH_MSG_EXT_INFO.
pub fn fn_algo_ext_info_c() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"ext-info-c".to_vec()))
}

// ── EXT_INFO extension names / values (RFC 8308) ─────────────────────────────
pub fn fn_ext_name_server_sig_algs() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"server-sig-algs".to_vec()))
}
pub fn fn_ext_val_rsa_sha2() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"rsa-sha2-256,rsa-sha2-512".to_vec()))
}

pub fn fn_puffin_banner() -> Result<String, FnError> {
    Ok("SSH-2.0-puffin\r\n".to_string())
}

pub fn fn_placeholder_16bytes() -> Result<[u8; 16], FnError> {
    Ok([0x07u8; 16])
}

pub fn fn_placeholder_32bytes() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]))
}

/// A `Vec<u8>` payload leaf for CHANNEL_DATA / CHANNEL_EXTENDED_DATA. Unlike the
/// opaque `fn_placeholder_32bytes` (a fixed `SshBytes`), this is a byte-vector
/// leaf wrapped via `fn_ssh_bytes`, giving the fuzzer a direct target: bit-level
/// havoc grows/shrinks/flips these bytes, and the DY mutator can swap the leaf
/// for any other `Vec<u8>` producer (exec payload, password, empty, …). This is
/// the entry point for fuzzing the peer's post-auth channel-data parser.
pub fn fn_channel_payload() -> Result<Vec<u8>, FnError> {
    Ok(b"puffin-channel-data-payload".to_vec())
}

// ── Channel / request type names ─────────────────────────────────────────────

pub fn fn_channel_exec() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"exec".to_vec()))
}
pub fn fn_channel_shell() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"shell".to_vec()))
}
pub fn fn_channel_pty_req() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"pty-req".to_vec()))
}

// ── Disconnect reason codes ──────────────────────────────────────────────────

pub fn fn_disconnect_reason_protocol_error() -> Result<u32, FnError> {
    Ok(2) // SSH_DISCONNECT_PROTOCOL_ERROR
}
pub fn fn_disconnect_reason_service_not_available() -> Result<u32, FnError> {
    Ok(7) // SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
}

// ── Auth method_data payloads (raw bytes, RFC 4252) ──────────────────────────
//
// These produce the raw `method_data` bytes that follow the method name in
// SSH_MSG_USERAUTH_REQUEST.  They are Vec<u8> (not SshBytes) because
// method_data is not a length-prefixed string — it is the raw remainder of
// the packet whose format is method-specific.

pub fn fn_password_auth_data(password: &Vec<u8>) -> Result<Vec<u8>, FnError> {
    // RFC 4252 §8: boolean FALSE + string password
    let mut data = vec![0x00]; // change-password = false
    let len = password.len() as u32;
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(password);
    Ok(data)
}

pub fn fn_none_auth_data() -> Result<Vec<u8>, FnError> {
    // "none" method has no method_data
    Ok(vec![])
}

// ── Extra scalar / edge-case atoms ───────────────────────────────────────────
//
// More alternatives per field so DY mutations have meaningful values to splice
// in (empty / oversized / boundary), not just the single value the seeds need.

pub fn fn_cookie_zeros() -> Result<[u8; 16], FnError> {
    Ok([0u8; 16])
}
pub fn fn_cookie_ff() -> Result<[u8; 16], FnError> {
    Ok([0xffu8; 16])
}
pub fn fn_username_empty() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(Vec::new()))
}
pub fn fn_username_root() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"root".to_vec()))
}
/// An oversized user name (300 bytes) for length / buffer-handling exploration.
pub fn fn_username_long() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(vec![b'A'; 300]))
}
pub fn fn_password_empty() -> Result<Vec<u8>, FnError> {
    Ok(Vec::new())
}
pub fn fn_password_long() -> Result<Vec<u8>, FnError> {
    Ok(vec![b'p'; 512])
}

// ── Identities B and C ───────────────────────────────────────────────────────
//
// Distinct credentials for credential-confusion / impersonation fuzzing. The
// harness allow-list (both PUTs) authorizes A ("user"/"test", key A) and B
// ("userb"/"testb", key B); C ("userc"/"testc", key C) is NOT authorized. The
// fuzzer swaps a username / pubkey-blob / signature across identities to try to
// make a stack authenticate the wrong pairing. See fn_client_{b,c}_pubkey_blob
// and fn_sign_userauth_{b,c} in fn_crypto.rs.
pub fn fn_username_b() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"userb".to_vec()))
}
pub fn fn_username_c() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"userc".to_vec()))
}
pub fn fn_password_b() -> Result<Vec<u8>, FnError> {
    Ok(b"testb".to_vec())
}
pub fn fn_password_c() -> Result<Vec<u8>, FnError> {
    Ok(b"testc".to_vec())
}
pub fn fn_u32_7() -> Result<u32, FnError> {
    Ok(7)
}
pub fn fn_u32_max() -> Result<u32, FnError> {
    Ok(u32::MAX)
}
/// 0x10000 — just past the typical 64 KiB channel-window / packet boundary.
pub fn fn_u32_0x10000() -> Result<u32, FnError> {
    Ok(0x10000)
}

/// RFC 4252 §7 publickey method_data, WITH signature:
///   boolean TRUE
///   string  public key algorithm name ("rsa-sha2-256")
///   string  public key blob
///   string  signature  (= string "rsa-sha2-256" || string raw signature)
pub fn fn_publickey_auth_data(
    pubkey_blob: &SshBytes,
    signature_raw: &SshBytes,
) -> Result<Vec<u8>, FnError> {
    fn push_str(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s);
    }
    let mut data = vec![0x01]; // has-signature = TRUE
    push_str(&mut data, b"rsa-sha2-256");
    push_str(&mut data, &pubkey_blob.0);
    // The signature field is itself an SSH string wrapping [algo][raw sig].
    let mut sig_blob = Vec::new();
    push_str(&mut sig_blob, b"rsa-sha2-256");
    push_str(&mut sig_blob, &signature_raw.0);
    push_str(&mut data, &sig_blob);
    Ok(data)
}

// ── Exec command payload (raw bytes for ChannelRequest with type "exec") ─────

pub fn fn_exec_payload(command: &SshBytes) -> Result<Vec<u8>, FnError> {
    // RFC 4254 §6.5: the exec request data is a single SSH string (command)
    let mut data = Vec::new();
    let len = command.0.len() as u32;
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&command.0);
    Ok(data)
}
