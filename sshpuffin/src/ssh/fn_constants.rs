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
pub fn fn_channel_session() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(b"session".to_vec()))
}

// ── A non-empty placeholder for ECDH keys / opaque byte blobs ───────────────
//
// 32 bytes of non-zero data so the fuzzer can build a KexEcdhInit that passes
// the "empty key" guard in libssh and reaches the actual key-validation logic.

pub fn fn_placeholder_32bytes() -> Result<SshBytes, FnError> {
    Ok(SshBytes::new(vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20,
    ]))
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

// ── Exec command payload (raw bytes for ChannelRequest with type "exec") ─────

pub fn fn_exec_payload(command: &SshBytes) -> Result<Vec<u8>, FnError> {
    // RFC 4254 §6.5: the exec request data is a single SSH string (command)
    let mut data = Vec::new();
    let len = command.0.len() as u32;
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&command.0);
    Ok(data)
}
