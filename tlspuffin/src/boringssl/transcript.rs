use boring::ssl::SslRef;
use boringssl_sys as boringssl;
use core::ffi::{c_char, CStr};
use foreign_types::ForeignTypeRef;

use crate::claims::TlsTranscript;

/// Extract the current transcript hash and actual state from boringssl during
/// the handshake
pub fn extract_current_transcript(ssl: &SslRef) -> Option<(TlsTranscript, String)> {
    let mut target: [u8; 64] = [0; 64];
    let mut s: usize = 0;
    unsafe {
        let ssl = ssl.as_ptr();
        if boringssl::PUFFIN_extract_transcript(ssl, target.as_mut_ptr(), &mut s as *mut usize) == 0
        {
            return None;
        }

        let status: *const c_char = boringssl::PUFFIN_get_server_handshake_state(ssl);
        let status_str = ptr_to_string(status);

        Some((TlsTranscript(target, s as i32), status_str))
    }
}

fn ptr_to_string(ptr: *const c_char) -> String {
    // Convert the *const c_char pointer to a *const u8 pointer
    let ptr_u8: *const u8 = ptr as *const u8;
    // Dereference the *const u8 pointer to get a slice of bytes
    let bytes = unsafe { std::slice::from_raw_parts(ptr_u8, CStr::from_ptr(ptr).to_bytes().len()) };
    String::from_utf8(bytes.to_vec()).unwrap()
}
