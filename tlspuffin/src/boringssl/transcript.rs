use core::ffi::{c_char, CStr};

use boring::ssl::SslRef;
use boringssl_sys as boringssl;
use foreign_types::ForeignTypeRef;

use crate::claims::TlsTranscript;

/// Extract the current transcript hash from boringssl during the handshake
pub fn extract_current_transcript(ssl: &SslRef) -> Option<TlsTranscript> {
    let mut target: [u8; 64] = [0; 64];
    let mut s: usize = 0;
    unsafe {
        let ssl = ssl.as_ptr();
        if boringssl::PUFFIN_extract_transcript(ssl, target.as_mut_ptr(), &mut s as *mut usize) == 0
        {
            return None;
        }

        Some(TlsTranscript(target, s as i32))
    }
}
