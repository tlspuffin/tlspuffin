use std::mem;

use libc::{c_int, c_ulong, c_void};
use log::debug;
use security_claims::register::Claimer;
use wolfssl_sys as wolf;

use crate::wolfssl::transcript::claim_transcript;

pub unsafe extern "C" fn SSL_finished(
    _ssl: *mut wolf::WOLFSSL,
    _a: *const u8,
    _b: *const u8,
    _c: *mut u8,
    _d: *mut c_void,
) -> i32 {
    /*debug!(
        "SSL_finished {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
    0
}

pub unsafe extern "C" fn SSL_keylog13(
    _ssl: *mut wolf::WOLFSSL,
    _a: c_int,
    _b: *const u8,
    _d: c_int,
    _c: *mut c_void,
) -> i32 {
    /*match a as u32 {
        wolf::Tls13Secret_CLIENT_EARLY_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_EARLY_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_CLIENT_HANDSHAKE_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_SERVER_HANDSHAKE_TRAFFIC_SECRET => {
            info!("Tls13Secret_SERVER_HANDSHAKE_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_CLIENT_TRAFFIC_SECRET => {
            info!("Tls13Secret_CLIENT_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_SERVER_TRAFFIC_SECRET => {
            info!("Tls13Secret_SERVER_TRAFFIC_SECRET");
        }
        wolf::Tls13Secret_EARLY_EXPORTER_SECRET => {
            info!("Tls13Secret_EARLY_EXPORTER_SECRET");
        }
        wolf::Tls13Secret_EXPORTER_SECRET => {
            info!("Tls13Secret_EXPORTER_SECRET");
        }
        _ => {}
    };*/
    /*debug!(
        "SSL_keylog13 {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/

    0
}

pub unsafe extern "C" fn SSL_info(_ssl: *const wolf::WOLFSSL, _a: c_int, _b: c_int) {
    /*debug!(
        "SSL_info {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
}

pub unsafe extern "C" fn SSL_keylog(_ssl: *const wolf::WOLFSSL, _a: *const i8) {
    /*debug!(
        "SSL_keylog {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
}

pub unsafe extern "C" fn SSL_Msg_Cb(
    _write_p: c_int,
    _version: c_int,
    _content_type: c_int,
    _buf: *const c_void,
    _len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    arg: *mut c_void,
) {
    let claimer: &mut Box<Claimer> = unsafe { mem::transmute(arg) };
    claim_transcript(ssl, claimer);

    /*debug!(
        "SSL_Msg_Cb {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3),
    );*/
}

extern "C" {
    fn free(ptr: *mut c_void);
}

pub unsafe extern "C" fn SSL_connect_timeout_ex(_info: *mut wolf::TimeoutInfo) -> i32 {
    /*    for i in 0..(*info).numberPackets {
        let buffer = (*info).packets[i as usize].bufferValue;

        if !buffer.is_null() {
            free(buffer as *mut _);
        }
    }*/

    0
}

pub unsafe extern "C" fn SSL_connect_ex(_info: *mut wolf::HandShakeInfo) -> i32 {
    debug!("SSL_connect_ex");
    0
}
