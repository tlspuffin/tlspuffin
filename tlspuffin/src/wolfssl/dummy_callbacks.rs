use std::mem;

use libc::{c_int, c_ulong, c_void};
use log::trace;
use security_claims::register::Claimer;
use wolfssl_sys as wolf;

use crate::{
    agent::TLSVersion,
    wolfssl::{transcript::claim_transcript, Ssl},
};

pub unsafe extern "C" fn SSL_finished(
    ssl: *mut wolf::WOLFSSL,
    a: *const u8,
    b: *const u8,
    c: *mut u8,
    d: *mut c_void,
) -> i32 {
    /*trace!(
        "SSL_finished {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
    0
}

pub unsafe extern "C" fn SSL_keylog13(
    ssl: *mut wolf::WOLFSSL,
    a: c_int,
    b: *const u8,
    d: c_int,
    c: *mut c_void,
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
    /*trace!(
        "SSL_keylog13 {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/

    0
}

pub unsafe extern "C" fn SSL_info(ssl: *const wolf::WOLFSSL, a: c_int, b: c_int) {
    /*trace!(
        "SSL_info {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
}

pub unsafe extern "C" fn SSL_keylog(ssl: *const wolf::WOLFSSL, a: *const i8) {
    /*trace!(
        "SSL_keylog {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3)
    );*/
}

pub unsafe extern "C" fn SSL_Msg_Cb(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: c_ulong,
    ssl: *mut wolf::WOLFSSL,
    arg: *mut c_void,
) {
    let claimer: &mut Box<Claimer> = unsafe { mem::transmute(arg) };
    claim_transcript(ssl, claimer);

    /*trace!(
        "SSL_Msg_Cb {:?}",
        Ssl::from_ptr(ssl as *mut wolf::WOLFSSL).accept_state(TLSVersion::V1_3),
    );*/
}

pub unsafe extern "C" fn SSL_connect_ex(arg1: *mut wolf::HandShakeInfo) -> i32 {
    trace!("SSL_connect_ex");
    1
}
