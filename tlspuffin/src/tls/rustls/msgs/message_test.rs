use std::{
    convert::TryFrom,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use super::{
    codec::Reader,
    enums::{AlertDescription, AlertLevel, HandshakeType},
    message::{Message, OpaqueMessage, PlainMessage},
};

#[test]
fn alert_is_not_handshake() {
    let m = Message::build_alert(AlertLevel::Fatal, AlertDescription::DecodeError);
    assert!(!m.is_handshake_type(HandshakeType::ClientHello));
}

#[test]
fn alert_is_not_opaque() {
    let m = Message::build_alert(AlertLevel::Fatal, AlertDescription::DecodeError);
    assert!(Message::try_from(m).is_ok());
}

#[test]
fn construct_all_types() {
    let samples = [
        &b"\x14\x03\x04\x00\x01\x01"[..],
        &b"\x15\x03\x04\x00\x02\x01\x16"[..],
        &b"\x16\x03\x04\x00\x05\x18\x00\x00\x01\x00"[..],
        &b"\x17\x03\x04\x00\x04\x11\x22\x33\x44"[..],
        &b"\x18\x03\x04\x00\x04\x11\x22\x33\x44"[..],
    ];
    for &bytes in samples.iter() {
        let m = OpaqueMessage::read(&mut Reader::init(bytes)).unwrap();
        // println!("m = {:?}", m);
        let m = Message::try_from(m.into_plain_message());
        // println!("m' = {:?}", m);
    }
}
