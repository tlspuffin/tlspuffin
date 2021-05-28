use std::convert::TryFrom;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::internal::msgs::{
    codec::Codec,
    message::{Message, MessagePayload},
};

pub fn debug_binary_message(buffer: &dyn AsRef<[u8]>) {
    debug_binary_message_with_info("", buffer);
}

pub fn debug_binary_message_with_info(info: &'static str, buffer: &dyn AsRef<[u8]>) {
    let mut reader = Reader::init(buffer.as_ref());
    if let Ok(mut opaque_message) = OpaqueMessage::read(&mut reader) {
        if let Ok(mut message) = Message::try_from(opaque_message) {
            debug_message_with_info(info, &message);
        } else {
            panic!("Failed to decode message!")
        }
    } else {
        panic!("Failed to decode message!")
    }
}

pub fn debug_message(message: &Message) {
    debug_message_with_info("", message);
}

pub fn debug_opaque_message_with_info(info: &str, message: &OpaqueMessage) {
    info!(
        "{}Record ({:?}): {:?}/{:?}",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " "
        },
        message.version,
        message.typ,
        message.payload
    );
}


pub fn debug_message_with_info(info: &str, message: &Message) {
    let msg = match &message.payload {
        MessagePayload::Alert(payload) => {
            format!("Level: {:?}", payload.level)
        }
        MessagePayload::Handshake(payload) => {
            format!("{:?}", payload.payload)
        }
        MessagePayload::ChangeCipherSpec(_) => "CCS".to_string(),
        MessagePayload::ApplicationData(_) => "Data".to_string(),
    };

    info!(
        "{}Record ({:?}): {}",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " "
        },
        message.version,
        msg
    );
}
