use std::convert::TryFrom;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::internal::msgs::message::{Message, MessagePayload};

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
        "{}Opaque Message ({:?}): {:?}",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " | "
        },
        message.version,
        message.typ,
    );
    //info!("{:?}", hexdump::hexdump(message.payload.0.as_slice()))
}

pub fn debug_message_with_info(info: &str, message: &Message) {
    let msg = match &message.payload {
        MessagePayload::Alert(payload) => {
            format!("Alert with Level: {:?}", payload.level)
        }
        MessagePayload::Handshake(payload) => {
            format!("{:?}", payload.payload)
        }
        MessagePayload::ChangeCipherSpec(_) => "ChangeCipherSpec".to_string(),
        MessagePayload::ApplicationData(_) => "ApplicationData".to_string(),
    };

    info!(
        "{}Message ({:?}): {}",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " | "
        },
        message.version,
        msg
    );
}
