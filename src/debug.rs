use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::internal::msgs::{
    codec::Codec,
    message::{Message, MessagePayload},
};
use std::convert::TryFrom;

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

pub fn debug_message_with_info(info: &'static str, message: &Message) {
    info!(
        "{} Record ({:?}): ",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " "
        },
        message.version
    );
    match &message.payload {
        MessagePayload::Alert(payload) => {
            trace!("Level: {:?}", payload.level);
        }
        MessagePayload::Handshake(payload) => {
            let output = format!("{:?}", payload.payload);
            trace!("{}", output);
        }
        MessagePayload::ChangeCipherSpec(_) => {}
        MessagePayload::ApplicationData(_) => {}
    }
}
