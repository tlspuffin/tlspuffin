use std::convert::TryFrom;

use rustls::msgs::codec::Reader;
use rustls::msgs::message::{Message, MessagePayload};
use rustls::msgs::message::{OpaqueMessage};

pub fn debug_binary_message(buffer: &dyn AsRef<[u8]>) {
    debug_binary_message_with_info("", buffer);
}

pub fn debug_binary_message_with_info(info: &'static str, buffer: &dyn AsRef<[u8]>) {
    let mut reader = Reader::init(buffer.as_ref());
    match OpaqueMessage::read(&mut reader) {
        Ok(opaque_message) => match Message::try_from(opaque_message.into_plain_message()) {
            Ok(message) => {
                debug_message_with_info(info, &message.try_into().unwrap());
            }
            Err(err) => {
                trace!(
                    "Failed to debug message as decoding to an Message failed: {}",
                    err
                );
            }
        },
        Err(err) => {
            trace!(
                "Failed to debug message as decoding to an OpaqueMessage failed: {:?}",
                err
            );
        }
    }
}

pub fn debug_message(message: &Message) {
    debug_message_with_info("", message);
}

pub fn debug_opaque_message_with_info(info: &str, message: &OpaqueMessage) {
    trace!(
        "{}Opaque Message  ({} bytes) ({:?}): {:?}",
        if info.is_empty() {
            info.to_string()
        } else {
            info.to_string() + " | "
        },
        message.clone().encode().len(),
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
        MessagePayload::TLS12EncryptedHandshake(_) => "TLS12EncryptedHandshake".to_string(),
        MessagePayload::ChangeCipherSpec(_) => "ChangeCipherSpec".to_string(),
        MessagePayload::ApplicationData(_) => "ApplicationData".to_string(),
        MessagePayload::Heartbeat(_) => "Heartbeat".to_string(),
    };

    trace!(
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
