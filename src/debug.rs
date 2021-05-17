use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::message::{Message, MessagePayload};

pub fn debug_message(buffer: &dyn AsRef<[u8]>) {
    debug_message_with_info("", buffer);
}

pub fn debug_message_with_info(info: &'static str, buffer: &dyn AsRef<[u8]>) {
    if let Some(mut message) = Message::read_bytes(buffer.as_ref()) {
        message.decode_payload();

        info!(
            "{}{:?} Record ({:?}): ",
            if info.is_empty() {
                info.to_string()
            } else {
                info.to_string() + " "
            },
            message.typ,
            message.version
        );
        match message.payload {
            MessagePayload::Alert(payload) => {
                trace!("Level: {:?}", payload.level);
            }
            MessagePayload::Handshake(payload) => {
                let output = format!("{:?}", payload.payload);
                trace!("{}", output);
            }
            MessagePayload::ChangeCipherSpec(_) => {}
            MessagePayload::Opaque(_) => {}
        }
    } else {
        panic!("Failed to decode message!")
    }
}
