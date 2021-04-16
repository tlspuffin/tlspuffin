use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::internal::msgs::codec::Codec;

pub fn debug_message(buffer: &Vec<u8>) {
    debug_message_raw(buffer.as_slice())
}

pub fn debug_message_raw(buffer: &[u8]) {
    let mut message = Message::read_bytes(buffer).unwrap();
    message.decode_payload();

    info!("{:?} Record ({:?}): ", message.typ, message.version);
    match message.payload {
        MessagePayload::Alert(payload) => {
            trace!("Level: {:?}", payload.level);
        }
        MessagePayload::Handshake(payload) => {
            let output = format!("{:?}", payload.payload);
            trace!("{}", output);
        }
        MessagePayload::ChangeCipherSpec(payload) => {

        }
        MessagePayload::Opaque(payload) => {

        }
    }
}