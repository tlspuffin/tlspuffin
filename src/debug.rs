use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::message::{Message, MessagePayload};

pub fn debug_message(buffer: &dyn AsRef<[u8]>) {
    let mut message = Message::read_bytes(buffer.as_ref()).unwrap();
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
        MessagePayload::ChangeCipherSpec(payload) => {}
        MessagePayload::Opaque(payload) => {}
    }
}