use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::codec::Codec;

pub fn print_as_message(buffer: &Vec<u8>) {
    let mut message = Message::read_bytes(buffer.as_slice()).unwrap();
    message.decode_payload();
    println!("{:#?}", message);
}