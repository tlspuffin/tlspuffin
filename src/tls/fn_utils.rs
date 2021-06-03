// ----
// Utils
// ----

use crate::tls::MultiMessage;
use rustls::internal::msgs::message::Message;

pub fn fn_concat_messages_2(msg1: &Message, msg2: &Message) -> MultiMessage {
    MultiMessage {
        messages: vec![msg1.clone(), msg2.clone()],
    }
}

pub fn fn_concat_messages_3(msg1: &Message, msg2: &Message, msg3: &Message) -> MultiMessage {
    MultiMessage {
        messages: vec![msg1.clone(), msg2.clone(), msg3.clone()],
    }
}
