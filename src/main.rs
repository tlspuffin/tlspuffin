mod trace;
mod variable;

use crate::trace::{ClientHelloSendStep, TraceContext};
use crate::variable::{ClientVersion, RandomVariableValue, Variable, VariableData};
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
use rustls::internal::msgs::enums::HandshakeType;
use rustls::internal::msgs::enums::ProtocolVersion::{TLSv1_2, TLSv1_3};
use rustls::internal::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionID,
};
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::ProtocolVersion;

fn main() {
    let mut ctx = TraceContext::new();
    let trace = trace::Trace {
        steps: vec![
            Box::new(ClientHelloSendStep::new(vec![])),
            Box::new(ClientHelloSendStep::new(vec![])),
        ],
    };

    let version = ClientVersion::random_value();
    let b = Box::new(version);
    ctx.add_variable(b);
    trace.execute(&ctx)
}
