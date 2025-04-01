use opcua::types::OpenSecureChannelRequest;
use puffin::algebra::dynamic_function::FunctionAttributes;
use puffin::algebra::error::FnError;
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::protocol::{EvaluatedTerm, Extractable, ProtocolTypes};
use puffin::trace::{Knowledge, Source};
use puffin::{codec, dummy_codec, dummy_extract_knowledge, dummy_extract_knowledge_codec};

use crate::types::{ChannelMode, OpcuaProtocolTypes};

// We modelize as a term algebra the messages as we did in the paper.
// We use then the PUT harness for implementation details.

// // MessageSecurityMode
// impl CodecP for MessageSecurityMode {
//         /// Encode yourself by appending onto `bytes`.
//         fn encode(&self, bytes: &mut Vec<u8>){
//             let ctx_f = ContextOwned::default();
//             let ctx = ctx_f.context();
//             BinaryEncodable::encode(&self, &mut stream, &ctx).expect("Encoding failed")
//         };

//         /// Decode yourself by fiddling with the `Reader`.
//         /// Return Some if it worked, None if not.
//         fn read(_: &mut Reader) -> Option<Self>{
//             let ctx_f = ContextOwned::default();
//             let ctx = ctx_f.context();
//             Self::decode(&mut Reader, &ctx)
//         };
// }

impl Extractable<OpcuaProtocolTypes> for OpenSecureChannelRequest {
    fn extract_knowledge<'a>(
        &'a self,
        knowledges: &mut Vec<Knowledge<'a, OpcuaProtocolTypes>>,
        matcher: Option<<OpcuaProtocolTypes as ProtocolTypes>::Matcher>,
        source: &'a Source,
    ) -> Result<(), Error> {
        knowledges.push(Knowledge {
            source,
            matcher,
            data: self,
        });
        Ok(())
    }
}
// dummy_extract_knowledge_codec!(OpcuaProtocolTypes, MessageSecurityMode);

// Open Secure Channel

#[derive(Debug, Clone)]
pub struct ChannelID {
    id: u32,
}
dummy_extract_knowledge_codec!(OpcuaProtocolTypes, ChannelID);

pub fn fn_new_channel_id() -> Result<ChannelID, FnError> {
    Ok(ChannelID { id: 0 }) // 0 for a new channel request.
}
pub fn fn_channel_id(id: u32) -> Result<ChannelID, FnError> {
    Ok(ChannelID { id })
}

#[derive(Debug, Clone)]
pub struct RequestID;

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, RequestID);

pub fn fn_new_request_id() -> Result<RequestID, FnError> {
    Ok(RequestID)
}

#[derive(Debug, Clone)]
pub struct Certificate;

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, Certificate);

pub fn fn_new_certificate() -> Result<Certificate, FnError> {
    Ok(Certificate)
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, ChannelMode);

pub fn fn_mode(m: ChannelMode) -> Result<ChannelMode, FnError> {
    Ok(m)
}

#[derive(Debug, Clone)]
pub struct OpenChannelRequest {
    sc_id: ChannelID,
    mode: ChannelMode,
    payload: Vec<u8>,
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, OpenChannelRequest);

// pub fn fn_open_channel_request(
//     mode: ChannelMode
// ) -> Result<OpenSecureChannelRequest, FnError> {
//     let local_nonce: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
//     Ok(OpenSecureChannelRequest {
//         request_header: opcua_types::RequestHeader::dummy(),
//         client_protocol_version: 1,
//         request_type: opcua_types::SecurityTokenRequestType::Issue,
//         security_mode: opcua_types::MessageSecurityMode::Sign,
//         client_nonce: opcua_types::ByteString { value: Some(local_nonce)},
//         requested_lifetime: 777
//        }
//     )
// }

#[derive(Debug, Clone)]
pub struct ChannelToken;

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, ChannelToken);

pub fn fn_new_channel_token() -> Result<ChannelToken, FnError> {
    Ok(ChannelToken)
}

#[derive(Debug, Clone)]
pub struct MessageHeader {
    msg_type: [u8; 3],
    // is_final: u8,
    // msg_size: u32,
    sc_id: ChannelID,
}

#[derive(Debug, Clone)]
pub struct MessageChunk {
    msg_header: MessageHeader,
    //sec_header: SecurityHeader,
    payload: Vec<u8>,
}

dummy_extract_knowledge_codec!(OpcuaProtocolTypes, MessageChunk);

pub fn fn_message_chunk() -> Result<MessageChunk, FnError> {
    Ok(MessageChunk {
        msg_header: MessageHeader {
            msg_type: *(b"OPN"),
            // is_final: b'F',
            // msg_size: 0x15,
            sc_id: fn_new_channel_id().unwrap(),
        },
        payload: vec![0x01, 0x02, 0x03, 0x04],
    })
}
