use serde::{Deserialize, Serialize};

use opcua::puffin::signature::{fn_server_hello, fn_client_hello, fn_acknowledge};
use opcua::puffin::signature::fn_impl::fn_constants::{
    fn_basic256sha256, fn_bob_cert, fn_bob_endpoint, fn_bob_sk, fn_channel_nonce_1, fn_channel_nonce_2,
    fn_default_size, fn_issue, fn_mode_none, fn_mode_sign, fn_mallory_cert, fn_mallory_sk, fn_no_bytes, fn_no_nonce, fn_null_cert,
    fn_open, fn_sa_token_zero,
    fn_security_policy_none, fn_seq_0};
use opcua::puffin::signature::fn_impl::fn_uasc::{
    fn_asym_decrypt, fn_asym_encrypt, fn_data_to_encrypt, fn_data_to_sign, fn_dummy_chunk_header, fn_client_mac_key, fn_client_open,
    fn_header, fn_mac, fn_message, fn_open_message, fn_open_header,
    fn_request, fn_request_header, fn_sequence_header, fn_sign};

use opcua::puffin::messages::{DecryptedBody, Message};
use opcua::puffin::types::{OpcuaDescriptorConfig, OpcuaProtocolTypes};

use puffin::agent::{AgentDescriptor, ProtocolDescriptorConfig};
use puffin::algebra::{Term, TermType};
use puffin::claims::GlobalClaimList;
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::protocol::ProtocolBehavior;
use puffin::put::{Put, PutOptions};
use puffin::put_registry::{Factory, PutRegistry};
use puffin::term;
use puffin::trace::{Spawner, TraceContext};

use crate::protocol::OpcuaProtocolBehavior;

#[test]
pub fn client() {

    let max_size = 32768; //fn_default_size().unwrap();
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let hello_message: Message = fn_client_hello(
         &"opc.tcp://PenDuick:53530/OPCUA/SimulationServer".as_bytes().to_vec(), //&fn_bob_endpoint().unwrap(),
        &max_size,  &max_size).unwrap();
    hello_message.encode(&mut send_buffer);
    let hello_msg : Vec<u8> = vec![
    0x48, 0x45, 0x4c, 0x46, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69,
    0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53,
    0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    //println!("hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer,  &hello_msg);
}
#[test]
pub fn server() {

    let max_size: u32 = 5000;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let reverse_message: Message = fn_server_hello(
        &"opc.tcp://PenDuick:53530".as_bytes().to_vec(), //&fn_bob_uri().unwrap(),
        &"opc.tcp://PenDuick:53530/OPCUA/SimulationServer".as_bytes().to_vec(), //&fn_bob_endpoint().unwrap()
        ).unwrap();
    reverse_message.encode(&mut send_buffer);
    let rev_hello_msg : Vec<u8> = vec![
    0x52, 0x48, 0x45, 0x46, 0x57, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
    0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35,
    0x33, 0x35, 0x33, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a,
    0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30,
    0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    // Compiler bug if the rev_hello_msg is the same as hello_msg !!??
    // println!("reverse hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer,  &rev_hello_msg);

    send_buffer.clear();
    let acknowledge_message: Message = fn_acknowledge(
        &max_size,
        &max_size).unwrap();
    acknowledge_message.encode(&mut send_buffer);
    let ack_msg : Vec<u8> = vec![
    0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00,
    0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    //println!("acknowledge: {:x?}",  send_buffer);
    assert_eq!(&send_buffer,  &ack_msg);
}


#[derive(Default, Clone, Debug, Hash, Serialize, Deserialize)]
pub struct OpcuaPUTConfig;

impl ProtocolDescriptorConfig for OpcuaPUTConfig {
    fn is_reusable_with(&self, _other: &Self) -> bool {
        false
    }
}

pub struct TestFactory;

    impl Factory<OpcuaProtocolBehavior> for TestFactory {
        fn create(
            &self,
            _agent_descriptor: &AgentDescriptor<OpcuaDescriptorConfig>,
            _claims: &GlobalClaimList<<OpcuaProtocolBehavior as ProtocolBehavior>::Claim>,
            _options: &PutOptions,
        ) -> Result<Box<dyn Put<OpcuaProtocolBehavior>>, Error> {
            panic!("Not implemented for test stub");
        }

        fn name(&self) -> String {
            String::from("TESTSTUB_RUST_PUT")
        }

        fn versions(&self) -> Vec<(String, String)> {
            vec![(
                "harness".to_string(),
                format!("{} {}", self.name(), "puffin::full_version()"),
            )]
        }

        fn supports(&self, _capability: &str) -> bool {
            false
        }

        fn clone_factory(&self) -> Box<dyn Factory<OpcuaProtocolBehavior>> {
            //Box::new(dyn Factory<OpcuaProtocolBehavior>::new())
            Box::new(TestFactory)

        }
    }

fn dummy_factory() -> Box<dyn Factory<OpcuaProtocolBehavior>> {
    Box::new(TestFactory)
}


#[test]
pub fn test_hello() {

    let hello_term: Term<OpcuaProtocolTypes> = term! {
      fn_client_hello(
        fn_bob_endpoint,
        fn_default_size,
        fn_default_size)
    };

    let registry =
       PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);
//context
//    .knowledge_store
//    .add_raw_knowledge(data, Source::Agent(AgentName::first()), None);

    let hello_message: Vec<u8> = hello_term.evaluate_symbolic(&context).unwrap();
    let hello_msg : Vec<u8> = vec![
        72,69,76,70,67,0,0,0,0,0,0,0,0,160,0,0,0,160,0,0,0,0,0,0,0,0,0,0,35,0,0,0,
        111,112,99,46,116,99,112,58,47,47,108,111,99,97,108,104,111,115,116,58,52,
        56,52,48,47,98,111,98,95,115,101,114,118,101,114];
    assert_eq!(&hello_message, &hello_msg);

    let ack_term: Term<OpcuaProtocolTypes> = term! {
      fn_acknowledge(
        fn_default_size,
        fn_default_size)
    };
    let ack_message: Vec<u8> = ack_term.evaluate_symbolic(&context).unwrap();
    let ack_msg : Vec<u8> = vec![65,67,75,70,28,0,0,0,0,0,0,0,0,160,0,0,0,160,0,0,0,0,0,0,0,0,0,0];
    assert_eq!(&ack_message,  &ack_msg);

}

#[test]
pub fn test_sign() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let data : Vec<u8> = vec!
        [63, 49, 171, 149, 4, 169, 159, 58, 127, 18, 63, 224, 191, 27, 68, 177, 108, 113, 8, 13, 186, 162, 161, 208, 88, 80, 194, 242, 0, 168, 149, 102, 85, 197, 223, 182, 138, 169, 164, 12, 141, 95, 215, 190, 175, 151, 226, 219, 97, 204, 89, 174, 127, 155, 71, 122, 96, 237, 67, 103, 143, 201, 5, 165, 146, 61, 230, 143, 234, 208, 136, 105, 173, 201, 165, 179, 249, 156, 89, 83, 5, 141, 45, 62, 117, 14, 20, 78, 214, 144, 174, 187, 60, 15, 157, 115, 28, 28, 145, 107, 153, 195, 82, 212, 167, 212, 85, 24, 96, 81, 10, 80, 222, 253, 32, 76, 156, 118, 26, 80, 217, 57, 162, 66, 211, 217, 194, 174, 116, 175, 255, 33, 240, 103, 136, 53, 120, 40, 224, 69, 42, 90, 42, 58, 151, 184, 165, 7, 252, 100, 31, 136, 152, 86, 90, 177, 118, 134, 166, 250, 150, 59, 124, 83, 58, 24, 204, 241, 35, 65, 89, 230, 101, 177, 220, 55, 162, 205, 37, 206, 38, 12, 63, 73, 43, 178, 19, 104, 140, 25, 49, 5, 120, 251, 18, 193, 215, 195, 84, 199, 205, 6, 235, 131, 166, 170, 236, 194, 201, 252, 108, 47, 70, 13, 234, 38, 151, 71, 160, 131, 159, 207, 243, 153, 62, 97, 83, 202, 196, 1, 16, 150, 17, 32, 208, 107, 60, 176, 42, 239, 252, 74, 206, 253, 87, 39, 180, 240, 116, 34, 167, 186, 231, 96, 162, 63];

    let sign_term: Term<OpcuaProtocolTypes> = term! {
        fn_sign(
            fn_bob_endpoint,
            fn_basic256sha256,
            fn_bob_cert,
            fn_bob_sk
        )
    };
    let signature: Vec<u8> = sign_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&signature,  &data);
}

#[test]
pub fn test_encrypt() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let data : Vec<u8> = vec!
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 32, 0, 0, 0, 96, 136, 65, 244, 244, 100, 47, 233, 225, 193, 23, 66, 151, 245, 47, 115, 34, 200, 125, 96, 220, 252, 162, 206, 62, 160, 115, 203, 96, 15, 105, 6, 224, 147, 4, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 52, 56, 52, 48, 47, 98, 111, 98, 95, 115, 101, 114, 118, 101, 114];

    let encrypt_term: Term<OpcuaProtocolTypes> = term! {
        fn_asym_decrypt(
            (fn_asym_encrypt(
                fn_basic256sha256,
                fn_mallory_cert,
                fn_bob_cert,
                (fn_data_to_encrypt(
                    fn_basic256sha256,
                    fn_bob_cert,
                    (fn_request(
                        (fn_sequence_header(fn_seq_0, fn_seq_0)),
                        (fn_client_open(
                            (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                            fn_issue,
                            fn_mode_sign,
                            fn_channel_nonce_1
                        ))
                    )),
                    fn_bob_endpoint
                ))
            )),
            fn_bob_sk
        )
    };
    let plain_text: Vec<u8> = encrypt_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&plain_text,  &data);
}

#[test]
pub fn test_mac() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let data : Vec<u8> = vec!
        [234, 186, 57, 182, 35, 158, 2, 226, 190, 213, 11, 11, 97, 34, 241, 225, 248, 43, 101, 241, 19, 114, 142,
        36, 213, 87, 125, 136, 56, 9, 65, 81];

    let sign_term: Term<OpcuaProtocolTypes> = term! {
        fn_mac(
            fn_bob_endpoint,
            fn_basic256sha256,
            (fn_client_mac_key(
                fn_basic256sha256,
                fn_channel_nonce_1,
                fn_channel_nonce_2
            ))
        )
    };
    let signature: Vec<u8> = sign_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&signature,  &data);
}

#[test]
pub fn test_open() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let data : Vec<u8> = vec!
        [79, 80, 78, 70, 132, 0, 0, 0, 0, 0, 0, 0, 47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 224, 147, 4, 0];


    let open_term: Term<OpcuaProtocolTypes> = term! {
        fn_open_message (
            (fn_open_header(
                (fn_header(fn_open, fn_seq_0)),
                fn_security_policy_none,
                fn_null_cert,
                fn_null_cert,
                (fn_request(
                    (fn_sequence_header(fn_seq_0, fn_seq_0)),
                    (fn_client_open(
                        (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                        fn_issue,
                        fn_mode_none,
                        fn_no_nonce
                    ))
                ))
            )),
            (fn_asym_encrypt(
                fn_security_policy_none,
                fn_null_cert,
                fn_null_cert,
                (fn_data_to_encrypt(
                    fn_security_policy_none,
                    fn_null_cert,
                    (fn_request(
                        (fn_sequence_header(fn_seq_0, fn_seq_0)),
                        (fn_client_open(
                            (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                            fn_issue,
                            fn_mode_none,
                            fn_no_nonce
                        ))
                    )),
                    fn_no_bytes
                ))
            ))
        )
    };
    let open: Vec<u8> = open_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&open,  &data);
}

#[test]
pub fn test_dummy_header() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let data : Vec<u8> = vec!
        [77, 83, 71, 70, 12, 0, 0, 0, 0, 0, 0, 0];


    let dummy_term: Term<OpcuaProtocolTypes> = term! {
        fn_dummy_chunk_header()
    };
    let header: Vec<u8> = dummy_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&header,  &data);
}
