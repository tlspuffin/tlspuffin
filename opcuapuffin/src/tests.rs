use opcua::puffin::messages::Message;
use opcua::puffin::signature::fn_impl::fn_constants::{
    fn_basic256sha256, fn_bob_cert, fn_bob_endpoint, fn_bob_sk, fn_channel_nonce_1,
    fn_channel_nonce_2, fn_default_size, fn_issue, fn_mallory_cert, fn_mallory_sk, fn_mode_none,
    fn_mode_sign, fn_no_bytes, fn_no_nonce, fn_null_cert, fn_open, fn_sa_token_zero, fn_security_policy_none,
    fn_seq_0, fn_tcp_1,
};
use opcua::puffin::signature::fn_impl::fn_uasc::{
    fn_asym_decrypt, fn_asym_encrypt, fn_asym_header, fn_client_mac_key, fn_client_open,
    fn_data_to_encrypt, fn_data_to_sign, fn_decrypted_body, fn_header, fn_mac, fn_open_header, fn_open_message,
    fn_request_header, fn_sequence_header, fn_service, fn_sign,
};
use opcua::puffin::signature::{fn_acknowledge, fn_client_hello, fn_server_hello};
use opcua::puffin::types::{ApplicationConfig, OpcuaProtocolTypes};
use opcua::types::UAString;
use puffin::agent::{AgentDescriptor, ProtocolDescriptorConfig};
use puffin::algebra::{Term, TermType};
use puffin::claims::GlobalClaimList;
use puffin::codec::CodecP;
use puffin::error::Error;
use puffin::protocol::ProtocolBehavior;
use puffin::put::{Put, PutDescriptor, PutOptions};
use puffin::put_registry::{Factory, PutRegistry};
use puffin::term;
use puffin::trace::{Spawner, TraceContext};
use serde::{Deserialize, Serialize};

use crate::protocol::OpcuaProtocolBehavior;

#[test]
pub fn client_hello() {
    let max_size = 32768;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let hello_message: Message = fn_client_hello(
        &01,
        &UAString::from("opc.tcp://PenDuick:53530/OPCUA/SimulationServer"),
        &max_size,
        &max_size,
    )
    .unwrap();
    hello_message.encode(&mut send_buffer);
    let right: Vec<u8> = vec![
        01, 0x48, 0x45, 0x4c, 0x46, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f,
        0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65,
        0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50,
        0x43, 0x55, 0x41, 0x2f, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53,
        0x65, 0x72, 0x76, 0x65, 0x72,
    ];
    //println!("hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer, &right);
}
#[test]
pub fn server_hello() {
    let max_size: u32 = 5000;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let reverse_message: Message = fn_server_hello(
        &01,
        &UAString::from("opc.tcp://PenDuick:53530"),
        &UAString::from("opc.tcp://PenDuick:53530/OPCUA/SimulationServer"),
    )
    .unwrap();
    reverse_message.encode(&mut send_buffer);
    let rev_hello_msg: Vec<u8> = vec![
        01, 0x52, 0x48, 0x45, 0x46, 0x57, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70,
        0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63,
        0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
        0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a,
        0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53, 0x69, 0x6d,
        0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
    ];
    // Compiler bug if the rev_hello_msg is the same as hello_msg !!??
    // println!("reverse hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer, &rev_hello_msg);

    send_buffer.clear();
    let acknowledge_message: Message = fn_acknowledge(&01, &max_size, &max_size).unwrap();
    acknowledge_message.encode(&mut send_buffer);
    let ack_msg: Vec<u8> = vec![
        01, 0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x13,
        0x00, 0x00, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    //println!("acknowledge: {:x?}",  send_buffer);
    assert_eq!(&send_buffer, &ack_msg);
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
        _agent_descriptor: &AgentDescriptor<ApplicationConfig>,
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
        fn_tcp_1,
        fn_bob_endpoint,
        fn_default_size,
        fn_default_size)
    };

    let registry = PutRegistry::<OpcuaProtocolBehavior>::new(
        [("teststub", dummy_factory())],
        PutDescriptor::new("teststub", PutOptions::empty()),
    );
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let hello_message: Vec<u8> = hello_term.evaluate_symbolic(&context).unwrap();
    let hello_msg: Vec<u8> = vec![
        01, 72, 69, 76, 70, 72, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 40, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104,
        111, 115, 116, 58, 52, 56, 52, 48, 47, 111, 112, 99, 117, 97, 112, 117, 102, 102, 105, 110,
        46, 98, 111, 98,
    ];
    assert_eq!(&hello_message, &hello_msg);

    let ack_term: Term<OpcuaProtocolTypes> = term! {
      fn_acknowledge(
        fn_tcp_1,
        fn_default_size,
        fn_default_size)
    };
    let ack_message: Vec<u8> = ack_term.evaluate_symbolic(&context).unwrap();
    let ack_msg: Vec<u8> = vec![
        01, 65, 67, 75, 70, 28, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    assert_eq!(&ack_message, &ack_msg);
}

#[test]
pub fn test_sign() {
    let registry = PutRegistry::<OpcuaProtocolBehavior>::new(
        [("teststub", dummy_factory())],
        PutDescriptor::new("teststub", PutOptions::empty()),
    );
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec![
        95, 185, 108, 80, 56, 115, 129, 97, 93, 50, 143, 193, 208, 66, 146, 225, 231, 67, 106, 152,
        147, 180, 116, 142, 192, 226, 143, 164, 55, 221, 26, 195, 153, 72, 103, 37, 221, 98, 26,
        118, 78, 104, 240, 151, 180, 95, 125, 14, 33, 1, 228, 58, 223, 109, 42, 230, 37, 60, 247,
        173, 179, 118, 84, 110, 35, 111, 255, 108, 179, 204, 203, 65, 6, 135, 36, 161, 48, 196,
        237, 134, 138, 90, 168, 26, 136, 248, 12, 76, 247, 105, 184, 240, 196, 154, 37, 122, 223,
        33, 126, 65, 90, 188, 222, 208, 204, 143, 199, 254, 192, 27, 160, 88, 36, 132, 34, 250, 11,
        145, 22, 47, 34, 35, 55, 146, 223, 211, 49, 228, 149, 49, 195, 101, 226, 137, 96, 178, 67,
        152, 92, 215, 27, 80, 69, 214, 137, 6, 199, 243, 112, 250, 224, 70, 72, 236, 41, 185, 9,
        202, 127, 4, 66, 85, 42, 41, 1, 96, 104, 77, 89, 205, 203, 255, 98, 121, 5, 150, 173, 107,
        149, 221, 55, 45, 114, 185, 222, 151, 187, 158, 115, 227, 21, 66, 82, 123, 10, 251, 51,
        239, 56, 177, 166, 9, 76, 130, 228, 218, 237, 24, 203, 239, 172, 214, 187, 148, 242, 27,
        175, 151, 1, 130, 93, 22, 157, 182, 86, 160, 239, 201, 111, 41, 118, 232, 117, 151, 154,
        55, 0, 249, 210, 6, 95, 138, 23, 203, 86, 167, 22, 198, 210, 179, 193, 232, 165, 165, 23,
        6,
    ];

    let sign_term: Term<OpcuaProtocolTypes> = term! {
        fn_sign(
            fn_bob_sk,
            fn_basic256sha256,
            fn_bob_cert,
            fn_bob_sk
        )
    };
    let signature: Vec<u8> = sign_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&signature, &right);
}

#[test]
pub fn test_encrypt() {
    let registry = PutRegistry::<OpcuaProtocolBehavior>::new(
        [("teststub", dummy_factory())],
        PutDescriptor::new("teststub", PutOptions::empty()),
    );
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0, 128, 192, 12, 163, 36, 93, 220, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 32, 0, 0, 0, 96, 136, 65, 244, 244, 100, 47, 233, 225, 193, 23, 66, 151, 245, 47, 115, 34, 200, 125, 96, 220, 252, 162, 206, 62, 160, 115, 203, 96, 15, 105, 6, 224, 147, 4, 0, 155, 6, 160, 166, 5, 242, 156, 33, 100, 51, 101, 225, 14, 63, 42, 69, 57, 212, 91, 128, 236, 32, 108, 160, 86, 89, 19, 254, 78, 234, 195, 62, 69, 58, 78, 28, 10, 46, 110, 67, 11, 140, 127, 199, 37, 26, 73, 145, 143, 199, 178, 203, 26, 177, 53, 91, 52, 82, 183, 180, 39, 10, 127, 108, 122, 158, 139, 118, 253, 147, 31, 22, 119, 235, 112, 70, 84, 237, 19, 206, 226, 146, 131, 27, 228, 194, 50, 72, 17, 31, 150, 210, 161, 119, 224, 96, 106, 204, 79, 51, 4, 47, 37, 182, 53, 116, 226, 167, 16, 119, 134, 155, 48, 106, 3, 83, 15, 139, 87, 178, 0, 93, 193, 40, 34, 153, 74, 135, 146, 207, 177, 24, 22, 180, 90, 152, 144, 112, 250, 128, 13, 251, 201, 170, 69, 159, 72, 103, 132, 248, 165, 147, 176, 31, 62, 73, 235, 235, 156, 33, 98, 62, 82, 238, 242, 168, 18, 32, 161, 240, 116, 123, 75, 235, 65, 239, 227, 188, 2, 108, 206, 51, 239, 157, 42, 129, 88, 180, 227, 60, 250, 209, 80, 139, 221, 250, 227, 233, 103, 159, 150, 189, 182, 244, 152, 110, 241, 29, 173, 89, 83, 206, 199, 191, 18, 220, 109, 128, 225, 122, 253, 48, 59, 32, 241, 252, 85, 15, 103, 57, 184, 123, 239, 255, 165, 0, 197, 87, 242, 170, 97, 130, 181, 45, 195, 174, 171, 62, 3, 239, 248, 167, 0, 39, 223, 32
    ];

    let encrypt_term: Term<OpcuaProtocolTypes> = term! {
        fn_decrypted_body(
            (fn_asym_decrypt(
                fn_basic256sha256,
                (fn_asym_encrypt(
                    fn_basic256sha256,
                    fn_bob_cert,
                    (fn_data_to_encrypt(
                        fn_basic256sha256,
                        fn_bob_cert,
                        fn_service(
                            (fn_sequence_header(fn_seq_0, fn_seq_0)),
                            (fn_client_open(
                                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                fn_issue,
                                fn_mode_sign,
                                fn_channel_nonce_1
                            ))
                        ),
                        (fn_sign(
                            (fn_data_to_sign(
                                (fn_open_header(
                                    (fn_header(fn_open, fn_seq_0)),
                                    fn_basic256sha256,
                                    fn_mallory_cert,
                                    fn_bob_cert,
                                    fn_service(
                                        (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                        (fn_client_open(
                                            (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                            fn_issue,
                                            fn_mode_sign,
                                            fn_channel_nonce_1
                                        ))
                                    )
                                )),
                                fn_basic256sha256,
                                fn_mallory_cert,
                                fn_bob_cert,
                                fn_service(
                                    (fn_sequence_header(fn_seq_0, fn_seq_0)),
                                    (fn_client_open(
                                        (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                        fn_issue,
                                        fn_mode_sign,
                                        fn_channel_nonce_1
                                    ))
                                )
                            )),
                            fn_basic256sha256,
                            fn_mallory_cert,
                            fn_mallory_sk
                        ))
                   ))
                )),
                fn_bob_sk
            )),
            fn_bob_sk
        )
    };
    let plain_text: Vec<u8> = encrypt_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&plain_text, &right);
}

#[test]
pub fn test_mac() {
    let registry = PutRegistry::<OpcuaProtocolBehavior>::new(
        [("teststub", dummy_factory())],
        PutDescriptor::new("teststub", PutOptions::empty()),
    );
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec![
        71, 130, 161, 99, 131, 114, 86, 118, 87, 84, 226, 91, 234, 114, 151, 195, 14, 132, 155,
        130, 220, 115, 161, 136, 37, 185, 11, 33, 55, 215, 111, 136,
    ];

    let sign_term: Term<OpcuaProtocolTypes> = term! {
        fn_mac(
            fn_bob_sk,
            fn_basic256sha256,
            (fn_client_mac_key(
                fn_basic256sha256,
                fn_channel_nonce_1,
                fn_channel_nonce_2
            ))
        )
    };
    let signature: Vec<u8> = sign_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&signature, &right);
}

#[test]
pub fn test_open() {
    let registry = PutRegistry::<OpcuaProtocolBehavior>::new(
        [("teststub", dummy_factory())],
        PutDescriptor::new("teststub", PutOptions::empty()),
    );
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec![
        01, 79, 80, 78, 70, 132, 0, 0, 0, 0, 0, 0, 0, 47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47,
        111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85,
        65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110,
        101, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0,
        128, 192, 12, 163, 36, 93, 220, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 224, 147, 4, 0,
    ];

    let open_term: Term<OpcuaProtocolTypes> = term! {
        fn_open_message(
            fn_tcp_1,
            (fn_open_header(
                (fn_header(fn_open, fn_seq_0)),
                fn_security_policy_none,
                fn_null_cert,
                fn_null_cert,
                (fn_service(
                    (fn_sequence_header(fn_seq_0, fn_seq_0)),
                    (fn_client_open(
                        (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                        fn_issue,
                        fn_mode_none,
                        fn_no_nonce
                    ))
                ))
            )),
            (fn_asym_header(
                fn_security_policy_none,
                fn_null_cert,
                fn_null_cert
            )),
            (fn_asym_encrypt(
                fn_security_policy_none,
                fn_null_cert,
                (fn_data_to_encrypt(
                    fn_security_policy_none,
                    fn_null_cert,
                    (fn_service(
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
    assert_eq!(&open, &right);
}
