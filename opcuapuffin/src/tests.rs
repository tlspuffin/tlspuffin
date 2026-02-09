use opcua::types::UAString;
use serde::{Deserialize, Serialize};

use opcua::puffin::signature::{fn_server_hello, fn_client_hello, fn_acknowledge};
use opcua::puffin::signature::fn_impl::fn_constants::{
    fn_basic256sha256, fn_bob_cert, fn_bob_endpoint, fn_bob_sk, fn_channel_nonce_1, fn_channel_nonce_2,
    fn_default_size, fn_issue, fn_mode_none, fn_mode_sign, fn_no_bytes, fn_no_nonce, fn_null_cert,
    fn_open, fn_sa_token_zero,
    fn_security_policy_none, fn_seq_0};
use opcua::puffin::signature::fn_impl::fn_uasc::{
    fn_asym_decrypt, fn_asym_encrypt, fn_asym_header, fn_data_to_encrypt, fn_client_mac_key, fn_client_open, fn_decrypted_body,
    fn_header, fn_mac, fn_open_message, fn_open_header, fn_request_header,
    fn_sequence_header, fn_service, fn_sign};

use opcua::puffin::messages::Message;
use opcua::puffin::types::{ApplicationConfig, OpcuaProtocolTypes};

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
pub fn client_hello() {

    let max_size = 32768;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let hello_message: Message = fn_client_hello(
         &UAString::from("opc.tcp://PenDuick:53530/OPCUA/SimulationServer"),
        &max_size,  &max_size).unwrap();
    hello_message.encode(&mut send_buffer);
    let right: Vec<u8> = vec![
    0x48, 0x45, 0x4c, 0x46, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69,
    0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53,
    0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    //println!("hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer,  &right);
}
#[test]
pub fn server_hello() {

    let max_size: u32 = 5000;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let reverse_message: Message = fn_server_hello(
        &UAString::from("opc.tcp://PenDuick:53530"),
        &UAString::from("opc.tcp://PenDuick:53530/OPCUA/SimulationServer"),
        ).unwrap();
    reverse_message.encode(&mut send_buffer);
    let rev_hello_msg: Vec<u8> = vec![
    0x52, 0x48, 0x45, 0x46, 0x57, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
    0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35,
    0x33, 0x35, 0x33, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a,
    0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30,
    0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    // Compiler bug if the rev_hello_msg is the same as hello_msg !!??
    // println!("reverse hello: {:x?}",  send_buffer);
    assert_eq!(&send_buffer, &rev_hello_msg);

    send_buffer.clear();
    let acknowledge_message: Message = fn_acknowledge(
        &max_size,
        &max_size).unwrap();
    acknowledge_message.encode(&mut send_buffer);
    let ack_msg: Vec<u8> = vec![
    0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00,
    0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
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
        fn_bob_endpoint,
        fn_default_size,
        fn_default_size)
    };

    let registry =
       PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let hello_message: Vec<u8> = hello_term.evaluate_symbolic(&context).unwrap();
    let hello_msg : Vec<u8> = vec![
        72,69,76,70,72,0,0,0,0,0,0,0,0,160,0,0,0,160,0,0,0,0,0,0,0,0,0,0,40,0,0,0,
        111,112,99,46,116,99,112,58,47,47,108,111,99,97,108,104,111,115,116,58,52,
        56,52,48,47,111,112,99,117,97,112,117,102,102,105,110,46,98,111,98];
    assert_eq!(&hello_message, &hello_msg);

    let ack_term: Term<OpcuaProtocolTypes> = term! {
      fn_acknowledge(
        fn_default_size,
        fn_default_size)
    };
    let ack_message: Vec<u8> = ack_term.evaluate_symbolic(&context).unwrap();
    let ack_msg: Vec<u8> = vec![65,67,75,70,28,0,0,0,0,0,0,0,0,160,0,0,0,160,0,0,0,0,0,0,0,0,0,0];
    assert_eq!(&ack_message, &ack_msg);

}

#[test]
pub fn test_sign() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec!
        [95, 185, 108, 80, 56, 115, 129, 97, 93, 50, 143, 193, 208, 66, 146, 225, 231, 67, 106, 152, 147, 180, 116, 142, 192, 226, 143, 164, 55, 221, 26, 195, 153, 72, 103, 37, 221, 98, 26, 118, 78, 104, 240, 151, 180, 95, 125, 14, 33, 1, 228, 58, 223, 109, 42, 230, 37, 60, 247, 173, 179, 118, 84, 110, 35, 111, 255, 108, 179, 204, 203, 65, 6, 135, 36, 161, 48, 196, 237, 134, 138, 90, 168, 26, 136, 248, 12, 76, 247, 105, 184, 240, 196, 154, 37, 122, 223, 33, 126, 65, 90, 188, 222, 208, 204, 143, 199, 254, 192, 27, 160, 88, 36, 132, 34, 250, 11, 145, 22, 47, 34, 35, 55, 146, 223, 211, 49, 228, 149, 49, 195, 101, 226, 137, 96, 178, 67, 152, 92, 215, 27, 80, 69, 214, 137, 6, 199, 243, 112, 250, 224, 70, 72, 236, 41, 185, 9, 202, 127, 4, 66, 85, 42, 41, 1, 96, 104, 77, 89, 205, 203, 255, 98, 121, 5, 150, 173, 107, 149, 221, 55, 45, 114, 185, 222, 151, 187, 158, 115, 227, 21, 66, 82, 123, 10, 251, 51, 239, 56, 177, 166, 9, 76, 130, 228, 218, 237, 24, 203, 239, 172, 214, 187, 148, 242, 27, 175, 151, 1, 130, 93, 22, 157, 182, 86, 160, 239, 201, 111, 41, 118, 232, 117, 151, 154, 55, 0, 249, 210, 6, 95, 138, 23, 203, 86, 167, 22, 198, 210, 179, 193, 232, 165, 165, 23, 6];

    let sign_term: Term<OpcuaProtocolTypes> = term! {
        fn_sign(
            fn_bob_sk,
            fn_basic256sha256,
            fn_bob_cert,
            fn_bob_sk
        )
    };
    let signature: Vec<u8> = sign_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&signature,  &right);
}

#[test]
pub fn test_encrypt() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec!
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0, 128, 192, 12, 163, 36, 93, 220, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 32, 0, 0, 0, 96, 136, 65, 244, 244, 100, 47, 233, 225, 193, 23, 66, 151, 245, 47, 115, 34, 200, 125, 96, 220, 252, 162, 206, 62, 160, 115, 203, 96, 15, 105, 6, 224, 147, 4, 0, 48, 130, 4, 190, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130, 4, 168, 48, 130, 4, 164, 2, 1, 0, 2, 130, 1, 1, 0, 207, 210, 185, 167, 147, 80, 1, 140, 128, 89, 102, 1, 208, 212, 25, 55, 128, 180, 148, 47, 119, 115, 1, 176, 160, 31, 167, 202, 241, 149, 136, 20, 71, 55, 164, 88, 110, 245, 67, 190, 217, 230, 83, 38, 54, 44, 84, 231, 171, 96, 93, 27, 122, 129, 17, 47, 165, 29, 133, 227, 220, 7, 132, 51, 180, 90, 190, 44, 255, 125, 89, 206, 102, 131, 231, 134, 227, 149, 244, 20, 112, 13, 138, 205, 173, 255, 54, 137, 30, 236, 226, 92, 97, 242, 216, 36, 89, 156, 239, 237, 91, 40, 54, 8, 5, 233, 37, 208, 244, 43, 15, 1, 203, 67, 196, 119, 225, 84, 117, 97, 169, 81, 81, 49, 3, 169, 77, 201, 163, 148, 151, 98, 99, 204, 183, 212, 145, 146, 178, 251, 3, 52, 128, 251, 149, 47, 193, 202, 34, 211, 239, 100, 248, 76, 89, 45, 229, 43, 15, 154, 175, 101, 179, 170, 252, 202, 82, 70, 216, 86, 239, 104, 44, 247, 230, 84, 223, 173, 239, 199, 122, 157, 106, 197, 123, 23, 115, 118, 218, 89, 63, 47, 202, 106, 66, 181, 144, 18, 244, 41, 241, 41, 50, 39, 164, 81, 66, 245, 56, 208, 247, 96, 159, 140, 11, 71, 202, 89, 108, 29, 129, 142, 223, 209, 55, 15, 179, 31, 234, 130, 88, 132, 16, 72, 100, 126, 134, 196, 227, 98, 190, 4, 80, 244, 103, 235, 119, 68, 18, 195, 139, 57, 139, 233, 90, 61, 2, 3, 1, 0, 1, 2, 130, 1, 0, 5, 176, 51, 120, 73, 86, 35, 17, 132, 7, 110, 99, 137, 34, 85, 11, 246, 118, 122, 219, 220, 36, 31, 233, 234, 180, 223, 231, 116, 84, 34, 11, 45, 165, 113, 163, 135, 157, 244, 245, 188, 240, 177, 39, 35, 50, 116, 162, 224, 71, 93, 37, 10, 204, 89, 45, 224, 18, 23, 204, 71, 107, 172, 114, 120, 63, 122, 202, 73, 182, 86, 6, 86, 212, 99, 109, 186, 87, 197, 201, 26, 56, 219, 17, 139, 85, 219, 140, 224, 15, 56, 50, 25, 33, 212, 175, 123, 158, 214, 164, 189, 30, 51, 164, 101, 198, 158, 127, 92, 63, 136, 170, 56, 129, 118, 36, 153, 15, 178, 36, 102, 95, 208, 106, 229, 160, 142, 227, 218, 90, 237, 202, 62, 122, 189, 246, 32, 182, 131, 84, 90, 141, 191, 233, 228, 192, 137, 196, 206, 64, 71, 34, 192, 155, 250, 105, 167, 244, 239, 108, 206, 143, 85, 128, 28, 114, 14, 222, 94, 188, 23, 136, 146, 55, 199, 163, 49, 233, 96, 252, 38, 205, 173, 73, 201, 99, 75, 75, 6, 190, 13, 132, 33, 27, 158, 99, 233, 87, 179, 20, 76, 140, 19, 162, 189, 239, 179, 109, 92, 18, 158, 69, 53, 254, 248, 86, 68, 35, 160, 78, 56, 21, 150, 13, 44, 191, 60, 17, 173, 137, 123, 223, 13, 23, 80, 85, 241, 1, 64, 39, 29, 111, 34, 185, 232, 251, 40, 61, 242, 59, 68, 69, 87, 119, 78, 13, 2, 129, 129, 0, 243, 142, 163, 16, 204, 12, 179, 233, 52, 59, 39, 40, 206, 195, 80, 121, 176, 224, 165, 253, 53, 232, 215, 206, 190, 202, 58, 46, 252, 50, 208, 52, 230, 124, 164, 5, 170, 253, 149, 5, 144, 14, 187, 116, 149, 195, 88, 54, 7, 89, 84, 88, 50, 95, 43, 103, 28, 186, 153, 146, 254, 192, 0, 181, 188, 157, 137, 179, 206, 143, 133, 74, 156, 222, 59, 67, 87, 70, 98, 181, 195, 152, 131, 33, 31, 160, 13, 173, 207, 208, 54, 59, 2, 228, 157, 138, 5, 183, 121, 135, 70, 87, 100, 147, 130, 112, 62, 83, 133, 139, 118, 98, 53, 72, 158, 28, 136, 25, 246, 40, 38, 145, 98, 188, 44, 136, 40, 151, 2, 129, 129, 0, 218, 112, 189, 155, 42, 132, 215, 32, 55, 22, 191, 128, 165, 116, 235, 65, 169, 71, 47, 92, 60, 94, 147, 248, 202, 102, 183, 133, 250, 141, 164, 158, 84, 133, 126, 208, 58, 29, 25, 113, 176, 189, 92, 121, 38, 46, 214, 181, 84, 104, 219, 214, 75, 111, 149, 186, 221, 101, 29, 242, 134, 18, 190, 2, 36, 113, 7, 130, 104, 95, 112, 3, 169, 17, 123, 83, 217, 156, 5, 102, 227, 197, 16, 88, 31, 100, 151, 230, 1, 117, 108, 137, 164, 131, 20, 47, 230, 238, 171, 236, 40, 17, 191, 153, 253, 64, 112, 197, 88, 13, 114, 139, 86, 227, 235, 199, 143, 161, 213, 170, 160, 61, 231, 54, 20, 238, 250, 75, 2, 129, 128, 111, 65, 123, 233, 163, 92, 54, 30, 212, 22, 37, 88, 53, 194, 240, 146, 246, 34, 88, 144, 167, 60, 154, 192, 61, 85, 1, 105, 15, 25, 99, 20, 151, 40, 222, 128, 28, 80, 195, 239, 11, 148, 63, 59, 13, 98, 115, 124, 18, 181, 82, 155, 11, 63, 128, 3, 21, 19, 132, 45, 170, 163, 40, 111, 220, 30, 22, 150, 5, 72, 120, 57, 210, 24, 141, 247, 191, 249, 78, 3, 251, 186, 66, 68, 50, 63, 25, 160, 137, 42, 114, 107, 88, 113, 248, 40, 225, 93, 163, 109, 16, 203, 193, 12, 196, 235, 226, 252, 162, 39, 71, 199, 170, 209, 102, 48, 96, 87, 131, 163, 105, 162, 197, 248, 113, 91, 45, 55, 2, 129, 129, 0, 165, 65, 247, 224, 37, 9, 188, 234, 237, 98, 115, 92, 243, 80, 2, 15, 121, 238, 149, 224, 244, 247, 36, 129, 107, 54, 204, 143, 58, 223, 223, 243, 188, 196, 6, 13, 168, 121, 141, 95, 90, 179, 215, 250, 251, 173, 33, 216, 171, 84, 109, 68, 177, 107, 104, 222, 167, 82, 49, 150, 226, 97, 217, 136, 43, 99, 171, 167, 184, 40, 195, 200, 177, 38, 189, 163, 209, 20, 221, 109, 90, 210, 34, 172, 88, 139, 180, 243, 88, 149, 42, 152, 243, 114, 11, 90, 182, 30, 72, 200, 240, 3, 133, 110, 13, 143, 172, 1, 80, 189, 83, 180, 32, 247, 107, 208, 93, 84, 181, 30, 81, 254, 163, 38, 98, 45, 238, 3, 2, 129, 129, 0, 177, 48, 205, 50, 248, 78, 21, 46, 234, 64, 210, 167, 33, 244, 196, 155, 165, 246, 165, 111, 31, 154, 147, 207, 94, 172, 141, 146, 14, 67, 216, 193, 7, 247, 150, 181, 141, 67, 81, 183, 178, 124, 124, 251, 46, 195, 100, 128, 152, 230, 95, 3, 125, 1, 64, 114, 158, 195, 67, 107, 144, 76, 151, 90, 222, 30, 213, 93, 137, 232, 228, 185, 9, 101, 228, 212, 138, 10, 172, 184, 222, 51, 118, 116, 66, 14, 13, 165, 226, 165, 84, 52, 27, 173, 232, 88, 138, 226, 162, 242, 165, 138, 165, 41, 12, 249, 10, 155, 33, 68, 216, 65, 133, 8, 50, 237, 61, 129, 111, 89, 154, 143, 99, 180, 131, 101, 7, 241];

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
                        (fn_service(
                            (fn_sequence_header(fn_seq_0, fn_seq_0)),
                            (fn_client_open(
                                (fn_request_header(fn_sa_token_zero, fn_seq_0)),
                                fn_issue,
                                fn_mode_sign,
                                fn_channel_nonce_1
                            ))
                        )),
                        fn_bob_sk
                    ))
                )),
                fn_bob_sk
            )),
            fn_bob_sk
        )
    };
    let plain_text: Vec<u8> = encrypt_term.evaluate_symbolic(&context).unwrap();
    assert_eq!(&plain_text,  &right);
}

#[test]
pub fn test_mac() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec!
        [71, 130, 161, 99, 131, 114, 86, 118, 87, 84, 226, 91, 234, 114, 151, 195, 14, 132, 155, 130, 220, 115, 161, 136, 37, 185, 11, 33, 55, 215, 111, 136];

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
    assert_eq!(&signature,  &right);
}

#[test]
pub fn test_open() {

    let registry =
        PutRegistry::<OpcuaProtocolBehavior>::new([("teststub", dummy_factory())], "teststub");
    let spawner = Spawner::new(registry);
    let context = TraceContext::new(spawner);

    let right: Vec<u8> = vec!
        [79, 80, 78, 70, 132, 0, 0, 0, 0, 0, 0, 0, 47, 0, 0, 0, 104, 116, 116, 112, 58, 47, 47, 111, 112, 99, 102, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 111, 114, 103, 47, 85, 65, 47, 83, 101, 99, 117, 114, 105, 116, 121, 80, 111, 108, 105, 99, 121, 35, 78, 111, 110, 101, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 190, 1, 0, 0, 128, 192, 12, 163, 36, 93, 220, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 224, 147, 4, 0];

    let open_term: Term<OpcuaProtocolTypes> = term! {
        fn_open_message(
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
