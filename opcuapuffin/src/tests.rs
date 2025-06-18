use serde::{Deserialize, Serialize};

use opcua::puffin::signature::{fn_hello, fn_acknowledge, fn_reverse_hello};
use opcua::puffin::signature::fn_impl::fn_constants::{fn_default_size, fn_simulation_server};
use opcua::puffin::types::{OpcuaDescriptorConfig, OpcuaProtocolTypes};
use opcua::types::{AcknowledgeMessage, HelloMessage, ReverseHelloMessage};

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

    let max_size = fn_default_size().unwrap();
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let hello_message: HelloMessage = fn_hello(
        &fn_simulation_server().unwrap(),
        &max_size,  &max_size).unwrap();
    hello_message.encode(&mut send_buffer);
    let hello_msg : Vec<u8> = vec![
    0x48, 0x45, 0x4c, 0x46, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69,
    0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53,
    0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    assert_eq!(&send_buffer,  &hello_msg);
    //println!("hello: {:x?}",  send_buffer);
}
#[test]
pub fn server() {

    let max_size: u32 = 5000;
    let mut send_buffer: Vec<u8> = Vec::with_capacity(max_size as usize);

    let reverse_message: ReverseHelloMessage = fn_reverse_hello(
        &String::from("opc.tcp://Penduick:53530"),
        &String::from("opc.tcp://PenDuick:53530/OPCUA/SimulationServer")).unwrap();
    reverse_message.encode(&mut send_buffer);
    let rev_hello_msg : Vec<u8> = vec![
    0x52, 0x48, 0x45, 0x46, 0x57, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
    0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x64, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35,
    0x33, 0x35, 0x33, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a,
    0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69, 0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30,
    0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    // Compiler bug if the rev_hello_msg is the same as hello_msg !!??
    assert_eq!(&send_buffer,  &rev_hello_msg);
    //println!("reverse hello: {:x?}",  send_buffer);

    send_buffer.clear();
    let acknowledge_message: AcknowledgeMessage = fn_acknowledge(
        &max_size,
        &max_size).unwrap();
    acknowledge_message.encode(&mut send_buffer);
    let ack_msg : Vec<u8> = vec![
    0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00,
    0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(&send_buffer,  &ack_msg);
      //println!("acknowledge: {:x?}",  send_buffer);
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
            Box::new(TestFactory {})
        }
    }

fn dummy_factory() -> Box<dyn Factory<OpcuaProtocolBehavior>> {
    Box::new(TestFactory)
}


#[test]
pub fn test_hello() {

    let hello_term: Term<OpcuaProtocolTypes> = term! {
      fn_hello(
        fn_simulation_server,
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
        0x48, 0x45, 0x4c, 0x46, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00,
        0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x50, 0x65, 0x6e, 0x44, 0x75, 0x69,
        0x63, 0x6b, 0x3a, 0x35, 0x33, 0x35, 0x33, 0x30, 0x2f, 0x4f, 0x50, 0x43, 0x55, 0x41, 0x2f, 0x53,
        0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72];
    assert_eq!(&hello_message, &hello_msg);

    let ack_term: Term<OpcuaProtocolTypes> = term! {
      fn_acknowledge(
        fn_default_size,
        fn_default_size)
    };
    let ack_message: Vec<u8> = ack_term.evaluate_symbolic(&context).unwrap();
    let ack_msg : Vec<u8> = vec![
        0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(&ack_message,  &ack_msg);


}