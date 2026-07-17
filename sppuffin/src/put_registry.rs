use puffin::agent::AgentDescriptor;
use puffin::claims::GlobalClaimList;
use puffin::error::Error as PuffinError;
use puffin::protocol::ProtocolBehavior;
use puffin::put::Put;
use puffin::put::{PutDescriptor, PutOptions};
use puffin::put_registry::Factory;
/// Minimal placeholder registry for the sppuffin prototype.
/// In the real system this would expose PutRegistry and descriptors compatible
/// with the puffin framework. For the prototype a simple unit struct is fine.
use puffin::put_registry::PutRegistry;
use puffin::stream::MemoryStream;

use crate::protocol::{SwissPUTConfig, SwissProtocolBehavior};

// Minimal Rust factory and Put implementation to integrate with puffin's fuzzer.
struct SppRustFactory;

impl Factory<SwissProtocolBehavior> for SppRustFactory {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<SwissPUTConfig>,
        _claims: &GlobalClaimList<<SwissProtocolBehavior as ProtocolBehavior>::Claim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<SwissProtocolBehavior>>, PuffinError> {
        print!("NEW");
        Ok(Box::new(SppPut::new(agent_descriptor.clone())))
    }

    fn name(&self) -> String {
        "spp-rust-put".to_string()
    }

    fn versions(&self) -> Vec<(String, String)> {
        vec![("harness".to_string(), "sppuffin-prototype".to_string())]
    }

    fn supports(&self, _capability: &str) -> bool {
        false
    }

    fn clone_factory(&self) -> Box<dyn Factory<SwissProtocolBehavior>> {
        Box::new(SppRustFactory)
    }
}

struct SppPut {
    descriptor: AgentDescriptor<SwissPUTConfig>,
    stream: MemoryStream,
    socket: Option<std::net::TcpStream>,
}

impl SppPut {
    fn new(descriptor: AgentDescriptor<SwissPUTConfig>) -> Self {
        // Try to connect to the Lua server on localhost:40138
        let socket = std::net::TcpStream::connect("127.0.0.1:40138")
            .ok()
            .and_then(|s| {
                s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                s.set_write_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok();
                Some(s)
            });

        if socket.is_none() {
            eprintln!("Warning: Could not connect to Lua server at 127.0.0.1:40138");
        }

        Self {
            descriptor,
            stream: MemoryStream::new(),
            socket,
        }
    }
}

use puffin::algebra::ConcreteMessage;
use puffin::stream::Stream;

impl Stream<SwissProtocolBehavior> for SppPut {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::debug!("{:?}", message);
        // disambiguate the generic Stream impl
        if let Some(ref mut sock) = self.socket {
            if let Err(e) = sock.write_all(&message) {
                log::error!("Error writing to socket: {}", e);
                self.socket = None;
            }
        }

        <MemoryStream as puffin::stream::Stream<SwissProtocolBehavior>>::add_to_inbound(
            &mut self.stream,
            message,
        );
    }

    fn take_message_from_outbound(
        &mut self,
        output_flight: &mut Option<<SwissProtocolBehavior as puffin::protocol::ProtocolBehavior>::OpaqueProtocolMessageFlight>,
    ) -> Result<(), PuffinError> {
        <MemoryStream as puffin::stream::Stream<SwissProtocolBehavior>>::take_message_from_outbound(
            &mut self.stream,
            output_flight,
        )
    }
}

use std::io::Write;

impl Put<SwissProtocolBehavior> for SppPut {
    fn progress(&mut self) -> Result<(), PuffinError> {
        println!("PROGRESS");
        // Send data to the Lua server if connected
        if let Some(ref mut sock) = self.socket {
            let msg = b"test message from fuzzer\n";
            if let Err(e) = sock.write_all(msg) {
                eprintln!("Error writing to socket: {}", e);
                self.socket = None;
            }
        }

        Ok(())
    }

    fn reset(&mut self, _new_name: puffin::agent::AgentName) -> Result<(), PuffinError> {
        // No-op
        Ok(())
    }

    fn descriptor(&self) -> &AgentDescriptor<SwissPUTConfig> {
        &self.descriptor
    }

    fn describe_state(&self) -> String {
        "sppuffin: idle".to_string()
    }

    fn is_state_successful(&self) -> bool {
        true
    }

    fn shutdown(&mut self) -> String {
        "sppuffin: shutdown".to_string()
    }

    fn version() -> String
    where
        Self: Sized,
    {
        "sppuffin-prototype".to_string()
    }
}

/// Return a PutRegistry wired into puffin for SwissPost (sppuffin)
pub fn spp_registry() -> PutRegistry<SwissProtocolBehavior> {
    let puts: Vec<(String, Box<dyn Factory<SwissProtocolBehavior>>)> =
        vec![("spp-rust-put".to_string(), Box::new(SppRustFactory))];

    let default_descriptor = PutDescriptor::new("spp-rust-put", PutOptions::empty());
    PutRegistry::new(puts, default_descriptor)
}
