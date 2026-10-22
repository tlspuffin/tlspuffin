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
use crate::swisspost::{JmsConfig, JmsProducer};

fn check_postgres_connection() -> Result<(), PuffinError> {
    let database_url = std::env::var("SPP_POSTGRES_URL").unwrap_or_else(|_| {
        "host=127.0.0.1 port=5432 user=control_component password=control_component dbname=control_component"
            .to_string()
    });
    let mut client = postgres::Client::connect(&database_url, postgres::NoTls)
        .map_err(|e| PuffinError::Put(format!("failed to connect to PostgreSQL for reset: {e}")))?;
    client
        .query_one("SELECT 1", &[])
        .map_err(|e| PuffinError::Put(format!("PostgreSQL reset query failed: {e}")))?;
    Ok(())
}

// Minimal Rust factory and Put implementation to integrate with puffin's fuzzer.
struct SppRustFactory;

impl Factory<SwissProtocolBehavior> for SppRustFactory {
    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<SwissPUTConfig>,
        _claims: &GlobalClaimList<<SwissProtocolBehavior as ProtocolBehavior>::Claim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<SwissProtocolBehavior>>, PuffinError> {
        log::debug!("NEW");
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
    jms: Option<JmsProducer>,
}

impl SppPut {
    fn new(descriptor: AgentDescriptor<SwissPUTConfig>) -> Self {
        let config = JmsConfig::from_env();
        let jms = JmsProducer::connect(config.clone())
            .map_err(|e| {
                log::warn!(
                    "Could not connect to JMS broker at {} destination {}: {}",
                    config.broker_url,
                    config.destination,
                    e
                );
                e
            })
            .ok();

        Self {
            descriptor,
            stream: MemoryStream::new(),
            jms,
        }
    }
}

use puffin::algebra::ConcreteMessage;
use puffin::stream::Stream;

impl Stream<SwissProtocolBehavior> for SppPut {
    fn add_to_inbound(&mut self, message: &ConcreteMessage) {
        log::debug!("{:?}", message);
        // disambiguate the generic Stream impl
        if let Some(jms) = self.jms.as_mut() {
            if let Err(e) = jms.send_bytes(message) {
                log::error!("Error sending JMS message: {}", e);
                self.jms = None;
            }
        }

        <MemoryStream as puffin::stream::Stream<SwissProtocolBehavior>>::add_to_inbound(
            &mut self.stream,
            message,
        );
    }

    fn take_message_from_outbound(
        &mut self,
        _output_flight: &mut Option<
            <SwissProtocolBehavior as puffin::protocol::ProtocolBehavior>::OpaqueProtocolMessageFlight,
        >,
    ) -> Result<(), PuffinError> {
        // <MemoryStream as puffin::stream::Stream<SwissProtocolBehavior>>::take_message_from_outbound(
        //     &mut self.stream,
        //     output_flight,
        // );
        Ok(())
    }
}

impl Put<SwissProtocolBehavior> for SppPut {
    fn progress(&mut self) -> Result<(), PuffinError> {
        log::debug!("PROGRESS");
        Ok(())
    }

    fn reset(&mut self, _new_name: puffin::agent::AgentName) -> Result<(), PuffinError> {
        check_postgres_connection()
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
        if let Some(jms) = self.jms.take() {
            jms.close();
        }
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
