use serde_json::Value;
use std::env;
use std::fs::OpenOptions;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};

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
use crate::swisspost::{JacocoCoverageClient, JmsConfig, JmsProducer};

const CONTROL_COMPONENT_JAR: &str =
    "/home/binj/Documents/stageM2/e-voting/control-component/target/control-component-1.5.3.2-runnable.jar";
const CONTROL_COMPONENT_STDOUT: &str = "/tmp/sppuffin-control-component.stdout.log";
const CONTROL_COMPONENT_STDERR: &str = "/tmp/sppuffin-control-component.stderr.log";
const POSTGRES_LOG: &str = "/tmp/pg.log";

type SharedServices = Arc<Mutex<ManagedServices>>;

struct ManagedServices {
    owner_pid: u32,
    control_component: Option<Child>,
    postgres_started: bool,
    client: Option<Client>,
}

impl ManagedServices {
    fn new() -> Self {
        Self {
            owner_pid: std::process::id(),
            control_component: None,
            postgres_started: false,
            client: None,
        }
    }

    fn start(&mut self) -> Result<(), PuffinError> {
        // We first need to start the Postgres Database, at the CC will crash at start without it
        self.start_postgres()?;

        self.start_control_component()
    }

    fn restart_for_put(&mut self) -> Result<(), PuffinError> {
        if std::process::id() != self.owner_pid {
            return if self.control_component.is_some() {
                self.restart_postgres()
            } else {
                Err(PuffinError::Put(
                    "managed services must be started before the fuzzer launcher forks".to_string(),
                ))
            };
        }

        if !self.postgres_started {
            self.start()
        } else {
            self.restart_postgres()?;
            self.start_control_component()
        }
    }

    fn start_postgres(&mut self) -> Result<(), PuffinError> {
        log::debug!("Starting the Postgres Database");
        let pgdata = env::var("PGDATA").map_err(|_| {
            PuffinError::Put("PGDATA is not set; enter the sppuffin nix shell first".to_string())
        })?;
        let pghost = env::var("PGHOST").map_err(|_| {
            PuffinError::Put("PGHOST is not set; enter the sppuffin nix shell first".to_string())
        })?;
        let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "control_component".into());
        let pass =
            std::env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "control_component".into());
        let db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "control_component".into());

        Command::new("pg_ctl")
            .args([
                "-D",
                &pgdata,
                "restart",
                "-m",
                "fast",
                "-l",
                POSTGRES_LOG,
                "-o",
                &format!("-k {pghost}"),
            ])
            .output()
            .map_err(|e| PuffinError::Put(format!("failed to run pg_ctl restart: {e}")))?;

        // Now we wait for it to be actually started

        let url = format!("host={pghost} user={user} password={pass} dbname={db}");
        log::debug!("waiting for postgres ({url}) ...");
        let postgres_start_timeout = Duration::from_secs(20);
        let start_time = Instant::now();

        while start_time.elapsed() < postgres_start_timeout {
            match Client::connect(&url, NoTls) {
                Ok(mut client) => match client.query_one("SELECT 1", &[]) {
                    Ok(_) => {
                        log::debug!("Postgres is started");
                        self.postgres_started = true;
                        self.client = Some(client);
                        return Ok(());
                    }
                    Err(e) => log::error!("query failed: {e}"),
                },
                Err(e) => log::error!("not ready: {e}"),
            }
            thread::sleep(Duration::from_millis(5));
        }

        log::error!("Postgres startup timeout");
        Err(PuffinError::Put("Postgres startup timeout".to_string()))
    }

    fn restart_postgres(&mut self) -> Result<(), PuffinError> {
        log::debug!("Restarting the PostgreSQL Database");

        let client = self.client.as_mut().unwrap(); // TODO: remove unwrap
        let role = "control_component_1";
        client.query_one(
            "DO $$
DECLARE
  t text;
BEGIN
  -- skip FK enforcement during restore (superuser only); golden is consistent, so order doesn't matter
  PERFORM set_config('session_replication_role', 'replica', true);
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = '$1' ORDER BY tablename LOOP
    EXECUTE format('DELETE FROM $1.%I', t);
    EXECUTE format('INSERT INTO $1.%I SELECT * FROM golden.%I', t, t);
  END LOOP;
END $$;",
                &[&role],
        ).map_err(|e| PuffinError::Put(format!("failed to open {CONTROL_COMPONENT_STDOUT}: {e}"))
        )?;

        self.postgres_started = true;
        Ok(())
    }

    fn start_control_component(&mut self) -> Result<(), PuffinError> {
        let existing_status = self.control_component.as_mut().map(Child::try_wait);
        match existing_status {
            Some(Ok(None)) => return Ok(()),
            Some(Ok(Some(status))) => {
                self.control_component.take();
                return Err(PuffinError::Put(format!(
                    "control component exited unexpectedly ({status})"
                )));
            }
            Some(Err(err)) => {
                return Err(PuffinError::Put(format!(
                    "failed to inspect control component: {err}"
                )));
            }
            None => {}
        }

        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(CONTROL_COMPONENT_STDOUT)
            .map_err(|e| {
                PuffinError::Put(format!("failed to open {CONTROL_COMPONENT_STDOUT}: {e}"))
            })?;
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .open(CONTROL_COMPONENT_STDERR)
            .map_err(|e| {
                PuffinError::Put(format!("failed to open {CONTROL_COMPONENT_STDERR}: {e}"))
            })?;

        log::debug!("Starting the Control Component");
        let child = Command::new("java")
            .args([
                "-javaagent:/home/binj/Programmes/jacoco-0.8.14/lib/jacocoagent.jar=output=tcpserver,address=127.0.0.1,port=6300,jmx=true",
                "-Dcom.sun.management.jmxremote",
                "-Dcom.sun.management.jmxremote.host=127.0.0.1",
                "-Dcom.sun.management.jmxremote.port=9010",
                "-Dcom.sun.management.jmxremote.rmi.port=9010",
                "-Dcom.sun.management.jmxremote.authenticate=false",
                "-Dcom.sun.management.jmxremote.ssl=false",
                "-Djava.rmi.server.hostname=127.0.0.1",
                "-jar",
                CONTROL_COMPONENT_JAR,
            ])
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| {
                PuffinError::Put(format!(
                    "failed to start control component with java -jar {CONTROL_COMPONENT_JAR}: {e}"
                ))
            })?;

        // Check the status to wait for the CC to be up
        log::debug!("Waiting for the Control Component");

        let mut cc_up = false;
        while !cc_up {
            while !cc_up {
                match reqwest::blocking::get("http://localhost:8080/actuator/health") {
                    Ok(resp) if resp.status().is_success() => match resp.json::<Value>() {
                        Ok(v) => {
                            if v.get("status").is_some_and(|status| status == "UP") {
                                println!("health is UP");
                                cc_up = true;
                            } else {
                            }
                        }
                        Err(e) => {
                            log::error!("invalid JSON : {e}");
                        }
                    },
                    Ok(_) => {}
                    Err(_) => {}
                };
                thread::sleep(Duration::from_secs(1));
            }
        }

        self.control_component = Some(child);
        Ok(())
    }

    fn stop_control_component(&mut self) {
        if let Some(mut control_component) = self.control_component.take() {
            match control_component.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(err) = control_component.kill() {
                        log::warn!("failed to stop control component: {err}");
                    }
                    let _ = control_component.wait();
                }
                Err(err) => log::warn!("failed to inspect control component: {err}"),
            }
        }
    }

    fn stop_postgres(&mut self) -> Result<(), PuffinError> {
        if !self.postgres_started {
            return Ok(());
        }

        let pgdata = env::var("PGDATA").map_err(|_| {
            PuffinError::Put("PGDATA is not set; cannot stop PostgreSQL".to_string())
        })?;
        let output = Command::new("pg_ctl")
            .args(["-D", &pgdata, "stop", "-m", "fast"])
            .output()
            .map_err(|e| PuffinError::Put(format!("failed to run pg_ctl stop: {e}")))?;

        if output.status.success() {
            self.postgres_started = false;
            Ok(())
        } else {
            Err(PuffinError::Put("Failed to stop PostgreSQL".to_string()))
        }
    }
}

impl Drop for ManagedServices {
    fn drop(&mut self) {
        if std::process::id() != self.owner_pid {
            return;
        }
        self.stop_control_component();
        if let Err(err) = self.stop_postgres() {
            log::warn!("failed to stop PostgreSQL: {err}");
        }
    }
}

fn start_managed_services(services: &SharedServices) -> Result<(), PuffinError> {
    services
        .lock()
        .map_err(|_| PuffinError::Put("sppuffin managed service lock is poisoned".to_string()))?
        .start()
}

fn restart_managed_services_for_put(services: &SharedServices) -> Result<(), PuffinError> {
    services
        .lock()
        .map_err(|_| PuffinError::Put("sppuffin managed service lock is poisoned".to_string()))?
        .restart_for_put()
}

fn restart_managed_postgres(services: &SharedServices) -> Result<(), PuffinError> {
    services
        .lock()
        .map_err(|_| PuffinError::Put("sppuffin managed service lock is poisoned".to_string()))?
        .restart_postgres()
}

// Minimal Rust factory and Put implementation to integrate with puffin's fuzzer.
struct SppRustFactory {
    services: SharedServices,
}

impl SppRustFactory {
    fn new() -> Self {
        Self {
            services: Arc::new(Mutex::new(ManagedServices::new())),
        }
    }
}

impl Factory<SwissProtocolBehavior> for SppRustFactory {
    fn prepare(&self) -> Result<(), PuffinError> {
        start_managed_services(&self.services)
    }

    fn create(
        &self,
        agent_descriptor: &AgentDescriptor<SwissPUTConfig>,
        _claims: &GlobalClaimList<<SwissProtocolBehavior as ProtocolBehavior>::Claim>,
        _options: &PutOptions,
    ) -> Result<Box<dyn Put<SwissProtocolBehavior>>, PuffinError> {
        log::debug!("NEW");
        restart_managed_services_for_put(&self.services)?;
        Ok(Box::new(SppPut::new(
            agent_descriptor.clone(),
            Arc::clone(&self.services),
        )))
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
        Box::new(SppRustFactory {
            services: Arc::clone(&self.services),
        })
    }
}

struct SppPut {
    descriptor: AgentDescriptor<SwissPUTConfig>,
    stream: MemoryStream,
    jms: Option<JmsProducer>,
    jacoco: Option<JacocoCoverageClient>,
    coverage_data: Option<Vec<u8>>,
    services: SharedServices,
}

impl SppPut {
    fn new(descriptor: AgentDescriptor<SwissPUTConfig>, services: SharedServices) -> Self {
        Self {
            descriptor,
            stream: MemoryStream::new(),
            jms: connect_jms(),
            jacoco: connect_jacoco(),
            coverage_data: None,
            services,
        }
    }
}

fn connect_jacoco() -> Option<JacocoCoverageClient> {
    JacocoCoverageClient::from_env()
        .map_err(|error| {
            log::warn!("Could not connect to JaCoCo JMX: {error}");
            error
        })
        .ok()
}

fn connect_jms() -> Option<JmsProducer> {
    let config = JmsConfig::from_env();
    JmsProducer::connect(config.clone())
        .map_err(|e| {
            log::warn!(
                "Could not connect to JMS broker at {} destination {}: {}",
                config.broker_url,
                config.destination,
                e
            );
            e
        })
        .ok()
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
        let result = self
            .jacoco
            .as_ref()
            .map(|jacoco| jacoco.get_execution_data(false));
        match result {
            Some(Ok(data)) => {
                log::debug!("Retrieved JaCoCo execution data ({} bytes)", data.len());
                self.coverage_data = Some(data);
            }
            Some(Err(error)) => {
                log::warn!("Could not retrieve JaCoCo execution data: {error}");
                if let Some(jacoco) = self.jacoco.take() {
                    jacoco.close();
                }
            }
            None => {}
        }
        Ok(())
    }

    fn reset(&mut self, _new_name: puffin::agent::AgentName) -> Result<(), PuffinError> {
        restart_managed_postgres(&self.services)
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
        if let Some(jacoco) = self.jacoco.take() {
            jacoco.close();
        }
        if let Some(data) = self.coverage_data.take() {
            let destination =
                env::var("SPP_JACOCO_DESTFILE").unwrap_or_else(|_| "./cov.exec".to_string());
            if let Err(error) = std::fs::write(&destination, data) {
                log::error!("Failed to write JaCoCo execution data to {destination}: {error}");
            }
        }
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
        vec![("spp-rust-put".to_string(), Box::new(SppRustFactory::new()))];

    let default_descriptor = PutDescriptor::new("spp-rust-put", PutOptions::empty());
    PutRegistry::new(puts, default_descriptor)
}
