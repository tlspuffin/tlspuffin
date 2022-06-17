use crate::agent::{AgentName, PutName};
use crate::error::Error;
use crate::io::{MessageResult, Stream};
use crate::put::{Config, Put};
use crate::put_registry::{Factory, OPENSSL111, TCP};
use crate::trace::VecClaimer;
use log::error;
use rustls::msgs::deframer::MessageDeframer;
use rustls::msgs::message::{Message, OpaqueMessage};
use std::cell::RefCell;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::time::Duration;

pub fn new_tcp_factory() -> Box<dyn Factory> {
    struct OpenSSLFactory;
    impl Factory for OpenSSLFactory {
        fn create(&self, config: Config) -> Box<dyn Put> {
            Box::new(TcpPut::new(config).unwrap())
        }

        fn put_name(&self) -> PutName {
            TCP
        }

        fn put_version(&self) -> &'static str {
            TcpPut::version()
        }

        fn make_deterministic(&self) {
            TcpPut::make_deterministic()
        }
    }

    Box::new(OpenSSLFactory)
}

pub struct TcpPut {
    stream: TcpStream,
    outbound_buffer: io::Cursor<Vec<u8>>,
    deframer: MessageDeframer,
}

impl TcpPut {
    fn new_stream() -> TcpStream {
        let stream = TcpStream::connect("127.0.0.1:44330").unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set_read_timeout call failed");
        stream
    }
}

impl Stream for TcpPut {
    fn add_to_inbound(&mut self, opaque_message: &OpaqueMessage) {
        self.stream
            .write_all(&mut opaque_message.clone().encode())
            .unwrap();
    }

    fn take_message_from_outbound(&mut self) -> Result<Option<MessageResult>, Error> {
        let mut first_message = self.deframer.frames.pop_front();

        first_message = if first_message.is_none() {
            self.deframer.read(&mut self.stream);
            self.deframer.frames.pop_front()
        } else {
            first_message
        };

        if let Some(opaque_message) = first_message {
            let message = match Message::try_from(opaque_message.clone().into_plain_message()) {
                Ok(message) => Some(message),
                Err(err) => {
                    error!("Failed to decode message! This means we maybe need to remove logical checks from rustls! {}", err);
                    None
                }
            };

            Ok(Some(MessageResult(message, opaque_message)))
        } else {
            // no message to return
            Ok(None)
        }
    }
}

impl Read for TcpPut {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TcpPut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for TcpPut {
    fn drop(&mut self) {}
}

impl Put for TcpPut {
    fn new(c: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut stream = Self::new_stream();

        Ok(Self {
            stream,
            outbound_buffer: io::Cursor::new(Vec::new()),
            deframer: Default::default(),
        })
    }

    fn progress(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        self.stream = Self::new_stream();
        Ok(())
    }

    #[cfg(feature = "claims")]
    fn register_claimer(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {
        todo!()
    }

    #[cfg(feature = "claims")]
    fn deregister_claimer(&mut self) {
        todo!()
    }

    fn change_agent_name(&mut self, claimer: Rc<RefCell<VecClaimer>>, agent_name: AgentName) {}

    fn describe_state(&self) -> &'static str {
        panic!("Unsupported with TCP Puts")
    }

    fn is_state_successful(&self) -> bool {
        false
    }

    fn version() -> &'static str
    where
        Self: Sized,
    {
        "Undefined"
    }

    fn make_deterministic()
    where
        Self: Sized,
    {
    }
}
