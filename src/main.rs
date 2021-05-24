#[macro_use]
extern crate log;

use core::time;
use std::io::Write;
use std::thread;

use env_logger::{fmt, Builder, Env};
use log::Level;
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::Compression;
use rustls::internal::msgs::handshake::{ClientExtension, Random, ServerExtension, SessionID};
use rustls::{CipherSuite, ProtocolVersion};

use crate::term::{
    op_application_data, op_change_cipher_spec, op_client_hello, op_encrypted_certificate,
    op_server_hello, Signature, Term,
};
use crate::trace::{Action, InputAction, OutputAction, Step, Trace, TraceContext};

use crate::fuzzer::start_fuzzing;

mod agent;
mod debug;
mod fuzzer;
mod io;
mod openssl_binding;
mod term;
mod tests;
mod trace;
mod variable_data;

/*use libafl_targets::{EDGES_MAP, MAX_EDGES_NUM};
*/
fn main() {
    let mut ctx = TraceContext::new();
    let client_openssl = ctx.new_openssl_agent(false);
    //let server_openssl = ctx.new_openssl_agent(true);


}
fn main1() {
    fn init_logger() {
        let env = Env::default().filter("RUST_LOG");

        Builder::from_env(env)
            .format(|buf, record| {
                let mut style = buf.style();
                match record.level() {
                    Level::Error => {
                        style.set_color(fmt::Color::Red).set_bold(true);
                    }
                    Level::Warn => {
                        style.set_color(fmt::Color::Yellow).set_bold(true);
                    }
                    Level::Info => {
                        style.set_color(fmt::Color::Blue).set_bold(true);
                    }
                    Level::Debug => {}
                    Level::Trace => {}
                };

                let timestamp = buf.timestamp();

                writeln!(buf, "{} {}", timestamp, style.value(record.args()))
            })
            .init();
    }

    init_logger();
    //pretty_env_logger::formatted_builder().target(Target::Stdout).filter_level(LevelFilter::Trace).init();

    //info!("{}", openssl_binding::openssl_version());

    //start_fuzzing();

    //loop {
        let mut ctx = TraceContext::new();
        let client_openssl = ctx.new_openssl_agent(false);
        let server_openssl = ctx.new_openssl_agent(true);

        /*        let client_hello_expect = ClientHelloExpectAction::new();
        let server_hello_expect = ServerHelloExpectAction::new();
        let ccc_expect = CCCExpectAction::new();
        let mut trace = trace::Trace {
            steps: vec![
                Step {
                    agent: client_openssl,
                    action: &client_hello_expect,
                    send_to: server_openssl,
                },
                Step {
                    agent: server_openssl,
                    action: &server_hello_expect,
                    send_to: client_openssl,
                },
                Step {
                    agent: server_openssl,
                    action: &ccc_expect,
                    send_to: client_openssl,
                },
            ],
        };*/

        let mut sig = Signature::default();
        let op_client_hello = sig.new_op(&op_client_hello);
        let op_server_hello = sig.new_op(&op_server_hello);
        let op_change_cipher_spec = sig.new_op(&op_change_cipher_spec);
        //let op_encrypted_certificate = sig.new_op(&op_encrypted_certificate);
        //let op_certificate = sig.new_op(&op_certificate);
        let op_application_data = sig.new_op(&op_application_data);

        let mut trace = Trace {
            steps: vec![
                Step {
                    agent: client_openssl,
                    action: Action::Output(OutputAction { id: 0 }),
                },
                // Client Hello Client -> Server
                Step {
                    agent: server_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_client_hello,
                            args: vec![
                                Term::Variable(sig.new_var::<ProtocolVersion>((0, 0))),
                                Term::Variable(sig.new_var::<Random>((0, 0))),
                                Term::Variable(sig.new_var::<SessionID>((0, 0))),
                                Term::Variable(sig.new_var::<Vec<CipherSuite>>((0, 0))),
                                Term::Variable(sig.new_var::<Vec<Compression>>((0, 0))),
                                Term::Variable(sig.new_var::<Vec<ClientExtension>>((0, 0))),
                            ],
                        },
                    }),
                },
                Step {
                    agent: server_openssl,
                    action: Action::Output(OutputAction { id: 1 }),
                },
                // Server Hello Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_server_hello,
                            args: vec![
                                Term::Variable(sig.new_var::<ProtocolVersion>((1, 0))),
                                Term::Variable(sig.new_var::<Random>((1, 0))),
                                Term::Variable(sig.new_var::<SessionID>((1, 0))),
                                Term::Variable(sig.new_var::<CipherSuite>((1, 0))),
                                Term::Variable(sig.new_var::<Compression>((1, 0))),
                                Term::Variable(sig.new_var::<Vec<ServerExtension>>((1, 0))),
                            ],
                        },
                    }),
                },
                // CCS Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_change_cipher_spec.clone(),
                            args: vec![],
                        },
                    }),
                },
                // Encrypted Extensions Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((1, 2)))],
                        },
                    }),
                },
                // Certificate Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((1, 3)))],
                        },
                    }),
                },
                // Certificate Verify Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((1, 4)))],
                        },
                    }),
                },
                // Finish Server -> Client
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((1, 5)))],
                        },
                    }),
                },
                Step {
                    agent: client_openssl,
                    action: Action::Output(OutputAction { id: 2 }),
                },
                /*
                // CCS Client -> Server
                Step {
                    agent: server_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_change_cipher_spec.clone(),
                            args: vec![],
                        },
                    }),
                },*/
                // todo missing:
                //      CCS Client -> Server
                // Finished Client -> Server
                Step {
                    agent: server_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((2, 0)))],
                        },
                    }),
                },
                Step {
                    agent: server_openssl,
                    action: Action::Output(OutputAction { id: 3 }),
                },
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            args: vec![Term::Variable(sig.new_var::<Payload>((3, 0)))],
                        },
                    }),
                },
                Step {
                    agent: client_openssl,
                    action: Action::Input(InputAction {
                        recipe: Term::Application {
                            op: op_application_data.clone(),
                            // todo can we express this with projections?
                            args: vec![Term::Variable(sig.new_var::<Payload>((3, 1)))],
                        },
                    }),
                },
            ],
        };

        // example mutation
        /*match &mut trace.steps[3].action {
            Action::Input(input) => {
                input.attacker_term = Term::Variable(sig.new_var_by_type::<SessionID>());
            }
            Action::Output(_) => {}
        }*/

        //let serialized = serde_json::to_string_pretty(&trace).unwrap();
        //println!("serialized = {}", serialized);

        info!("{}", trace);
        //trace.execute(&mut ctx);

/*    unsafe {
        println!("{:?}", EDGES_MAP);
        println!("{}", MAX_EDGES_NUM);
    }*/

    // Slow down the fuzzing
        thread::sleep(time::Duration::from_millis(500));
   // }
}
