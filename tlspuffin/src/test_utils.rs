use std::collections::HashSet;
use std::time::Duration;

use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::signature::FunctionDefinition;
use puffin::algebra::Term;
use puffin::error::Error;
use puffin::execution::{ExecutionStatus, ForkedRunner, Runner, TraceRunner};
use puffin::fuzzer::bit_mutations::all_mutations;
use puffin::fuzzer::mutations::MutationConfig;
use puffin::libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use puffin::libafl::mutators::MutatorsTuple;
use puffin::libafl::prelude::StdState;
use puffin::libafl_bolts::bolts_prelude::{RomuDuoJrRand, StdRand};
use puffin::libafl_bolts::tuples::NamedTuple;
use puffin::protocol::ProtocolTypes;
use puffin::put::PutDescriptor;
use puffin::put_registry::PutRegistry;
pub use puffin::test_utils::{add_one_payload_randomly, add_payloads_randomly, test_pay, ZooTest};
use puffin::trace::{Spawner, Trace, TraceContext};
use puffin::trace_helper::TraceHelper;

use crate::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use crate::put_registry::tls_registry;
use crate::tls::fn_impl::{
    fn_certificate_transcript, fn_client_finished_transcript, fn_decrypt12, fn_decrypt_application,
    fn_decrypt_multiple_handshake_messages, fn_derive_psk, fn_server_finished_transcript,
    fn_server_hello_transcript,
};
use crate::tls::seeds::seed_successful;
use crate::tls::TLS_SIGNATURE;

pub fn default_runner_for(put: impl Into<String>) -> Runner<TLSProtocolBehavior> {
    let mut registry = tls_registry();
    registry.set_default_factory(&put.into()).unwrap();
    let spawner = Spawner::new(registry.clone());

    Runner::new(registry, spawner)
}

pub fn default_runner_for_desc(put_desc: impl Into<PutDescriptor>) -> Runner<TLSProtocolBehavior> {
    let mut registry = tls_registry();
    registry.set_default(put_desc.into()).unwrap();
    let spawner = Spawner::new(registry.clone());

    Runner::new(registry, spawner)
}

#[allow(dead_code)]
pub fn expect_trace_crash(
    trace: Trace<TLSProtocolTypes>,
    runner: Runner<TLSProtocolBehavior>,
    timeout: impl Into<Option<Duration>>,
    retry: Option<usize>,
) {
    let nb_retry = retry.unwrap_or(1);
    let forked_runner = ForkedRunner::new(&runner).with_timeout(timeout);

    let _ = std::iter::repeat(())
        .take(nb_retry)
        .enumerate()
        .inspect(|(i, _)| {
            log::debug!("expect_trace_crash (retry {})", i);
        })
        .map(|_| forked_runner.execute(&trace, &mut 0))
        .inspect(|status| {
            use ExecutionStatus as S;
            match &status {
                Ok(S::Crashed) => log::debug!("trace execution crashed"),
                Ok(S::Failure(_)) => log::debug!("invalid trace"),
                Ok(S::Timeout) => log::debug!("trace execution timed out"),
                Ok(S::Interrupted) => log::debug!("trace execution interrupted"),
                Ok(S::Success) => log::debug!("expected trace execution to crash, but succeeded"),
                Err(reason) => log::debug!("trace execution error: {reason}"),
            };
        })
        .find(|status| matches!(status, Ok(ExecutionStatus::Crashed)))
        .unwrap_or_else(|| {
            panic!(
                "expected trace execution to crash (retried {} times)",
                nb_retry
            )
        });
}

pub mod tcp {
    use puffin::put::PutOptions;
    use tempfile::{tempdir, TempDir};

    use crate::protocol::TLSVersion;
    use crate::tcp::{collect_output, execute_command};

    const OPENSSL_PROG: &str = "openssl";

    pub struct ParametersGuard {
        port: u16,
        prog: String,
        args: String,
        cwd: Option<String>,

        #[allow(dead_code)]
        /// In case `temp_dir` is set this acts as a guard. Dropping it makes it invalid.
        temp_dir: Option<TempDir>,
    }

    impl ParametersGuard {
        pub fn build_options(&self) -> PutOptions {
            let port = self.port.to_string();
            let mut options: Vec<(&str, &str)> =
                vec![("port", &port), ("prog", &self.prog), ("args", &self.args)];
            if let Some(cwd) = &self.cwd {
                options.push(("cwd", cwd));
            }
            options.into()
        }
    }

    fn gen_certificate() -> (String, String, TempDir) {
        let temp_dir = tempdir().unwrap();

        let key = temp_dir.path().join("key.pem");
        let key_path = key.as_os_str().to_str().unwrap();
        let cert = temp_dir.path().join("cert.pem");
        let cert_path = cert.as_os_str().to_str().unwrap();

        let openssl_gen_cert_args = [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/C=US/ST=New Sweden/L=Stockholm/O=.../OU=.../CN=.../emailAddress=...",
        ];

        let cert_output = collect_output(execute_command::<_, _, &str>(
            OPENSSL_PROG,
            openssl_gen_cert_args,
            None,
        ));
        println!("Certificate generation: {}", cert_output);

        (key_path.to_owned(), cert_path.to_owned(), temp_dir)
    }

    pub fn wolfssl_client(port: u16, version: TLSVersion, warmups: Option<u32>) -> ParametersGuard {
        let (_key, _cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec!["-h", "127.0.0.1", "-p", &port_string, "-x", "-d"];
        let prog = "./examples/client/client";
        let cwd = "/home/max/projects/wolfssl";

        match version {
            TLSVersion::V1_3 => {
                args.push("-v");
                args.push("4");
            }
            TLSVersion::V1_2 => {
                args.push("-v");
                args.push("3");
            }
            TLSVersion::Both => panic!("Both version found"), //TODO (NB) come back here
        }

        let warmups = warmups.map(|warmups| warmups.to_string());

        if let Some(warmups) = &warmups {
            args.push("-b");
            args.push(warmups);
        }

        ParametersGuard {
            port,
            prog: prog.to_owned(),
            args: args.join(" "),
            cwd: Some(cwd.to_owned()),
            temp_dir: Some(temp_dir),
        }
    }

    pub fn wolfssl_server(port: u16, version: TLSVersion) -> ParametersGuard {
        let (_key, _cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec!["-p", &port_string, "-x", "-d", "-i"];
        let prog = "./examples/server/server";
        let cwd = "/home/max/projects/wolfssl";

        match version {
            TLSVersion::V1_3 => {
                args.push("-v");
                args.push("4");
            }
            TLSVersion::V1_2 => {
                args.push("-v");
                args.push("3");
            }
            TLSVersion::Both => panic!("Both version found"), //TODO (NB) come back here
        }

        ParametersGuard {
            port,
            prog: prog.to_owned(),
            args: args.join(" "),
            cwd: Some(cwd.to_owned()),
            temp_dir: Some(temp_dir),
        }
    }

    pub fn openssl_server(port: u16, version: TLSVersion) -> ParametersGuard {
        let (key, cert, temp_dir) = gen_certificate();

        let port_string = port.to_string();
        let mut args = vec![
            "s_server",
            "-accept",
            &port_string,
            "-msg",
            "-state",
            "-key",
            &key,
            "-cert",
            &cert,
        ];

        match version {
            TLSVersion::V1_3 => {
                args.push("-tls1_3");
            }
            TLSVersion::V1_2 => {
                args.push("-tls1_2");
            }
            TLSVersion::Both => panic!("Both version found"), //TODO (NB) come back here
        }

        ParametersGuard {
            port,
            prog: OPENSSL_PROG.to_owned(),
            args: args.join(" "),
            cwd: None,
            temp_dir: Some(temp_dir),
        }
    }

    pub fn openssl_client(port: u16, version: TLSVersion) -> ParametersGuard {
        let connect = format!("{}:{}", "127.0.0.1", port);
        let mut args = vec!["s_client", "-connect", &connect, "-msg", "-state"];

        match version {
            TLSVersion::V1_3 => {
                args.push("-tls1_3");
            }
            TLSVersion::V1_2 => {
                args.push("-tls1_2");
            }
            TLSVersion::Both => panic!("Both version found"), //TODO (NB) come back here
        }

        ParametersGuard {
            port,
            prog: OPENSSL_PROG.to_owned(),
            args: args.join(" "),
            cwd: None,
            temp_dir: None,
        }
    }
}

pub mod prelude {
    #![allow(unused_imports)]

    pub use puffin::execution::TraceRunner;
    pub use puffin::test_utils::AssertExecution;
    pub use puffin::trace_helper::TraceHelper;
    pub use puffin::{supports, test_differential_puts, test_puts};
    pub use puffin_macros::apply;

    pub use crate::put_registry::{for_puts, tls_registry};
    pub use crate::test_utils::tcp::*;
    pub use crate::test_utils::{default_runner_for, default_runner_for_desc, expect_trace_crash};
}

/// Functions that are known to fail to be adversarially generated
pub fn ignore_gen() -> HashSet<String> {
    [
        // As expected, attacker cannot use them as there is no adversarial
        // '*Transcript*', which are required as argument
        fn_server_finished_transcript.name(),
        fn_client_finished_transcript.name(),
        fn_server_hello_transcript.name(),
        fn_certificate_transcript.name(),
    ]
    .iter()
    .map(|fn_name| fn_name.to_string())
    .collect::<HashSet<String>>()
}

/// Functions that are known to fail to be evaluated (without payloads)
pub fn ignore_eval() -> HashSet<String> {
    let mut ignore_gen = ignore_gen();
    let ignore_eval = [
        // Those 2 are the function symbols for which we can generate a term but all fail to
        // DY_execute! Indeed, the HandshakeHash that is fed as argument must be
        // computed in a very specific way! We might give known,valid hash-transcript to help?
        fn_decrypt_application.name(),
        fn_decrypt_multiple_handshake_messages.name(),
        fn_decrypt12.name(),
    ]
    .iter()
    .map(|fn_name| fn_name.to_string())
    .collect::<HashSet<String>>();
    ignore_gen.extend(ignore_eval);
    ignore_gen
}

/// Functions that are flagged to fail to be adversarially generated and evaluated according to the
/// signature attribute [no_gen]
pub fn ignore_eval_attribute() -> HashSet<String> {
    TLS_SIGNATURE
        .functions
        .iter()
        .filter(|f| TLS_SIGNATURE.attrs_by_name.get(f.0.name).unwrap().no_gen)
        .map(|f| f.0.name.to_string())
        .collect::<HashSet<String>>()
}

/// Functions that are known to fail to be adversarially generated, MakeMessage, evaluated
pub fn ignore_add_payload() -> HashSet<String> {
    let mut ignore_eval = ignore_eval();
    let ignore_pay: HashSet<String> = vec![]
        .iter()
        .map(|fn_name: &&str| fn_name.to_string())
        .collect::<HashSet<String>>();
    ignore_eval.extend(ignore_pay);
    ignore_eval
}

/// Functions that are known to fail to be adversarially generated, MakeMessage, mutated, evaluated
pub fn ignore_add_payload_mutate() -> HashSet<String> {
    let mut ignore_add_payload = ignore_add_payload();
    let ignore_mutate: HashSet<String> = [
        // No additional failures
    ]
    .iter()
    .map(|fn_name: &&str| fn_name.to_string())
    .collect::<HashSet<String>>();
    ignore_add_payload.extend(ignore_mutate);
    ignore_add_payload
}

/// Functions that are unstables, we might be able to generate them but not easily
pub fn unstable_functions() -> HashSet<String> {
    vec![fn_derive_psk.name()]
        .iter()
        .map(|fn_name: &&str| fn_name.to_string())
        .collect::<HashSet<String>>()
}

/// Parametric test for testing operations on terms (closure `test_map`, e.g., evaluation) through
/// the generation of a zoo of terms. The TLS instance of [`ZooTest`].
#[allow(clippy::too_many_arguments)]
pub fn zoo_test<Ft>(
    test_map: Ft,
    rand: RomuDuoJrRand,
    how_many: usize, // number of terms to generate for each function symbol (at root position)
    stop_on_success: bool, /* do not test further term if its function at root position was
                      * already positively tested */
    stop_on_error: bool, /* for each function, stop testing further terms if an error is
                          * encountered */
    filter_executable: bool,
    filter_no_gen: bool,
    filter: Option<&FunctionDefinition<TLSProtocolTypes>>,
    ignored_functions: &HashSet<String>,
) -> bool
where
    Ft: FnMut(
        &Term<TLSProtocolTypes>,
        &TraceContext<TLSProtocolBehavior>,
        &mut RomuDuoJrRand,
    ) -> Result<(), Error>,
{
    ZooTest {
        how_many,
        stop_on_success,
        stop_on_error,
        filter_executable,
        filter_no_gen,
        filter,
        ignored_functions: ignored_functions.clone(),
        ..tls_zoo()
    }
    .run(rand, test_map)
}

/// The TLS term zoo, with the symbols whose outcome is not checked.
pub fn tls_zoo() -> ZooTest<'static, TLSProtocolBehavior> {
    ZooTest {
        unstable_functions: unstable_functions(),
        ..ZooTest::new(&TLS_SIGNATURE, tls_registry())
    }
}

pub type TLSState = StdState<
    InMemoryCorpus<Trace<TLSProtocolTypes>>,
    Trace<TLSProtocolTypes>,
    RomuDuoJrRand,
    InMemoryCorpus<Trace<TLSProtocolTypes>>,
>;

pub fn create_state() -> TLSState {
    let rand = StdRand::with_seed(1235);
    let mut corpus: InMemoryCorpus<Trace<_>> = InMemoryCorpus::new();
    corpus
        .add(Testcase::new(seed_successful.build_trace()))
        .unwrap();
    StdState::new(rand, corpus, InMemoryCorpus::new(), &mut (), &mut ()).unwrap()
}

pub fn test_mutations(
    registry: &PutRegistry<TLSProtocolBehavior>,
    with_bit_level: bool,
    with_dy: bool,
) -> impl MutatorsTuple<Trace<TLSProtocolTypes>, TLSState> + NamedTuple + '_ {
    all_mutations::<TLSState, TLSProtocolTypes, TLSProtocolBehavior>(
        MutationConfig {
            with_bit_level,
            with_dy,
            with_focus: false,
            ..MutationConfig::default()
        },
        TLSProtocolTypes::signature(),
        registry,
    )
}
