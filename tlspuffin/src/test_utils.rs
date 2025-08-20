use std::cmp::{max, min};
use std::collections::HashSet;
use std::time::Duration;

use itertools::Itertools;
use puffin::agent::AgentName;
use puffin::algebra::dynamic_function::DescribableFunction;
use puffin::algebra::signature::FunctionDefinition;
use puffin::algebra::{DYTerm, Term, TermType};
use puffin::error::Error;
use puffin::execution::{ExecutionStatus, ForkedRunner, Runner, TraceRunner};
use puffin::fuzzer::mutations::MutationConfig;
use puffin::fuzzer::term_zoo::TermZoo;
use puffin::fuzzer::utils::{choose, find_term_by_term_path_mut, Choosable, TermConstraints};
use puffin::libafl::corpus::{Corpus, InMemoryCorpus, Testcase};
use puffin::libafl::mutators::MutatorsTuple;
use puffin::libafl::prelude::StdState;
use puffin::libafl_bolts::bolts_prelude::{Rand, RomuDuoJrRand, StdRand};
use puffin::protocol::{ProtocolBehavior, ProtocolTypes};
use puffin::put::PutDescriptor;
use puffin::put_registry::PutRegistry;
use puffin::trace::Action::Input;
use puffin::trace::{InputAction, Spawner, Step, Trace, TraceContext};
use puffin::trace_helper::TraceHelper;

use crate::protocol::{TLSProtocolBehavior, TLSProtocolTypes};
use crate::put_registry::tls_registry;
use crate::tls::fn_impl::{
    fn_certificate_transcript, fn_client_finished_transcript, fn_decrypt_application,
    fn_decrypt_multiple_handshake_messages, fn_server_finished_transcript,
    fn_server_hello_transcript,
};
use crate::tls::seeds::seed_successful;
use crate::tls::TLS_SIGNATURE;

pub fn default_runner_for(put: impl Into<PutDescriptor>) -> Runner<TLSProtocolBehavior> {
    let registry = tls_registry();
    let spawner = Spawner::new(registry.clone()).with_default(put.into());

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
    pub use puffin::{supports, test_puts};
    pub use puffin_macros::apply;

    pub use crate::put_registry::{for_puts, tls_registry};
    pub use crate::test_utils::tcp::*;
    pub use crate::test_utils::{default_runner_for, expect_trace_crash};
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
    let ignore_pay: HashSet<String> = ["tlspuffin::tls::fn_impl::fn_utils::fn_derive_psk"]
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

/// Parametric test for testing operations on terms (closure `test_map`, e.g., evaluation) through
/// the generation of a zoo of terms
pub fn zoo_test<Ft>(
    mut test_map: Ft,
    mut rand: RomuDuoJrRand,
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
    let tls_registry = tls_registry();
    let spawner = Spawner::new(tls_registry.clone());
    let ctx = TraceContext::new(spawner);

    let all_functions_shape = TLS_SIGNATURE.functions.to_owned();
    let number_functions = all_functions_shape.len();
    let mut number_terms = 0;
    let mut number_success = 0;
    let mut number_failure = 0;
    let mut number_failure_on_ignored = 0;
    let mut successful_functions = vec![];

    let bucket_size = 200;
    for f in &all_functions_shape {
        if filter.is_none() || (filter.is_some() && filter.unwrap().0.name == f.0.name) {
            'outer: for i in 0..max(1, how_many / bucket_size) {
                let bucket_size_step = if how_many < bucket_size || i < how_many / bucket_size - 1 {
                    min(how_many, bucket_size)
                } else {
                    min(
                        how_many,
                        how_many - bucket_size * (how_many / bucket_size - 1),
                    )
                };
                log::error!("Call generate_many with bucket_size_step={bucket_size_step} and function {} and filter_executable: {filter_executable}", f.0.name);
                let zoo_f = TermZoo::<TLSProtocolBehavior>::generate_many(
                    &ctx,
                    &TLS_SIGNATURE,
                    &mut rand,
                    bucket_size_step,
                    Some(&f),
                    filter_executable,
                    filter_no_gen,
                );
                let terms_f = zoo_f.terms();
                if terms_f.len() != how_many {
                    log::warn!(
                        "Failed to generate {bucket_size_step} terms (only {}) for function {}.",
                        terms_f.len(),
                        f.0.name
                    );
                }
                number_terms += terms_f.len();

                for term in terms_f.iter() {
                    match test_map(term, &ctx, &mut rand) {
                        Ok(_) => {
                            successful_functions.push(term.name().to_string());
                            number_success += 1;
                            if stop_on_success {
                                break 'outer;
                            }
                        }
                        Err(e) => {
                            if ignored_functions.contains(term.name()) {
                                log::debug!("[Ignored function] Failed to test_map term {term} with error {e}. ");
                                number_failure_on_ignored += 1;
                            } else {
                                log::error!("[Not ignored function] Failed to test_map term {term} with error {e}. ");
                                number_failure += 1;
                                if stop_on_error {
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let all_functions = all_functions_shape
        .iter()
        .map(|(shape, _)| shape.name.to_string())
        .collect::<HashSet<String>>();

    let mut successful_functions = successful_functions
        .into_iter()
        .collect::<HashSet<String>>();
    let successful_functions_tested = successful_functions.clone();
    successful_functions.extend(ignored_functions.clone());

    let difference = all_functions.difference(&successful_functions);
    let difference_inverse = successful_functions_tested.intersection(&ignored_functions);

    log::debug!("[zoo_test] ignored_functions: {:?}\n", &ignored_functions);
    log::error!("[zoo_test] Diff: {:?}", &difference);
    log::error!(
        "[zoo_test] Intersection with ignored: {:?}",
        &difference_inverse
    );
    log::error!(
        "[zoo_test] Stats: how_many: {how_many}, stop_on_success: {stop_on_success}, stop_on_error: {stop_on_error}\n\
        --> number_functions: {}, number_terms: {}, number_success: {}, number_failure: {}, number_failure_on_ignored: {}\n\
        --> Successfully built (out of {:?} functions): {:?}",
        number_functions,
        number_terms,
        number_success,
        number_failure,
        number_failure_on_ignored,
        &all_functions.len(),
        &successful_functions_tested.len()
    );
    (difference.count() == 0) && (difference_inverse.count() == 0)
}
