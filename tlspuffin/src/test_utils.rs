use std::time::Duration;

use puffin::execution::{forked_execution, ExecutionStatus, Runner, TraceRunner};
use puffin::put::PutDescriptor;
use puffin::trace::{Spawner, Trace};

use crate::protocol::TLSProtocolBehavior;
use crate::put_registry::tls_registry;
use crate::query::TlsQueryMatcher;

pub fn default_runner_for(put: impl Into<PutDescriptor>) -> Runner<TLSProtocolBehavior> {
    let registry = tls_registry();
    let spawner = Spawner::new(registry.clone()).with_default(put.into());

    Runner::new(registry, spawner)
}

// TODO refactor forked execution into a build pattern
//
//     Because we now have several optional arguments to execute a trace and
//     several more in [`forked_execution()`], the API is difficult to read at
//     call site.
//
//     It would make sense to group everything into a builder pattern for
//     creating an trace execution. This would give something like:
//
//     Execution::builder(trace, options)
//         .timeout(Duration::from_secs(10))
//         .retry(5)
//         .expect_crash()
#[allow(dead_code)]
pub fn expect_trace_crash(
    trace: Trace<TlsQueryMatcher>,
    runner: Runner<TLSProtocolBehavior>,
    timeout: Option<Duration>,
    retry: Option<usize>,
) {
    let nb_retry = retry.unwrap_or(1);

    let _ = std::iter::repeat(())
        .take(nb_retry)
        .enumerate()
        .map(|(i, _)| {
            log::debug!("expect_trace_crash at retry {}", i);
            forked_execution(
                || {
                    // Ignore Rust errors
                    let _ = runner.clone().execute(&trace);
                },
                timeout,
            )
        })
        .map(|status| {
            use ExecutionStatus as S;
            match &status {
                Ok(S::Failure(_)) | Ok(S::Crashed) => log::info!("trace execution crashed"),
                Ok(S::Timeout) => log::info!("trace execution timed out"),
                Ok(S::Success) => log::info!("expected trace execution to crash, but succeeded"),
                Err(reason) => log::info!("trace execution error: {reason}"),
            };
            status
        })
        .find(|status| {
            matches!(
                status,
                Ok(ExecutionStatus::Failure(_)) | Ok(ExecutionStatus::Crashed)
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "expected trace execution to crash (retried {} times)",
                nb_retry
            )
        });
}

pub mod tcp {
    use puffin::agent::TLSVersion;
    use puffin::put::PutOptions;
    use tempfile::{tempdir, TempDir};

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

    pub use crate::put_registry::tls_registry;
    pub use crate::test_utils::tcp::*;
    pub use crate::test_utils::{default_runner_for, expect_trace_crash};
}
