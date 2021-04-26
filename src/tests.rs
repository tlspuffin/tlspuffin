pub mod test_utils {
    use rustls::internal::msgs::enums::Compression;

    use crate::agent::AgentName;
    use crate::trace::{Trace, TraceContext};
    use crate::variable::{
        CipherSuiteData, ClientExtensionData, CompressionData, RandomData, SessionIDData,
        VariableData, VersionData,
    };

    pub fn setup_client_hello_variables(ctx: &mut TraceContext, agent: AgentName) {
        ctx.add_variable(Box::new(VersionData::random_value(agent)));
        ctx.add_variable(Box::new(SessionIDData::random_value(agent)));
        ctx.add_variable(Box::new(RandomData::random_value(agent)));

        // A random extension
        //ctx.add_variable(Box::new(ExtensionData::random_value(fuzz_agent)));

        // Some static extensions
        ctx.add_variable(Box::new(ClientExtensionData::static_extension(
            agent,
            ClientExtensionData::key_share(),
        )));
        ctx.add_variable(Box::new(ClientExtensionData::static_extension(
            agent,
            ClientExtensionData::supported_versions(),
        )));
        ctx.add_variable(Box::new(ClientExtensionData::static_extension(
            agent,
            ClientExtensionData::supported_groups(),
        )));
        ctx.add_variable(Box::new(ClientExtensionData::static_extension(
            agent,
            ClientExtensionData::server_name("maxammann.org"),
        )));
        ctx.add_variable(Box::new(ClientExtensionData::static_extension(
            agent,
            ClientExtensionData::signature_algorithms(),
        )));

        ctx.add_variable(Box::new(CipherSuiteData::random_value(agent)));
        ctx.add_variable(Box::new(CipherSuiteData::random_value(agent)));
        ctx.add_variable(Box::new(CipherSuiteData::random_value(agent)));
        ctx.add_variable(Box::new(CompressionData::static_extension(
            agent,
            Compression::Null,
        )));
    }

    #[cfg(test)]
    pub mod tests {
        use test_env_log::test;

        use crate::trace;
        use crate::trace::{ClientHelloExpectAction, ClientHelloSendAction, ServerHelloExpectAction, Step, TraceContext, CCCExpectAction};
        use crate::agent::AgentName;
        use rand::random;

        #[test]
        /// Test for having an OpenSSL server (honest) agent
        pub fn openssl_server() {
            let mut ctx = TraceContext::new();
            let client = ctx.new_agent();
            let openssl_server = ctx.new_openssl_agent(true);

            let client_hello = ClientHelloSendAction::new();
            let server_hello = ServerHelloExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        agent: client,
                        action: &client_hello,
                        send_to: openssl_server
                    },
                    Step {
                        agent: openssl_server,
                        action: &server_hello,
                        send_to: AgentName::none()
                    },
                ],
            };

            info!("{}", trace);

            super::setup_client_hello_variables(&mut ctx, client);
            trace.execute(&mut ctx);
        }

        #[test]
        /// Test for having an OpenSSL client (honest) agent
        fn openssl_client() {
            let mut ctx = TraceContext::new();
            let honest_agent = ctx.new_agent();
            let openssl_client_agent = ctx.new_openssl_agent(false);

            let client_hello_initial = ClientHelloExpectAction::new();
            let client_hello_expect = ClientHelloExpectAction::new();
            let client_hello = ClientHelloSendAction::new();
            let server_hello_expect = ServerHelloExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        agent: openssl_client_agent,
                        action: &client_hello_initial,
                        send_to: honest_agent
                    },
                    Step {
                        agent: honest_agent,
                        action: &client_hello_expect,
                        send_to: honest_agent
                    },
                    Step {
                        agent: honest_agent,
                        action: &client_hello,
                        send_to: openssl_client_agent
                    },
                    Step {
                        agent: openssl_client_agent,
                        action: &server_hello_expect,
                        send_to: AgentName::none()
                    },
                ],
            };

            info!("{}", trace);
            trace.execute(&mut ctx);
        }

        #[test]
        /// Having two dishonest agents:
        /// * Send message from client to server, and receive variables
        fn two_dishonest() {
            let mut ctx = TraceContext::new();
            let client = ctx.new_agent();
            let server = ctx.new_openssl_agent(true);

            let a = ClientHelloSendAction::new();
            let b = ClientHelloExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        agent: client,
                        action: &a,
                        send_to: server
                    },
                    Step {
                        agent: server,
                        action: &b,
                        send_to: AgentName::none()
                    },
                ],
            };

            info!("{}", trace);

            super::setup_client_hello_variables(&mut ctx, client);
            trace.execute(&mut ctx);
        }

        #[test]
        fn only_openssl() {
            let mut ctx = TraceContext::new();
            let client_openssl = ctx.new_openssl_agent(false);
            let server_openssl = ctx.new_openssl_agent(true);

            let client_hello_expect = ClientHelloExpectAction::new();
            let server_hello_expect = ServerHelloExpectAction::new();
            let ccc_expect = CCCExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        agent: client_openssl,
                        action: &client_hello_expect,
                        send_to: server_openssl
                    },
                    Step {
                        agent: server_openssl,
                        action: &server_hello_expect,
                        send_to: client_openssl
                    },
                    Step {
                        agent: server_openssl,
                        action: &ccc_expect,
                        send_to: client_openssl
                    },
                ],
            };

            info!("{}", trace);
            trace.execute(&mut ctx);


            let client_state = ctx.find_agent(client_openssl)
                .unwrap()
                .stream
                .describe_state();
            let server_state = ctx.find_agent(server_openssl)
                .unwrap()
                .stream
                .describe_state();
            assert!(client_state.contains("SSL negotiation finished successfully"));
            assert!(server_state.contains("TLSv1.3 early data"));
        }
    }
}
