pub mod test_utils {
    use crate::agent::AgentName;
    use crate::trace::{TraceContext, Trace};
    use crate::variable::{
        CipherSuiteData, ClientExtensionData, CompressionData, RandomData, SessionIDData,
        VariableData, VersionData,
    };
    use rustls::internal::msgs::enums::Compression;

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
        ctx.add_variable(Box::new(CompressionData::static_extension(agent, Compression::Null)));
    }

    #[cfg(test)]
    pub mod tests {
        use crate::trace;
        use crate::trace::{
            ClientHelloExpectAction, ClientHelloSendAction, ServerHelloExpectAction, Step,
            TraceContext,
        };

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
                        from: client,
                        to: openssl_server,
                        action: &client_hello,
                    },
                    Step {
                        from: client,
                        to: openssl_server,
                        action: &server_hello,
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
            let dummy = ctx.new_agent();
            let honest_agent = ctx.new_agent();
            let openssl_client_agent = ctx.new_openssl_agent(false);

            let client_hello = ClientHelloExpectAction::new();
            let client_hello = ClientHelloSendAction::new();
            let server_hello_expect = ServerHelloExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        from: dummy,
                        to: openssl_client_agent,
                        action: &client_hello,
                    },
                    Step {
                        from: honest_agent,
                        to: openssl_client_agent,
                        action: &client_hello,
                    },
                    Step {
                        from: honest_agent,
                        to: openssl_client_agent,
                        action: &server_hello_expect,
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
                        from: client,
                        to: server,
                        action: &a,
                    },
                    Step {
                        from: client,
                        to: server,
                        action: &b,
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
            let dummy = ctx.new_agent();
            let client_openssl = ctx.new_openssl_agent(false);
            let server_openssl = ctx.new_openssl_agent(true);

            let client_hello = ClientHelloExpectAction::new();
            let server_hello_expect = ServerHelloExpectAction::new();
            let mut trace = trace::Trace {
                steps: vec![
                    Step {
                        from: server_openssl,
                        to: client_openssl,
                        action: &client_hello,
                    },
                    Step {
                        from: dummy,
                        to: server_openssl,
                        action: &server_hello_expect,
                    },
                ],
            };

            info!("{}", trace);
            trace.execute(&mut ctx);
        }
    }
}
