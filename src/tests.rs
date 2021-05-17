pub mod test_utils {
    use rustls::internal::msgs::enums::Compression;

    use crate::agent::AgentName;
    use crate::trace::TraceContext;
    use crate::variable_data::{
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
    pub mod tlspuffin {
        use test_env_log::test;

        use crate::agent::AgentName;
        use crate::trace;
        use crate::trace::{
            CCCExpectAction, ClientHelloExpectAction, ClientHelloSendAction,
            ServerHelloExpectAction, Step, TraceContext,
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
                        agent: client,
                        action: &client_hello,
                        send_to: openssl_server,
                    },
                    Step {
                        agent: openssl_server,
                        action: &server_hello,
                        send_to: AgentName::none(),
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
                        send_to: honest_agent,
                    },
                    Step {
                        agent: honest_agent,
                        action: &client_hello_expect,
                        send_to: honest_agent,
                    },
                    Step {
                        agent: honest_agent,
                        action: &client_hello,
                        send_to: openssl_client_agent,
                    },
                    Step {
                        agent: openssl_client_agent,
                        action: &server_hello_expect,
                        send_to: AgentName::none(),
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
                        send_to: server,
                    },
                    Step {
                        agent: server,
                        action: &b,
                        send_to: AgentName::none(),
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
            };

            info!("{}", trace);
            trace.execute(&mut ctx);

            let client_state = ctx
                .find_agent(client_openssl)
                .unwrap()
                .stream
                .describe_state();
            let server_state = ctx
                .find_agent(server_openssl)
                .unwrap()
                .stream
                .describe_state();
            assert!(client_state.contains("SSLv3/TLS write client hello"));
            assert!(server_state.contains("TLSv1.3 early data"));
        }
    }
}

#[cfg(test)]
pub mod integration {
    use std::io::{Read, stdout, Write};
    use std::net::TcpStream;
    use std::sync::Arc;

    use rustls;
    use rustls::internal::msgs::codec::Codec;
    use rustls::internal::msgs::enums::ContentType::Handshake as RecordHandshake;
    use rustls::internal::msgs::enums::HandshakeType;
    use rustls::internal::msgs::enums::ProtocolVersion::{TLSv1_2, TLSv1_3};
    use rustls::internal::msgs::handshake::{
        ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionID,
    };
    use rustls::internal::msgs::message::Message;
    use rustls::internal::msgs::message::MessagePayload::Handshake;
    use rustls::ProtocolVersion;
    use rustls::Session;
    use test_env_log::test;
    use webpki;
    use webpki_roots;

    #[test]
    fn test_rustls_message_stability() {
        let bytes: [u8; 1] = [5];
        let random = [0u8; 32];
        let message = Message {
            typ: RecordHandshake,
            version: TLSv1_2,
            payload: Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: ProtocolVersion::TLSv1_3,
                    random: Random::from_slice(&random),
                    session_id: SessionID::new(&bytes),
                    cipher_suites: vec![],
                    compression_methods: vec![],
                    extensions: vec![],
                }),
            }),
        };

        let mut out: Vec<u8> = Vec::new();
        message.encode(&mut out);
        hexdump::hexdump(&out);

        let mut decoded_message = Message::read_bytes(out.as_slice()).unwrap();

        decoded_message.decode_payload();
        println!("{:?}", decoded_message);

        // Hex from wireshark
        let hello_client_hex = "1603010136010001320303aa1795f64f48fcfcd0121368f88f176fe2570b0768bbc85e9f2c80c557553d7d20e1e15d0028932f4f7479cf256302b7847d81a68e708525f9d38d94fc6ef742a3003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000ab00000012001000000d6d6178616d6d616e6e2e6f7267000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d00209b8a24e29770f7ed95bf330e7e3929b21090350a415ab4cdf01b04e9ffc0fc50";
        let cert_hex = "16030309b50b0009b1000009ad00053a308205363082041ea00302010202120400ca5961d39c1622093596f2132488f93e300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3231303332383031343335385a170d3231303632363031343335385a301c311a3018060355040313117777772e6d6178616d6d616e6e2e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100b8ad1a3825f4aa8f8cdf5221a5d98d29f93be72f470397e07e1ceca379376bf1b148d19feaf6c5d3b01b344369bcc50dd33f967b281eec6edf4e9ee6b1a134589d40b3d3c2b2d51814ecafebcd59da1b01aea221af57f50e523694ac7603bf363b3a5380d48bef06cffbae66123046a7cfb3055f35755b50c71c93aef4c2a0bc8badb56b37d07be0d3319cac9b2f210a29115b4b6377734b647088adcbc12cc82a59a5f10fe2478ab2937f4ed667fbbdda3c468148f974da14dda787234811457d4a2d99677f27a3eae68f782c1291243e02653a4fe70ca4cb3d3eda66ba47926e25b25045b92ef8c20a89b1b5fce69ac18091f1229d9be473f96f23ed40d43f0203010001a382025a30820256300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e0416041412b43a1e54091741afc831d1e4de7babcb110ebe301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f302b0603551d1104243022820d6d6178616d6d616e6e2e6f726782117777772e6d6178616d6d616e6e2e6f7267304c0603551d20044530433008060667810c0102013037060b2b0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727970742e6f726730820103060a2b06010401d6790204020481f40481f100ef0076004494652eb0eeceafc44007d8a8fe28c0dae682bed8cb31b53fd33396b5b681a80000017876b7770e000004030047304502201c5b58adfa5df8abf6077d94b765750a24d32b49b3af2dcf5c65efaf32c949d6022100866e2301bf3633cf54a33124459c9dc69e6f953c9b2200f7c73919cefee849150075007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997e22f0d70000017876b7772e00000403004630440220030a54d2296566cab9b5fa3e6505566e5e014d48f15f6cd8727896e2cc352eb302207aff1ae19ca44c14dc0e136583dde241f742f141ec518adf26c5b08d59d92936300d06092a864886f70d01010b050003820101008c770bcf525fc99d9f8f04d279b724bbb2bebc42184e671aa392b058265b097de2d9f668f64e696d0048a00023ad2c6dfd5cc6f41bde11810d0fbad97822c6863012a4f0e8430a385cfeb699278e99622af1cca45419cb61d59dcbb80464cf65ff07d15c05f69caf2a69970cae8b4533f5a006b9b9414cbaa6d8a8ac862c430dadb8149e6c151ff75efe0a69b17658b85dbd95a6eb363e52784b9f11c78bbe906ca303f58bbeab8748e92d31344a6c297dfab4738351602951622cd3730f2b94ba7e68ecc1f678a79f5535f6758be357cf0a8a9efa907c2980b2d281c270b7fb97d8c3e1d3af37089002d09e7524d8d441950da466ee77489d25018e5cfa05fe0000000469308204653082034da0030201020210400175048314a4c8218c84a90c16cddf300d06092a864886f70d01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e311730150603550403130e44535420526f6f74204341205833301e170d3230313030373139323134305a170d3231303932393139323134305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a38201683082016430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186304b06082b06010505070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e63727970742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414142eb317b75856cbae500940e61faf9d8b14c2c6301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a864886f70d01010b05000382010100d94ce0c9f584883731dbbb13e2b3fc8b6b62126c58b7497e3c02b7a81f2861ebcee02e73ef49077a35841f1dad68f0d8fe56812f6d7f58a66e3536101c73c3e5bd6d5e01d76e72fb2aa0b8d35764e55bc269d4d0b2f77c4bc3178e887273dcfdfc6dbde3c90b8e613a16587d74362b55803dc763be8443c639a10e6b579e3f29c180f6b2bd47cbaa306cb732e159540b1809175e636cfb96673c1c730c938bc611762486de400707e47d2d66b525a39658c8ea80eecf693b96fce68dc033f389f8292d14142d7ef06170955df70be5c0fb24faec8ecb61c8ee637128a82c053b77ef9b5e0364f051d1e485535cb00297d47ec634d2ce1000e4b1df3ac2ea17be0000";

        let hello_client = hex::decode(hello_client_hex).unwrap();
        hexdump::hexdump(&hello_client);

        let cert = hex::decode(cert_hex).unwrap();
        hexdump::hexdump(&cert);

        let mut wireshark = Message::read_bytes(cert.as_slice()).unwrap();
        wireshark.version = TLSv1_3;
        wireshark.decode_payload();
        println!("{:#?}", wireshark);
    }

    /// This is the simplest possible client using rustls that does something useful:
    /// it accepts the default configuration, loads some root certs, and then connects
    /// to google.com and issues a basic HTTP request.  The response is printed to stdout.
    ///
    /// It makes use of rustls::Stream to treat the underlying TLS session as a basic
    /// bi-directional stream -- the underlying IO is performed transparently.
    ///
    /// Note that `unwrap()` is used to deal with networking errors; this is not something
    /// that is sensible outside of example code.
    #[test]
    fn execute_rustls() {
        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        let dns_name = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
        let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
        let mut sock = TcpStream::connect("google.com:443").unwrap();
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);
        tls.write_all(
            concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
            )
                .as_bytes(),
        )
            .unwrap();
        let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
        writeln!(
            &mut std::io::stderr(),
            "Current ciphersuite: {:?}",
            ciphersuite.suite
        )
            .unwrap();
        let mut plaintext = Vec::new();
        tls.read_to_end(&mut plaintext).unwrap();
        stdout().write_all(&plaintext).unwrap();
    }
}
