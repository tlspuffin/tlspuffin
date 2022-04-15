#[cfg(test)]
pub mod seeds {
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus::{Exited, Signaled};
    use nix::sys::wait::{waitpid, WaitPidFlag};
    use nix::unistd::{fork, ForkResult};
    use test_log::test;

    use crate::agent::AgentName;
    use crate::openssl_binding::{make_deterministic, openssl_version};
    use crate::trace::Action;
    use crate::{fuzzer::seeds::*, trace::TraceContext};

    fn expect_crash<R>(mut func: R)
    where
        R: FnMut(),
    {
     match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                let status = waitpid(child, Option::from(WaitPidFlag::empty())).unwrap();

                if let Signaled(_, signal, _) = status {
                    if signal != Signal::SIGSEGV && signal != Signal::SIGABRT {
                        panic!("Trace did not crash with SIGSEGV/SIGABRT!")
                    }
                } else if let Exited(_, code) = status {
                    if code == 0 {
                        panic!("Trace did not crash exit with non-zero code (AddressSanitizer)!")
                    }
                } else {
                    panic!("Trace did not signal!")
                }
            }
            Ok(ForkResult::Child) => {
                func();
                std::process::exit(0);
            }
            Err(_) => panic!("Fork failed"),
        }
    }
    #[test]
    fn test_version() {
        println!("{}", openssl_version());
    }

    #[cfg(all(feature = "openssl101f", feature = "asan"))]
    #[test]
    fn test_seed_hearbeat() {
        expect_crash(|| {
            make_deterministic();
            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_heartbleed(client, server);

            trace.execute(&mut ctx).unwrap();
        })
    }

    #[test]
    fn test_seed_cve_2021_3449() {
        if !openssl_version().contains("1.1.1j") {
            return;
        }
        expect_crash(|| {
            make_deterministic();
            let mut ctx = TraceContext::new();
            let server = AgentName::first();
            let trace = seed_cve_2021_3449(server);

            trace.execute(&mut ctx).unwrap();
        });
    }

    #[test]
    fn test_seed_client_attacker12() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let server = AgentName::first();
        let trace = seed_client_attacker12(server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_client_attacker() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let server = AgentName::first();
        let trace = seed_client_attacker(server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_client_attacker_full() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let server = AgentName::first();
        let (trace, ..) = seed_client_attacker_full(server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(all(feature = "tls13", feature = "session-resumption"))]
    #[test]
    fn test_seed_session_resumption_dhe() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_dhe(initial_server, server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(all(feature = "tls13", feature = "session-resumption"))]
    #[test]
    fn test_seed_session_resumption_dhe_full() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_dhe_full(initial_server, server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(all(feature = "tls13", feature = "session-resumption"))]
    #[test]
    fn test_seed_session_resumption_ke() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_ke(initial_server, server);

        trace.execute(&mut ctx).unwrap();

        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", server_state);
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_successful() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful(client, server);
        //println!("{}", trace);

        trace.execute(&mut ctx).unwrap();

        let client_state = ctx.find_agent(client).unwrap().stream.describe_state();
        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", client_state);
        //println!("{}", server_state);
        assert!(client_state.contains("SSL negotiation finished successfully"));
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    // Cases:
    // expected = "Not the best cipher choosen", // in case MITM attack succeeded because transcript is ignored -> We detect the MITM and error
    // expected = "decryption failed or bad record mac"  // in case MITM attack did fail
    #[should_panic]
    fn test_seed_successful_mitm() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful_mitm(client, server);
        //println!("{}", trace);

        trace.execute(&mut ctx).unwrap();

        let client_state = ctx.find_agent(client).unwrap().stream.describe_state();
        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", client_state);
        //println!("{}", server_state);
        assert!(client_state.contains("SSL negotiation finished successfully"));
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[cfg(feature = "tls13")] // require version which supports TLS 1.3
    #[test]
    fn test_seed_successful_with_ccs() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful_with_ccs(client, server);

        trace.execute(&mut ctx).unwrap();

        let client_state = ctx.find_agent(client).unwrap().stream.describe_state();
        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", client_state);
        //println!("{}", server_state);
        assert!(client_state.contains("SSL negotiation finished successfully"));
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    // require version which supports TLS 1.3
    // LibreSSL does not yet support PSK
    #[cfg(all(feature = "tls13", feature = "session-resumption"))]
    #[test]
    fn test_seed_successful_with_tickets() {
        make_deterministic();
        let mut ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful_with_tickets(client, server);

        trace.execute(&mut ctx).unwrap();

        let client_state = ctx.find_agent(client).unwrap().stream.describe_state();
        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", client_state);
        //println!("{}", server_state);
        assert!(client_state.contains("SSL negotiation finished successfully"));
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    #[test]
    fn test_seed_successful12() {
        // println!("{}", openssl_version());

        let mut ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful12(client, server);

        trace.execute(&mut ctx).unwrap();

        let client_state = ctx.find_agent(client).unwrap().stream.describe_state();
        let server_state = ctx.find_agent(server).unwrap().stream.describe_state();
        //println!("{}", client_state);
        //println!("{}", server_state);
        assert!(client_state.contains("SSL negotiation finished successfully"));
        assert!(server_state.contains("SSL negotiation finished successfully"));
    }

    // Vulnerable up until OpenSSL 1.0.1j
    #[cfg(all(feature = "openssl101f", feature = "asan"))]
    #[test]
    #[ignore] // We can not check for this vulnerability right now
    fn test_seed_freak() {
        expect_crash(|| {
            make_deterministic();
            //println!("{}", openssl_version());

            let mut ctx = TraceContext::new();
            let client = AgentName::first();
            let server = client.next();
            let trace = seed_freak(client, server);

            trace.execute(&mut ctx).unwrap();
        });
    }

    #[test]
    fn test_term_sizes() {
        let client = AgentName::first();
        let server = client.next();

        for trace in [
            seed_successful12(client, server),
            seed_successful(client, server),
            seed_client_attacker12(server),
            seed_cve_2021_3449(server),
            seed_client_attacker(server),
        ] {
            for step in &trace.steps {
                match &step.action {
                    Action::Input(input) => {
                        // should be below 200, else we should increase MAX_TERM_SIZE in fuzzer setup
                        assert!(input.recipe.size() < 200);
                    }
                    Action::Output(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
pub mod serialization {
    use test_log::test;

    use crate::agent::AgentName;
    use crate::fuzzer::seeds::*;
    use crate::{
        fuzzer::seeds::seed_successful,
        trace::{Trace, TraceContext},
    };

    #[test]
    fn test_serialisation_seed_seed_session_resumption_dhe_json() {
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_dhe(initial_server, server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialisation_seed_seed_session_resumption_ke_json() {
        let initial_server = AgentName::first();
        let server = initial_server.next();
        let trace = seed_session_resumption_ke(initial_server, server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialisation_seed_client_attacker12_json() {
        let server = AgentName::first();
        let trace = seed_client_attacker12(server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialisation_seed_successful_json() {
        /*let _ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful(client, server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);*/
    }

    #[test]
    fn test_serialisation_seed_successful_postcard() {
        let _ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful(client, server);

        let serialized1 = postcard::to_allocvec(&trace).unwrap();

        let deserialized_trace = postcard::from_bytes::<Trace>(serialized1.as_slice()).unwrap();
        let serialized2 = postcard::to_allocvec(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialisation_seed_successful12_json() {
        let _ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_successful12(client, server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialisation_seed_heartbleed() {
        let _ctx = TraceContext::new();
        let client = AgentName::first();
        let server = client.next();
        let trace = seed_heartbleed(client, server);

        let serialized1 = serde_json::to_string_pretty(&trace).unwrap();

        let deserialized_trace = serde_json::from_str::<Trace>(serialized1.as_str()).unwrap();
        let serialized2 = serde_json::to_string_pretty(&deserialized_trace).unwrap();

        assert_eq!(serialized1, serialized2);
    }
}

#[cfg(test)]
pub mod rustls {
    use std::convert::TryFrom;
    use std::{
        io::{stdout, Read, Write},
        net::TcpStream,
        sync::Arc,
    };

    use rustls::internal::msgs::enums::ContentType;
    use rustls::msgs::base::Payload;
    use rustls::msgs::codec::Reader;
    use rustls::msgs::message::OpaqueMessage;
    use rustls::{
        self,
        internal::msgs::{
            enums::{
                HandshakeType,
                ProtocolVersion::{TLSv1_2, TLSv1_3},
            },
            handshake::{
                ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, Random, SessionID,
            },
            message::{Message, MessagePayload::Handshake},
        },
        Connection, ProtocolVersion, RootCertStore,
    };
    use test_log::test;

    #[test]
    fn test_rustls_message_stability_ch() {
        let hello_client_hex = "1603010136010001320303aa1795f64f48fcfcd0121368f88f176fe2570b07\
        68bbc85e9f2c80c557553d7d20e1e15d0028932f4f7479cf256302b7847d81a68e708525f9d38d94fc6ef742a30\
        03e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009\
        c0130033009d009c003d003c0035002f00ff010000ab00000012001000000d6d6178616d6d616e6e2e6f7267000\
        b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306\
        03080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b00090\
        80304030303020301002d00020101003300260024001d00209b8a24e29770f7ed95bf330e7e3929b21090350a41\
        5ab4cdf01b04e9ffc0fc50";

        let hello_client = hex::decode(hello_client_hex).unwrap();
        //hexdump::hexdump(&hello_client);

        let opaque_message =
            OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
        let _message = Message::try_from(opaque_message).unwrap();
        //println!("{:#?}", message);
    }

    #[test]
    fn test_heartbleed_ch() {
        // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
        let hello_client_hex = "
            16 03 03 00  dc 01 00 00 d8 03 03 53
            43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
            bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
            00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
            00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
            c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
            c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
            c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
            c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
            00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
            03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
            00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
            00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
            00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
            00 0f 00 01 01";

        let hello_client = hex::decode(
            hello_client_hex
                .to_string()
                .replace(' ', "")
                .replace('\n', ""),
        )
        .unwrap();
        //hexdump::hexdump(&hello_client);

        let opaque_message =
            OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
        let _message = Message::try_from(opaque_message).unwrap();
        //println!("{:#?}", message);
    }

    #[test]
    fn test_rustls_message_stability_ch_renegotiation() {
        // Derived from "openssl s_client -msg -connect localhost:44330" and then pressing R
        let hello_client_hex = "16030300cc\
        010000c8030368254f1b232142c49512b09ac3929df07b6d461dc15473c064\
        e1ffdfbfd5cc9d000036c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac014003\
        9c009c0130033009d009c003d003c0035002f01000069ff01000d0cdcf098f907352157bc31b073000b00040300\
        0102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e0403050306030807080\
        80809080a080b080408050806040105010601030302030301020103020202040205020602";

        let hello_client = hex::decode(hello_client_hex).unwrap();
        //hexdump::hexdump(&hello_client);

        let opaque_message =
            OpaqueMessage::read(&mut Reader::init(hello_client.as_slice())).unwrap();
        let _message = Message::try_from(opaque_message).unwrap();
        //println!("{:#?}", message);
    }

    /// https://github.com/tlspuffin/rustls/commit/d5d26a119f5a0edee43ebcd77f3bbae8bbd1db7d
    #[test]
    fn test_server_hello_parsing() {
        let hex = "160303004a020000460303de257a3941501c11fa7898af1b1b2aea4f5e39e521b35dc84ffab\
        e830e9a98ec20e1cb49645b1cd6e2d0aa5c87b5a3837bcf33334e96c37a77a79c9df63413dc15c02f00";
        let binary = hex::decode(hex).unwrap();
        let opaque_message = OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
        let _message = Message::try_from(opaque_message).unwrap();
        //println!("{:#?}", message);
    }

    #[test]
    fn test_encrypted_tls12_messages() {
        let hexn = vec![
           "1603030028155e38ddd323ca97440b4bb44fe810e9f4d10e5280795ca0660c7d8c8dddcd95355538a3d2cc0256",
        "16030300280d8d288b7a398d5c078280388c71106391756b19d1bb5c95ec18f5de8a0c772062df0d18f24e02b5",
        "16030300280032e43a49aa2134ac20d701f3427aee8cf7c397eb2b9ed88a09bfba4c9fe94a10e6c88be89a7a67",
        "1603030028149ee35e3205a0fea0fd2f14555c7fd0b6acc2bf926a674841375ed061dbf359ac64905c8c616095",
        "1603030028182bdc85dc708633cc973b23173fd1e9a7296c744ce44443c678b2be0d9c0b050b3b26f9cd697ed9",
        "160303002805330e9cee1941f19b744f7ddab94a8caf2afcc8ceb97e4389c4f7c0b329219bcbf4d68c1fc71266",
        "1603030028fe4121bb8fb7467a63b25cc96f2eb3df1ef61fc31431a37db61825a7680d85b9fc04e980055e65db",
        ];

        for hex in hexn {
            let binary = hex::decode(hex).unwrap();
            let opaque_message = OpaqueMessage::read(&mut Reader::init(binary.as_slice())).unwrap();
            let _message = Message::try_from(opaque_message).unwrap();
            //println!("{:#?}", message);
        }
    }
    #[test]
    fn test_rustls_message_stability_cert() {
        let cert_hex = "16030309b50b0009b1000009ad00053a308205363082041ea00302010202120400ca59\
        61d39c1622093596f2132488f93e300d06092a864886f70d01010b05003032310b3009060355040613025553311\
        63014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d323130333238\
        3031343335385a170d3231303632363031343335385a301c311a3018060355040313117777772e6d6178616d6d6\
        16e6e2e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100b8ad1a3825f4\
        aa8f8cdf5221a5d98d29f93be72f470397e07e1ceca379376bf1b148d19feaf6c5d3b01b344369bcc50dd33f967\
        b281eec6edf4e9ee6b1a134589d40b3d3c2b2d51814ecafebcd59da1b01aea221af57f50e523694ac7603bf363b\
        3a5380d48bef06cffbae66123046a7cfb3055f35755b50c71c93aef4c2a0bc8badb56b37d07be0d3319cac9b2f2\
        10a29115b4b6377734b647088adcbc12cc82a59a5f10fe2478ab2937f4ed667fbbdda3c468148f974da14dda787\
        234811457d4a2d99677f27a3eae68f782c1291243e02653a4fe70ca4cb3d3eda66ba47926e25b25045b92ef8c20\
        a89b1b5fce69ac18091f1229d9be473f96f23ed40d43f0203010001a382025a30820256300e0603551d0f0101ff\
        0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d13010\
        1ff04023000301d0603551d0e0416041412b43a1e54091741afc831d1e4de7babcb110ebe301f0603551d230418\
        30168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b0\
        60105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b0601050507300286166874\
        74703a2f2f72332e692e6c656e63722e6f72672f302b0603551d1104243022820d6d6178616d6d616e6e2e6f726\
        782117777772e6d6178616d6d616e6e2e6f7267304c0603551d20044530433008060667810c0102013037060b2b\
        0601040182df130101013028302606082b06010505070201161a687474703a2f2f6370732e6c657473656e63727\
        970742e6f726730820103060a2b06010401d6790204020481f40481f100ef0076004494652eb0eeceafc44007d8\
        a8fe28c0dae682bed8cb31b53fd33396b5b681a80000017876b7770e000004030047304502201c5b58adfa5df8a\
        bf6077d94b765750a24d32b49b3af2dcf5c65efaf32c949d6022100866e2301bf3633cf54a33124459c9dc69e6f\
        953c9b2200f7c73919cefee849150075007d3ef2f88fff88556824c2c0ca9e5289792bc50e78097f2e6a9768997\
        e22f0d70000017876b7772e00000403004630440220030a54d2296566cab9b5fa3e6505566e5e014d48f15f6cd8\
        727896e2cc352eb302207aff1ae19ca44c14dc0e136583dde241f742f141ec518adf26c5b08d59d92936300d060\
        92a864886f70d01010b050003820101008c770bcf525fc99d9f8f04d279b724bbb2bebc42184e671aa392b05826\
        5b097de2d9f668f64e696d0048a00023ad2c6dfd5cc6f41bde11810d0fbad97822c6863012a4f0e8430a385cfeb\
        699278e99622af1cca45419cb61d59dcbb80464cf65ff07d15c05f69caf2a69970cae8b4533f5a006b9b9414cba\
        a6d8a8ac862c430dadb8149e6c151ff75efe0a69b17658b85dbd95a6eb363e52784b9f11c78bbe906ca303f58bb\
        eab8748e92d31344a6c297dfab4738351602951622cd3730f2b94ba7e68ecc1f678a79f5535f6758be357cf0a8a\
        9efa907c2980b2d281c270b7fb97d8c3e1d3af37089002d09e7524d8d441950da466ee77489d25018e5cfa05fe0\
        000000469308204653082034da0030201020210400175048314a4c8218c84a90c16cddf300d06092a864886f70d\
        01010b0500303f31243022060355040a131b4469676974616c205369676e617475726520547275737420436f2e3\
        11730150603550403130e44535420526f6f74204341205833301e170d3230313030373139323134305a170d3231\
        303932393139323134305a3032310b300906035504061302555331163014060355040a130d4c6574277320456e6\
        372797074310b300906035504031302523330820122300d06092a864886f70d01010105000382010f003082010a\
        0282010100bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a\
        3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec09424\
        2587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a5403\
        46b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715d\
        d446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a670171\
        4af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb150203010001a3820168308201\
        6430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020186304b06082b0601050\
        5070101043f303d303b06082b06010505073002862f687474703a2f2f617070732e6964656e74727573742e636f\
        6d2f726f6f74732f647374726f6f74636178332e703763301f0603551d23041830168014c4a7b1a47b2c71fadbe\
        14b9075ffc4156085891030540603551d20044d304b3008060667810c010201303f060b2b0601040182df130101\
        013030302e06082b060105050702011622687474703a2f2f6370732e726f6f742d78312e6c657473656e6372797\
        0742e6f7267303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c2e6964656e74727573742e\
        636f6d2f445354524f4f544341583343524c2e63726c301d0603551d0e04160414142eb317b75856cbae500940e\
        61faf9d8b14c2c6301d0603551d250416301406082b0601050507030106082b06010505070302300d06092a8648\
        86f70d01010b05000382010100d94ce0c9f584883731dbbb13e2b3fc8b6b62126c58b7497e3c02b7a81f2861ebc\
        ee02e73ef49077a35841f1dad68f0d8fe56812f6d7f58a66e3536101c73c3e5bd6d5e01d76e72fb2aa0b8d35764\
        e55bc269d4d0b2f77c4bc3178e887273dcfdfc6dbde3c90b8e613a16587d74362b55803dc763be8443c639a10e6\
        b579e3f29c180f6b2bd47cbaa306cb732e159540b1809175e636cfb96673c1c730c938bc611762486de400707e4\
        7d2d66b525a39658c8ea80eecf693b96fce68dc033f389f8292d14142d7ef06170955df70be5c0fb24faec8ecb6\
        1c8ee637128a82c053b77ef9b5e0364f051d1e485535cb00297d47ec634d2ce1000e4b1df3ac2ea17be0000";

        let cert = hex::decode(cert_hex).unwrap();
        //hexdump::hexdump(&cert);

        let mut opaque_message = OpaqueMessage::read(&mut Reader::init(cert.as_slice())).unwrap();
        // Required for choosing the correct parsing function
        opaque_message.version = TLSv1_3;
        let _message = Message::try_from(opaque_message).unwrap();
        //println!("{:#?}", message);
    }

    #[test]
    fn test_encrypted_tls12_into_message() {
        let opaque = OpaqueMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(vec![1, 2, 3]),
        };

        let _message = Message::try_from(opaque).unwrap();
        //println!("{:?}", message);
    }

    #[test]
    fn test_rustls_message_stability() {
        let random = [0u8; 32];
        let message = Message {
            version: TLSv1_2,
            payload: Handshake(HandshakeMessagePayload {
                typ: HandshakeType::ClientHello,
                payload: HandshakePayload::ClientHello(ClientHelloPayload {
                    client_version: ProtocolVersion::TLSv1_3,
                    random: Random::from(random),
                    session_id: SessionID::empty(),
                    cipher_suites: vec![],
                    compression_methods: vec![],
                    extensions: vec![],
                }),
            }),
        };

        let mut out: Vec<u8> = Vec::new();
        out.append(&mut OpaqueMessage::from(message).encode());
        //hexdump::hexdump(&out);

        let _decoded_message =
            Message::try_from(OpaqueMessage::read(&mut Reader::init(out.as_slice())).unwrap())
                .unwrap();

        //println!("{:?}", decoded_message);
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
    //#[test] Disable for now as it can fail because of missing internet
    fn test_execute_rustls() {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = rustls::ConfigBuilder::with_safe_defaults()
            .for_client()
            .unwrap()
            .with_root_certificates(root_store, &[])
            .with_no_client_auth();

        let dns_name = webpki::DnsNameRef::try_from_ascii_str("google.com").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), dns_name).unwrap();
        let mut sock = TcpStream::connect("google.com:443").unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let _written = tls.write(
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
        let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
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
