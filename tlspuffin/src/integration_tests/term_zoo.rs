#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::collections::HashSet;
    use std::fmt::Debug;

    use puffin::algebra::TermType;
    use puffin::trace::TraceContext;
    use puffin::{algebra::dynamic_function::DescribableFunction, codec, fuzzer::term_zoo::TermZoo, libafl::bolts::rands::StdRand};
    use puffin::algebra::error::FnError;
    use puffin::codec::Encode;
    use puffin::error::Error;
    use puffin::protocol::ProtocolBehavior;

    use crate::{query::TlsQueryMatcher, tls::{fn_impl::*, TLS_SIGNATURE}, try_downcast};
    use crate::protocol::TLSProtocolBehavior;
    use crate::tls::{
    fn_impl::*,
    rustls::msgs::{
    enums::{CipherSuite, Compression, HandshakeType, ProtocolVersion},
handshake::{Random, ServerExtension, SessionID},
},

trace_helper::TraceHelper,
};

    use crate::put_registry::TLS_PUT_REGISTRY;
    use crate::tls::rustls::hash_hs::HandshakeHash;
    use crate::tls::rustls::key::{Certificate, PrivateKey};
    use crate::tls::rustls::msgs::alert::AlertMessagePayload;
    use crate::tls::rustls::msgs::enums::{ExtensionType, NamedGroup, SignatureScheme};
    use crate::tls::rustls::msgs::handshake::{CertificateEntry, ClientExtension, HasServerExtensions};
    use crate::tls::rustls::msgs::message::{Message, MessagePayload, OpaqueMessage};

    #[test]
    /// Tests whether all function symbols can be used when generating random terms
    fn test_term_generation() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate(&TLS_SIGNATURE, &mut rand);
        // println!("zoo size: {}", zoo.terms().len());
        let subgraphs = zoo
            .terms()
            .iter()
            .enumerate()
            .map(|(i, term)| term.term.dot_subgraph(false, i, i.to_string().as_str()))
            .collect::<Vec<_>>();
        // println!("subgraph size: {}", subgraphs.len());

        let _graph = format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            subgraphs.join("\n")
        );

        let all_functions = TLS_SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();

        let mut successfully_built_functions = zoo
            .terms()
            .iter()
            .map(|term| term.name().to_string())
            .collect::<HashSet<String>>();

        let ignored_functions = [
            fn_decrypt_application.name(), // FIXME: why ignore this?
            fn_rsa_sign_client.name(), // FIXME: We are currently excluding this, because an attacker does not have access to the private key of alice, eve or bob.
            fn_rsa_sign_server.name(),
            // transcript functions -> ClaimList is usually available as Variable
            fn_server_finished_transcript.name(),
            fn_client_finished_transcript.name(),
            fn_server_hello_transcript.name(),
            fn_certificate_transcript.name(),
        ]
        .iter()
        .map(|fn_name| fn_name.to_string())
        .collect::<HashSet<String>>();

        successfully_built_functions.extend(ignored_functions);

        let difference = all_functions.difference(&successfully_built_functions);
        // println!("Diff: {:?}\n", &difference);
        // println!("Successfully built: {:?}\n", &successfully_built_functions);
        // println!("All functions: {:?}\n", &all_functions);
        assert_eq!(difference.count(), 0);
        //println!("{}", graph);
    }

    #[test]
    /// Tests whether all function symbols can be used when generating random terms and then be correctly evaluated
    fn test_term_eval_custom1() {
        /// WIP: testing out solutions for evaluating almost any term
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate(&TLS_SIGNATURE, &mut rand);
        // println!("zoo size: {}", zoo.terms().len());
        let terms = zoo.terms();
        let number_terms = terms.len();
        let mut eval_count = 0;
        // println!("zoo terms: {}", zoo.terms());
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, Default::default());

        for term in terms.iter() {
            let default_box = Box::new(());
            let mut term_any = term
                .term
                .evaluate_lazy(&ctx)
                .unwrap_or(default_box.clone());

            match term.evaluate_symbolic(&ctx) {
                Ok(eval) => {
                    eval_count += 1;
                    // println!(
                    //     " [x] Succeed evaluation of term: {} \nresulting in {:?}\n",
                    //     term, eval
                    // );
                }
                Err(e) => {
                    match e.clone() {
                        Error::Fn(FnError::Unknown(ee)) =>
                            println!("[Unknown] Failed evaluation due to FnError::Unknown: [{}]", e),
                        Error::Fn(FnError::Crypto(ee)) =>
                            println!("[Crypto] Failed evaluation due to FnError::Crypto:[{}]", e),
                        Error::Fn(FnError::Malformed(ee)) => (),
                            // println!("[Malformed] Failed evaluation due to FnError::Crypto:[{}]", e),
                        Error::Term(ee) => {
                        //     println!("[Term] Failed evaluation due to Error:Term: [{}]\n ===For Term: [{}]", e, term),
                        // _ => {
                            println!("===========================\n\n\n [OTHER] Failed evaluation of term: {} \n with error {}. Trying to downcast manually:", term, e);
                            let t1 = term.evaluate_lazy(&ctx);
                            if t1.is_ok() {print!("Evaluate_lazy success. ");
                            match t1.expect("NO").downcast_ref::<Vec<u8>>() {
                                Some(downcast) => {
                                    print!("Downcast succeeded: {downcast:?}. ");
                                    let bitstring = Encode::get_encoding(downcast);
                                    print!("Encoding succeeded:: {bitstring:?}. ");
                                },
                                _ => {println!("Downcast FAILED. ")},
                            }
                            } else {println!("Evaluate_lazy FAILED. ");
                            }
                        }
                        _ => {},
                    }
                }
            }
        }
        print!("number_terms: {}, eval_count: {}\n", number_terms, eval_count);
        assert_eq!(number_terms, eval_count);
    }
}
