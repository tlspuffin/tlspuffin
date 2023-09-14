#[allow(clippy::ptr_arg)]
#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::collections::HashSet;
    use std::fmt::Debug;

    use puffin::algebra::TermType;
    use puffin::trace::TraceContext;
    use puffin::{
        algebra::dynamic_function::DescribableFunction, fuzzer::term_zoo::TermZoo,
        libafl::bolts::rands::StdRand,
    };
    use puffin::codec::Codec;

    use crate::{
        query::TlsQueryMatcher,
        tls::{fn_impl::*, TLS_SIGNATURE},
    };
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
    use crate::tls::rustls::key::PrivateKey;
    use crate::tls::rustls::msgs::alert::AlertMessagePayload;
    use crate::tls::rustls::msgs::enums::{ExtensionType, NamedGroup};
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
        let mut eval_count_any = 0;
        // println!("zoo terms: {}", zoo.terms());
        let mut ctx = TraceContext::new(&TLS_PUT_REGISTRY, Default::default());

        for term in terms.iter() {
            let default_box = Box::new(());
            let mut term_any = term
                .term
                .evaluate_lazy(&ctx)
                .unwrap_or(default_box);

            // let _ = term_any.downcast_ref::<Message>()
            //     .map(|b| {
            //         eval_count += 1;
            //         println!("--> Succeed evaluation of Message: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<OpaqueMessage>()
            //     .map(|b| {
            //         eval_count += 1;
            //         println!("--> Succeed evaluation of OpaqueMessage: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<CipherSuite>()
            //     .map(|b| {
            //                 eval_count += 1;
            //              println!("--> Succeed evaluation of CipherSuite: {} \nresulting in {:?}\n",
            //                    term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<AlertMessagePayload>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of AlertMessagePayload: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<Compression>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of Compression: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<ExtensionType>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of ExtensionType: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<NamedGroup>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of NamedGroup: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<ClientExtension>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of ClientExtension: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<Random>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of Random: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<ServerExtension>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of ServerExtension: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<SessionID>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of SessionID: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<Message>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of Message: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<MessagePayload>()
            //     .map(|b| {                    eval_count += 1;let mut buf = Vec::new();
            //         println!("--> Succeed evaluation of MessagePayload: {} \nresulting in {:?}\n",
            //                  term, {b.encode(&mut buf);buf})});
            // let _ = term_any.downcast_ref::<CertificateEntry>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of CertificateEntry: {} \nresulting in {:?}\n",
            //                  term, b.get_encoding())});
            // let _ = term_any.downcast_ref::<HandshakeHash>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of HandshakeHash: {} \nresulting in {:?}\n",
            //                  term, b.get_current_hash_raw())});
            // let _ = term_any.downcast_ref::<PrivateKey>()
            //     .map(|b| {                    eval_count += 1;
            //         println!("--> Succeed evaluation of PrivateKey: {} \nresulting in {:?}\n",
            //                  term, b.0.get_encoding())});

// TODO: invesitagte why we get different numbers here...
            match term.evaluate_symbolic(&ctx) {
                Ok(eval) => {
                    eval_count_any += 1;
                    // println!(
                    //     " [x] Succeed evaluation of term: {} \nresulting in {:?}\n",
                    //     term, eval
                    // );
                }
                Err(e) => {
                    println!(" [ ] Failed evaluation of term: {} \n with error {}", term, e);
                }
            }
        }
        print!("number_terms: {}, eval_count: {}, eval_count_any: {}", number_terms, eval_count, eval_count_any);
        assert_eq!(number_terms, eval_count);
    }
}
