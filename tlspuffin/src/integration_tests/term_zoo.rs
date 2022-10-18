mod tests {
    use std::collections::HashSet;

    use puffin::{
        algebra::dynamic_function::DescribableFunction, fuzzer::term_zoo::TermZoo,
        libafl::bolts::rands::StdRand,
    };

    use crate::{
        query::TlsQueryMatcher,
        tls::{fn_impl::*, TLS_SIGNATURE},
    };

    #[test]
    /// Tests whether all function symbols can be used when generating random terms
    fn test_term_generation() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::<TlsQueryMatcher>::generate(&TLS_SIGNATURE, &mut rand);

        let subgraphs = zoo
            .terms()
            .iter()
            .enumerate()
            .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
            .collect::<Vec<_>>();

        let _graph = format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            subgraphs.join("\n")
        );

        let all_functions = crate::tls::TLS_SIGNATURE
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
        println!("{:?}", &difference);
        assert_eq!(difference.count(), 0);
        //println!("{}", graph);
    }
}
