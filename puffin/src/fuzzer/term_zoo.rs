//! Generates a zoo of terms form a [`Signature`]. For each function symbol in the signature
//! a closed term is generated and added to the zoo.

use libafl::bolts::rands::Rand;

use crate::{
    algebra::{
        atoms::Function,
        signature::{FunctionDefinition, Signature},
        Term,
    },
    fuzzer::mutations::util::Choosable,
};

const MAX_DEPTH: u16 = 8; // how deep terms we allow max
const MAX_TRIES: u16 = 100; // How often we want to try to generate before stopping

pub struct TermZoo {
    terms: Vec<Term>,
}

impl TermZoo {
    pub fn generate<R: Rand>(signature: &Signature, rand: &mut R) -> Self {
        let terms = signature
            .functions
            .iter()
            .filter_map(|def| {
                let mut counter = MAX_TRIES;

                loop {
                    if counter == 0 {
                        break None;
                    }

                    counter -= 1;

                    if let Some(term) = Self::generate_term(signature, def, MAX_DEPTH, rand) {
                        break Some(term);
                    }
                }
            })
            .collect::<Vec<_>>();

        Self { terms }
    }

    fn generate_term<R: Rand>(
        signature: &Signature,
        (shape, dynamic_fn): &FunctionDefinition,
        depth: u16,
        rand: &mut R,
    ) -> Option<Term> {
        if depth == 0 {
            // Reached max depth
            return None;
        }

        let required_types = &shape.argument_types;

        let mut subterms = Vec::with_capacity(required_types.len());

        for typ in required_types {
            if let Some(possibilities) = signature.functions_by_typ.get(typ) {
                if let Some(possibility) = possibilities.choose(rand) {
                    if let Some(subterm) =
                        Self::generate_term(signature, possibility, depth - 1, rand)
                    {
                        subterms.push(subterm)
                    } else {
                        // Max depth reached
                        return None;
                    }
                } else {
                    // No possibilities available
                    return None;
                }
            } else {
                // Type not available
                return None;
            }
        }

        Some(Term::Application(
            Function::new(shape.clone(), dynamic_fn.clone()),
            subterms,
        ))
    }

    pub fn choose_filtered<P, R: Rand>(&self, filter: P, rand: &mut R) -> Option<&Term>
    where
        P: FnMut(&&Term) -> bool,
    {
        self.terms.choose_filtered(filter, rand)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use libafl::bolts::rands::StdRand;

    use crate::{
        algebra::dynamic_function::DescribableFunction,
        fuzzer::term_zoo::TermZoo,
        tls::{
            fn_impl::{
                fn_certificate_transcript, fn_client_finished_transcript, fn_decrypt_application,
                fn_rsa_sign_client, fn_rsa_sign_server, fn_server_finished_transcript,
                fn_server_hello_transcript,
            },
            SIGNATURE,
        },
    };

    #[test]
    fn test_term_generation() {
        let mut rand = StdRand::with_seed(101);
        let zoo = TermZoo::generate(&SIGNATURE, &mut rand);

        let subgraphs = zoo
            .terms
            .iter()
            .enumerate()
            .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
            .collect::<Vec<_>>();

        let _graph = format!(
            "strict digraph \"Trace\" {{ splines=true; {} }}",
            subgraphs.join("\n")
        );

        let all_functions = SIGNATURE
            .functions
            .iter()
            .map(|(shape, _)| shape.name.to_string())
            .collect::<HashSet<String>>();
        let mut successfully_built_functions = zoo
            .terms
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
