use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use libafl::bolts::rands::StdRand;
use libafl::corpus::InMemoryCorpus;
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::StdState;
use openssl::rand::rand_bytes;

use crate::agent::{AgentDescriptor, AgentName, TLSVersion};
use crate::fuzzer::mutations::util::{TermConstraints, TracePath};
use crate::fuzzer::mutations::{
    RemoveAndLiftMutator, RepeatMutator, ReplaceMatchMutator, ReplaceReuseMutator, SkipMutator,
    SwapMutator,
};
use crate::fuzzer::seeds::*;
use crate::fuzzer::term_zoo::generate_term_zoo;
use crate::openssl_binding::make_deterministic;
use crate::term::dynamic_function::DescribableFunction;
use crate::term::Term;
use crate::tls::fn_impl::*;
use crate::tls::SIGNATURE;
use crate::trace::{Action, InputAction, Step, Trace, TraceContext};

#[cfg(feature = "deterministic")]
#[test]
fn test_openssl_no_randomness() {
    make_deterministic(); // his affects also other tests, which is fine as we generally prefer deterministic tests
    let mut buf1 = [0; 2];
    rand_bytes(&mut buf1).unwrap();
    assert_eq!(buf1, [70, 100]);
}

/// Checks whether repeat can repeat the last step
#[test]
fn test_repeat_mutator() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();
    let _trace = seed_client_attacker12(server);

    let mut mutator = RepeatMutator::new(15);

    fn check_is_encrypt12(step: &Step) -> bool {
        if let Action::Input(input) = &step.action {
            if input.recipe.name() == fn_encrypt12.name() {
                return true;
            }
        }
        false
    }

    loop {
        let mut trace = seed_client_attacker12(server);
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        let length = trace.steps.len();
        if let Some(last) = trace.steps.get(length - 1) {
            if check_is_encrypt12(last) {
                if let Some(step) = trace.steps.get(length - 2) {
                    if check_is_encrypt12(step) {
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn test_replace_match_mutator() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();

    let mut mutator = ReplaceMatchMutator::new(TermConstraints::default());

    loop {
        let mut trace = seed_client_attacker12(server);
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if let Some(last) = trace.steps.iter().last() {
            match &last.action {
                Action::Input(input) => match &input.recipe {
                    Term::Variable(_) => {}
                    Term::Application(_, subterms) => {
                        if let Some(last_subterm) = subterms.iter().last() {
                            if last_subterm.name() == fn_seq_1.name() {
                                break;
                            }
                        }
                    }
                },
                Action::Output(_) => {}
            }
        }
    }
}

#[test]
fn test_remove_lift_mutator() {
    // Should remove an extension
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();
    let mut mutator = RemoveAndLiftMutator::new(TermConstraints::default());

    // Returns the amount of extensions in the trace
    fn sum_extension_appends(trace: &Trace) -> u16 {
        trace.count_functions_by_name(fn_client_extensions_append.name())
    }

    loop {
        let mut trace = seed_client_attacker12(server);
        let before_mutation = sum_extension_appends(&trace);
        let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if let MutationResult::Mutated = result {
            let after_mutation = sum_extension_appends(&trace);
            if after_mutation < before_mutation {
                // extension removed
                break;
            }
        }
    }
}

#[test]
fn test_replace_reuse_mutator() {
    let rand = StdRand::with_seed(45);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();
    let mut mutator = ReplaceReuseMutator::new(TermConstraints::default());

    fn count_client_hello(trace: &Trace) -> u16 {
        trace.count_functions_by_name(fn_client_hello.name())
    }

    fn count_finished(trace: &Trace) -> u16 {
        trace.count_functions_by_name(fn_finished.name())
    }

    loop {
        let mut trace = seed_client_attacker12(server);
        let result = mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if let MutationResult::Mutated = result {
            let client_hellos = count_client_hello(&trace);
            let finishes = count_finished(&trace);
            if client_hellos == 2 && finishes == 0 {
                // finished replaced by client_hello
                break;
            }
        }
    }
}

#[test]
fn test_skip_mutator() {
    let rand = StdRand::with_seed(45);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();
    let mut mutator = SkipMutator::new(2);

    loop {
        let mut trace = seed_client_attacker12(server);
        let before_len = trace.steps.len();
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        if before_len - 1 == trace.steps.len() {
            break;
        }
    }
}

#[test]
fn test_swap_mutator() {
    let rand = StdRand::with_seed(45);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();
    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
    let server = AgentName::first();
    let mut mutator = SwapMutator::new(TermConstraints::default());

    loop {
        let mut trace = seed_client_attacker12(server);
        mutator.mutate(&mut state, &mut trace, 0).unwrap();

        let is_last_not_encrypt = if let Some(last) = trace.steps.iter().last() {
            match &last.action {
                Action::Input(input) => Some(input.recipe.name() != fn_encrypt12.name()),
                Action::Output(_) => None,
            }
        } else {
            None
        };

        let is_first_not_ch = if let Some(first) = trace.steps.iter().nth(0) {
            match &first.action {
                Action::Input(input) => Some(input.recipe.name() != fn_client_hello.name()),
                Action::Output(_) => None,
            }
        } else {
            None
        };

        if let Some(first) = is_first_not_ch {
            if let Some(last) = is_last_not_encrypt {
                if first {
                    if last {
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn test_find_term() {
    let mut rand = StdRand::with_seed(45);
    let (client_hello, mut trace) = util::setup_simple_trace();

    let mut stats: HashSet<TracePath> = HashSet::new();

    for _ in 0..10000 {
        let path = crate::fuzzer::mutations::util::choose_term_path(
            &trace,
            TermConstraints::default(),
            &mut rand,
        )
        .unwrap();
        crate::fuzzer::mutations::util::find_term_mut(&mut trace, &path).unwrap();
        stats.insert(path);
    }

    assert_eq!(client_hello.size(), stats.len());
}

#[test]
fn test_reservoir_sample_randomness() {
    /// https://rust-lang-nursery.github.io/rust-cookbook/science/mathematics/statistics.html#standard-deviation
    fn std_deviation(data: &[u32]) -> Option<f32> {
        fn mean(data: &[u32]) -> Option<f32> {
            let sum = data.iter().sum::<u32>() as f32;
            let count = data.len();

            match count {
                positive if positive > 0 => Some(sum / count as f32),
                _ => None,
            }
        }

        match (mean(data), data.len()) {
            (Some(data_mean), count) if count > 0 => {
                let variance = data
                    .iter()
                    .map(|value| {
                        let diff = data_mean - (*value as f32);

                        diff * diff
                    })
                    .sum::<f32>()
                    / count as f32;

                Some(variance.sqrt())
            }
            _ => None,
        }
    }

    let (client_hello, trace) = util::setup_simple_trace();

    let mut rand = StdRand::with_seed(45);
    let mut stats: HashMap<u32, u32> = HashMap::new();

    for _ in 0..10000 {
        let term =
            crate::fuzzer::mutations::util::choose(&trace, TermConstraints::default(), &mut rand)
                .unwrap();

        let id = term.0.resistant_id();

        let count: u32 = *stats.get(&id).unwrap_or(&0);
        stats.insert(id, count + 1);
    }

    let std_dev = std_deviation(stats.values().cloned().collect::<Vec<u32>>().as_slice()).unwrap();
    println!("{:?}", std_dev);
    println!("{:?}", stats);

    assert!(std_dev < 30.0);
    assert_eq!(client_hello.size(), stats.len());
}

#[test]
fn test_term_generation() {
    let mut rand = StdRand::with_seed(100);
    let terms = generate_term_zoo(&SIGNATURE, &mut rand);

    let subgraphs = terms
        .iter()
        .enumerate()
        .map(|(i, term)| term.dot_subgraph(false, i, i.to_string().as_str()))
        .collect_vec();

    let _graph = format!(
        "strict digraph \"Trace\" {{ splines=true; {} }}",
        subgraphs.join("\n")
    );

    let all_functions = SIGNATURE
        .functions
        .iter()
        .map(|(shape, _)| shape.name.to_string())
        .collect::<HashSet<String>>();
    let mut successfully_built_functions = terms
        .iter()
        .map(|term| term.name().to_string())
        .collect::<HashSet<String>>();

    let ignored_functions = [
        // transcript functions -> VecClaimer is usually available as Variable
        fn_decrypt_application.name(),
        fn_server_finished_transcript.name(),
        fn_client_finished_transcript.name(),
        fn_server_hello_transcript.name(),
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

#[test]
fn test_corpus_term_size() {
    let corpus = create_corpus();
    let trace_term_sizes = corpus
        .iter()
        .map(|(trace, name)| {
            (
                name,
                trace
                    .steps
                    .iter()
                    .map(|step| match &step.action {
                        Action::Input(input) => input.recipe.size(),
                        Action::Output(_) => 0,
                    })
                    .sum::<usize>(),
            )
        })
        .collect_vec();

    //println!("{:?}", trace_term_sizes);
}

mod util {
    use crate::agent::{AgentDescriptor, AgentName, TLSVersion};
    use crate::graphviz::write_graphviz;
    use crate::term;
    use crate::term::Term;
    use crate::tls::fn_impl::*;
    use crate::trace::{Action, InputAction, Step, Trace};

    pub fn setup_simple_trace() -> (Term, Trace) {
        let server = AgentName::first();
        let client_hello = term! {
              fn_client_hello(
                fn_protocol_version12,
                fn_new_random,
                fn_new_session_id,
                (fn_append_cipher_suite(
                    (fn_new_cipher_suites()),
                    // force TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    fn_cipher_suite12
                )),
                fn_compressions,
                (fn_client_extensions_append(
                    (fn_client_extensions_append(
                        (fn_client_extensions_append(
                            (fn_client_extensions_append(
                                (fn_client_extensions_append(
                                    (fn_client_extensions_append(
                                        fn_client_extensions_new,
                                        fn_secp384r1_support_group_extension
                                    )),
                                    fn_signature_algorithm_extension
                                )),
                                fn_ec_point_formats_extension
                            )),
                            fn_signed_certificate_timestamp_extension
                        )),
                         // Enable Renegotiation
                        (fn_renegotiation_info_extension(fn_empty_bytes_vec))
                    )),
                    // Add signature cert extension
                    fn_signature_algorithm_cert_extension
                ))
            )
        };

        let cloned = client_hello.clone();
        (
            client_hello,
            Trace {
                prior_traces: vec![],
                descriptors: vec![AgentDescriptor {
                    name: server,
                    tls_version: TLSVersion::V1_2,
                    server: true,
                    try_reuse: false,
                }],
                steps: vec![Step {
                    agent: server,
                    action: Action::Input(InputAction { recipe: cloned }),
                }],
            },
        )
    }

    impl Trace {
        pub(crate) fn count_functions_by_name(&self, find_name: &'static str) -> u16 {
            self.steps
                .iter()
                .map(|step| match &step.action {
                    Action::Input(input) => input.recipe.count_functions_by_name(find_name),
                    Action::Output(_) => 0,
                })
                .sum::<u16>()
        }

        pub(crate) fn write_plots(&self, i: u16) {
            write_graphviz(
                format!("test_mutation{}.svg", i).as_str(),
                "svg",
                self.dot_graph(true).as_str(),
            )
            .unwrap();
        }
    }

    impl Term {
        pub(crate) fn count_functions_by_name(&self, find_name: &'static str) -> u16 {
            let mut found = 0;
            for term in self.into_iter() {
                if let Term::Application(func, _) = term {
                    if func.name() == find_name {
                        found += 1;
                    }
                }
            }
            found
        }
    }
}
