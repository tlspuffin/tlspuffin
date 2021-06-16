use libafl::bolts::rands::{Rand, RomuTrioRand, StdRand};
use libafl::corpus::InMemoryCorpus;
use libafl::mutators::Mutator;
use libafl::state::StdState;
use openssl::rand::rand_bytes;

use crate::agent::AgentName;
use crate::fuzzer::mutations::ReplaceReuseMutator;
use crate::fuzzer::seeds::*;

use crate::openssl_binding::make_deterministic;
use crate::trace::Trace;



#[test]
fn test_openssl_no_randomness() {
    make_deterministic(); // his affects also other tests, which is fine as we generally prefer deterministic tests
    let mut buf1 = [0; 2];
    rand_bytes(&mut buf1).unwrap();
    assert_eq!(buf1, [70, 100]);
}

#[test]
fn test_replace_reuse() {
    let rand = StdRand::with_seed(1235);
    let corpus: InMemoryCorpus<Trace> = InMemoryCorpus::new();

    let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());

    let mut mutator: ReplaceReuseMutator<
        RomuTrioRand,
        StdState<InMemoryCorpus<Trace>, (), _, _, InMemoryCorpus<Trace>>,
    > = ReplaceReuseMutator::new();

    let client = AgentName::first();
    let server = client.next();
    let _trace = seed_client_attacker12(client, server);

    /*        write_graphviz("test_mutation.svg", "svg", trace.dot_graph(true).as_str());
     */
    for _i in 0..10 {
        let mut trace = seed_client_attacker12(client, server);
        println!("{:?}", mutator.mutate(&mut state, &mut trace, 0).unwrap());
        /*            write_graphviz(
            format!("mutations_preview/test_mutation_after{}.svg", i).as_str(),
            "svg",
            trace.dot_graph(true).as_str(),
        )
        .unwrap();*/
    }
}

#[test]
fn test_rand() {
    let mut rand = StdRand::with_seed(1337);
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
    println!("{}", rand.between(0, 1));
}
