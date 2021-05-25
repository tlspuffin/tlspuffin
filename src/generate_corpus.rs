use std::{fs::File, io::Write};

use postcard;

use tlspuffin::{fuzzer::seeds::seed_successful, trace::TraceContext};

fn main() {
    let mut ctx = TraceContext::new();

    let (client, server, trace) = seed_successful(&mut ctx);

    let mut file = File::create("corpus/1.dat").unwrap();
    let serialized = postcard::to_allocvec(&trace).unwrap();
    file.write_all(&serialized).unwrap();
}
