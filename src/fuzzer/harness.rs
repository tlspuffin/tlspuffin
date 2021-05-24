use libafl::executors::ExitKind;
use rand::Rng;

use crate::trace::Trace;

pub fn harness(input: &Trace) -> ExitKind {
    let mut rng = rand::thread_rng();

    let n1 = rng.gen_range(0..10);
    println!("Run {}", n1);
    if n1 <= 3 {
        //panic!()
    }
    ExitKind::Timeout
}
