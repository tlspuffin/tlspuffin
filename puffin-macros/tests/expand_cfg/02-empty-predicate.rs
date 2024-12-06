// test that `expand_cfg` without predicate keeps the annotated function
//
// For example:
//
//     #[expand_cfg("openssl111k")]
//     fn my_annotated_function(name: &str) {
//         println!("hello {}!", name);
//     }
//
// Should simply expand to:
//
//     fn my_annotated_function(name: &str) {
//         println!("hello {}!", name);
//     }

use tlspuffin_macros::expand_cfg;

#[expand_cfg("val1")]
fn my_annotated_function() {
    // do nothing
}

fn main() {
    my_annotated_function();
}
