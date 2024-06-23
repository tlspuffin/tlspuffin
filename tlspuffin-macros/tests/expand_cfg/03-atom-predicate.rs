// test `expand_cfg` expansion with a single atom predicate
//
// For example: `#[expand_cfg("val1", cap_1)]` becomes `#[cfg(cap_1 = "val1")]`

use tlspuffin_macros::expand_cfg;

#[expand_cfg("val1", cap_1)] // => #[cfg(cap_1 = "val1")] => true
fn my_function_preserved() {
    // do nothing
}

#[expand_cfg("val1", cap_2)] // => #[cfg(cap_2 = "val1")] => false
fn my_function_discarded() {
    compile_error!("function should have been discarded");
}

fn main() {
    my_function_preserved();
}
