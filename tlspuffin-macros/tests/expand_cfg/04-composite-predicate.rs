// test `expand_cfg` expansion with composite predicates
//
// For example: `#[expand_cfg("val1", all(cap_1, cap_2))]` becomes `#[cfg(all(cap_1 = "val1", cap_2 = "val1"))]`

use tlspuffin_macros::expand_cfg;

#[expand_cfg("val1", all(cap_1, cap_all))] // => #[cfg(all(cap_1 = "val1", cap_all = "val1"))] => true
fn my_function_all_preserved() {
    // do nothing
}

#[expand_cfg("val1", all(cap_2, cap_all))] // => #[cfg(all(cap_2 = "val1", cap_all = "val1"))] => false
fn my_function_all_discarded() {
    compile_error!("function should have been discarded");
}

#[expand_cfg("val1", any(cap_1, cap_2))] // => #[cfg(any(cap_1 = "val1", cap_2 = "val1"))] => true
fn my_function_any_preserved() {
    // do nothing
}

#[expand_cfg("val1", any(cap_2, cap_3))] // => #[cfg(any(cap_2 = "val1", cap_3 = "val1"))] => false
fn my_function_any_discarded() {
    compile_error!("function should have been discarded");
}

#[expand_cfg("val1", not(cap_2))] // => #[cfg(not(cap_2 = "val1"))] => true
fn my_function_not_preserved() {
    // do nothing
}

#[expand_cfg("val1", not(cap_1))] // => #[cfg(not(cap_1 = "val1"))] => false
fn my_function_not_discarded() {
    compile_error!("function should have been discarded");
}

fn main() {
    my_function_all_preserved();
    my_function_any_preserved();
    my_function_not_preserved();
}
