// test that the `duplicate` macro can perform substitutions

use tlspuffin_macros::duplicate;
use tlspuffin_macros::expand_cfg;

#[duplicate(__TO_REPLACE => replace_function_name)]
fn __TO_REPLACE() {
    // do nothing
}

#[duplicate(__TO_REPLACE => variable_name)]
fn replace_variable_name() -> bool {
    let __TO_REPLACE = 42;

    variable_name == 42
}

#[duplicate(__TO_REPLACE => val1)]
#[expand_cfg(__TO_REPLACE, all(cap_1, cap_1_2))]
fn replace_in_attributes() {
    // do nothing
}

fn main() {
    replace_function_name();
    replace_variable_name();
    replace_in_attributes();
}
