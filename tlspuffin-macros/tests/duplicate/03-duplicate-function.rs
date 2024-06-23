// test that the `duplicate` macro can perform function duplication

use tlspuffin_macros::duplicate;

#[duplicate(__TO_REPLACE => f1, f2, f3, f4)]
fn __TO_REPLACE() {
    // do nothing
}

fn main() {
    f1();
    f2();
    f3();
    f4();
}
