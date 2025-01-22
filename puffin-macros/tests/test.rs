#[test]
fn trybuild_macros_tests() {
    let t = trybuild::TestCases::new();

    // NOTE we set a number of configuration options for tests
    //
    // For example:
    //
    //   --cfg 'cap_all="val1"'
    //   --cfg 'cap_all="val2"'
    //   --cfg 'cap_all="val3"'
    //
    // This means for example that `cfg!(cap_all = "val2")` would evaluate to `true`.
    //
    // Refer to the workspace's `.cargo/config.toml` file for the complete list.

    t.pass("tests/expand_cfg/01-import-successful.rs");
    t.pass("tests/expand_cfg/02-empty-predicate.rs");
    t.pass("tests/expand_cfg/03-atom-predicate.rs");
    t.pass("tests/expand_cfg/04-composite-predicate.rs");
    t.pass("tests/expand_cfg/05-stringify-ident.rs");

    // TODO test expand_cfg error case: non-function annotated
    // TODO test expand_cfg error case: unknown cfg predicate

    t.pass("tests/apply/01-import-successful.rs");
}
