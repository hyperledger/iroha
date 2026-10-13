//! Compiler diagnostics for explicit generated event-set identities.
#![cfg(all(feature = "trybuild-tests", not(coverage)))]

#[test]
fn event_set_identity_metadata() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui_fail/event_set_identity_missing.rs");
    cases.compile_fail("tests/ui_fail/event_set_identity_duplicate.rs");
    cases.compile_fail("tests/ui_fail/event_set_identity_invalid.rs");
    cases.compile_fail("tests/ui_fail/event_set_too_many.rs");
}
