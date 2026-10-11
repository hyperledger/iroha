//! Reject SDK mutation selection in non-test libraries and shipping dependencies.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "iroha mutation-testing is test-only; use cargo test -p iroha --lib, never a dependency or library build"
);
