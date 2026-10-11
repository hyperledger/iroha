//! Reject TORII mutation selection in non-test libraries and shipping dependencies.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "iroha_torii mutation-testing is test-only; use cargo test -p iroha_torii --lib, never a dependency or library build"
);
