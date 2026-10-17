//! Reject P2P mutation selection in non-test libraries and shipping dependencies.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "iroha_p2p mutation-testing is test-only; use cargo test -p iroha_p2p --lib, never a dependency or library build"
);
