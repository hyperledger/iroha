//! Reject DEPLOY mutation selection in non-test libraries and shipping dependencies.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "iroha_deploy mutation-testing is test-only; use cargo test -p iroha_deploy --lib, never a dependency or library build"
);
