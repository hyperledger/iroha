//! Reject Model mutation selectors in every non-test library or shipping dependency.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "iroha_data_model mutation-testing is test-only; use cargo test -p iroha_data_model --lib, never a dependency or library build"
);
