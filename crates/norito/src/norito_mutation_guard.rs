//! Reject Norito origin mutations in every non-test library or dependency.

#[cfg(all(feature = "mutation-testing", not(test)))]
compile_error!(
    "norito mutation-testing is test-only; use cargo test -p norito --lib, never a dependency or library build"
);
