//! One-shot bounded canonical ballot verification diagnostic, with no ledger effects.
//!
//! This is an engineering observation boundary, not a shipping API or a complete native
//! memory certificate. Run only as a fresh process with no concurrent application work.
#![allow(unsafe_code)]

#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "../../iroha_parliament_ballot_proof/examples/resource_contract/arena.rs"]
mod arena;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "canonical_resource_probe/budget.rs"]
mod budget;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "canonical_resource_probe/cli.rs"]
mod cli;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "../../iroha_parliament_ballot_proof/examples/memory_entry/fatal.rs"]
mod fatal;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "../../iroha_parliament_ballot_proof/examples/resource_contract/native.rs"]
mod native;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "canonical_resource_probe/staging.rs"]
mod staging;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "canonical_resource_probe/verify.rs"]
mod verify;
#[cfg(all(
    target_pointer_width = "64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "canonical_resource_probe/workspace.rs"]
mod workspace;

fn main() {
    #[cfg(all(
        target_pointer_width = "64",
        any(target_os = "macos", target_os = "linux")
    ))]
    std::process::exit(cli::run());
    #[cfg(not(all(
        target_pointer_width = "64",
        any(target_os = "macos", target_os = "linux")
    )))]
    {
        eprintln!("canonical_resource_probe requires 64-bit Linux or macOS");
        std::process::exit(4);
    }
}
