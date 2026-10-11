//! Genuine oversized generic Ω negative for the native Payment joint bound.
//! This deliberately exercises rejection, never an accepted Receive fixture.
//! TODO: Compile and execute the native-BLS-funded case on the current candidate.
#![allow(clippy::duplicate_mod)]
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "common/first_load_fixture.rs"]
mod first_load_fixture;
#[path = "common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
/// Genuine Load/Omega component fixture for the oversized-wrapper negative.
#[path = "load_omega.rs"]
pub mod load_outer;
#[path = "common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;
/// Actual Send source proofs used by the bounds check.
#[path = "a_send.rs"]
pub mod send_components;

use load_outer::load_chain;

/// Run the retained composition assertions with genuine native Load originals.
pub fn genuine_generic_omega_is_rejected_by_receive_payment_cap(fixture: load_outer::LoadFixture) {
    let rooted = load_outer::two_terminal_load_omega(&fixture);
    drop(fixture);
    let source = &rooted.artifact;
    let send = send_components::genuine_send_source(&source.source.state);
    let omega = 320
        + source.proof.len()
        + source.source.pallas.to_bytes().len()
        + source.vesta.to_bytes().len();
    let sigma = send.sigma.len();
    assert!(
        omega + sigma
            > iroha_kagemusha_proof::a_relation::native::receive::MAX_PAYMENT_ORIGINAL_BYTES
    );
    assert_eq!(
        iroha_kagemusha_proof::a_relation::native::receive::check_payment_original_sizes(
            omega, sigma
        ),
        Err(iroha_kagemusha_proof::a_relation::native::receive::Error::Input)
    );
}

#[test]
#[ignore = "native BLS receipt and genuine oversized Omega/Send originals; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_generic_omega_is_rejected_by_receive_payment_cap() {
    let (fixture, rebuilds) = first_load_fixture::first_load_fixture(2);
    genuine_generic_omega_is_rejected_by_receive_payment_cap(fixture);
    assert_eq!(rebuilds.load(std::sync::atomic::Ordering::Relaxed), 2);
}
