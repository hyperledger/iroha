//! Genuine four-stage native Load wrapped by the complete Omega predicate.
//! Bootstrap-only or two-terminal catalogs remain explicit component scopes;
//! neither establishes the complete operation catalog or production byte gate.
//! Run each ignored test separately with a fresh `KAGEMUSHA_LOAD_OUTPUT` directory.

#![allow(clippy::duplicate_mod)] // Each chain retains its exact shared Bootstrap source types.

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
#[path = "common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

/// Shared genuine Bootstrap predecessor and four-stage Load continuation fixtures.
#[path = "common/proof_fixtures/a_load_recursive.rs"]
pub mod load_chain;

include!("common/proof_fixtures/load_omega_body.rs");

use first_load_fixture::first_load_fixture;

#[test]
#[ignore = "explicit genuine BLS-admitted Load and diagnostic outer proof; not full52 or carried-key continuity"]
fn native_load_reaches_complete_outer_predicate_from_bls_receipt() {
    let (fixture, rebuilds) = first_load_fixture(1);
    native_load_reaches_complete_outer_predicate(&fixture);
    assert_eq!(rebuilds.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
#[ignore = "explicit genuine BLS-admitted Bootstrap/Load two-terminal rekey and outer proofs; not full52"]
fn common_bootstrap_load_catalog_rebinds_every_proof_and_key_from_bls_receipt() {
    let (fixture, rebuilds) = first_load_fixture(2);
    common_bootstrap_load_catalog_rebinds_every_proof_and_key(&fixture);
    assert_eq!(rebuilds.load(std::sync::atomic::Ordering::Relaxed), 2);
}
