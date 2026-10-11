//! Direct BLS admission of a captured receipt followed by genuine monetary Load.
//! Synthetic ledger execution identities remain component-only; the certificate
//! and every native Load stage are independently verified.

#![allow(clippy::duplicate_mod)] // The shared Bootstrap chain retains its exact source types.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
/// The same native Load four-A/three-W producer used by subsequent chain fixtures.
#[path = "a_load_recursive.rs"]
pub mod load_chain;
#[path = "common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

use ff::Field;
use iroha_pasta::Fp;
use ordinary_load_receipt::{first_capture, verified_receipt};
use std::{path::PathBuf, sync::Arc};

#[test]
fn exact_first_load_capture_matches_bootstrap_identity_without_relabeling() {
    load_fixture::check_first_capture(&first_capture());
}

#[test]
fn first_load_certificate_and_receipt_verify_without_proving_keys() {
    let receipt = verified_receipt(&first_capture());
    assert_eq!(receipt.len(), 282);
}

#[test]
#[ignore = "explicit genuine four-A/three-W Load proof construction after direct BLS admission"]
fn exact_first_load_native_finality_then_native_load() {
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_LOAD_OUTPUT")
            .expect("exclusive native Load artifact output directory"),
    );
    let receipt = verified_receipt(&first_capture());
    let rooted = load_chain::bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    let fixture: load_chain::LoadFixture =
        Arc::new(move |rooted| load_fixture::build(rooted, &receipt, &output));
    let terminal = load_chain::authenticated_load(&rooted, &fixture);
    assert_eq!(
        terminal.state.core[iroha_kagemusha_proof::witness::core_index::BALANCE],
        Fp::from(100)
    );
    assert_eq!(
        terminal.state.core[iroha_kagemusha_proof::witness::core_index::NEXT_LOAD],
        Fp::ONE
    );
}
