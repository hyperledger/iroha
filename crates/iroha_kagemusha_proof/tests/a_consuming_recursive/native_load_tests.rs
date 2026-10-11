//! Funded Unload and Retiring proof chains using exact native-BLS Load originals.
//!
//! The two-terminal catalog and synthetic execution receipt are component inputs.
//! TODO: Compile and execute both cases on the current candidate; no release claim.

#[path = "../common/first_load_fixture.rs"]
mod first_load_fixture;
#[path = "../common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "../common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

use super::{
    bootstrap, bootstrap_objects, catalog::send_chain::load_outer::load_chain, common, load_objects,
};
use first_load_fixture::first_load_fixture;
use std::sync::atomic::Ordering;

#[test]
#[ignore = "native BLS receipt and genuine funded Unload/Retiring chains; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_wallet_proves_unload_and_retiring_with_all_owners() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::compact_loaded_wallet_proves_unload_and_retiring_with_all_owners(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and funded Unload/Retiring native differential and checkpoint replay; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_native_consuming_proves_and_restores_every_stage() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::installed_native_consuming_proves_and_restores_every_stage(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}
