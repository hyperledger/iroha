//! Funded Archive acceptance and no-op branches under exact native-BLS Load originals.
//!
//! These partial-catalog component cases do not establish full52 admission or
//! real-network settlement. TODO: Compile and execute on the current candidate.

#[path = "../common/first_load_fixture.rs"]
mod first_load_fixture;
#[path = "../common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "../common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "../common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

use super::{
    bootstrap, bootstrap_objects, common, compact_catalog::send_chain::load_outer::load_chain,
};
use first_load_fixture::first_load_fixture;
use std::sync::atomic::Ordering;

#[test]
#[ignore = "native BLS receipt and genuine ArchiveReceive acceptance chain; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_archive_receive_accepts_and_removes_pending() {
    let (fixture, rebuilds) = first_load_fixture(3);
    super::genuine_archive_receive_accepts_and_removes_pending(fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}

#[test]
#[ignore = "native BLS receipt and genuine ArchiveReceive invalid-proof no-op chain; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_archive_receive_invalid_proof_retains_adjusted_pending() {
    let (fixture, rebuilds) = first_load_fixture(3);
    super::genuine_archive_receive_invalid_proof_retains_adjusted_pending(fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}

#[test]
#[ignore = "native BLS receipt and genuine ArchiveReceive full-envelope-tail no-op chain; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_archive_receive_full_envelope_tail_retains_adjusted_pending() {
    let (fixture, rebuilds) = first_load_fixture(3);
    super::genuine_archive_receive_full_envelope_tail_retains_adjusted_pending(fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}
