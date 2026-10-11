//! Funded ancestry, Send, and Receive branches using exact native-BLS Load originals.
//!
//! These genuine proof constructions reuse the existing source, key-continuity and mutation
//! assertions. Their partial catalogs and captured synthetic execution are component evidence;
//! they do not replace full52 admission, a real monetary network campaign or phone measurements.
//! TODO: Compile and execute these thirteen registered cases against the current candidate.

#[path = "../common/bootstrap.rs"]
mod bootstrap;
#[path = "../common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
#[path = "../common/mod.rs"]
mod common;
#[path = "../common/first_load_fixture.rs"]
mod first_load_fixture;
#[path = "../common/ordinary_load_fixture.rs"]
mod load_fixture;
#[path = "../common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "../common/ordinary_load_receipt.rs"]
mod ordinary_load_receipt;

// Alias the actual nested source types; a separately included Load chain would
// construct a different Rust type even when its source file is identical.
use super::receive_chain::compact_catalog::{self, send_chain::load_outer::load_chain};
use first_load_fixture::first_load_fixture;
use std::sync::atomic::Ordering;

#[test]
#[ignore = "native BLS receipt, genuine funded Receive acceptance and four-slot Omega; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_receive_acceptance_closes_all_four_outer_obligations() {
    let (fixture, rebuilds) = first_load_fixture(3);
    super::genuine_receive_acceptance_closes_all_four_outer_obligations(fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}

#[test]
#[ignore = "native BLS receipt, genuine funded corrected-V burn and four-slot Omega; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_receive_corrected_burn_closes_all_four_outer_obligations() {
    let (fixture, rebuilds) = first_load_fixture(3);
    super::genuine_receive_corrected_burn_closes_all_four_outer_obligations(fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}

#[test]
#[ignore = "native BLS receipt and genuine funded ReceiveRenewed ten-A/nine-W chain; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_renewed_receive_accepts_exact_payer_and_receiver_heads() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::receive_chain::canonical_envelope_receive_renewed_accepts_exact_payer_and_receiver_heads(
        &fixture,
    );
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine corrected-V Receive without consumed insertion; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_receive_corrected_burn_preserves_consumed_root() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::receive_chain::canonical_envelope_receive_corrected_vesta_burn_without_consumed_insert(
        &fixture,
    );
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine funded accepted Receive ten-A/nine-W chain; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_receive_accepts_exact_payer_and_receiver_heads() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::receive_chain::canonical_envelope_receive_accepts_exact_payer_and_receiver_heads(
        &fixture,
    );
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine Omega with nondeciding carried Vesta claim; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_omega_nondeciding_claim_requires_same_challenges_correction() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::receive_chain::genuine_omega_can_carry_a_succinct_but_nondeciding_vesta_claim(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine corrected-V Receive with consumed insertion; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_receive_corrected_burn_inserts_credit() {
    let (fixture, rebuilds) = first_load_fixture(2);
    super::receive_chain::canonical_envelope_receive_corrected_vesta_burn_inserts_credit(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine Bootstrap/Load compact rekey; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_catalog_rebinds_bootstrap_and_load() {
    let (fixture, rebuilds) = first_load_fixture(2);
    compact_catalog::compact_bootstrap_load_catalog_rebinds_every_proof_and_key(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine Bootstrap/Load/Send compact rekey; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_catalog_rebinds_bootstrap_load_and_send() {
    let (fixture, rebuilds) = first_load_fixture(3);
    compact_catalog::compact_bootstrap_load_send_catalog_rebinds_every_proof_and_key(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 3);
}

#[test]
#[ignore = "native BLS receipt and genuine installed five-A/four-W Send differential; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_native_send_preserves_all_stages_and_originals() {
    let (fixture, rebuilds) = first_load_fixture(2);
    compact_catalog::compact_predecessor_native_send_preserves_every_installed_stage_and_original(
        &fixture,
    );
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and genuine common-key Send authorization/map owners; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_common_key_send_executes_all_owners() {
    let (fixture, rebuilds) = first_load_fixture(2);
    compact_catalog::send_chain::common_key_send_executes_all_authorization_and_map_tasks(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and two distinct wallets under the same compact key; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_distinct_wallets_share_exact_catalog() {
    let (fixture, rebuilds) = first_load_fixture(2);
    compact_catalog::compact_distinct_wallets_share_the_exact_predecessor_catalog(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}

#[test]
#[ignore = "native BLS receipt and exact Load predecessor catalog retention; run alone optimized with fresh KAGEMUSHA_LOAD_OUTPUT"]
fn funded_load_retains_exact_predecessor_catalog() {
    let (fixture, rebuilds) = first_load_fixture(2);
    compact_catalog::compact_payer_load_retains_the_exact_predecessor_catalog(&fixture);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 2);
}
