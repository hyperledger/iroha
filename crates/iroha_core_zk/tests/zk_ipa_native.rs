#![doc = "First-release rejection test for the removed generic IPA verifier route."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
//! The first release exposes protocol-specific Halo2 routes only.
use iroha_core_zk::verify_backend;
use iroha_data_model::proof::ProofBox;
#[test]
fn removed_generic_ipa_poly_open_route_fails_closed() {
    let removed = "halo2/ipa/poly-open";
    let proof = ProofBox::new(removed.into(), vec![0xA5; 64]);
    assert!(!verify_backend(removed, &proof, None));
}
