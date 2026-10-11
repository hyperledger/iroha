#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Verify Proof events map to the expected JSON object (WS/SSE share mapper).
#![cfg(feature = "app_api")]
#[path = "common/proof_events.rs"]
mod proof_events;
use iroha_torii::event_to_json_value;
use proof_events::ProofEventFixture;
#[test]
fn proof_verified_and_rejected_json_mapping() {
    // Verified
    let v = ProofEventFixture::new("pipa-r/pasta", [0x12; 32])
        .with_vk("vk_name", [0x34; 32])
        .verified();
    let j = event_to_json_value(&v);
    assert_eq!(
        j.get("event").and_then(|x| x.as_str()),
        Some("ProofVerified")
    );
    assert_eq!(
        j.get("backend").and_then(|x| x.as_str()),
        Some("pipa-r/pasta")
    );
    assert_eq!(
        j.get("proof_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0x12u8; 32]).as_str())
    );
    assert_eq!(
        j.get("call_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0xAAu8; 32]).as_str())
    );
    assert_eq!(
        j.get("vk_ref").and_then(|x| x.as_str()),
        Some("pipa-r/pasta::vk_name")
    );
    assert_eq!(
        j.get("vk_commitment").and_then(|x| x.as_str()),
        Some(hex::encode([0x34u8; 32]).as_str())
    );
    // Rejected
    let r = ProofEventFixture::new("groth16", [0x56; 32])
        .without_vk()
        .with_call_hash(None)
        .rejected();
    let j2 = event_to_json_value(&r);
    assert_eq!(
        j2.get("event").and_then(|x| x.as_str()),
        Some("ProofRejected")
    );
    assert_eq!(j2.get("backend").and_then(|x| x.as_str()), Some("groth16"));
    assert_eq!(
        j2.get("proof_hash").and_then(|x| x.as_str()),
        Some(hex::encode([0x56u8; 32]).as_str())
    );
    assert!(j2.get("call_hash").is_some());
}
