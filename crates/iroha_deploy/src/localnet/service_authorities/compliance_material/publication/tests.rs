//! Pure generated catalog predicates use a catalog signed by the real held provider owner.

use super::*;

#[test]
fn generated_catalog_payload_rejects_injected_state_and_invalid_intervals() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, plan, first) =
        crate::managed::gateway_compliance::material_tests::generated_catalog_fixture();
    let start = first.payload.generated_at_unix;
    // Generated policy never accepts injected source/rule state, even before signing.
    let mut changed = first.payload.clone();
    changed.valid_until_unix += 1;
    assert!(validate_generated_payload(&changed, &plan).is_err());
    let mut reversed = first.payload.clone();
    reversed.valid_until_unix = reversed.generated_at_unix - 1;
    assert!(validate_generated_payload(&reversed, &plan).is_err());
    let mut changed = first.payload.clone();
    changed.generated_at_unix -= 1;
    assert!(validate_generated_payload(&changed, &plan).is_err());
    let mut changed = first.payload.clone();
    changed.source_anchors.push(
        sorafs_manifest::gateway_compliance::GatewayComplianceSourceAnchorV1 {
            feed_id: "unselected-feed".into(),
            feed_digest: [1; 32],
            generated_at_unix: start,
        },
    );
    changed = changed.normalize().unwrap();
    changed.validate().unwrap();
    assert!(validate_generated_payload(&changed, &plan).is_err());
    let mut oversized = first.clone();
    oversized.approvals = vec![first.approvals[0].clone(); PLAN_MAX_BYTES / 64 + 1];
    assert!(encode(&oversized).is_err());
}
