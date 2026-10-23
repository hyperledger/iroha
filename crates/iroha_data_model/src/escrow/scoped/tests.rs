//! Semantic regressions; these fixtures do not manufacture certified World authority.
use super::*;
use crate::{account::AccountId, escrow::{AssetEscrowKind, AssetEscrowStatus, EscrowId}};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_primitives::numeric::Quantity;

fn asset() -> AssetDefinitionId { "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap() }
fn incarnation(seed: &str) -> AxtAssetIncarnationV1 {
    AxtAssetIncarnationV1::try_from_bytes(*Hash::new(seed).as_ref()).unwrap()
}
fn scope(count: u64) -> AssetEscrowScopeV1 {
    AssetEscrowScopeV1 { asset_definition_id: asset(), asset_incarnation: incarnation("current"),
        revision: 1, record_count: count }
}
fn record(seed: &str) -> AssetEscrowRecord {
    let key = KeyPair::try_from_seed(vec![51; 32], Algorithm::Ed25519).unwrap();
    let seller = AccountId::new(key.public_key().clone());
    AssetEscrowRecord { id: EscrowId::new(Hash::new(seed)), seller: seller.clone(),
        buyer: None, asset_definition: asset(), amount: Quantity::one(), custody: seller,
        status: AssetEscrowStatus::Locked, kind: AssetEscrowKind::Lock,
        remaining_amount: Quantity::one(), release_authority: None, expires_at_ms: None,
        evidence_hashes: Vec::new(), conditions: Vec::new(), created_at_ms: 1,
        accepted_at_ms: None, payment_sent_at_ms: None, disputed_at_ms: None,
        closed_at_ms: None, resolution: None }
}
fn validates(scope: &AssetEscrowScopeV1, records: &[AssetEscrowRecord]) -> bool {
    scope.validate_records(&asset(), &incarnation("current"), records).is_ok()
}

#[test]
fn initialized_zero_is_an_explicit_versioned_record() {
    assert!(validates(&scope(0), &[]));
    let mut absent_revision = scope(0); absent_revision.revision = 0;
    assert!(!validates(&absent_revision, &[]));
}
#[test]
fn omitted_and_added_rows_refuse() {
    assert!(!validates(&scope(1), &[]));
    assert!(!validates(&scope(0), &[record("one")]));
}
#[test]
fn duplicate_cannot_replace_omitted_row() {
    let row = record("one");
    assert!(!validates(&scope(2), &[row.clone(), row]));
}
#[test]
fn foreign_asset_and_old_incarnation_refuse() {
    let mut foreign = record("one");
    let mut aid = asset().aid_bytes(); aid[0] ^= 1;
    foreign.asset_definition = AssetDefinitionId::from_uuid_bytes(aid).unwrap();
    assert!(!validates(&scope(1), &[foreign]));
    let mut old = scope(0); old.asset_incarnation = incarnation("retired");
    assert!(!validates(&old, &[]));
}
#[test]
fn terminal_records_still_belong_to_complete_set() {
    let mut row = record("released"); row.status = AssetEscrowStatus::Released;
    row.remaining_amount = Quantity::zero(); row.closed_at_ms = Some(3);
    assert!(validates(&scope(1), &[row]));
    assert!(!validates(&scope(1), &[]));
}
#[test]
fn canonical_order_is_required() {
    let mut rows = vec![record("one"), record("two")]; rows.sort_by_key(|row| row.id);
    assert!(validates(&scope(2), &rows)); rows.reverse();
    assert!(!validates(&scope(2), &rows));
}
#[test]
fn scope_and_original_roundtrip_canonical_norito() {
    let bytes = norito::encode_canonical(&scope(1)).unwrap();
    assert_eq!(norito::decode_canonical::<AssetEscrowScopeV1>(&bytes).unwrap(), scope(1));
    let value = AssetEscrowScopeOriginalV1 { scope_original: bytes, records: vec![record("one")] };
    let bytes = norito::encode_canonical(&value).unwrap();
    assert_eq!(norito::decode_canonical::<AssetEscrowScopeOriginalV1>(&bytes).unwrap(), value);
}
#[test]
fn incarnation_and_asset_are_distinct_in_scope_key() {
    let current = scope_key(&asset(), &incarnation("current")).unwrap();
    assert_ne!(current, scope_key(&asset(), &incarnation("retired")).unwrap());
    let mut aid = asset().aid_bytes(); aid[0] ^= 1;
    assert_ne!(current, scope_key(&AssetDefinitionId::from_uuid_bytes(aid).unwrap(),
        &incarnation("current")).unwrap());
}
#[test]
fn reserved_namespace_matching_does_not_capture_neighboring_user_key() {
    assert!(is_native_scope_key("sc/native/asset_escrow_scope_v1"));
    assert!(is_native_scope_key("sc/native/asset_escrow_scope_v1/a/b"));
    assert!(!is_native_scope_key("sc/native/asset_escrow_scope_v1x/user"));
}
