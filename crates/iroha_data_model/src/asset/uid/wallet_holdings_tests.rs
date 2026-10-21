//! Staged wire/schema controls for requested-wallet UID projection; native tests UNRUN.
use super::*;
use crate::{asset::AssetBalanceScope, query::asset_uid::FindAssetUidPoliciesV1};
use iroha_crypto::{Algorithm, KeyPair};
use norito::codec::{DecodeAll, Encode};
fn fixture() -> AssetUidWalletHoldingsV1 {
    let account_id = AccountId::new(
        KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    let definition = AssetDefinitionId::from_uuid_bytes([
        0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
        0xa8,
    ])
    .unwrap();
    AssetUidWalletHoldingsV1 {
        asset_id: AssetId::with_scope(definition, account_id.clone(), AssetBalanceScope::Global),
        account_id,
        spendable: 11_u32.into(),
        locked: 3_u32.into(),
        total: 14_u32.into(),
        pending_incoming: 7_u32.into(),
    }
}
#[test]
fn exact_wallet_product_round_trips_raw_framed_and_json() {
    let value = fixture();
    assert_eq!(
        AssetUidWalletHoldingsV1::decode_all(&mut value.encode().as_slice()).unwrap(),
        value
    );
    assert_eq!(
        norito::decode_canonical::<AssetUidWalletHoldingsV1>(
            &norito::encode_canonical(&value).unwrap()
        )
        .unwrap(),
        value
    );
    let json = norito::json::to_json(&value).unwrap();
    assert_eq!(
        norito::json::from_str::<AssetUidWalletHoldingsV1>(&json).unwrap(),
        value
    );
    let extra = json.strip_suffix('}').unwrap().to_owned() + ",\"foreign_wallets\":[]} ";
    assert!(norito::json::from_str::<AssetUidWalletHoldingsV1>(&extra).is_err());
}
#[test]
fn request_optional_wallet_selection_is_part_of_exact_native_transport() {
    let value = fixture();
    for wallet_account_id in [None, Some(value.account_id)] {
        let query = FindAssetUidPoliciesV1 {
            asset_definition_id: value.asset_id.definition().clone(),
            uid: Some([7; 32]),
            wallet_account_id,
        };
        let encoded = query.encode();
        let decoded = FindAssetUidPoliciesV1::decode_all(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.wallet_account_id, query.wallet_account_id);
        assert_eq!(decoded.uid, query.uid);
    }
}
#[test]
fn product_schema_pins_only_requested_account_scope_and_four_quantities() {
    use std::any::TypeId;
    let schema = AssetUidWalletHoldingsV1::schema();
    let Some(iroha_schema::Metadata::Struct(fields)) = schema.get::<AssetUidWalletHoldingsV1>()
    else {
        panic!("wallet product")
    };
    assert_eq!(
        fields
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>(),
        [
            "account_id",
            "asset_id",
            "spendable",
            "locked",
            "total",
            "pending_incoming"
        ]
    );
    assert_eq!(fields.declarations[0].ty, TypeId::of::<AccountId>());
    assert_eq!(fields.declarations[1].ty, TypeId::of::<AssetId>());
    assert!(
        fields.declarations[2..]
            .iter()
            .all(|d| d.ty == TypeId::of::<Quantity>())
    );
    let schema = AssetUidPolicyViewV1::schema();
    let Some(iroha_schema::Metadata::Struct(fields)) = schema.get::<AssetUidPolicyViewV1>() else {
        panic!("UID view")
    };
    assert_eq!(
        fields
            .declarations
            .iter()
            .find(|d| d.name == "wallet_holdings")
            .unwrap()
            .ty,
        TypeId::of::<Option<AssetUidWalletHoldingsV1>>()
    );
}
