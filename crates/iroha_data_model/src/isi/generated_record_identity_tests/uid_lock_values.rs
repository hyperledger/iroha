//! First-release captures for UID policy and authenticated contract lock records.
use super::*;

#[test]
#[ignore = "explicit maintenance command captures UID policy and controlled native locks"]
fn print_uid_and_controlled_lock_record_fixture_rows() {
    use crate::{
        NetworkId,
        account::AccountId,
        asset::AssetDefinitionId,
        asset::uid::{AssetUidDailyWindowV1, AssetUidPolicyV1},
        block::BlockHeader,
        escrow::control::{AssetLockControlV1, controlled_asset_lock_id},
        isi::{
            asset_uid::SetAssetUidPolicyV1,
            escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock, OpenAssetLock},
            escrow_control::{
                CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
                ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
            },
        },
        smart_contract::ContractAddress,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::topology::DataSpaceId;
    use std::{collections::BTreeSet, num::NonZeroU64};
    fn row<T>(value: T) -> Value
    where
        T: NoritoSchema
            + NoritoSerialize
            + for<'de> NoritoDeserialize<'de>
            + Clone
            + Debug
            + PartialEq,
    {
        let value = capture(value);
        json::object([
            ("nominal", value.get("nominal").unwrap().clone()),
            (
                "serialize_hash",
                value.get("serialize_hash").unwrap().clone(),
            ),
            (
                "deserialize_hash",
                value.get("deserialize_hash").unwrap().clone(),
            ),
            ("cases", Value::Array(vec![frame_fields(&value)])),
        ])
        .unwrap()
    }
    let account = |seed| {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
        )
    };
    let source = account(91);
    let destination = account(92);
    let asset = AssetDefinitionId::from_uuid_bytes([
        0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0x48, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8, 0xa8,
        0xa8,
    ])
    .unwrap();
    let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new("uid-lock-capture"),
    ));
    let controller =
        ContractAddress::derive(&network, &source, 17, DataSpaceId::UNIVERSAL).unwrap();
    let key = b"uid-lock-record-capture".to_vec();
    let escrow_id = controlled_asset_lock_id(&controller, &key);
    let mut lock = OpenAssetLock::new(escrow_id, asset.clone(), destination, 30_u32);
    lock.release_authority = Some(controller.subject_id());
    lock.expires_at_ms = Some(604_800_000);
    let rows = vec![
        row(SetAssetUidPolicyV1 {
            policy: AssetUidPolicyV1 {
                asset_definition_id: asset,
                uid: [17; 32],
                revision: 1,
                accounts: BTreeSet::from([source.clone()]),
                holding_limit: Some(50_u32.into()),
                daily_window: AssetUidDailyWindowV1::JerusalemDay,
                daily_limit: Some(100_u32.into()),
            },
        }),
        row(OpenControlledAssetLockV1 {
            source,
            key,
            lock,
            control: AssetLockControlV1 {
                controller,
                release_until_ms: NonZeroU64::new(259_200_000),
                cancel_not_before_ms: NonZeroU64::new(604_800_000),
            },
        }),
        row(DrawdownControlledAssetLockV1 {
            drawdown: DrawdownAssetLock {
                escrow_id,
                amount: 10_u32.into(),
                expected_remaining_amount: 30_u32.into(),
            },
        }),
        row(CancelControlledAssetLockV1 {
            cancel: CancelAssetLock {
                escrow_id,
                expected_remaining_amount: 20_u32.into(),
            },
        }),
        row(ExpireControlledAssetLockV1 {
            expiry: ExpireAssetLock { escrow_id },
        }),
    ];
    println!(
        "UID_CONTROLLED_LOCK_FIXTURE_ROWS={}",
        json::to_json(&rows).unwrap()
    );
}
