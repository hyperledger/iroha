//! Native UID, FI and controlled-lock wire payloads retain complete public schemas.

use super::{IntoSchema, find_missing_schema_references};
use iroha_data_model::{
    asset::{
        fi_link::{AssetFiLinkV1, AssetFiRelationshipViewV1},
        uid::{
            AssetUidBindingV1, AssetUidPolicyV1, AssetUidPolicyViewV1, AssetUidUsageV1,
            AssetUidWalletHoldingsV1,
        },
        uid_enrollment::{AssetUidEnrollmentViewV1, AssetUidSystemAccountV1},
    },
    escrow::control::{AssetLockControlV1, AssetLockWaterfallSettlementV1},
    isi::{
        asset_fi::{
            SetAssetFiLinkAttestationV1, SetAssetFiLinkV1, SetAssetFiV1, TransferToLinkedFiV1,
        },
        asset_uid::{SetAssetUidPolicyReaderV1, SetAssetUidPolicyV1},
        asset_uid_enrollment::{ActivateAssetUidEnrollmentV1, SetAssetUidSystemAccountV1},
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
            ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
        },
    },
    query::asset_uid::FindAssetUidPoliciesV1,
};

#[test]
fn uid_fi_and_controlled_lock_export_contains_exact_public_schema_closure() {
    let mut expected = SetAssetUidPolicyV1::schema();
    macro_rules! include {
        ($($ty:ty),+ $(,)?) => { $(<$ty>::update_schema_map(&mut expected);)+ };
    }
    include!(
        SetAssetUidPolicyReaderV1,
        ActivateAssetUidEnrollmentV1,
        SetAssetUidSystemAccountV1,
        SetAssetFiV1,
        SetAssetFiLinkAttestationV1,
        SetAssetFiLinkV1,
        TransferToLinkedFiV1,
        OpenControlledAssetLockV1,
        DrawdownControlledAssetLockV1,
        CancelControlledAssetLockV1,
        ExpireControlledAssetLockV1,
        FindAssetUidPoliciesV1,
        AssetUidBindingV1,
        AssetUidUsageV1,
        AssetUidPolicyViewV1,
        AssetUidEnrollmentViewV1,
        AssetFiRelationshipViewV1,
    );
    let exported = crate::build_schemas();
    let exported: std::collections::BTreeMap<_, _> = exported.iter().collect();
    for (id, descriptor) in expected.iter() {
        assert_eq!(
            exported.get(id).copied(),
            Some(descriptor),
            "missing or substituted UID/FI/controlled-lock descriptor: {}",
            descriptor.type_name,
        );
    }
    assert!(expected.contains_key::<AssetUidPolicyV1>());
    assert!(expected.contains_key::<AssetUidBindingV1>());
    assert!(expected.contains_key::<AssetUidUsageV1>());
    assert!(expected.contains_key::<AssetUidWalletHoldingsV1>());
    assert!(expected.contains_key::<AssetUidSystemAccountV1>());
    assert!(expected.contains_key::<AssetFiLinkV1>());
    assert!(expected.contains_key::<AssetLockControlV1>());
    assert!(expected.contains_key::<Option<AssetLockWaterfallSettlementV1>>());
    assert!(find_missing_schema_references(&expected).is_empty());
}
