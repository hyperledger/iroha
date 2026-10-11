//! Canonical fixed-array custody and exact retained-role tests, without proof authority.

use super::*;
use crate::kagemusha::{
    KagemushaWalletEffectV1, KagemushaWalletPolicyUpdateKindV1, KagemushaWalletQuotaWindowKindV1,
    KagemushaWalletRecoveryCapsuleV1, KagemushaWalletRetainedInputRoleV1,
    KagemushaWalletRetainedInputV1,
};

fn full() -> KagemushaWalletQuotaRefreshWitnessV1 {
    KagemushaWalletQuotaRefreshWitnessV1 {
        version: 1,
        predecessor_usage: core::array::from_fn(|i| {
            let i = u64::try_from(i).unwrap();
            Some(KagemushaWalletQuotaUsageLeafV1 {
                window_kind: KagemushaWalletQuotaWindowKindV1::Daily,
                window_start_ms: i * 2,
                window_end_ms: i * 2 + 2,
                used: u128::MAX - u128::from(i),
            })
        }),
    }
}

#[test]
fn all64_slots_and_empty_padding_roundtrip_with_exact_roots() {
    for witness in
        [
            full(),
            KagemushaWalletQuotaRefreshWitnessV1::from_usage(
                &KagemushaWalletQuotaUsageArrayV1::empty(),
            )
            .unwrap(),
        ]
    {
        let usage = witness.usage().unwrap();
        assert_eq!(
            KagemushaWalletQuotaRefreshWitnessV1::from_usage(&usage).unwrap(),
            witness
        );
        let bytes = witness.to_canonical_bytes().unwrap();
        assert!(bytes.len() <= KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1);
        let decoded = KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, witness);
        assert_eq!(decoded.usage().unwrap().root(), usage.root());
        assert_eq!(decoded.to_canonical_bytes().unwrap(), bytes);
        for changed in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ] {
            assert!(KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&changed).is_err());
        }
        eprintln!(
            "QUOTA_REFRESH_WITNESS slots=64 occupied={} frame_bytes={} padding=8",
            witness.predecessor_usage.iter().flatten().count(),
            bytes.len()
        );
    }
    assert!(
        KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&vec![
            0;
            KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}

#[test]
fn malformed_order_version_intervals_and_holes_fail_canonical_intake() {
    for change in 0..6 {
        let mut witness = full();
        match change {
            0 => witness.version = 2,
            1 => witness.predecessor_usage[0] = None,
            2 => witness.predecessor_usage.swap(0, 1),
            3 => witness.predecessor_usage[1] = witness.predecessor_usage[0],
            4 => witness.predecessor_usage[0].as_mut().unwrap().window_end_ms = 0,
            _ => witness.predecessor_usage[0].as_mut().unwrap().window_end_ms = 3,
        }
        assert!(witness.usage().is_err());
        assert!(witness.to_canonical_bytes().is_err());
        let original = norito::encode_canonical(&witness).unwrap();
        assert!(KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(&original).is_err());
    }
}

#[test]
fn quota_effect_requires_exactly_one_typed_original_and_other_effects_refuse_it() {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1"))
        .unwrap();
    let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let mut capsule: KagemushaWalletRecoveryCapsuleV1 = norito::decode_canonical(&bytes).unwrap();
    assert!(capsule.quota_refresh_witness().unwrap().is_none());
    let input = KagemushaWalletRetainedInputV1 {
        role: KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness,
        bytes: full().to_canonical_bytes().unwrap(),
    };
    capsule.retained_inputs.push(input.clone());
    assert!(capsule.quota_refresh_witness().is_err());
    assert!(capsule.validate().is_err());
    capsule.statement.effect = KagemushaWalletEffectV1::RefreshPolicy {
        update_kind: KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        update: [1; 32],
        accepted_time_floor_ms: 0,
    };
    assert_eq!(capsule.quota_refresh_witness().unwrap(), Some(full()));
    capsule.retained_inputs.push(input);
    assert!(capsule.quota_refresh_witness().is_err());
    capsule.retained_inputs.pop();
    capsule.retained_inputs.last_mut().unwrap().bytes.push(0);
    assert!(capsule.quota_refresh_witness().is_err());
    capsule.retained_inputs.pop();
    assert!(capsule.quota_refresh_witness().is_err());
}
