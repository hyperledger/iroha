//! Exact owner-only current native FI context candidate.
use crate::{asset::fi_context::AssetFiContextTargetV1, nexus::AxtAssetIncarnationV1};
use derive_more::Display;
queries! {
    /// Derive exactly one selected native context under ordinary bounded query admission.
    /// This candidate supplies no authenticated execution, finality or freshness claim.
    #[derive(Display)]
    #[display("Find selected current native FI context")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_fi_context::FindAssetFiContextV1")]
    pub struct FindAssetFiContextV1 {
        /// Exact descriptive v3 target retained by the caller.
        pub target: AssetFiContextTargetV1,
        /// Exact current asset incarnation expected by the caller.
        pub expected_incarnation: AxtAssetIncarnationV1,
        /// Exact expected opaque UID; any current wallet binding must agree.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub expected_uid: [u8;32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_fi_query_round_trips_both_exact_v3_targets() {
        for transfer in [false, true] {
            let assertion = crate::isi::asset_fi_context::test_values::current(transfer);
            let query = FindAssetFiContextV1 {
                target: assertion.target,
                expected_incarnation: assertion.expected_incarnation,
                expected_uid: assertion.expected_uid,
            };
            let bytes = norito::encode_canonical(&query).unwrap();
            assert_eq!(
                norito::decode_canonical::<FindAssetFiContextV1>(&bytes).unwrap(),
                query
            );
            let json = norito::json::to_json(&query).unwrap();
            assert_eq!(
                norito::json::from_str::<FindAssetFiContextV1>(&json).unwrap(),
                query
            );
            let mut trailing = bytes;
            trailing.push(0);
            assert!(norito::decode_canonical::<FindAssetFiContextV1>(&trailing).is_err());
        }
    }
}
