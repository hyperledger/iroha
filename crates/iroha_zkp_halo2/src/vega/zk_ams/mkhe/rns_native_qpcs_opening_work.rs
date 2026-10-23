//! Fail-closed work preflight for native qPCS Merkle and initial rebind hashes.
//!
//! This private prerequisite derives a conservative hash-work bound from the
//! canonical six-lane leaf and node frames, including the repeated payload and
//! index hashes in `bind_query_openings_v1`. It deliberately does not authenticate
//! a proof, account for query-opening digests, transcript or source arithmetic,
//! or grant a qPCS receipt. The original proof-session budget reaches the
//! source-bound transition, but no live source constructor reaches that stage.
//! TODO: retain the budget through complete qPCS authentication and account
//! for query-opening and transcript hashes, source work, arithmetic, memory,
//! spool, and I/O.

#![allow(
    dead_code,
    reason = "the source-bound qPCS transition has no live production constructor"
)]

use super::{
    rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1, ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1,
    },
    rns_native_proof_hash::RnsNativeProofHashWorkV1,
    rns_native_qpcs_leaf::RnsNativeOracleV1,
    rns_native_resource_budget::{RnsNativeProofResourceBudgetV1, RnsNativeResourceErrorV1},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeQpcsOpeningWorkErrorV1 {
    InvalidOracle,
    InvalidCount,
    ArithmeticOverflow,
    Resource(RnsNativeResourceErrorV1),
}

/// Conservative hash work for canonical multiproofs and initial query rebinding.
/// Each opened leaf is hashed once as a payload and once with its position; at
/// most one ancestor per tree level is hashed per opened leaf. Rebinding charges
/// both leaf frames again even if the one-entry public-leaf cache hits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RnsNativeQpcsOpeningHashWorkV1 {
    field_operations: u64,
}

impl RnsNativeQpcsOpeningHashWorkV1 {
    pub(super) fn for_opened_leaves_v1(
        parameter_digest: [u8; 32],
        oracle: RnsNativeOracleV1,
        opened_leaves: u64,
    ) -> Result<Self, RnsNativeQpcsOpeningWorkErrorV1> {
        let tree_leaves = u64::from(
            oracle
                .length()
                .map_err(|_| RnsNativeQpcsOpeningWorkErrorV1::InvalidOracle)?,
        );
        if opened_leaves == 0 || opened_leaves > tree_leaves {
            return Err(RnsNativeQpcsOpeningWorkErrorV1::InvalidCount);
        }
        let [payload, index, node] = oracle
            .full_tree_frame_work(parameter_digest)
            .map_err(|_| RnsNativeQpcsOpeningWorkErrorV1::InvalidOracle)?;
        let leaf_operations = frame_operations_v1(payload)?
            .checked_add(frame_operations_v1(index)?)
            .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        let node_operations = frame_operations_v1(node)?;
        let depth = u64::from(tree_leaves.ilog2());
        let per_leaf = leaf_operations
            .checked_add(
                depth
                    .checked_mul(node_operations)
                    .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        Ok(Self {
            field_operations: checked_opening_work_v1(opened_leaves, per_leaf)?,
        })
    }

    /// Conservative sum of every canonical initial, quotient, and correlated-FRI
    /// Merkle opening plus the second initial-leaf pass for query binding. Each
    /// tree opens at most two leaves per query, capped by its governed domain
    /// size; duplicate pairs and cache hits only reduce actual work. The verifier
    /// hashes at most one ancestor per opened leaf at each level.
    pub(super) fn for_canonical_merkle_and_rebind_leaf_hashes_v1(
        parameter_digest: [u8; 32],
    ) -> Result<Self, RnsNativeQpcsOpeningWorkErrorV1> {
        let max_opened = u64::from(ZK_AMS_MKHE_RNS_NATIVE_QUERY_COUNT_V1)
            .checked_mul(2)
            .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        let mut field_operations = 0_u64;
        for oracle in [RnsNativeOracleV1::Initial, RnsNativeOracleV1::Quotient] {
            let work = Self::for_opened_leaves_v1(parameter_digest, oracle, max_opened)?;
            field_operations = field_operations
                .checked_add(work.field_operations)
                .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        }
        for layer in 0..ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 {
            let oracle = RnsNativeOracleV1::Fri { layer };
            let length = u64::from(
                oracle
                    .length()
                    .map_err(|_| RnsNativeQpcsOpeningWorkErrorV1::InvalidOracle)?,
            );
            let work =
                Self::for_opened_leaves_v1(parameter_digest, oracle, max_opened.min(length))?;
            field_operations = field_operations
                .checked_add(work.field_operations)
                .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        }
        // Initial authentication then calls bind_query_openings_v1, which asks
        // the one-entry cache for each of 160 ordered leaf pairs a second time.
        // A hit skips only the payload hash, never the index hash; charge both
        // canonical frames for all 320 calls before the first public read.
        let [payload, index, _] = RnsNativeOracleV1::Initial
            .full_tree_frame_work(parameter_digest)
            .map_err(|_| RnsNativeQpcsOpeningWorkErrorV1::InvalidOracle)?;
        let per_rebound_leaf = frame_operations_v1(payload)?
            .checked_add(frame_operations_v1(index)?)
            .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        field_operations = field_operations
            .checked_add(checked_opening_work_v1(max_opened, per_rebound_leaf)?)
            .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)?;
        Ok(Self { field_operations })
    }

    pub(super) const fn field_operations_v1(self) -> u64 {
        self.field_operations
    }

    /// Debit the caller's existing original-session ledger. Work is permanent
    /// even when later proof authentication fails; no fresh budget is created.
    pub(super) fn admit_v1(
        self,
        original_budget: &mut RnsNativeProofResourceBudgetV1,
    ) -> Result<(), RnsNativeQpcsOpeningWorkErrorV1> {
        let _reservation = original_budget
            .admit(self.field_operations, 0, 0)
            .map_err(RnsNativeQpcsOpeningWorkErrorV1::Resource)?;
        Ok(())
    }
}

fn frame_operations_v1(
    frame: RnsNativeProofHashWorkV1,
) -> Result<u64, RnsNativeQpcsOpeningWorkErrorV1> {
    frame
        .field_multiplications
        .checked_add(frame.field_additions)
        .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)
}

fn checked_opening_work_v1(
    opened_leaves: u64,
    per_leaf: u64,
) -> Result<u64, RnsNativeQpcsOpeningWorkErrorV1> {
    opened_leaves
        .checked_mul(per_leaf)
        .ok_or(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::zk_ams::mkhe::{
        rns_native_profile::ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1,
        rns_native_proof_hash::RnsNativeProofHashContextV1,
    };

    fn parameter_v1() -> [u8; 32] {
        RnsNativeProofHashContextV1::canonical()
            .unwrap()
            .parameter_digest()
    }

    #[test]
    fn canonical_frames_bound_opening_hashes_without_discounting_cache_hits() {
        let work = RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
            parameter_v1(),
            RnsNativeOracleV1::Initial,
            320,
        )
        .unwrap();
        assert_eq!(
            work.field_operations_v1(),
            320 * (4_809_204 + 476_862 + 19 * 466_716)
        );
        let [payload, index, _] = RnsNativeOracleV1::Initial
            .full_tree_frame_work(parameter_v1())
            .unwrap();
        assert_eq!(frame_operations_v1(payload).unwrap(), 4_809_204);
        assert_eq!(frame_operations_v1(index).unwrap(), 476_862);
        assert!(matches!(
            RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
                parameter_v1(),
                RnsNativeOracleV1::Fri { layer: 18 },
                1,
            ),
            Err(RnsNativeQpcsOpeningWorkErrorV1::InvalidOracle)
        ));
        assert!(matches!(
            RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
                parameter_v1(),
                RnsNativeOracleV1::Initial,
                0,
            ),
            Err(RnsNativeQpcsOpeningWorkErrorV1::InvalidCount)
        ));
    }

    #[test]
    fn merkle_and_initial_rebind_sum_uses_original_budget_and_rejects_one_over() {
        let parameter = parameter_v1();
        let initial = RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
            parameter,
            RnsNativeOracleV1::Initial,
            320,
        )
        .unwrap();
        let all = RnsNativeQpcsOpeningHashWorkV1::for_canonical_merkle_and_rebind_leaf_hashes_v1(
            parameter,
        )
        .unwrap();
        assert_eq!(all.field_operations_v1(), 56_714_638_392);
        assert_eq!(
            all.field_operations_v1() - 55_023_097_272,
            320 * (4_809_204 + 476_862)
        );
        let terminal = RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
            parameter,
            RnsNativeOracleV1::Fri { layer: 17 },
            4,
        )
        .unwrap();
        assert_eq!(terminal.field_operations_v1(), 24_877_992);
        assert!(all.field_operations_v1() > initial.field_operations_v1());
        assert!(all.field_operations_v1() < ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1);

        let mut exact = RnsNativeProofResourceBudgetV1::default();
        exact
            .charge(ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1 - all.field_operations_v1())
            .unwrap();
        all.admit_v1(&mut exact).unwrap();
        assert_eq!(
            exact.consumed().unwrap(),
            ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1
        );

        let mut over = RnsNativeProofResourceBudgetV1::default();
        over.charge(ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1 - all.field_operations_v1() + 1)
            .unwrap();
        let prior = over.consumed().unwrap();
        assert!(matches!(
            all.admit_v1(&mut over),
            Err(RnsNativeQpcsOpeningWorkErrorV1::Resource(
                RnsNativeResourceErrorV1::WorkLimit
            ))
        ));
        assert_eq!(over.consumed().unwrap(), prior);
    }

    #[test]
    fn exact_cap_and_one_over_use_the_same_original_ledger() {
        let work = RnsNativeQpcsOpeningHashWorkV1::for_opened_leaves_v1(
            parameter_v1(),
            RnsNativeOracleV1::Fri { layer: 17 },
            4,
        )
        .unwrap();
        let mut original = RnsNativeProofResourceBudgetV1::default();
        let unrelated = RnsNativeProofResourceBudgetV1::default();
        let retained = original.reserve_workspace_v1(8, 0).unwrap();
        assert!(retained.belongs_to_v1(&original));
        assert!(!retained.belongs_to_v1(&unrelated));
        original
            .charge(ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1 - work.field_operations_v1())
            .unwrap();
        work.admit_v1(&mut original).unwrap();
        assert_eq!(
            original.consumed().unwrap(),
            ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1
        );
        assert_eq!(original.live_bytes().unwrap(), 8);
        assert_eq!(unrelated.consumed().unwrap(), 0);

        let mut over = RnsNativeProofResourceBudgetV1::default();
        over.charge(ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1 - work.field_operations_v1() + 1)
            .unwrap();
        let prior = over.consumed().unwrap();
        assert!(matches!(
            work.admit_v1(&mut over),
            Err(RnsNativeQpcsOpeningWorkErrorV1::Resource(
                RnsNativeResourceErrorV1::WorkLimit
            ))
        ));
        assert_eq!(over.consumed().unwrap(), prior);
    }

    #[test]
    fn checked_work_multiplication_rejects_overflow() {
        assert_eq!(
            checked_opening_work_v1(u64::MAX, 2),
            Err(RnsNativeQpcsOpeningWorkErrorV1::ArithmeticOverflow)
        );
    }
}
