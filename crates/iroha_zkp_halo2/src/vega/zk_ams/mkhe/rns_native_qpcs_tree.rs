//! Canonical native qPCS tree construction with admission before source access.
//!
//! This test-only prototype charges dense-MDS field operations and live tree
//! buffers to the canonical production resource owner before source access.
//! It does not own or export a second budget. Its current initial-tree work
//! exceeds the unchanged cap, and extraction does not enable a production tree
//! or establish whole-proof qualification.

use zeroize::Zeroizing;

use super::{
    rns_native_proof_hash::{RnsNativeProofDigestV1, RnsNativeProofHashWorkV1},
    rns_native_qpcs_leaf::{
        CANONICAL_LEAF_BYTES_V1, RnsNativeLeafErrorV1, RnsNativeLeafPayloadV1, RnsNativeOracleV1,
        oracle_node_hash_v1,
    },
    rns_native_resource_budget::{
        RnsNativeProofResourceBudgetV1, RnsNativeResourceErrorV1, RnsNativeResourceReservationV1,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeTreeErrorV1 {
    InvalidOracle,
    InvalidSource,
    ArithmeticOverflow,
    Resource(RnsNativeResourceErrorV1),
    Allocation,
}

impl From<RnsNativeResourceErrorV1> for RnsNativeTreeErrorV1 {
    fn from(error: RnsNativeResourceErrorV1) -> Self {
        Self::Resource(error)
    }
}

/// Source-derived arithmetic and digest-storage requirements for one fixed oracle.
/// The all-payload cost is the exact constructor cost. The one-payload cost is a
/// diagnostic lower bound for immutable repeated public payloads, never an input
/// that discounts arbitrary source work at admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RnsNativeTreeWorkV1 {
    pub(super) leaves: u64,
    pub(super) internal_nodes: u64,
    pub(super) payload_frame: RnsNativeProofHashWorkV1,
    pub(super) index_frame: RnsNativeProofHashWorkV1,
    pub(super) node_frame: RnsNativeProofHashWorkV1,
    pub(super) all_payload_permutations: u64,
    pub(super) all_payload_field_operations: u64,
    pub(super) one_payload_permutations: u64,
    pub(super) one_payload_field_operations: u64,
    pub(super) digest_storage_bytes: u64,
}

impl RnsNativeTreeWorkV1 {
    pub(super) fn for_oracle(
        parameter_digest: [u8; 32],
        oracle: RnsNativeOracleV1,
    ) -> Result<Self, RnsNativeTreeErrorV1> {
        let leaves = u64::from(
            oracle
                .length()
                .map_err(|_| RnsNativeTreeErrorV1::InvalidOracle)?,
        );
        let internal_nodes = leaves
            .checked_sub(1)
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        let [payload_frame, index_frame, node_frame] = oracle
            .full_tree_frame_work(parameter_digest)
            .map_err(|_| RnsNativeTreeErrorV1::InvalidOracle)?;
        let counts = |payloads: u64, units: fn(&RnsNativeProofHashWorkV1) -> u64| {
            payloads
                .checked_mul(units(&payload_frame))
                .and_then(|work| {
                    leaves
                        .checked_mul(units(&index_frame))
                        .and_then(|leaves| work.checked_add(leaves))
                })
                .and_then(|work| {
                    internal_nodes
                        .checked_mul(units(&node_frame))
                        .and_then(|nodes| work.checked_add(nodes))
                })
                .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)
        };
        let permutations = |frame: &RnsNativeProofHashWorkV1| frame.lane_permutations;
        // Every frame is bounded by the fixed current geometry, so this per-frame
        // addition is checked once before using the total-count closure.
        for frame in [&payload_frame, &index_frame, &node_frame] {
            frame
                .field_multiplications
                .checked_add(frame.field_additions)
                .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        }
        let operations =
            |frame: &RnsNativeProofHashWorkV1| frame.field_multiplications + frame.field_additions;
        let digest_storage_bytes = leaves
            .checked_add(internal_nodes)
            .and_then(|count| count.checked_mul(48))
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        Ok(Self {
            leaves,
            internal_nodes,
            payload_frame,
            index_frame,
            node_frame,
            all_payload_permutations: counts(leaves, permutations)?,
            all_payload_field_operations: counts(leaves, operations)?,
            one_payload_permutations: counts(1, permutations)?,
            one_payload_field_operations: counts(1, operations)?,
            digest_storage_bytes,
        })
    }

    /// Exact work floor for the current index-bound leaves and binary nodes.
    ///
    /// This deliberately excludes every payload hash. It screens proposals
    /// that only shorten or avoid payload hashing while retaining the same
    /// six-lane index and node frames; it is not a replacement admission cost.
    pub(super) fn index_node_floor_field_operations(self) -> Result<u64, RnsNativeTreeErrorV1> {
        let index = self
            .index_frame
            .field_multiplications
            .checked_add(self.index_frame.field_additions)
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        let node = self
            .node_frame
            .field_multiplications
            .checked_add(self.node_frame.field_additions)
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        self.leaves
            .checked_mul(index)
            .and_then(|work| {
                self.internal_nodes
                    .checked_mul(node)
                    .and_then(|nodes| work.checked_add(nodes))
            })
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)
    }
}

/// All nodes of one exact governed tree, leaves first and root last.
/// Raw digests cannot be installed as a tree; construction hashes canonical values.
#[derive(Debug)]
pub(super) struct RnsNativeQpcsTreeV1 {
    oracle: RnsNativeOracleV1,
    leaves: usize,
    nodes: Vec<RnsNativeProofDigestV1>,
    // Declared after nodes so their allocation drops before its reservation.
    _reservation: RnsNativeResourceReservationV1,
}

impl RnsNativeQpcsTreeV1 {
    /// Build with exact indexed leaves and nodes after fixed-profile work admission.
    /// The callback supplies one canonical 6000-byte leaf; it must overwrite every
    /// byte. The scratch buffer is cleared before each call and zeroized on drop.
    /// Work for producing those values belongs to the source owner, not this hash ledger.
    pub(super) fn build(
        parameter_digest: [u8; 32],
        oracle: RnsNativeOracleV1,
        budget: &mut RnsNativeProofResourceBudgetV1,
        mut read_leaf: impl FnMut(
            u32,
            &mut [u8; CANONICAL_LEAF_BYTES_V1],
        ) -> Result<(), RnsNativeLeafErrorV1>,
    ) -> Result<Self, RnsNativeTreeErrorV1> {
        let work = RnsNativeTreeWorkV1::for_oracle(parameter_digest, oracle)?;
        // Admit cumulative work and all live named buffers before allocating,
        // constructing scratch, hashing residues, or calling the source.
        let mut reservation = budget.admit(
            work.all_payload_field_operations,
            work.digest_storage_bytes,
            CANONICAL_LEAF_BYTES_V1 as u64,
        )?;
        let leaves =
            usize::try_from(work.leaves).map_err(|_| RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        let count = work
            .leaves
            .checked_add(work.internal_nodes)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(RnsNativeTreeErrorV1::ArithmeticOverflow)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(count)
            .map_err(|_| RnsNativeTreeErrorV1::Allocation)?;
        // A larger allocator-selected capacity must not become an uncharged
        // retained buffer. Reject it before source access or any proof hashing.
        if nodes.capacity() != count {
            return Err(RnsNativeTreeErrorV1::Allocation);
        }
        let mut scratch = Zeroizing::new([0; CANONICAL_LEAF_BYTES_V1]);
        for index in 0..leaves {
            scratch.fill(0);
            read_leaf(index as u32, &mut scratch)
                .map_err(|_| RnsNativeTreeErrorV1::InvalidSource)?;
            let payload = RnsNativeLeafPayloadV1::from_canonical_values(
                parameter_digest,
                oracle,
                &scratch[..],
            )
            .map_err(|_| RnsNativeTreeErrorV1::InvalidSource)?;
            nodes.push(
                payload
                    .at_index(index as u32)
                    .map_err(|_| RnsNativeTreeErrorV1::InvalidSource)?,
            );
        }
        let mut previous_start = 0;
        let mut previous_length = leaves;
        for height in 1..=leaves.ilog2() as usize {
            let current_start = nodes.len();
            for index in 0..previous_length / 2 {
                let first = previous_start + 2 * index;
                nodes.push(
                    oracle_node_hash_v1(
                        parameter_digest,
                        oracle,
                        height,
                        index as u32,
                        [nodes[first], nodes[first + 1]],
                    )
                    .map_err(|_| RnsNativeTreeErrorV1::InvalidSource)?,
                );
            }
            previous_start = current_start;
            previous_length /= 2;
        }
        if nodes.len() != count {
            return Err(RnsNativeTreeErrorV1::InvalidSource);
        }
        drop(scratch);
        reservation.release_scratch();
        Ok(Self {
            oracle,
            leaves,
            nodes,
            _reservation: reservation,
        })
    }

    pub(super) fn root(&self) -> RnsNativeProofDigestV1 {
        self.nodes[self.nodes.len() - 1]
    }

    pub(super) fn node(&self, height: usize, index: u32) -> Option<RnsNativeProofDigestV1> {
        if height > self.leaves.ilog2() as usize || index as usize >= self.leaves >> height {
            return None;
        }
        let offset = 2 * self.leaves - (self.leaves >> height) * 2;
        self.nodes.get(offset + index as usize).copied()
    }

    pub(super) fn oracle(&self) -> RnsNativeOracleV1 {
        self.oracle
    }
}

#[cfg(test)]
mod tests {
    use super::super::rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1, ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1,
    };
    use super::super::rns_native_proof_hash::RnsNativeProofHashContextV1;
    use super::*;

    fn parameter() -> [u8; 32] {
        RnsNativeProofHashContextV1::canonical()
            .unwrap()
            .parameter_digest()
    }

    #[test]
    fn actual_frames_derive_exact_full_and_repeated_payload_initial_bounds() {
        let work =
            RnsNativeTreeWorkV1::for_oracle(parameter(), RnsNativeOracleV1::Initial).unwrap();
        assert_eq!((work.leaves, work.internal_nodes), (524_288, 524_287));
        assert_eq!(
            [
                work.payload_frame.words_per_lane,
                work.index_frame.words_per_lane,
                work.node_frame.words_per_lane
            ],
            [948, 94, 92]
        );
        assert_eq!(work.all_payload_permutations, 1_783_627_500);
        assert_eq!(work.one_payload_permutations, 292_555_272);
        assert_eq!(work.all_payload_field_operations, 3_016_114_102_500);
        assert_eq!(work.one_payload_field_operations, 494_710_964_952);
        let structural_floor = work.index_node_floor_field_operations().unwrap();
        assert_eq!(structural_floor, 494_706_155_748);
        let index_only = work.leaves
            * (work.index_frame.field_multiplications + work.index_frame.field_additions);
        assert_eq!(index_only, 250_013_024_256);
        assert!(index_only > ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1);
        assert_eq!(
            work.all_payload_field_operations - structural_floor,
            work.leaves
                * (work.payload_frame.field_multiplications + work.payload_frame.field_additions)
        );
        assert_eq!(
            work.one_payload_field_operations - structural_floor,
            work.payload_frame.field_multiplications + work.payload_frame.field_additions
        );
        assert!(structural_floor > ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1);
        let mut overflowing = work;
        overflowing.leaves = u64::MAX;
        assert_eq!(
            overflowing.index_node_floor_field_operations(),
            Err(RnsNativeTreeErrorV1::ArithmeticOverflow)
        );
        assert_eq!(work.digest_storage_bytes, 50_331_600);
        assert!(work.one_payload_field_operations > ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1);
        for oracle in [
            RnsNativeOracleV1::Quotient,
            RnsNativeOracleV1::Fri { layer: 0 },
            RnsNativeOracleV1::Fri { layer: 17 },
        ] {
            let other = RnsNativeTreeWorkV1::for_oracle(parameter(), oracle).unwrap();
            assert_eq!(other.payload_frame.words_per_lane, 948);
            assert_eq!(other.index_frame.words_per_lane, 94);
            assert_eq!(other.node_frame.words_per_lane, 92);
            assert_eq!(other.internal_nodes + 1, other.leaves);
        }
        let terminal =
            RnsNativeTreeWorkV1::for_oracle(parameter(), RnsNativeOracleV1::Fri { layer: 17 })
                .unwrap();
        assert!(
            terminal.index_node_floor_field_operations().unwrap()
                < ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1
        );
        assert_eq!(
            RnsNativeTreeWorkV1::for_oracle(parameter(), RnsNativeOracleV1::Fri { layer: 18 }),
            Err(RnsNativeTreeErrorV1::InvalidOracle)
        );
        assert_eq!(
            RnsNativeTreeWorkV1::for_oracle([0; 32], RnsNativeOracleV1::Initial),
            Err(RnsNativeTreeErrorV1::InvalidOracle)
        );
    }

    #[test]
    fn oversize_full_trees_reject_before_any_source_call_and_preserve_budget() {
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        budget.charge(7).unwrap();
        for oracle in [
            RnsNativeOracleV1::Initial,
            RnsNativeOracleV1::Quotient,
            RnsNativeOracleV1::Fri { layer: 0 },
        ] {
            let result = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| {
                panic!("work rejection must precede source access")
            });
            assert!(matches!(
                result,
                Err(RnsNativeTreeErrorV1::Resource(
                    RnsNativeResourceErrorV1::WorkLimit
                ))
            ));
            assert_eq!(budget.consumed().expect("healthy resource ledger"), 7);
        }
        // The cap is exact and fixed, with no caller-supplied limit or reset.
        budget
            .charge(ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1 - 7)
            .unwrap();
        assert_eq!(budget.charge(1), Err(RnsNativeResourceErrorV1::WorkLimit));
        assert_eq!(
            budget.charge(u64::MAX),
            Err(RnsNativeResourceErrorV1::ArithmeticOverflow)
        );
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            ZK_AMS_MKHE_RNS_NATIVE_WORK_MAX_V1
        );
    }

    #[test]
    fn final_layer_tree_uses_every_canonical_index_and_exact_shared_nodes() {
        let oracle = RnsNativeOracleV1::Fri { layer: 17 };
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        let mut calls = Vec::new();
        let tree = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |index, bytes| {
            calls.push(index);
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes[0] = index as u8;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [0, 1, 2, 3]);
        assert_eq!(tree.oracle(), oracle);
        assert_eq!(tree.nodes.len(), 7);
        let mut leaves = Vec::new();
        for index in 0..4 {
            let mut bytes = [0; CANONICAL_LEAF_BYTES_V1];
            bytes[0] = index as u8;
            let leaf = RnsNativeLeafPayloadV1::from_canonical_values(parameter(), oracle, &bytes)
                .unwrap()
                .at_index(index)
                .unwrap();
            assert_eq!(tree.node(0, index), Some(leaf));
            leaves.push(leaf);
        }
        let left = oracle_node_hash_v1(parameter(), oracle, 1, 0, [leaves[0], leaves[1]]).unwrap();
        let right = oracle_node_hash_v1(parameter(), oracle, 1, 1, [leaves[2], leaves[3]]).unwrap();
        assert_eq!(tree.node(1, 0), Some(left));
        assert_eq!(tree.node(1, 1), Some(right));
        assert_eq!(
            tree.root(),
            oracle_node_hash_v1(parameter(), oracle, 2, 0, [left, right]).unwrap()
        );
        assert_eq!(tree.node(2, 0), Some(tree.root()));
        assert_eq!(tree.node(2, 1), None);
        assert_eq!(tree.node(3, 0), None);
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            RnsNativeTreeWorkV1::for_oracle(parameter(), oracle)
                .unwrap()
                .all_payload_field_operations
        );
    }

    #[test]
    fn source_failure_and_noncanonical_packing_never_refund_admitted_work() {
        let oracle = RnsNativeOracleV1::Fri { layer: 17 };
        let expected = RnsNativeTreeWorkV1::for_oracle(parameter(), oracle)
            .unwrap()
            .all_payload_field_operations;
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        let mut calls = 0;
        let result = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| {
            calls += 1;
            Err(RnsNativeLeafErrorV1::Payload)
        });
        assert!(matches!(result, Err(RnsNativeTreeErrorV1::InvalidSource)));
        assert_eq!(calls, 1);
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            expected
        );
        let result = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, bytes| {
            bytes[..15].fill(255);
            Ok(())
        });
        assert!(matches!(result, Err(RnsNativeTreeErrorV1::InvalidSource)));
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            2 * expected
        );
        let source = include_str!("rns_native_qpcs_tree.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();
        let charged = implementation
            .find("let mut reservation = budget.admit(")
            .unwrap();
        for later in [".try_reserve_exact(", "Zeroizing::new", "read_leaf(index"] {
            assert!(charged < implementation.find(later).unwrap());
        }
    }

    #[test]
    fn two_real_terminal_trees_keep_exact_live_storage_until_each_drop() {
        fn requires_send_sync<T: Send + Sync>() {}
        requires_send_sync::<RnsNativeProofResourceBudgetV1>();
        requires_send_sync::<RnsNativeQpcsTreeV1>();
        let oracle = RnsNativeOracleV1::Fri { layer: 17 };
        let work = RnsNativeTreeWorkV1::for_oracle(parameter(), oracle).unwrap();
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        let first = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |index, bytes| {
            bytes[0] = index as u8;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            first.nodes.capacity() as u64 * 48,
            work.digest_storage_bytes
        );
        assert_eq!(
            budget.live_bytes().expect("healthy resource ledger"),
            work.digest_storage_bytes
        );
        let second =
            RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |index, bytes| {
                bytes[0] = index as u8;
                Ok(())
            })
            .unwrap();
        assert_eq!(first.root(), second.root());
        assert_eq!(
            budget.live_bytes().expect("healthy resource ledger"),
            2 * work.digest_storage_bytes
        );
        assert_eq!(
            budget.peak_bytes().expect("healthy resource ledger"),
            2 * work.digest_storage_bytes + CANONICAL_LEAF_BYTES_V1 as u64
        );
        drop(first);
        assert_eq!(
            budget.live_bytes().expect("healthy resource ledger"),
            work.digest_storage_bytes
        );
        drop(second);
        assert_eq!(budget.live_bytes().expect("healthy resource ledger"), 0);
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            2 * work.all_payload_field_operations
        );
    }

    #[test]
    fn cumulative_workspace_rejects_a_real_tree_before_source_and_work_charge() {
        let oracle = RnsNativeOracleV1::Fri { layer: 17 };
        let work = RnsNativeTreeWorkV1::for_oracle(parameter(), oracle).unwrap();
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        // This reservation represents another live named buffer; no giant
        // allocation is needed to test the exact admission boundary.
        let retained = ZK_AMS_MKHE_RNS_NATIVE_WORKSPACE_MAX_BYTES_V1
            - work.digest_storage_bytes
            - CANONICAL_LEAF_BYTES_V1 as u64
            + 1;
        let other = budget.admit(11, retained, 0).unwrap();
        let result = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| {
            panic!("workspace rejection must precede source access")
        });
        assert!(matches!(
            result,
            Err(RnsNativeTreeErrorV1::Resource(
                RnsNativeResourceErrorV1::WorkspaceLimit
            ))
        ));
        assert_eq!(budget.consumed().expect("healthy resource ledger"), 11);
        assert_eq!(
            budget.live_bytes().expect("healthy resource ledger"),
            retained
        );
        drop(other);
        let tree =
            RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| Ok(())).unwrap();
        assert_eq!(
            budget.live_bytes().expect("healthy resource ledger"),
            work.digest_storage_bytes
        );
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            11 + work.all_payload_field_operations
        );
        drop(tree);
        assert_eq!(budget.live_bytes().expect("healthy resource ledger"), 0);
    }

    #[test]
    fn source_error_and_unwind_release_every_reservation_without_refunding_work() {
        let oracle = RnsNativeOracleV1::Fri { layer: 17 };
        let work = RnsNativeTreeWorkV1::for_oracle(parameter(), oracle).unwrap();
        let mut budget = RnsNativeProofResourceBudgetV1::default();
        let error = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| {
            Err(RnsNativeLeafErrorV1::Payload)
        });
        assert!(matches!(error, Err(RnsNativeTreeErrorV1::InvalidSource)));
        assert_eq!(budget.live_bytes().expect("healthy resource ledger"), 0);
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            work.all_payload_field_operations
        );
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _tree = RnsNativeQpcsTreeV1::build(parameter(), oracle, &mut budget, |_, _| {
                panic!("source unwind after admission")
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(
            budget.live_bytes(),
            Ok(0),
            "source runs outside the ledger lock"
        );
        assert_eq!(budget.charge(0), Ok(()), "healthy ledger remains usable");
        assert_eq!(budget.live_bytes().expect("healthy resource ledger"), 0);
        assert_eq!(
            budget.consumed().expect("healthy resource ledger"),
            2 * work.all_payload_field_operations
        );
        assert_eq!(
            budget.peak_bytes().expect("healthy resource ledger"),
            work.digest_storage_bytes + CANONICAL_LEAF_BYTES_V1 as u64
        );
    }
}
