//! The sole native qPCS leaf construction, shared by prover and verifier owners.
//!
//! A leaf first commits all canonical packed residues under its oracle context;
//! the index-bound commitment then binds all six payload-digest lanes. A cache
//! borrows at most one already-public proof payload and its typed commitment.
//! It never caches witness coefficients or changes the construction on a hit.

use super::rns_native_proof_hash::RnsNativeProofHashWorkV1;
use super::{
    rns_native_profile::{
        ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1, ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1,
        ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1,
    },
    rns_native_proof_hash::{
        RnsNativeProofDigestV1, RnsNativeProofHashContextV1, RnsNativeProofHashPhaseV1,
        RnsNativeProofHashPositionV1, RnsNativeProofHashRoleV1,
    },
    rns_native_qpcs_field_wire::{RNS_NATIVE_QPCS_FQ2_BYTES_V1, decode_fq2_v1},
};

const VERSION_V1: u8 = 1;
const ROWS_PER_LIMB_V1: usize = 10;
const COORDINATES_V1: usize = ZK_AMS_MKHE_RNS_NATIVE_LIMBS_V1 * ROWS_PER_LIMB_V1;
pub(super) const CANONICAL_LEAF_BYTES_V1: usize = COORDINATES_V1 * RNS_NATIVE_QPCS_FQ2_BYTES_V1;
const PAYLOAD_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.canonical-leaf-payload";
const INITIAL_NODE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.initial-node";
const PREFIX_NODE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.prefix.tree-node";
const INDEX_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.mkhe.rns-native-qpcs.index-bound-leaf";

/// Verifier-owned oracle identity; its length is derived from the fixed profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeOracleV1 {
    Initial,
    Quotient,
    Fri { layer: u8 },
}

impl RnsNativeOracleV1 {
    fn geometry(self) -> Result<(RnsNativeProofHashRoleV1, [u8; 2], u32), RnsNativeLeafErrorV1> {
        let domain = 1_u32 << ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1;
        match self {
            Self::Initial => Ok((RnsNativeProofHashRoleV1::Initial, [0, 0], domain)),
            Self::Quotient => Ok((RnsNativeProofHashRoleV1::Quotient, [1, 0], domain)),
            Self::Fri { layer } if layer < ZK_AMS_MKHE_RNS_NATIVE_FRI_ROUNDS_V1 => {
                Ok((RnsNativeProofHashRoleV1::Fri, [2, layer], domain >> layer))
            }
            _ => Err(RnsNativeLeafErrorV1::Oracle),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RnsNativeLeafErrorV1 {
    Oracle,
    Payload,
    Index,
    Context,
    Hash,
}

/// A validated payload commitment for one exact oracle; no raw constructor exists.
#[derive(Clone, Copy)]
pub(super) struct RnsNativeLeafPayloadV1 {
    context: RnsNativeProofHashContextV1,
    oracle: RnsNativeOracleV1,
    digest: RnsNativeProofDigestV1,
}

impl RnsNativeLeafPayloadV1 {
    pub(super) fn from_canonical_values(
        parameter_digest: [u8; 32],
        oracle: RnsNativeOracleV1,
        values: &[u8],
    ) -> Result<Self, RnsNativeLeafErrorV1> {
        oracle.geometry()?;
        if values.len() != CANONICAL_LEAF_BYTES_V1 {
            return Err(RnsNativeLeafErrorV1::Payload);
        }
        for (coordinate, pair) in values
            .chunks_exact(RNS_NATIVE_QPCS_FQ2_BYTES_V1)
            .enumerate()
        {
            decode_fq2_v1(coordinate / ROWS_PER_LIMB_V1, pair)
                .map_err(|_| RnsNativeLeafErrorV1::Payload)?;
        }
        let context =
            RnsNativeProofHashContextV1::canonical().map_err(|_| RnsNativeLeafErrorV1::Context)?;
        if context.parameter_digest() != parameter_digest {
            return Err(RnsNativeLeafErrorV1::Context);
        }
        let digest = with_leaf_frame_v1(context, oracle, None, values, |frame| {
            Ok(RnsNativeProofDigestV1::from_shared(frame.hash()))
        })?;
        Ok(Self {
            context,
            oracle,
            digest,
        })
    }

    /// Bind the complete validated payload digest to one exact in-range leaf.
    pub(super) fn at_index(
        &self,
        index: u32,
    ) -> Result<RnsNativeProofDigestV1, RnsNativeLeafErrorV1> {
        with_leaf_frame_v1(
            self.context,
            self.oracle,
            Some(index),
            self.digest.as_bytes(),
            |frame| Ok(RnsNativeProofDigestV1::from_shared(frame.hash())),
        )
    }
}

/// Apply one actual shared leaf frame without retaining stack field descriptors.
fn with_leaf_frame_v1<T>(
    context: RnsNativeProofHashContextV1,
    oracle: RnsNativeOracleV1,
    index: Option<u32>,
    content: &[u8],
    apply: impl FnOnce(&fastpq_isi::GoldilocksDigest384FrameV1<'_>) -> Result<T, RnsNativeLeafErrorV1>,
) -> Result<T, RnsNativeLeafErrorV1> {
    let (tree_role, axes, length) = oracle.geometry()?;
    let (role, domain, position) = if let Some(index) = index {
        if index >= length || content.len() != 48 {
            return Err(RnsNativeLeafErrorV1::Index);
        }
        (
            tree_role,
            INDEX_DOMAIN_V1,
            RnsNativeProofHashPositionV1 {
                level: 0,
                index: u64::from(index),
                counter: 0,
            },
        )
    } else {
        if content.len() != CANONICAL_LEAF_BYTES_V1 {
            return Err(RnsNativeLeafErrorV1::Payload);
        }
        (
            RnsNativeProofHashRoleV1::OraclePayload,
            PAYLOAD_DOMAIN_V1,
            RnsNativeProofHashPositionV1 {
                level: u64::from(axes[1]),
                index: 0,
                counter: 0,
            },
        )
    };
    let fields: &[&[u8]] = &[
        domain,
        &[VERSION_V1],
        &axes,
        &length.to_be_bytes(),
        &(COORDINATES_V1 as u16).to_be_bytes(),
        &[RNS_NATIVE_QPCS_FQ2_BYTES_V1 as u8],
        &(CANONICAL_LEAF_BYTES_V1 as u32).to_be_bytes(),
        content,
    ];
    let frame = context
        .frame(role, RnsNativeProofHashPhaseV1::Leaf, position, fields)
        .map_err(|_| RnsNativeLeafErrorV1::Hash)?;
    apply(&frame)
}

/// The sole initial/quotient/FRI node frame, used by construction and membership.
fn with_node_frame_v1<T>(
    context: RnsNativeProofHashContextV1,
    oracle: RnsNativeOracleV1,
    height: usize,
    index: u32,
    children: [RnsNativeProofDigestV1; 2],
    apply: impl FnOnce(&fastpq_isi::GoldilocksDigest384FrameV1<'_>) -> Result<T, RnsNativeLeafErrorV1>,
) -> Result<T, RnsNativeLeafErrorV1> {
    let (role, axes, length) = oracle.geometry()?;
    if height == 0 || height > length.ilog2() as usize || index >= length >> height {
        return Err(RnsNativeLeafErrorV1::Index);
    }
    let initial_version = [VERSION_V1];
    let prefix_version = [VERSION_V1, axes[1]];
    let (domain, version): (&[u8], &[u8]) = match oracle {
        RnsNativeOracleV1::Initial => (INITIAL_NODE_DOMAIN_V1, &initial_version),
        _ => (PREFIX_NODE_DOMAIN_V1, &prefix_version),
    };
    let fields: &[&[u8]] = &[
        domain,
        version,
        &length.to_be_bytes(),
        children[0].as_bytes(),
        children[1].as_bytes(),
    ];
    let frame = context
        .frame(
            role,
            RnsNativeProofHashPhaseV1::Node,
            RnsNativeProofHashPositionV1 {
                level: height as u64,
                index: u64::from(index),
                counter: 0,
            },
            fields,
        )
        .map_err(|_| RnsNativeLeafErrorV1::Hash)?;
    apply(&frame)
}

impl RnsNativeOracleV1 {
    /// Exact leaf count from the governed oracle identity; callers cannot choose a smaller tree.
    pub(super) fn length(self) -> Result<u32, RnsNativeLeafErrorV1> {
        self.geometry().map(|(_, _, length)| length)
    }

    /// Reconstruct the actual payload/index/node frames and count arithmetic without hashing.
    pub(super) fn full_tree_frame_work(
        self,
        parameter_digest: [u8; 32],
    ) -> Result<[RnsNativeProofHashWorkV1; 3], RnsNativeLeafErrorV1> {
        let context = canonical_context_v1(parameter_digest)?;
        let count = |frame: &fastpq_isi::GoldilocksDigest384FrameV1<'_>| {
            RnsNativeProofHashWorkV1::from_frame(frame).map_err(|_| RnsNativeLeafErrorV1::Hash)
        };
        // Contents never affect frame length. These fixed zero slices are not hashed
        // and do not serve as authenticated leaves, proofs or source coefficients.
        let payload =
            with_leaf_frame_v1(context, self, None, &[0; CANONICAL_LEAF_BYTES_V1], count)?;
        let index = with_leaf_frame_v1(context, self, Some(0), &[0; 48], count)?;
        let node = with_node_frame_v1(
            context,
            self,
            1,
            0,
            [RnsNativeProofDigestV1::ZERO; 2],
            count,
        )?;
        Ok([payload, index, node])
    }
}

fn canonical_context_v1(
    parameter_digest: [u8; 32],
) -> Result<RnsNativeProofHashContextV1, RnsNativeLeafErrorV1> {
    let context =
        RnsNativeProofHashContextV1::canonical().map_err(|_| RnsNativeLeafErrorV1::Context)?;
    if context.parameter_digest() != parameter_digest {
        return Err(RnsNativeLeafErrorV1::Context);
    }
    Ok(context)
}

pub(super) fn oracle_node_hash_v1(
    parameter_digest: [u8; 32],
    oracle: RnsNativeOracleV1,
    height: usize,
    index: u32,
    children: [RnsNativeProofDigestV1; 2],
) -> Result<RnsNativeProofDigestV1, RnsNativeLeafErrorV1> {
    with_node_frame_v1(
        canonical_context_v1(parameter_digest)?,
        oracle,
        height,
        index,
        children,
        |frame| Ok(RnsNativeProofDigestV1::from_shared(frame.hash())),
    )
}

/// One-entry cache of borrowed canonical public payload bytes, with no allocation.
///
/// Exact bytes are compared before reuse. The Rust borrow keeps that payload
/// immutable for the cache lifetime; a miss replaces the single prior entry.
pub(super) struct RnsNativeLeafCacheV1<'a> {
    parameter_digest: [u8; 32],
    oracle: RnsNativeOracleV1,
    entry: Option<(&'a [u8], RnsNativeLeafPayloadV1)>,
    #[cfg(test)]
    payload_hashes: usize,
}

impl<'a> RnsNativeLeafCacheV1<'a> {
    pub(super) fn new(
        parameter_digest: [u8; 32],
        oracle: RnsNativeOracleV1,
    ) -> Result<Self, RnsNativeLeafErrorV1> {
        oracle.geometry()?;
        let context =
            RnsNativeProofHashContextV1::canonical().map_err(|_| RnsNativeLeafErrorV1::Context)?;
        if context.parameter_digest() != parameter_digest {
            return Err(RnsNativeLeafErrorV1::Context);
        }
        Ok(Self {
            parameter_digest,
            oracle,
            entry: None,
            #[cfg(test)]
            payload_hashes: 0,
        })
    }

    pub(super) fn leaf(
        &mut self,
        index: u32,
        values: &'a [u8],
    ) -> Result<RnsNativeProofDigestV1, RnsNativeLeafErrorV1> {
        // Reject an out-of-range leaf before hashing or changing the cache.
        let (_, _, length) = self.oracle.geometry()?;
        if index >= length {
            return Err(RnsNativeLeafErrorV1::Index);
        }
        if let Some((previous, commitment)) = self.entry
            && previous == values
        {
            return commitment.at_index(index);
        }
        let commitment = RnsNativeLeafPayloadV1::from_canonical_values(
            self.parameter_digest,
            self.oracle,
            values,
        )?;
        let leaf = commitment.at_index(index)?;
        self.entry = Some((values, commitment));
        #[cfg(test)]
        {
            self.payload_hashes += 1;
        }
        Ok(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        rns_native_profile::ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1,
        rns_native_qpcs_field_wire::encode_fq2_v1, rns_native_qpcs_prefix::Fq2V1,
    };
    use super::*;

    #[test]
    fn both_leaf_frames_match_shared_owner_and_every_oracle_and_index_is_bound() {
        let context = RnsNativeProofHashContextV1::canonical().unwrap();
        let values = [0; CANONICAL_LEAF_BYTES_V1];
        let mut roots = std::collections::BTreeSet::new();
        for oracle in [
            RnsNativeOracleV1::Initial,
            RnsNativeOracleV1::Quotient,
            RnsNativeOracleV1::Fri { layer: 0 },
            RnsNativeOracleV1::Fri { layer: 17 },
        ] {
            let (role, axes, length) = oracle.geometry().unwrap();
            let payload = RnsNativeLeafPayloadV1::from_canonical_values(
                context.parameter_digest(),
                oracle,
                &values,
            )
            .unwrap();
            let expected_payload = context
                .hash(
                    RnsNativeProofHashRoleV1::OraclePayload,
                    RnsNativeProofHashPhaseV1::Leaf,
                    RnsNativeProofHashPositionV1 {
                        level: u64::from(axes[1]),
                        index: 0,
                        counter: 0,
                    },
                    &[
                        PAYLOAD_DOMAIN_V1,
                        &[VERSION_V1],
                        &axes,
                        &length.to_be_bytes(),
                        &(COORDINATES_V1 as u16).to_be_bytes(),
                        &[15],
                        &(CANONICAL_LEAF_BYTES_V1 as u32).to_be_bytes(),
                        &values,
                    ],
                )
                .unwrap();
            assert_eq!(payload.digest, expected_payload);
            assert_eq!(
                context
                    .frame(
                        RnsNativeProofHashRoleV1::OraclePayload,
                        RnsNativeProofHashPhaseV1::Leaf,
                        RnsNativeProofHashPositionV1 {
                            level: u64::from(axes[1]),
                            index: 0,
                            counter: 0
                        },
                        &[
                            PAYLOAD_DOMAIN_V1,
                            &[VERSION_V1],
                            &axes,
                            &length.to_be_bytes(),
                            &(COORDINATES_V1 as u16).to_be_bytes(),
                            &[15],
                            &(CANONICAL_LEAF_BYTES_V1 as u32).to_be_bytes(),
                            &values,
                        ]
                    )
                    .unwrap()
                    .word_count(),
                948
            );
            for index in [0, 1, length - 1] {
                let expected = context
                    .hash(
                        role,
                        RnsNativeProofHashPhaseV1::Leaf,
                        RnsNativeProofHashPositionV1 {
                            level: 0,
                            index: u64::from(index),
                            counter: 0,
                        },
                        &[
                            INDEX_DOMAIN_V1,
                            &[VERSION_V1],
                            &axes,
                            &length.to_be_bytes(),
                            &(COORDINATES_V1 as u16).to_be_bytes(),
                            &[15],
                            &(CANONICAL_LEAF_BYTES_V1 as u32).to_be_bytes(),
                            expected_payload.as_bytes(),
                        ],
                    )
                    .unwrap();
                let actual = payload.at_index(index).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(
                    context
                        .frame(
                            role,
                            RnsNativeProofHashPhaseV1::Leaf,
                            RnsNativeProofHashPositionV1 {
                                level: 0,
                                index: u64::from(index),
                                counter: 0
                            },
                            &[
                                INDEX_DOMAIN_V1,
                                &[VERSION_V1],
                                &axes,
                                &length.to_be_bytes(),
                                &(COORDINATES_V1 as u16).to_be_bytes(),
                                &[15],
                                &(CANONICAL_LEAF_BYTES_V1 as u32).to_be_bytes(),
                                expected_payload.as_bytes(),
                            ]
                        )
                        .unwrap()
                        .word_count(),
                    94
                );
                assert!(roots.insert(actual));
            }
            assert_eq!(payload.at_index(length), Err(RnsNativeLeafErrorV1::Index));
        }
        assert_eq!(roots.len(), 12);
        assert!(
            RnsNativeLeafPayloadV1::from_canonical_values(
                context.parameter_digest(),
                RnsNativeOracleV1::Fri { layer: 18 },
                &values
            )
            .is_err()
        );
        assert!(
            RnsNativeLeafPayloadV1::from_canonical_values(
                [0; 32],
                RnsNativeOracleV1::Initial,
                &values
            )
            .is_err()
        );
    }

    #[test]
    fn every_packed_coordinate_is_canonical_and_retired_leaf_shapes_are_rejected() {
        let parameter = RnsNativeProofHashContextV1::canonical()
            .unwrap()
            .parameter_digest();
        let mut values = [0; CANONICAL_LEAF_BYTES_V1];
        for (limb, &q) in ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1.iter().enumerate() {
            let offset = limb * ROWS_PER_LIMB_V1 * RNS_NATIVE_QPCS_FQ2_BYTES_V1;
            values[offset..offset + 15].copy_from_slice(
                &encode_fq2_v1(
                    limb,
                    Fq2V1 {
                        c0: q - 1,
                        c1: q - 1,
                    },
                )
                .unwrap(),
            );
        }
        assert!(
            RnsNativeLeafPayloadV1::from_canonical_values(
                parameter,
                RnsNativeOracleV1::Initial,
                &values
            )
            .is_ok()
        );
        for component in 0..2 {
            let mut invalid = values;
            let limb = 39;
            let q = ZK_AMS_MKHE_RNS_NATIVE_MODULI_V1[limb];
            let packed = if component == 0 {
                u128::from(q) << 60
            } else {
                u128::from(q)
            };
            let offset = (limb * ROWS_PER_LIMB_V1 + 9) * 15;
            invalid[offset..offset + 15].copy_from_slice(&packed.to_be_bytes()[1..]);
            assert!(matches!(
                RnsNativeLeafPayloadV1::from_canonical_values(
                    parameter,
                    RnsNativeOracleV1::Initial,
                    &invalid
                ),
                Err(RnsNativeLeafErrorV1::Payload)
            ));
        }
        for size in [
            0,
            CANONICAL_LEAF_BYTES_V1 - 1,
            CANONICAL_LEAF_BYTES_V1 + 1,
            400 * 16,
        ] {
            assert!(matches!(
                RnsNativeLeafPayloadV1::from_canonical_values(
                    parameter,
                    RnsNativeOracleV1::Initial,
                    &vec![0; size]
                ),
                Err(RnsNativeLeafErrorV1::Payload)
            ));
        }
    }

    #[test]
    fn one_entry_cache_preserves_direct_construction_and_rejects_before_mutation() {
        let parameter = RnsNativeProofHashContextV1::canonical()
            .unwrap()
            .parameter_digest();
        let first = [0; CANONICAL_LEAF_BYTES_V1];
        let mut second = first;
        second[..15].copy_from_slice(&encode_fq2_v1(0, Fq2V1 { c0: 1, c1: 2 }).unwrap());
        let mut cache = RnsNativeLeafCacheV1::new(parameter, RnsNativeOracleV1::Initial).unwrap();
        for index in 0..4 {
            assert_eq!(
                cache.leaf(index, &first).unwrap(),
                RnsNativeLeafPayloadV1::from_canonical_values(
                    parameter,
                    RnsNativeOracleV1::Initial,
                    &first
                )
                .unwrap()
                .at_index(index)
                .unwrap()
            );
        }
        assert_eq!(cache.payload_hashes, 1);
        assert!(core::mem::size_of::<RnsNativeLeafCacheV1<'_>>() <= 256);
        let original = cache.leaf(0, &first).unwrap();
        assert_ne!(original, cache.leaf(0, &second).unwrap());
        assert_eq!(cache.payload_hashes, 2);
        assert_eq!(original, cache.leaf(0, &first).unwrap());
        assert_eq!(cache.payload_hashes, 3);
        assert_eq!(
            cache.leaf(0, &first[..first.len() - 1]),
            Err(RnsNativeLeafErrorV1::Payload)
        );
        assert_eq!(
            cache.leaf(1 << ZK_AMS_MKHE_RNS_NATIVE_LDE_DOMAIN_LOG2_V1, &first),
            Err(RnsNativeLeafErrorV1::Index)
        );
        assert_eq!(cache.payload_hashes, 3);
        assert_eq!(cache.leaf(0, &first).unwrap(), original);
        assert_eq!(cache.payload_hashes, 3);
        assert!(RnsNativeLeafCacheV1::new([0; 32], RnsNativeOracleV1::Initial).is_err());
    }
}
