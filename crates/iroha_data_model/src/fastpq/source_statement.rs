//! Canonical ordinary FASTPQ source-statement commitments and bounded openings.
//!
//! Membership checks bind exact expected facts to a caller-supplied ordinary-write
//! root. They do not authenticate that root, establish execution completeness, or
//! grant spend authority. Validators must derive the complete ordered entry projection.
//! TODO: wire validator capture/replay and finality-authenticated admission before
//! accepting these openings as production source evidence.

use std::num::NonZeroU64;

use crate::{NetworkId, execution_witness::FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1};
use iroha_crypto::{Hash, HashOf, MerkleProof, MerkleTree, MerkleTreeCommitment};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_schema::IntoSchema;
use norito::{NoritoDeserialize, NoritoSerialize};

/// Network and height shared by one source manifest.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqSourceStatementContextV1",
    frame = "iroha_data_model::fastpq::FastpqSourceStatementContextV1"
)]
#[norito(decode_fields)]
pub struct FastpqSourceStatementContextV1 {
    /// Exact genesis-derived deployment identity, independently authenticated.
    pub network_id: NetworkId,
    /// Exact source height; zero is not an executed block height.
    pub height: u64,
}

/// Exact lane identity observed at the source height.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqSourceLaneV1",
    frame = "iroha_data_model::fastpq::FastpqSourceLaneV1"
)]
#[norito(decode_fields)]
pub struct FastpqSourceLaneV1 {
    /// Source execution lane.
    pub lane_id: LaneId,
    /// Full source-height incarnation hash, never an activation height or prefix.
    pub lane_incarnation: Hash,
}

/// Runtime source lane binding, independent of the execution dataspace.
/// An absent lane never acquires a default lane or a synthetic incarnation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqSourceRouteV1",
    frame = "iroha_data_model::fastpq::FastpqSourceRouteV1"
)]
pub enum FastpqSourceRouteV1 {
    /// Execution supplied no lane context.
    Unrouted,
    /// Exact lane context derived at the source height.
    Lane(FastpqSourceLaneV1),
}

/// Meaning of the source identity, authenticated by the source commitment.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqSourceExecutionKindV1",
    frame = "iroha_data_model::fastpq::FastpqSourceExecutionKindV1"
)]
pub enum FastpqSourceExecutionKindV1 {
    /// Execution call, including signed, triggered or internally derived IVM execution.
    ExecutionCall,
    /// Native protocol execution keyed by its exact typed purpose identity.
    ProtocolPurpose,
}

/// One complete source execution entry in its validator-derived projection order.
/// The fields require independently authenticated execution and route authority.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqSourceExecutionEntryV1",
    frame = "iroha_data_model::fastpq::FastpqSourceExecutionEntryV1"
)]
#[norito(decode_fields)]
pub struct FastpqSourceExecutionEntryV1 {
    /// Actual execution-call or typed native protocol-purpose identity.
    pub entry_hash: Hash,
    /// Validator-derived meaning of the source identity.
    pub execution_kind: FastpqSourceExecutionKindV1,
    /// Exact source lane binding, including an explicitly absent lane.
    pub route: FastpqSourceRouteV1,
    /// Execution dataspace at the source height.
    pub dataspace_id: DataSpaceId,
}

/// Structural bound for one canonical source-entry frame, not an admission quota.
pub const FASTPQ_SOURCE_EXECUTION_ENTRY_MAX_BYTES_V1: usize = 2_048;

/// Commit the complete ordered entry projection with bounded per-entry scratch.
///
/// The preimage is the fixed domain `iroha:fastpq:source-execution-entries:v1\0`,
/// the little-endian `u32` entry count, then for each entry its little-endian
/// `u32` frame length and complete canonical nominal Norito frame. No full-list
/// frame or concatenation buffer is allocated. Count and caller cap are checked
/// before traversal; encoding failure never returns a partial digest. Order and
/// multiplicity are committed, while completeness and uniqueness remain the
/// validator's responsibility. This commitment is separate from transaction wire
/// identities committed by the public inputs.
#[must_use]
pub fn fastpq_source_execution_entries_digest_v1(
    entries: &[FastpqSourceExecutionEntryV1],
    max_executed_entries: u32,
) -> Option<Hash> {
    let count = u32::try_from(entries.len()).ok()?;
    if count > max_executed_entries {
        return None;
    }
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    Hash::new_from_writer(|writer| {
        writer.write_all(b"iroha:fastpq:source-execution-entries:v1\0")?;
        writer.write_all(&count.to_le_bytes())?;
        for entry in entries {
            let length =
                norito::canonical_frame_len(entry).map_err(|_| std::io::ErrorKind::InvalidData)?;
            if length > FASTPQ_SOURCE_EXECUTION_ENTRY_MAX_BYTES_V1 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let length = u32::try_from(length).map_err(|_| std::io::ErrorKind::InvalidData)?;
            writer.write_all(&length.to_le_bytes())?;
            norito::core::write_canonical_to_writer(entry, writer)
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
        }
        Ok(())
    })
    .ok()
}

/// One complete nonempty typed effect tape at an exact execution-entry position.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementLeafV1",
    frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1"
)]
#[norito(decode_fields)]
pub struct FastpqOrdinarySourceStatementLeafV1 {
    /// Source context repeated in each leaf to prevent cross-manifest reuse.
    pub source: FastpqSourceStatementContextV1,
    /// Sequential position among all nonempty complete effect tapes in the manifest.
    pub statement_index: u32,
    /// Position in the complete canonical source projection: external calls, time
    /// invocations, then other applied transcript sources in ascending hash order.
    pub entry_index: u32,
    /// Complete nonzero number of original typed effects in this execution-entry tape.
    /// This count may exceed the manifest's number of statement leaves.
    pub effect_count: u32,
    /// Exact source call or typed native protocol-purpose identity.
    pub entry_hash: Hash,
    /// Validator-derived meaning of the source identity.
    pub execution_kind: FastpqSourceExecutionKindV1,
    /// Exact source lane binding, including an explicitly absent lane.
    pub route: FastpqSourceRouteV1,
    /// Validator-derived source dataspace identifier.
    pub dataspace_id: DataSpaceId,
    /// Exact `execution_effects_digest_v1` of the complete original tape, including
    /// source context, ordinals, quantities, lifecycle and authority/purpose facts.
    /// Private paths, derived touched roots, statement/proof bytes are excluded.
    pub effects_digest: [u8; 32],
    /// Original source carrier timestamp in the existing FASTPQ nanosecond slot units.
    pub slot: u64,
    /// Original completed role-ID/permission/epoch table root; not account membership.
    pub perm_root: [u8; 32],
    /// Original ordered canonical transaction-wire commitment from source execution.
    pub tx_set_hash: [u8; 32],
}

/// Deterministic quantity-coverage status derived only by the original executor.
/// Optional proof/archive availability and local memory pressure are never values here.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fastpq::FastpqSourceEffectCoverageV1")]
pub enum FastpqSourceEffectCoverageV1 {
    /// Every observed quantity mutation is covered by complete typed effect occurrences.
    #[codec(index = 0)]
    Complete,
    /// Original storage observed an actual untyped quantity write/lease or a partially
    /// applied typed quantity operation. Ordinary effect-proof admission must refuse.
    #[codec(index = 1)]
    Unsupported,
}

/// Untrusted ordinary manifest; authentication comes from finality.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementManifestV1",
    frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1"
)]
#[norito(decode_fields)]
pub struct FastpqOrdinarySourceStatementManifestV1 {
    /// Source network and height.
    pub source: FastpqSourceStatementContextV1,
    /// Size of the complete source projection, including external/time entries
    /// without transfers and every additional applied transcript source.
    pub executed_entry_count: u32,
    /// Commitment to every ordered source entry, including entries without leaves.
    /// This does not replace the canonical transaction-wire hash in public inputs.
    pub source_entries_digest: Hash,
    /// Actual deterministic quantity coverage; unrelated proof availability is excluded.
    pub coverage: FastpqSourceEffectCoverageV1,
    /// Exact number of nonempty execution-entry bundles, authenticated with the root.
    pub statement_count: u32,
    /// Canonical application-Merkle root, or the distinct empty-manifest root.
    pub statement_root: Hash,
}

/// Untrusted bounded source-opening transport; no embedded finality claim.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementOpeningV1",
    frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementOpeningV1"
)]
pub struct FastpqOrdinarySourceStatementOpeningV1 {
    /// Advertised source manifest, whose inclusion must be checked separately.
    pub manifest: FastpqOrdinarySourceStatementManifestV1,
    /// Advertised exact ordinary statement identity and execution route.
    pub leaf: FastpqOrdinarySourceStatementLeafV1,
    /// Root-and-count membership of the leaf in the manifest.
    pub membership: MerkleProof<FastpqOrdinarySourceStatementLeafV1>,
    /// Exactly 256 ordinary-write SMT siblings, leaf level first.
    pub manifest_siblings: Vec<Hash>,
}

/// Decode one nominal opening under explicit caller wire and cumulative limits.
/// The result remains untrusted; no finality or membership is checked here.
///
/// # Errors
/// Rejects oversized, noncanonical, wrongly shaped or over-budget frames. An enclosing
/// Norito resource scope remains effective across sequential opening decodes.
pub fn decode_fastpq_ordinary_source_statement_opening_v1(
    bytes: &[u8],
    max_wire_bytes: usize,
    limits: norito::DecodeLimits,
) -> Result<FastpqOrdinarySourceStatementOpeningV1, norito::Error> {
    if bytes.len() > max_wire_bytes {
        return Err(norito::Error::Message(
            "source opening exceeds wire-byte limit".into(),
        ));
    }
    let opening: FastpqOrdinarySourceStatementOpeningV1 =
        norito::decode_canonical_with_limits(bytes, limits)?;
    if opening.manifest_siblings.len() != 256 || opening.membership.audit_path().len() > 32 {
        return Err(norito::Error::Message(
            "invalid ordinary source-opening proof shape".into(),
        ));
    }
    Ok(opening)
}

/// Verify both inclusions relative to independently expected source facts/root.
/// Callers must authenticate those expectations before using a successful result.
pub fn verify_fastpq_ordinary_source_statement_opening_v1(
    opening: &FastpqOrdinarySourceStatementOpeningV1,
    expected: &FastpqOrdinarySourceStatementLeafV1,
    expected_ordinary_writes_root: Hash,
    max_executed_entries: u32,
    max_statements: u32,
) -> bool {
    verify_fastpq_ordinary_source_statement_manifest_write_v1(
        &opening.manifest,
        expected.source,
        &opening.manifest_siblings,
        expected_ordinary_writes_root,
        max_executed_entries,
        max_statements,
    ) && verify_fastpq_ordinary_source_statement_membership_v1(
        &opening.leaf,
        expected,
        &opening.manifest,
        &opening.membership,
        max_executed_entries,
        max_statements,
    )
}

/// Distinct root for an explicitly present manifest with no effect tapes.
pub fn fastpq_ordinary_source_statement_empty_root_v1() -> Hash {
    Hash::new(b"iroha:fastpq:ordinary-source-statements:empty:v1\0")
}

/// Maximum complete canonical leaf bytes, bounding allocation before content hashing.
pub const FASTPQ_SOURCE_STATEMENT_LEAF_MAX_BYTES_V1: usize = 2_048;

/// Hash the complete canonical nominal leaf frame under its fixed allocation cap.
/// Encoding failure returns `None`; no unbounded or bare-payload fallback is used.
#[must_use]
pub fn fastpq_ordinary_source_statement_leaf_hash_v1(
    leaf: &FastpqOrdinarySourceStatementLeafV1,
) -> Option<HashOf<FastpqOrdinarySourceStatementLeafV1>> {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    if norito::canonical_frame_len(leaf).ok()? > FASTPQ_SOURCE_STATEMENT_LEAF_MAX_BYTES_V1 {
        return None;
    }
    // The complete canonical nominal frame is the same byte preimage; no
    // input-sized frame allocation is needed for root-only hashing.
    Hash::new_from_writer(|writer| {
        norito::core::write_canonical_to_writer(leaf, writer)
            .map_err(|_| std::io::ErrorKind::InvalidData.into())
    })
    .ok()
    .map(HashOf::from_untyped_unchecked)
}

/// Construct a manifest only from a bounded, exact ordered entry projection.
///
/// The caller must derive every leaf from its complete ordered execution-entry
/// effect tape. These structural checks bind the exact entry inventory and
/// permit at most one nonempty bundle leaf per entry; they cannot establish that
/// an omitted entry actually contained no effects or authenticate bundle contents.
pub fn build_fastpq_ordinary_source_statement_manifest_v1(
    source: FastpqSourceStatementContextV1,
    entries: &[FastpqSourceExecutionEntryV1],
    leaves: &[FastpqOrdinarySourceStatementLeafV1],
    max_executed_entries: u32,
    max_statements: u32,
) -> Option<FastpqOrdinarySourceStatementManifestV1> {
    let executed_entry_count = u32::try_from(entries.len()).ok()?;
    if source.height == 0 || executed_entry_count > max_executed_entries {
        return None;
    }
    let statement_count = u32::try_from(leaves.len()).ok()?;
    if statement_count > max_statements || statement_count > executed_entry_count {
        return None;
    }
    let mut previous: Option<&FastpqOrdinarySourceStatementLeafV1> = None;
    for (index, leaf) in leaves.iter().enumerate() {
        if leaf.source != source
            || leaf.statement_index != u32::try_from(index).ok()?
            || leaf.entry_index >= executed_entry_count
            || leaf.effect_count == 0
        {
            return None;
        }
        let entry = entries.get(usize::try_from(leaf.entry_index).ok()?)?;
        if entry.entry_hash != leaf.entry_hash
            || entry.execution_kind != leaf.execution_kind
            || entry.route != leaf.route
            || entry.dataspace_id != leaf.dataspace_id
        {
            return None;
        }
        if previous.is_some_and(|prior| leaf.entry_index <= prior.entry_index) {
            return None;
        }
        previous = Some(leaf);
    }
    let source_entries_digest =
        fastpq_source_execution_entries_digest_v1(entries, max_executed_entries)?;
    let mut hashing_failed = false;
    let root = MerkleTree::root_from_typed_leaves(leaves.iter().filter_map(|leaf| {
        let hash = fastpq_ordinary_source_statement_leaf_hash_v1(leaf);
        hashing_failed |= hash.is_none();
        hash
    }));
    if hashing_failed {
        return None;
    }
    Some(FastpqOrdinarySourceStatementManifestV1 {
        source,
        executed_entry_count,
        source_entries_digest,
        coverage: FastpqSourceEffectCoverageV1::Complete,
        statement_count,
        statement_root: root
            .map_or_else(fastpq_ordinary_source_statement_empty_root_v1, Hash::from),
    })
}

/// Maximum complete canonical manifest bytes; all fields have fixed bounded shapes.
pub const FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1: usize = 2_048;

/// Check the bounded canonical manifest shape without granting source authority.
///
/// A caller must separately authenticate the complete ordinary write or its proof.
/// Empty statement roots are accepted only with an exact zero statement count.
#[must_use]
pub fn validate_fastpq_ordinary_source_statement_manifest_v1(
    manifest: &FastpqOrdinarySourceStatementManifestV1,
    expected_source: FastpqSourceStatementContextV1,
    max_executed_entries: u32,
    max_statements: u32,
) -> bool {
    manifest.source == expected_source
        && manifest.source.height != 0
        && manifest.executed_entry_count <= max_executed_entries
        && manifest.statement_count <= max_statements
        && manifest.statement_count <= manifest.executed_entry_count
        && (manifest.executed_entry_count != 0
            || Some(manifest.source_entries_digest)
                == fastpq_source_execution_entries_digest_v1(&[], 0))
        && (manifest.statement_count == 0)
            == (manifest.statement_root == fastpq_ordinary_source_statement_empty_root_v1())
}

/// Check a fixed manifest write against a separately authenticated root.
/// This authenticates inclusion relative to that root, not the root's finality.
pub fn verify_fastpq_ordinary_source_statement_manifest_write_v1(
    manifest: &FastpqOrdinarySourceStatementManifestV1,
    expected_source: FastpqSourceStatementContextV1,
    siblings: &[Hash],
    expected_ordinary_writes_root: Hash,
    max_executed_entries: u32,
    max_statements: u32,
) -> bool {
    if !validate_fastpq_ordinary_source_statement_manifest_v1(
        manifest,
        expected_source,
        max_executed_entries,
        max_statements,
    ) || siblings.len() != 256
    {
        return false;
    }
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let Ok(value) =
        norito::core::to_bytes_bounded(manifest, FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1)
    else {
        return false;
    };
    let path = Hash::new(FASTPQ_ORDINARY_SOURCE_STATEMENTS_WITNESS_KEY_V1);
    let value_hash = Hash::new(value);
    let mut preimage = [0_u8; 65];
    preimage[1..33].copy_from_slice(path.as_ref());
    preimage[33..].copy_from_slice(value_hash.as_ref());
    let mut current = Hash::new(preimage);
    preimage[0] = 1;
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = 255 - level;
        let right = path.as_ref()[bit / 8] & (1 << (bit % 8)) != 0;
        let (left, right) = if right {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        preimage[1..33].copy_from_slice(left.as_ref());
        preimage[33..].copy_from_slice(right.as_ref());
        current = Hash::new(preimage);
    }
    current == expected_ordinary_writes_root
}

/// Check one expected source statement against a caller-authenticated manifest.
///
/// Both `expected` and `manifest` require independently authenticated provenance.
/// A successful membership check by itself grants no authority. Raw decode must
/// apply an enclosing Norito budget before constructing these in-memory values.
pub fn verify_fastpq_ordinary_source_statement_membership_v1(
    leaf: &FastpqOrdinarySourceStatementLeafV1,
    expected: &FastpqOrdinarySourceStatementLeafV1,
    manifest: &FastpqOrdinarySourceStatementManifestV1,
    proof: &MerkleProof<FastpqOrdinarySourceStatementLeafV1>,
    max_executed_entries: u32,
    max_statements: u32,
) -> bool {
    if manifest.coverage != FastpqSourceEffectCoverageV1::Complete
        || leaf != expected
        || leaf.source != manifest.source
        || manifest.source.height == 0
        || manifest.executed_entry_count > max_executed_entries
        || manifest.statement_count > max_statements
        || manifest.statement_count > manifest.executed_entry_count
        || leaf.entry_index >= manifest.executed_entry_count
        || leaf.effect_count == 0
        || leaf.statement_index >= manifest.statement_count
        || proof.leaf_index() != leaf.statement_index
        || proof.audit_path().len() > 32
    {
        return false;
    }
    let Some(count) = NonZeroU64::new(u64::from(manifest.statement_count)) else {
        return false;
    };
    let root = HashOf::<MerkleTree<FastpqOrdinarySourceStatementLeafV1>>::from_untyped_unchecked(
        manifest.statement_root,
    );
    let Some(leaf_hash) = fastpq_ordinary_source_statement_leaf_hash_v1(leaf) else {
        return false;
    };
    proof.verify(&leaf_hash, &MerkleTreeCommitment::new(root, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entries(
        count: u32,
        leaves: &[FastpqOrdinarySourceStatementLeafV1],
    ) -> Vec<FastpqSourceExecutionEntryV1> {
        (0..count)
            .map(|index| {
                let leaf = leaves.iter().find(|leaf| leaf.entry_index == index);
                FastpqSourceExecutionEntryV1 {
                    entry_hash: leaf
                        .map_or_else(|| Hash::new(index.to_le_bytes()), |leaf| leaf.entry_hash),
                    execution_kind: leaf
                        .map_or(FastpqSourceExecutionKindV1::ExecutionCall, |leaf| {
                            leaf.execution_kind
                        }),
                    route: leaf.map_or(FastpqSourceRouteV1::Unrouted, |leaf| leaf.route),
                    dataspace_id: leaf.map_or(DataSpaceId::UNIVERSAL, |leaf| leaf.dataspace_id),
                }
            })
            .collect()
    }

    fn build_test_manifest(
        source: FastpqSourceStatementContextV1,
        count: u32,
        leaves: &[FastpqOrdinarySourceStatementLeafV1],
        max_entries: u32,
        max_statements: u32,
    ) -> Option<FastpqOrdinarySourceStatementManifestV1> {
        build_fastpq_ordinary_source_statement_manifest_v1(
            source,
            &test_entries(count, leaves),
            leaves,
            max_entries,
            max_statements,
        )
    }

    fn network(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new([seed])))
    }

    fn leaves() -> Vec<FastpqOrdinarySourceStatementLeafV1> {
        (0..3)
            .map(|i| FastpqOrdinarySourceStatementLeafV1 {
                source: FastpqSourceStatementContextV1 {
                    network_id: network(7),
                    height: 19,
                },
                statement_index: i,
                entry_index: i * 2,
                effect_count: i + 2,
                entry_hash: Hash::new([u8::try_from(i).expect("fixture value fits u8")]),
                execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
                route: FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                    lane_id: LaneId::new(2),
                    lane_incarnation: Hash::new(b"source lane incarnation"),
                }),
                dataspace_id: DataSpaceId::new(4),
                effects_digest: [u8::try_from(i).expect("fixture value fits u8") + 9; 32],
                slot: 19_000_000,
                perm_root: Hash::new(b"original permission context").into(),
                tx_set_hash: Hash::new(b"original ordered transaction wires").into(),
            })
            .collect()
    }

    #[test]
    fn empty_manifest_shape_preserves_exact_root_inventory_and_bounds() {
        let source = leaves()[0].source;
        let empty = build_test_manifest(source, 0, &[], 0, 0).unwrap();
        assert!(validate_fastpq_ordinary_source_statement_manifest_v1(
            &empty, source, 0, 0
        ));
        let entries_without_effects = build_test_manifest(source, 2, &[], 2, 0).unwrap();
        assert!(validate_fastpq_ordinary_source_statement_manifest_v1(
            &entries_without_effects,
            source,
            2,
            0
        ));
        assert!(!validate_fastpq_ordinary_source_statement_manifest_v1(
            &entries_without_effects,
            source,
            1,
            0
        ));
        for mutation in 0..4 {
            let mut invalid = empty;
            match mutation {
                0 => invalid.statement_root = Hash::new(b"forged empty root"),
                1 => invalid.source_entries_digest = Hash::new(b"forged empty inventory"),
                2 => invalid.statement_count = 1,
                _ => invalid.source.height = 0,
            }
            assert!(!validate_fastpq_ordinary_source_statement_manifest_v1(
                &invalid, source, 2, 2
            ));
        }
    }

    #[test]
    fn ordinary_manifest_keeps_ragged_geometry_and_entry_gaps() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        assert_eq!(manifest.statement_root, Hash::from(tree.root().unwrap()));
        assert_eq!(manifest.statement_count, 3);
        for leaf in &leaves {
            let proof = tree.get_proof(leaf.statement_index).unwrap();
            assert!(verify_fastpq_ordinary_source_statement_membership_v1(
                leaf, leaf, &manifest, &proof, 5, 5
            ));
        }
        assert!(build_test_manifest(leaves[0].source, 5, &leaves, 4, 4).is_none());
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[0],
            &leaves[0],
            &manifest,
            &tree.get_proof(0).unwrap(),
            4,
            4
        ));
    }

    #[test]
    fn ordinary_manifest_binds_one_complete_nonempty_bundle_per_entry() {
        let base = leaves()[0];
        let entries = test_entries(1, &[base]);
        // Bundle cardinality is independent of the leaf count, including its u32 boundary.
        for effect_count in [1, 3, u32::MAX] {
            let leaf = FastpqOrdinarySourceStatementLeafV1 {
                effect_count,
                ..base
            };
            let manifest = build_fastpq_ordinary_source_statement_manifest_v1(
                base.source,
                &entries,
                &[leaf],
                1,
                1,
            )
            .unwrap();
            assert_eq!(
                (manifest.executed_entry_count, manifest.statement_count),
                (1, 1)
            );
            let tree: MerkleTree<_> =
                [fastpq_ordinary_source_statement_leaf_hash_v1(&leaf).unwrap()]
                    .into_iter()
                    .collect();
            let proof = tree.get_proof(0).unwrap();
            assert!(verify_fastpq_ordinary_source_statement_membership_v1(
                &leaf, &leaf, &manifest, &proof, 1, 1,
            ));
            assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                &leaf, &leaf, &manifest, &proof, 1, 0,
            ));
            assert!(
                build_fastpq_ordinary_source_statement_manifest_v1(
                    base.source,
                    &entries,
                    &[leaf],
                    1,
                    0,
                )
                .is_none()
            );
            // The expected leaf and Merkle commitment independently bind bundle cardinality.
            for changed_count in [0, if effect_count == 1 { 2 } else { 1 }] {
                let changed = FastpqOrdinarySourceStatementLeafV1 {
                    effect_count: changed_count,
                    ..leaf
                };
                assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                    &changed, &leaf, &manifest, &proof, 1, 1,
                ));
                assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                    &changed, &changed, &manifest, &proof, 1, 1,
                ));
            }
        }
    }

    #[test]
    fn ordinary_manifest_rejects_duplicate_and_reordered_complete_entry_bundles() {
        let originals = leaves();
        let entries = test_entries(5, &originals);
        assert!(
            build_fastpq_ordinary_source_statement_manifest_v1(
                originals[0].source,
                &entries,
                &originals,
                5,
                3,
            )
            .is_some()
        );
        for mutation in 0..4 {
            let mut changed = originals.clone();
            match mutation {
                0 => changed[1] = changed[0],
                1 => changed.swap(0, 1),
                2 => changed.swap(1, 2),
                3 => changed[1].effect_count = 0,
                _ => unreachable!(),
            }
            // Sequential statement positions cannot hide a duplicate or reordered entry.
            for (index, leaf) in changed.iter_mut().enumerate() {
                leaf.statement_index = u32::try_from(index).expect("fixture value fits u32");
            }
            assert!(
                build_fastpq_ordinary_source_statement_manifest_v1(
                    originals[0].source,
                    &entries,
                    &changed,
                    5,
                    3,
                )
                .is_none(),
                "mutation {mutation}",
            );
        }
    }

    #[test]
    fn ordinary_membership_rejects_empty_bundles_even_with_matching_root() {
        let base = leaves()[0];
        for index in [0, 2] {
            let mut leaves = leaves();
            leaves[index].effect_count = 0;
            let entries = test_entries(5, &leaves);
            assert!(
                build_fastpq_ordinary_source_statement_manifest_v1(
                    base.source,
                    &entries,
                    &leaves,
                    5,
                    3,
                )
                .is_none()
            );
            let tree: MerkleTree<_> = leaves
                .iter()
                .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
                .collect();
            let manifest = FastpqOrdinarySourceStatementManifestV1 {
                source: base.source,
                executed_entry_count: 5,
                source_entries_digest: fastpq_source_execution_entries_digest_v1(&entries, 5)
                    .unwrap(),
                coverage: FastpqSourceEffectCoverageV1::Complete,
                statement_count: 3,
                statement_root: Hash::from(tree.root().unwrap()),
            };
            assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                &leaves[index],
                &leaves[index],
                &manifest,
                &tree
                    .get_proof(u32::try_from(index).expect("fixture value fits u32"))
                    .unwrap(),
                5,
                3,
            ));
        }
    }

    #[test]
    fn source_leaf_rejects_exact_per_transcript_layout_under_same_nominal_identity() {
        // Encoding-only hostile wire fixture: the previous per-transcript layout
        // has no runtime decoder, adapter or alternative accepted V1 representation.
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::iroha_data_model::PerTranscriptLeaf",
            frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1"
        )]
        struct PerTranscriptLeaf {
            source: FastpqSourceStatementContextV1,
            statement_index: u32,
            entry_index: u32,
            transcript_index: u32,
            entry_transcript_count: u32,
            entry_hash: Hash,
            execution_kind: FastpqSourceExecutionKindV1,
            route: FastpqSourceRouteV1,
            dataspace_id: DataSpaceId,
            statement_digest: [u8; 32],
        }
        assert_eq!(
            norito::schema::identity::frame_hash::<PerTranscriptLeaf>(),
            norito::schema::identity::frame_hash::<FastpqOrdinarySourceStatementLeafV1>(),
        );
        let leaf = leaves()[0];
        for transcript_index in 0..3 {
            let previous = PerTranscriptLeaf {
                source: leaf.source,
                statement_index: transcript_index,
                entry_index: leaf.entry_index,
                transcript_index,
                entry_transcript_count: 3,
                entry_hash: leaf.entry_hash,
                execution_kind: leaf.execution_kind,
                route: leaf.route,
                dataspace_id: leaf.dataspace_id,
                statement_digest: leaf.effects_digest,
            };
            let frame = norito::encode_canonical(&previous).unwrap();
            assert!(
                norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&frame).is_err()
            );
        }
    }

    #[test]
    fn source_leaf_rejects_pre_occurrence_layout_under_same_nominal_identity() {
        #[derive(NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::iroha_data_model::EntryLeaf",
            frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1"
        )]
        struct EntryLeaf {
            source: FastpqSourceStatementContextV1,
            statement_index: u32,
            entry_index: u32,
            entry_hash: Hash,
            execution_kind: FastpqSourceExecutionKindV1,
            route: FastpqSourceRouteV1,
            dataspace_id: DataSpaceId,
            statement_digest: [u8; 32],
        }
        let leaf = leaves()[0];
        let previous = EntryLeaf {
            source: leaf.source,
            statement_index: leaf.statement_index,
            entry_index: leaf.entry_index,
            entry_hash: leaf.entry_hash,
            execution_kind: leaf.execution_kind,
            route: leaf.route,
            dataspace_id: leaf.dataspace_id,
            statement_digest: leaf.effects_digest,
        };
        assert_eq!(
            norito::schema::identity::frame_hash::<EntryLeaf>(),
            norito::schema::identity::frame_hash::<FastpqOrdinarySourceStatementLeafV1>()
        );
        let frame = norito::encode_canonical(&previous).unwrap();
        assert!(norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&frame).is_err());
    }

    #[test]
    fn ordinary_manifest_rejects_reordered_duplicate_missing_and_cross_source_positions() {
        let originals = leaves();
        for mutation in 0..6 {
            let mut changed = originals.clone();
            match mutation {
                0 => changed.swap(0, 1),
                1 => changed[1].entry_index = changed[0].entry_index,
                2 => changed[1].statement_index = 2,
                3 => changed[1].source.height += 1,
                4 => changed[1].source.network_id = network(8),
                5 => changed[2].entry_index = 5,
                _ => unreachable!(),
            }
            assert!(
                build_test_manifest(originals[0].source, 5, &changed, 5, 5).is_none(),
                "mutation {mutation}"
            );
        }
        assert!(build_test_manifest(originals[0].source, 2, &originals, 5, 5).is_none());
    }

    #[test]
    fn ordinary_membership_rejects_every_leaf_context_substitution() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        let proof = tree.get_proof(0).unwrap();
        let FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
            lane_id,
            lane_incarnation,
        }) = leaves[0].route
        else {
            unreachable!()
        };
        for mutation in 0..15 {
            let mut changed = leaves[0];
            match mutation {
                0 => changed.source.network_id = network(8),
                1 => changed.source.height += 1,
                2 => changed.statement_index += 1,
                3 => changed.entry_index += 1,
                4 => changed.entry_hash = Hash::new(b"different entry"),
                5 => {
                    changed.route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                        lane_id: LaneId::new(3),
                        lane_incarnation,
                    })
                }
                6 => {
                    changed.route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                        lane_id,
                        lane_incarnation: Hash::new(b"another lane incarnation"),
                    })
                }
                7 => changed.dataspace_id = DataSpaceId::new(5),
                8 => changed.effects_digest[0] ^= 1,
                9 => changed.route = FastpqSourceRouteV1::Unrouted,
                10 => changed.execution_kind = FastpqSourceExecutionKindV1::ProtocolPurpose,
                11 => changed.effect_count += 1,
                12 => changed.slot += 1,
                13 => changed.perm_root[0] ^= 1,
                14 => changed.tx_set_hash[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                !verify_fastpq_ordinary_source_statement_membership_v1(
                    &changed, &leaves[0], &manifest, &proof, 5, 5
                ),
                "expected context {mutation}"
            );
            assert!(
                !verify_fastpq_ordinary_source_statement_membership_v1(
                    &changed, &changed, &manifest, &proof, 5, 5
                ),
                "Merkle context {mutation}"
            );
        }
    }

    #[test]
    fn ordinary_membership_rejects_count_index_root_and_padding_substitutions() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        let proof = tree.get_proof(2).unwrap();
        for count in [0, 1, 2, 4, 6] {
            let mut changed = manifest;
            changed.statement_count = count;
            assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                &leaves[2], &leaves[2], &changed, &proof, 6, 6
            ));
        }
        let mut impossible = manifest;
        impossible.executed_entry_count = 2;
        // The opening at entry zero remains locally in range, but three distinct
        // entry bundles cannot belong to a complete inventory of only two entries.
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[0],
            &leaves[0],
            &impossible,
            &tree.get_proof(0).unwrap(),
            5,
            5,
        ));
        let mut changed = manifest;
        changed.statement_root = fastpq_ordinary_source_statement_empty_root_v1();
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[2], &leaves[2], &changed, &proof, 5, 5
        ));
        let mut path = proof.audit_path().to_vec();
        assert!(path[0].is_none());
        path[0] = Some(fastpq_ordinary_source_statement_leaf_hash_v1(&leaves[2]).unwrap());
        let filled_padding = MerkleProof::from_audit_path(2, path);
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[2],
            &leaves[2],
            &manifest,
            &filled_padding,
            5,
            5
        ));
        let wrong_position = MerkleProof::from_audit_path(0, proof.audit_path().to_vec());
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[2],
            &leaves[2],
            &manifest,
            &wrong_position,
            5,
            5
        ));
        let too_deep = MerkleProof::from_audit_path(2, vec![None; 33]);
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaves[2], &leaves[2], &manifest, &too_deep, 5, 5
        ));
    }

    #[test]
    fn ordinary_empty_manifest_is_explicit_and_has_no_membership() {
        let leaf = leaves().remove(0);
        let empty = build_test_manifest(leaf.source, 5, &[], 5, 5).unwrap();
        assert_eq!(empty.statement_count, 0);
        assert_eq!(
            empty.statement_root,
            fastpq_ordinary_source_statement_empty_root_v1()
        );
        assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
            &leaf,
            &leaf,
            &empty,
            &MerkleProof::from_audit_path(0, vec![]),
            5,
            5
        ));
        let zero_height = FastpqSourceStatementContextV1 {
            height: 0,
            ..leaf.source
        };
        assert!(build_test_manifest(zero_height, 5, &[], 5, 5).is_none());
    }

    #[test]
    fn ordinary_membership_binds_incarnation_bytes_beyond_a_u64_prefix() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        let proof = tree.get_proof(0).unwrap();
        let FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
            lane_id,
            lane_incarnation,
        }) = leaves[0].route
        else {
            unreachable!()
        };
        for byte in 8..Hash::LENGTH {
            let mut changed = leaves[0];
            let mut incarnation = *lane_incarnation.as_ref();
            incarnation[byte] ^= 0x80;
            changed.route = FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id,
                lane_incarnation: Hash::prehashed(incarnation),
            });
            assert_eq!(&incarnation[..8], &lane_incarnation.as_ref()[..8]);
            assert!(
                !verify_fastpq_ordinary_source_statement_membership_v1(
                    &changed, &changed, &manifest, &proof, 5, 5
                ),
                "incarnation byte {byte}"
            );
        }
    }

    #[test]
    fn ordinary_opening_codec_roundtrips_without_claiming_valid_inclusion() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        let opening = FastpqOrdinarySourceStatementOpeningV1 {
            manifest,
            leaf: leaves[1],
            membership: tree.get_proof(1).unwrap(),
            manifest_siblings: vec![Hash::new([]); 256],
        };
        let limits = norito::DecodeLimits::new(1_024, 32 * 1_024, 64 * 1_024, 512 * 1_024, 32);
        let frame = norito::encode_canonical(&opening).unwrap();
        let decoded =
            decode_fastpq_ordinary_source_statement_opening_v1(&frame, frame.len(), limits)
                .unwrap();
        assert_eq!(decoded, opening);
        assert!(!verify_fastpq_ordinary_source_statement_opening_v1(
            &decoded,
            &opening.leaf,
            Hash::new(b"unrelated root"),
            5,
            5
        ));
        assert!(
            decode_fastpq_ordinary_source_statement_opening_v1(&frame, frame.len() - 1, limits)
                .is_err()
        );
    }

    #[test]
    fn ordinary_manifest_nominal_frames_roundtrip_and_remain_distinct() {
        let leaves = leaves();
        let manifest = build_test_manifest(leaves[0].source, 5, &leaves, 5, 5).unwrap();
        let encoded = norito::encode_canonical(&manifest).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&encoded).unwrap(),
            manifest
        );
        let leaf = norito::encode_canonical(&leaves[0]).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&leaf).unwrap(),
            leaves[0]
        );
        assert!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&leaf).is_err()
        );
        assert!(norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&encoded).is_err());
        let context = norito::encode_canonical(&leaves[0].source).unwrap();
        assert_eq!(
            norito::decode_canonical::<FastpqSourceStatementContextV1>(&context).unwrap(),
            leaves[0].source
        );
    }
    #[test]
    fn ordinary_leaf_hash_binds_nominal_frame_and_ignores_ambient_layout() {
        let leaf = leaves().remove(0);
        let frame = norito::encode_canonical(&leaf).unwrap();
        assert!(frame.len() < 512);
        let expected = HashOf::from_untyped_unchecked(Hash::new(&frame));
        assert_eq!(
            fastpq_ordinary_source_statement_leaf_hash_v1(&leaf),
            Some(expected)
        );
        assert_ne!(
            fastpq_ordinary_source_statement_leaf_hash_v1(&leaf),
            Some(HashOf::new(&leaf))
        );
        for flags in (u8::MIN..=u8::MAX).filter(|&f| norito::core::validate_header_flags(f).is_ok())
        {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                fastpq_ordinary_source_statement_leaf_hash_v1(&leaf),
                Some(expected)
            );
            assert_eq!(norito::core::effective_decode_flags(), Some(flags));
        }
    }

    #[test]
    fn source_kind_and_route_roundtrip_and_bind_without_sentinel_lanes() {
        let base = leaves()[0];
        let routes = [
            FastpqSourceRouteV1::Unrouted,
            FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::SINGLE,
                lane_incarnation: Hash::new(b"active incarnation"),
            }),
            // Even a zero-derived marked hash is a lane claim, distinct from explicit absence.
            FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LaneId::SINGLE,
                lane_incarnation: Hash::prehashed([0; 32]),
            }),
        ];
        let mut cases = Vec::new();
        for execution_kind in [
            FastpqSourceExecutionKindV1::ExecutionCall,
            FastpqSourceExecutionKindV1::ProtocolPurpose,
        ] {
            let kind_frame = norito::encode_canonical(&execution_kind).unwrap();
            assert_eq!(
                norito::decode_canonical::<FastpqSourceExecutionKindV1>(&kind_frame).unwrap(),
                execution_kind
            );
            for route in routes {
                if let FastpqSourceRouteV1::Lane(lane) = route {
                    let lane_frame = norito::encode_canonical(&lane).unwrap();
                    assert_eq!(
                        norito::decode_canonical::<FastpqSourceLaneV1>(&lane_frame).unwrap(),
                        lane
                    );
                    assert!(norito::decode_canonical::<FastpqSourceRouteV1>(&lane_frame).is_err());
                }
                let route_frame = norito::encode_canonical(&route).unwrap();
                assert_eq!(
                    norito::decode_canonical::<FastpqSourceRouteV1>(&route_frame).unwrap(),
                    route
                );
                assert!(
                    norito::decode_canonical::<FastpqSourceExecutionKindV1>(&route_frame).is_err()
                );
                let leaf = FastpqOrdinarySourceStatementLeafV1 {
                    execution_kind,
                    route,
                    ..base
                };
                let frame = norito::encode_canonical(&leaf).unwrap();
                assert_eq!(
                    norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&frame)
                        .unwrap(),
                    leaf
                );
                let manifest = build_test_manifest(leaf.source, 1, &[leaf], 1, 1).unwrap();
                let tree: MerkleTree<_> =
                    [fastpq_ordinary_source_statement_leaf_hash_v1(&leaf).unwrap()]
                        .into_iter()
                        .collect();
                let proof = tree.get_proof(0).unwrap();
                assert!(verify_fastpq_ordinary_source_statement_membership_v1(
                    &leaf, &leaf, &manifest, &proof, 1, 1
                ));
                cases.push((leaf, frame, manifest, proof));
            }
        }
        for (index, (leaf, frame, manifest, proof)) in cases.iter().enumerate() {
            for (other_index, (other, other_frame, other_manifest, _)) in cases.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                assert_eq!(leaf.effects_digest, other.effects_digest);
                assert_ne!(frame, other_frame);
                assert_ne!(manifest.statement_root, other_manifest.statement_root);
                assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                    other, leaf, manifest, proof, 1, 1
                ));
                assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                    other, other, manifest, proof, 1, 1
                ));
            }
        }
    }

    #[test]
    fn source_leaf_rejects_the_unqualified_flat_lane_prototype_layout() {
        #[derive(Clone, Copy, NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(
            name = "test::iroha_data_model::FlatPrototypeLeaf",
            frame = "iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1"
        )]
        struct FlatPrototypeLeaf {
            source: FastpqSourceStatementContextV1,
            statement_index: u32,
            entry_index: u32,
            entry_hash: Hash,
            lane_id: LaneId,
            lane_incarnation: Hash,
            dataspace_id: DataSpaceId,
            statement_digest: [u8; 32],
        }
        assert_eq!(
            norito::schema::identity::frame_hash::<FlatPrototypeLeaf>(),
            norito::schema::identity::frame_hash::<FastpqOrdinarySourceStatementLeafV1>(),
            "test must exercise layout rejection even under the same unqualified nominal identity"
        );
        let leaf = leaves()[0];
        for lane_id in [LaneId::SINGLE, LaneId::new(1), LaneId::new(2)] {
            let old = FlatPrototypeLeaf {
                source: leaf.source,
                statement_index: leaf.statement_index,
                entry_index: leaf.entry_index,
                entry_hash: leaf.entry_hash,
                lane_id,
                lane_incarnation: Hash::new(b"source lane incarnation"),
                dataspace_id: leaf.dataspace_id,
                statement_digest: leaf.effects_digest,
            };
            let frame = norito::encode_canonical(&old).unwrap();
            assert!(
                norito::decode_canonical::<FastpqOrdinarySourceStatementLeafV1>(&frame).is_err()
            );
        }
    }

    #[test]
    fn ordinary_membership_entry_range_is_half_open_without_overflow() {
        let baseline = leaves()[0];
        let baseline_manifest = build_test_manifest(baseline.source, 1, &[baseline], 1, 1).unwrap();
        for (count, index, expected) in [
            (0, 0, false),
            (1, 0, true),
            (1, 1, false),
            (u32::MAX, u32::MAX - 1, true),
            (u32::MAX, u32::MAX, false),
        ] {
            let mut leaf = baseline;
            leaf.entry_index = index;
            let tree: MerkleTree<_> =
                [fastpq_ordinary_source_statement_leaf_hash_v1(&leaf).unwrap()]
                    .into_iter()
                    .collect();
            let mut manifest = baseline_manifest;
            // This verifier receives an already authenticated entry commitment; build
            // the actual leaf root independently to isolate its index/count boundary.
            manifest.executed_entry_count = count;
            manifest.statement_root = Hash::from(tree.root().unwrap());
            assert_eq!(
                verify_fastpq_ordinary_source_statement_membership_v1(
                    &leaf,
                    &leaf,
                    &manifest,
                    &tree.get_proof(0).unwrap(),
                    u32::MAX,
                    1,
                ),
                expected,
                "entry {index} of {count}"
            );
        }
    }

    #[test]
    fn streamed_source_and_leaf_hashes_retain_exact_owned_canonical_preimages() {
        let leaves = leaves();
        let entries = test_entries(5, &leaves);
        let expected = Hash::new_from_writer(|writer| {
            writer.write_all(b"iroha:fastpq:source-execution-entries:v1\0")?;
            writer.write_all(&5u32.to_le_bytes())?;
            for entry in &entries {
                let frame = norito::encode_canonical(entry).unwrap();
                assert!(frame.len() <= FASTPQ_SOURCE_EXECUTION_ENTRY_MAX_BYTES_V1);
                writer.write_all(&u32::try_from(frame.len()).unwrap().to_le_bytes())?;
                writer.write_all(&frame)?;
            }
            Ok(())
        })
        .unwrap();
        for flags in [0, norito::core::default_encode_flags()] {
            let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                fastpq_source_execution_entries_digest_v1(&entries, 5),
                Some(expected)
            );
            for leaf in &leaves {
                assert_eq!(
                    Hash::from(fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap()),
                    Hash::new(norito::encode_canonical(leaf).unwrap())
                );
            }
        }
        assert!(fastpq_source_execution_entries_digest_v1(&entries, 4).is_none());
    }

    #[test]
    fn unsupported_quantity_coverage_roundtrips_but_refuses_proof_membership() {
        let leaves = leaves();
        let complete = build_test_manifest(leaves[0].source, 5, &leaves, 5, 3).unwrap();
        let unsupported = FastpqOrdinarySourceStatementManifestV1 {
            coverage: FastpqSourceEffectCoverageV1::Unsupported,
            ..complete
        };
        let complete_bytes = norito::encode_canonical(&complete).unwrap();
        let unsupported_bytes = norito::encode_canonical(&unsupported).unwrap();
        assert_ne!(complete_bytes, unsupported_bytes);
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&complete_bytes)
                .unwrap(),
            complete
        );
        assert_eq!(
            norito::decode_canonical::<FastpqOrdinarySourceStatementManifestV1>(&unsupported_bytes)
                .unwrap(),
            unsupported
        );
        let tree: MerkleTree<_> = leaves
            .iter()
            .map(|leaf| fastpq_ordinary_source_statement_leaf_hash_v1(leaf).unwrap())
            .collect();
        for leaf in &leaves {
            let proof = tree.get_proof(leaf.statement_index).unwrap();
            assert!(verify_fastpq_ordinary_source_statement_membership_v1(
                leaf, leaf, &complete, &proof, 5, 3
            ));
            assert!(!verify_fastpq_ordinary_source_statement_membership_v1(
                leaf,
                leaf,
                &unsupported,
                &proof,
                5,
                3
            ));
        }
    }
}

#[cfg(test)]
mod source_entries_tests;

#[cfg(test)]
mod captured_cutover_identity_tests {
    fn check<T>(nominal: &str, frame: &str, hash: &str)
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        assert_eq!(T::nominal_name(), nominal);
        assert_eq!(T::frame_name(), frame);
        assert_eq!(
            hex::encode(norito::schema::identity::frame_hash::<T>()),
            hash
        );
    }

    #[test]
    fn captured_owner_identities() {
        check::<super::FastpqSourceStatementContextV1>(
            "iroha_data_model::fastpq::source_statement::FastpqSourceStatementContextV1",
            "iroha_data_model::fastpq::FastpqSourceStatementContextV1",
            "7e48033109e7e361a873c9fbbd003354",
        );
        check::<super::FastpqSourceLaneV1>(
            "iroha_data_model::fastpq::source_statement::FastpqSourceLaneV1",
            "iroha_data_model::fastpq::FastpqSourceLaneV1",
            "f55338511b9c06432bb8d9de3f62b265",
        );
        check::<super::FastpqSourceRouteV1>(
            "iroha_data_model::fastpq::source_statement::FastpqSourceRouteV1",
            "iroha_data_model::fastpq::FastpqSourceRouteV1",
            "d2484a1c17621b1cfd32c6b908989781",
        );
        check::<super::FastpqSourceExecutionKindV1>(
            "iroha_data_model::fastpq::source_statement::FastpqSourceExecutionKindV1",
            "iroha_data_model::fastpq::FastpqSourceExecutionKindV1",
            "179692754ca72583f022f29872cdf989",
        );
        check::<super::FastpqSourceExecutionEntryV1>(
            "iroha_data_model::fastpq::source_statement::FastpqSourceExecutionEntryV1",
            "iroha_data_model::fastpq::FastpqSourceExecutionEntryV1",
            "54097bbce045c968a8bb8241cd3a69ef",
        );
        check::<super::FastpqOrdinarySourceStatementLeafV1>(
            "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementLeafV1",
            "iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1",
            "f926b1a18ce1cdba26f4d6bd6943567f",
        );
        check::<super::FastpqOrdinarySourceStatementManifestV1>(
            "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementManifestV1",
            "iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1",
            "8c84bc09cdb24bd972f55d4a2349d6f1",
        );
        check::<super::FastpqOrdinarySourceStatementOpeningV1>(
            "iroha_data_model::fastpq::source_statement::FastpqOrdinarySourceStatementOpeningV1",
            "iroha_data_model::fastpq::FastpqOrdinarySourceStatementOpeningV1",
            "d4dc364d9003f8bf36f103ba592121dd",
        );
    }
}
