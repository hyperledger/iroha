use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{
    da::types::{BlobDigest, RetentionPolicy, StorageTicketId},
    sorafs::pin_registry::ManifestDigest,
};
use iroha_crypto::{Hash, HashOf, Signature};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    to_bytes,
};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Last completed admission/fill milestone for one original DA source.
///
/// Partial physical allocations remain in their original slots at the current
/// milestone. Advancing never releases a charge or skips a refused allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreparationPhase {
    Unadmitted,
    MetadataAdmitted,
    Planned,
    PayloadAdmitted,
    Ready,
}

/// Proof scheme used to authenticate DA commitments.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    Default,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "type", content = "value", decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaProofScheme")]
pub enum DaProofScheme {
    /// Merkle proof over SHA-256 chunk digests.
    #[default]
    MerkleSha256,
}
/// Policy snapshot describing the proof scheme expected for a lane.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields, decode_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaProofPolicy")]
pub struct DaProofPolicy {
    /// Numeric lane identifier.
    pub lane_id: LaneId,
    /// Dataspace identifier associated with the lane.
    pub dataspace_id: DataSpaceId,
    /// Human-readable lane alias.
    pub alias: String,
    /// Proof scheme enforced for DA commitments on this lane.
    pub proof_scheme: DaProofScheme,
}
mod proof_policy;
pub use proof_policy::{
    DaProofPolicyBundle, DaProofPolicyCustodyError, PreparedDaProofPolicyBundle,
};

fn hash_policies(policies: &[DaProofPolicy]) -> Hash {
    let bytes = to_bytes(&policies.to_vec())
        .expect("serializing proof policies with Norito must not fail at runtime");
    Hash::new(bytes)
}
impl DaProofScheme {
    /// Returns the canonical string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MerkleSha256 => "merkle_sha256",
        }
    }
}
impl fmt::Display for DaProofScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Error surfaced when parsing [`DaProofScheme`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid DA proof scheme `{0}`")]
pub struct DaProofSchemeParseError(pub String);
impl FromStr for DaProofScheme {
    type Err = DaProofSchemeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "merkle_sha256" => Ok(Self::MerkleSha256),
            other => Err(DaProofSchemeParseError(other.to_string())),
        }
    }
}
/// Canonical DA commitment persisted in Nexus blocks.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields, decode_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentRecord")]
pub struct DaCommitmentRecord {
    /// Lane the blob belongs to.
    pub lane_id: LaneId,
    /// Epoch the blob was scheduled for.
    pub epoch: u64,
    /// Monotonic sequence inside `(lane_id, epoch)`.
    pub sequence: u64,
    /// Client-declared blob identifier.
    pub client_blob_id: BlobDigest,
    /// Canonical manifest digest (BLAKE3 over encoded `DaManifestV1`).
    pub manifest_hash: ManifestDigest,
    /// Proof scheme expected for the target lane.
    pub proof_scheme: DaProofScheme,
    /// Merkle root over chunk digests for the blob.
    pub chunk_root: Hash,
    /// Optional digest covering PDP/PoTR scheduling metadata.
    #[norito(required)]
    pub proof_digest: Option<Hash>,
    /// Retention summary applied to this blob.
    pub retention_class: RetentionClass,
    /// Storage ticket tying the blob to `SoraFS` replication state.
    pub storage_ticket: StorageTicketId,
    /// Signature issued by the Torii DA service key.
    pub acknowledgement_sig: Signature,
}
impl DaCommitmentRecord {
    /// Convenience constructor assembling a record with the default bundle version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: LaneId,
        epoch: u64,
        sequence: u64,
        client_blob_id: BlobDigest,
        manifest_hash: ManifestDigest,
        proof_scheme: DaProofScheme,
        chunk_root: Hash,
        proof_digest: Option<Hash>,
        retention_class: RetentionClass,
        storage_ticket: StorageTicketId,
        acknowledgement_sig: Signature,
    ) -> Self {
        Self {
            lane_id,
            epoch,
            sequence,
            client_blob_id,
            manifest_hash,
            proof_scheme,
            chunk_root,
            proof_digest,
            retention_class,
            storage_ticket,
            acknowledgement_sig,
        }
    }
}
mod commitment_bundle;
pub use commitment_bundle::{
    DaCommitmentBundle, DaCommitmentCustodyError, PreparedDaCommitmentBundle,
};

/// Alias representing the retained policy class recorded on-chain.
pub type RetentionClass = RetentionPolicy;
/// Canonical key identifying a DA commitment across lanes/epochs.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentKey")]
pub struct DaCommitmentKey {
    /// Lane the blob belongs to.
    pub lane_id: LaneId,
    /// Epoch the blob was scheduled for.
    pub epoch: u64,
    /// Monotonic sequence inside `(lane_id, epoch)`.
    pub sequence: u64,
}
impl DaCommitmentKey {
    /// Build a key from an existing commitment record.
    #[must_use]
    pub fn from_record(record: &DaCommitmentRecord) -> Self {
        Self {
            lane_id: record.lane_id,
            epoch: record.epoch,
            sequence: record.sequence,
        }
    }
}
/// Location of a sealed DA commitment inside the blockchain.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentLocation")]
pub struct DaCommitmentLocation {
    /// Height of the block that sealed the commitment.
    pub block_height: u64,
    /// Index within the commitment bundle for that block (0-based).
    pub index_in_bundle: u32,
}
/// Commitment record paired with its on-chain location.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentWithLocation")]
pub struct DaCommitmentWithLocation {
    /// Raw commitment stored on chain.
    pub commitment: DaCommitmentRecord,
    /// Position of this commitment within the chain.
    pub location: DaCommitmentLocation,
}
/// Direction of a sibling inside a binary Merkle tree.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "direction", content = "value")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::da::commitment::MerkleDirection")]
pub enum MerkleDirection {
    /// Sibling hash is on the left.
    Left,
    /// Sibling hash is on the right.
    Right,
}
/// A single hop inside a Merkle proof path.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::da::commitment::MerklePathItem")]
pub struct MerklePathItem {
    /// Hash of the sibling node at this tree level.
    pub sibling: Hash,
    /// Whether the sibling sits to the left or right of the target node.
    pub direction: MerkleDirection,
}
/// Membership proof for a DA commitment inside a block bundle.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    Hash,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::da::commitment::DaCommitmentProof")]
pub struct DaCommitmentProof {
    /// Commitment covered by the proof.
    pub commitment: DaCommitmentRecord,
    /// Position of the commitment inside the block bundle.
    pub location: DaCommitmentLocation,
    /// Header commitment to the tree version, leaf count, and Merkle root.
    pub bundle_hash: HashOf<DaCommitmentBundle>,
    /// Total number of commitments in the bundle.
    pub bundle_len: u32,
    /// Merkle root derived from the ordered commitment list.
    pub root: Hash,
    /// Merkle path connecting the commitment leaf to `root`.
    pub path: Vec<MerklePathItem>,
}
const DA_COMMITMENT_MERKLE_LEAF_DOMAIN_V1: &[u8] = b"iroha:da:commitment-merkle:leaf:v1\0";
const DA_COMMITMENT_MERKLE_INTERNAL_DOMAIN_V1: &[u8] = b"iroha:da:commitment-merkle:internal:v1\0";
const DA_COMMITMENT_MERKLE_COMMITMENT_DOMAIN_V1: &[u8] =
    b"iroha:da:commitment-merkle:commitment:v1\0";
/// Hash a commitment into its domain-separated Merkle leaf value.
#[must_use]
pub fn commitment_leaf_hash(record: &DaCommitmentRecord) -> Hash {
    // Encoding a commitment must be infallible; treat failures as unreachable.
    let bytes = to_bytes(record).expect("DA commitment must encode");
    let mut preimage = Vec::with_capacity(DA_COMMITMENT_MERKLE_LEAF_DOMAIN_V1.len() + bytes.len());
    preimage.extend_from_slice(DA_COMMITMENT_MERKLE_LEAF_DOMAIN_V1);
    preimage.extend_from_slice(&bytes);
    Hash::new(preimage)
}
/// Hash two child nodes into a domain-separated DA commitment Merkle node.
#[must_use]
pub fn commitment_internal_hash(left: &Hash, right: &Hash) -> Hash {
    let mut preimage =
        Vec::with_capacity(DA_COMMITMENT_MERKLE_INTERNAL_DOMAIN_V1.len() + Hash::LENGTH * 2);
    preimage.extend_from_slice(DA_COMMITMENT_MERKLE_INTERNAL_DOMAIN_V1);
    preimage.extend_from_slice(left.as_ref());
    preimage.extend_from_slice(right.as_ref());
    Hash::new(preimage)
}
/// Reconstruct the header commitment for a DA commitment Merkle tree.
#[must_use]
pub fn commitment_merkle_commitment(
    version: u16,
    leaf_count: u32,
    root: &Hash,
) -> HashOf<DaCommitmentBundle> {
    let mut preimage = Vec::with_capacity(
        DA_COMMITMENT_MERKLE_COMMITMENT_DOMAIN_V1.len()
            + core::mem::size_of::<u16>()
            + core::mem::size_of::<u32>()
            + Hash::LENGTH,
    );
    preimage.extend_from_slice(DA_COMMITMENT_MERKLE_COMMITMENT_DOMAIN_V1);
    preimage.extend_from_slice(&version.to_le_bytes());
    preimage.extend_from_slice(&leaf_count.to_le_bytes());
    preimage.extend_from_slice(root.as_ref());
    HashOf::from_untyped_unchecked(Hash::new(preimage))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Hash;
    use norito::codec::{DecodeAll, decode_exact_from_slice, encode_adaptive};
    use std::str::FromStr;
    fn sample_record() -> DaCommitmentRecord {
        DaCommitmentRecord {
            lane_id: LaneId::new(7),
            epoch: 42,
            sequence: 3,
            client_blob_id: BlobDigest::new([0x11; 32]),
            manifest_hash: ManifestDigest::new([0x22; 32]),
            proof_scheme: DaProofScheme::MerkleSha256,
            chunk_root: Hash::prehashed([0x33; 32]),
            proof_digest: Some(Hash::prehashed([0x55; 32])),
            retention_class: RetentionClass::default(),
            storage_ticket: StorageTicketId::new([0x66; 32]),
            acknowledgement_sig: Signature::try_from_bytes(&[0x77; 64])
                .expect("checked data-model DA commitment acknowledgement signature fixture"),
        }
    }
    #[test]
    fn commitment_round_trip() {
        let record = sample_record();
        let bytes = encode_adaptive(&record);
        let decoded = DaCommitmentRecord::decode_all(&mut bytes.as_slice()).expect("decode");
        assert_eq!(record, decoded);
    }

    #[test]

    fn consensus_da_json_requires_exact_current_fields() {
        let record = sample_record();
        let mut missing = norito::json::to_value(&record).expect("serialize DA commitment record");
        missing
            .as_object_mut()
            .expect("DA commitment JSON object")
            .remove("proof_digest");
        assert!(
            norito::json::from_value::<DaCommitmentRecord>(missing).is_err(),
            "the first-release DA commitment must require its nullable proof-digest slot"
        );

        let mut unknown = norito::json::to_value(&record).expect("serialize DA commitment record");
        unknown
            .as_object_mut()
            .expect("DA commitment JSON object")
            .insert("pre_release_field".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<DaCommitmentRecord>(unknown).is_err(),
            "the first-release DA commitment must reject unknown fields"
        );

        let policy = DaProofPolicy {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "default".to_owned(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let mut unknown_policy =
            norito::json::to_value(&policy).expect("serialize DA proof policy");
        unknown_policy
            .as_object_mut()
            .expect("DA proof policy JSON object")
            .insert("pre_release_field".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<DaProofPolicy>(unknown_policy).is_err(),
            "the first-release DA proof policy must reject unknown fields"
        );

        let policy_bundle = DaProofPolicyBundle::new(vec![policy]);
        let mut unknown_policy_bundle =
            norito::json::to_value(&policy_bundle).expect("serialize DA proof-policy bundle");
        unknown_policy_bundle
            .as_object_mut()
            .expect("DA proof-policy bundle JSON object")
            .insert("pre_release_field".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<DaProofPolicyBundle>(unknown_policy_bundle).is_err(),
            "the first-release DA proof-policy bundle must reject unknown fields"
        );

        let commitment_bundle = DaCommitmentBundle::new(vec![record]);
        let mut unknown_commitment_bundle =
            norito::json::to_value(&commitment_bundle).expect("serialize DA commitment bundle");
        unknown_commitment_bundle
            .as_object_mut()
            .expect("DA commitment bundle JSON object")
            .insert("pre_release_field".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<DaCommitmentBundle>(unknown_commitment_bundle).is_err(),
            "the first-release DA commitment bundle must reject unknown fields"
        );
    }

    #[test]
    fn bundle_round_trip() {
        let bundle = DaCommitmentBundle::new(vec![sample_record()]);
        let bytes = encode_adaptive(&bundle);
        let decoded = DaCommitmentBundle::decode_all(&mut bytes.as_slice()).expect("decode");
        assert_eq!(bundle, decoded);
        assert!(!bundle.is_empty());
    }
    #[test]
    fn bundle_new_sorts_commitments_canonically() {
        let mut earlier = sample_record();
        earlier.sequence = 1;
        let later = sample_record();
        let bundle = DaCommitmentBundle::new(vec![later.clone(), earlier.clone()]);
        assert_eq!(bundle.commitments(), vec![earlier, later]);
    }
    #[test]
    fn bundle_new_makes_tree_commitment_independent_of_input_order() {
        let records: Vec<_> = (0..3)
            .map(|idx| {
                let tag = u8::try_from(idx).expect("test index fits in u8");
                let mut record = sample_record();
                record.sequence = idx;
                record.client_blob_id = BlobDigest::new([0x10 + tag; 32]);
                record.manifest_hash = ManifestDigest::new([0x20 + tag; 32]);
                record.storage_ticket = StorageTicketId::new([0x30 + tag; 32]);
                record.acknowledgement_sig = Signature::try_from_bytes(&[0x40 + tag; 64])
                    .expect("checked data-model DA commitment acknowledgement signature fixture");
                record
            })
            .collect();
        let canonical = DaCommitmentBundle::new(records.clone());
        let shuffled = DaCommitmentBundle::new(vec![
            records[2].clone(),
            records[0].clone(),
            records[1].clone(),
        ]);
        assert_eq!(canonical.commitments(), records);
        assert_eq!(shuffled.commitments(), canonical.commitments());
        assert_eq!(shuffled.merkle_root(), canonical.merkle_root());
        assert_eq!(shuffled.merkle_commitment(), canonical.merkle_commitment());
    }
    #[test]
    fn bundle_decode_from_slice_rejects_trailing_bytes() {
        let bundle = DaCommitmentBundle::new(vec![sample_record()]);
        let mut bytes = encode_adaptive(&bundle);
        bytes.push(0);
        let err = decode_exact_from_slice::<DaCommitmentBundle>(&bytes)
            .expect_err("DA commitment bundle slice decoder must reject trailing bytes");
        assert!(matches!(err, norito::core::Error::LengthMismatch));
    }
    #[test]
    fn merkle_root_returns_none_for_empty_bundle() {
        assert!(DaCommitmentBundle::default().merkle_root().is_none());
    }
    #[test]
    fn merkle_root_uses_single_leaf_without_hashing_upwards() {
        let record = sample_record();
        let leaf = commitment_leaf_hash(&record);
        let bundle = DaCommitmentBundle::new(vec![record]);
        assert_eq!(bundle.merkle_root(), Some(leaf));
    }
    #[test]
    fn merkle_root_promotes_last_leaf_on_odd_layers() {
        let mut records = Vec::new();
        // Three leaves -> level 1 has two nodes: hash(0 || 1) and leaf(2).
        for idx in 0..3 {
            let mut record = sample_record();
            record.sequence = idx;
            records.push(record);
        }
        let bundle = DaCommitmentBundle::new(records.clone());
        let leaves: Vec<_> = records.iter().map(commitment_leaf_hash).collect();
        let level1_left = commitment_internal_hash(&leaves[0], &leaves[1]);
        let expected_root = commitment_internal_hash(&level1_left, &leaves[2]);
        assert_eq!(bundle.merkle_root(), Some(expected_root));
    }
    #[test]
    fn merkle_leaf_and_internal_nodes_use_disjoint_hash_domains() {
        let record = sample_record();
        let encoded = to_bytes(&record).expect("encode commitment");
        assert_ne!(commitment_leaf_hash(&record), Hash::new(&encoded));
        let left = Hash::new(b"left");
        let right = Hash::new(b"right");
        let mut untagged = Vec::with_capacity(Hash::LENGTH * 2);
        untagged.extend_from_slice(left.as_ref());
        untagged.extend_from_slice(right.as_ref());
        assert_ne!(commitment_internal_hash(&left, &right), Hash::new(untagged));
    }
    #[test]
    fn merkle_commitment_binds_version_leaf_count_and_root() {
        let root = Hash::new(b"root");
        let baseline = commitment_merkle_commitment(DaCommitmentBundle::VERSION_V1, 3, &root);
        assert_ne!(
            baseline,
            commitment_merkle_commitment(DaCommitmentBundle::VERSION_V1 + 1, 3, &root)
        );
        assert_ne!(
            baseline,
            commitment_merkle_commitment(DaCommitmentBundle::VERSION_V1, 4, &root)
        );
        assert_ne!(
            baseline,
            commitment_merkle_commitment(
                DaCommitmentBundle::VERSION_V1,
                3,
                &Hash::new(b"other-root"),
            )
        );
        assert!(DaCommitmentBundle::default().merkle_commitment().is_none());
    }
    #[test]
    fn proof_scheme_from_str_accepts_only_canonical_merkle_label() {
        assert_eq!(
            DaProofScheme::from_str("merkle_sha256").expect("parse"),
            DaProofScheme::MerkleSha256
        );
        for retired_alias in ["Merkle_Sha256", "merkle-sha256", "merkle"] {
            assert!(
                DaProofScheme::from_str(retired_alias).is_err(),
                "non-canonical proof scheme `{retired_alias}` must fail closed"
            );
        }
    }
    #[test]
    fn proof_scheme_from_str_rejects_unimplemented_kzg() {
        assert!(DaProofScheme::from_str("kzg_bls12_381").is_err());
        assert!(DaProofScheme::from_str("kzg-bls12-381").is_err());
        assert!(DaProofScheme::from_str("kzg").is_err());
    }
    #[test]
    fn proof_scheme_from_str_rejects_unknown() {
        assert!(DaProofScheme::from_str("unknown-scheme").is_err());
    }
    #[test]
    fn proof_policy_bundle_hash_changes_on_drift() {
        let base = DaProofPolicy {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::new(11),
            alias: "lane-a".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let mut switched = base.clone();
        switched.alias = "lane-b".to_string();
        let bundle_a = DaProofPolicyBundle::new(vec![base]);
        let bundle_b = DaProofPolicyBundle::new(vec![switched]);
        assert_ne!(bundle_a.policy_hash(), bundle_b.policy_hash());
    }
    #[test]
    fn proof_policy_bundle_hash_stable_for_same_ordering() {
        let policy_a = DaProofPolicy {
            lane_id: LaneId::new(1),
            dataspace_id: DataSpaceId::new(1),
            alias: "one".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let policy_b = DaProofPolicy {
            lane_id: LaneId::new(2),
            dataspace_id: DataSpaceId::new(2),
            alias: "two".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let first = DaProofPolicyBundle::new(vec![policy_a.clone(), policy_b.clone()]);
        let second = DaProofPolicyBundle::new(vec![policy_a, policy_b]);
        assert_eq!(first.policy_hash(), second.policy_hash());
        assert_eq!(first.version(), DaProofPolicyBundle::VERSION_V1);
    }
}

#[cfg(test)]
mod captured_commitment_schema_tests;
