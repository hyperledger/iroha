//! Lane privacy commitment registry and verification helpers (NX-10).
//!
//! Nexus private lanes currently support only domain-separated Merkle commitments. A proof-system
//! commitment must not be added here until admission can resolve an on-chain verifying key and
//! invoke its real cryptographic verifier.

/// Complete native BLAKE3-256 commitment to the sole first-release privacy catalog.
///
/// The data-model owner retains the exact ordered preimage and strict decoder.
/// Native proof engines consume these same 32 raw bytes as public context;
/// proof-internal hash outputs and parameters remain owned by their engines.
pub const PRIVACY_EXACT12_CATALOG_COMMITMENT_BYTES_V1: [u8; 32] = [
    0x5b, 0xcf, 0x36, 0x6f, 0xb1, 0x8d, 0x2e, 0x43, 0x61, 0x48, 0x6c, 0x01, 0x5d, 0xa5, 0xb4, 0x1a,
    0x3f, 0xb0, 0x0e, 0xdf, 0x05, 0x61, 0x10, 0x42, 0xcc, 0xc4, 0x52, 0x12, 0x0d, 0x17, 0x6e, 0xb0,
];

use crate::{Hash, HashOf, MerkleProof, MerkleTree};
use core::{convert::TryFrom, fmt};
use iroha_schema::IntoSchema;
#[cfg(feature = "json")]
use norito::derive::{JsonDeserialize, JsonSerialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
/// Domain tag used when hashing a raw lane-privacy Merkle leaf.
///
/// The trailing NUL prevents the tag from being a prefix of another protocol label.
const LANE_MERKLE_LEAF_DOMAIN_V1: &[u8] = b"iroha:nexus:lane-privacy:merkle:leaf:v1\x00";
/// Domain tag used when hashing a lane-privacy Merkle internal node.
const LANE_MERKLE_NODE_DOMAIN_V1: &[u8] = b"iroha:nexus:lane-privacy:merkle:node:v1\x00";
/// Result type returned by the privacy commitment helpers.
pub type Result<T, E = PrivacyError> = core::result::Result<T, E>;
/// Identifier assigned to a registered commitment slot.
#[cfg_attr(feature = "json", derive(JsonSerialize, JsonDeserialize))]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::codec::Encode,
    norito::codec::Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::privacy::LaneCommitmentId")]
pub struct LaneCommitmentId(u16);
impl LaneCommitmentId {
    /// Create a new identifier.
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self(id)
    }
    /// Return the numeric representation.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}
impl fmt::Display for LaneCommitmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
/// Canonical commitment schemes supported by Nexus private lanes.
///
/// The first release deliberately exposes only Merkle commitments. A proof-system variant requires
/// a real, on-chain verifying-key-backed verifier before it can join this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentScheme {
    /// Merkle tree root enforcing membership proofs.
    Merkle(MerkleCommitment),
}
/// Runtime witness supplied when validating a commitment.
#[derive(Clone, Debug)]
pub enum PrivacyWitness {
    /// Membership proof for a Merkle commitment.
    Merkle(MerkleWitness),
}
/// High-level commitment descriptor stored in the lane registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanePrivacyCommitment {
    id: LaneCommitmentId,
    scheme: CommitmentScheme,
}
impl LanePrivacyCommitment {
    /// Construct a Merkle-root commitment.
    #[must_use]
    pub const fn merkle(id: LaneCommitmentId, commitment: MerkleCommitment) -> Self {
        Self {
            id,
            scheme: CommitmentScheme::Merkle(commitment),
        }
    }
    /// Return the identifier assigned to this commitment.
    #[must_use]
    pub const fn id(&self) -> LaneCommitmentId {
        self.id
    }
    /// Borrow the embedded commitment scheme.
    #[must_use]
    pub const fn scheme(&self) -> &CommitmentScheme {
        &self.scheme
    }
    /// Verify the provided witness against the stored scheme.
    ///
    /// # Errors
    ///
    /// Returns any verification error raised by the Merkle verifier.
    pub fn verify(&self, witness: PrivacyWitness) -> Result<()> {
        match (&self.scheme, witness) {
            (CommitmentScheme::Merkle(commitment), PrivacyWitness::Merkle(witness)) => {
                commitment.verify(&witness)
            }
        }
    }
}
/// Errors raised when verifying lane commitments.
#[derive(Debug, Error, PartialEq, Eq, Copy, Clone)]
pub enum PrivacyError {
    /// Lane privacy membership proofs must traverse at least one tree edge.
    #[error("lane privacy merkle proof must contain at least one sibling")]
    EmptyMerkleProof,
    /// Lane privacy proofs use complete paths and may not omit siblings.
    #[error("lane privacy merkle proof is missing sibling at level {level}")]
    MissingMerkleSibling {
        /// Zero-based level in the leaf-to-root path.
        level: u8,
    },
    /// Proof depth exceeds the declared Merkle-tree budget.
    #[error("merkle proof depth {actual} exceeds declared limit {declared}")]
    MerkleProofExceedsDepth {
        /// Depth declared when registering the root.
        declared: u8,
        /// Depth observed at runtime.
        actual: u8,
    },
    /// Merkle proof failed verification against the registered root.
    #[error("merkle proof failed to verify against the registered root")]
    InvalidMerkleProof,
}
/// Merkle membership proof bound to a raw 32-byte lane leaf.
///
/// The verifier applies the lane-specific leaf domain before walking the
/// proof. Callers must not pre-hash `leaf`.
#[derive(Clone, Debug)]
pub struct MerkleWitness {
    leaf: [u8; 32],
    proof: MerkleProof<[u8; 32]>,
}
impl MerkleWitness {
    /// Construct a witness from raw leaf bytes and a proof.
    #[must_use]
    pub fn new(leaf: [u8; 32], proof: MerkleProof<[u8; 32]>) -> Self {
        Self { leaf, proof }
    }
    /// Construct a witness from raw leaf bytes and a proof.
    #[must_use]
    pub fn from_leaf_bytes(leaf: [u8; 32], proof: MerkleProof<[u8; 32]>) -> Self {
        Self::new(leaf, proof)
    }
    /// Borrow the raw leaf referenced by this witness.
    #[must_use]
    pub const fn leaf(&self) -> &[u8; 32] {
        &self.leaf
    }
    /// Borrow the Merkle proof.
    #[must_use]
    pub const fn proof(&self) -> &MerkleProof<[u8; 32]> {
        &self.proof
    }
    /// Compute the lane-specific Merkle root implied by this witness.
    ///
    /// Leaves and internal nodes use distinct SHA-256 domains. Paths must be
    /// non-empty and every level must supply a sibling; generic
    /// [`MerkleProof`] semantics remain unchanged for other callers.
    ///
    /// # Errors
    ///
    /// Returns a structural or depth error when the proof is not a valid lane privacy path.
    pub fn implied_root(&self, max_depth: u8) -> Result<HashOf<MerkleTree<[u8; 32]>>> {
        let depth = self.proof.audit_path().len();
        if depth == 0 {
            return Err(PrivacyError::EmptyMerkleProof);
        }
        if depth > usize::from(max_depth) {
            return Err(PrivacyError::MerkleProofExceedsDepth {
                declared: max_depth,
                actual: u8::try_from(depth).unwrap_or(u8::MAX),
            });
        }
        if depth < u32::BITS as usize && u64::from(self.proof.leaf_index()) >= 1_u64 << depth {
            return Err(PrivacyError::InvalidMerkleProof);
        }
        let mut position = self.proof.leaf_index();
        let mut accumulator = lane_merkle_leaf_hash(&self.leaf);
        for (level, sibling) in self.proof.audit_path().iter().enumerate() {
            let sibling = sibling
                .as_ref()
                .ok_or_else(|| PrivacyError::MissingMerkleSibling {
                    level: u8::try_from(level).unwrap_or(u8::MAX),
                })?;
            accumulator = if position & 1 == 0 {
                lane_merkle_node_hash(&accumulator, sibling)
            } else {
                lane_merkle_node_hash(sibling, &accumulator)
            };
            position >>= 1;
        }
        let root: Hash = accumulator.into();
        Ok(HashOf::from_untyped_unchecked(root))
    }
}
/// Metadata recorded for registered Merkle roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleCommitment {
    root: HashOf<MerkleTree<[u8; 32]>>,
    max_depth: u8,
}
impl MerkleCommitment {
    /// Create a new commitment from a canonical lane-specific root hash.
    #[must_use]
    pub const fn new(root: HashOf<MerkleTree<[u8; 32]>>, max_depth: u8) -> Self {
        Self { root, max_depth }
    }
    /// Convert a raw 32-byte root digest into the typed representation.
    #[must_use]
    pub fn from_root_bytes(root: [u8; 32], max_depth: u8) -> Self {
        let hash = Hash::prehashed(root);
        let typed = HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(hash);
        Self::new(typed, max_depth)
    }
    /// Borrow the registered root hash.
    #[must_use]
    pub const fn root(&self) -> &HashOf<MerkleTree<[u8; 32]>> {
        &self.root
    }
    /// Maximum depth allowed for membership proofs.
    #[must_use]
    pub const fn max_depth(&self) -> u8 {
        self.max_depth
    }
    fn verify(&self, witness: &MerkleWitness) -> Result<()> {
        if witness.implied_root(self.max_depth)? == self.root {
            Ok(())
        } else {
            Err(PrivacyError::InvalidMerkleProof)
        }
    }
}
/// Hash a raw lane-privacy leaf using the versioned leaf domain.
#[must_use]
pub fn lane_merkle_leaf_hash(leaf: &[u8; 32]) -> HashOf<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(LANE_MERKLE_LEAF_DOMAIN_V1);
    hasher.update(leaf);
    let digest: [u8; 32] = hasher.finalize().into();
    HashOf::from_untyped_unchecked(Hash::prehashed(digest))
}
/// Hash a lane-privacy internal node using the versioned node domain.
#[must_use]
pub fn lane_merkle_node_hash(
    left: &HashOf<[u8; 32]>,
    right: &HashOf<[u8; 32]>,
) -> HashOf<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(LANE_MERKLE_NODE_DOMAIN_V1);
    hasher.update(left.as_ref());
    hasher.update(right.as_ref());
    let digest: [u8; 32] = hasher.finalize().into();
    HashOf::from_untyped_unchecked(Hash::prehashed(digest))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn witness_with_root(
        leaf: [u8; 32],
        leaf_index: u32,
        path: Vec<[u8; 32]>,
    ) -> (MerkleWitness, HashOf<MerkleTree<[u8; 32]>>) {
        let witness =
            MerkleWitness::new(leaf, MerkleProof::from_audit_path_bytes(leaf_index, path));
        let root = witness
            .implied_root(u8::MAX)
            .expect("well-formed proof must produce a root");
        (witness, root)
    }
    #[test]
    fn merkle_commitment_accepts_valid_proof() {
        let (witness, root) = witness_with_root([0x11; 32], 1, vec![[0x22; 32], [0x33; 32]]);
        let commitment =
            LanePrivacyCommitment::merkle(LaneCommitmentId::new(7), MerkleCommitment::new(root, 8));
        assert!(commitment.verify(PrivacyWitness::Merkle(witness)).is_ok());
    }
    #[test]
    fn merkle_commitment_rejects_empty_path() {
        let witness = MerkleWitness::new(
            [0x11; 32],
            MerkleProof::from_audit_path_bytes(0, Vec::new()),
        );
        let commitment = LanePrivacyCommitment::merkle(
            LaneCommitmentId::new(7),
            MerkleCommitment::from_root_bytes([0x11; 32], 8),
        );
        assert_eq!(
            commitment
                .verify(PrivacyWitness::Merkle(witness))
                .expect_err("empty paths must fail at the verifier"),
            PrivacyError::EmptyMerkleProof
        );
    }
    #[test]
    fn merkle_commitment_rejects_missing_sibling() {
        let witness = MerkleWitness::new([0x11; 32], MerkleProof::from_audit_path(0, vec![None]));
        let commitment = LanePrivacyCommitment::merkle(
            LaneCommitmentId::new(7),
            MerkleCommitment::from_root_bytes([0x11; 32], 8),
        );
        assert_eq!(
            commitment
                .verify(PrivacyWitness::Merkle(witness))
                .expect_err("omitted siblings must fail at the verifier"),
            PrivacyError::MissingMerkleSibling { level: 0 }
        );
    }
    #[test]
    fn merkle_commitment_rejects_out_of_range_leaf_index() {
        let witness = MerkleWitness::new(
            [0x11; 32],
            MerkleProof::from_audit_path_bytes(2, vec![[0x22; 32]]),
        );
        assert_eq!(
            witness
                .implied_root(8)
                .expect_err("one proof level can address only leaves zero and one"),
            PrivacyError::InvalidMerkleProof
        );
    }
    #[test]
    fn merkle_commitment_rejects_excessive_depth() {
        let (witness, root) =
            witness_with_root([0xFF; 32], 0, vec![[0x44; 32], [0x55; 32], [0x66; 32]]);
        let commitment =
            LanePrivacyCommitment::merkle(LaneCommitmentId::new(9), MerkleCommitment::new(root, 2));
        let err = commitment
            .verify(PrivacyWitness::Merkle(witness))
            .expect_err("depth mismatch");
        assert_eq!(
            err,
            PrivacyError::MerkleProofExceedsDepth {
                declared: 2,
                actual: 3
            }
        );
    }
    #[test]
    fn lane_merkle_leaf_and_node_domains_are_distinct() {
        let raw = [0x5A; 32];
        let leaf = lane_merkle_leaf_hash(&raw);
        let node = lane_merkle_node_hash(&leaf, &leaf);
        assert_ne!(
            leaf.as_ref(),
            node.as_ref(),
            "an internal node must not be usable as a leaf"
        );
    }
    #[test]
    fn lane_merkle_hashing_matches_v1_golden_vector() {
        let (witness, root) = witness_with_root([0xAA; 32], 0, vec![[0xBB; 32]]);
        assert_eq!(
            hex::encode(lane_merkle_leaf_hash(witness.leaf()).as_ref()),
            "7b08f69e5888269358d2f3029831ede108d0f7b464449001bcc5f7a64f498447"
        );
        assert_eq!(
            hex::encode(root.as_ref()),
            "175dd23c29dda55ead958e0b1db68811f2108aa9a6f8d2222bec59bd2aed3a09"
        );
    }
}

#[cfg(test)]
mod captured_schema_tests;
