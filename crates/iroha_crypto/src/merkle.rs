//! Merkle tree implementation for light clients to efficiently verify transaction inclusion proofs.
//! This is the canonical Merkle type used across the workspace (node and IVM).
use crate::{Hash, HashOf};
use iroha_schema::{IntoSchema, TypeId};
use norito::codec::{Decode, Encode};
#[cfg(feature = "json")]
use norito::json::{self, JsonDeserialize, JsonSerialize};
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use sha2::{Digest as _, Sha256};
use std::{collections::VecDeque, format, num::NonZeroU64, string::String, vec, vec::Vec};
use thiserror::Error;
mod application_allocation;
#[cfg(test)]
mod borrowed_serialization_tests;
mod proof_siblings;
const COMPACT_MERKLE_PROOF_MAX_DEPTH: u8 = 32;
/// Maximum number of leaves addressable by the canonical `u32` proof index.
const MERKLE_PROOF_MAX_LEAF_COUNT: u64 = 1_u64 << u32::BITS;
/// Maximum number of canonical leaves accepted by the V1 serialized tree.
///
/// Persisted application trees are block-scoped; 65,536 leaves is already far
/// above the practical block envelope while keeping reconstruction memory
/// bounded independently of attacker-selected cached-node counts.
const SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1: usize = 1 << 16;
const MERKLE_HASH_SCHEME_APPLICATION_V1: u8 = 1;
const MERKLE_HASH_SCHEME_SHA256_V1: u8 = 2;
/// Domain tag for canonical application Merkle leaf nodes.
const TAG_MERKLE_LEAF_V1: &[u8] = b"iroha:merkle:leaf:v1\x00";
/// Domain tag for canonical application Merkle internal nodes.
///
/// The trailing NUL prevents concatenation ambiguity with future domain tags.
const TAG_MERKLE_INTERNAL_V1: &[u8] = b"iroha:merkle:internal:v1\x00";
/// Array representation of [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)
/// for verifying elements of type `T`.
///
/// In memory, the hashing scheme is retained alongside nodes cached in breadth-first order. The
/// canonical wire never serializes derived parents or the root: it carries the retained V1
/// hash-scheme discriminant and bounded canonical leaf-node hashes, then deterministically rebuilds
/// the entire cache on decode. Internal nodes may be `None` only for rightmost padding in
/// incomplete trees (where both children are missing). Missing nodes in proofs belong only in
/// `MerkleProof` audit paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, TypeId)]
pub struct MerkleTree<T> {
    hash_scheme: MerkleHashScheme,
    nodes: Vec<Option<HashOf<T>>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MerkleHashScheme {
    ApplicationV1,
    Sha256V1,
}
impl MerkleHashScheme {
    const fn wire_id(self) -> u8 {
        match self {
            Self::ApplicationV1 => MERKLE_HASH_SCHEME_APPLICATION_V1,
            Self::Sha256V1 => MERKLE_HASH_SCHEME_SHA256_V1,
        }
    }
    fn from_wire_id(scheme: u8) -> Result<Self, MerkleError> {
        match scheme {
            MERKLE_HASH_SCHEME_APPLICATION_V1 => Ok(Self::ApplicationV1),
            MERKLE_HASH_SCHEME_SHA256_V1 => Ok(Self::Sha256V1),
            scheme => Err(MerkleError::UnsupportedHashScheme { scheme }),
        }
    }
}
/// Authenticated commitment to a Merkle tree root and its exact leaf count.
///
/// A root alone does not authenticate the proof depth or the geometry of a ragged right edge.
/// Verifiers must use this pair as one indivisible commitment and obtain it from the protocol
/// object that authenticates the tree.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema)]
pub struct MerkleTreeCommitment<T> {
    root: HashOf<MerkleTree<T>>,
    leaf_count: NonZeroU64,
}
impl<T> Clone for MerkleTreeCommitment<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for MerkleTreeCommitment<T> {}
impl<T> MerkleTreeCommitment<T> {
    /// Construct a commitment from an authenticated root and non-zero count.
    #[must_use]
    pub const fn new(root: HashOf<MerkleTree<T>>, leaf_count: NonZeroU64) -> Self {
        Self { root, leaf_count }
    }
    /// Borrow the authenticated root hash.
    #[must_use]
    pub const fn root(&self) -> &HashOf<MerkleTree<T>> {
        &self.root
    }
    /// Return the authenticated number of leaves.
    #[must_use]
    pub const fn leaf_count(&self) -> NonZeroU64 {
        self.leaf_count
    }
}
/// Errors returned by Merkle tree helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// A fallible Merkle node allocation could not be reserved.
    #[error("merkle tree allocation unavailable")]
    AllocationUnavailable,
    /// Chunk size must be in the range `1..=32`.
    #[error("invalid chunk size {chunk}; expected 1..=32 bytes")]
    InvalidChunkSize {
        /// The invalid chunk size provided by the caller.
        chunk: usize,
    },
    /// Merkle tree layout is malformed.
    #[error("invalid merkle tree layout: {0}")]
    InvalidLayout(String),
    /// A compact proof cannot represent an audit path deeper than 32 levels.
    #[error("merkle proof depth {depth} exceeds compact proof limit {max_depth}")]
    CompactProofTooDeep {
        /// Actual audit-path depth.
        depth: usize,
        /// Maximum depth supported by the compact direction bitset.
        max_depth: u8,
    },
    /// Compact proof fields are internally inconsistent or non-canonical.
    #[error("non-canonical compact merkle proof")]
    NonCanonicalCompactProof,
    /// A serialized tree exceeds the V1 leaf reconstruction bound.
    #[error("serialized merkle tree has {actual} leaves; maximum is {maximum}")]
    SerializedTreeTooManyLeaves {
        /// Leaf count declared by the serialized tree.
        actual: usize,
        /// Maximum leaf count accepted by the V1 tree wire.
        maximum: usize,
    },
    /// The serialized tree names a node-hashing scheme unknown to this release.
    #[error("unsupported merkle tree hash scheme {scheme}")]
    UnsupportedHashScheme {
        /// Unknown wire discriminant.
        scheme: u8,
    },
    /// Cached nodes do not follow the tree's retained canonical V1 hashing scheme.
    #[error("merkle tree cached nodes are inconsistent with its retained hash scheme and leaves")]
    InconsistentCachedNodes,
}
#[cfg(feature = "json")]
impl<T> JsonSerialize for MerkleTreeCommitment<T> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("root", out);
        out.push(':');
        self.root.json_serialize(out);
        out.push(',');
        json::write_json_string("leaf_count", out);
        out.push(':');
        self.leaf_count.get().json_serialize(out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), json::BoundedJsonError> {
            out.push_str("{\"root\":")?;
            self.root.json_serialize_to(out)?;
            out.push_str(",\"leaf_count\":")?;
            self.leaf_count.get().json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
#[cfg(feature = "json")]
impl<T> JsonDeserialize for MerkleTreeCommitment<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut root = None;
        let mut leaf_count = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let key = parser.parse_key()?;
            match key.as_str() {
                "root" => {
                    if root.is_some() {
                        return Err(json::Error::duplicate_field("root"));
                    }
                    root = Some(HashOf::<MerkleTree<T>>::json_deserialize(parser)?);
                }
                "leaf_count" => {
                    if leaf_count.is_some() {
                        return Err(json::Error::duplicate_field("leaf_count"));
                    }
                    let count = u64::json_deserialize(parser)?;
                    leaf_count = Some(NonZeroU64::new(count).ok_or_else(|| {
                        json::Error::Message("leaf_count must be non-zero".into())
                    })?);
                }
                _ => parser.skip_value()?,
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Ok(Self {
            root: root.ok_or_else(|| json::Error::missing_field("root"))?,
            leaf_count: leaf_count.ok_or_else(|| json::Error::missing_field("leaf_count"))?,
        })
    }
}
fn proof_depth_for_leaf_count(leaf_count: NonZeroU64) -> usize {
    (u64::BITS - leaf_count.get().saturating_sub(1).leading_zeros()) as usize
}
fn proof_shape_is_canonical<T>(
    leaf_index: u32,
    audit_path: &[Option<HashOf<T>>],
    leaf_count: NonZeroU64,
) -> bool {
    let mut width = leaf_count.get();
    let mut index = u64::from(leaf_index);
    if width > MERKLE_PROOF_MAX_LEAF_COUNT
        || index >= width
        || audit_path.len() != proof_depth_for_leaf_count(leaf_count)
    {
        return false;
    }
    for sibling in audit_path {
        let sibling_must_exist = !index.is_multiple_of(2) || index + 1 < width;
        if sibling.is_some() != sibling_must_exist {
            return false;
        }
        index >>= 1;
        width = width.div_ceil(2);
    }
    index == 0 && width == 1
}
fn validate_chunk_size(chunk: usize) -> Result<(), MerkleError> {
    if (1..=32).contains(&chunk) {
        Ok(())
    } else {
        Err(MerkleError::InvalidChunkSize { chunk })
    }
}
/// A Merkle proof: index of a leaf among all leaves, and the shortest list of additional nodes to recompute the root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema)]
pub struct MerkleProof<T> {
    /// Zero-based index of the leaf among all leaves.
    leaf_index: u32,
    /// List of missing nodes required to recompute the nodes leading from a leaf to the root.
    audit_path: Vec<Option<HashOf<T>>>,
}
/// Compact Merkle proof using a direction bitset and sibling nodes.
///
/// - `depth`: number of levels used (<= 32 for `dirs` to cover)
/// - `dirs`: bit i encodes the direction at level i (0: accumulator is left child; 1: right child)
/// - `siblings`: sibling nodes from leaf → root; missing nodes encoded as `None`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, IntoSchema)]
pub struct CompactMerkleProof<T> {
    depth: u8,
    dirs: u32,
    siblings: Vec<Option<HashOf<T>>>,
}
// Markers carry identity only; tree and proof payloads do not serialize T.
macro_rules! merkle_schema_identity {
    ($($ty:ident => $name:literal),+ $(,)?) => {$(
        impl<T: norito::NoritoSchema> norito::NoritoSchema for $ty<T> {
            fn nominal_name() -> String {
                norito::schema::identity::generic_name($name, &[T::nominal_name()])
            }
        }
    )+};
}
merkle_schema_identity! {
    MerkleTree => "iroha_crypto::merkle::MerkleTree",
    MerkleTreeCommitment => "iroha_crypto::merkle::MerkleTreeCommitment",
    MerkleProof => "iroha_crypto::merkle::MerkleProof",
    CompactMerkleProof => "iroha_crypto::merkle::CompactMerkleProof",
}

/// Exact immutable leaf references after complete cache validation.
/// The existing sequence codec owns count/framing and checks iterator cardinality.
struct BorrowedMerkleLeaves<'a, T>(&'a [Option<HashOf<T>>]);
impl<T> BorrowedMerkleLeaves<'_, T> {
    fn iter(&self) -> impl ExactSizeIterator<Item = &HashOf<T>> {
        self.0.iter().map(|leaf| {
            leaf.as_ref()
                .expect("validated canonical Merkle leaves are present")
        })
    }
}
impl<T> norito::core::SerializePayload for BorrowedMerkleLeaves<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::write_element_sequence::<HashOf<T>, _>(writer, self.iter())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_hint(self.iter())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_exact(self.iter())
    }
}
impl<T> norito::core::SerializePayload for MerkleTree<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let (hash_scheme, leaves) = self
            .serialized_view()
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        norito::core::SerializePayload::serialize(&(hash_scheme, leaves), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        let (hash_scheme, leaves) = self.serialized_view().ok()?;
        norito::core::SerializePayload::encoded_len_hint(&(hash_scheme, leaves))
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let (hash_scheme, leaves) = self.serialized_view().ok()?;
        norito::core::SerializePayload::encoded_len_exact(&(hash_scheme, leaves))
    }
}
// -------------------------------
// Shielded commitments (ZK) helpers
// -------------------------------
/// Domain tag for shielded commitment leaves (Merkle leaves for ZK shielded pools).
/// Kept stable across platforms; trailing NUL disambiguates from adjacent tags.
const TAG_ZK_SHIELD_CM_V1: &[u8] = b"iroha:zk:shield:cm:v1\x00";
impl MerkleTree<[u8; 32]> {
    /// Compute a domain‑tagged leaf hash for a 32‑byte commitment using Blake2b‑32.
    /// The tag is `b"iroha:zk:shield:cm:v1\0"` and is concatenated with the commitment bytes.
    pub fn shielded_leaf_from_commitment(cm: [u8; 32]) -> HashOf<[u8; 32]> {
        HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[TAG_ZK_SHIELD_CM_V1, &cm]))
    }
    /// Explicit empty‑tree root for a fixed height `depth` (binary tree).
    ///
    /// Construction:
    /// - Shielded commitment C0 = Hash(shield-domain || `[0u8; 32]`)
    /// - Base leaf L0 = Hash(leaf-domain || C0)
    /// - For each level, parent = Hash(internal-domain || prev || prev)
    ///
    /// Returns the raw 32‑byte digest underlying `Hash` (LSB set by `Hash`).
    pub fn shielded_empty_root(depth: u8) -> [u8; 32] {
        // L0 — shield-domain commitment, then the generic Merkle leaf boundary.
        let zero_leaf = [0_u8; 32];
        let shield_leaf = Hash::new_from_chunks(&[TAG_ZK_SHIELD_CM_V1, &zero_leaf]);
        let mut h = Hash::new_from_chunks(&[TAG_MERKLE_LEAF_V1, shield_leaf.as_ref()]);
        for _ in 0..depth {
            h = Hash::new_from_chunks(&[TAG_MERKLE_INTERNAL_V1, h.as_ref(), h.as_ref()]);
        }
        h.into()
    }
}

impl<'de, T> norito::core::DeserializePayload<'de> for MerkleTree<T> {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("MerkleTree decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let payload =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (tree, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(payload)?;
        if used != payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(tree)
    }
}
impl<'de, T> norito::core::DecodeFromSlice<'de> for MerkleTree<T> {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (scheme_len, scheme_header) = norito::core::read_len_dyn_slice(bytes)?;
        let scheme_start = scheme_header;
        let scheme_end = scheme_start
            .checked_add(scheme_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let scheme_field = bytes
            .get(scheme_start..scheme_end)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let (hash_scheme, scheme_used) =
            <u8 as norito::core::DecodeFromSlice>::decode_from_slice(scheme_field)?;
        if scheme_used != scheme_field.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        let remaining = bytes
            .get(scheme_end..)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let (leaves_len, leaves_header) = norito::core::read_len_dyn_slice(remaining)?;
        let leaves_start = scheme_end
            .checked_add(leaves_header)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let used = leaves_start
            .checked_add(leaves_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let leaves_field = bytes
            .get(leaves_start..used)
            .ok_or(norito::core::Error::LengthMismatch)?;
        // Inspect and reject the element count before `Vec` allocates. The
        // ordinary Norito sequence decoder still performs global resource
        // accounting when it subsequently materializes an accepted vector.
        let (declared_leaf_count, _) = norito::core::inspect_seq_len_slice(leaves_field)?;
        Self::ensure_serialized_leaf_count(declared_leaf_count)
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        let (leaves, leaves_used) =
            <Vec<HashOf<T>> as norito::core::DecodeFromSlice>::decode_from_slice(leaves_field)?;
        if leaves_used != leaves_field.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        let tree = Self::from_serialized_parts(hash_scheme, leaves)
            .map_err(|error| norito::core::Error::Message(error.to_string()))?;
        Ok((tree, used))
    }
}
#[cfg(feature = "json")]
impl<T> JsonSerialize for MerkleTree<T> {
    fn json_serialize(&self, out: &mut String) {
        let Ok((hash_scheme, leaves)) = self.serialized_view() else {
            // `JsonSerialize` is infallible. Emit an explicitly invalid scheme
            // rather than publishing attacker-controlled cached nodes as a
            // canonical tree; the decoder will reject this value.
            out.push_str(r#"{"hash_scheme":0,"leaves":[]}"#);
            return;
        };
        out.push('{');
        json::write_json_string("hash_scheme", out);
        out.push(':');
        hash_scheme.json_serialize(out);
        out.push(',');
        json::write_json_string("leaves", out);
        out.push(':');
        out.push('[');
        for (index, leaf) in leaves.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            leaf.json_serialize(out);
        }
        out.push(']');
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        let Ok((hash_scheme, leaves)) = self.serialized_view() else {
            out.begin_container()?;
            let result = (|| -> Result<(), json::BoundedJsonError> {
                out.push_str("{\"hash_scheme\":0,\"leaves\":")?;
                out.begin_container()?;
                let result = (|| -> Result<(), json::BoundedJsonError> {
                    out.push_str("[]")?;
                    Ok(())
                })();
                out.end_container();
                result?;
                out.push('}')?;
                Ok(())
            })();
            out.end_container();
            return result;
        };
        out.begin_container()?;
        let result = (|| -> Result<(), json::BoundedJsonError> {
            out.push_str("{\"hash_scheme\":")?;
            hash_scheme.json_serialize_to(out)?;
            out.push_str(",\"leaves\":")?;
            out.begin_container()?;
            let result = (|| -> Result<(), json::BoundedJsonError> {
                out.push('[')?;
                for (index, leaf) in leaves.iter().enumerate() {
                    if index != 0 {
                        out.push(',')?;
                    }
                    leaf.json_serialize_to(out)?;
                }
                out.push(']')?;
                Ok(())
            })();
            out.end_container();
            result?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
#[cfg(feature = "json")]
impl<T> JsonDeserialize for MerkleTree<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut hash_scheme = None;
        let mut leaves = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let key = parser.parse_key()?;
            match key.as_str() {
                "hash_scheme" => {
                    if hash_scheme.is_some() {
                        return Err(json::Error::duplicate_field("hash_scheme"));
                    }
                    hash_scheme = Some(u8::json_deserialize(parser)?);
                }
                "leaves" => {
                    if leaves.is_some() {
                        return Err(json::Error::duplicate_field("leaves"));
                    }
                    leaves = Some(Self::deserialize_json_leaves_bounded(parser)?);
                }
                _ => parser.skip_value()?,
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Self::from_serialized_parts(
            hash_scheme.ok_or_else(|| json::Error::missing_field("hash_scheme"))?,
            leaves.ok_or_else(|| json::Error::missing_field("leaves"))?,
        )
        .map_err(|error| json::Error::Message(error.to_string()))
    }
}
#[cfg(feature = "json")]
impl<T> MerkleTree<T> {
    fn deserialize_json_leaves_bounded(
        parser: &mut json::Parser<'_>,
    ) -> Result<Vec<HashOf<T>>, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'[')?;
        let mut leaves = Vec::new();
        parser.skip_ws();
        if parser.try_consume_char(b']')? {
            return Ok(leaves);
        }
        loop {
            if leaves.len() == SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 {
                return Err(json::Error::Message(
                    MerkleError::SerializedTreeTooManyLeaves {
                        actual: SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1,
                        maximum: SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1,
                    }
                    .to_string(),
                ));
            }
            leaves.push(HashOf::<T>::json_deserialize(parser)?);
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b']')?;
            break;
        }
        Ok(leaves)
    }
}
struct NoritoRef<'a, T>(&'a T);

impl<T: norito::core::SerializePayload> norito::core::SerializePayload for NoritoRef<'_, T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(self.0, writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(self.0)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(self.0)
    }
}

impl<T> norito::core::SerializePayload for MerkleProof<T> {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(
            &(NoritoRef(&self.leaf_index), NoritoRef(&self.audit_path)),
            writer,
        )
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&(
            NoritoRef(&self.leaf_index),
            NoritoRef(&self.audit_path),
        ))
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&(
            NoritoRef(&self.leaf_index),
            NoritoRef(&self.audit_path),
        ))
    }
}

impl<'de, T> norito::core::DeserializePayload<'de> for MerkleProof<T> {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("MerkleProof decode")
    }
    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let payload =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (proof, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(payload)?;
        if used != payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(proof)
    }
}
impl<'de, T> norito::core::DecodeFromSlice<'de> for MerkleProof<T> {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let ((leaf_index, audit_path), used) =
            <(u32, Vec<Option<HashOf<T>>>) as norito::core::DecodeFromSlice>::decode_from_slice(
                bytes,
            )?;
        Ok((
            Self {
                leaf_index,
                audit_path,
            },
            used,
        ))
    }
}
#[cfg(feature = "json")]
impl<T> JsonSerialize for MerkleProof<T> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("leaf_index", out);
        out.push(':');
        json::JsonSerialize::json_serialize(&self.leaf_index, out);
        out.push(',');
        json::write_json_string("audit_path", out);
        out.push(':');
        json::JsonSerialize::json_serialize(&self.audit_path, out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), json::BoundedJsonError> {
            out.push_str("{\"leaf_index\":")?;
            self.leaf_index.json_serialize_to(out)?;
            out.push_str(",\"audit_path\":")?;
            self.audit_path.json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
#[cfg(feature = "json")]
impl<T> JsonDeserialize for MerkleProof<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut leaf_index: Option<u32> = None;
        let mut audit_path: Option<Vec<Option<HashOf<T>>>> = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let key = parser.parse_key()?;
            match key.as_str() {
                "leaf_index" => {
                    if leaf_index.is_some() {
                        return Err(json::Error::duplicate_field("leaf_index"));
                    }
                    leaf_index = Some(u32::json_deserialize(parser)?);
                }
                "audit_path" => {
                    if audit_path.is_some() {
                        return Err(json::Error::duplicate_field("audit_path"));
                    }
                    audit_path = Some(Vec::<Option<HashOf<T>>>::json_deserialize(parser)?);
                }
                _ => parser.skip_value()?,
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Ok(MerkleProof {
            leaf_index: leaf_index.ok_or_else(|| json::Error::missing_field("leaf_index"))?,
            audit_path: audit_path.ok_or_else(|| json::Error::missing_field("audit_path"))?,
        })
    }
}
/// Iterator over the leaf hashes of a [`MerkleTree`], yielding each leaf in left-to-right order.
pub struct LeafHashIterator<'a, T> {
    tree: &'a MerkleTree<T>,
    index: usize,
    index_back: usize,
}
/// A complete binary tree supporting indexed access to nodes in breadth-first order.
trait CompleteBinaryTree {
    /// The type of value stored in each node.
    type NodeValue;
    /// Returns the total number of nodes in the tree.
    fn len(&self) -> usize;
    /// Returns a reference to the node value at `index`, in breadth-first order from the root.
    fn get(&self, index: usize) -> Option<&Self::NodeValue>;
    /// Returns a reference to the leaf node value at `index`, in left-to-right order among leaves.
    fn get_leaf(&self, index: usize) -> Option<&Self::NodeValue> {
        let offset = (1 << self.height()) - 1_usize;
        offset.checked_add(index).and_then(|i| self.get(i))
    }
    /// Returns the height of the tree, defined as the number of edges from root to any leaf.
    fn height(&self) -> u32 {
        (usize::BITS - self.len().leading_zeros()).saturating_sub(1)
    }
    /// Returns the height of a complete binary tree with the given number of leaves.
    fn height_from_n_leaves(n: usize) -> u32 {
        usize::BITS - n.saturating_sub(1).leading_zeros()
    }
    /// Returns the maximum number of nodes the tree can contain without increasing its height.
    fn capacity(&self) -> usize {
        (1 << (self.height() + 1)) - 1
    }
    /// Returns the index of the given leaf, in breadth-first order from the root.
    fn index_in_tree(&self, leaf_index: usize) -> Option<usize> {
        let index = Self::index_in_tree_unchecked(leaf_index, self.height() as usize);
        (index < self.len()).then_some(index)
    }
    /// Returns the index of the given leaf, in breadth-first order from the root.
    ///
    /// Does not check if the result is within bounds.
    fn index_in_tree_unchecked(leaf_index: usize, height: usize) -> usize {
        let offset = (1 << height) - 1_usize;
        offset.saturating_add(leaf_index)
    }
    /// Returns the index of the parent of the node at `index`, or `None` if the node is the root.
    fn parent_index(&self, index: usize) -> Option<usize> {
        if 0 == index {
            return None;
        }
        let index = (index - 1) >> 1;
        (index < self.len()).then_some(index)
    }
    /// Returns the index of the left child of the node at `index`, if it exists.
    fn l_child_index(&self, index: usize) -> Option<usize> {
        let index = (index << 1) + 1;
        (index < self.len()).then_some(index)
    }
    /// Returns the index of the right child of the node at `index`, if it exists.
    fn r_child_index(&self, index: usize) -> Option<usize> {
        let index = (index << 1) + 2;
        (index < self.len()).then_some(index)
    }
    /// Returns the index of the sibling node of the node at `index`, if it exists.
    fn sibling_index(&self, index: usize) -> Option<usize> {
        if index.is_multiple_of(2) {
            (0 < index).then(|| index - 1)
        } else {
            (index < self.len() - 1).then(|| index + 1)
        }
    }
    /// Returns a reference to the left child of the node at `index`, if it exists.
    fn get_l_child(&self, index: usize) -> Option<&Self::NodeValue> {
        self.l_child_index(index).and_then(|i| self.get(i))
    }
    /// Returns a reference to the right child of the node at `index`, if it exists.
    fn get_r_child(&self, index: usize) -> Option<&Self::NodeValue> {
        self.r_child_index(index).and_then(|i| self.get(i))
    }
}
impl<T> CompleteBinaryTree for MerkleTree<T> {
    type NodeValue = HashOf<T>;
    fn len(&self) -> usize {
        self.nodes.len()
    }
    fn get(&self, index: usize) -> Option<&Self::NodeValue> {
        self.nodes.get(index).and_then(|opt| opt.as_ref())
    }
}
impl<T> FromIterator<HashOf<T>> for MerkleTree<T> {
    fn from_iter<I: IntoIterator<Item = HashOf<T>>>(iter: I) -> Self {
        Self::from_application_leaf_nodes(iter.into_iter().map(|leaf| Self::leaf_hash(&leaf)))
    }
}
// NOTE: Leaf nodes in the order of insertion
impl<T: IntoSchema> IntoSchema for MerkleTree<T> {
    fn type_name() -> String {
        format!("MerkleTree<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if !map.contains_key::<Self>() {
            u8::update_schema_map(map);
            HashOf::<T>::update_schema_map(map);
            Vec::<HashOf<T>>::update_schema_map(map);
            map.insert::<Self>(iroha_schema::Metadata::Tuple(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![
                        core::any::TypeId::of::<u8>(),
                        core::any::TypeId::of::<Vec<HashOf<T>>>(),
                    ],
                },
            ));
        }
    }
}
impl<T> Default for MerkleTree<T> {
    fn default() -> Self {
        Self {
            hash_scheme: MerkleHashScheme::ApplicationV1,
            nodes: Vec::new(),
        }
    }
}
impl<T> MerkleTree<T> {
    /// Clone the retained node array using a checked, fallible allocation.
    ///
    /// The clone keeps the exact node ordering and hashing scheme. Runtime
    /// owners can reserve its reported footprint before calling this method.
    ///
    /// # Errors
    /// Returns [`MerkleError::AllocationUnavailable`] if the node array does
    /// not fit the host allocation geometry or the allocator refuses it.
    pub fn try_clone_allocation(&self) -> Result<Self, MerkleError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| MerkleError::AllocationUnavailable)?;
        nodes.extend_from_slice(&self.nodes);
        Ok(Self {
            hash_scheme: self.hash_scheme,
            nodes,
        })
    }

    /// Allocator-requested bytes retained by the internal node array.
    ///
    /// This reports native allocation capacity, independently of the wire
    /// encoding and tree commitment. Allocator bookkeeping is excluded.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.nodes.capacity() * core::mem::size_of::<Option<HashOf<T>>>()
    }
    fn ensure_serialized_leaf_count(leaf_count: usize) -> Result<(), MerkleError> {
        if leaf_count > SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 {
            return Err(MerkleError::SerializedTreeTooManyLeaves {
                actual: leaf_count,
                maximum: SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1,
            });
        }
        Ok(())
    }
    fn from_leaf_nodes_with<I, F>(hash_scheme: MerkleHashScheme, leaves: I, pair_hash: F) -> Self
    where
        I: IntoIterator<Item = HashOf<T>>,
        F: Fn(Option<&HashOf<T>>, Option<&HashOf<T>>) -> Option<HashOf<T>>,
    {
        let mut queue = leaves.into_iter().map(Some).collect::<VecDeque<_>>();
        if queue.is_empty() {
            // No leaf or cached parent exists: preserve the selected scheme
            // without manufacturing and then discarding allocated padding.
            return Self {
                hash_scheme,
                nodes: Vec::new(),
            };
        }
        let height = Self::height_from_n_leaves(queue.len());
        let n_complement = (1 << height) - queue.len();
        for _ in 0..n_complement {
            queue.push_back(None);
        }
        let mut tree = Vec::with_capacity(1 << (height + 1));
        while let Some(r_node) = queue.pop_back() {
            if let Some(l_node) = queue.pop_back() {
                queue.push_front(pair_hash(l_node.as_ref(), r_node.as_ref()));
                tree.push(r_node);
                tree.push(l_node);
            } else {
                tree.push(r_node);
                break;
            }
        }
        tree.reverse();
        for _ in 0..n_complement {
            tree.pop();
        }
        Self {
            hash_scheme,
            nodes: tree,
        }
    }
    fn from_application_leaf_nodes<I>(leaves: I) -> Self
    where
        I: IntoIterator<Item = HashOf<T>>,
    {
        Self::from_leaf_nodes_with(MerkleHashScheme::ApplicationV1, leaves, Self::pair_hash)
    }
    fn from_sha256_leaf_nodes<I>(leaves: I) -> Self
    where
        I: IntoIterator<Item = HashOf<T>>,
    {
        Self::from_leaf_nodes_with(MerkleHashScheme::Sha256V1, leaves, Self::pair_hash_sha256)
    }
    fn from_serialized_parts(hash_scheme: u8, leaves: Vec<HashOf<T>>) -> Result<Self, MerkleError> {
        Self::ensure_serialized_leaf_count(leaves.len())?;
        match MerkleHashScheme::from_wire_id(hash_scheme)? {
            MerkleHashScheme::ApplicationV1 => Ok(Self::from_application_leaf_nodes(leaves)),
            MerkleHashScheme::Sha256V1 => Ok(Self::from_sha256_leaf_nodes(leaves)),
        }
    }
    // Original materialized cache reconstruction exists only as an independent
    // test oracle. Production serialization uses the same immutable source.
    #[cfg(test)]
    fn serialized_parts(&self) -> Result<(u8, Vec<HashOf<T>>), MerkleError> {
        Self::validate_nodes(&self.nodes)?;
        let leaf_count = self.leaf_count();
        Self::ensure_serialized_leaf_count(leaf_count)?;
        let leaves = self.leaves().collect::<Vec<_>>();
        if leaves.len() != leaf_count {
            return Err(MerkleError::InconsistentCachedNodes);
        }
        let rebuilt = match self.hash_scheme {
            MerkleHashScheme::ApplicationV1 => {
                Self::from_application_leaf_nodes(leaves.iter().copied())
            }
            MerkleHashScheme::Sha256V1 => Self::from_sha256_leaf_nodes(leaves.iter().copied()),
        };
        if rebuilt.nodes != self.nodes {
            return Err(MerkleError::InconsistentCachedNodes);
        }
        Ok((self.hash_scheme.wire_id(), leaves))
    }
    /// Validate every original cached parent and borrow the exact canonical
    /// leaves. No leaf vector, queue or replacement graph is constructed.
    fn serialized_view(&self) -> Result<(u8, BorrowedMerkleLeaves<'_, T>), MerkleError> {
        Self::validate_nodes(&self.nodes)?;
        let leaf_count = self.leaf_count();
        Self::ensure_serialized_leaf_count(leaf_count)?;
        let offset = if self.nodes.is_empty() {
            0
        } else {
            let height = (usize::BITS - self.nodes.len().leading_zeros()).saturating_sub(1);
            (1usize << height) - 1
        };
        if !self.nodes.is_empty() {
            for index in (0..offset).rev() {
                let left = self.nodes.get((index << 1) + 1).and_then(Option::as_ref);
                let right = self.nodes.get((index << 1) + 2).and_then(Option::as_ref);
                let expected = self.pair_hash_for_scheme(left, right);
                if self.nodes[index] != expected {
                    return Err(MerkleError::InconsistentCachedNodes);
                }
            }
        }
        Ok((
            self.hash_scheme.wire_id(),
            BorrowedMerkleLeaves(&self.nodes[offset..]),
        ))
    }
    fn validate_nodes(nodes: &[Option<HashOf<T>>]) -> Result<(), MerkleError> {
        if nodes.is_empty() {
            return Ok(());
        }
        let len = nodes.len();
        let height = (usize::BITS - len.leading_zeros()).saturating_sub(1);
        let height_usize = height as usize;
        if height_usize >= usize::BITS as usize {
            return Err(MerkleError::InvalidLayout(
                "merkle tree height exceeds platform bit width".to_owned(),
            ));
        }
        let pow2 = 1usize << height_usize;
        let offset = pow2 - 1;
        if len <= offset {
            return Err(MerkleError::InvalidLayout(
                "merkle tree node count underflows leaf offset".to_owned(),
            ));
        }
        let leaf_count = len - offset;
        let expected_height = <Self as CompleteBinaryTree>::height_from_n_leaves(leaf_count);
        if expected_height != height {
            return Err(MerkleError::InvalidLayout(format!(
                "merkle tree node count {len} does not match leaf count {leaf_count}"
            )));
        }
        if nodes[0].is_none() {
            return Err(MerkleError::InvalidLayout(
                "merkle tree root must be present".to_owned(),
            ));
        }
        if nodes[offset..].iter().any(Option::is_none) {
            return Err(MerkleError::InvalidLayout(
                "merkle tree leaves must be present".to_owned(),
            ));
        }
        for i in 0..offset {
            let li = (i << 1) + 1;
            let ri = li + 1;
            let left = nodes.get(li).and_then(|node| node.as_ref());
            let right = nodes.get(ri).and_then(|node| node.as_ref());
            let parent = nodes[i].as_ref();
            if left.is_none() && right.is_some() {
                return Err(MerkleError::InvalidLayout(format!(
                    "merkle tree has right-only child at node {i}"
                )));
            }
            if parent.is_none() && (left.is_some() || right.is_some()) {
                return Err(MerkleError::InvalidLayout(format!(
                    "merkle tree missing parent for existing child at node {i}"
                )));
            }
            if left.is_none() && right.is_none() && parent.is_some() {
                return Err(MerkleError::InvalidLayout(format!(
                    "merkle tree has parent without children at node {i}"
                )));
            }
        }
        Ok(())
    }
    /// Return the depth (number of edges from root to any leaf) of the complete tree.
    #[must_use]
    pub fn depth(&self) -> u32 {
        <Self as CompleteBinaryTree>::height(self)
    }
}
impl<'a, T> MerkleTree<T> {
    /// Canonical leaf-node hashes of this Merkle tree.
    ///
    /// Generic application trees domain-separate caller-supplied typed hashes
    /// before storing them. Specialized constructors, such as the SHA-256 byte
    /// tree helpers, define their own leaf-node protocol.
    pub fn leaves(&'a self) -> LeafHashIterator<'a, T> {
        LeafHashIterator::new(self)
    }
}
impl<T> MerkleTree<T> {
    #[inline]
    fn leaf_hash(leaf: &HashOf<T>) -> HashOf<T> {
        HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[TAG_MERKLE_LEAF_V1, leaf.as_ref()]))
    }
    /// Returns the hash of the root node, or `None` if the tree has no nodes.
    pub fn root(&self) -> Option<HashOf<Self>> {
        self.get(0).copied().map(HashOf::transmute)
    }
    /// Compute the canonical application-tree root with logarithmic memory.
    ///
    /// This has the same leaf and internal-node domain separation and ragged
    /// right-edge promotion as collecting the hashes into [`MerkleTree`], but
    /// retains only one completed subtree per level.
    pub fn root_from_typed_leaves<I>(leaves: I) -> Option<HashOf<Self>>
    where
        I: IntoIterator<Item = HashOf<T>>,
    {
        // A native pointer-width frontier covers every representable leaf count. No
        // fallible backing allocation or input-sized scratch is needed for root-only hashing.
        let mut frontier = [None; usize::BITS as usize];
        for leaf in leaves {
            let mut node = Self::leaf_hash(&leaf);
            let mut level = 0_usize;
            loop {
                let slot = frontier.get_mut(level)?;
                if let Some(left) = slot.take() {
                    node = Self::pair_hash(Some(&left), Some(&node))?;
                    level = level.checked_add(1)?;
                } else {
                    *slot = Some(node);
                    break;
                }
            }
        }
        let mut right = None;
        for left in frontier.into_iter().flatten() {
            right = Some(match right {
                None => left,
                Some(right) => Self::pair_hash(Some(&left), Some(&right))?,
            });
        }
        right.map(HashOf::transmute)
    }
    /// Return the exact number of leaves represented by this tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        if self.nodes.is_empty() {
            return 0;
        }
        let leaf_offset = (1usize << self.height()) - 1;
        self.nodes.len() - leaf_offset
    }
    /// Validate the cached tree against the canonical logical leaf hashes.
    ///
    /// Unlike rebuilding a [`MerkleTree`] from the iterator, this walks the
    /// retained leaves and parent nodes in place and uses constant additional
    /// memory. The retained hash scheme determines whether logical leaves are
    /// application-domain separated or already SHA-256 leaf nodes.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::InvalidLayout`] when the retained node layout is malformed, or
    /// [`MerkleError::InconsistentCachedNodes`] when a leaf or parent differs from its canonical
    /// hash, including when the supplied leaf count differs.
    pub fn validate_leaves<I>(&self, leaves: I) -> Result<(), MerkleError>
    where
        I: IntoIterator<Item = HashOf<T>>,
    {
        Self::validate_nodes(&self.nodes)?;
        let mut supplied = leaves.into_iter();
        let mut retained = self.leaves();
        loop {
            match (supplied.next(), retained.next()) {
                (Some(leaf), Some(retained_leaf)) => {
                    let expected = match self.hash_scheme {
                        MerkleHashScheme::ApplicationV1 => Self::leaf_hash(&leaf),
                        MerkleHashScheme::Sha256V1 => leaf,
                    };
                    if retained_leaf != expected {
                        return Err(MerkleError::InconsistentCachedNodes);
                    }
                }
                (None, None) => break,
                _ => return Err(MerkleError::InconsistentCachedNodes),
            }
        }
        let leaf_offset = (1usize << self.height()) - 1;
        for index in (0..leaf_offset).rev() {
            let expected =
                self.pair_hash_for_scheme(self.get_l_child(index), self.get_r_child(index));
            if self.nodes[index] != expected {
                return Err(MerkleError::InconsistentCachedNodes);
            }
        }
        Ok(())
    }
    /// Return the canonical root-and-count commitment, or `None` for an empty tree.
    #[must_use]
    pub fn commitment(&self) -> Option<MerkleTreeCommitment<T>> {
        let root = self.root()?;
        let leaf_count = u64::try_from(self.leaf_count()).ok()?;
        Some(MerkleTreeCommitment::new(
            root,
            NonZeroU64::new(leaf_count)?,
        ))
    }
    /// Constructs a Merkle proof for the leaf at the given index among all leaves.
    pub fn get_proof(&self, leaf_index: u32) -> Option<MerkleProof<T>> {
        Some(MerkleProof {
            leaf_index,
            audit_path: self.proof_siblings(leaf_index)?.collect(),
        })
    }
    /// Incrementally update the leaf at `leaf_index` and recompute parents
    /// using this tree's retained hashing scheme.
    ///
    /// Application trees domain-separate the typed hash as a leaf. SHA-256
    /// trees treat it as an already-hashed canonical leaf node.
    pub fn update_typed_leaf(&mut self, leaf_index: usize, new_leaf: HashOf<T>) {
        let height = self.height() as usize;
        let index = MerkleTree::<T>::index_in_tree_unchecked(leaf_index, height);
        let leaf_node = match self.hash_scheme {
            MerkleHashScheme::ApplicationV1 => Self::leaf_hash(&new_leaf),
            MerkleHashScheme::Sha256V1 => new_leaf,
        };
        if let Some(slot) = self.nodes.get_mut(index) {
            *slot = Some(leaf_node);
            self.update(index);
        }
    }
    /// Appends a leaf hash and updates parents using the retained hash scheme.
    ///
    /// Application trees domain-separate the typed hash as a leaf. SHA-256
    /// trees treat it as an already-hashed canonical leaf node.
    pub fn add(&mut self, hash: HashOf<T>) {
        // If the tree is perfect, increment its height to double the leaf capacity.
        if self.capacity() == self.len() {
            let height = self.height();
            let mut new_array = vec![None];
            let mut array = core::mem::take(&mut self.nodes);
            for depth in 0..height {
                let capacity_at_depth = 1 << depth;
                let tail = array.split_off(capacity_at_depth);
                array.extend(vec![None; capacity_at_depth]);
                new_array.append(&mut array);
                array = tail;
            }
            new_array.append(&mut array);
            self.nodes = new_array;
        }
        let leaf_node = match self.hash_scheme {
            MerkleHashScheme::ApplicationV1 => Self::leaf_hash(&hash),
            MerkleHashScheme::Sha256V1 => hash,
        };
        self.nodes.push(Some(leaf_node));
        self.update(self.len() - 1);
    }
    /// Recomputes hashes along the path from the leaf at `index` up to the root.
    fn update(&mut self, mut index: usize) {
        let mut node = self.get(index).copied();
        while let Some(parent_index) = self.parent_index(index) {
            let (l_node, r_node) = match index % 2 {
                0 => (self.get_l_child(parent_index), node.as_ref()),
                1 => (node.as_ref(), self.get_r_child(parent_index)),
                _ => unreachable!(),
            };
            let parent_node = self.pair_hash_for_scheme(l_node, r_node);
            let Some(parent_mut) = self.nodes.get_mut(parent_index) else {
                return;
            };
            *parent_mut = parent_node;
            index = parent_index;
            node = parent_node;
        }
    }
    /// Combines two child hashes into a parent hash.
    ///
    /// Pre-hash processing:
    /// - If both children are present, prefixes the canonical internal-node
    ///   domain tag and then concatenates their hashes.
    ///   The order is non-commutative and essential for index verification.
    /// - If only the left child is present, promotes it to the next level without hashing.
    /// - If the left child is absent, returns `None`.
    #[inline]
    fn pair_hash(l_node: Option<&HashOf<T>>, r_node: Option<&HashOf<T>>) -> Option<HashOf<T>> {
        let (l_hash, r_hash) = match (l_node, r_node) {
            (Some(l_hash), Some(r_hash)) => (l_hash, r_hash),
            (Some(l_hash), None) => return Some(*l_hash),
            (None, Some(_)) => {
                // Invalid Merkle path: a right-only child cannot exist in a complete tree.
                // Return None instead of panicking to allow graceful rejection during verification.
                return None;
            }
            (None, None) => return None,
        };
        Some(HashOf::from_untyped_unchecked(Hash::new_from_chunks(&[
            TAG_MERKLE_INTERNAL_V1,
            l_hash.as_ref(),
            r_hash.as_ref(),
        ])))
    }
    #[inline]
    fn pair_hash_sha256(
        l_node: Option<&HashOf<T>>,
        r_node: Option<&HashOf<T>>,
    ) -> Option<HashOf<T>> {
        let (l_hash, r_hash) = match (l_node, r_node) {
            (Some(l_hash), Some(r_hash)) => (l_hash, r_hash),
            (Some(l_hash), None) => return Some(*l_hash),
            (None, Some(_) | None) => return None,
        };
        let mut input = [0_u8; Hash::LENGTH * 2];
        input[..Hash::LENGTH].copy_from_slice(l_hash.as_ref());
        input[Hash::LENGTH..].copy_from_slice(r_hash.as_ref());
        let digest: [u8; Hash::LENGTH] = Sha256::digest(input).into();
        Some(HashOf::from_untyped_unchecked(Hash::prehashed(digest)))
    }
    #[inline]
    fn pair_hash_for_scheme(
        &self,
        l_node: Option<&HashOf<T>>,
        r_node: Option<&HashOf<T>>,
    ) -> Option<HashOf<T>> {
        match self.hash_scheme {
            MerkleHashScheme::ApplicationV1 => Self::pair_hash(l_node, r_node),
            MerkleHashScheme::Sha256V1 => Self::pair_hash_sha256(l_node, r_node),
        }
    }
    /// Parallel builder from typed leaf hashes using canonical pair-hash
    /// semantics. This constructs the complete BFS array bottom-up, computing
    /// parents in parallel per level. Semantics match the sequential
    /// `FromIterator<HashOf<T>>` implementation.
    #[cfg(feature = "rayon")]
    pub fn from_typed_leaves_parallel<I>(leaves: I) -> Self
    where
        T: Send + Sync,
        I: IntoIterator<Item = HashOf<T>>,
    {
        let leaves_vec: Vec<HashOf<T>> = leaves.into_iter().collect();
        if leaves_vec.is_empty() {
            return Self::default();
        }
        let n = leaves_vec.len();
        let height = Self::height_from_n_leaves(n);
        let pow2 = 1usize << height;
        let capacity = (1usize << (height + 1)) - 1;
        let offset = pow2 - 1; // index of first leaf in BFS layout
        // Initialize BFS node array with None, then place leaves.
        let mut nodes: Vec<Option<HashOf<T>>> = vec![None; capacity];
        for (i, leaf) in leaves_vec.into_iter().enumerate() {
            nodes[offset + i] = Some(Self::leaf_hash(&leaf));
        }
        // Compute parents bottom-up, in parallel per level.
        for lvl in (0..height).rev() {
            let start = (1usize << lvl) - 1;
            let end = (1usize << (lvl + 1)) - 1; // exclusive upper bound
            for i in start..end {
                let li = (i << 1) + 1;
                let ri = li + 1;
                let l = nodes.get(li).and_then(|o| o.as_ref());
                let r = nodes.get(ri).and_then(|o| o.as_ref());
                nodes[i] = Self::pair_hash(l, r);
            }
        }
        let complement = pow2 - n;
        if complement > 0 {
            nodes.truncate(nodes.len() - complement);
        }
        Self {
            hash_scheme: MerkleHashScheme::ApplicationV1,
            nodes,
        }
    }
}
impl<T> MerkleProof<T> {
    /// Construct a Merkle proof from a leaf index and an audit path.
    ///
    /// This constructor does not validate the path; it is primarily intended for tests and
    /// interoperability scenarios where the sibling list is produced externally (e.g., from another
    /// crate) and needs to be wrapped into a proof structure.
    pub fn from_audit_path(leaf_index: u32, audit_path: Vec<Option<HashOf<T>>>) -> Self {
        MerkleProof {
            leaf_index,
            audit_path,
        }
    }
    /// Verify the proof against an authenticated root-and-count commitment.
    ///
    /// The exact depth, leaf-index range, and every `Some`/`None` sibling on a
    /// ragged right edge must match the committed count.
    #[must_use]
    pub fn verify(&self, leaf: &HashOf<T>, commitment: &MerkleTreeCommitment<T>) -> bool {
        if !proof_shape_is_canonical(self.leaf_index, &self.audit_path, commitment.leaf_count) {
            return false;
        }
        let mut index = u64::from(self.leaf_index);
        let committed_leaf = MerkleTree::<T>::leaf_hash(leaf);
        let Some(computed_root) =
            self.audit_path
                .iter()
                .try_fold(committed_leaf, |acc, sibling| {
                    let (left, right) = if index.is_multiple_of(2) {
                        (Some(&acc), sibling.as_ref())
                    } else {
                        (sibling.as_ref(), Some(&acc))
                    };
                    index >>= 1;
                    MerkleTree::pair_hash(left, right)
                })
        else {
            return false;
        };
        commitment.root == computed_root.transmute()
    }
    /// Borrow the audit path (list of sibling nodes) for this proof.
    pub fn audit_path(&self) -> &[Option<HashOf<T>>] {
        &self.audit_path
    }
    /// Consume the proof and return its audit path.
    pub fn into_audit_path(self) -> Vec<Option<HashOf<T>>> {
        self.audit_path
    }
    /// Leaf index among all leaves for this proof.
    pub fn leaf_index(&self) -> u32 {
        self.leaf_index
    }
}
impl<T> CompactMerkleProof<T> {
    /// Construct a compact proof from raw parts. Depth is limited to 32 by the encoding used in VM
    /// syscalls, and `siblings.len()` should be equal to `depth`.
    pub fn from_parts(depth: u8, dirs: u32, siblings: Vec<Option<HashOf<T>>>) -> Self {
        CompactMerkleProof {
            depth,
            dirs,
            siblings,
        }
    }
    /// Number of levels used in this proof.
    pub fn depth(&self) -> u8 {
        self.depth
    }
    /// Direction bitset for each level.
    pub fn dirs(&self) -> u32 {
        self.dirs
    }
    /// Borrow the sibling list.
    pub fn siblings(&self) -> &[Option<HashOf<T>>] {
        &self.siblings
    }
    /// Construct a compact proof from a full proof without losing path data.
    ///
    /// # Errors
    /// Returns [`MerkleError::CompactProofTooDeep`] when the full path cannot
    /// be represented by the 32-bit direction bitset.
    pub fn try_from_full(full: MerkleProof<T>) -> Result<Self, MerkleError> {
        let path_len = full.audit_path.len();
        if path_len > usize::from(COMPACT_MERKLE_PROOF_MAX_DEPTH) {
            return Err(MerkleError::CompactProofTooDeep {
                depth: path_len,
                max_depth: COMPACT_MERKLE_PROOF_MAX_DEPTH,
            });
        }
        let depth = u8::try_from(path_len).map_err(|_| MerkleError::CompactProofTooDeep {
            depth: path_len,
            max_depth: COMPACT_MERKLE_PROOF_MAX_DEPTH,
        })?;
        // Direction bits use leaf-index semantics: bit i = 0 (left), 1 (right).
        let depth_bits = u32::from(depth);
        let mask = if depth == COMPACT_MERKLE_PROOF_MAX_DEPTH {
            u32::MAX
        } else {
            (1u32 << depth_bits) - 1
        };
        let dirs = full.leaf_index & mask;
        Ok(CompactMerkleProof {
            depth,
            dirs,
            siblings: full.audit_path,
        })
    }
    /// Expand a canonical compact proof into its full representation.
    ///
    /// The direction bitset is the leaf index. Bits above `depth` must be zero
    /// so alternative encodings of the same proof are rejected.
    ///
    /// # Errors
    /// Returns [`MerkleError::NonCanonicalCompactProof`] when the depth,
    /// sibling count, or unused direction bits are invalid.
    pub fn try_into_full(self) -> Result<MerkleProof<T>, MerkleError> {
        if !self.has_canonical_encoding() {
            return Err(MerkleError::NonCanonicalCompactProof);
        }
        Ok(MerkleProof::from_audit_path(self.dirs, self.siblings))
    }
    fn has_canonical_encoding(&self) -> bool {
        if self.depth > COMPACT_MERKLE_PROOF_MAX_DEPTH
            || self.siblings.len() != usize::from(self.depth)
        {
            return false;
        }
        let used_mask = if self.depth == COMPACT_MERKLE_PROOF_MAX_DEPTH {
            u32::MAX
        } else if self.depth == 0 {
            0
        } else {
            (1u32 << u32::from(self.depth)) - 1
        };
        self.dirs & !used_mask == 0
    }
    /// Verify this compact proof against an authenticated commitment.
    #[must_use]
    pub fn verify(&self, leaf: &HashOf<T>, commitment: &MerkleTreeCommitment<T>) -> bool {
        if !self.has_canonical_encoding() {
            return false;
        }
        let full = MerkleProof::from_audit_path(self.dirs, self.siblings.clone());
        full.verify(leaf, commitment)
    }
}
#[cfg(feature = "json")]
impl<T> JsonSerialize for CompactMerkleProof<T> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string("depth", out);
        out.push(':');
        json::JsonSerialize::json_serialize(&self.depth, out);
        out.push(',');
        json::write_json_string("dirs", out);
        out.push(':');
        json::JsonSerialize::json_serialize(&self.dirs, out);
        out.push(',');
        json::write_json_string("siblings", out);
        out.push(':');
        json::JsonSerialize::json_serialize(&self.siblings, out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), json::BoundedJsonError> {
            out.push_str("{\"depth\":")?;
            self.depth.json_serialize_to(out)?;
            out.push_str(",\"dirs\":")?;
            self.dirs.json_serialize_to(out)?;
            out.push_str(",\"siblings\":")?;
            self.siblings.json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}
#[cfg(feature = "json")]
impl<T> JsonDeserialize for CompactMerkleProof<T> {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        parser.skip_ws();
        parser.consume_char(b'{')?;
        let mut depth: Option<u8> = None;
        let mut dirs: Option<u32> = None;
        let mut siblings: Option<Vec<Option<HashOf<T>>>> = None;
        loop {
            parser.skip_ws();
            if parser.try_consume_char(b'}')? {
                break;
            }
            let key = parser.parse_key()?;
            match key.as_str() {
                "depth" => {
                    if depth.is_some() {
                        return Err(json::Error::duplicate_field("depth"));
                    }
                    depth = Some(u8::json_deserialize(parser)?);
                }
                "dirs" => {
                    if dirs.is_some() {
                        return Err(json::Error::duplicate_field("dirs"));
                    }
                    dirs = Some(u32::json_deserialize(parser)?);
                }
                "siblings" => {
                    if siblings.is_some() {
                        return Err(json::Error::duplicate_field("siblings"));
                    }
                    siblings = Some(Vec::<Option<HashOf<T>>>::json_deserialize(parser)?);
                }
                _ => parser.skip_value()?,
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.consume_char(b'}')?;
            break;
        }
        Ok(CompactMerkleProof {
            depth: depth.ok_or_else(|| json::Error::missing_field("depth"))?,
            dirs: dirs.ok_or_else(|| json::Error::missing_field("dirs"))?,
            siblings: siblings.ok_or_else(|| json::Error::missing_field("siblings"))?,
        })
    }
}
impl CompactMerkleProof<[u8; 32]> {
    /// Compute the SHA-256 root of this proof's path fragment.
    ///
    /// This deliberately does not authenticate a leaf count and therefore is
    /// not a membership verifier. It is intended only for protocols that
    /// explicitly expose a depth-capped partial root.
    #[must_use]
    pub fn compute_partial_root_sha256(
        &self,
        leaf: &HashOf<[u8; 32]>,
    ) -> Option<HashOf<MerkleTree<[u8; 32]>>> {
        if !self.has_canonical_encoding() {
            return None;
        }
        MerkleProof::from_audit_path(self.dirs, self.siblings.clone())
            .compute_partial_root_sha256(leaf, usize::from(self.depth))
    }
    /// Verify a compact proof where inner nodes are combined using SHA-256 of
    /// left||right and leaves are SHA-256 digests.
    ///
    /// The proof encoding and ragged-tree geometry must exactly match the authenticated leaf count.
    pub fn verify_sha256(
        &self,
        leaf: &HashOf<[u8; 32]>,
        commitment: &MerkleTreeCommitment<[u8; 32]>,
    ) -> bool {
        if !self.has_canonical_encoding() {
            return false;
        }
        let full = MerkleProof::from_audit_path(self.dirs, self.siblings.clone());
        full.verify_sha256(leaf, commitment)
    }
}
// Specialized helpers for byte-oriented Merkle trees using SHA-256 as the
// node-combining hash. These helpers build a MerkleTree<[u8;32]> whose internal
// nodes store HashOf<[u8;32]>. The underlying bytes for each node are the
// SHA-256 digests of either a leaf chunk, or the concatenation of two child
// nodes. The resulting 32-byte digests are wrapped with Hash::prehashed to
// maintain the Hash invariants (LSB set) while preserving the SHA-256 layout.
impl MerkleTree<[u8; 32]> {
    fn repeated_sha256_node_capacity(leaf_count: usize) -> Result<usize, MerkleError> {
        if leaf_count == 0 {
            return Ok(0);
        }
        leaf_count
            .max(1)
            .checked_next_power_of_two()
            .and_then(|slots| slots.checked_mul(2))
            .ok_or(MerkleError::AllocationUnavailable)
    }

    /// Requested bytes for the sole node allocation of a repeated-leaf SHA-256 tree.
    ///
    /// Reserve this amount before calling
    /// [`Self::try_from_repeated_hashed_leaf_sha256`]. The returned tree reports
    /// its actual retained capacity through [`Self::allocated_bytes`].
    ///
    /// # Errors
    /// Returns [`MerkleError::AllocationUnavailable`] when the requested node
    /// array cannot fit in the host address space.
    pub fn repeated_sha256_node_allocation_bytes(leaf_count: usize) -> Result<usize, MerkleError> {
        let bytes = Self::repeated_sha256_node_capacity(leaf_count)?
            .checked_mul(core::mem::size_of::<Option<HashOf<[u8; 32]>>>())
            .ok_or(MerkleError::AllocationUnavailable)?;
        if bytes > isize::MAX as usize {
            return Err(MerkleError::AllocationUnavailable);
        }
        Ok(bytes)
    }

    /// Build a repeated pre-hashed SHA-256 leaf tree with one fallible node allocation.
    ///
    /// The breadth-first node layout, promotion of an unpaired right-edge
    /// leaf, and retained node capacity match [`Self::from_hashed_leaves_sha256`].
    ///
    /// # Errors
    /// Returns [`MerkleError::AllocationUnavailable`] for overflowing geometry
    /// or when the node array cannot be reserved.
    pub fn try_from_repeated_hashed_leaf_sha256(
        leaf_count: usize,
        digest: [u8; 32],
    ) -> Result<Self, MerkleError> {
        let mut tree = Self::try_sha256_node_storage(leaf_count)?;
        if leaf_count != 0 {
            let offset = tree.nodes.len() - leaf_count;
            let leaf = HashOf::from_untyped_unchecked(Hash::prehashed(digest));
            tree.nodes[offset..].fill(Some(leaf));
            tree.rebuild_sha256_parents(offset);
        }
        Ok(tree)
    }

    /// Build exact hashed leaves with one fallible, fixed-geometry node allocation.
    ///
    /// Capacity matches [`Self::repeated_sha256_node_allocation_bytes`]. Leaves,
    /// node ordering and ragged promotion use the same canonical SHA-256 relation
    /// as [`Self::rewrite_hashed_leaves_sha256`]; no temporary queue is allocated.
    ///
    /// # Errors
    /// Returns [`MerkleError::AllocationUnavailable`] for overflowing geometry
    /// or when the sole node array cannot be reserved.
    pub fn try_from_hashed_leaves_sha256(digests: &[[u8; 32]]) -> Result<Self, MerkleError> {
        let mut tree = Self::try_sha256_node_storage(digests.len())?;
        tree.rewrite_hashed_leaves_sha256(digests)?;
        Ok(tree)
    }

    fn try_sha256_node_storage(leaf_count: usize) -> Result<Self, MerkleError> {
        Self::repeated_sha256_node_allocation_bytes(leaf_count)?;
        let capacity = Self::repeated_sha256_node_capacity(leaf_count)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(capacity)
            .map_err(|_| MerkleError::AllocationUnavailable)?;
        if leaf_count != 0 {
            nodes.resize(capacity / 2 - 1 + leaf_count, None);
        }
        Ok(Self {
            hash_scheme: MerkleHashScheme::Sha256V1,
            nodes,
        })
    }

    fn rebuild_sha256_parents(&mut self, leaf_offset: usize) {
        for parent in (0..leaf_offset).rev() {
            let left = self.nodes.get((parent << 1) + 1).and_then(Option::as_ref);
            let right = self.nodes.get((parent << 1) + 2).and_then(Option::as_ref);
            self.nodes[parent] = Self::pair_hash_sha256(left, right);
        }
    }

    /// Build a Merkle tree from an iterator of pre-hashed 32-byte leaves.
    /// Each leaf is assumed to be the SHA-256 digest of a chunk, and inner
    /// nodes are computed as SHA-256 of left||right. If a right child is
    /// missing, the left child is promoted unchanged. Empty input yields an empty tree (no root).
    pub fn from_hashed_leaves_sha256<I>(leaves: I) -> Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let leaf_nodes = leaves
            .into_iter()
            .map(|digest| HashOf::from_untyped_unchecked(Hash::prehashed(digest)));
        Self::from_sha256_leaf_nodes(leaf_nodes)
    }
    /// Build a Merkle tree from raw bytes by splitting them into `chunk`-sized
    /// pieces and hashing each zero-padded chunk with SHA-256. The final chunk,
    /// if shorter, is padded with zeros up to `chunk` bytes before hashing.
    /// Inner nodes are combined as SHA-256(left||right).
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::InvalidChunkSize`] when `chunk` is outside `1..=32`,
    /// or [`MerkleError::AllocationUnavailable`] when its sole fixed node allocation
    /// cannot be reserved. Its requested bytes are exactly
    /// [`Self::repeated_sha256_node_allocation_bytes`] for the padded leaf count.
    pub fn from_byte_chunks(data: &[u8], chunk: usize) -> Result<Self, MerkleError> {
        validate_chunk_size(chunk)?;
        let count = data.len().div_ceil(chunk).max(1);
        let mut tree = Self::try_sha256_node_storage(count)?;
        let offset = tree.nodes.len() - count;
        for (index, node) in tree.nodes[offset..].iter_mut().enumerate() {
            // Empty input retains its canonical single zero leaf. A partial
            // final chunk is padded to exactly `chunk`, never to 32 bytes.
            let start = index * chunk;
            let end = start.saturating_add(chunk).min(data.len());
            let digest: [u8; 32] = if end - start == chunk {
                Sha256::digest(&data[start..end]).into()
            } else {
                let mut padded = [0u8; 32];
                if start < end {
                    padded[..end - start].copy_from_slice(&data[start..end]);
                }
                Sha256::digest(&padded[..chunk]).into()
            };
            *node = Some(HashOf::from_untyped_unchecked(Hash::prehashed(digest)));
        }
        tree.rebuild_sha256_parents(offset);
        Ok(tree)
    }
    /// Build a Merkle tree from an owned vector of pre-hashed 32-byte leaves, computing internal
    /// nodes in parallel. Semantics match `from_hashed_leaves_sha256` exactly and remain
    /// deterministic. Empty input yields an empty tree (no root).
    #[cfg(feature = "rayon")]
    pub fn from_hashed_leaves_sha256_parallel(leaves: Vec<[u8; 32]>) -> Self {
        use crate::Hash;
        let n = leaves.len();
        if n == 0 {
            return Self {
                hash_scheme: MerkleHashScheme::Sha256V1,
                nodes: Vec::new(),
            };
        }
        let height = Self::height_from_n_leaves(n);
        let pow2 = 1usize << height;
        let capacity = (1usize << (height + 1)) - 1;
        let offset = pow2 - 1; // index of first leaf in BFS layout
        // Initialize BFS node array with None, then place leaves.
        let mut nodes: Vec<Option<[u8; 32]>> = vec![None; capacity];
        for (i, leaf) in leaves.into_iter().enumerate() {
            nodes[offset + i] = Some(leaf);
        }
        // Compute parents bottom-up, level by level, in parallel per level.
        for lvl in (0..height).rev() {
            let start = (1usize << lvl) - 1;
            let end = (1usize << (lvl + 1)) - 1; // exclusive upper bound
            for i in start..end {
                let li = (i << 1) + 1;
                let ri = li + 1;
                let l = nodes.get(li).and_then(|o| *o);
                let r = nodes.get(ri).and_then(|o| *o);
                nodes[i] = match (l, r) {
                    (Some(mut l), Some(mut r)) => {
                        // Match canonical: set prehashed marker on child digests
                        l[Hash::LENGTH - 1] |= 1;
                        r[Hash::LENGTH - 1] |= 1;
                        let mut buf = [0u8; 64];
                        buf[..32].copy_from_slice(&l);
                        buf[32..].copy_from_slice(&r);
                        let digest = Sha256::digest(buf);
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&digest);
                        Some(arr)
                    }
                    (Some(l), None) => Some(l),
                    (None, _) => None,
                };
            }
        }
        let complement = pow2 - n;
        if complement > 0 {
            nodes.truncate(nodes.len() - complement);
        }
        // Wrap raw digests into HashOf<[u8;32]> (using Hash::prehashed)
        let inner = nodes
            .into_iter()
            .map(|opt| opt.map(|d| HashOf::from_untyped_unchecked(Hash::prehashed(d))))
            .collect();
        Self {
            hash_scheme: MerkleHashScheme::Sha256V1,
            nodes: inner,
        }
    }
    /// Parallel variant of `from_byte_chunks` guarded by the `rayon` feature.
    ///
    /// # Errors
    /// Returns [`MerkleError::InvalidChunkSize`] when `chunk` is outside `1..=32`.
    #[cfg(feature = "rayon")]
    pub fn from_chunked_bytes_parallel(data: &[u8], chunk: usize) -> Result<Self, MerkleError> {
        validate_chunk_size(chunk)?;
        let num_chunks = data.len().div_ceil(chunk);
        let mut leaves = vec![[0u8; 32]; num_chunks.max(1)];
        leaves.par_iter_mut().enumerate().for_each(|(i, slot)| {
            let start = i * chunk;
            if start >= data.len() {
                // only possible when data is empty; compute hash of zero-padded chunk
                let buf = [0u8; 32];
                let digest = Sha256::digest(&buf[..chunk]);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&digest);
                *slot = arr;
                return;
            }
            let end = (start + chunk).min(data.len());
            let mut buf = [0u8; 32];
            buf[..(end - start)].copy_from_slice(&data[start..end]);
            let digest = Sha256::digest(&buf[..chunk]);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&digest);
            *slot = arr;
        });
        Ok(Self::from_hashed_leaves_sha256_parallel(leaves))
    }
    /// Incrementally update the leaf at `leaf_index` with a new SHA-256 digest
    /// and recompute parent nodes up to the root using SHA-256(left||right)
    /// semantics with left-promotion.
    pub fn update_hashed_leaf_sha256(&mut self, leaf_index: usize, new_digest: [u8; 32]) {
        use crate::Hash;
        assert_eq!(
            self.hash_scheme,
            MerkleHashScheme::Sha256V1,
            "SHA-256 leaf updates require a SHA-256 Merkle tree"
        );
        // Compute the tree index of the leaf and set it to the new digest
        let height = self.height() as usize;
        let idx = MerkleTree::<[u8; 32]>::index_in_tree_unchecked(leaf_index, height);
        let new_leaf = HashOf::from_untyped_unchecked(Hash::prehashed(new_digest));
        if let Some(slot) = self.nodes.get_mut(idx) {
            *slot = Some(new_leaf);
        } else {
            // Out of bounds leaf update; ignore (or could panic). Keep graceful.
            return;
        }
        self.update(idx);
    }

    /// Rewrite every SHA-256 leaf and parent in an existing tree without changing
    /// its node allocation. The caller must supply exactly the current leaf count.
    ///
    /// # Errors
    /// Returns [`MerkleError::InvalidLayout`] for another hash scheme or leaf count.
    pub fn rewrite_hashed_leaves_sha256(
        &mut self,
        digests: &[[u8; 32]],
    ) -> Result<(), MerkleError> {
        if self.hash_scheme != MerkleHashScheme::Sha256V1 || self.leaf_count() != digests.len() {
            return Err(MerkleError::InvalidLayout(
                "SHA-256 rewrite requires the existing leaf count and scheme".into(),
            ));
        }
        let leaf_offset = (1_usize << self.height()) - 1;
        for (slot, digest) in self.nodes[leaf_offset..].iter_mut().zip(digests) {
            *slot = Some(HashOf::from_untyped_unchecked(Hash::prehashed(*digest)));
        }
        self.rebuild_sha256_parents(leaf_offset);
        Ok(())
    }
}
impl MerkleProof<[u8; 32]> {
    /// Compute a partial Merkle root using SHA-256(left || right) semantics.
    ///
    /// This deliberately does not authenticate a leaf count and therefore is
    /// not a membership verifier. It exists only for protocols, such as an IVM
    /// partial-root operation, that explicitly commit to a path fragment.
    pub fn compute_partial_root_sha256(
        &self,
        leaf: &HashOf<[u8; 32]>,
        max_height: usize,
    ) -> Option<HashOf<MerkleTree<[u8; 32]>>> {
        let height = self.audit_path.len();
        if max_height < height {
            return None;
        }
        if height < u32::BITS as usize {
            let max_leaves = 1usize << height;
            if self.leaf_index as usize >= max_leaves {
                return None;
            }
        }
        let mut index = u64::from(self.leaf_index);
        let mut acc_bytes: [u8; 32] = *leaf.as_ref();
        for sibling in &self.audit_path {
            let (l_opt, r_opt) = if index.is_multiple_of(2) {
                (
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(acc_bytes))),
                    sibling.as_ref().copied(),
                )
            } else {
                (
                    sibling.as_ref().copied(),
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(acc_bytes))),
                )
            };
            index >>= 1;
            let combined = match (l_opt, r_opt) {
                (Some(lh), Some(rh)) => {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(lh.as_ref());
                    buf[32..].copy_from_slice(rh.as_ref());
                    let digest = Sha256::digest(buf);
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&digest);
                    arr
                }
                (Some(lh), None) => *lh.as_ref(),
                (None, Some(_) | None) => return None,
            };
            acc_bytes = combined;
        }
        Some(HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(
            Hash::prehashed(acc_bytes),
        ))
    }
    /// Verify a proof where internal nodes are SHA-256(left || right).
    ///
    /// Exact path depth, leaf-index range, and ragged sibling geometry are
    /// derived from the authenticated leaf count.
    pub fn verify_sha256(
        &self,
        leaf: &HashOf<[u8; 32]>,
        commitment: &MerkleTreeCommitment<[u8; 32]>,
    ) -> bool {
        Self::verify_audit_path_sha256(self.leaf_index, &self.audit_path, leaf, commitment)
    }
    /// Verify a borrowed SHA-256 audit path without constructing an owned proof.
    ///
    /// This uses the same authenticated leaf count and canonical shape checks
    /// as [`Self::verify_sha256`], including ragged sibling geometry.
    pub fn verify_audit_path_sha256(
        leaf_index: u32,
        audit_path: &[Option<HashOf<[u8; 32]>>],
        leaf: &HashOf<[u8; 32]>,
        commitment: &MerkleTreeCommitment<[u8; 32]>,
    ) -> bool {
        if !proof_shape_is_canonical(leaf_index, audit_path, commitment.leaf_count) {
            return false;
        }
        let mut index = u64::from(leaf_index);
        let mut acc_bytes: [u8; 32] = *leaf.as_ref();
        for sibling in audit_path {
            let (l_opt, r_opt) = if index.is_multiple_of(2) {
                (
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(acc_bytes))),
                    sibling.as_ref().copied(),
                )
            } else {
                (
                    sibling.as_ref().copied(),
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(acc_bytes))),
                )
            };
            index >>= 1;
            let combined = match (l_opt, r_opt) {
                (Some(lh), Some(rh)) => {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(lh.as_ref());
                    buf[32..].copy_from_slice(rh.as_ref());
                    let digest = Sha256::digest(buf);
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&digest);
                    arr
                }
                (Some(lh), None) => *lh.as_ref(),
                (None, Some(_) | None) => return false,
            };
            acc_bytes = combined;
        }
        let computed =
            HashOf::<MerkleTree<[u8; 32]>>::from_untyped_unchecked(Hash::prehashed(acc_bytes));
        commitment.root == computed
    }
    /// Construct a SHA-256 proof from raw sibling bytes.
    ///
    /// Conventions:
    /// - The path is ordered from leaf → root.
    /// - A sibling of all-zero bytes represents a missing node (`None`).
    pub fn from_audit_path_bytes(leaf_index: u32, path: Vec<[u8; 32]>) -> Self {
        let audit_path = path
            .into_iter()
            .map(|b| {
                if b == [0u8; 32] {
                    None
                } else {
                    Some(HashOf::from_untyped_unchecked(Hash::prehashed(b)))
                }
            })
            .collect();
        MerkleProof {
            leaf_index,
            audit_path,
        }
    }
}
impl<T> Iterator for LeafHashIterator<'_, T> {
    type Item = HashOf<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index_back <= self.index {
            return None;
        }
        let Some(leaf) = self.tree.get_leaf(self.index).copied() else {
            self.index = self.index_back;
            return None;
        };
        // Increment the front index eagerly.
        self.index += 1;
        Some(leaf)
    }
}
impl<T> DoubleEndedIterator for LeafHashIterator<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index_back <= self.index {
            return None;
        }
        // Decrement the back index lazily.
        self.index_back -= 1;
        let Some(leaf) = self.tree.get_leaf(self.index_back).copied() else {
            self.index = self.index_back;
            return None;
        };
        Some(leaf)
    }
}
impl<T> ExactSizeIterator for LeafHashIterator<'_, T> {
    fn len(&self) -> usize {
        self.index_back - self.index
    }
}
impl<'a, T> LeafHashIterator<'a, T> {
    fn new(tree: &'a MerkleTree<T>) -> Self {
        let offset = (1 << tree.height()) - 1;
        let n_leaves = tree.len() - offset;
        Self {
            tree,
            index: 0,
            index_back: n_leaves,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    #[test]
    fn empty_tree_builders_preserve_the_original_scheme_without_allocated_padding() {
        use crate::test_allocations::without_allocations;
        let application =
            without_allocations(|| std::iter::empty::<HashOf<()>>().collect::<MerkleTree<()>>());
        assert_eq!(application, MerkleTree::default());
        assert_eq!(application.allocated_bytes(), 0);
        let sha = without_allocations(|| MerkleTree::from_hashed_leaves_sha256([]));
        let fixed = without_allocations(|| MerkleTree::try_from_hashed_leaves_sha256(&[]).unwrap());
        let repeated = without_allocations(|| {
            MerkleTree::try_from_repeated_hashed_leaf_sha256(0, [0x53; 32]).unwrap()
        });
        for tree in [&sha, &fixed, &repeated] {
            assert_eq!(tree.hash_scheme, MerkleHashScheme::Sha256V1);
            assert!(tree.nodes.is_empty());
            assert_eq!(tree.allocated_bytes(), 0);
            assert_eq!(tree.root(), None);
            assert_eq!(tree.commitment(), None);
        }
        assert_eq!(
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(0),
            Ok(0)
        );
        without_allocations(|| {
            assert_eq!(application.serialized_parts().unwrap(), (1, Vec::new()));
            assert_eq!(sha.serialized_parts().unwrap(), (2, Vec::new()));
        });
        #[cfg(feature = "rayon")]
        {
            let parallel =
                without_allocations(|| MerkleTree::from_hashed_leaves_sha256_parallel(Vec::new()));
            assert_eq!(parallel, sha);
            assert_eq!(parallel.allocated_bytes(), 0);
        }
    }

    #[test]
    fn empty_and_nonempty_builder_wire_matches_the_original_padding_algorithm() {
        use crate::test_allocations::allocations_during;
        // Independent original constructor is a test oracle only. Production
        // owns one algorithm; canonical scheme/leaves and every cache stay exact.
        fn original<T>(scheme: MerkleHashScheme, leaves: Vec<HashOf<T>>) -> MerkleTree<T> {
            let mut queue = leaves.into_iter().map(Some).collect::<VecDeque<_>>();
            let height = MerkleTree::<T>::height_from_n_leaves(queue.len());
            let complement = (1 << height) - queue.len();
            for _ in 0..complement {
                queue.push_back(None);
            }
            let mut nodes = Vec::with_capacity(1 << (height + 1));
            while let Some(right) = queue.pop_back() {
                if let Some(left) = queue.pop_back() {
                    let parent = match scheme {
                        MerkleHashScheme::ApplicationV1 => {
                            MerkleTree::pair_hash(left.as_ref(), right.as_ref())
                        }
                        MerkleHashScheme::Sha256V1 => {
                            MerkleTree::pair_hash_sha256(left.as_ref(), right.as_ref())
                        }
                    };
                    queue.push_front(parent);
                    nodes.push(right);
                    nodes.push(left);
                } else {
                    nodes.push(right);
                    break;
                }
            }
            nodes.reverse();
            for _ in 0..complement {
                nodes.pop();
            }
            MerkleTree {
                hash_scheme: scheme,
                nodes,
            }
        }
        let (_, retired_allocations) =
            allocations_during(|| original::<()>(MerkleHashScheme::ApplicationV1, Vec::new()));
        assert!(
            retired_allocations >= 2,
            "real original padding allocated both queue and cache"
        );
        for count in [0, 1, 2, 3, 7, 31, 127] {
            let leaves = test_hashes(count);
            for scheme in [MerkleHashScheme::ApplicationV1, MerkleHashScheme::Sha256V1] {
                let expected = original(scheme, leaves.clone());
                let actual = match scheme {
                    MerkleHashScheme::ApplicationV1 => {
                        MerkleTree::from_application_leaf_nodes(leaves.iter().copied())
                    }
                    MerkleHashScheme::Sha256V1 => {
                        MerkleTree::from_sha256_leaf_nodes(leaves.iter().copied())
                    }
                };
                assert_eq!(actual, expected);
                assert_eq!(actual.root(), expected.root());
                assert_eq!(actual.commitment(), expected.commitment());
                assert_eq!(
                    norito::encode_canonical(&actual).unwrap(),
                    norito::encode_canonical(&expected).unwrap()
                );
                for index in 0..u32::from(count) {
                    assert_eq!(actual.get_proof(index), expected.get_proof(index));
                }
                if count != 0 {
                    assert_eq!(actual.allocated_bytes(), expected.allocated_bytes());
                }
            }
        }
    }
    #[test]
    fn byte_chunks_fixed_allocation_preserves_empty_ragged_roots_and_proofs() {
        for chunk in [1, 7, 17, 32] {
            for len in [
                0,
                1,
                chunk - 1,
                chunk,
                chunk + 1,
                3 * chunk - 1,
                65 * chunk - 3,
            ] {
                let data: Vec<_> = (0..len)
                    .map(|index| u8::try_from(index % 256).unwrap().wrapping_mul(37))
                    .collect();
                let mut leaves: Vec<[u8; 32]> = data
                    .chunks(chunk)
                    .map(|piece| {
                        let mut padded = [0u8; 32];
                        padded[..piece.len()].copy_from_slice(piece);
                        Sha256::digest(&padded[..chunk]).into()
                    })
                    .collect();
                if leaves.is_empty() {
                    leaves.push(Sha256::digest(&[0u8; 32][..chunk]).into());
                }
                let expected = MerkleTree::from_hashed_leaves_sha256(leaves.iter().copied());
                let actual = MerkleTree::from_byte_chunks(&data, chunk).unwrap();
                assert_eq!(actual, expected, "chunk {chunk}, bytes {len}");
                assert_eq!(
                    actual.allocated_bytes(),
                    MerkleTree::repeated_sha256_node_allocation_bytes(leaves.len()).unwrap()
                );
                for index in 0..u32::try_from(leaves.len()).unwrap() {
                    assert_eq!(actual.get_proof(index), expected.get_proof(index));
                }
            }
        }
    }

    #[test]
    fn sha256_rewrite_reuses_nodes_and_matches_canonical_ragged_roots() {
        for count in [0, 1, 2, 3, 5, 63, 64, 65, 256] {
            let mut tree =
                MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(vec![[0x11; 32]; count]);
            let original_nodes = tree.nodes.as_ptr();
            let original_capacity = tree.nodes.capacity();
            let digests: Vec<_> = (0..count)
                .map(|index| [u8::try_from(index).expect("at most 256 fixture leaves"); 32])
                .collect();
            tree.rewrite_hashed_leaves_sha256(&digests).unwrap();
            assert_eq!(tree.nodes.as_ptr(), original_nodes);
            assert_eq!(tree.nodes.capacity(), original_capacity);
            let canonical = MerkleTree::from_hashed_leaves_sha256(digests.iter().copied());
            assert_eq!(tree, canonical);
            let fixed = MerkleTree::try_from_hashed_leaves_sha256(&digests).unwrap();
            assert_eq!(fixed, canonical);
            assert_eq!(
                fixed.allocated_bytes(),
                MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(count).unwrap()
            );
            for index in 0..u32::try_from(count).unwrap() {
                assert_eq!(tree.get_proof(index), canonical.get_proof(index));
                assert_eq!(fixed.get_proof(index), canonical.get_proof(index));
            }
        }
        let mut tree = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256([[0x55; 32]; 3]);
        let unchanged = tree.clone();
        assert!(matches!(
            tree.rewrite_hashed_leaves_sha256(&[[0x77; 32]; 2]),
            Err(MerkleError::InvalidLayout(_))
        ));
        assert_eq!(tree, unchanged);
        let leaf = HashOf::from_untyped_unchecked(Hash::prehashed([0x55; 32]));
        let mut application: MerkleTree<[u8; 32]> = [leaf; 3].into_iter().collect();
        let unchanged = application.clone();
        assert!(matches!(
            application.rewrite_hashed_leaves_sha256(&[[0x77; 32]; 3]),
            Err(MerkleError::InvalidLayout(_))
        ));
        assert_eq!(application, unchanged);
    }
    #[test]
    fn fallible_node_clone_preserves_scheme_and_is_independent() {
        for count in [0, 1, 3, 256] {
            let mut source =
                MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(vec![[0x5a; 32]; count]);
            let copied = source
                .try_clone_allocation()
                .expect("bounded Merkle node clone");
            assert_eq!(copied, source);
            assert_eq!(copied.root(), source.root());
            if let Some(first) = source.nodes.first_mut() {
                *first = None;
                assert_ne!(copied, source);
            }
        }
    }

    #[test]
    fn fallible_repeated_sha256_tree_preserves_canonical_layout_and_capacity() {
        let digest = [0xA5; 32];
        for count in [0, 1, 2, 3, 5, 256] {
            let canonical = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(vec![digest; count]);
            let fallible =
                MerkleTree::<[u8; 32]>::try_from_repeated_hashed_leaf_sha256(count, digest)
                    .expect("bounded repeated-leaf tree allocation");
            assert_eq!(fallible, canonical, "node layout differs at {count} leaves");
            assert_eq!(fallible.root(), canonical.root());
            assert_eq!(fallible.allocated_bytes(), canonical.allocated_bytes());
            assert_eq!(
                fallible.allocated_bytes(),
                MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(count)
                    .expect("bounded node capacity"),
            );
        }
        assert!(matches!(
            MerkleTree::<[u8; 32]>::repeated_sha256_node_allocation_bytes(usize::MAX),
            Err(MerkleError::AllocationUnavailable)
        ));
        assert!(matches!(
            MerkleTree::<[u8; 32]>::try_from_repeated_hashed_leaf_sha256(usize::MAX, digest,),
            Err(MerkleError::AllocationUnavailable)
        ));
    }

    #[test]
    fn allocated_bytes_reports_retained_capacity_after_removing_nodes() {
        let mut tree = MerkleTree::<()>::default();
        tree.nodes.reserve(32);
        let reserved = tree.nodes.capacity() * core::mem::size_of::<Option<HashOf<()>>>();
        assert_eq!(tree.allocated_bytes(), reserved);
        tree.nodes.push(None);
        tree.nodes.clear();
        assert_eq!(tree.allocated_bytes(), reserved);
        tree.nodes = Vec::new();
        assert_eq!(tree.allocated_bytes(), 0);
    }

    fn find_deeper_even_step<T>(leaf_index: u32, audit_len: usize) -> Option<usize> {
        let mut index = MerkleTree::<T>::index_in_tree_unchecked(leaf_index as usize, audit_len);
        let mut chosen: Option<usize> = None;
        for step in 0..audit_len {
            if step > 0 && index % 2 == 0 {
                chosen = Some(step);
                break;
            }
            index = index.saturating_sub(1) >> 1;
        }
        chosen
    }
    fn test_hashes(n_hashes: u8) -> Vec<HashOf<()>> {
        (0..n_hashes)
            .map(|i| Hash::prehashed([i; Hash::LENGTH]))
            .map(HashOf::from_untyped_unchecked)
            .collect()
    }
    fn raw_application_tree<T>(nodes: Vec<Option<HashOf<T>>>) -> MerkleTree<T> {
        MerkleTree {
            hash_scheme: MerkleHashScheme::ApplicationV1,
            nodes,
        }
    }
    #[test]
    fn merkle_proof_lengths_and_wire_match_owned_tuple_for_all_supported_layouts() {
        use norito::core::header_flags::COMPACT_LEN;
        let proof: MerkleProof<()> = MerkleProof::from_audit_path(
            1,
            vec![
                Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                    [1; Hash::LENGTH],
                ))),
                None,
                Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                    [3; Hash::LENGTH],
                ))),
            ],
        );
        for flags in [0, COMPACT_LEN] {
            norito::core::reset_decode_state();
            let _guard = norito::core::DecodeFlagsGuard::enter(flags);
            let mut actual = Vec::new();
            norito::core::serialize_to_buffer(&proof, &mut actual)
                .expect("serialize borrowed Merkle-proof tuple");
            let owned = (proof.leaf_index(), proof.audit_path().to_vec());
            let mut expected = Vec::new();
            norito::core::serialize_to_buffer(&owned, &mut expected)
                .expect("serialize historical owned Merkle-proof tuple");
            assert_eq!(actual, expected, "wire changed for flags 0x{flags:02x}");
            assert_eq!(
                norito::core::SerializePayload::encoded_len_hint(&proof),
                Some(actual.len()),
                "hint differs from payload for flags 0x{flags:02x}"
            );
            assert_eq!(
                norito::core::SerializePayload::encoded_len_exact(&proof),
                Some(actual.len()),
                "exact length differs from payload for flags 0x{flags:02x}"
            );
        }
        norito::core::reset_decode_state();
    }
    #[cfg(feature = "json")]
    #[test]
    fn merkle_proof_json_ignores_unknown_members_and_rejects_duplicates() {
        let proof: MerkleProof<()> = norito::json::from_str(
            r#"{
                "future_before": {"nested": [1, true, null]},
                "leaf_index": 7,
                "audit_path": [null],
                "future_after": "ignored"
            }"#,
        )
        .expect("additive Merkle proof members must be ignored");
        assert_eq!(proof.leaf_index(), 7);
        assert_eq!(proof.audit_path(), &[None]);
        for json in [
            r#"{"leaf_index":1,"leaf_index":2,"audit_path":[]}"#,
            r#"{"leaf_index":1,"audit_path":[],"audit_path":[null]}"#,
        ] {
            let err = norito::json::from_str::<MerkleProof<()>>(json)
                .expect_err("duplicate declared Merkle proof member must fail");
            assert!(err.to_string().contains("duplicate field"));
        }
    }
    #[cfg(feature = "json")]
    #[test]
    fn compact_merkle_proof_json_ignores_unknown_members_and_rejects_duplicates() {
        let proof: CompactMerkleProof<()> = norito::json::from_str(
            r#"{
                "depth": 1,
                "future": [{"opaque": true}],
                "dirs": 0,
                "siblings": [null]
            }"#,
        )
        .expect("additive compact Merkle proof members must be ignored");
        assert_eq!(proof.depth(), 1);
        assert_eq!(proof.dirs(), 0);
        assert_eq!(proof.siblings(), &[None]);
        for json in [
            r#"{"depth":1,"depth":2,"dirs":0,"siblings":[]}"#,
            r#"{"depth":1,"dirs":0,"dirs":1,"siblings":[]}"#,
            r#"{"depth":1,"dirs":0,"siblings":[],"siblings":[null]}"#,
        ] {
            let err = norito::json::from_str::<CompactMerkleProof<()>>(json)
                .expect_err("duplicate declared compact Merkle proof member must fail");
            assert!(err.to_string().contains("duplicate field"));
        }
    }
    #[test]
    fn builds_tree_from_hashes() {
        let tree: MerkleTree<_> = test_hashes(5).into_iter().collect();
        //               a3: first 2 hex digits of the hash
        //         ______/\______
        //       60              04
        //     __/\__          __/\__
        //   43      46      04      **
        //   /\      /\      /
        // 00  01  02  03  04
        for (i, node) in tree.nodes.iter().enumerate() {
            println!("{i:02}th node: {node:?}")
        }
        assert_eq!(tree.height(), 3);
        assert_eq!(tree.len(), 12);
        assert!(tree.get(6).is_none());
        assert!(tree.get(11).is_some());
        assert!(tree.get(12).is_none());
    }
    #[test]
    fn iterates_over_leaves() {
        let hashes = test_hashes(5);
        let tree: MerkleTree<_> = hashes.clone().into_iter().collect();
        let leaves: Vec<_> = tree.leaves().collect();
        let committed: Vec<_> = hashes.iter().map(MerkleTree::leaf_hash).collect();
        assert_eq!(committed, leaves);
        let mut leaves_iter = tree.leaves();
        assert_eq!(leaves_iter.len(), 5);
        assert_eq!(leaves_iter.next(), Some(leaves[0]));
        assert_eq!(leaves_iter.next_back(), Some(leaves[4]));
        assert_eq!(leaves_iter.len(), 3);
        assert_eq!(leaves_iter.next(), Some(leaves[1]));
        assert_eq!(leaves_iter.next_back(), Some(leaves[3]));
        assert_eq!(leaves_iter.next(), Some(leaves[2]));
        assert_eq!(leaves_iter.len(), 0);
        assert_eq!(leaves_iter.next_back(), None);
        assert_eq!(leaves_iter.next(), None);
        assert_eq!(leaves_iter.len(), 0);
    }
    #[test]
    fn validates_retained_tree_without_rebuilding_it() {
        let hashes = test_hashes(5);
        let tree: MerkleTree<_> = hashes.iter().copied().collect();
        tree.validate_leaves(hashes.iter().copied())
            .expect("canonical retained tree");
        assert_eq!(
            tree.validate_leaves(hashes[..4].iter().copied()),
            Err(MerkleError::InconsistentCachedNodes)
        );
        let mut wrong_hashes = hashes.clone();
        wrong_hashes[2] = HashOf::from_untyped_unchecked(Hash::prehashed([0xAA; Hash::LENGTH]));
        assert_eq!(
            tree.validate_leaves(wrong_hashes),
            Err(MerkleError::InconsistentCachedNodes)
        );
        let mut corrupt = tree;
        corrupt.nodes[0] = Some(HashOf::from_untyped_unchecked(Hash::prehashed(
            [0xBB; Hash::LENGTH],
        )));
        assert_eq!(
            corrupt.validate_leaves(hashes),
            Err(MerkleError::InconsistentCachedNodes)
        );
    }
    #[test]
    fn streaming_root_matches_retained_tree_for_ragged_layouts() {
        for count in 0_u8..=31 {
            let hashes = test_hashes(count);
            let tree: MerkleTree<_> = hashes.iter().copied().collect();
            assert_eq!(
                MerkleTree::root_from_typed_leaves(hashes),
                tree.root(),
                "leaf count {count}"
            );
        }
    }
    #[test]
    fn stack_streaming_root_matches_large_exact_and_ragged_trees() {
        for count in [255_u64, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097] {
            let hashes = (0..count)
                .map(|index| HashOf::<()>::from_untyped_unchecked(Hash::new(index.to_le_bytes())));
            let tree: MerkleTree<()> = hashes.clone().collect();
            assert_eq!(
                MerkleTree::root_from_typed_leaves(hashes),
                tree.root(),
                "leaf count {count}"
            );
        }
    }
    #[test]
    fn leaf_iterator_stops_on_missing_front_leaf() {
        let leaf = test_hashes(1)[0];
        let bad_tree = raw_application_tree(vec![Some(leaf), None, Some(leaf)]);
        let mut leaves_iter = bad_tree.leaves();
        assert_eq!(leaves_iter.len(), 2);
        assert_eq!(leaves_iter.next(), None);
        assert_eq!(leaves_iter.len(), 0);
        assert_eq!(leaves_iter.next_back(), None);
    }
    #[test]
    fn leaf_iterator_stops_on_missing_back_leaf() {
        let leaf = test_hashes(1)[0];
        let bad_tree = raw_application_tree(vec![Some(leaf), Some(leaf), None]);
        let mut leaves_iter = bad_tree.leaves();
        assert_eq!(leaves_iter.len(), 2);
        assert_eq!(leaves_iter.next_back(), None);
        assert_eq!(leaves_iter.len(), 0);
        assert_eq!(leaves_iter.next(), None);
    }
    #[test]
    fn update_stops_on_missing_parent_slot() {
        let mut tree = raw_application_tree::<()>(vec![None]);
        tree.update(3);
        assert_eq!(tree.nodes, vec![None]);
    }
    #[test]
    fn grows_incrementally_and_matches_prebuilt_tree() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let mut growing_tree = MerkleTree::default();
        for leaf in leaves {
            growing_tree.add(leaf);
        }
        assert_eq!(growing_tree.root(), tree.root());
        assert_eq!(growing_tree, tree);
    }
    #[test]
    fn provides_and_verifies_inclusion_proofs() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("non-empty tree");
        // Generate proofs.
        let mut proofs: Vec<_> = (0..5).map(|i| tree.get_proof(i).unwrap()).collect();
        // Verify: valid proofs should succeed.
        for (leaf, proof) in leaves.iter().zip(proofs.clone()) {
            assert!(proof.verify(leaf, &commitment));
        }
        // Mirror the leaf index to invalidate proofs.
        let mirror_index = |index: usize| {
            let height = MerkleTree::<()>::height_from_n_leaves(5);
            let capacity_for_leaves = 1 << height;
            let mirrored = capacity_for_leaves - 1 - index;
            println!("mirroring index from {index} to {mirrored}");
            u32::try_from(mirrored).unwrap()
        };
        // Corrupt each proof by modifying its leaf index.
        for (i, proof) in proofs.iter_mut().enumerate() {
            proof.leaf_index = mirror_index(i);
        }
        // Verify: corrupted proofs should fail.
        for (leaf, proof) in leaves.iter().zip(proofs) {
            assert!(!proof.verify(leaf, &commitment));
        }
    }
    #[test]
    fn singleton_commitment_domains_the_leaf_and_authenticates_count() {
        let leaf = test_hashes(1)[0];
        let tree: MerkleTree<()> = [leaf].into_iter().collect();
        let commitment = tree.commitment().expect("singleton commitment");
        let proof = tree.get_proof(0).expect("singleton proof");
        assert_eq!(commitment.leaf_count().get(), 1);
        assert_eq!(
            commitment.root(),
            &MerkleTree::<()>::leaf_hash(&leaf).transmute()
        );
        assert!(proof.verify(&leaf, &commitment));
        let wrong_count =
            MerkleTreeCommitment::new(*commitment.root(), NonZeroU64::new(2).expect("non-zero"));
        assert!(!proof.verify(&leaf, &wrong_count));
    }
    #[test]
    fn ragged_proof_requires_exact_some_none_geometry() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<()> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let proof = tree.get_proof(4).expect("rightmost proof");
        assert_eq!(
            proof
                .audit_path()
                .iter()
                .map(Option::is_some)
                .collect::<Vec<_>>(),
            vec![false, false, true]
        );
        assert!(proof.verify(&leaves[4], &commitment));
        let bogus = HashOf::from_untyped_unchecked(Hash::prehashed([0x44; Hash::LENGTH]));
        let mut filled_padding = proof.clone();
        filled_padding.audit_path[0] = Some(bogus);
        assert!(!filled_padding.verify(&leaves[4], &commitment));
        let mut missing_real_sibling = proof;
        missing_real_sibling.audit_path[2] = None;
        assert!(!missing_real_sibling.verify(&leaves[4], &commitment));
    }
    #[test]
    fn shielded_empty_root_matches_generic_leaf_and_internal_domains() {
        let raw_leaf = MerkleTree::<[u8; 32]>::shielded_leaf_from_commitment([0; 32]);
        let singleton: MerkleTree<[u8; 32]> = [raw_leaf].into_iter().collect();
        assert_eq!(
            singleton.root().expect("singleton root").as_ref(),
            &MerkleTree::<[u8; 32]>::shielded_empty_root(0)
        );
        let pair: MerkleTree<[u8; 32]> = [raw_leaf, raw_leaf].into_iter().collect();
        assert_eq!(
            pair.root().expect("pair root").as_ref(),
            &MerkleTree::<[u8; 32]>::shielded_empty_root(1)
        );
    }
    #[test]
    fn merkle_tree_roundtrip() {
        let tree: MerkleTree<_> = test_hashes(3).into_iter().collect();
        let bytes = norito::to_bytes(&tree).expect("encode");
        let archived = norito::from_bytes::<MerkleTree<()>>(&bytes).expect("failed to decode");
        let decoded = norito::core::DeserializePayload::deserialize(archived);
        assert_eq!(tree, decoded);
    }
    #[test]
    fn merkle_proof_roundtrip() {
        let leaves = test_hashes(3);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let proof = tree.get_proof(1).unwrap();
        let bytes = norito::to_bytes(&proof).expect("encode");
        let archived = norito::from_bytes::<MerkleProof<()>>(&bytes).expect("failed to decode");
        let decoded = norito::core::DeserializePayload::deserialize(archived);
        assert_eq!(proof, decoded);
    }
    #[test]
    fn merkle_proof_try_deserialize_rejects_malformed_archive_without_panicking() {
        struct MalformedMerkleProof;
        impl norito::NoritoSchema for MalformedMerkleProof {
            fn nominal_name() -> String {
                "test::iroha_crypto::malformed_merkle_proof".to_owned()
            }
            fn frame_name() -> String {
                <MerkleProof<()> as norito::NoritoSchema>::frame_name()
            }
        }

        impl norito::core::SerializePayload for MalformedMerkleProof {
            fn serialize(
                &self,
                writer: &mut norito::core::Encoder<'_>,
            ) -> Result<(), norito::core::Error> {
                let minimum = norito::core::archived_payload_size::<MerkleProof<()>>().max(16);
                let mut payload = vec![0_u8; minimum];
                payload[..8].copy_from_slice(&u64::MAX.to_le_bytes());
                writer.write_all(&payload)?;
                Ok(())
            }
        }
        let bytes = norito::to_bytes(&MalformedMerkleProof).expect("encode malformed fixture");
        let archived =
            norito::from_bytes::<MerkleProof<()>>(&bytes).expect("validate outer archive");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            <MerkleProof<()> as norito::core::DeserializePayload>::try_deserialize(archived)
        }));
        let error = outcome
            .expect("fallible Merkle proof decoding must not unwind")
            .expect_err("malformed Merkle proof must be rejected");
        assert!(matches!(
            error,
            norito::core::Error::LengthMismatch
                | norito::core::Error::SequenceLengthExceeded { .. }
                | norito::core::Error::AllocationFailed { .. }
        ));
    }
    #[cfg(feature = "rayon")]
    #[test]
    fn generic_parallel_equals_sequential() {
        let leaves = test_hashes(17);
        let seq: MerkleTree<()> = leaves.clone().into_iter().collect();
        let par: MerkleTree<()> = MerkleTree::from_typed_leaves_parallel(leaves);
        assert_eq!(seq.root(), par.root());
        // Compare a few proofs for equality as well
        for &idx in &[0u32, 4, 9, 16] {
            let p1 = seq.get_proof(idx).expect("proof");
            let p2 = par.get_proof(idx).expect("proof");
            assert_eq!(p1.audit_path(), p2.audit_path());
        }
    }
    #[test]
    fn into_audit_path_returns_path() {
        let tree: MerkleTree<_> = test_hashes(3).into_iter().collect();
        let proof = tree.get_proof(1).unwrap();
        let expected = proof.audit_path.clone();
        assert_eq!(proof.into_audit_path(), expected);
    }
    #[test]
    fn byte_tree_from_chunks_matches_manual() {
        // 35 bytes -> 2 leaves for chunk=32 (padded final chunk)
        let data: Vec<u8> = (0..35u8).collect();
        let chunk = 32;
        // Manual leaves: hash first 32 bytes, then hash zero-padded remainder
        let mut l0 = [0u8; 32];
        l0.copy_from_slice(&sha2::Sha256::digest(&data[..chunk]));
        let mut buf = [0u8; 32];
        buf[..(data.len() - chunk)].copy_from_slice(&data[chunk..]);
        let mut l1 = [0u8; 32];
        l1.copy_from_slice(&sha2::Sha256::digest(&buf[..chunk]));
        let manual: MerkleTree<[u8; 32]> = MerkleTree::from_hashed_leaves_sha256([l0, l1]);
        // Helper-based build
        let via_helper =
            MerkleTree::<[u8; 32]>::from_byte_chunks(&data, chunk).expect("valid chunk");
        assert_eq!(manual.root(), via_helper.root());
    }
    #[cfg(feature = "rayon")]
    #[test]
    fn byte_tree_parallel_equals_sequential() {
        let data: Vec<u8> = (0..150u32).map(|i| (i % 251) as u8).collect();
        let a = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let b =
            MerkleTree::<[u8; 32]>::from_chunked_bytes_parallel(&data, 32).expect("valid chunk");
        assert_eq!(a.root(), b.root());
    }
    #[test]
    fn hashed_leaves_sha256_empty_tree_has_no_root() {
        let tree = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(Vec::new());
        assert!(tree.root().is_none());
    }
    #[cfg(feature = "rayon")]
    #[test]
    fn hashed_leaves_sha256_parallel_empty_tree_has_no_root() {
        let tree = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256_parallel(Vec::new());
        assert!(tree.root().is_none());
    }
    #[test]
    fn byte_proof_verify_sha256() {
        let data: Vec<u8> = (0..90u32).map(|i| (i % 200) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32;
        let proof = tree.get_proof(idx).expect("proof");
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        assert!(proof.verify_sha256(&leaf, &commitment));
        // Corrupt the leaf index to invalidate
        let mut bad = proof;
        bad.leaf_index = idx + 1;
        assert!(!bad.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn borrowed_sha256_verifier_preserves_owned_shape_and_order_rules() {
        for count in [1_u32, 2, 3, 5, 8, 9] {
            let data: Vec<u8> = (0..count * 32).map(|i| (i % 251) as u8).collect();
            let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).unwrap();
            let commitment = tree.commitment().unwrap();
            for index in 0..count {
                let proof = tree.get_proof(index).unwrap();
                let leaf = tree.leaves().nth(index as usize).unwrap();
                let verify = |path: &[Option<HashOf<[u8; 32]>>], position| {
                    let owned = MerkleProof {
                        leaf_index: position,
                        audit_path: path.to_vec(),
                    };
                    let borrowed =
                        MerkleProof::verify_audit_path_sha256(position, path, &leaf, &commitment);
                    assert_eq!(borrowed, owned.verify_sha256(&leaf, &commitment));
                    borrowed
                };
                assert!(verify(&proof.audit_path, index));
                assert!(!verify(&proof.audit_path, count));
                let mut extra = proof.audit_path.clone();
                extra.push(None);
                assert!(!verify(&extra, index));
                if !proof.audit_path.is_empty() {
                    assert!(!verify(
                        &proof.audit_path[..proof.audit_path.len() - 1],
                        index
                    ));
                }
                for sibling in 0..proof.audit_path.len() {
                    let mut altered = proof.audit_path.clone();
                    altered[sibling] = if altered[sibling].is_some() {
                        None
                    } else {
                        Some(leaf)
                    };
                    assert!(!verify(&altered, index));
                }
                if proof.audit_path.len() > 1 {
                    let mut reversed = proof.audit_path.clone();
                    reversed.reverse();
                    if reversed != proof.audit_path {
                        assert!(!verify(&reversed, index));
                    }
                }
            }
        }
    }
    #[test]
    fn byte_proof_rejects_out_of_range_leaf_index_sha256() {
        let data: Vec<u8> = (0..90u32).map(|i| (i % 200) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut proof = tree.get_proof(idx).expect("proof");
        let height = proof.audit_path.len();
        let height_u32 = u32::try_from(height).expect("height fits in u32");
        proof.leaf_index = 1u32 << height_u32;
        assert!(proof.compute_partial_root_sha256(&leaf, height).is_none());
        assert!(!proof.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn byte_proof_compute_partial_root_sha256_matches_root() {
        let data: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let root = tree.root().expect("root");
        let idx = 1u32;
        let proof = tree.get_proof(idx).expect("proof");
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let computed = proof
            .compute_partial_root_sha256(&leaf, proof.audit_path().len())
            .expect("computed root");
        assert_eq!(root, computed);
    }
    #[test]
    fn compact_proof_roundtrip_and_verify() {
        let leaves = test_hashes(10);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 7u32;
        let leaf = leaves[idx as usize];
        let full = tree.get_proof(idx).expect("proof");
        // Compact conversion + verify
        let compact = CompactMerkleProof::try_from_full(full.clone()).expect("compact proof");
        assert!(compact.verify(&leaf, &commitment));
        // Expand back to full and compare the authenticated index and audit path.
        let expanded = compact.try_into_full().expect("canonical compact proof");
        assert_eq!(expanded.leaf_index(), idx);
        assert_eq!(full.audit_path(), expanded.audit_path());
    }
    #[test]
    fn compact_proof_dirs_match_leaf_index_bits() {
        let leaves = test_hashes(8);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        for idx in 0..8u32 {
            let leaf = leaves[idx as usize];
            let full = tree.get_proof(idx).expect("proof");
            let compact = CompactMerkleProof::try_from_full(full).expect("compact proof");
            let depth = compact.depth() as usize;
            let mask = (1u64 << depth) - 1;
            assert_eq!(
                u64::from(compact.dirs()),
                u64::from(idx) & mask,
                "dirs mismatch at idx={idx}"
            );
            assert!(compact.verify(&leaf, &commitment));
        }
    }
    #[test]
    fn compact_proof_sha256_dirs_match_leaf_index_bits() {
        let data: Vec<u8> = (0..128u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 2u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let full = tree.get_proof(idx).expect("proof");
        let compact = CompactMerkleProof::try_from_full(full).expect("compact proof");
        let depth = compact.depth() as usize;
        let mask = (1u64 << depth) - 1;
        assert_eq!(u64::from(compact.dirs()), u64::from(idx) & mask);
        assert!(compact.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn compact_proof_computes_explicit_partial_sha256_root() {
        let data: Vec<u8> = (0..128u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let idx = 2u32;
        let leaf = tree.leaves().nth(idx as usize).expect("leaf");
        let compact = CompactMerkleProof::try_from_full(
            tree.get_proof(idx).expect("proof for an existing leaf"),
        )
        .expect("compact proof");
        assert_eq!(
            compact.compute_partial_root_sha256(&leaf),
            tree.root(),
            "a complete compact path reconstructs the tree root"
        );
        let noncanonical = CompactMerkleProof::from_parts(
            compact.depth(),
            compact.dirs() | (1_u32 << u32::from(compact.depth())),
            compact.siblings().to_vec(),
        );
        assert!(noncanonical.compute_partial_root_sha256(&leaf).is_none());
    }
    #[test]
    fn compact_proof_rejects_sibling_length_mismatch() {
        let leaves = test_hashes(8);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 5u32;
        let leaf = leaves[idx as usize];
        let mut compact = CompactMerkleProof::try_from_full(tree.get_proof(idx).expect("proof"))
            .expect("compact proof");
        compact.siblings.pop();
        assert!(!compact.verify(&leaf, &commitment));
    }
    #[test]
    fn compact_proof_rejects_unused_direction_bits() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<()> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 4u32;
        let mut compact = CompactMerkleProof::try_from_full(tree.get_proof(idx).expect("proof"))
            .expect("compact proof");
        compact.dirs |= 1u32 << u32::from(compact.depth);
        assert!(!compact.verify(&leaves[idx as usize], &commitment));
        assert!(matches!(
            compact.try_into_full(),
            Err(MerkleError::NonCanonicalCompactProof)
        ));
    }
    #[test]
    fn compact_proof_max_depth_matches_direction_bit_width() {
        assert_eq!(
            u32::from(COMPACT_MERKLE_PROOF_MAX_DEPTH),
            u32::BITS,
            "compact proof depth must match the u32 direction bitset width"
        );
    }
    #[test]
    fn compact_proof_rejects_audit_path_over_depth_limit() {
        let sibling: HashOf<()> =
            HashOf::from_untyped_unchecked(Hash::prehashed([0x11; Hash::LENGTH]));
        let full = MerkleProof::from_audit_path(0, vec![Some(sibling); 40]);
        let error = CompactMerkleProof::try_from_full(full).expect_err("must not truncate proof");
        assert!(matches!(
            error,
            MerkleError::CompactProofTooDeep { depth: 40, .. }
        ));
    }
    #[test]
    fn compact_proof_rejects_depth_over_32() {
        let leaves = test_hashes(6);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 2u32;
        let leaf = leaves[idx as usize];
        let mut compact = CompactMerkleProof::try_from_full(tree.get_proof(idx).expect("proof"))
            .expect("compact proof");
        compact.depth = 33;
        while compact.siblings.len() < 33 {
            compact.siblings.push(None);
        }
        assert!(!compact.verify(&leaf, &commitment));
    }
    #[test]
    fn compact_proof_sha256_rejects_sibling_length_mismatch() {
        let data: Vec<u8> = (0..96u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut compact = CompactMerkleProof::try_from_full(tree.get_proof(idx).expect("proof"))
            .expect("compact proof");
        compact.siblings.pop();
        assert!(!compact.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn compact_proof_sha256_rejects_depth_over_32() {
        let data: Vec<u8> = (0..96u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut compact = CompactMerkleProof::try_from_full(tree.get_proof(idx).expect("proof"))
            .expect("compact proof");
        compact.depth = 33;
        while compact.siblings.len() < 33 {
            compact.siblings.push(None);
        }
        assert!(!compact.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn byte_proof_tamper_audit_path_fails_sha256() {
        let data: Vec<u8> = (0..120u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 2u32;
        let mut proof = tree.get_proof(idx).expect("proof");
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        assert!(proof.verify_sha256(&leaf, &commitment));
        // Tamper with the first sibling (if any), otherwise set first path element.
        if let Some(slot) = proof.audit_path.iter_mut().find(|s| s.is_some()) {
            *slot = Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                [0xAA; Hash::LENGTH],
            )));
        } else if !proof.audit_path.is_empty() {
            proof.audit_path[0] = Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                [0x55; Hash::LENGTH],
            )));
        }
        assert!(!proof.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn proof_truncated_path_fails() {
        let leaves = test_hashes(7);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 3u32;
        let leaf = leaves[idx as usize];
        let mut proof = tree.get_proof(idx).expect("proof");
        // Remove the last sibling in the path (toward the root)
        proof.audit_path.pop();
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn proof_rejects_out_of_range_leaf_index() {
        let leaves = test_hashes(6);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32;
        let leaf = leaves[idx as usize];
        let mut proof = tree.get_proof(idx).expect("proof");
        let height = proof.audit_path.len();
        let height_u32 = u32::try_from(height).expect("height fits in u32");
        proof.leaf_index = 1u32 << height_u32;
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn proof_extended_path_fails() {
        let leaves = test_hashes(6);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        let idx = 2u32;
        let leaf = leaves[idx as usize];
        let mut proof = tree.get_proof(idx).expect("proof");
        // Append an extra bogus sibling at the end of the path
        proof
            .audit_path
            .push(Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                [0x42; Hash::LENGTH],
            ))));
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn byte_proof_reversed_order_fails_sha256() {
        let data: Vec<u8> = (0..120u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 2u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut proof = tree.get_proof(idx).expect("proof");
        // Reverse the audit path orientation (root->leaf instead of leaf->root)
        proof.audit_path.reverse();
        assert!(!proof.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn proof_right_only_child_fails() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        // Choose an index with even initial tree index so that (l=None, r=Some) occurs when sibling is None.
        let idx = 1u32; // ensures even parity at first step for typical heights
        let leaf = leaves[idx as usize];
        let mut proof = tree.get_proof(idx).expect("proof");
        if !proof.audit_path.is_empty() {
            proof.audit_path[0] = None;
        }
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn byte_proof_right_only_child_fails_sha256() {
        let data: Vec<u8> = (0..96u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let idx = 1u32; // even parity at first step
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut proof = tree.get_proof(idx).expect("proof");
        if !proof.audit_path.is_empty() {
            proof.audit_path[0] = None;
        }
        assert!(!proof.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn proof_right_only_child_deeper_fails() {
        // Build a tree with enough height to have deeper steps
        let leaves = test_hashes(9);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let commitment = tree.commitment().expect("commitment");
        // Pick an index that has an even step at depth > 0; try candidates
        let mut picked = None;
        for idx in 0..u32::try_from(leaves.len()).expect("leaves length fits in u32") {
            if let Some(step) = find_deeper_even_step::<()>(idx, tree.height() as usize) {
                picked = Some((idx, step));
                break;
            }
        }
        let (idx, step) = picked.expect("found a deeper even step");
        let leaf = leaves[idx as usize];
        let mut proof = tree.get_proof(idx).expect("proof");
        // Force a right-only child at the chosen deeper step
        proof.audit_path[step] = None;
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn typed_incremental_update_matches_rebuild() {
        // Build initial tree from typed leaves
        let mut leaves: Vec<HashOf<()>> = (0u8..16)
            .map(|i| Hash::prehashed([i; Hash::LENGTH]))
            .map(HashOf::from_untyped_unchecked)
            .collect();
        let mut tree: MerkleTree<()> = leaves.clone().into_iter().collect();
        let baseline_root = tree.root().expect("root");
        // Apply two updates using incremental typed API
        let new_a = HashOf::from_untyped_unchecked(Hash::prehashed([0xAA; Hash::LENGTH]));
        let new_b = HashOf::from_untyped_unchecked(Hash::prehashed([0xBB; Hash::LENGTH]));
        tree.update_typed_leaf(3, new_a);
        tree.update_typed_leaf(11, new_b);
        // Build a fresh tree from updated leaves for conformance
        leaves[3] = new_a;
        leaves[11] = new_b;
        let rebuilt: MerkleTree<()> = leaves.clone().into_iter().collect();
        assert_ne!(baseline_root, rebuilt.root().expect("root"));
        assert_eq!(tree.root(), rebuilt.root());
        // Compare proofs at a few indices
        for &idx in &[0u32, 3, 7, 11, 15] {
            let p1 = tree.get_proof(idx).expect("proof");
            let p2 = rebuilt.get_proof(idx).expect("proof");
            assert_eq!(p1.audit_path(), p2.audit_path());
        }
    }
    #[test]
    fn sha256_incremental_update_preserves_scheme_and_cache() {
        let mut leaves = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        let mut tree = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(leaves);
        leaves[2] = [0xAA; 32];
        tree.update_hashed_leaf_sha256(2, leaves[2]);
        let rebuilt = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(leaves);
        assert_eq!(tree, rebuilt);
        assert_eq!(tree.hash_scheme, MerkleHashScheme::Sha256V1);
        assert_eq!(
            tree.serialized_parts().expect("canonical SHA-256 cache").0,
            MERKLE_HASH_SCHEME_SHA256_V1
        );
    }
    #[test]
    fn byte_proof_right_only_child_deeper_fails_sha256() {
        let data: Vec<u8> = (0..320u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let commitment = tree.commitment().expect("commitment");
        let n = data.len().div_ceil(32);
        let mut picked = None;
        for idx in 0..u32::try_from(n).expect("n fits in u32") {
            if let Some(step) = find_deeper_even_step::<[u8; 32]>(idx, tree.height() as usize) {
                picked = Some((idx, step));
                break;
            }
        }
        let (idx, step) = picked.expect("found a deeper even step for bytes");
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let mut proof = tree.get_proof(idx).expect("proof");
        proof.audit_path[step] = None;
        assert!(!proof.verify_sha256(&leaf, &commitment));
    }
    #[test]
    fn proof_rejects_wrong_committed_leaf_count() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<_> = leaves.clone().into_iter().collect();
        let root = tree.root().expect("root");
        let idx = 4u32;
        let leaf = leaves[idx as usize];
        let proof = tree.get_proof(idx).expect("proof");
        let wrong_count = MerkleTreeCommitment::new(root, NonZeroU64::new(8).unwrap());
        assert!(!proof.verify(&leaf, &wrong_count));
    }
    #[test]
    fn proof_rejects_commitment_beyond_u32_index_space() {
        let leaf = test_hashes(1)[0];
        let sibling = HashOf::from_untyped_unchecked(Hash::new(b"oversized tree sibling"));
        let audit_path = vec![Some(sibling); 33];
        let mut root = MerkleTree::<()>::leaf_hash(&leaf);
        for sibling in &audit_path {
            root = MerkleTree::<()>::pair_hash(Some(&root), sibling.as_ref())
                .expect("both children are present");
        }
        let commitment = MerkleTreeCommitment::new(
            root.transmute(),
            NonZeroU64::new(MERKLE_PROOF_MAX_LEAF_COUNT + 1).expect("non-zero count"),
        );
        let proof = MerkleProof::from_audit_path(0, audit_path);
        assert!(
            !proof.verify(&leaf, &commitment),
            "a u32-indexed proof must not authenticate a larger tree"
        );
    }
    #[test]
    fn byte_proof_rejects_wrong_committed_leaf_count_sha256() {
        let data: Vec<u8> = (0..96u32).map(|i| (i % 251) as u8).collect();
        let tree = MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).expect("valid chunk");
        let root = tree.root().expect("root");
        let idx = 2u32;
        let leaf = tree.leaves().nth(idx as usize).unwrap();
        let proof = tree.get_proof(idx).expect("proof");
        let wrong_count = MerkleTreeCommitment::new(root, NonZeroU64::new(4).unwrap());
        assert!(!proof.verify_sha256(&leaf, &wrong_count));
    }
    #[test]
    fn from_byte_chunks_rejects_invalid_chunk_size() {
        let data = [0u8; 4];
        assert!(matches!(
            MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 0),
            Err(MerkleError::InvalidChunkSize { .. })
        ));
        assert!(matches!(
            MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 64),
            Err(MerkleError::InvalidChunkSize { .. })
        ));
    }
    #[cfg(feature = "rayon")]
    #[test]
    fn from_chunked_bytes_parallel_rejects_invalid_chunk_size() {
        let data = [0u8; 4];
        assert!(matches!(
            MerkleTree::<[u8; 32]>::from_chunked_bytes_parallel(&data, 0),
            Err(MerkleError::InvalidChunkSize { .. })
        ));
    }
    #[test]
    fn merkle_proof_verify_rejects_oversized_height() {
        let leaf = HashOf::from_untyped_unchecked(Hash::prehashed([0x11; Hash::LENGTH]));
        let root =
            HashOf::<MerkleTree<()>>::from_untyped_unchecked(Hash::prehashed([0x22; Hash::LENGTH]));
        let commitment = MerkleTreeCommitment::new(root, NonZeroU64::new(1).unwrap());
        let proof = MerkleProof::from_audit_path(0, vec![None; usize::BITS as usize]);
        assert!(!proof.verify(&leaf, &commitment));
    }
    #[test]
    fn merkle_tree_encode_rejects_invalid_layout() {
        let bad_leaf: HashOf<()> =
            HashOf::from_untyped_unchecked(Hash::prehashed([0xAA; Hash::LENGTH]));
        let bad_tree = raw_application_tree::<()>(vec![Some(bad_leaf), Some(bad_leaf)]);
        let err = norito::to_bytes(&bad_tree).expect_err("invalid merkle layout should fail");
        assert!(matches!(err, norito::Error::Message(_)));
    }
    #[test]
    fn merkle_tree_encode_rejects_missing_nodes() {
        let bad_tree = raw_application_tree::<()>(vec![None]);
        let err = norito::to_bytes(&bad_tree).expect_err("missing nodes should fail");
        assert!(matches!(err, norito::Error::Message(_)));
    }
    #[test]
    fn merkle_tree_encode_rejects_missing_parent() {
        let leaf: HashOf<()> =
            HashOf::from_untyped_unchecked(Hash::prehashed([0xAB; Hash::LENGTH]));
        let bad_tree = raw_application_tree::<()>(vec![
            Some(leaf),
            None,
            Some(leaf),
            Some(leaf),
            Some(leaf),
            Some(leaf),
            Some(leaf),
        ]);
        let err = norito::to_bytes(&bad_tree).expect_err("missing parent should fail");
        assert!(matches!(err, norito::Error::Message(_)));
    }
    #[test]
    fn merkle_tree_wire_omits_cached_nodes_and_rebuilds_them() {
        let leaves = test_hashes(5);
        let tree: MerkleTree<()> = leaves.into_iter().collect();
        let root = tree.root().expect("non-empty root");
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(&tree, &mut payload).expect("serialize leaf-only tree");
        assert!(
            !payload
                .windows(Hash::LENGTH)
                .any(|window| window == root.as_ref()),
            "the cached root must not be present in the tree payload"
        );
        let bytes = norito::to_bytes(&tree).expect("encode canonical tree");
        let decoded = norito::decode_from_bytes::<MerkleTree<()>>(&bytes)
            .expect("decode and rebuild canonical tree");
        assert_eq!(decoded, tree);
        assert_eq!(decoded.root(), Some(root));
    }
    #[test]
    fn merkle_tree_decode_rejects_legacy_cached_node_vector() {
        let tree: MerkleTree<()> = test_hashes(5).into_iter().collect();
        let mut legacy_payload = Vec::new();
        norito::core::serialize_to_buffer(&tree.nodes, &mut legacy_payload)
            .expect("encode legacy cached-node vector fixture");
        let error =
            <MerkleTree<()> as norito::core::DecodeFromSlice>::decode_from_slice(&legacy_payload)
                .expect_err("cached parents and root must never be accepted from the wire");
        assert!(!legacy_payload.is_empty());
        assert!(
            !error.to_string().is_empty(),
            "legacy cached-node wire must fail with a concrete decode error"
        );
    }
    #[test]
    fn merkle_tree_encode_rejects_tampered_cached_root() {
        let mut tree: MerkleTree<()> = test_hashes(4).into_iter().collect();
        tree.nodes[0] = Some(HashOf::from_untyped_unchecked(Hash::new(
            b"attacker supplied cached root",
        )));
        let error = norito::to_bytes(&tree).expect_err("tampered cache must not serialize");
        assert!(error.to_string().contains("cached nodes"));
    }
    #[test]
    fn merkle_tree_encode_validates_cache_against_retained_scheme() {
        let mut tree: MerkleTree<()> = test_hashes(4).into_iter().collect();
        tree.hash_scheme = MerkleHashScheme::Sha256V1;
        let error = norito::to_bytes(&tree)
            .expect_err("application cache must not serialize under the SHA-256 scheme");
        assert!(error.to_string().contains("cached nodes"));
    }
    #[test]
    fn merkle_tree_sha256_wire_roundtrip_preserves_hash_scheme() {
        let leaves = [[0x11; 32], [0x22; 32], [0x33; 32]];
        let tree = MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256(leaves);
        let bytes = norito::to_bytes(&tree).expect("encode SHA-256 tree leaves");
        let decoded = norito::decode_from_bytes::<MerkleTree<[u8; 32]>>(&bytes)
            .expect("decode SHA-256 tree leaves");
        assert_eq!(decoded, tree);
        assert_eq!(decoded.root(), tree.root());
    }
    #[test]
    fn merkle_tree_sha256_ambiguous_shapes_retain_their_scheme() {
        for tree in [
            MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256([]),
            MerkleTree::<[u8; 32]>::from_hashed_leaves_sha256([[0x44; 32]]),
        ] {
            assert_eq!(tree.hash_scheme, MerkleHashScheme::Sha256V1);
            let bytes = norito::to_bytes(&tree).expect("encode SHA-256 tree");
            let decoded = norito::decode_from_bytes::<MerkleTree<[u8; 32]>>(&bytes)
                .expect("decode SHA-256 tree");
            assert_eq!(decoded.hash_scheme, MerkleHashScheme::Sha256V1);
            assert_eq!(decoded, tree);
            assert_eq!(
                decoded.serialized_parts().expect("canonical tree").0,
                MERKLE_HASH_SCHEME_SHA256_V1
            );
        }
    }
    #[cfg(feature = "json")]
    #[test]
    fn merkle_tree_json_carries_only_scheme_and_leaves() {
        let tree: MerkleTree<()> = test_hashes(3).into_iter().collect();
        let json = norito::json::to_json(&tree).expect("serialize leaf-only tree JSON");
        assert_eq!(
            norito::json::to_json_bounded(&tree, json.len()).expect("bounded tree JSON"),
            json
        );
        assert_eq!(
            norito::json::to_json_bounded(&tree, json.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
        assert!(json.contains("\"hash_scheme\":1"));
        assert!(json.contains("\"leaves\""));
        assert!(
            !json.contains("\"root\""),
            "cached root must not be serialized"
        );
        let decoded: MerkleTree<()> =
            norito::json::from_str(&json).expect("decode and rebuild tree JSON");
        assert_eq!(decoded, tree);
        let unsupported = r#"{"hash_scheme":255,"leaves":[]}"#;
        let error = norito::json::from_str::<MerkleTree<()>>(unsupported)
            .expect_err("unknown JSON scheme must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported merkle tree hash scheme")
        );
        let invalid = raw_application_tree::<()>(vec![None]);
        let fallback = norito::json::to_json(&invalid).expect("serialize invalid tree fallback");
        assert_eq!(fallback, r#"{"hash_scheme":0,"leaves":[]}"#);
        assert_eq!(
            norito::json::to_json_bounded(&invalid, fallback.len())
                .expect("bounded invalid tree fallback"),
            fallback
        );
    }
    #[cfg(feature = "json")]
    #[test]
    fn merkle_tree_json_leaf_decode_is_bounded() {
        let leaf_json = norito::json::to_json(&test_hashes(1)[0]).expect("serialize leaf JSON");
        let leaf_count = SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1;
        let mut json = String::with_capacity(leaf_json.len().saturating_mul(leaf_count));
        json.push_str(r#"{"hash_scheme":1,"leaves":["#);
        for index in 0..leaf_count {
            if index != 0 {
                json.push(',');
            }
            json.push_str(&leaf_json);
        }
        json.push_str("]}");
        let error = norito::json::from_str::<MerkleTree<()>>(&json)
            .expect_err("oversized JSON leaf set must fail at the tree bound");
        assert!(error.to_string().contains("maximum is"));
    }
    #[test]
    fn merkle_tree_decode_rejects_unknown_hash_scheme() {
        let leaves = vec![test_hashes(1)[0]];
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(&(u8::MAX, leaves), &mut payload)
            .expect("encode malformed wire fixture");
        let error = <MerkleTree<()> as norito::core::DecodeFromSlice>::decode_from_slice(&payload)
            .expect_err("unknown scheme must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported merkle tree hash scheme")
        );
    }
    #[test]
    fn merkle_tree_decode_rejects_oversized_count_before_leaf_allocation() {
        let mut payload = Vec::new();
        norito::core::serialize_to_buffer(
            &(MERKLE_HASH_SCHEME_APPLICATION_V1, Vec::<HashOf<()>>::new()),
            &mut payload,
        )
        .expect("encode empty tree wire fixture");
        let (scheme_len, scheme_header) =
            norito::core::read_len_dyn_slice(&payload).expect("read scheme field length");
        let leaves_field_header = scheme_header + scheme_len;
        let (_, leaves_header) = norito::core::read_len_dyn_slice(&payload[leaves_field_header..])
            .expect("read leaves field length");
        let count_offset = leaves_field_header + leaves_header;
        let oversized_count = u64::try_from(SERIALIZED_MERKLE_TREE_MAX_LEAVES_V1 + 1)
            .expect("leaf cap fits u64")
            .to_le_bytes();
        payload[count_offset..count_offset + 8].copy_from_slice(&oversized_count);
        let error = <MerkleTree<()> as norito::core::DecodeFromSlice>::decode_from_slice(&payload)
            .expect_err("oversized tree must fail");
        assert!(error.to_string().contains("maximum is"));
    }
}

#[cfg(all(test, feature = "json"))]
#[path = "merkle/checked_json_cleanup_tests.rs"]
mod checked_json_cleanup_tests;
