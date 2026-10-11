//! AMX proofs: the sparse-Merkle path of a record's write, the certified block that commits it,
//! and the record and handoff proofs relayed between instances (§11.4, §11.6, §11.7).
//!
//! The write set of a block is the canonical last-write-wins set of its execution witness. Its
//! root (`ExecutionCommitment::ordinary_writes_root`, part of the certified result `R`) is a
//! binary sparse Merkle tree of depth 256 over `H(key)`: a leaf is `H(0x00 ‖ H(key) ‖ H(value))`,
//! an inner node `H(0x01 ‖ left ‖ right)`, an empty subtree `H("")`, and the node at depth `L`
//! branches on bit `L` of `H(key)` (bit `i` is bit `i mod 8` of byte `i / 8`).

use iroha_crypto::Hash;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{AmxError, AmxRecordV1};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, block::CommitCertificate,
    sumeragi_finality::ExecutionResultCommitment,
};

/// Depth of the write-set tree.
const DEPTH: usize = 256;
/// Largest canonical core header accepted in a proof.
pub const MAX_AMX_HEADER_BYTES: usize = 8 * 1024;
/// Finite canonical `CommitQC` frame bound for the exact-quorum BLS proof reader.
pub const MAX_AMX_QC_BYTES: usize = 128 * 1024;

fn empty() -> Hash {
    Hash::new([])
}

fn leaf(key: &[u8], value: &[u8]) -> Hash {
    let path = Hash::new(key);
    let value = Hash::new(value);
    Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()])
}

fn node(left: &Hash, right: &Hash) -> Hash {
    Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()])
}

fn bit(path: &[u8; 32], index: usize) -> bool {
    path[index / 8] & (1 << (index % 8)) != 0
}

/// The sparse-Merkle path of one write: the non-empty siblings from the leaf level up, and a
/// bitmap of the levels that have one (bit `l` of the map = level `l`, the leaf level is 0).
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxWriteProofV1")]
pub struct AmxWriteProofV1 {
    /// Levels with a non-empty sibling.
    #[norito(
        with = "crate::json_helpers::fixed_bytes_hex",
        bounded_with = "crate::json_helpers::fixed_bytes_hex::serialize_bounded"
    )]
    pub present: [u8; 32],
    /// The non-empty siblings, leaf level first.
    pub siblings: Vec<[u8; 32]>,
}

impl AmxWriteProofV1 {
    /// The root this path proves for the write `(key, value)`.
    ///
    /// # Errors
    /// The sibling count differs from the bitmap.
    pub fn root(&self, key: &[u8], value: &[u8]) -> Result<Hash, AmxError> {
        let present = self
            .present
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum::<usize>();
        if present != self.siblings.len() {
            return Err(AmxError::Proof(
                "sibling count differs from the bitmap".into(),
            ));
        }
        let path: [u8; 32] = Hash::new(key).into();
        let mut current = leaf(key, value);
        let mut siblings = self.siblings.iter();
        for level in 0..DEPTH {
            let sibling = if bit(&self.present, level) {
                let Some(sibling) = siblings.next() else {
                    return Err(AmxError::Proof("missing sibling".into()));
                };
                Hash::from_marked_bytes(*sibling)
                    .ok_or_else(|| AmxError::Proof("sibling is not a chain hash".into()))?
            } else {
                empty()
            };
            current = if bit(&path, DEPTH - level - 1) {
                node(&sibling, &current)
            } else {
                node(&current, &sibling)
            };
        }
        Ok(current)
    }

    /// Build the path of `key` in the write set `writes` (canonical last write wins per key).
    /// Returns the path and the value of the key's last write.
    ///
    /// # Errors
    /// The key is not written, or two different keys collide on `H(key)`.
    pub fn from_writes<'a>(
        writes: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        key: &[u8],
    ) -> Result<(Self, Vec<u8>), AmxError> {
        let leaves = canonical_leaves(writes)?;
        let target: [u8; 32] = Hash::new(key).into();
        let index = leaves
            .binary_search_by_key(&target, |leaf| leaf.path)
            .map_err(|_| AmxError::Proof("the key is not in the write set".into()))?;
        let value = leaves[index].value.to_vec();
        let mut siblings_top_down = Vec::with_capacity(DEPTH);
        let mut subset: Vec<&Leaf<'_>> = leaves.iter().collect();
        for depth in 0..DEPTH {
            let (same, other): (Vec<&Leaf<'_>>, Vec<&Leaf<'_>>) = subset
                .into_iter()
                .partition(|leaf| bit(&leaf.path, depth) == bit(&target, depth));
            siblings_top_down.push(subtree(&other, depth + 1));
            subset = same;
        }
        let mut present = [0; 32];
        let mut siblings = Vec::new();
        for (level, sibling) in siblings_top_down.iter().rev().enumerate() {
            if *sibling != empty() {
                present[level / 8] |= 1 << (level % 8);
                siblings.push(<[u8; 32]>::from(*sibling));
            }
        }
        Ok((Self { present, siblings }, value))
    }
}

/// The root of a write set (canonical last write wins per key), as `R`'s ordinary-write root.
///
/// # Errors
/// Two different keys collide on `H(key)`.
pub fn write_set_root<'a>(
    writes: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Hash, AmxError> {
    let leaves = canonical_leaves(writes)?;
    let all: Vec<&Leaf<'_>> = leaves.iter().collect();
    Ok(subtree(&all, 0))
}

struct Leaf<'a> {
    path: [u8; 32],
    key: &'a [u8],
    value: &'a [u8],
    hash: Hash,
}

/// The leaves of a write set sorted by path, the last write of each key kept.
fn canonical_leaves<'a>(
    writes: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<Vec<Leaf<'a>>, AmxError> {
    let mut leaves: Vec<(usize, Leaf<'a>)> = writes
        .into_iter()
        .enumerate()
        .map(|(order, (key, value))| {
            (
                order,
                Leaf {
                    path: Hash::new(key).into(),
                    key,
                    value,
                    hash: leaf(key, value),
                },
            )
        })
        .collect();
    leaves.sort_by(|(left_order, left), (right_order, right)| {
        left.path.cmp(&right.path).then(left_order.cmp(right_order))
    });
    let mut out: Vec<Leaf<'a>> = Vec::with_capacity(leaves.len());
    for (_, leaf) in leaves {
        match out.last_mut() {
            Some(last) if last.path == leaf.path => {
                if last.key != leaf.key {
                    return Err(AmxError::Proof("write keys collide on their path".into()));
                }
                *last = leaf;
            }
            _ => out.push(leaf),
        }
    }
    Ok(out)
}

/// The root of the subtree at `depth` holding exactly `leaves`.
fn subtree(leaves: &[&Leaf<'_>], depth: usize) -> Hash {
    match leaves {
        [] => empty(),
        [only] if depth == DEPTH => only.hash,
        _ => {
            let (left, right): (Vec<&Leaf<'_>>, Vec<&Leaf<'_>>) =
                leaves.iter().partition(|leaf| !bit(&leaf.path, depth));
            node(&subtree(&left, depth + 1), &subtree(&right, depth + 1))
        }
    }
}

/// A certified block of a Sumeragi instance, without its payload: the canonical core header,
/// its `CommitQC` and the canonical preimage of the certified result `R` (the three parts of the
/// block's `CommitCertificate`).
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxCertifiedBlockV1")]
pub struct AmxCertifiedBlockV1 {
    /// Canonical core `BlockHeader`.
    #[norito(
        with = "crate::json_helpers::base64_vec",
        bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
    )]
    pub consensus_header: Vec<u8>,
    /// Canonical `CommitQC` of the header.
    #[norito(
        with = "crate::json_helpers::base64_vec",
        bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
    )]
    pub commit_qc: Vec<u8>,
    /// Canonical preimage of `R` (`ExecutionResultCommitment`).
    #[norito(
        with = "crate::json_helpers::base64_vec",
        bounded_with = "crate::json_helpers::base64_vec::serialize_bounded"
    )]
    pub result_preimage: Vec<u8>,
}

impl AmxCertifiedBlockV1 {
    /// The three parts of a stored block's commit certificate. Genesis carries a result-only
    /// certificate, which no tracker accepts.
    #[must_use]
    pub fn from_certificate(certificate: &CommitCertificate) -> Self {
        Self {
            consensus_header: certificate.consensus_header().to_vec(),
            commit_qc: certificate.commit_qc().to_vec(),
            result_preimage: certificate.result_preimage().to_vec(),
        }
    }
}

/// A proof that an instance recorded `record`: the certified block that wrote it and the path of
/// the write in that block's ordinary-write root (§11.4, §11.6).
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxRecordProofV1")]
pub struct AmxRecordProofV1 {
    /// The certified block.
    pub block: AmxCertifiedBlockV1,
    /// The proven record.
    pub record: AmxRecordV1,
    /// The path of the record's write.
    pub write: AmxWriteProofV1,
}

impl AmxRecordProofV1 {
    /// Build a record proof from the block's certificate and the write set its execution
    /// produced (the complete execution witness writes, including mandatory context writes).
    /// The resulting path must match the ordinary-write root in the canonical result preimage.
    /// This checks the supplied write set; the receiving foreign-instance tracker still
    /// authenticates the certificate and its binding to that preimage.
    ///
    /// # Errors
    /// The result preimage is malformed or exceeds its bound, the record is not written in
    /// `writes`, its written value is not the record, or the write set differs from the result.
    pub fn from_writes<'a>(
        block: AmxCertifiedBlockV1,
        writes: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        record: AmxRecordV1,
    ) -> Result<Self, AmxError> {
        let commitment = ExecutionResultCommitment::decode(&block.result_preimage)
            .map_err(|error| super::commitment_error(&error))?;
        let key = record.witness_key();
        let (write, value) = AmxWriteProofV1::from_writes(writes, &key)?;
        if value != record.witness_value()? {
            return Err(AmxError::Proof(
                "the written value is not the record".into(),
            ));
        }
        if write.root(&key, &value)? != commitment.execution.ordinary_writes_root {
            return Err(AmxError::Proof(
                "the write set differs from the block's ordinary-write root".into(),
            ));
        }
        Ok(Self {
            block,
            record,
            write,
        })
    }

    /// The ordinary-write root this proof's path yields for its record.
    ///
    /// # Errors
    /// A malformed record or path.
    pub fn claimed_root(&self) -> Result<Hash, AmxError> {
        self.record.validate()?;
        self.write
            .root(&self.record.witness_key(), &self.record.witness_value()?)
    }
}

/// A handoff proof (§11.7): the certified last block `s − 1` of a tracked epoch `e`, whose result
/// commits the complete authenticated context of epoch `e + 1` (its boundary decision).
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
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sumeragi_amx::AmxHandoffProofV1")]
pub struct AmxHandoffProofV1 {
    /// The certified boundary block.
    pub block: AmxCertifiedBlockV1,
}
