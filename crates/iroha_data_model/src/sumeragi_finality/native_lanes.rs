//! Fixed native result proof of the complete lane-lane state, including authenticated absence.
//!
//! The proof travels in the sole canonical result preimage and therefore shares its original
//! certificate/storage owner. Construction borrows the original witness and funds its only
//! dynamic scratch allocation from the original execution pool.

use crate::{NetworkId, block::consensus::ExecWitness};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use iroha_crypto::Hash;
use norito::{Decode, Encode};
use thiserror::Error;

use super::lane_state_commitment::SumeragiLaneStateCommitment;
use crate::sumeragi_lanes::SumeragiLaneState;

/// The one ordinary `StatePath` which commits the complete native lane lane state.
pub const SUMERAGI_LANE_STATE_WITNESS_KEY: &[u8] = b"iroha:sumeragi:lane-state:v1";

const DEPTH: usize = 256;
const COMMITMENT_BYTES: usize = 512;

/// The exact fixed-key lane-state commitment and its complete ordinary-write SMT path.
///
/// Decoding this value grants no authority. Its root must match an independently authenticated
/// native execution result at the exact network and carrier height. All fields have fixed size;
/// the 256 siblings use eight fixed groups of 32, preserving the existing 96-item
/// decoder bound without a sibling vector or fallback layout.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema, iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::NativeLaneStateProof")]
pub struct NativeLaneStateProof {
    commitment: SumeragiLaneStateCommitment,
    siblings: [[Hash; 32]; 8],
}

/// Why an original witness could not produce its mandatory native lane state proof.
#[derive(Debug, Error)]
pub enum NativeLaneStateProofError {
    /// Local scratch admission or physical allocation failed; the original witness is borrowed.
    #[error("native lane state proof scratch: {0}")]
    Scratch(#[from] ChargedBufferError),
    /// The original witness or its fixed-key commitment is malformed.
    #[error("native lane state proof: {0}")]
    Malformed(&'static str),
    /// Original canonical commitment decoder, including captured enclosing admission refusal.
    #[error("native lane state proof decoder: {0}")]
    Decode(#[from] norito::core::DecodeAttemptError),
    /// Canonical commitment comparison could not be encoded; this is not a decoder refusal.
    #[error("native lane state proof codec: {0}")]
    Codec(#[from] norito::Error),
}
impl NativeLaneStateProofError {
    /// Whether preserving the original execution and retrying local admission can progress.
    /// Captured caller decoder limits remain local after their scopes retire. Scratch demand
    /// exceeding the pool's hard ceiling, invalid bytes and encoder failures remain terminal.
    #[must_use]
    pub fn is_local_refusal(&self) -> bool {
        match self {
            Self::Scratch(
                ChargedBufferError::Admission(iroha_allocation::AllocationRefusal::Capacity {
                    ..
                })
                | ChargedBufferError::Allocator { .. },
            ) => true,
            Self::Decode(original) => matches!(
                original.kind(),
                norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit
            ),
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
struct Node {
    path: [u8; 32],
    hash: Hash,
    source: usize,
}

impl NativeLaneStateProof {
    /// Exact allocation demand of the two in-place scratch halves, without owned source clones.
    /// # Errors
    /// Rejects a write count whose backing would overflow the address space.
    pub fn scratch_bytes(write_count: usize) -> Result<usize, NativeLaneStateProofError> {
        write_count
            .checked_mul(2)
            .and_then(|count| count.checked_mul(std::mem::size_of::<Node>()))
            .ok_or(NativeLaneStateProofError::Malformed(
                "scratch size overflow",
            ))
    }
    /// Construct the exact proof from the original validator execution witness.
    ///
    /// Only one `2 * writes.len()` scratch allocation is made, charged to `budget`; all source
    /// keys and values remain borrowed. Repeated ordinary keys use their last write. A duplicate
    /// context commitment, key-path collision, malformed commitment or inconsistent root fails.
    ///
    /// # Errors
    /// Local resource refusal leaves the witness untouched. Malformed input must not be retried
    /// as a local capacity condition.
    pub fn from_witness(
        witness: &ExecWitness,
        budget: &AllocationBudget,
    ) -> Result<Self, NativeLaneStateProofError> {
        let malformed = NativeLaneStateProofError::Malformed;
        let mut targets = witness
            .writes
            .iter()
            .filter(|write| write.key == SUMERAGI_LANE_STATE_WITNESS_KEY);
        let target = targets
            .next()
            .ok_or_else(|| malformed("missing complete lane-state write"))?;
        if targets.next().is_some() {
            return Err(malformed("duplicate complete lane-state write"));
        }
        if target.value.len() > COMMITMENT_BYTES {
            return Err(malformed("oversized lane-state commitment"));
        }
        let commitment: SumeragiLaneStateCommitment = norito::decode_canonical_for_admission(
            &target.value,
            norito::DecodeLimits::new(32, COMMITMENT_BYTES, 128, 2048, 8),
        )?;
        if commitment.validate().is_err() {
            return Err(malformed("invalid lane-state commitment"));
        }
        let mut canonical = StackWriter::new();
        norito::core::write_canonical_to_writer(&commitment, &mut canonical)?;
        if canonical.as_slice() != target.value {
            return Err(malformed("noncanonical lane-state commitment"));
        }
        Self::scratch_bytes(witness.writes.len())?;
        let capacity = witness
            .writes
            .len()
            .checked_mul(2)
            .ok_or_else(|| malformed("scratch size overflow"))?;
        let mut storage = ChargedBuffer::new(capacity, budget)?;
        let empty = Hash::new([]);
        for _ in 0..capacity {
            storage.push_reserved(Node {
                path: [0; 32],
                hash: empty,
                source: 0,
            });
        }
        let (mut current, mut next) = storage.as_mut_slice().split_at_mut(witness.writes.len());
        for (source, write) in witness.writes.iter().enumerate() {
            let path = Hash::new(&write.key);
            let value = Hash::new(&write.value);
            current[source] = Node {
                path: path.into(),
                hash: Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]),
                source,
            };
        }
        current.sort_unstable_by_key(|node| (node.path, node.source));
        let mut length = 0;
        for source in 0..current.len() {
            let node = current[source];
            if length > 0 && current[length - 1].path == node.path {
                if witness.writes[current[length - 1].source].key != witness.writes[node.source].key
                {
                    return Err(malformed("ordinary-write key-path collision"));
                }
                current[length - 1] = node;
            } else {
                current[length] = node;
                length += 1;
            }
        }
        let mut target_path: [u8; 32] = Hash::new(SUMERAGI_LANE_STATE_WITNESS_KEY).into();
        let mut siblings = [[empty; 32]; 8];
        for (level, sibling_hash) in siblings.iter_mut().flatten().enumerate() {
            let bit = DEPTH - level - 1;
            let byte = bit / 8;
            let mask = 1_u8 << (bit % 8);
            let mut sibling = target_path;
            sibling[byte] ^= mask;
            *sibling_hash = lookup(&current[..length], &sibling).map_or(empty, |node| node.hash);
            let mut out = 0;
            for node in &current[..length] {
                let mut sibling = node.path;
                sibling[byte] ^= mask;
                let other = lookup(&current[..length], &sibling);
                let is_right = node.path[byte] & mask != 0;
                if is_right && other.is_some() {
                    continue;
                }
                let other_hash = other.map_or(empty, |node| node.hash);
                let (left, right) = if is_right {
                    (other_hash, node.hash)
                } else {
                    (node.hash, other_hash)
                };
                let mut parent = node.path;
                parent[byte] &= !mask;
                next[out] = Node {
                    path: parent,
                    hash: Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]),
                    source: 0,
                };
                out += 1;
            }
            next[..out].sort_unstable_by_key(|node| node.path);
            target_path[byte] &= !mask;
            std::mem::swap(&mut current, &mut next);
            length = out;
        }
        let proof = Self {
            commitment,
            siblings,
        };
        if length != 1 || !proof.verify_root(current[0].hash) {
            return Err(malformed(
                "lane state proof differs from original ordinary-write root",
            ));
        }
        Ok(proof)
    }

    /// Construct an explicit empty-lane state proof fixture and its actual ordinary-write root.
    /// This test helper executes no State transition and grants no finality or live authority.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn empty_for_testing(network: NetworkId, height: u64) -> (Self, Hash) {
        let commitment =
            SumeragiLaneStateCommitment::from_state(network, height, &SumeragiLaneState::default())
                .expect("valid empty context fixture");
        let witness = ExecWitness {
            writes: vec![crate::block::consensus::ExecKv {
                key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                value: norito::encode_canonical(&commitment).expect("fixed fixture commitment"),
            }],
            ..ExecWitness::default()
        };
        let budget = AllocationBudget::new(2 * std::mem::size_of::<Node>());
        let proof = Self::from_witness(&witness, &budget).expect("actual funded fixture path");
        let root = proof.root().expect("valid fixture commitment");
        (proof, root)
    }

    /// Verify the sole fixed `StatePath` against the exact native execution commitment.
    #[must_use]
    pub fn verify(&self, network: NetworkId, height: u64, root: Hash) -> bool {
        self.commitment.matches_carrier(network, height) && self.verify_root(root)
    }

    /// Check complete values, including their authenticated empty state, against this proof.
    ///
    /// # Errors
    /// The supplied set is malformed or belongs to another network/height.
    pub fn matches_state(
        &self,
        network: NetworkId,
        height: u64,
        contexts: &SumeragiLaneState,
    ) -> Result<bool, String> {
        Ok(self.commitment == SumeragiLaneStateCommitment::from_state(network, height, contexts)?)
    }

    /// Compare the exact complete canonical encoding with the value in this proof using
    /// bounded stack hashing and no dynamic scratch. This is equality only: it does not
    /// replace validation of untrusted context values or verification of the certified R root.
    /// The live archive calls it only over the original already-executed overlay.
    ///
    /// # Errors
    /// Noncanonical ordering, a foreign/future context or canonical encoding failure.
    pub fn matches_state_encoding(
        &self,
        network: NetworkId,
        height: u64,
        contexts: &SumeragiLaneState,
    ) -> Result<bool, norito::Error> {
        Ok(self.commitment
            == SumeragiLaneStateCommitment::from_state_encoding(network, height, contexts)?)
    }

    /// Compare a borrowed canonical lane payload against this proof's complete state commitment.
    ///
    /// The payload is the lane field from the sole canonical original execution archive, using
    /// the canonical layout flags. Its exact canonical frame is hashed without rebuilding lane
    /// records, public keys or `PoPs`. This does not decode state or validate an untrusted claim:
    /// callers must first authenticate this proof with [`Self::verify`] against the independently
    /// certified native result at the exact network and height. Only then does byte equality
    /// establish that the payload is the original complete canonical state.
    ///
    /// # Errors
    /// The exact canonical frame cannot be streamed. Foreign network/height or different bytes
    /// return `false`, including malformed or noncanonical payloads differing from the original.
    pub fn matches_state_payload(
        &self,
        network: NetworkId,
        height: u64,
        payload: &[u8],
    ) -> Result<bool, norito::Error> {
        self.commitment
            .matches_state_payload(network, height, payload)
    }

    fn verify_root(&self, expected: Hash) -> bool {
        self.root() == Some(expected)
    }

    /// Compute the root claimed by this untrusted path. This does not authenticate any State;
    /// a verifier must compare it with the independently certified execution commitment.
    #[must_use]
    pub fn computed_root(&self) -> Option<Hash> {
        self.root()
    }

    fn root(&self) -> Option<Hash> {
        if self.commitment.validate().is_err() {
            return None;
        }
        let mut bytes = StackWriter::new();
        if norito::core::write_canonical_to_writer(&self.commitment, &mut bytes).is_err() {
            return None;
        }
        let path = Hash::new(SUMERAGI_LANE_STATE_WITNESS_KEY);
        let value = Hash::new(bytes.as_slice());
        let mut current = Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]);
        for (level, sibling) in self.siblings.iter().flatten().enumerate() {
            let bit = DEPTH - level - 1;
            let (left, right) = if path.as_ref()[bit / 8] & (1 << (bit % 8)) != 0 {
                (sibling, &current)
            } else {
                (&current, sibling)
            };
            current = Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]);
        }
        Some(current)
    }
}

fn lookup<'a>(nodes: &'a [Node], path: &[u8; 32]) -> Option<&'a Node> {
    nodes
        .binary_search_by_key(path, |node| node.path)
        .ok()
        .map(|index| &nodes[index])
}

struct StackWriter {
    bytes: [u8; COMMITMENT_BYTES],
    length: usize,
}
impl StackWriter {
    fn new() -> Self {
        Self {
            bytes: [0; COMMITMENT_BYTES],
            length: 0,
        }
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
impl std::io::Write for StackWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .length
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WriteZero))?;
        self.bytes[self.length..end].copy_from_slice(bytes);
        self.length = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
