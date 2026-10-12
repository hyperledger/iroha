//! SCCP committee generations, liability and consensus anchors (`specs/sccp.md` §4.2, §4.8).
//!
//! These are committed State records, not certificate authority. A generation retains its
//! original validator bindings and deadlines; decoding it never authenticates its committee.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId};
use iroha_model_base::topology::LaneId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Number of consecutive consensus anchors in one complete immutable chunk (§4.2.1).
pub const SCCP_ANCHOR_CHUNK_SIZE_V1: usize = 4_096;
/// Height of the complete anchor Merkle tree; witnesses have exactly this many siblings.
pub const SCCP_ANCHOR_PATH_LENGTH_V1: usize = 12;
/// Extra step allowance of the liability clock after a chain halt (§3.9, §4.8).
pub const SCCP_LC_SLACK_MS_V1: u64 = 3_600_000;

/// Declare one closed Norito State record.
macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($body:tt)* }) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode,
            IntoSchema, DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
        #[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
        $(#[$meta])*
        pub struct $name { $($body)* }
    };
}

/// The sole causes of a new committee generation (§4.2.2 G1–G3, G7).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "cause", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::generation::SccpGenerationCauseV1")]
pub enum SccpGenerationCauseV1 {
    /// Initial committee installed by authenticated genesis.
    #[codec(index = 0)]
    #[norito(rename = "genesis")]
    Genesis,
    /// Scheduled epoch boundary changed the committee keys.
    #[codec(index = 1)]
    #[norito(rename = "key_change")]
    KeyChange,
    /// A time-based renewal, including when the committee keys stay the same.
    #[codec(index = 2)]
    #[norito(rename = "heartbeat")]
    Heartbeat,
    /// Recovery after missing a key change during degraded execution.
    #[codec(index = 3)]
    #[norito(rename = "resync")]
    Resync,
}

record! {
    /// Immutable NPoS registration bound to one consensus key at generation creation (G6).
    #[norito_schema(name = "iroha_data_model::sccp::generation::SccpGenerationMemberV1")]
    pub struct SccpGenerationMemberV1 {
        /// Lane whose staking registration supplied the key.
        pub lane_id: LaneId,
        /// Canonical domainless validator account.
        pub validator: AccountId,
        /// Activation height of the registration, retained across exit and re-registration.
        pub activation_height: u64,
    }
}

record! {
    /// Original generation end, including the successor bound by a handoff or resync.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::generation::SccpGenerationEndV1")]
    pub struct SccpGenerationEndV1 {
        /// Last height governed by the generation.
        pub end_height: u64,
        /// Timestamp of that height; resync takes it from the authenticated parent tip.
        pub end_timestamp_ms: u64,
        /// Root of the successor's canonical committee keys.
        pub next_committee_root: [u8; 32],
        /// Trust window granted to the successor at the transition.
        pub successor_validity_ms: u64,
    }
}

record! {
    /// Committed unit of destination trust and validator liability (§4.2.1).
    #[norito_schema(name = "iroha_data_model::sccp::generation::SccpCommitteeGenerationV1")]
    pub struct SccpCommitteeGenerationV1 {
        /// Nonzero generation, matching the map key.
        pub generation: u64,
        /// SCCP root of `keys` in their canonical order.
        pub committee_root: [u8; 32],
        /// Compressed BLS-normal keys; signer bit `i` refers to `keys[i]`.
        pub keys: Vec<[u8; 48]>,
        /// Original slashable bindings in the same order, with explicit unresolved entries.
        pub members: Vec<Option<SccpGenerationMemberV1>>,
        /// Authenticated genesis, ordinary rotation or degraded-boundary recovery.
        pub cause: SccpGenerationCauseV1,
        /// First height governed by this generation.
        pub start_height: u64,
        /// Certified time of creation; ordinary rotation uses its handoff block's time.
        pub start_timestamp_ms: u64,
        /// Liability clock at creation.
        pub start_lc: u64,
        /// Immutable destination trust duration captured at creation.
        pub validity_ms: u64,
        /// Saturating sum of creation time and validity.
        pub deadline_ms: u64,
        /// Immutable evidence grace period captured at creation.
        pub grace_ms: u64,
        /// Maximum extension while authenticated destination progress is missing.
        pub progress_cap_ms: u64,
        /// Saturating sum of `start_lc`, `validity_ms` and `grace_ms`.
        pub liable_until_lc: u64,
        /// First post-execution liability clock at which all destinations cleared the deadline.
        #[norito(required)]
        pub dest_cleared_lc: Option<u64>,
        /// End and successor, absent for the current open generation.
        #[norito(required)]
        pub end: Option<SccpGenerationEndV1>,
    }
}

impl SccpCommitteeGenerationV1 {
    /// One inclusive liability predicate for evidence, unbond release and pruning (§4.8).
    #[must_use]
    pub fn is_liable(&self, current_generation: u64, liability_clock: u64) -> bool {
        self.generation == current_generation
            || liability_clock <= self.liable_until_lc
            || liability_clock
                <= self.dest_cleared_lc.map_or_else(
                    || self.liable_until_lc.saturating_add(self.progress_cap_ms),
                    |cleared| cleared.saturating_add(self.grace_ms),
                )
    }

    /// Check local record structure; committee authority still requires authenticated history.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        use crate::sumeragi_finality::certified_result::{MAX_VALIDITY_MS, committee_root};
        self.generation != 0
            && self.start_height != 0
            && (self.cause == SccpGenerationCauseV1::Genesis) == (self.generation == 1)
            && self.start_lc <= self.start_timestamp_ms
            && crate::block::consensus::is_valid_committee_size(self.keys.len())
            && self.keys.is_sorted_by(|left, right| left < right)
            && self.keys.len() == self.members.len()
            && self
                .keys
                .iter()
                .all(|key| iroha_crypto::bls::consensus::key_validate(key))
            && self.committee_root != [0; 32]
            && committee_root(&self.keys) == Some(self.committee_root)
            && (1..=MAX_VALIDITY_MS).contains(&self.validity_ms)
            && self.deadline_ms == self.start_timestamp_ms.saturating_add(self.validity_ms)
            && self.liable_until_lc
                == self
                    .start_lc
                    .saturating_add(self.validity_ms)
                    .saturating_add(self.grace_ms)
            && self
                .dest_cleared_lc
                .is_none_or(|clock| clock >= self.start_lc)
            && self.end.is_none_or(|end| {
                end.end_height >= self.start_height
                    && end.end_timestamp_ms >= self.start_timestamp_ms
                    && end.next_committee_root != [0; 32]
                    && (1..=MAX_VALIDITY_MS).contains(&end.successor_validity_ms)
            })
    }
}

record! {
    /// Actual Sumeragi core identity and certified result of a height; not an Iroha header hash.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::generation::SccpAnchorV1")]
    pub struct SccpAnchorV1 {
        /// Core block hash signed as `QC.block_hash`.
        pub core_hash: [u8; 32],
        /// Outer result `R` signed by that same commit certificate.
        pub result: [u8; 32],
    }
}

/// Apply S0's bounded liability-clock step; a halt cannot consume the full liability window.
#[must_use]
pub fn next_liability_clock_v1(
    parent_lc: u64,
    parent_time: u64,
    time: u64,
    heartbeat_ms: u64,
) -> u64 {
    parent_lc.saturating_add(
        time.saturating_sub(parent_time)
            .min(heartbeat_ms.saturating_add(SCCP_LC_SLACK_MS_V1)),
    )
}

/// Domain-separated anchor leaf of one nonzero height; zero has no canonical anchor position.
#[must_use]
pub fn anchor_leaf_v1(height: u64, anchor: &SccpAnchorV1) -> Option<[u8; 32]> {
    (height != 0).then(|| {
        iroha_crypto::Hash::new_from_chunks(&[
            b"sccp/anchor-leaf/v1",
            &height.to_be_bytes(),
            &anchor.core_hash,
            &anchor.result,
        ])
        .into()
    })
}

fn anchor_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    iroha_crypto::Hash::new_from_chunks(&[b"sccp/anchor-node/v1", left, right]).into()
}

/// Fold exactly 4096 anchors using a fixed logarithmic frontier, with no heap allocation.
/// Returns `None` for an incomplete chunk or a chunk whose height range overflows.
#[must_use]
pub fn anchor_chunk_root_v1(chunk: u64, anchors: &[SccpAnchorV1]) -> Option<[u8; 32]> {
    if anchors.len() != SCCP_ANCHOR_CHUNK_SIZE_V1 {
        return None;
    }
    let first = chunk
        .checked_mul(SCCP_ANCHOR_CHUNK_SIZE_V1 as u64)?
        .checked_add(1)?;
    first.checked_add(SCCP_ANCHOR_CHUNK_SIZE_V1 as u64 - 1)?;
    let mut frontier = [None; SCCP_ANCHOR_PATH_LENGTH_V1 + 1];
    for (index, anchor) in anchors.iter().enumerate() {
        let mut value = anchor_leaf_v1(first + index as u64, anchor)?;
        let mut level = 0;
        while let Some(left) = frontier[level].take() {
            value = anchor_node(&left, &value);
            level += 1;
        }
        frontier[level] = Some(value);
    }
    frontier[SCCP_ANCHOR_PATH_LENGTH_V1]
}

/// Check one exact twelve-sibling anchor witness against its retained chunk root.
#[must_use]
pub fn verify_anchor_path_v1(
    height: u64,
    anchor: &SccpAnchorV1,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if path.len() != SCCP_ANCHOR_PATH_LENGTH_V1 {
        return false;
    }
    let Some(mut hash) = anchor_leaf_v1(height, anchor) else {
        return false;
    };
    let mut index = (height - 1) % SCCP_ANCHOR_CHUNK_SIZE_V1 as u64;
    for sibling in path {
        hash = if index & 1 == 0 {
            anchor_node(&hash, sibling)
        } else {
            anchor_node(sibling, &hash)
        };
        index >>= 1;
    }
    hash == *root
}

#[cfg(test)]
mod tests;
