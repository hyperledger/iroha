//! SCCP emergency pause facts and certificate identities (`specs/sccp.md` §4.14.7).
//!
//! These closed State records carry no independent authority. They must be derived from the
//! original eligible-citizen snapshot, signed endorsements and the block-start pass; loading
//! a DTO does not establish panel membership or authorize enactment.
//! TODO: integrate those authenticated producers and the selective-lift lifecycle in Core.

use std::collections::{BTreeMap, BTreeSet};

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId, account::AccountId,
    bridge::SccpNetworkV1, governance::GovernanceAnchorV1,
};

/// The largest panel draw: nine primary, nine backup and nine reserve members.
pub const SCCP_PAUSE_PANEL_MAX_DRAWN_V1: usize = 27;
/// Domain of the three-field fast-pause effect preimage.
pub const SCCP_FAST_PAUSE_EFFECT_V1: &[u8] = b"iroha.sccp.fast_pause.effect.v1";
/// Domain of the exact fast-pause certificate identity.
pub const SCCP_FAST_PAUSE_CERTIFICATE_ID_V1: &[u8] = b"iroha.sccp.fast_pause.certificate.id.v1";

macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($body:tt)* }) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode,
            IntoSchema, DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
        #[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
        $(#[$meta])*
        pub struct $name { $($body)* }
    };
}

/// Canonical panel order for independent rounds and same-pass enactment.
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
#[norito(tag = "role", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpPanelRoleV1")]
pub enum SccpPanelRoleV1 {
    /// First `k` drawn citizens; ordered before the backup.
    #[codec(index = 0)]
    #[norito(rename = "primary")]
    Primary,
    /// Second `k` drawn citizens, disjoint from the primary.
    #[codec(index = 1)]
    #[norito(rename = "backup")]
    Backup,
}

record! {
    /// Original location of one applied block-start item; timestamps never break ties.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpPassPositionV1")]
    pub struct SccpPassPositionV1 {
        /// Committed block height whose pass applies the item.
        pub height: u64,
        /// Zero-based position among applied pass items.
        pub position: u32,
    }
}

impl SccpPassPositionV1 {
    /// Whether the pause precedes the original Policy Jury casting-open anchor.
    #[must_use]
    pub const fn precedes_casting_open(self, anchor: GovernanceAnchorV1) -> bool {
        self.height < anchor.height
            || (self.height == anchor.height && self.position < anchor.position)
    }
}

record! {
    /// Current emergency pause, whose remaining parts are lifted independently.
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpFastPauseV1")]
    pub struct SccpFastPauseV1 {
        /// Exact certificate that created or renewed this pause.
        pub certificate_id: [u8; 32],
        /// That certificate's effect hash.
        pub effect_hash: [u8; 32],
        /// Primary or backup panel that approved it.
        pub panel_id: [u8; 32],
        /// Original enactment position, replaced by every renewal.
        pub enacted_at: SccpPassPositionV1,
        /// Timestamp of the enacting block.
        pub enacted_at_ms: u64,
        /// Absolute expiry, independent of later traffic.
        pub until_ms: u64,
        /// Whether the Taira part remains held.
        pub taira: bool,
        /// Remaining destination parts in strictly increasing revision order.
        pub revisions: Vec<u32>,
    }
}

impl SccpFastPauseV1 {
    /// Whether the persisted record has a valid nonempty shape.
    ///
    /// Route membership and the exact certificate are verified by the executing owner.
    #[must_use]
    pub fn has_valid_shape(&self) -> bool {
        self.certificate_id != [0; 32]
            && self.effect_hash != [0; 32]
            && self.panel_id != [0; 32]
            && self.enacted_at.height != 0
            && self.until_ms > self.enacted_at_ms
            && (self.taira || !self.revisions.is_empty())
            && self.revisions.first().is_none_or(|revision| *revision != 0)
            && self.revisions.windows(2).all(|pair| pair[0] < pair[1])
    }

    /// Active destination expiry for one part at the executing block's time.
    #[must_use]
    pub fn destination_expiry(&self, revision: u32, timestamp_ms: u64) -> u64 {
        if timestamp_ms < self.until_ms && self.revisions.binary_search(&revision).is_ok() {
            self.until_ms
        } else {
            0
        }
    }

    /// Whether inbound settlement and refunds remain held at the executing block's time.
    #[must_use]
    pub const fn holds_taira(&self, timestamp_ms: u64) -> bool {
        self.taira && timestamp_ms < self.until_ms
    }
}

record! {
    /// One chain-wide draw; acceptance changes no draw ordering or term anchor.
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpPausePanelV1")]
    pub struct SccpPausePanelV1 {
        /// Monotonic successful seating sequence.
        pub panel_seq: u64,
        /// Original epoch-boundary pulse identifier.
        pub pulse_id: [u8; 32],
        /// Boundary block that captured the parent-state electorate.
        pub seated_height: u64,
        /// Time of that block.
        pub seated_at_ms: u64,
        /// Fixed deadline before lazy reserve replacement applies.
        pub accept_until_ms: u64,
        /// Fixed earliest time at which a subsequent boundary can replace this draw.
        pub term_ends_at_ms: u64,
        /// Original draw order: primary, backup, then reserve; no member occurs twice.
        pub drawn: Vec<AccountId>,
        /// Drawn members whose signed acceptance or endorsement was recorded.
        pub accepted: BTreeSet<AccountId>,
        /// Content identity of the primary panel.
        pub primary_id: [u8; 32],
        /// Content identity of the backup panel.
        pub backup_id: [u8; 32],
    }
}

impl SccpPausePanelV1 {
    /// Whether the record has a bounded, disjoint draw and coherent deadlines.
    ///
    /// No eligibility, seat partition, quorum or randomness claim follows from decoding.
    /// Execution rechecks the actual parameters when interpreting the seated panel.
    #[must_use]
    pub fn has_valid_shape(&self) -> bool {
        self.panel_seq != 0
            && self.pulse_id != [0; 32]
            && self.seated_height != 0
            && self.accept_until_ms > self.seated_at_ms
            && self.term_ends_at_ms > self.accept_until_ms
            && self.drawn.len() >= 10
            && self.drawn.len() <= SCCP_PAUSE_PANEL_MAX_DRAWN_V1
            && self.primary_id != [0; 32]
            && self.backup_id != [0; 32]
            && self.primary_id != self.backup_id
            && self
                .drawn
                .iter()
                .enumerate()
                .all(|(index, member)| !self.drawn[..index].contains(member))
            && self
                .accepted
                .iter()
                .all(|member| self.drawn.contains(member))
    }

    /// Whether this draw can supply the exact configured primary and backup geometry.
    #[must_use]
    pub fn has_geometry(&self, seats: u32) -> bool {
        let Ok(k) = usize::try_from(seats) else {
            return false;
        };
        self.has_valid_shape()
            && super::params::SCCP_FAST_PAUSE_PANEL_SEATS_V1.contains(&seats)
            && (2 * k..=3 * k).contains(&self.drawn.len())
    }
}

record! {
    /// Facts recorded for one account's accepted fast-pause endorsement.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpFastPauseEndorsementV1")]
    pub struct SccpFastPauseEndorsementV1 {
        /// Nonzero incident digest signed by the endorsing account.
        pub incident_digest: [u8; 32],
        /// Committed block height that recorded the endorsement, not a timestamp.
        pub recorded_at_height: u64,
    }
}

record! {
    /// One network and panel's current endorsement window, replaced lazily after expiry.
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpFastPauseRoundV1")]
    pub struct SccpFastPauseRoundV1 {
        /// Primary or backup panel identity at round opening.
        pub panel_id: [u8; 32],
        /// Original seating sequence.
        pub panel_seq: u64,
        /// `FastHold(network)` head endorsed by every signer.
        pub head: u64,
        /// Timestamp of the first accepted endorsement.
        pub opened_at_ms: u64,
        /// Immutable closing deadline of this round.
        pub closes_at_ms: u64,
        /// Canonical account order, with each signer's incident digest and recording height.
        pub endorsers: BTreeMap<AccountId, SccpFastPauseEndorsementV1>,
        /// Quorum was reached; the next pass must recheck current seat ownership and eligibility.
        pub certify_due: bool,
    }
}

impl SccpFastPauseRoundV1 {
    /// Bounded record shape; the pass rechecks every signer against the current panel.
    #[must_use]
    pub fn has_valid_shape(&self) -> bool {
        self.panel_id != [0; 32]
            && self.panel_seq != 0
            && self.closes_at_ms > self.opened_at_ms
            && !self.endorsers.is_empty()
            && self.endorsers.len() <= SCCP_PAUSE_PANEL_MAX_DRAWN_V1
            && self.endorsers.values().all(|endorsement| {
                endorsement.incident_digest != [0; 32] && endorsement.recorded_at_height != 0
            })
    }
}

record! {
    /// Fixed certificate produced by the actual eligible endorsements at block start.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpFastPauseCertificateV1")]
    pub struct SccpFastPauseCertificateV1 {
        /// Exact chain identity of the signed endorsements.
        pub network_id: NetworkId,
        /// External network being paused.
        pub network: SccpNetworkV1,
        /// Panel that reached quorum.
        pub panel_id: [u8; 32],
        /// Canonical primary/backup role.
        pub panel_role: SccpPanelRoleV1,
        /// Original seating sequence.
        pub panel_seq: u64,
        /// Current `FastHold(network)` head.
        pub head: u64,
        /// Root over the eligible seat-holding endorsers in canonical account order.
        pub endorsement_root: [u8; 32],
        /// Number of eligible original endorsements committed by the root.
        pub endorsement_count: u32,
        /// Required threshold of the seated panel.
        pub quorum: u32,
        /// Root over the incidents committed by the eligible endorsements.
        pub incident_root: [u8; 32],
        /// Fingerprint of `(network_id, network, head)` in the fast-pause effect domain.
        pub effect_preimage_hash: [u8; 32],
        /// Block whose pass performed certification.
        pub certified_at_height: u64,
        /// Timestamp of that block.
        pub certified_at_ms: u64,
    }
}

impl SccpFastPauseCertificateV1 {
    /// Exact domain-separated effect identity, independent of panel membership metadata.
    #[must_use]
    pub fn effect_hash(network_id: NetworkId, network: SccpNetworkV1, head: u64) -> [u8; 32] {
        crate::governance_fingerprint::fingerprint(
            SCCP_FAST_PAUSE_EFFECT_V1,
            &(network_id, network, head),
        )
    }
}

/// Identifier of one exact certificate; it conveys no authority without State verification.
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
#[norito(no_fast_from_json, decode_from_slice)]
#[norito_schema(name = "iroha_data_model::sccp::fast_pause::SccpFastPauseCertificateId")]
pub struct SccpFastPauseCertificateId([u8; 32]);

impl SccpFastPauseCertificateId {
    /// Derive the content identifier from the exact certified fields.
    #[must_use]
    pub fn derive_v1(certificate: &SccpFastPauseCertificateV1) -> Self {
        Self(crate::governance_fingerprint::fingerprint(
            SCCP_FAST_PAUSE_CERTIFICATE_ID_V1,
            certificate,
        ))
    }

    /// Borrow the original fixed identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests;
