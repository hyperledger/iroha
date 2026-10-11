//! SCCP v1 inbound light-client value types (`specs/sccp.md` §4.13).
//!
//! World state stores authenticated validator sets of each source chain and finalized
//! checkpoints. The Parliament only initializes, re-initializes, freezes and installs trusted
//! checkpoints; every advance is permissionless. Chain data whose native integers can exceed
//! `2^53 − 1` (TON validator weights, config and key-block data) travels as opaque bytes inside
//! [`SccpLcBootstrapV1`], never as integer fields, so every Parliament proposal keeps the exact
//! JSON integer invariant.
//!
//! Stored state is [`SccpLightClientV1`] (params, head, freeze reason and CAS state hash),
//! [`SccpLcConsensusSetV1`], [`SccpLcCheckpointV1`] and the Parliament-activated compiled
//! profile versions ([`SccpLcProfileActivationV1`]). Advances and equivocation evidence are the
//! bounded opaque wrappers [`SccpLcAdvanceBytesV1`] and [`SccpLcEvidenceBytesV1`].

use super::{bounded_bytes::impl_sccp_bounded_bytes, governance::SCCP_JSON_SAFE_U64_MAX_V1};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, bridge::SccpNetworkV1};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Maximum byte length of one light-client bootstrap frame.
pub const SCCP_LC_BOOTSTRAP_MAX_BYTES_V1: usize = 1_048_576;
/// Default retention of a superseded validator set (180 d).
pub const SCCP_LC_DEFAULT_SET_RETENTION_MS_V1: u64 = 15_552_000_000;
/// Default age after which a non-permanent checkpoint is pruned (30 d).
pub const SCCP_LC_DEFAULT_CHECKPOINT_PRUNE_AFTER_MS_V1: u64 = 2_592_000_000;
/// Default weak-subjectivity bound for Ethereum (14 d).
pub const SCCP_LC_ETHEREUM_WS_BOUND_MS_V1: u64 = 1_209_600_000;
/// Default weak-subjectivity bound for BSC (5 d; BSC unbonding is 7 d).
pub const SCCP_LC_BSC_WS_BOUND_MS_V1: u64 = 432_000_000;
/// Permanent-checkpoint stride for Ethereum and BSC, in source blocks.
pub const SCCP_LC_EVM_CHECKPOINT_STRIDE_V1: u64 = 8_192;
/// Default bound on finality updates in one advance (Ethereum `LightClientUpdate`s, BSC set
/// transitions, TON key-block hops).
pub const SCCP_LC_DEFAULT_MAX_UPDATES_PER_ADVANCE_V1: u32 = 16;
/// Default bound on parent-linked headers in one Ethereum or BSC segment.
pub const SCCP_LC_EVM_MAX_SEGMENT_HEADERS_V1: u32 = 256;
/// Default bound on the TON shard-block `prev_ref` walk.
pub const SCCP_LC_TON_MAX_SEGMENT_HEADERS_V1: u32 = 32;
/// Default bound on ancestry headers in one Ethereum or BSC proof.
pub const SCCP_LC_EVM_MAX_ANCESTRY_HEADERS_V1: u32 = 256;
/// Default bound on TON ancestry blocks in one proof.
pub const SCCP_LC_TON_MAX_ANCESTRY_HEADERS_V1: u32 = 32;
/// Default bound on headers in one `Backfill` segment.
pub const SCCP_LC_DEFAULT_MAX_BACKFILL_HEADERS_V1: u32 = 256;
/// Default bound on the canonical bytes of one advance.
///
/// The node keeper's default `max_advance_bytes` (262 144) stays below it (§4.13.4).
pub const SCCP_LC_DEFAULT_MAX_ADVANCE_BYTES_V1: u32 = 1_048_576;
/// Default bound on the canonical bytes of one inbound or void proof.
pub const SCCP_LC_DEFAULT_MAX_PROOF_BYTES_V1: u32 = 1_048_576;

/// Compiled light-client profile version every network runs before any activation (§4.13.2).
pub const SCCP_LC_GENESIS_PROFILE_VERSION_V1: u32 = 1;

/// Stored parameters of one light client (§4.13.1).
///
/// The source-chain fork schedule and its `supported_until` belong to a compiled chain profile
/// version, selected by Parliament activation (§4.13.2), and are deliberately not stored here.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLightClientParamsV1")]
pub struct SccpLightClientParamsV1 {
    /// External source chain.
    pub network: SccpNetworkV1,
    /// Weak-subjectivity bound: a signing set superseded longer ago is stale. TON uses 0, the
    /// bound being derived from key-block data (`utime_until + stake_held_for − margin`).
    pub ws_bound_ms: u64,
    /// Retention of a superseded validator set.
    pub set_retention_ms: u64,
    /// Permanent-checkpoint stride in source blocks; TON uses 0 and keeps none.
    pub checkpoint_stride: u64,
    /// Age after which a non-permanent checkpoint is pruned.
    pub checkpoint_prune_after_ms: u64,
    /// Bound on finality updates carried by one advance.
    pub max_updates_per_advance: u32,
    /// Bound on headers in one authenticated segment.
    pub max_segment_headers: u32,
    /// Bound on ancestry headers in one inbound or void proof.
    pub max_ancestry_headers: u32,
    /// Bound on headers in one `Backfill` segment.
    pub max_backfill_headers: u32,
    /// Bound on the canonical bytes of one advance.
    pub max_advance_bytes: u32,
    /// Bound on the canonical bytes of one inbound or void proof.
    pub max_proof_bytes: u32,
}

/// Invalid [`SccpLightClientParamsV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpLightClientParamsError {
    /// The network is `sora-taira`, not an external source chain.
    #[error("light-client network must be an external profile")]
    NotExternal,
    /// A `u64` field exceeds `2^53 − 1`.
    #[error("light-client parameter `{field}` exceeds the exact JSON integer maximum")]
    ExceedsJsonSafeInteger {
        /// Offending field.
        field: &'static str,
    },
    /// A bound that must be positive is zero.
    #[error("light-client parameter `{field}` must be nonzero")]
    ZeroBound {
        /// Offending field.
        field: &'static str,
    },
    /// A TON field whose value is derived or unused is nonzero.
    #[error("light-client parameter `{field}` must be zero for TON")]
    TonDerivedFieldNonZero {
        /// Offending field.
        field: &'static str,
    },
}

impl SccpLightClientParamsV1 {
    /// Return the default parameters for an external source chain, or `None` for `sora-taira`.
    #[must_use]
    pub const fn defaults_for(network: SccpNetworkV1) -> Option<Self> {
        let (ws_bound_ms, checkpoint_stride, max_segment_headers, max_ancestry_headers) =
            match network {
                SccpNetworkV1::SoraTaira => return None,
                SccpNetworkV1::EthereumMainnet => (
                    SCCP_LC_ETHEREUM_WS_BOUND_MS_V1,
                    SCCP_LC_EVM_CHECKPOINT_STRIDE_V1,
                    SCCP_LC_EVM_MAX_SEGMENT_HEADERS_V1,
                    SCCP_LC_EVM_MAX_ANCESTRY_HEADERS_V1,
                ),
                SccpNetworkV1::BscMainnet => (
                    SCCP_LC_BSC_WS_BOUND_MS_V1,
                    SCCP_LC_EVM_CHECKPOINT_STRIDE_V1,
                    SCCP_LC_EVM_MAX_SEGMENT_HEADERS_V1,
                    SCCP_LC_EVM_MAX_ANCESTRY_HEADERS_V1,
                ),
                SccpNetworkV1::TonMainnet => (
                    0,
                    0,
                    SCCP_LC_TON_MAX_SEGMENT_HEADERS_V1,
                    SCCP_LC_TON_MAX_ANCESTRY_HEADERS_V1,
                ),
            };
        Some(Self {
            network,
            ws_bound_ms,
            set_retention_ms: SCCP_LC_DEFAULT_SET_RETENTION_MS_V1,
            checkpoint_stride,
            checkpoint_prune_after_ms: SCCP_LC_DEFAULT_CHECKPOINT_PRUNE_AFTER_MS_V1,
            max_updates_per_advance: SCCP_LC_DEFAULT_MAX_UPDATES_PER_ADVANCE_V1,
            max_segment_headers,
            max_ancestry_headers,
            max_backfill_headers: SCCP_LC_DEFAULT_MAX_BACKFILL_HEADERS_V1,
            max_advance_bytes: SCCP_LC_DEFAULT_MAX_ADVANCE_BYTES_V1,
            max_proof_bytes: SCCP_LC_DEFAULT_MAX_PROOF_BYTES_V1,
        })
    }

    /// Check the parameters independently of world state.
    ///
    /// The network is external, every `u64` is at most `2^53 − 1`, and every bound is nonzero,
    /// except that TON's `ws_bound_ms` and `checkpoint_stride` are exactly zero (derived bound,
    /// no permanent checkpoints).
    ///
    /// # Errors
    ///
    /// Returns the first violated rule.
    pub fn validate(&self) -> Result<(), SccpLightClientParamsError> {
        if !self.network.is_external() {
            return Err(SccpLightClientParamsError::NotExternal);
        }
        if let Some(field) = self.first_json_u64_field(SCCP_JSON_SAFE_U64_MAX_V1) {
            return Err(SccpLightClientParamsError::ExceedsJsonSafeInteger { field });
        }
        let is_ton = matches!(self.network, SccpNetworkV1::TonMainnet);
        for (field, value) in [
            ("ws_bound_ms", self.ws_bound_ms),
            ("checkpoint_stride", self.checkpoint_stride),
        ] {
            match (is_ton, value) {
                (true, 0) | (false, 1..) => {}
                (true, _) => {
                    return Err(SccpLightClientParamsError::TonDerivedFieldNonZero { field });
                }
                (false, 0) => return Err(SccpLightClientParamsError::ZeroBound { field }),
            }
        }
        for (field, value) in [
            ("set_retention_ms", self.set_retention_ms),
            ("checkpoint_prune_after_ms", self.checkpoint_prune_after_ms),
            (
                "max_updates_per_advance",
                u64::from(self.max_updates_per_advance),
            ),
            ("max_segment_headers", u64::from(self.max_segment_headers)),
            ("max_ancestry_headers", u64::from(self.max_ancestry_headers)),
            ("max_backfill_headers", u64::from(self.max_backfill_headers)),
            ("max_advance_bytes", u64::from(self.max_advance_bytes)),
            ("max_proof_bytes", u64::from(self.max_proof_bytes)),
        ] {
            if value == 0 {
                return Err(SccpLightClientParamsError::ZeroBound { field });
            }
        }
        Ok(())
    }

    /// Return a message for the first `u64` field above `maximum`.
    #[must_use]
    pub fn first_json_u64_violation(&self, maximum: u64) -> Option<&'static str> {
        self.json_u64_fields()
            .into_iter()
            .find_map(|(_, value, message)| (value > maximum).then_some(message))
    }

    fn first_json_u64_field(&self, maximum: u64) -> Option<&'static str> {
        self.json_u64_fields()
            .into_iter()
            .find_map(|(field, value, _)| (value > maximum).then_some(field))
    }

    fn json_u64_fields(&self) -> [(&'static str, u64, &'static str); 4] {
        [
            (
                "ws_bound_ms",
                self.ws_bound_ms,
                "SCCP light-client ws_bound_ms exceeds the exact JSON integer maximum",
            ),
            (
                "set_retention_ms",
                self.set_retention_ms,
                "SCCP light-client set_retention_ms exceeds the exact JSON integer maximum",
            ),
            (
                "checkpoint_stride",
                self.checkpoint_stride,
                "SCCP light-client checkpoint_stride exceeds the exact JSON integer maximum",
            ),
            (
                "checkpoint_prune_after_ms",
                self.checkpoint_prune_after_ms,
                "SCCP light-client checkpoint_prune_after_ms exceeds the exact JSON integer maximum",
            ),
        ]
    }
}

/// Weak-subjectivity bootstrap of one light client, carried by `InitializeLightClient`.
///
/// `bytes` is an opaque headered Norito frame of the per-chain bootstrap (for TON, a `BoC` inside
/// it), decoded only by `iroha_sccp::light_client`. It is bounded by
/// [`SCCP_LC_BOOTSTRAP_MAX_BYTES_V1`].
#[derive(
    Debug,
    Clone,
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcBootstrapV1")]
pub struct SccpLcBootstrapV1 {
    /// External source chain the bootstrap belongs to.
    pub network: SccpNetworkV1,
    /// Opaque headered-Norito bootstrap frame.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub bytes: Vec<u8>,
}

/// Finalized source-chain checkpoint content.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcCheckpointDataV1")]
pub struct SccpLcCheckpointDataV1 {
    /// Source-chain block height.
    pub source_height: u64,
    /// Source-chain block hash.
    pub block_hash: [u8; 32],
    /// State root, when the chain exposes one.
    #[norito(required)]
    pub state_root: Option<[u8; 32]>,
    /// Receipts root (EVM) or transaction root (TON).
    pub receipts_or_tx_root: [u8; 32],
    /// Source-chain block time in milliseconds.
    pub source_time_ms: u64,
}

impl SccpLcCheckpointDataV1 {
    /// Return a message for the first `u64` field above `maximum`.
    #[must_use]
    pub fn first_json_u64_violation(&self, maximum: u64) -> Option<&'static str> {
        if self.source_height > maximum {
            Some("SCCP checkpoint source_height exceeds the exact JSON integer maximum")
        } else if self.source_time_ms > maximum {
            Some("SCCP checkpoint source_time_ms exceeds the exact JSON integer maximum")
        } else {
            None
        }
    }
}

/// How a checkpoint entered world state.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "origin", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcCheckpointOriginV1")]
pub enum SccpLcCheckpointOriginV1 {
    /// Written by a permissionless advance.
    #[codec(index = 0)]
    #[norito(rename = "advance")]
    Advance,
    /// Written by an accepted inbound or void proof.
    #[codec(index = 1)]
    #[norito(rename = "proof")]
    Proof,
    /// Written by a `Backfill` advance.
    #[codec(index = 2)]
    #[norito(rename = "backfill")]
    Backfill,
    /// Installed by the Parliament (`InstallTrustedCheckpoint`); always permanent.
    #[codec(index = 3)]
    #[norito(rename = "parliament")]
    Parliament,
}

/// Stored checkpoint (`sccp_light_client_checkpoints`, §4.13.1).
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcCheckpointV1")]
pub struct SccpLcCheckpointV1 {
    /// Checkpoint content.
    pub data: SccpLcCheckpointDataV1,
    /// Taira block time at which it was recorded.
    pub recorded_at_taira_ms: u64,
    /// How it was recorded.
    pub origin: SccpLcCheckpointOriginV1,
}

/// Light-client state an `InitializeLightClient` action expects at enactment.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "expected", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcInitExpectationV1")]
pub enum SccpLcInitExpectationV1 {
    /// No light client is installed.
    #[codec(index = 0)]
    #[norito(rename = "absent")]
    Absent,
    /// The installed light client is frozen or has aged beyond its `ws_bound_ms`.
    #[codec(index = 1)]
    #[norito(rename = "unusable")]
    Unusable,
}

/// Largest light-client advance frame (1 MiB).
pub const SCCP_LC_ADVANCE_MAX_BYTES_V1: usize = 1_048_576;
/// Largest equivocation evidence frame (1 MiB).
pub const SCCP_LC_EVIDENCE_MAX_BYTES_V1: usize = 1_048_576;

/// Opaque light-client advance (`SccpLcAdvanceV1` frame, including `Backfill`), `1..=1 MiB`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
)]
#[norito(decode_from_slice)]
#[norito(validate = "Self::checked")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcAdvanceBytesV1")]
pub struct SccpLcAdvanceBytesV1 {
    /// Headered Norito frame of `iroha_sccp::light_client::SccpLcAdvanceV1`.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}

impl_sccp_bounded_bytes!(
    SccpLcAdvanceBytesV1,
    SCCP_LC_ADVANCE_MAX_BYTES_V1,
    "SCCP light-client advance"
);

/// Opaque quorum-valid source-chain record for equivocation evidence (`SccpLcEvidenceV1`
/// frame), `1..=1 MiB`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
)]
#[norito(decode_from_slice)]
#[norito(validate = "Self::checked")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcEvidenceBytesV1")]
pub struct SccpLcEvidenceBytesV1 {
    /// Headered Norito frame of `iroha_sccp::light_client::SccpLcEvidenceV1`.
    #[norito(json = "crate::json_helpers::base64_vec")]
    bytes: Vec<u8>,
}

impl_sccp_bounded_bytes!(
    SccpLcEvidenceBytesV1,
    SCCP_LC_EVIDENCE_MAX_BYTES_V1,
    "SCCP light-client evidence"
);

/// A finalized source-chain point.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcPointV1")]
pub struct SccpLcPointV1 {
    /// Source block height.
    pub source_height: u64,
    /// Source block hash.
    pub block_hash: [u8; 32],
    /// Source block time in milliseconds.
    pub source_time_ms: u64,
}

/// Head of one light client (§4.13.1).
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcHeadV1")]
pub struct SccpLcHeadV1 {
    /// Id of the newest stored consensus set.
    pub latest_set_id: u64,
    /// Newest finalized point.
    pub latest_finalized: SccpLcPointV1,
    /// Taira block time of the last advance that moved the head (keeper cadence, §4.13.4).
    pub last_progress_taira_ms: u64,
}

/// Payload of [`SccpLcFreezeReasonV1::Equivocation`].
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcEquivocationFreezeV1")]
pub struct SccpLcEquivocationFreezeV1 {
    /// Keccak-256 identifying the accepted evidence pair.
    pub evidence_hash: [u8; 32],
}

/// Payload of [`SccpLcFreezeReasonV1::Parliament`].
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcParliamentFreezeV1")]
pub struct SccpLcParliamentFreezeV1 {
    /// Parliament proposal that enacted `FreezeLightClient`.
    pub proposal_id: [u8; 32],
}

/// Why a light client is frozen (§4.13.2).
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "reason", content = "detail")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcFreezeReasonV1")]
pub enum SccpLcFreezeReasonV1 {
    /// `ReportSccpLightClientEquivocationV1` proved two conflicting quorum-valid records.
    #[codec(index = 0)]
    #[norito(rename = "equivocation")]
    Equivocation(SccpLcEquivocationFreezeV1),
    /// Parliament-enacted `FreezeLightClient`.
    #[codec(index = 1)]
    #[norito(rename = "parliament")]
    Parliament(SccpLcParliamentFreezeV1),
}

/// Stored light client (`sccp_light_clients[network]`, §4.13.1).
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLightClientV1")]
pub struct SccpLightClientV1 {
    /// Stored parameters.
    pub params: SccpLightClientParamsV1,
    /// Current head.
    pub head: SccpLcHeadV1,
    /// Freeze reason; a frozen light client accepts no advance or proof.
    #[norito(required)]
    pub frozen: Option<SccpLcFreezeReasonV1>,
    /// Keccak-256 of the canonical light-client state bytes; the wallets' CAS handle.
    pub state_hash: [u8; 32],
}

impl SccpLightClientV1 {
    /// Return whether the light client is frozen.
    #[must_use]
    pub const fn is_frozen(&self) -> bool {
        self.frozen.is_some()
    }
}

/// Stored authenticated consensus set (`sccp_light_client_sets[(network, set_id)]`,
/// §4.13.1).
#[derive(
    Debug,
    Clone,
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcConsensusSetV1")]
pub struct SccpLcConsensusSetV1 {
    /// Set id (sync-committee period, BSC epoch checkpoint or TON key-block seqno, as the chain
    /// profile defines it).
    pub set_id: u64,
    /// First source height the set covers.
    pub valid_from_source_height: u64,
    /// Source time at which a successor superseded the set; `None` while current.
    #[norito(required)]
    pub superseded_at_source_ms: Option<u64>,
    /// Opaque headered-Norito frame of the per-chain set, decoded by `iroha_sccp::light_client`.
    #[norito(json = "crate::json_helpers::base64_vec")]
    pub set_bytes: Vec<u8>,
}

impl SccpLcConsensusSetV1 {
    /// Return whether no successor has superseded the set.
    #[must_use]
    pub const fn is_current(&self) -> bool {
        self.superseded_at_source_ms.is_none()
    }
}

/// Parliament activation of one compiled light-client profile version
/// (`sccp_light_client_profiles[(network, version)]`, §4.13.2), written by an enacted
/// `ActivateLightClientProfile`.
///
/// Version 1 of every network is active from genesis without a record. At Taira height `h` the
/// active version of a network is its highest recorded version whose `activation_height ≤ h`
/// (version 1 when none is). Records are append-only: versions and activation heights only grow.
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
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::light_client::SccpLcProfileActivationV1")]
pub struct SccpLcProfileActivationV1 {
    /// Keccak-256 of the version's canonical profile bytes, as the enacted action named it.
    pub profile_hash: [u8; 32],
    /// First Taira height whose blocks verify under the version: the enacting block plus one,
    /// so the enacting block itself still runs the previous version.
    pub activation_height: u64,
    /// Parliament proposal that enacted the activation.
    pub proposal_id: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sccp::test_support::{assert_rejects_unknown_field, roundtrip};

    /// Zeroes one light-client parameter.
    type ZeroSetter = fn(&mut SccpLightClientParamsV1);
    /// Writes one `u64` light-client parameter.
    type ValueSetter = fn(&mut SccpLightClientParamsV1, u64);

    const JSON_MAX: u64 = (1_u64 << 53) - 1;
    const DAY_MS: u64 = 86_400_000;
    const EXTERNAL: [SccpNetworkV1; 3] = [
        SccpNetworkV1::EthereumMainnet,
        SccpNetworkV1::BscMainnet,
        SccpNetworkV1::TonMainnet,
    ];

    fn params(network: SccpNetworkV1) -> SccpLightClientParamsV1 {
        SccpLightClientParamsV1::defaults_for(network).expect("external network")
    }

    fn checkpoint() -> SccpLcCheckpointDataV1 {
        SccpLcCheckpointDataV1 {
            source_height: 21_000_000,
            block_hash: [0x44; 32],
            state_root: Some([0x45; 32]),
            receipts_or_tx_root: [0x46; 32],
            source_time_ms: 1_758_000_000_000,
        }
    }

    #[test]
    fn defaults_follow_the_per_chain_table() {
        assert_eq!(
            SccpLightClientParamsV1::defaults_for(SccpNetworkV1::SoraTaira),
            None
        );
        let eth = params(SccpNetworkV1::EthereumMainnet);
        assert_eq!(eth.ws_bound_ms, 14 * DAY_MS);
        assert_eq!(eth.checkpoint_stride, 8_192);
        assert_eq!(eth.max_updates_per_advance, 16);
        let bsc = params(SccpNetworkV1::BscMainnet);
        assert_eq!(bsc.ws_bound_ms, 5 * DAY_MS);
        assert_eq!(bsc.checkpoint_stride, 8_192);
        {
            let defaults = params(SccpNetworkV1::TonMainnet);
            assert_eq!(defaults.ws_bound_ms, 0);
            assert_eq!(defaults.checkpoint_stride, 0);
        }
        for network in EXTERNAL {
            let defaults = params(network);
            assert_eq!(defaults.network, network);
            assert_eq!(defaults.set_retention_ms, 180 * DAY_MS);
            assert_eq!(defaults.checkpoint_prune_after_ms, 30 * DAY_MS);
            assert_eq!(defaults.max_backfill_headers, 256);
            assert!(defaults.max_advance_bytes >= 262_144);
            assert_eq!(defaults.validate(), Ok(()), "{network:?}");
        }
    }

    #[test]
    fn validate_rejects_taira_and_zero_bounds() {
        let mut taira = params(SccpNetworkV1::EthereumMainnet);
        taira.network = SccpNetworkV1::SoraTaira;
        assert_eq!(
            taira.validate(),
            Err(SccpLightClientParamsError::NotExternal)
        );
        let setters: [(&str, ZeroSetter); 10] = [
            ("ws_bound_ms", |p| p.ws_bound_ms = 0),
            ("checkpoint_stride", |p| p.checkpoint_stride = 0),
            ("set_retention_ms", |p| p.set_retention_ms = 0),
            ("checkpoint_prune_after_ms", |p| {
                p.checkpoint_prune_after_ms = 0;
            }),
            ("max_updates_per_advance", |p| p.max_updates_per_advance = 0),
            ("max_segment_headers", |p| p.max_segment_headers = 0),
            ("max_ancestry_headers", |p| p.max_ancestry_headers = 0),
            ("max_backfill_headers", |p| p.max_backfill_headers = 0),
            ("max_advance_bytes", |p| p.max_advance_bytes = 0),
            ("max_proof_bytes", |p| p.max_proof_bytes = 0),
        ];
        for network in EXTERNAL {
            for (field, set) in setters {
                let mut candidate = params(network);
                set(&mut candidate);
                let result = candidate.validate();
                if network == SccpNetworkV1::TonMainnet
                    && matches!(field, "ws_bound_ms" | "checkpoint_stride")
                {
                    assert_eq!(result, Ok(()), "{network:?} {field}");
                } else {
                    assert_eq!(
                        result,
                        Err(SccpLightClientParamsError::ZeroBound { field }),
                        "{network:?} {field}"
                    );
                }
            }
        }
    }

    #[test]
    fn validate_requires_ton_derived_fields_to_be_zero() {
        let mut ton = params(SccpNetworkV1::TonMainnet);
        ton.ws_bound_ms = 1;
        assert_eq!(
            ton.validate(),
            Err(SccpLightClientParamsError::TonDerivedFieldNonZero {
                field: "ws_bound_ms"
            })
        );
        let mut ton = params(SccpNetworkV1::TonMainnet);
        ton.checkpoint_stride = 1;
        assert_eq!(
            ton.validate(),
            Err(SccpLightClientParamsError::TonDerivedFieldNonZero {
                field: "checkpoint_stride"
            })
        );
    }

    #[test]
    fn json_safe_bound_is_exact() {
        let setters: [(&str, ValueSetter); 4] = [
            ("ws_bound_ms", |p, v| p.ws_bound_ms = v),
            ("set_retention_ms", |p, v| p.set_retention_ms = v),
            ("checkpoint_stride", |p, v| p.checkpoint_stride = v),
            ("checkpoint_prune_after_ms", |p, v| {
                p.checkpoint_prune_after_ms = v;
            }),
        ];
        for (field, set) in setters {
            let mut at = params(SccpNetworkV1::EthereumMainnet);
            set(&mut at, JSON_MAX);
            assert_eq!(at.validate(), Ok(()), "{field}");
            assert_eq!(at.first_json_u64_violation(JSON_MAX), None, "{field}");
            let mut over = params(SccpNetworkV1::EthereumMainnet);
            set(&mut over, JSON_MAX + 1);
            assert_eq!(
                over.validate(),
                Err(SccpLightClientParamsError::ExceedsJsonSafeInteger { field })
            );
            let message = over
                .first_json_u64_violation(JSON_MAX)
                .expect("violation reported");
            assert!(message.contains(field), "{message} should name {field}");
        }
    }

    #[test]
    fn checkpoint_json_safe_bound_is_exact() {
        let mut at = checkpoint();
        at.source_height = JSON_MAX;
        at.source_time_ms = JSON_MAX;
        assert_eq!(at.first_json_u64_violation(JSON_MAX), None);
        let mut over = at;
        over.source_height = JSON_MAX + 1;
        assert!(
            over.first_json_u64_violation(JSON_MAX)
                .expect("height violation")
                .contains("source_height")
        );
        let mut over = at;
        over.source_time_ms = JSON_MAX + 1;
        assert!(
            over.first_json_u64_violation(JSON_MAX)
                .expect("time violation")
                .contains("source_time_ms")
        );
    }

    #[test]
    fn binary_and_json_roundtrip() {
        for network in EXTERNAL {
            roundtrip(&params(network));
            roundtrip(&SccpLcBootstrapV1 {
                network,
                bytes: vec![0x4e, 0x52, 0x54, 0x30, 0x00, 0xff],
            });
        }
        roundtrip(&SccpLcBootstrapV1 {
            network: SccpNetworkV1::TonMainnet,
            bytes: Vec::new(),
        });
        let mut data = checkpoint();
        roundtrip(&data);
        data.state_root = None;
        roundtrip(&data);
        for origin in [
            SccpLcCheckpointOriginV1::Advance,
            SccpLcCheckpointOriginV1::Proof,
            SccpLcCheckpointOriginV1::Backfill,
            SccpLcCheckpointOriginV1::Parliament,
        ] {
            roundtrip(&origin);
            roundtrip(&SccpLcCheckpointV1 {
                data,
                recorded_at_taira_ms: 1_758_000_000_123,
                origin,
            });
        }
        for expected in [
            SccpLcInitExpectationV1::Absent,
            SccpLcInitExpectationV1::Unusable,
        ] {
            roundtrip(&expected);
        }
    }

    #[test]
    fn bootstrap_json_is_base64_and_state_root_is_required() {
        let bootstrap = SccpLcBootstrapV1 {
            network: SccpNetworkV1::EthereumMainnet,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = norito::json::to_json(&bootstrap).expect("serialize");
        assert!(json.contains("3q2+7w=="), "{json}");

        let mut value = norito::json::to_value(&checkpoint()).expect("to value");
        value
            .as_object_mut()
            .expect("object")
            .remove("state_root")
            .expect("state_root present");
        let missing = norito::json::to_json(&value).expect("serialize");
        assert!(norito::json::from_json::<SccpLcCheckpointDataV1>(&missing).is_err());
    }

    fn head() -> SccpLcHeadV1 {
        SccpLcHeadV1 {
            latest_set_id: 1_400,
            latest_finalized: SccpLcPointV1 {
                source_height: 21_000_000,
                block_hash: [0x31; 32],
                source_time_ms: 1_758_000_000_000,
            },
            last_progress_taira_ms: 1_758_000_100_000,
        }
    }

    #[test]
    fn state_types_roundtrip() {
        roundtrip(&head());
        roundtrip(&head().latest_finalized);
        let reasons = [
            SccpLcFreezeReasonV1::Equivocation(SccpLcEquivocationFreezeV1 {
                evidence_hash: [0x51; 32],
            }),
            SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
                proposal_id: [0x52; 32],
            }),
        ];
        for network in EXTERNAL {
            let mut client = SccpLightClientV1 {
                params: params(network),
                head: head(),
                frozen: None,
                state_hash: [0x61; 32],
            };
            assert!(!client.is_frozen());
            roundtrip(&client);
            for reason in reasons {
                roundtrip(&reason);
                client.frozen = Some(reason);
                assert!(client.is_frozen());
                roundtrip(&client);
            }
            assert_rejects_unknown_field(&client, &[]);
            assert_rejects_unknown_field(&client, &["head", "latest_finalized"]);
        }
        let mut set = SccpLcConsensusSetV1 {
            set_id: 1_400,
            valid_from_source_height: 11_468_800,
            superseded_at_source_ms: None,
            set_bytes: vec![0x4e, 0x52, 0x54, 0x30],
        };
        assert!(set.is_current());
        roundtrip(&set);
        set.superseded_at_source_ms = Some(1_758_000_000_000);
        assert!(!set.is_current());
        roundtrip(&set);
        assert_rejects_unknown_field(&set, &[]);
        roundtrip(&SccpLcAdvanceBytesV1::new(vec![1, 2]).expect("bounded"));
        roundtrip(&SccpLcEvidenceBytesV1::new(vec![3]).expect("bounded"));
    }

    #[test]
    fn profile_activation_roundtrips_with_a_fixed_layout() {
        let activation = SccpLcProfileActivationV1 {
            profile_hash: [0x71; 32],
            activation_height: 9_007_199_254_740_991,
            proposal_id: [0x72; 32],
        };
        roundtrip(&activation);
        assert_rejects_unknown_field(&activation, &[]);
        // Two fixed 32-byte arrays around one u64: the bare layout has no length prefixes.
        let encoded = activation.encode();
        assert!(encoded.len() >= 72, "{}", encoded.len());
        let value = norito::json::to_value(&activation).expect("value");
        let object = value.as_object().expect("object");
        assert_eq!(object.len(), 3);
        for field in ["profile_hash", "activation_height", "proposal_id"] {
            assert!(object.contains_key(field), "{field}");
        }
        assert_eq!(SCCP_LC_GENESIS_PROFILE_VERSION_V1, 1);
    }

    #[test]
    fn frozen_and_superseded_fields_are_explicit_in_json() {
        let client = SccpLightClientV1 {
            params: params(SccpNetworkV1::EthereumMainnet),
            head: head(),
            frozen: None,
            state_hash: [0; 32],
        };
        let mut value = norito::json::to_value(&client).expect("value");
        value.as_object_mut().expect("object").remove("frozen");
        let json = norito::json::to_json(&value).expect("json");
        assert!(norito::json::from_json::<SccpLightClientV1>(&json).is_err());
        let set = SccpLcConsensusSetV1 {
            set_id: 1,
            valid_from_source_height: 2,
            superseded_at_source_ms: None,
            set_bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = norito::json::to_json(&set).expect("json");
        assert!(json.contains("\"set_bytes\":\"3q2+7w==\""), "{json}");
        let mut value = norito::json::to_value(&set).expect("value");
        value
            .as_object_mut()
            .expect("object")
            .remove("superseded_at_source_ms");
        let json = norito::json::to_json(&value).expect("json");
        assert!(norito::json::from_json::<SccpLcConsensusSetV1>(&json).is_err());
    }

    #[test]
    fn advance_and_evidence_wrappers_are_bounded() {
        use norito::{codec::DecodeAll as _, core::DecodeFromSlice as _};

        assert_eq!(SCCP_LC_ADVANCE_MAX_BYTES_V1, 1_048_576);
        assert_eq!(SCCP_LC_EVIDENCE_MAX_BYTES_V1, 1_048_576);
        assert_eq!(
            SccpLcAdvanceBytesV1::MAX_BYTES,
            SCCP_LC_ADVANCE_MAX_BYTES_V1
        );
        assert_eq!(
            SccpLcEvidenceBytesV1::MAX_BYTES,
            SCCP_LC_EVIDENCE_MAX_BYTES_V1
        );
        assert!(SccpLcAdvanceBytesV1::new(Vec::new()).is_err());
        assert!(SccpLcEvidenceBytesV1::new(Vec::new()).is_err());
        let at = vec![7; SCCP_LC_ADVANCE_MAX_BYTES_V1];
        assert_eq!(
            SccpLcAdvanceBytesV1::new(at.clone())
                .expect("maximum fits")
                .as_bytes(),
            at.as_slice()
        );
        assert_eq!(
            SccpLcEvidenceBytesV1::new(at.clone())
                .expect("maximum fits")
                .into_bytes(),
            at
        );
        let over = vec![7; SCCP_LC_ADVANCE_MAX_BYTES_V1 + 1];
        let error = SccpLcAdvanceBytesV1::new(over.clone()).expect_err("too long");
        assert!(
            error.to_string().contains("SCCP light-client advance"),
            "{error}"
        );
        let error = SccpLcEvidenceBytesV1::new(over.clone()).expect_err("too long");
        assert!(
            error.to_string().contains("SCCP light-client evidence"),
            "{error}"
        );

        let forged = SccpLcAdvanceBytesV1 {
            bytes: over.clone(),
        };
        let encoded = forged.encode();
        assert!(SccpLcAdvanceBytesV1::decode_all(&mut encoded.as_slice()).is_err());
        assert!(SccpLcAdvanceBytesV1::decode_from_slice(&encoded).is_err());
        let json = norito::json::to_json(&forged).expect("json");
        assert!(norito::json::from_json::<SccpLcAdvanceBytesV1>(&json).is_err());
        let forged = SccpLcEvidenceBytesV1 { bytes: Vec::new() };
        let framed = norito::to_bytes(&forged).expect("frame");
        assert!(norito::decode_from_bytes::<SccpLcEvidenceBytesV1>(&framed).is_err());
        let json = norito::json::to_json(&forged).expect("json");
        assert!(norito::json::from_json::<SccpLcEvidenceBytesV1>(&json).is_err());
    }
}
