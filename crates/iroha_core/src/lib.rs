//! Iroha — A simple, enterprise-grade decentralized ledger.
//!
//! Framed Core records declare their protocol identity with `NoritoSchema`.
//! Borrowed query views retain distinct nominal identities and explicitly project
//! to the owned result's frame; payload serialization does not choose an identity.
#![allow(unexpected_cfgs)]
#[cfg(not(feature = "zk-ipa-native"))]
compile_error!(
    "Native IPA helpers must remain enabled; `zk-ipa-native` is required for all builds"
);
// Test-only Core mutation controls must never enter a shipping library.
mod mutation_guard;

/// Randomness beacon scaffolding using BLS‑VRF outputs.
pub mod alias;
/// Declarative alias setup classification and planning primitives.
pub mod alias_setup;
pub mod beacon;
/// Block types and helpers.
pub mod block;
/// Lane compliance policy evaluation.
pub mod compliance;
/// Consensus-neutral key predicates shared by validation paths.
pub(crate) mod crypto_util;
/// Data availability orchestration and ingest helpers.
pub mod da;
/// Signed committee and monetary staking authority for opaque deferred execution.
pub(crate) mod deferred_authority;
/// Guard-owned execution witness recorder, its sparse Merkle tree and state-root projections.
pub mod exec_witness;
/// Local execution attempts and non-consensus retry outcomes.
pub mod execution_attempt;
/// Runtime executor integration and helpers.
pub mod executor;
/// FASTPQ transcript helpers and host plumbing.
pub mod fastpq;
/// Unified settlement fee evidence structures.
pub mod fees;
/// Committed execution-limit policy: the chain parameter that decides overlay, IVM,
/// quarantine, query and AMX limits of the transaction pipeline.
pub mod fraud_admission_policy;
/// Gas metering for non-VM ISI execution.
pub mod gas;
/// Gossip protocols for transactions and peers.
pub mod gossiper;
/// Governance helpers (parliament selection, etc.).
pub mod governance;
/// Cross-lane plumbing and privacy commitment registries.
pub mod interlane;
/// ISO bridge helpers (reference data ingestion, etc.).
pub mod iso_bridge;
/// Jurisdiction attestation/SDN enforcement helpers.
pub mod jurisdiction;
/// Kiso: storage primitives and data layout.
pub mod kiso;
/// Persistent block storage (Kura) backend.
pub mod kura;
/// Rebuildable, non-consensus Musubi description and keyword search projection.
pub mod musubi_search;
/// Nexus helpers (UAID portfolio aggregation, etc.).
pub mod nexus;
/// Oracle host helpers (admission/aggregation plumbing).
pub mod oracle;
/// Peer discovery and gossip.
pub mod peers_gossiper;
/// Pipeline helpers (access-set derivation, scheduler glue)
pub mod pipeline;
mod pipeline_gas_policy;
pub mod pipeline_validity_policy;
mod resource_coherence;
/// Internal privacy owner paths used by Core and Sumeragi-owned tests.
pub(crate) use iroha_core_privacy::{
    execution_proofs, privacy_engines, privacy_profiles, privacy_state, privacy_verifier,
};
/// Reserve-backed KAGEMUSHA wallet ledger orchestration.
pub mod kagemusha_wallet_v1;
/// First-release privacy protocol governance and admission budgets.
pub mod privacy;
/// Native deterministic privacy release evidence, compiled only into explicit
/// release runners and opt-in integration gates.
#[cfg(feature = "privacy-release-evidence")]
pub mod privacy_release_evidence;
/// Atomic private-settlement runtime helpers.
pub mod private_settlement;
pub(crate) mod publication_lock;
/// Reader/writer publication locks with original release-driven retry custody.
pub mod publication_rwlock;
/// Query API types and execution.
pub mod query;
/// Transaction queue and mempool logic.
pub mod queue;
/// Dataspace classes and immutable asset-definition homes.
pub mod read_scope;
pub(crate) mod receiver_snapshot;
/// Shared compiled validator identity and signed genesis input validation.
pub mod release_identity;
/// Native monthly retail fee accounting and read APIs.
pub mod retail_fee;
/// Retained P2P ownership through final gossip processing.
pub mod retained_gossip;
mod secure_file_metadata;
/// Unified XOR settlement engine.
pub mod settlement;
/// Smart contracts and host ABI.
pub mod smartcontracts;
/// World state snapshots.
pub mod snapshot;
/// Ledger-backed SNS ownership helpers.
pub mod sns;
/// Shared Soracloud runtime snapshot types and traits.
pub mod soracloud_runtime;
/// In-memory state and view types.
pub mod state;
/// Process-local, non-consensus operator diagnostics (Nexus economics, settlement, lanes, queue).
pub mod status;
/// Norito Streaming handshake/state helpers.
pub mod streaming;
/// Consensus protocol (Sumeragi).
pub mod sumeragi;
pub mod telemetry;
/// Network Time Service (scaffolding)
pub mod time;
/// Adaptive threshold-BLS timelock-release session and share verification.
pub mod tle_release;
/// Shared Torii helpers (query surfaces, filters).
pub mod torii;
/// Peer-to-peer Torii ingress proxy envelopes.
pub mod torii_proxy;
pub mod tx;
/// Validation-fee admission enforcement.
pub mod validation_fee;
/// Protected conversion accounting and validator rewards.
pub mod validation_fee_rewards;
/// Independently anchored evidence for pending committee signer custody.
pub mod validator_committee_evidence;
/// Crate-local path to `iroha_core_zk`; external crates import `iroha_core_zk` directly.
pub(crate) use iroha_core_zk as zk;
/// Adapters that build zk verification guardrails from a State's frozen ZK settings: the
/// committed validity policy for limits and switches, the node's own values for local resources.
pub mod zk_guardrails;
/// Committed ZK validity policy: the chain parameter that decides proof limits, windows,
/// verifier switches, relation-selecting keys and verification gas.
pub mod zk_validity_policy;
pub use block::InvalidGenesisError;
/// Native STARK/FRI verifier under `zk-stark`; external crates use `iroha_core_zk::stark`.
#[cfg(feature = "zk-stark")]
pub(crate) use iroha_core_zk::stark as zk_stark;
use iroha_model_base::peer::PeerId;
/// Pre-validate a genesis block against the expected genesis account prior to startup.
///
/// # Errors
///
/// Returns [`block::InvalidGenesisError`] when the provided block violates genesis invariants such
/// as signature, authority, or transaction structure requirements.
pub fn validate_genesis_block(
    block: &iroha_data_model::block::SignedBlock,
    genesis_account: &iroha_data_model::account::AccountId,
) -> Result<(), block::InvalidGenesisError> {
    block::check_genesis_block(block, genesis_account)
}
use gossiper::TransactionGossip;
use iroha_data_model::{events::EventBox, prelude::*};
use iroha_primitives::unique_vec::UniqueVec;
use norito::{
    codec::{Decode, Encode},
    streaming::ControlFrame,
};
use std::sync::Arc;
/// Re-export of Norito JSON derive macros for core crate internals.
pub mod json_macros {
    pub use norito::derive::{JsonDeserialize, JsonSerialize};
}
use crate::peers_gossiper::{PeerTrustGossip, PeersGossip};
use iroha_torii_shared::connect as connect_proto;
use tokio::sync::broadcast;
const NETWORK_MESSAGE_TORII_PROXY_REQUEST_TAG: u32 = 13;
const NETWORK_MESSAGE_TORII_PROXY_RESPONSE_TAG: u32 = 14;
const NETWORK_MESSAGE_SUMERAGI_TAG: u32 = 18;
fn inbound_enum_parts(payload: &[u8]) -> Result<(u32, &[u8]), norito::core::Error> {
    let tag: [u8; core::mem::size_of::<u32>()] = payload
        .get(..core::mem::size_of::<u32>())
        .ok_or(norito::core::Error::LengthMismatch)?
        .try_into()
        .map_err(|_| norito::core::Error::LengthMismatch)?;
    let remaining = payload
        .get(core::mem::size_of::<u32>()..)
        .ok_or(norito::core::Error::LengthMismatch)?;
    Ok((u32::from_le_bytes(tag), remaining))
}
fn inbound_enum_field(remaining: &[u8], flags: u8) -> Result<&[u8], norito::core::Error> {
    let (field_len, prefix_len) = norito::core::read_len_from_slice_with_flags(remaining, flags)?;
    let field_end = prefix_len
        .checked_add(field_len)
        .ok_or(norito::core::Error::LengthMismatch)?;
    if field_end != remaining.len() {
        return Err(norito::core::Error::LengthMismatch);
    }
    remaining
        .get(prefix_len..field_end)
        .ok_or(norito::core::Error::LengthMismatch)
}
fn inbound_owned_enum_field(remaining: &[u8], flags: u8) -> Result<&[u8], norito::core::Error> {
    // Enum fields are length-delimited by the derive, while Box/Arc add a
    // second ownership prefix around their value. Nested raw classifiers must
    // inspect the value after both canonical boundaries.
    let owned = inbound_enum_field(remaining, flags)?;
    inbound_enum_field(owned, flags)
}
fn inbound_transaction_gossip_topic(
    payload: &[u8],
    flags: u8,
) -> Result<iroha_p2p::network::message::Topic, norito::core::Error> {
    use iroha_p2p::network::message::Topic;
    let mut remaining = payload;
    let mut plane = None;
    for index in 0..4 {
        let (field_len, prefix_len) =
            norito::core::read_len_from_slice_with_flags(remaining, flags)?;
        let field_end = prefix_len
            .checked_add(field_len)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let field = remaining
            .get(prefix_len..field_end)
            .ok_or(norito::core::Error::LengthMismatch)?;
        remaining = remaining
            .get(field_end..)
            .ok_or(norito::core::Error::LengthMismatch)?;
        if index == 3 {
            plane = Some(field);
        }
    }
    if !remaining.is_empty() {
        return Err(norito::core::Error::LengthMismatch);
    }
    let (tag, trailing) = inbound_enum_parts(plane.ok_or(norito::core::Error::LengthMismatch)?)?;
    if !trailing.is_empty() {
        return Err(norito::core::Error::LengthMismatch);
    }
    match tag {
        0 => Ok(Topic::TxGossip),
        1 => Ok(Topic::TxGossipRestricted),
        _ => Err(norito::core::Error::Message(
            "unknown transaction-gossip plane discriminant".to_owned(),
        )),
    }
}
/// Specialized type of Iroha Network
pub type IrohaNetwork = iroha_p2p::NetworkHandle<NetworkMessage>;
/// Ids of peers.
pub type Peers = UniqueVec<PeerId>;
/// Type of `Sender<EventBox>` which should be used for channels of `Event` messages.
pub type EventsSender = broadcast::Sender<EventBox>;
/// Network message envelope exchanged between peers.
#[derive(Clone, Debug, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::NetworkMessage")]
#[norito(decode_from_slice)]
pub enum NetworkMessage {
    /// Transaction gossiper message.
    #[codec(index = 6)]
    TransactionGossiper(Arc<TransactionGossip>),
    /// Peer address gossip message.
    #[codec(index = 7)]
    PeersGossiper(Box<PeersGossip>),
    /// Peer trust gossip message.
    #[codec(index = 8)]
    PeerTrustGossip(Box<PeerTrustGossip>),
    /// Health check message.
    #[codec(index = 9)]
    Health,
    /// Network Time Service: time synchronization ping.
    #[codec(index = 10)]
    TimePing(Box<crate::time::TimePing>),
    /// Network Time Service: time synchronization pong.
    #[codec(index = 11)]
    TimePong(Box<crate::time::TimePong>),
    /// Iroha Connect (WalletConnect-style) authenticated P2P control message.
    #[codec(index = 12)]
    Connect(Box<connect_proto::ConnectP2pMessage>),
    /// Torii proxy request routed across bounded Torii ingress proxy hops.
    #[codec(index = 13)]
    ToriiProxyRequest(Arc<torii_proxy::ToriiProxyRequestV1>),
    /// Torii proxy response returned to the ingress node.
    #[codec(index = 14)]
    ToriiProxyResponse(Box<torii_proxy::ToriiProxyResponseV1>),
    /// Norito Streaming control-plane frame.
    #[codec(index = 15)]
    StreamingControl(Box<ControlFrame>),
    /// One Sumeragi consensus frame: the exact `iroha_sumeragi` `WireMessage` encoding and its
    /// instance id. Only the consensus driver decodes it (`sumeragi::net`).
    #[codec(index = 18)]
    Sumeragi(Arc<sumeragi::net::SumeragiFrame>),
}
impl NetworkMessage {
    /// Returns `true` when the message is handled by Torii's proxy-plane P2P
    /// subscribers instead of the generic `irohad` relay path.
    #[must_use]
    pub const fn is_torii_proxy_control_message(&self) -> bool {
        matches!(
            self,
            Self::ToriiProxyRequest(_) | Self::ToriiProxyResponse(_)
        )
    }
}
// Encode/Decode are derived above for `NetworkMessage`.
// Classify core network messages into P2P topics for scheduling.
impl iroha_p2p::network::message::ClassifyTopic for NetworkMessage {
    const HAS_INBOUND_DECODE_LIMITS: bool = true;
    fn topic(&self) -> iroha_p2p::network::message::Topic {
        use iroha_p2p::network::message::Topic as T;
        match self {
            NetworkMessage::ToriiProxyRequest(_)
            | NetworkMessage::ToriiProxyResponse(_)
            | NetworkMessage::StreamingControl(_) => T::Control,
            NetworkMessage::TransactionGossiper(gossip) => match gossip.plane {
                gossiper::GossipPlane::Public => T::TxGossip,
                gossiper::GossipPlane::Restricted => T::TxGossipRestricted,
            },
            NetworkMessage::PeersGossiper(_) => T::PeerGossip,
            NetworkMessage::PeerTrustGossip(_) => T::TrustGossip,
            NetworkMessage::Health | NetworkMessage::TimePing(_) | NetworkMessage::TimePong(_) => {
                T::Health
            }
            NetworkMessage::Connect(_) => T::Connect,
            NetworkMessage::Sumeragi(frame) => frame.topic(),
        }
    }
    fn subscriber_route(&self) -> iroha_p2p::network::message::SubscriberRoute {
        use iroha_p2p::network::message::SubscriberRoute;
        match self {
            Self::ToriiProxyRequest(_) | Self::ToriiProxyResponse(_) => SubscriberRoute::ToriiProxy,
            Self::Connect(_) => SubscriberRoute::Connect,
            Self::Sumeragi(_) => SubscriberRoute::Sumeragi,
            _ => SubscriberRoute::General,
        }
    }
    fn progress_reconstruction(&self) -> iroha_p2p::network::message::ProgressReconstruction {
        use iroha_p2p::network::message::ProgressReconstruction;
        match self {
            // The native core owns retransmission of the exact current instance state.
            Self::Sumeragi(_) => ProgressReconstruction::Retransmit,
            _ => ProgressReconstruction::Exact,
        }
    }
    fn inbound_topic(
        payload: &[u8],
        flags: u8,
    ) -> Result<Option<iroha_p2p::network::message::Topic>, norito::core::Error> {
        use iroha_p2p::network::message::Topic;
        let (tag, remaining) = inbound_enum_parts(payload)?;
        if !matches!(tag, 6..=15 | NETWORK_MESSAGE_SUMERAGI_TAG) {
            return Err(norito::core::Error::Message(
                "unknown core network-message discriminant".to_owned(),
            ));
        }
        if tag == 9 {
            if !remaining.is_empty() {
                return Err(norito::core::Error::LengthMismatch);
            }
            return Ok(Some(Topic::Health));
        }
        let field = if matches!(tag, 6 | NETWORK_MESSAGE_SUMERAGI_TAG) {
            inbound_owned_enum_field(remaining, flags)?
        } else {
            inbound_enum_field(remaining, flags)?
        };
        let topic = match tag {
            6 => inbound_transaction_gossip_topic(field, flags)?,
            7 => Topic::PeerGossip,
            8 => Topic::TrustGossip,
            10..=11 => Topic::Health,
            12 => Topic::Connect,
            13..=15 => Topic::Control,
            NETWORK_MESSAGE_SUMERAGI_TAG => sumeragi::net::inbound_frame_topic(field, flags)?,
            _ => {
                return Err(norito::core::Error::Message(
                    "unknown core network-message discriminant".to_owned(),
                ));
            }
        };
        Ok(Some(topic))
    }
    fn inbound_decode_limits(
        payload: &[u8],
        framed_len: usize,
        flags: u8,
    ) -> Result<Option<norito::DecodeLimits>, norito::core::Error> {
        let discriminant = payload
            .get(..core::mem::size_of::<u32>())
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut discriminant_bytes = [0_u8; core::mem::size_of::<u32>()];
        discriminant_bytes.copy_from_slice(discriminant);
        match u32::from_le_bytes(discriminant_bytes) {
            0..=5 | 16..=17 => Err(norito::core::Error::Message(
                "unknown core network-message discriminant".to_owned(),
            )),
            NETWORK_MESSAGE_TORII_PROXY_REQUEST_TAG => {
                use torii_proxy::{
                    TORII_PROXY_REQUEST_MAX_DECODE_ALLOCATED_BYTES_V1,
                    TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1,
                };
                if framed_len > TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1 {
                    return Err(norito::core::Error::ArchiveLengthExceeded {
                        length: u64::try_from(framed_len).unwrap_or(u64::MAX),
                        limit: u64::try_from(TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1)
                            .unwrap_or(u64::MAX),
                    });
                }
                Ok(Some(norito::DecodeLimits::new(
                    TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_REQUEST_MAX_DECODE_ALLOCATED_BYTES_V1,
                    64,
                )))
            }
            NETWORK_MESSAGE_TORII_PROXY_RESPONSE_TAG => {
                use torii_proxy::{
                    TORII_PROXY_RESPONSE_MAX_DECODE_ALLOCATED_BYTES_V1,
                    TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1,
                };
                if framed_len > TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1 {
                    return Err(norito::core::Error::ArchiveLengthExceeded {
                        length: u64::try_from(framed_len).unwrap_or(u64::MAX),
                        limit: u64::try_from(TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1)
                            .unwrap_or(u64::MAX),
                    });
                }
                Ok(Some(norito::DecodeLimits::new(
                    TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1,
                    TORII_PROXY_RESPONSE_MAX_DECODE_ALLOCATED_BYTES_V1,
                    64,
                )))
            }
            NETWORK_MESSAGE_SUMERAGI_TAG => {
                let (_, remaining) = inbound_enum_parts(payload)?;
                let field = inbound_owned_enum_field(remaining, flags)?;
                sumeragi::net::inbound_decode_limits(field, framed_len, flags).map(Some)
            }
            6..=15 => Ok(None),
            _ => Err(norito::core::Error::Message(
                "unknown core network-message discriminant".to_owned(),
            )),
        }
    }
    fn is_outbound_allowed(&self) -> bool {
        match self {
            // Never send a frame the receivers could not classify.
            Self::Sumeragi(frame) => frame.class().is_some(),
            _ => true,
        }
    }
}
pub mod role {
    //! Module with extension for [`RoleId`] to be stored inside state.
    use super::*;
    use derive_more::Constructor;
    /// Sole Model-owned canonical native role-assignment key.
    pub use iroha_data_model::role::RoleIdWithOwner;
    use iroha_primitives::impl_as_dyn_key;
    /// Reference to [`RoleIdWithOwner`].
    #[derive(Debug, Clone, Copy, Constructor, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RoleIdWithOwnerRef<'role> {
        /// [`AccountId`] of the owner.
        pub account: &'role AccountId,
        /// [`RoleId`]  of the given role.
        pub role: &'role RoleId,
    }
    impl AsRoleIdWithOwnerRef for RoleIdWithOwner {
        fn as_key(&self) -> RoleIdWithOwnerRef<'_> {
            RoleIdWithOwnerRef {
                account: &self.account,
                role: &self.id,
            }
        }
    }
    impl_as_dyn_key! {
        target: RoleIdWithOwner,
        key: RoleIdWithOwnerRef<'_>,
        trait: AsRoleIdWithOwnerRef
    }
}
// RoleIdWithOwner derives codec implementations in the role module above.
pub mod prelude {
    //! Re-exports important traits and types. Meant to be glob imported when using `Iroha`.
    #[doc(inline)]
    pub use crate::{
        oracle::{ObservationAdmission, OracleAggregator, aggregate},
        smartcontracts::ValidSingularQuery,
        state::{StateReadOnly, StateView, World, WorldReadOnly},
        tx::AcceptedTransaction,
    };
    #[doc(inline)]
    pub use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, PublicKey};
}
// These synthetic-state regressions need deliberately nonshipping validation
// or state-apply fixtures. Compile them inside the library test harness so
// ordinary `cargo test` keeps exercising them without exporting fixture
// authority from production builds.
#[cfg(test)]
extern crate self as iroha_core;
#[cfg(test)]
#[path = "../tests/adversarial_block_rejections.rs"]
mod adversarial_block_rejections_tests;
#[cfg(test)]
#[path = "../tests/bls_batch_pop.rs"]
mod bls_batch_pop_tests;
#[cfg(test)]
#[path = "../tests/event_ordering.rs"]
mod event_ordering_tests;
#[cfg(test)]
#[path = "../tests/execute_trigger_events.rs"]
mod execute_trigger_events_tests;
#[cfg(test)]
pub(crate) mod execution_output_test_support;
#[cfg(test)]
mod frame_identity_tests;
#[cfg(test)]
pub(crate) mod ivm_test_support;
#[cfg(any(test, feature = "iroha-core-tests"))]
pub(crate) mod manifest_signing_test_support;
#[cfg(test)]
#[path = "../tests/common/native_validation.rs"]
mod native_validation;
#[cfg(test)]
pub(crate) mod unit_test_support;
// Governance height/custody fixtures use explicit synthetic publication,
// so they share this nonshipping harness rather than exporting that authority.
#[cfg(test)]
#[path = "../tests/gov_plain_referendum_open_event.rs"]
mod gov_plain_referendum_open_event_tests;
#[cfg(test)]
#[path = "../tests/gov_referendum_open_close.rs"]
mod gov_referendum_open_close_tests;
#[cfg(test)]
#[path = "../tests/gov_slash_and_restitute.rs"]
mod gov_slash_and_restitute_tests;
#[cfg(test)]
#[path = "../tests/gov_unlock_sweep.rs"]
mod gov_unlock_sweep_tests;
#[cfg(test)]
#[path = "../tests/isi_gas_fees.rs"]
mod isi_gas_fees_tests;
#[cfg(test)]
#[path = "../tests/ivm_corehost_axt.rs"]
mod ivm_corehost_axt_tests;
#[cfg(test)]
mod network_payload_tests;
#[cfg(test)]
#[path = "../tests/overlay_chunking.rs"]
mod overlay_chunking_tests;
#[cfg(test)]
#[path = "../tests/overlay_workers_parity.rs"]
mod overlay_workers_parity_tests;
#[cfg(test)]
#[path = "../tests/parallel_apply_knob.rs"]
mod parallel_apply_knob_tests;
#[cfg(test)]
#[path = "../tests/parallel_apply.rs"]
mod parallel_apply_tests;
#[cfg(test)]
#[path = "../tests/pipeline_warning_event.rs"]
mod pipeline_warning_event_tests;
#[cfg(test)]
#[path = "../tests/scheduler_gpu_key_bucket_parity.rs"]
mod scheduler_gpu_key_bucket_parity_tests;
#[cfg(test)]
#[path = "../tests/scheduler_ready_queue_heap_parity.rs"]
mod scheduler_ready_queue_heap_parity_tests;
#[cfg(test)]
#[path = "../tests/scheduler_telemetry.rs"]
mod scheduler_telemetry_tests;
#[cfg(test)]
#[path = "../tests/signature_batch_determinism.rs"]
mod signature_batch_determinism_tests;
#[cfg(test)]
#[path = "../tests/snapshots.rs"]
mod synthetic_state_snapshots;
#[cfg(test)]
#[path = "../tests/validation_fee_admission.rs"]
mod validation_fee_admission_tests;
#[cfg(test)]
mod tests {
    use crate::{
        NetworkMessage, PeerTrustGossip, PeersGossip,
        gossiper::{GossipPlane, GossipRoute, GossipTransaction, TransactionGossip},
        queue::{RoutingDecision, RoutingPlan},
        role::RoleIdWithOwner,
        torii_proxy::{
            TORII_PROXY_NETWORK_MESSAGE_OVERHEAD_BYTES_V1,
            TORII_PROXY_REQUEST_MAX_DECODE_ALLOCATED_BYTES_V1,
            TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1, TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1,
            TORII_PROXY_REQUEST_VERSION_V1, TORII_PROXY_RESPONSE_MAX_ENCODED_BYTES_V1,
            TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1, TORII_PROXY_RESPONSE_VERSION_V1,
            ToriiFanoutRouteScopeV1, ToriiProxyHttpResponseV1, ToriiProxyRequestKindV1,
            ToriiProxyRequestV1, ToriiProxyResponseFormatV1, ToriiProxyResponseV1,
            ToriiReadEndpointV1, ToriiReadProxyRequestV1, ToriiRouteHintV1, ToriiRoutingPlanHintV1,
        },
    };
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::block::BlockHeader;
    use iroha_data_model::role::RoleId;
    use iroha_data_model::transaction::{TransactionBuilder, TransactionEntrypoint};
    use iroha_data_model::{Level, NetworkId, isi::Log};
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use iroha_p2p::{
        ClassifyTopic,
        network::message::{SubscriberRoute, Topic as NetworkTopic},
    };
    use iroha_test_samples::gen_account_in;
    use norito::{codec::Encode, core as ncore};
    use std::{cmp::Ordering, collections::BTreeMap, sync::Arc, time::Duration};
    fn test_network_id(label: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            label,
        )))
    }
    fn checked_topic_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked network topic keypair")
    }
    fn assert_network_admission(
        message: &NetworkMessage,
        expected: iroha_p2p::TransportAdmissionClass,
    ) {
        assert_eq!(message.admission_class(), expected);
        for requested in [0, ncore::header_flags::COMPACT_LEN] {
            let (bare, flags) = {
                let _encode_guard = ncore::DecodeFlagsGuard::enter(requested);
                norito::codec::encode_with_header_flags(message)
            };
            let _decode_guard = ncore::DecodeFlagsGuard::enter(flags);
            assert_eq!(
                NetworkMessage::inbound_admission_class(&bare, flags).unwrap(),
                expected
            );
            let (decoded, consumed) = ncore::decode_field_canonical::<NetworkMessage>(&bare)
                .expect("canonical message still decodes under advertised flags");
            assert_eq!(
                consumed,
                bare.len(),
                "canonical decode consumes the exact payload"
            );
            assert_eq!(decoded.admission_class(), expected);
            assert_eq!(
                decoded.topic(),
                message.topic(),
                "classification does not change topic caps"
            );
        }
    }
    fn raw_network_topic(message: &NetworkMessage) -> NetworkTopic {
        assert_network_admission(message, message.admission_class());
        let encoded = ncore::to_bytes(message).expect("encode raw-topic fixture");
        let view = ncore::from_bytes_view(&encoded).expect("inspect raw-topic fixture");
        <NetworkMessage as ClassifyTopic>::inbound_topic(view.as_bytes(), view.flags())
            .expect("classify well-formed raw network payload")
            .expect("core network messages have a total raw classifier")
    }
    fn raw_network_tag(message: &NetworkMessage) -> u32 {
        let encoded = ncore::to_bytes(message).expect("encode raw-tag fixture");
        let view = ncore::from_bytes_view(&encoded).expect("inspect raw-tag fixture");
        super::inbound_enum_parts(view.as_bytes())
            .expect("extract core network-message discriminant")
            .0
    }
    #[test]
    fn network_topic_fixture_uses_checked_ed25519_keypair() {
        let keypair = checked_topic_keypair();
        assert_eq!(
            keypair
                .public_key()
                .try_algorithm()
                .expect("checked topic fixture key algorithm"),
            iroha_crypto::Algorithm::Ed25519
        );
    }
    fn canonical_signed_transaction_payload(
        signed: &iroha_data_model::transaction::SignedTransaction,
    ) -> Arc<Vec<u8>> {
        Arc::new(
            ncore::to_bytes(
                &iroha_data_model::transaction::TransactionEntrypoint::External(signed.clone()),
            )
            .expect("encode signed transaction entrypoint"),
        )
    }
    #[test]
    fn trust_gossip_classifies_to_trust_topic() {
        let gossip = PeerTrustGossip {
            network_id: test_network_id(b"trust-gossip-topic"),
            trust: Vec::new(),
        };
        let msg = NetworkMessage::PeerTrustGossip(Box::new(gossip));
        assert!(matches!(
            msg.topic(),
            iroha_p2p::network::message::Topic::TrustGossip
        ));
    }
    #[test]
    fn current_network_tags_preserve_distinct_protocol_identity() {
        use iroha_primitives::unique_vec::UniqueVec;
        use iroha_torii_shared::connect::{ConnectP2pMessageV1, ConnectSessionTerminatedV1};
        use norito::streaming::{ControlErrorFrame, ErrorCode};
        let fixtures = vec![
            (
                NetworkMessage::PeersGossiper(Box::new(PeersGossip {
                    peers: UniqueVec::new(),
                    peer_capabilities: BTreeMap::new(),
                })),
                7,
                NetworkTopic::PeerGossip,
                SubscriberRoute::General,
            ),
            (
                NetworkMessage::PeerTrustGossip(Box::new(PeerTrustGossip {
                    network_id: test_network_id(b"trust-gossip-wire-tag"),
                    trust: Vec::new(),
                })),
                8,
                NetworkTopic::TrustGossip,
                SubscriberRoute::General,
            ),
            (
                NetworkMessage::Health,
                9,
                NetworkTopic::Health,
                SubscriberRoute::General,
            ),
            (
                NetworkMessage::TimePing(Box::new(crate::time::TimePing { id: 1, t1_ms: 2 })),
                10,
                NetworkTopic::Health,
                SubscriberRoute::General,
            ),
            (
                NetworkMessage::TimePong(Box::new(crate::time::TimePong {
                    id: 1,
                    t2_ms: 2,
                    t3_ms: 3,
                })),
                11,
                NetworkTopic::Health,
                SubscriberRoute::General,
            ),
            (
                NetworkMessage::Connect(Box::new(ConnectP2pMessageV1::SessionTerminated(
                    ConnectSessionTerminatedV1 {
                        sid: [0x14; 32],
                        reason: "closed".to_owned(),
                    },
                ))),
                12,
                NetworkTopic::Connect,
                SubscriberRoute::Connect,
            ),
            (
                NetworkMessage::StreamingControl(Box::new(norito::streaming::ControlFrame::Error(
                    ControlErrorFrame {
                        code: ErrorCode::ProtocolViolation,
                        message: "invalid frame".to_owned(),
                    },
                ))),
                15,
                NetworkTopic::Control,
                SubscriberRoute::General,
            ),
        ];
        for (message, expected_tag, expected_topic, expected_route) in fixtures {
            assert_eq!(raw_network_tag(&message), expected_tag);
            assert_eq!(message.topic(), expected_topic);
            assert_eq!(raw_network_topic(&message), expected_topic);
            assert_eq!(message.subscriber_route(), expected_route);
        }
    }
    #[test]
    fn retired_network_tags_are_rejected_before_payload_decode() {
        for requested in [0, ncore::header_flags::COMPACT_LEN] {
            let (mut payload, flags) = {
                let _guard = ncore::DecodeFlagsGuard::enter(requested);
                norito::codec::encode_with_header_flags(&NetworkMessage::Health)
            };
            for tag in [0_u32, 1, 2, 3, 4, 5, 16, 17, 19, u32::MAX] {
                payload[..4].copy_from_slice(&tag.to_le_bytes());
                assert!(NetworkMessage::inbound_topic(&payload, flags).is_err());
                assert!(
                    NetworkMessage::inbound_decode_limits(&payload, usize::MAX, flags).is_err()
                );
                let _guard = ncore::DecodeFlagsGuard::enter(flags);
                assert!(ncore::decode_field_canonical::<NetworkMessage>(&payload).is_err());
                // An unbounded dynamic payload cannot turn an unknown tag into a decoder.
                let mut malicious = payload.clone();
                malicious.extend_from_slice(&u64::MAX.to_le_bytes());
                assert!(NetworkMessage::inbound_topic(&malicious, flags).is_err());
                assert!(
                    NetworkMessage::inbound_decode_limits(&malicious, usize::MAX, flags).is_err()
                );
            }
        }
    }
    #[test]
    fn role_id_with_owner_parse_roundtrip() {
        let (account, _keypair) = gen_account_in("wonderland");
        let role: RoleId = "auditor".parse().expect("valid role id");
        let rid = RoleIdWithOwner {
            account: account.clone(),
            id: role.clone(),
        };
        let encoded = rid.to_string();
        let decoded: RoleIdWithOwner = encoded.parse().expect("roundtrip");
        assert_eq!(decoded.account.subject_id(), account.subject_id());
        assert_eq!(decoded.id, role);
    }
    #[test]
    fn network_message_decode_from_slice_roundtrip() {
        let message = NetworkMessage::Health;
        let bytes = norito::to_bytes(&message).expect("encode network message");
        let view = norito::core::from_bytes_view(&bytes).expect("archive view");
        let decoded: NetworkMessage = view.decode().expect("decode network message");
        assert!(matches!(decoded, NetworkMessage::Health));
        assert_eq!(raw_network_topic(&message), NetworkTopic::Health);
    }
    #[test]
    fn raw_network_topic_is_total_for_restricted_gossip_and_fails_closed_on_unknown_layouts() {
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_core::tests::raw_network_topic_is_total_for_restricted_gossip_and_fails_closed_on_unknown_layouts::SingleFieldNetworkMessage"
        )]
        #[derive(Encode)]
        enum SingleFieldNetworkMessage {
            Field(u8),
        }
        let restricted = NetworkMessage::TransactionGossiper(Arc::new(TransactionGossip {
            txs: Vec::new(),
            routes: Vec::new(),
            plans: Vec::new(),
            plane: GossipPlane::Restricted,
        }));
        assert_eq!(
            raw_network_topic(&restricted),
            NetworkTopic::TxGossipRestricted
        );
        for (tag, expected) in [
            (7_u32, NetworkTopic::PeerGossip),
            (8, NetworkTopic::TrustGossip),
            (10, NetworkTopic::Health),
            (11, NetworkTopic::Health),
            (12, NetworkTopic::Connect),
            (13, NetworkTopic::Control),
            (14, NetworkTopic::Control),
            (15, NetworkTopic::Control),
        ] {
            let (mut payload, flags) =
                norito::codec::encode_with_header_flags(&SingleFieldNetworkMessage::Field(0));
            payload[..core::mem::size_of::<u32>()].copy_from_slice(&tag.to_le_bytes());
            let classified = <NetworkMessage as ClassifyTopic>::inbound_topic(&payload, flags)
                .expect("classify explicit first-release tag");
            assert_eq!(
                classified,
                Some(expected),
                "wire tag {tag} must retain its exact first-release transport class"
            );
        }
        let flags = ncore::default_encode_flags();
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_topic(&19_u32.to_le_bytes(), flags).is_err(),
            "the first tag after the compact range (18 is the Sumeragi frame) must fail before typed decode"
        );
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_topic(&18_u32.to_le_bytes(), flags).is_err(),
            "a Sumeragi tag without its frame must fail before typed decode"
        );
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_topic(&99_u32.to_le_bytes(), flags).is_err(),
            "unknown network-message tags must fail before typed decode"
        );
        let mut trailing_health = 9_u32.to_le_bytes().to_vec();
        trailing_health.push(0);
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_topic(&trailing_health, flags).is_err(),
            "the unit health tag must not hide a trailing dynamic payload"
        );
    }

    #[test]
    fn torii_proxy_control_message_classification_covers_current_variants() {
        let torii_request = NetworkMessage::ToriiProxyRequest(Arc::new(ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::prehashed([0x14; 32]),
            deadline_unix_ms: 1_900_000_000_000,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::Read(ToriiReadProxyRequestV1 {
                endpoint: ToriiReadEndpointV1::AccountsList,
                route_scope: ToriiFanoutRouteScopeV1::AllDataspaces,
                expected_route: ToriiRouteHintV1 {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
                path_args: Vec::new(),
                query_string: None,
                body: Vec::new(),
                response_format: ToriiProxyResponseFormatV1::Json,
            }),
        }));
        let torii_response = NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id: Hash::prehashed([0x15; 32]),
            response: ToriiProxyHttpResponseV1 {
                status_code: 200,
                headers: Vec::new(),
                body: Vec::new(),
            },
        }));
        assert!(torii_request.is_torii_proxy_control_message());
        assert!(torii_response.is_torii_proxy_control_message());
        assert!(!NetworkMessage::Health.is_torii_proxy_control_message());
        for (message, expected_tag) in [(&torii_request, 13), (&torii_response, 14)] {
            assert_eq!(raw_network_tag(message), expected_tag);
            assert_eq!(message.topic(), NetworkTopic::Control);
            assert_eq!(raw_network_topic(message), NetworkTopic::Control);
            assert_eq!(message.subscriber_route(), SubscriberRoute::ToriiProxy);
            assert_eq!(
                iroha_p2p::network::reliable_progress_class(
                    message.topic(),
                    message.subscriber_route(),
                ),
                None,
                "Torii proxy request/response carriers must use recoverable best-effort admission, not the reliable-progress corridor"
            );
        }
        let target = PeerId::from(
            KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::BlsNormal)
                .expect("generate canonical relay peer")
                .public_key()
                .clone(),
        );
        let capped = crate::IrohaNetwork::closed_for_tests()
            .with_topic_plaintext_frame_cap_for_tests(NetworkTopic::Control, 1);
        for message in [torii_request.clone(), torii_response.clone()] {
            match capped.post_best_effort_recoverable(iroha_p2p::Post {
                data: message,
                peer_id: target.clone(),
                priority: iroha_p2p::Priority::High,
            }) {
                Err(iroha_p2p::network::NetworkPostAdmissionError::Rejected {
                    message,
                    reason: iroha_p2p::network::NetworkActorAdmissionRejection::FrameTooLarge,
                }) => {
                    assert_eq!(message.data.topic(), NetworkTopic::Control);
                    assert_eq!(message.data.subscriber_route(), SubscriberRoute::ToriiProxy);
                }
                other => panic!(
                    "oversized actual Torii proxy carrier must fail exact recoverable admission: {other:?}"
                ),
            }
        }
        let network = crate::IrohaNetwork::closed_for_tests();
        for message in [torii_request, torii_response] {
            match network.post_best_effort_recoverable(iroha_p2p::Post {
                data: message,
                peer_id: target.clone(),
                priority: iroha_p2p::Priority::High,
            }) {
                Err(iroha_p2p::network::NetworkPostAdmissionError::Closed { message }) => {
                    assert_eq!(message.data.topic(), NetworkTopic::Control);
                    assert_eq!(message.data.subscriber_route(), SubscriberRoute::ToriiProxy);
                }
                other => panic!(
                    "actual Torii proxy carrier must reach best-effort actor admission: {other:?}"
                ),
            }
        }
    }
    #[test]
    fn torii_proxy_carriers_preserve_request_wire_and_have_explicit_decode_caps() {
        #[derive(norito::NoritoSchema)]
        #[norito_schema(
            name = "iroha_core::tests::torii_proxy_carriers_preserve_request_wire_and_have_explicit_decode_caps::BoxToriiProxyCarrier",
            frame = "iroha_core::NetworkMessage"
        )]
        #[derive(Encode)]
        enum BoxToriiProxyCarrier {
            #[codec(index = 13)]
            Request(Box<ToriiProxyRequestV1>),
        }
        let request = ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::prehashed([0x24; 32]),
            deadline_unix_ms: 1_900_000_000_000,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::Read(ToriiReadProxyRequestV1 {
                endpoint: ToriiReadEndpointV1::AccountsList,
                route_scope: ToriiFanoutRouteScopeV1::AllDataspaces,
                expected_route: ToriiRouteHintV1 {
                    lane_id: LaneId::SINGLE,
                    dataspace_id: DataSpaceId::UNIVERSAL,
                },
                path_args: Vec::new(),
                query_string: None,
                body: Vec::new(),
                response_format: ToriiProxyResponseFormatV1::Json,
            }),
        };
        // This payload-only fixture varies ownership under the actual network frame.
        let (boxed_payload, boxed_flags) = norito::codec::encode_with_header_flags(
            &BoxToriiProxyCarrier::Request(Box::new(request.clone())),
        );
        let boxed =
            ncore::frame_bare_with_header_flags::<NetworkMessage>(&boxed_payload, boxed_flags)
                .expect("frame Box proxy carrier with the live owner");
        let boxed_view = ncore::from_bytes_view(&boxed).expect("valid Box carrier frame/checksum");
        assert_eq!(
            boxed_view.schema(),
            norito::schema::identity::frame_hash::<NetworkMessage>()
        );
        assert_eq!(boxed_view.as_bytes(), boxed_payload);
        let shared = ncore::to_bytes(&NetworkMessage::ToriiProxyRequest(Arc::new(request)))
            .expect("encode Arc proxy carrier");
        assert_eq!(
            shared, boxed,
            "Box-to-Arc ownership must not change wire bytes"
        );
        let origin_key = KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::BlsNormal)
            .expect("generate proxy relay origin key");
        let origin = PeerId::new(origin_key.public_key().clone());
        let live = ncore::decode_from_bytes::<NetworkMessage>(&shared)
            .expect("decode live Arc proxy carrier");
        let p2p_wire_len = iroha_p2p::network::data_frame_wire_len(&origin, None, &live);
        assert_ne!(p2p_wire_len, usize::MAX, "valid node relay geometry");
        let view = ncore::from_bytes_view(&shared).expect("inspect proxy carrier frame");
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_decode_limits(
                view.as_bytes(),
                p2p_wire_len,
                view.flags(),
            )
            .expect("derive proxy decode limits")
            .is_some()
        );
        assert!(matches!(
            <NetworkMessage as ClassifyTopic>::inbound_decode_limits(
                view.as_bytes(),
                TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1 + 1,
                view.flags(),
            ),
            Err(ncore::Error::ArchiveLengthExceeded { .. })
        ));
        let worst_request_wire =
            iroha_p2p::network::broadcast_data_frame_wire_len_from_payload_len::<NetworkMessage>(
                TORII_PROXY_REQUEST_MAX_ENCODED_BYTES_V1
                    + TORII_PROXY_NETWORK_MESSAGE_OVERHEAD_BYTES_V1,
            );
        assert!(worst_request_wire <= TORII_PROXY_REQUEST_MAX_FRAME_BYTES_V1);
        let response = NetworkMessage::ToriiProxyResponse(Box::new(ToriiProxyResponseV1 {
            schema_version: TORII_PROXY_RESPONSE_VERSION_V1,
            request_id: Hash::prehashed([0x25; 32]),
            response: ToriiProxyHttpResponseV1 {
                status_code: 200,
                headers: Vec::new(),
                body: vec![0x5a; 32],
            },
        }));
        let response_bytes = ncore::to_bytes(&response).expect("encode proxy response carrier");
        let response_wire_len = iroha_p2p::network::data_frame_wire_len(&origin, None, &response);
        let response_view =
            ncore::from_bytes_view(&response_bytes).expect("inspect proxy response frame");
        assert!(
            <NetworkMessage as ClassifyTopic>::inbound_decode_limits(
                response_view.as_bytes(),
                response_wire_len,
                response_view.flags(),
            )
            .expect("derive proxy-response decode limits")
            .is_some()
        );
        assert!(matches!(
            <NetworkMessage as ClassifyTopic>::inbound_decode_limits(
                response_view.as_bytes(),
                TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1 + 1,
                response_view.flags(),
            ),
            Err(ncore::Error::ArchiveLengthExceeded { .. })
        ));
        let worst_response_wire =
            iroha_p2p::network::broadcast_data_frame_wire_len_from_payload_len::<NetworkMessage>(
                TORII_PROXY_RESPONSE_MAX_ENCODED_BYTES_V1
                    + TORII_PROXY_NETWORK_MESSAGE_OVERHEAD_BYTES_V1,
            );
        assert!(worst_response_wire <= TORII_PROXY_RESPONSE_MAX_FRAME_BYTES_V1);
    }
    #[test]
    fn torii_proxy_submit_decode_budget_covers_ten_mib_transaction_carrier() {
        const TRANSACTION_BODY_BYTES: usize = 10 * 1024 * 1024;
        let (account, keypair) = gen_account_in("wonderland");
        let mut builder = TransactionBuilder::new(
            test_network_id(b"ten-mib-torii-proxy-submit"),
            account,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(1));
        let transaction = builder
            .with_instructions([Log::new(Level::INFO, "P".repeat(TRANSACTION_BODY_BYTES))])
            .sign(keypair.private_key());
        let route = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
        let message = NetworkMessage::ToriiProxyRequest(Arc::new(ToriiProxyRequestV1 {
            schema_version: TORII_PROXY_REQUEST_VERSION_V1,
            request_id: Hash::new(b"ten-mib-torii-proxy-submit-request"),
            deadline_unix_ms: 1_900_000_000_000,
            hop_count: 1,
            max_hops: 3,
            visited_peer_ids: Vec::new(),
            request: ToriiProxyRequestKindV1::SubmitTransaction {
                transaction: TransactionEntrypoint::External(transaction),
                expected_plan: ToriiRoutingPlanHintV1::from(RoutingPlan::single(route)),
            },
        }));
        let encoded = ncore::to_bytes(&message).expect("encode 10 MiB proxy submission");
        let view = ncore::from_bytes_view(&encoded).expect("inspect 10 MiB proxy submission");
        let limits = <NetworkMessage as ClassifyTopic>::inbound_decode_limits(
            view.as_bytes(),
            encoded.len(),
            view.flags(),
        )
        .expect("select proxy submission decode policy")
        .expect("proxy submission installs explicit decode limits");
        assert_eq!(
            limits.max_total_allocated_bytes(),
            TORII_PROXY_REQUEST_MAX_DECODE_ALLOCATED_BYTES_V1
        );
        let decoded = ncore::decode_from_bytes_with_limits::<NetworkMessage>(&encoded, limits)
            .expect("decode exact 10 MiB proxy submission within its explicit allocation cap");
        let NetworkMessage::ToriiProxyRequest(decoded) = decoded else {
            panic!("decoded proxy submission changed its network-message variant");
        };
        let ToriiProxyRequestKindV1::SubmitTransaction { transaction, .. } = &decoded.request
        else {
            panic!("decoded proxy submission changed its request kind");
        };
        let TransactionEntrypoint::External(transaction) = transaction else {
            panic!("decoded proxy submission changed its transaction entrypoint");
        };
        let iroha_data_model::transaction::Executable::Instructions(instructions) =
            transaction.instructions()
        else {
            panic!("decoded proxy submission changed its executable kind");
        };
        let log = instructions
            .first()
            .and_then(|instruction| instruction.as_any().downcast_ref::<Log>())
            .expect("decoded proxy submission preserves its Log carrier");
        assert_eq!(instructions.len(), 1);
        assert_eq!(log.level, Level::INFO);
        assert_eq!(log.msg.len(), TRANSACTION_BODY_BYTES);
        assert!(log.msg.as_bytes().iter().all(|byte| *byte == b'P'));
    }
    #[test]
    fn network_message_roundtrip_cached_transaction_gossip() {
        let (account, keypair) = gen_account_in("wonderland");
        let network_id = test_network_id(b"cached-transaction-gossip");
        let mut builder = TransactionBuilder::new(
            network_id,
            account,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(0));
        let signed = builder
            .with_instructions([Log::new(Level::INFO, "ping".to_owned())])
            .sign(keypair.private_key());
        let payload = canonical_signed_transaction_payload(&signed);
        let route = GossipRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
        };
        let gossip = TransactionGossip {
            txs: vec![GossipTransaction::with_encoded(
                signed.clone(),
                Arc::clone(&payload),
            )],
            routes: vec![route],
            plans: vec![RoutingPlan::single(RoutingDecision::new(
                route.lane_id,
                route.dataspace_id,
            ))],
            plane: GossipPlane::Public,
        };
        let msg = NetworkMessage::TransactionGossiper(Arc::new(gossip));
        assert_eq!(raw_network_tag(&msg), 6);
        assert_eq!(raw_network_topic(&msg), NetworkTopic::TxGossip);
        let bytes = msg.encode();
        let (decoded, used) = <NetworkMessage as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
            .expect("decode gossip network");
        assert_eq!(used, bytes.len());
        match decoded {
            NetworkMessage::TransactionGossiper(gossip) => {
                assert_eq!(gossip.txs.len(), 1);
                assert_eq!(
                    gossip.txs[0]
                        .clone()
                        .into_entrypoint_with_payload()
                        .unwrap()
                        .0,
                    TransactionEntrypoint::External(signed.clone())
                );
                let (_, wire) = gossip.txs[0]
                    .clone()
                    .into_entrypoint_with_payload()
                    .expect("recover cached entrypoint frame");
                assert_eq!(wire.as_slice(), payload.as_slice());
                assert!(wire.starts_with(&ncore::MAGIC));
                assert_eq!(gossip.routes.len(), 1);
                assert_eq!(gossip.routes[0].lane_id, LaneId::SINGLE);
                assert_eq!(gossip.routes[0].dataspace_id, DataSpaceId::UNIVERSAL);
            }
            other => panic!("expected transaction gossip, got {other:?}"),
        }
    }
    #[test]
    fn network_message_roundtrip_cached_transaction_gossip_is_context_free() {
        let (account, keypair) = gen_account_in("wonderland");
        let network_id = test_network_id(b"context-free-cached-transaction-gossip");
        let mut builder = TransactionBuilder::new(
            network_id,
            account,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(0));
        let signed = builder
            .with_instructions([Log::new(Level::INFO, "pong".to_owned())])
            .sign(keypair.private_key());
        let canonical_payload = canonical_signed_transaction_payload(&signed);
        let payload = {
            let _guard = ncore::DecodeFlagsGuard::enter(ncore::header_flags::COMPACT_LEN);
            Arc::new(
                ncore::to_bytes(
                    &iroha_data_model::transaction::TransactionEntrypoint::External(signed.clone()),
                )
                .expect("encode signed transaction entrypoint"),
            )
        };
        std::thread::spawn(move || {
            let route = GossipRoute {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
            };
            let gossip = TransactionGossip {
                txs: vec![GossipTransaction::with_encoded(
                    signed.clone(),
                    Arc::clone(&payload),
                )],
                routes: vec![route],
                plans: vec![RoutingPlan::single(RoutingDecision::new(
                    route.lane_id,
                    route.dataspace_id,
                ))],
                plane: GossipPlane::Public,
            };
            let msg = NetworkMessage::TransactionGossiper(Arc::new(gossip));
            let bytes = msg.encode();
            let (decoded, used) =
                <NetworkMessage as ncore::DecodeFromSlice>::decode_from_slice(&bytes)
                    .expect("decode gossip network");
            assert_eq!(used, bytes.len());
            match decoded {
                NetworkMessage::TransactionGossiper(gossip) => {
                    assert_eq!(gossip.txs.len(), 1);
                    assert_eq!(
                        gossip.txs[0]
                            .clone()
                            .into_entrypoint_with_payload()
                            .unwrap()
                            .0,
                        TransactionEntrypoint::External(signed.clone())
                    );
                    let (_, wire) = gossip.txs[0]
                        .clone()
                        .into_entrypoint_with_payload()
                        .expect("recover context-free cached entrypoint frame");
                    assert_eq!(wire.as_slice(), canonical_payload.as_slice());
                    assert!(wire.starts_with(&ncore::MAGIC));
                    assert_eq!(gossip.routes.len(), 1);
                    assert_eq!(gossip.routes[0].lane_id, LaneId::SINGLE);
                    assert_eq!(gossip.routes[0].dataspace_id, DataSpaceId::UNIVERSAL);
                }
                other => panic!("expected transaction gossip, got {other:?}"),
            }
        })
        .join()
        .expect("context-free network gossip thread");
    }
    #[test]
    fn cmp_role_id_with_owner() {
        let role_id_a: RoleId = "a".parse().expect("failed to parse RoleId");
        let role_id_b: RoleId = "b".parse().expect("failed to parse RoleId");
        let (account_id_a, _account_keypair_a) = gen_account_in("domain");
        let (account_id_b, _account_keypair_b) = gen_account_in("domain");
        let mut role_ids_with_owner = Vec::new();
        for account_id in [&account_id_a, &account_id_b] {
            for role_id in [&role_id_a, &role_id_b] {
                role_ids_with_owner.push(RoleIdWithOwner {
                    id: role_id.clone(),
                    account: account_id.clone(),
                })
            }
        }
        for role_id_with_owner_1 in &role_ids_with_owner {
            for role_id_with_owner_2 in &role_ids_with_owner {
                match (
                    role_id_with_owner_1
                        .account
                        .cmp(&role_id_with_owner_2.account),
                    role_id_with_owner_1.id.cmp(&role_id_with_owner_2.id),
                ) {
                    // `AccountId` take precedence in comparison
                    // if `AccountId`s are equal than comparison based on `RoleId`s
                    (Ordering::Equal, ordering) | (ordering, _) => assert_eq!(
                        role_id_with_owner_1.cmp(role_id_with_owner_2),
                        ordering,
                        "{role_id_with_owner_1:?} and {role_id_with_owner_2:?} are expected to be {ordering:?}"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod test_allocations;

#[cfg(test)]
mod retail_fee_tests;
