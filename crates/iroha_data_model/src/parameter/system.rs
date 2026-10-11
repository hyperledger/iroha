//! Built-in parameter definitions and validation logic.
pub use self::model::*;
use super::{execution_output::ExecutionOutputPolicyV1, fastpq_source::FastpqSourcePolicyV1};

use super::custom::json_helpers;
use super::custom::{CustomParameter, CustomParameterId, CustomParameters};
use core::{
    convert::TryFrom,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    time::Duration,
};
use iroha_crypto::Algorithm;
use iroha_data_model_derive::model;
use iroha_primitives::{json::Json, numeric::Quantity};

use norito::json::{self, JsonDeserialize, JsonSerialize};

use std::collections::BTreeMap;
use std::sync::LazyLock;

mod npos_json;
pub use npos_json::{AdmittedSumeragiNposParameters, SumeragiNposJsonAdmissionError};
/// Maximum governed IVM heap size in bytes for ABI V1.
///
/// The ABI V1 address map reserves the half-open range `0x0010_0000..0x0020_0000` for the heap.
pub const IVM_HEAP_MAX_BYTES: u64 = 0x0010_0000;
/// Block-payload bytes the global proposer keeps free for a block's non-transaction fields.
///
/// This is the single owner of the reserve (`specs/zk_resource_contract.json`,
/// `block.payload_transaction_reserve_bytes`). The proposer selects framed transactions
/// within `max_block_bytes` less this reserve and queue admission refuses a transaction no
/// proposer can select, so both stages make the same decision from committed parameters.
pub const BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES: u32 = 64 * 1024;
/// Lane-payload bytes a lane proposer keeps free for the framing of its batch.
pub const LANE_BATCH_FRAMING_RESERVE_BYTES: u32 = 64;
/// A signed transaction larger than every payload the committed parameters allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "signed transaction is {encoded_bytes} bytes; the committed transaction and block payload limits include at most {max_bytes} bytes"
)]
pub struct TransactionNeverIncludable {
    /// Framed canonical length of the signed transaction.
    pub encoded_bytes: u64,
    /// Largest framed transaction a proposer of the committed chain can include.
    pub max_bytes: u64,
}
/// The proposers that can carry one signed transaction, decided by its committed route.
///
/// The route is part of the bound: a lane's payload limit helps only a transaction routed to
/// that lane. A caller that does not know the route uses [`Self::Global`]: a transaction
/// within the global budget is includable on every route, because the bound of a native lane
/// is never below the global one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionInclusionRoute {
    /// Routed to lane zero, or no native lane carries it: only the global proposer selects it.
    Global,
    /// Routed to a native lane. Its proposer selects the transaction within the lane's
    /// budget. The global proposer rescues a transaction of a stalled lane only within the
    /// global budget: a larger one is carried by its lane's proposer or by none.
    NativeLane {
        /// `max_block_bytes` pinned by the committed record of the routed lane.
        max_block_bytes: NonZeroU32,
    },
}
/// Largest framed signed transaction that is both admitted and includable in a block.
///
/// `max_tx_bytes` is the committed per-transaction cap, `max_block_bytes` the committed
/// global payload limit and `route` the proposers the transaction's committed route reaches.
/// A transaction is includable when one of those proposers can select it; the result is the
/// smaller of the cap and the largest selection budget on the route. It is zero when no
/// payload on the route leaves room for a transaction.
// TODO(X.2): the default payload limit (4 MiB) is below the transaction cap (10 MiB), so this
// bound is the payload budget today. Once parameter validation enforces
// `max_tx_bytes + reserve <= max_block_bytes` the result is always `max_tx_bytes`
// (`specs/zk_resource_contract.json`, `transaction_cap_fits_block_payload`).
#[must_use]
pub const fn max_includable_transaction_bytes(
    max_tx_bytes: NonZeroU64,
    max_block_bytes: NonZeroU32,
    route: TransactionInclusionRoute,
) -> u64 {
    let global = max_block_bytes
        .get()
        .saturating_sub(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES);
    let lane = match route {
        TransactionInclusionRoute::NativeLane { max_block_bytes } => max_block_bytes
            .get()
            .saturating_sub(LANE_BATCH_FRAMING_RESERVE_BYTES),
        TransactionInclusionRoute::Global => 0,
    };
    let payload = if global > lane { global } else { lane } as u64;
    if payload < max_tx_bytes.get() {
        payload
    } else {
        max_tx_bytes.get()
    }
}
/// Raw 32-byte consensus fingerprint with one canonical JSON representation.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parameter::system::ConsensusFingerprint")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
)]
pub struct ConsensusFingerprint(pub [u8; 32]);
impl ConsensusFingerprint {
    /// Construct from the canonical raw digest bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Return the raw digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}
impl core::fmt::Display for ConsensusFingerprint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "0x{}", hex::encode(self.0))
    }
}
impl JsonSerialize for ConsensusFingerprint {
    fn json_serialize(&self, out: &mut String) {
        json::write_json_string(&format!("0x{}", hex::encode(self.0)), out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        json::write_json_string_to(&format!("0x{}", hex::encode(self.0)), out)
    }
}

impl JsonDeserialize for ConsensusFingerprint {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let encoded = String::json_deserialize(parser)?;
        let body = encoded
            .strip_prefix("0x")
            .ok_or_else(|| json::Error::InvalidField {
                field: "consensus_fingerprint".to_owned(),
                message: "expected lowercase 0x-prefixed 32-byte hexadecimal digest".to_owned(),
            })?;
        if body.len() != 64
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(json::Error::InvalidField {
                field: "consensus_fingerprint".to_owned(),
                message: "expected lowercase 0x-prefixed 32-byte hexadecimal digest".to_owned(),
            });
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(body, &mut bytes).map_err(|error| json::Error::InvalidField {
            field: "consensus_fingerprint".to_owned(),
            message: error.to_string(),
        })?;
        Ok(Self(bytes))
    }
}
/// Where the committee of a Sumeragi instance comes from (§10 of `specs/sumeragi.md`).
///
/// Every committee member has one vote in both modes; the mode only selects the application
/// policy that schedules committees: the genesis roster and permissioned changes, or `NPoS`
/// elections.
// TODO(WP9): merge with `SumeragiConsensusMode`; both exist only because the signed genesis
// handshake metadata carries this JSON-tagged form while genesis builders use the other.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Decode,
    norito::codec::Encode,
    iroha_schema::IntoSchema,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(
    tag = "mode",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parameter::system::ConsensusMode")]
pub enum ConsensusMode {
    /// Every validator has voting power one.
    Permissioned,
    /// Stake selects the finalized epoch committee; every member has one vote.
    Npos,
}
impl ConsensusMode {
    /// Return whether this is permissioned consensus.
    #[must_use]
    pub const fn is_permissioned(self) -> bool {
        matches!(self, Self::Permissioned)
    }
}
impl From<SumeragiConsensusMode> for ConsensusMode {
    fn from(mode: SumeragiConsensusMode) -> Self {
        match mode {
            SumeragiConsensusMode::Permissioned => Self::Permissioned,
            SumeragiConsensusMode::Npos => Self::Npos,
        }
    }
}
impl From<ConsensusMode> for SumeragiConsensusMode {
    fn from(mode: ConsensusMode) -> Self {
        match mode {
            ConsensusMode::Permissioned => Self::Permissioned,
            ConsensusMode::Npos => Self::Npos,
        }
    }
}
/// Canonical signed Sumeragi handshake metadata stored in genesis.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::parameter::system::ConsensusHandshakeMetadata")]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::codec::Encode,
    norito::codec::Decode,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields)]
pub struct ConsensusHandshakeMetadata {
    /// Signed first-release consensus mode.
    pub mode: SumeragiConsensusMode,
    /// Signed immutable block cadence in milliseconds.
    pub block_cadence_ms: NonZeroU64,
    /// First-release consensus wire version.
    pub wire_protocol_version: u32,
    /// Canonical consensus fingerprint.
    pub consensus_fingerprint: ConsensusFingerprint,
    /// Signed inputs for the first Sumeragi height context.
    pub sumeragi_context: crate::block::consensus::SumeragiGenesisContextParameters,
}
impl ConsensusHandshakeMetadata {
    /// Validate the first-release signed handshake envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the wire version is not the first-release version
    /// or the signed Sumeragi context is invalid.
    pub fn validate(&self) -> Result<(), String> {
        let expected_version = u32::from(crate::sumeragi::PROTOCOL_VERSION);
        if self.wire_protocol_version != expected_version {
            return Err(
                "wire_protocol_version must equal the first-release protocol version".to_owned(),
            );
        }
        self.sumeragi_context
            .validate()
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

mod json_support {
    use super::*;
    use std::string::String;
    pub(super) type Map = BTreeMap<String, json::Value>;
    pub(super) fn write_field<T: JsonSerialize>(
        out: &mut String,
        first: &mut bool,
        key: &str,
        value: &T,
    ) {
        if *first {
            *first = false;
        } else {
            out.push(',');
        }
        json::write_json_string(key, out);
        out.push(':');
        value.json_serialize(out);
    }
    pub(super) fn write_field_to<T: JsonSerialize>(
        out: &mut dyn json::JsonWriteSink,
        first: &mut bool,
        key: &str,
        value: &T,
    ) -> Result<(), json::BoundedJsonError> {
        if *first {
            *first = false;
        } else {
            out.push(',')?;
        }
        json::write_json_string_to(key, out)?;
        out.push(':')?;
        value.json_serialize_to(out)
    }
    pub(super) fn expect_object(value: json::Value, context: &str) -> Result<Map, json::Error> {
        match value {
            json::Value::Object(map) => Ok(map),
            _ => Err(json::Error::InvalidField {
                field: context.into(),
                message: String::from("expected object"),
            }),
        }
    }
    pub(super) fn ensure_no_extra(map: Map) -> Result<(), json::Error> {
        if let Some((field, _)) = map.into_iter().next() {
            return Err(json::Error::UnknownField { field });
        }
        Ok(())
    }
    pub(super) fn expect_u64(value: &json::Value, field: &str) -> Result<u64, json::Error> {
        match value {
            json::Value::Number(num) => num.as_u64().ok_or_else(|| json::Error::InvalidField {
                field: field.to_owned(),
                message: String::from("expected unsigned integer"),
            }),
            _ => Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: String::from("expected unsigned integer"),
            }),
        }
    }
    pub(super) fn expect_nonzero_u64(
        value: &json::Value,
        field: &str,
    ) -> Result<NonZeroU64, json::Error> {
        let raw = expect_u64(value, field)?;
        NonZeroU64::new(raw).ok_or_else(|| json::Error::InvalidField {
            field: field.to_owned(),
            message: String::from("expected non-zero integer"),
        })
    }
    pub(super) fn expect_nonzero_u32(
        value: &json::Value,
        field: &str,
    ) -> Result<NonZeroU32, json::Error> {
        let raw = expect_u64(value, field)?;
        u32::try_from(raw)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| json::Error::InvalidField {
                field: field.to_owned(),
                message: String::from("expected non-zero integer that fits u32"),
            })
    }
    pub(super) fn expect_bool(value: &json::Value, field: &str) -> Result<bool, json::Error> {
        match value {
            json::Value::Bool(b) => Ok(*b),
            _ => Err(json::Error::InvalidField {
                field: field.to_owned(),
                message: String::from("expected boolean"),
            }),
        }
    }
    pub(super) fn expect_u8(value: &json::Value, field: &str) -> Result<u8, json::Error> {
        let raw = expect_u64(value, field)?;
        u8::try_from(raw).map_err(|_| json::Error::InvalidField {
            field: field.to_owned(),
            message: String::from("value out of range for u8"),
        })
    }
    pub(super) fn parse_value_as<T>(value: &json::Value) -> Result<T, json::Error>
    where
        T: JsonDeserialize,
    {
        let json =
            norito::json::to_json(value).map_err(|err| json::Error::Message(err.to_string()))?;
        let mut parser = norito::json::Parser::new(&json);
        T::json_deserialize(&mut parser)
    }
}

fn parse_custom_parameters_value(value: json::Value) -> Result<CustomParameters, json::Error> {
    let map = json_support::expect_object(value, "Parameters.custom")?;
    let value = json::Value::Object(map);
    json_helpers::from_value(value)
}
#[model]
mod model {
    use super::*;
    use derive_more::Display;
    use getset::{CopyGetters, Getters};
    use iroha_schema::IntoSchema;
    use norito::codec::{Decode, Encode};
    /// Consensus runtime mode
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SumeragiConsensusMode")]
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema,
    )]
    pub enum SumeragiConsensusMode {
        /// Classic permissioned Sumeragi
        Permissioned,
        /// Nominated Proof‑of‑Stake mode
        Npos,
    }
    // Bridge Norito codec to the bounded core slice-decoding path.
    impl<'a> norito::core::DecodeFromSlice<'a> for SumeragiConsensusMode {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let mut s: &'a [u8] = bytes;
            let value = <Self as norito::codec::DecodeAll>::decode_all(&mut s)
                .map_err(|e| norito::core::Error::Message(format!("codec decode error: {e}")))?;
            let used = bytes.len() - s.len();
            Ok((value, used))
        }
    }
    /// Limits that govern consensus operation
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SumeragiParameters")]
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    #[display("{block_cadence_ms},{max_clock_drift_ms}_SL")]
    pub struct SumeragiParameters {
        /// Signed-genesis block cadence in milliseconds (default 1000).
        ///
        /// A block is created if this limit or [`BlockParameters::max_transactions`] limit is reached,
        /// whichever comes first. Regardless of the limits, an empty block is never created.
        /// Sumeragi freezes this value at startup for both permissioned and
        /// `NPoS` operation; post-genesis updates are rejected.
        ///
        /// Under Sumeragi this is the target block time `ChainParams.block_time` (§9.3 of
        /// `specs/sumeragi.md`).
        // TODO(WP8): once the genesis handshake no longer freezes the cadence, give it a mutable
        // `SumeragiParameter` variant scheduled at `h + 2` like the other chain parameters.
        #[norito(default = "defaults::sumeragi::block_cadence_ms")]
        pub block_cadence_ms: NonZeroU64,
        /// Maximal allowed random deviation from the nominal rate
        ///
        /// # Warning
        ///
        /// This value should be kept as low as possible to not affect soundness of the consensus
        #[norito(default = "defaults::sumeragi::max_clock_drift_ms")]
        pub max_clock_drift_ms: u64,
        /// Minimum lead time (blocks) between publishing a new consensus key and activation.
        #[norito(default = "defaults::sumeragi::key_activation_lead_blocks")]
        pub key_activation_lead_blocks: u64,
        /// Overlap/grace window (blocks) permitting dual-signing during rotation.
        // TODO(WP9): delete. Sumeragi rotates a key at a single height and a committee never holds
        // two keys of one validator (§10.3 of `specs/sumeragi.md`); block validation still reads
        // this window for consensus-key liveness.
        #[norito(default = "defaults::sumeragi::key_overlap_grace_blocks")]
        pub key_overlap_grace_blocks: u64,
        /// Expiry grace window (blocks) after declared expiry.
        #[norito(default = "defaults::sumeragi::key_expiry_grace_blocks")]
        pub key_expiry_grace_blocks: u64,
        /// Allowed algorithms for consensus/committee keys.
        #[norito(default = "defaults::sumeragi::key_allowed_algorithms")]
        pub key_allowed_algorithms: Vec<iroha_crypto::Algorithm>,
        /// Payload rebuild retry interval in milliseconds, `ChainParams.payload_retry_interval`
        /// (default 5000). Must not be below [`Self::block_cadence_ms`] (§9.4).
        #[norito(default = "defaults::sumeragi::payload_retry_interval_ms")]
        pub payload_retry_interval_ms: NonZeroU64,
        /// Execution budget `E_max` in milliseconds, `ChainParams.e_max` (default 4000).
        #[norito(default = "defaults::sumeragi::exec_budget_ms")]
        pub exec_budget_ms: NonZeroU64,
        /// Apply budget `A_max` in milliseconds, `ChainParams.a_max` (default 1000).
        #[norito(default = "defaults::sumeragi::apply_budget_ms")]
        pub apply_budget_ms: NonZeroU64,
        /// Largest payload a block may carry in bytes, `ChainParams.max_block_bytes`
        /// (default 4 MiB). Must fit the transport frame limit with its overhead (§9.4, O10).
        #[norito(default = "defaults::sumeragi::max_block_bytes")]
        pub max_block_bytes: NonZeroU32,
        /// Epoch length in heights, `ChainParams.epoch_length` (default 3600, §11.7).
        #[norito(default = "defaults::sumeragi::epoch_length_blocks")]
        pub epoch_length_blocks: NonZeroU64,
        /// Demotion window `W` in heights (default 128; should be at least `4n`), a genesis
        /// constant of the instance passed in `Init.demotion_window` (§2.1, §10.1). It is not a
        /// chain parameter: it may only be set in the genesis block.
        #[norito(default = "defaults::sumeragi::demotion_window")]
        pub demotion_window: NonZeroU64,
    }
    /// NPoS-specific consensus parameters persisted as a custom parameter payload.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SumeragiNposParameters")]
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, IntoSchema)]
    #[norito(deny_unknown_fields)]
    pub struct SumeragiNposParameters {
        /// Canonical XOR asset authenticated by genesis for this network.
        ///
        /// This identity is immutable after installation; aliases and node-local
        /// selectors cannot introduce another staking currency.
        pub xor_asset_definition_id: crate::asset::AssetDefinitionId,
        /// Deterministic epoch seed used for PRF-based leader and validator selection.
        pub epoch_seed: [u8; 32],
        /// Exact bounded `3f + 1` ceiling for the next epoch committee.
        pub max_validators: u32,
        /// Minimum self-bond required for validator eligibility.
        pub min_self_bond: Quantity,
        /// Minimum nomination bond required for delegators.
        pub min_nomination_bond: Quantity,
        /// Finality margin in blocks before activating a newly elected set.
        pub finality_margin_blocks: u64,
        /// Evidence retention horizon in blocks.
        pub evidence_horizon_blocks: u64,
        /// Activation lag in blocks for newly scheduled validator sets.
        pub activation_lag_blocks: u64,
        /// Slashing delay in blocks before evidence penalties apply.
        pub slashing_delay_blocks: u64,
        /// Epoch length in blocks.
        pub epoch_length_blocks: NonZeroU64,
    }
    impl SumeragiNposParameters {
        /// Identifier used for the custom parameter storing `NPoS` tunables.
        pub const PARAMETER_ID_STR: &'static str = "sumeragi_npos_parameters";
        /// Exact UUID of the rejected `xor#nexus.universal` fixture.
        ///
        /// Validation compares these canonical bytes without constructing temporary
        /// domain, name or formatted seed allocations inside an admitted decode.
        pub(crate) const REJECTED_SYNTHETIC_XOR_ASSET_BYTES: [u8; 16] = [
            0x5e, 0xcd, 0x1e, 0x80, 0xac, 0x7d, 0x4d, 0x18, 0xb2, 0x27, 0x72, 0x09, 0x1a, 0x73,
            0xfc, 0x13,
        ];
        /// Construct the [`CustomParameterId`] associated with this payload.
        #[must_use]
        pub fn parameter_id() -> CustomParameterId {
            Self::PARAMETER_ID_STR
                .parse()
                .expect("valid sumeragi_npos custom parameter identifier")
        }
        /// Convert the payload into a [`CustomParameter`].
        #[must_use]
        pub fn into_custom_parameter(self) -> CustomParameter {
            CustomParameter::new(Self::parameter_id(), Json::new(self))
        }
        /// Decode this payload when the custom parameter names the `NPoS` policy.
        ///
        /// A different identifier is absent. A matching identifier retains the original
        /// decoder error, including a local resource refusal, instead of becoming absent.
        ///
        /// # Errors
        /// The matching payload cannot be decoded or violates the signed policy bounds.
        pub fn from_custom_parameter(
            custom: &CustomParameter,
        ) -> Result<Option<Self>, norito::json::Error> {
            if custom.id != Self::parameter_id() {
                return Ok(None);
            }
            let value = norito::json::from_str::<Self>(custom.payload().get())?;
            value
                .validate()
                .map_err(|message| norito::json::Error::InvalidField {
                    field: Self::PARAMETER_ID_STR.to_owned(),
                    message: message.to_owned(),
                })?;
            Ok(Some(value))
        }
        /// Canonical XOR asset authenticated by genesis for this network.
        #[must_use]
        pub fn xor_asset_definition_id(&self) -> &crate::asset::AssetDefinitionId {
            &self.xor_asset_definition_id
        }
        /// Exact bounded `3f + 1` ceiling for the next epoch committee.
        #[must_use]
        pub fn max_validators(&self) -> u32 {
            self.max_validators
        }
        /// Minimum self-bonded stake required for validators.
        #[must_use]
        pub fn min_self_bond(&self) -> &Quantity {
            &self.min_self_bond
        }
        /// Minimum nomination bond required for delegators.
        #[must_use]
        pub fn min_nomination_bond(&self) -> &Quantity {
            &self.min_nomination_bond
        }
        /// Finality margin in blocks before activating a newly elected set.
        #[must_use]
        pub fn finality_margin_blocks(&self) -> u64 {
            self.finality_margin_blocks
        }
        /// Number of blocks for which slashing evidence remains valid.
        #[must_use]
        pub fn evidence_horizon_blocks(&self) -> u64 {
            self.evidence_horizon_blocks
        }
        /// Number of blocks to wait before activating newly elected validators.
        #[must_use]
        pub fn activation_lag_blocks(&self) -> u64 {
            self.activation_lag_blocks
        }
        /// Slashing delay (blocks) before evidence penalties apply.
        #[must_use]
        pub fn slashing_delay_blocks(&self) -> u64 {
            self.slashing_delay_blocks
        }
        /// Epoch length measured in blocks.
        #[must_use]
        pub fn epoch_length_blocks(&self) -> NonZeroU64 {
            self.epoch_length_blocks
        }
        /// Epoch seed used for randomness-dependent protocols.
        #[must_use]
        pub fn epoch_seed(&self) -> [u8; 32] {
            self.epoch_seed
        }
        /// Override the epoch seed and return the updated payload.
        #[must_use]
        pub fn with_epoch_seed(mut self, value: [u8; 32]) -> Self {
            self.epoch_seed = value;
            self
        }
        /// Validate all signed `NPoS` election and reconfiguration invariants.
        ///
        /// # Errors
        /// Returns a stable diagnostic when a seed, bond,
        /// or reconfiguration bound is invalid.
        pub fn validate(&self) -> Result<(), &'static str> {
            // DM17 restores only fixed synthetic-identity reconstruction.
            #[cfg(not(all(test, sumeragi_model_mutation = "DM17")))]
            let synthetic_bytes = Self::REJECTED_SYNTHETIC_XOR_ASSET_BYTES;
            #[cfg(all(test, sumeragi_model_mutation = "DM17"))]
            let synthetic_bytes = crate::asset::AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::parse_fully_qualified("nexus.universal")
                    .expect("fixed synthetic domain"),
                "xor".parse().expect("fixed synthetic asset name"),
            )
            .aid_bytes();
            if self.xor_asset_definition_id.aid_bytes() == synthetic_bytes {
                return Err(
                    "NPoS must use the network's canonical XOR asset, not synthetic nexus.universal/xor",
                );
            }
            if self.epoch_seed == [0; 32] {
                return Err("epoch_seed must not be all zero");
            }
            if usize::try_from(self.max_validators)
                .ok()
                .is_none_or(|count| !crate::block::consensus::is_valid_committee_size(count))
            {
                return Err("max_validators must be a bounded 3f + 1 committee size (4..=31)");
            }
            if self.min_self_bond.is_zero() || self.min_nomination_bond.is_zero() {
                return Err("NPoS minimum bond values must be greater than zero");
            }
            if self.finality_margin_blocks == 0
                || self.evidence_horizon_blocks == 0
                || self.activation_lag_blocks == 0
                || self.slashing_delay_blocks == 0
            {
                return Err("NPoS finality and reconfiguration bounds must be greater than zero");
            }
            let accountability_window = self
                .evidence_horizon_blocks
                .checked_add(self.slashing_delay_blocks)
                .ok_or("NPoS evidence-and-slashing window overflows u64")?;
            let retained_roster_window = self
                .epoch_length_blocks
                .get()
                .checked_mul(3)
                .ok_or("NPoS three-epoch evidence capacity window overflows u64")?;
            if accountability_window > retained_roster_window {
                return Err(
                    "evidence_horizon_blocks + slashing_delay_blocks must not exceed three epoch lengths",
                );
            }
            Ok(())
        }
    }
    impl Default for SumeragiNposParameters {
        fn default() -> Self {
            use defaults::sumeragi::npos::*;
            Self {
                xor_asset_definition_id: crate::asset::AssetDefinitionId::parse_address_literal(
                    "6TEAJqbb8oEPmLncoNiMRbLEK6tw",
                )
                .expect(
                    "canonical Taira XOR identity; public Nexus genesis supplies its own identity",
                ),
                epoch_seed: [0xA5; 32],
                max_validators: max_validators(),
                min_self_bond: min_self_bond(),
                min_nomination_bond: min_nomination_bond(),
                finality_margin_blocks: finality_margin_blocks(),
                evidence_horizon_blocks: evidence_horizon_blocks(),
                activation_lag_blocks: activation_lag_blocks(),
                slashing_delay_blocks: slashing_delay_blocks(),
                epoch_length_blocks: epoch_length_blocks(),
            }
        }
    }
    impl From<SumeragiNposParameters> for CustomParameter {
        fn from(value: SumeragiNposParameters) -> Self {
            value.into_custom_parameter()
        }
    }
    /// Single Sumeragi parameter
    ///
    /// Check [`SumeragiParameters`] for more details
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SumeragiParameter")]
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    ///
    /// The Sumeragi chain parameters (`PayloadRetryIntervalMs` .. `EpochLengthBlocks`) are
    /// committed in the state after height `h` and take effect at `h + 2` (§10.1 of
    /// `specs/sumeragi.md`). `DemotionWindow` is a genesis constant: it is accepted only in the
    /// genesis block ([`Self::is_genesis_only`]).
    // `iroha_core::sumeragi::schedule` validates a change of the chain parameters with
    // `iroha_sumeragi::pacemaker::validate_chain`, schedules it through the lag-2 consensus
    // schedule and rejects `DemotionWindow` above the genesis height.
    pub enum SumeragiParameter {
        /// Maximum admitted clock drift. Block cadence is frozen in genesis and
        /// therefore deliberately has no mutable parameter variant.
        MaxClockDriftMs(u64),
        /// [`SumeragiParameters::payload_retry_interval_ms`].
        PayloadRetryIntervalMs(NonZeroU64),
        /// [`SumeragiParameters::exec_budget_ms`].
        ExecBudgetMs(NonZeroU64),
        /// [`SumeragiParameters::apply_budget_ms`].
        ApplyBudgetMs(NonZeroU64),
        /// [`SumeragiParameters::max_block_bytes`].
        MaxBlockBytes(NonZeroU32),
        /// [`SumeragiParameters::epoch_length_blocks`].
        EpochLengthBlocks(NonZeroU64),
        /// [`SumeragiParameters::demotion_window`]; genesis block only.
        DemotionWindow(NonZeroU64),
    }
    /// Limits that a block must obey to be accepted.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::BlockParameters")]
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        CopyGetters,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[display(
        "{max_transactions},{max_time_trigger_invocations},{execution_output},{fastpq_source}_BL"
    )]
    #[getset(get_copy = "pub")]
    pub struct BlockParameters {
        /// Maximal number of transactions in a block.
        ///
        /// A block is created if this limit is reached or [`SumeragiParameters::block_cadence_ms`] has expired,
        /// whichever comes first. Regardless of the limits, an empty block is never created.
        pub max_transactions: NonZeroU64,
        /// Independent active Time invocation count, captured before Network execution.
        /// Must remain within the genesis execution-output capacity envelope.
        pub max_time_trigger_invocations: NonZeroU32,
        /// Agreed immutable capacity envelope for output rows and trigger registries.
        pub execution_output: ExecutionOutputPolicyV1,
        /// Agreed immutable FASTPQ execution-source profile, installed at genesis.
        pub fastpq_source: FastpqSourcePolicyV1,
    }
    /// Single block parameter
    ///
    /// Check [`BlockParameters`] for more details
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::BlockParameter")]
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    #[expect(
        variant_size_differences,
        reason = "The Copy block parameter retains the complete immutable FASTPQ profile inline; boxing changes its API and allocation behavior."
    )]
    pub enum BlockParameter {
        MaxTransactions(NonZeroU64),
        /// Change the active Time count inside the committed capacity envelope.
        MaxTimeTriggerInvocations(NonZeroU32),
        /// Install the whole output capacity envelope at genesis.
        ExecutionOutput(ExecutionOutputPolicyV1),
        /// Install the whole FASTPQ execution-source profile at genesis.
        FastpqSource(FastpqSourcePolicyV1),
    }
    /// Limits that a transaction must obey to be accepted.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::TransactionParameters")]
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        CopyGetters,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[display(
        "{max_signatures},{max_instructions},{ivm_bytecode_size},{max_tx_bytes},{max_decompressed_bytes},{max_metadata_depth},{max_time_to_live_ms}_TL"
    )]
    #[getset(get_copy = "pub")]
    pub struct TransactionParameters {
        /// Maximum number of signatures allowed per transaction (non-zero).
        pub max_signatures: NonZeroU64,
        /// Maximum number of instructions per transaction
        pub max_instructions: NonZeroU64,
        /// Maximum size of IVM bytecode, in bytes
        pub ivm_bytecode_size: NonZeroU64,
        /// Maximum encoded transaction size accepted at admission (bytes).
        pub max_tx_bytes: NonZeroU64,
        /// Maximum post-decompression size accepted at admission (bytes).
        pub max_decompressed_bytes: NonZeroU64,
        /// Maximum allowed JSON nesting depth across transaction metadata values.
        pub max_metadata_depth: NonZeroU16,
        /// Maximum signature-bound wall-clock lifetime accepted for a transaction, in milliseconds.
        pub max_time_to_live_ms: NonZeroU64,
        /// Enforce height-based TTL metadata (`expires_at_height`) at admission.
        #[norito(default)]
        pub require_height_ttl: bool,
        /// Enforce strictly monotonic per-sender sequence metadata (`tx_sequence`) at admission.
        #[norito(default)]
        pub require_sequence: bool,
    }
    /// Single transaction parameter
    ///
    /// Check [`TransactionParameters`] for more details
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::TransactionParameter")]
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    pub enum TransactionParameter {
        MaxSignatures(NonZeroU64),
        MaxInstructions(NonZeroU64),
        IvmBytecodeSize(NonZeroU64),
        MaxTxBytes(NonZeroU64),
        MaxDecompressedBytes(NonZeroU64),
        MaxMetadataDepth(NonZeroU16),
        MaxTimeToLiveMs(NonZeroU64),
        RequireHeightTtl(bool),
        RequireSequence(bool),
    }
    /// Limits that a smart contract must obey at runtime to considered valid.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SmartContractParameters")]
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        CopyGetters,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[display("{fuel},{memory},{max_output_items},{max_output_bytes}_SCL")]
    #[getset(get_copy = "pub")]
    pub struct SmartContractParameters {
        /// Maximum amount of fuel that a smart contract can consume
        pub fuel: NonZeroU64,
        /// Maximum IVM heap size in bytes
        pub memory: NonZeroU64,
        /// Maximum depth of synchronous and chained trigger executions
        pub execution_depth: u8,
        /// Maximum number of effect artifacts retained by one IVM execution
        pub max_output_items: NonZeroU64,
        /// Maximum aggregate encoded size of effect artifacts retained by one IVM execution
        pub max_output_bytes: NonZeroU64,
    }
    /// Single smart contract parameter
    ///
    /// Check [`SmartContractParameters`] for more details
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::SmartContractParameter")]
    #[derive(
        Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema,
    )]
    pub enum SmartContractParameter {
        Fuel(NonZeroU64),
        Memory(NonZeroU64),
        ExecutionDepth(u8),
        MaxOutputItems(NonZeroU64),
        MaxOutputBytes(NonZeroU64),
    }
    /// Set of all current blockchain parameter values
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::Parameters")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        CopyGetters,
        Decode,
        Encode,
        IntoSchema,
    )]
    pub struct Parameters {
        /// Sumeragi parameters
        #[getset(get = "pub")]
        #[norito(default)]
        pub sumeragi: SumeragiParameters,
        /// Block parameters
        #[getset(get_copy = "pub")]
        #[norito(default)]
        pub block: BlockParameters,
        /// Transaction parameters
        #[getset(get_copy = "pub")]
        #[norito(default)]
        pub transaction: TransactionParameters,
        /// Executor parameters
        #[getset(get_copy = "pub")]
        #[norito(default)]
        pub executor: SmartContractParameters,
        /// Smart contract parameters
        #[getset(get_copy = "pub")]
        #[norito(default)]
        pub smart_contract: SmartContractParameters,
        /// Collection of blockchain specific parameters
        #[getset(get = "pub")]
        #[norito(default)]
        #[norito(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        pub custom: CustomParameters,
    }
    /// Single blockchain parameter.
    ///
    /// Check [`Parameters`] for more details
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::parameter::system::model::Parameter")]
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema)]
    pub enum Parameter {
        Sumeragi(SumeragiParameter),
        Block(BlockParameter),
        Transaction(TransactionParameter),
        SmartContract(SmartContractParameter),
        Executor(SmartContractParameter),
        Custom(CustomParameter),
    }
}
impl core::fmt::Display for Parameter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sumeragi(v) => core::fmt::Display::fmt(&v, f),
            Self::Block(v) => core::fmt::Display::fmt(&v, f),
            Self::Transaction(v) => core::fmt::Display::fmt(&v, f),
            Self::SmartContract(v) | Self::Executor(v) => core::fmt::Display::fmt(&v, f),
            Self::Custom(v) => write!(f, "{}({})", v.id, v.payload),
        }
    }
}

#[derive(norito::derive::JsonSerialize)]
struct SumeragiNposParametersJson {
    xor_asset_definition_id: crate::asset::AssetDefinitionId,
    epoch_seed: [u8; 32],
    max_validators: u32,
    min_self_bond: Quantity,
    min_nomination_bond: Quantity,
    finality_margin_blocks: u64,
    evidence_horizon_blocks: u64,
    activation_lag_blocks: u64,
    slashing_delay_blocks: u64,
    epoch_length_blocks: NonZeroU64,
}

impl From<SumeragiNposParameters> for SumeragiNposParametersJson {
    fn from(value: SumeragiNposParameters) -> Self {
        Self {
            xor_asset_definition_id: value.xor_asset_definition_id,
            epoch_seed: value.epoch_seed,
            max_validators: value.max_validators,
            min_self_bond: value.min_self_bond,
            min_nomination_bond: value.min_nomination_bond,
            finality_margin_blocks: value.finality_margin_blocks,
            evidence_horizon_blocks: value.evidence_horizon_blocks,
            activation_lag_blocks: value.activation_lag_blocks,
            slashing_delay_blocks: value.slashing_delay_blocks,
            epoch_length_blocks: value.epoch_length_blocks,
        }
    }
}

impl JsonSerialize for SumeragiNposParameters {
    fn json_serialize(&self, out: &mut String) {
        SumeragiNposParametersJson::from(self.clone()).json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(
                out,
                &mut first,
                "xor_asset_definition_id",
                &self.xor_asset_definition_id,
            )?;
            json_support::write_field_to(out, &mut first, "epoch_seed", &self.epoch_seed)?;
            json_support::write_field_to(out, &mut first, "max_validators", &self.max_validators)?;
            json_support::write_field_to(out, &mut first, "min_self_bond", &self.min_self_bond)?;
            json_support::write_field_to(
                out,
                &mut first,
                "min_nomination_bond",
                &self.min_nomination_bond,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "finality_margin_blocks",
                &self.finality_margin_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "evidence_horizon_blocks",
                &self.evidence_horizon_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "activation_lag_blocks",
                &self.activation_lag_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "slashing_delay_blocks",
                &self.slashing_delay_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "epoch_length_blocks",
                &self.epoch_length_blocks,
            )?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for SumeragiNposParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = npos_json::decode_ordinary(parser)?;
        npos_json::validate_outer(&value)?;
        Ok(value)
    }
}

impl JsonSerialize for Parameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        match self {
            Parameter::Sumeragi(value) => {
                json::write_json_string("Sumeragi", out);
                out.push(':');
                value.json_serialize(out);
            }
            Parameter::Block(value) => {
                json::write_json_string("Block", out);
                out.push(':');
                value.json_serialize(out);
            }
            Parameter::Transaction(value) => {
                json::write_json_string("Transaction", out);
                out.push(':');
                value.json_serialize(out);
            }
            Parameter::SmartContract(value) => {
                json::write_json_string("SmartContract", out);
                out.push(':');
                value.json_serialize(out);
            }
            Parameter::Executor(value) => {
                json::write_json_string("Executor", out);
                out.push(':');
                value.json_serialize(out);
            }
            Parameter::Custom(value) => {
                json::write_json_string("Custom", out);
                out.push(':');
                value.json_serialize(out);
            }
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                Parameter::Sumeragi(value) => {
                    out.push_str("\"Sumeragi\":")?;
                    value.json_serialize_to(out)?;
                }
                Parameter::Block(value) => {
                    out.push_str("\"Block\":")?;
                    value.json_serialize_to(out)?;
                }
                Parameter::Transaction(value) => {
                    out.push_str("\"Transaction\":")?;
                    value.json_serialize_to(out)?;
                }
                Parameter::SmartContract(value) => {
                    out.push_str("\"SmartContract\":")?;
                    value.json_serialize_to(out)?;
                }
                Parameter::Executor(value) => {
                    out.push_str("\"Executor\":")?;
                    value.json_serialize_to(out)?;
                }
                Parameter::Custom(value) => {
                    out.push_str("\"Custom\":")?;
                    value.json_serialize_to(out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for Parameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let map = json_support::expect_object(value, "Parameter")?;
        let mut iter = map.into_iter();
        let (field, payload) = iter.next().ok_or_else(|| json::Error::InvalidField {
            field: String::from("Parameter"),
            message: String::from("expected single-key object"),
        })?;
        if let Some((extra, _)) = iter.next() {
            return Err(json::Error::UnknownField { field: extra });
        }
        match field.as_str() {
            "Sumeragi" => Ok(Self::Sumeragi(json_support::parse_value_as::<
                SumeragiParameter,
            >(&payload)?)),
            "Block" => Ok(Self::Block(json_support::parse_value_as::<BlockParameter>(
                &payload,
            )?)),
            "Transaction" => Ok(Self::Transaction(json_support::parse_value_as::<
                TransactionParameter,
            >(&payload)?)),
            "SmartContract" => Ok(Self::SmartContract(json_support::parse_value_as::<
                SmartContractParameter,
            >(&payload)?)),
            "Executor" => Ok(Self::Executor(json_support::parse_value_as::<
                SmartContractParameter,
            >(&payload)?)),
            "Custom" => Ok(Self::Custom(
                json_support::parse_value_as::<CustomParameter>(&payload)?,
            )),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}

impl JsonSerialize for SumeragiConsensusMode {
    fn json_serialize(&self, out: &mut String) {
        let label = match self {
            SumeragiConsensusMode::Permissioned => "Permissioned",
            SumeragiConsensusMode::Npos => "Npos",
        };
        json::write_json_string(label, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        let label = match self {
            SumeragiConsensusMode::Permissioned => "Permissioned",
            SumeragiConsensusMode::Npos => "Npos",
        };
        json::write_json_string_to(label, out)
    }
}

impl JsonDeserialize for SumeragiConsensusMode {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = parser.parse_string()?;
        match value.as_str() {
            "Permissioned" => Ok(SumeragiConsensusMode::Permissioned),
            "Npos" => Ok(SumeragiConsensusMode::Npos),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}
// (Codecs are provided by derives and candidate decoders. Tests use wrappers where needed.)
impl SumeragiParameters {
    /// Maximum canonical block size in bytes.
    #[must_use]
    pub fn max_block_bytes(&self) -> NonZeroU32 {
        self.max_block_bytes
    }
    /// Execution time budget in milliseconds.
    #[must_use]
    pub fn exec_budget_ms(&self) -> NonZeroU64 {
        self.exec_budget_ms
    }
    /// Apply time budget in milliseconds.
    #[must_use]
    pub fn apply_budget_ms(&self) -> NonZeroU64 {
        self.apply_budget_ms
    }
    /// Signed, immutable block cadence in milliseconds.
    #[must_use]
    pub fn block_cadence_ms(&self) -> NonZeroU64 {
        self.block_cadence_ms
    }
    /// Raw clock drift bound in milliseconds.
    #[must_use]
    pub fn max_clock_drift_ms(&self) -> u64 {
        self.max_clock_drift_ms
    }
    /// Maximal allowed random deviation from the nominal rate
    ///
    /// # Warning
    ///
    /// This value should be kept as low as possible to not affect soundness of the consensus
    pub fn max_clock_drift(&self) -> Duration {
        Duration::from_millis(self.max_clock_drift_ms)
    }
    /// Signed interval between block-production opportunities.
    ///
    /// A block is created if this limit or [`BlockParameters::max_transactions`] limit is reached,
    /// whichever comes first. Regardless of the limits, an empty block is never created.
    /// This value is authoritative for both permissioned and `NPoS` pacemaker timing.
    pub fn block_cadence(&self) -> Duration {
        Duration::from_millis(self.block_cadence_ms.get())
    }
}

impl SumeragiParameter {
    /// Canonical JSON tag of this variant.
    #[must_use]
    pub const fn json_tag(&self) -> &'static str {
        match self {
            Self::MaxClockDriftMs(_) => "MaxClockDriftMs",
            Self::PayloadRetryIntervalMs(_) => "PayloadRetryIntervalMs",
            Self::ExecBudgetMs(_) => "ExecBudgetMs",
            Self::ApplyBudgetMs(_) => "ApplyBudgetMs",
            Self::MaxBlockBytes(_) => "MaxBlockBytes",
            Self::EpochLengthBlocks(_) => "EpochLengthBlocks",
            Self::DemotionWindow(_) => "DemotionWindow",
        }
    }

    /// The carried value widened to `u64` (every variant carries one unsigned integer).
    #[must_use]
    pub fn value_u64(&self) -> u64 {
        match self {
            Self::MaxClockDriftMs(value) => *value,
            Self::PayloadRetryIntervalMs(value)
            | Self::ExecBudgetMs(value)
            | Self::ApplyBudgetMs(value)
            | Self::EpochLengthBlocks(value)
            | Self::DemotionWindow(value) => value.get(),
            Self::MaxBlockBytes(value) => u64::from(value.get()),
        }
    }

    /// Whether this parameter may only be set in the genesis block (a genesis constant of the
    /// Sumeragi instance, never a chain parameter).
    #[must_use]
    pub const fn is_genesis_only(&self) -> bool {
        matches!(self, Self::DemotionWindow(_))
    }
}

impl JsonSerialize for SumeragiParameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        json::write_json_string(self.json_tag(), out);
        out.push(':');
        self.value_u64().json_serialize(out);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            json::write_json_string_to(self.json_tag(), out)?;
            out.push(':')?;
            self.value_u64().json_serialize_to(out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for SumeragiParameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let map = json_support::expect_object(value, "SumeragiParameter")?;
        let mut iter = map.into_iter();
        let (field, payload) = iter.next().ok_or_else(|| json::Error::InvalidField {
            field: String::from("SumeragiParameter"),
            message: String::from("expected single-key object"),
        })?;
        if let Some((extra, _)) = iter.next() {
            return Err(json::Error::UnknownField { field: extra });
        }
        let nonzero = |name: &str| json_support::expect_nonzero_u64(&payload, name);
        match field.as_str() {
            "MaxClockDriftMs" => Ok(Self::MaxClockDriftMs(json_support::expect_u64(
                &payload,
                "MaxClockDriftMs",
            )?)),
            "PayloadRetryIntervalMs" => Ok(Self::PayloadRetryIntervalMs(nonzero(&field)?)),
            "ExecBudgetMs" => Ok(Self::ExecBudgetMs(nonzero(&field)?)),
            "ApplyBudgetMs" => Ok(Self::ApplyBudgetMs(nonzero(&field)?)),
            "MaxBlockBytes" => Ok(Self::MaxBlockBytes(json_support::expect_nonzero_u32(
                &payload, &field,
            )?)),
            "EpochLengthBlocks" => Ok(Self::EpochLengthBlocks(nonzero(&field)?)),
            "DemotionWindow" => Ok(Self::DemotionWindow(nonzero(&field)?)),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}

impl JsonSerialize for SumeragiParameters {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        json_support::write_field(out, &mut first, "block_cadence_ms", &self.block_cadence_ms);
        json_support::write_field(
            out,
            &mut first,
            "max_clock_drift_ms",
            &self.max_clock_drift_ms,
        );
        json_support::write_field(
            out,
            &mut first,
            "key_activation_lead_blocks",
            &self.key_activation_lead_blocks,
        );
        json_support::write_field(
            out,
            &mut first,
            "key_overlap_grace_blocks",
            &self.key_overlap_grace_blocks,
        );
        json_support::write_field(
            out,
            &mut first,
            "key_expiry_grace_blocks",
            &self.key_expiry_grace_blocks,
        );
        json_support::write_field(
            out,
            &mut first,
            "key_allowed_algorithms",
            &self.key_allowed_algorithms,
        );
        json_support::write_field(
            out,
            &mut first,
            "payload_retry_interval_ms",
            &self.payload_retry_interval_ms,
        );
        json_support::write_field(out, &mut first, "exec_budget_ms", &self.exec_budget_ms);
        json_support::write_field(out, &mut first, "apply_budget_ms", &self.apply_budget_ms);
        json_support::write_field(out, &mut first, "max_block_bytes", &self.max_block_bytes);
        json_support::write_field(
            out,
            &mut first,
            "epoch_length_blocks",
            &self.epoch_length_blocks,
        );
        json_support::write_field(out, &mut first, "demotion_window", &self.demotion_window);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(
                out,
                &mut first,
                "block_cadence_ms",
                &self.block_cadence_ms,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_clock_drift_ms",
                &self.max_clock_drift_ms,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "key_activation_lead_blocks",
                &self.key_activation_lead_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "key_overlap_grace_blocks",
                &self.key_overlap_grace_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "key_expiry_grace_blocks",
                &self.key_expiry_grace_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "key_allowed_algorithms",
                &self.key_allowed_algorithms,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "payload_retry_interval_ms",
                &self.payload_retry_interval_ms,
            )?;
            json_support::write_field_to(out, &mut first, "exec_budget_ms", &self.exec_budget_ms)?;
            json_support::write_field_to(
                out,
                &mut first,
                "apply_budget_ms",
                &self.apply_budget_ms,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_block_bytes",
                &self.max_block_bytes,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "epoch_length_blocks",
                &self.epoch_length_blocks,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "demotion_window",
                &self.demotion_window,
            )?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for SumeragiParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let mut map = json_support::expect_object(value, "SumeragiParameters")?;
        let block_cadence_ms = map
            .remove("block_cadence_ms")
            .map(|value| json_support::expect_nonzero_u64(&value, "block_cadence_ms"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::block_cadence_ms);
        let max_clock_drift_ms = map
            .remove("max_clock_drift_ms")
            .map(|value| json_support::expect_u64(&value, "max_clock_drift_ms"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::max_clock_drift_ms);
        let key_activation_lead_blocks = map
            .remove("key_activation_lead_blocks")
            .map(|value| json_support::expect_u64(&value, "key_activation_lead_blocks"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::key_activation_lead_blocks);
        let key_overlap_grace_blocks = map
            .remove("key_overlap_grace_blocks")
            .map(|value| json_support::expect_u64(&value, "key_overlap_grace_blocks"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::key_overlap_grace_blocks);
        let key_expiry_grace_blocks = map
            .remove("key_expiry_grace_blocks")
            .map(|value| json_support::expect_u64(&value, "key_expiry_grace_blocks"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::key_expiry_grace_blocks);
        let key_allowed_algorithms = map
            .remove("key_allowed_algorithms")
            .map(|value| json_support::parse_value_as::<Vec<Algorithm>>(&value))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::key_allowed_algorithms);
        let mut nonzero = |field: &str, default: fn() -> NonZeroU64| {
            map.remove(field)
                .map(|value| json_support::expect_nonzero_u64(&value, field))
                .transpose()
                .map(|value| value.unwrap_or_else(default))
        };
        let payload_retry_interval_ms = nonzero(
            "payload_retry_interval_ms",
            defaults::sumeragi::payload_retry_interval_ms,
        )?;
        let exec_budget_ms = nonzero("exec_budget_ms", defaults::sumeragi::exec_budget_ms)?;
        let apply_budget_ms = nonzero("apply_budget_ms", defaults::sumeragi::apply_budget_ms)?;
        let epoch_length_blocks = nonzero(
            "epoch_length_blocks",
            defaults::sumeragi::epoch_length_blocks,
        )?;
        let demotion_window = nonzero("demotion_window", defaults::sumeragi::demotion_window)?;
        let max_block_bytes = map
            .remove("max_block_bytes")
            .map(|value| json_support::expect_nonzero_u32(&value, "max_block_bytes"))
            .transpose()?
            .unwrap_or_else(defaults::sumeragi::max_block_bytes);
        json_support::ensure_no_extra(map)?;
        let params = Self {
            block_cadence_ms,
            max_clock_drift_ms,
            key_activation_lead_blocks,
            key_overlap_grace_blocks,
            key_expiry_grace_blocks,
            key_allowed_algorithms,
            payload_retry_interval_ms,
            exec_budget_ms,
            apply_budget_ms,
            max_block_bytes,
            epoch_length_blocks,
            demotion_window,
        };
        Ok(params)
    }
}
mod defaults {
    pub mod sumeragi {
        use core::num::{NonZeroU32, NonZeroU64};
        use iroha_crypto::Algorithm;
        /// §9.3 default target block time: one second.
        pub const fn block_cadence_ms() -> NonZeroU64 {
            nonzero_ext::nonzero!(1_000_u64)
        }
        /// §9.3 default bounded payload rebuild retry interval.
        pub const fn payload_retry_interval_ms() -> NonZeroU64 {
            nonzero_ext::nonzero!(5_000_u64)
        }
        /// §9.3 default execution budget `E_max`.
        pub const fn exec_budget_ms() -> NonZeroU64 {
            nonzero_ext::nonzero!(4_000_u64)
        }
        /// §9.3 default apply budget `A_max`.
        pub const fn apply_budget_ms() -> NonZeroU64 {
            nonzero_ext::nonzero!(1_000_u64)
        }
        /// §9.3 default block payload limit: 4 MiB.
        pub const fn max_block_bytes() -> NonZeroU32 {
            nonzero_ext::nonzero!(4_194_304_u32)
        }
        /// Default epoch length: one hour at the default block time (Appendix E, E12).
        pub const fn epoch_length_blocks() -> NonZeroU64 {
            nonzero_ext::nonzero!(3_600_u64)
        }
        /// Default demotion window `W` (covers `W ≥ 4n` up to 32 members).
        pub const fn demotion_window() -> NonZeroU64 {
            nonzero_ext::nonzero!(128_u64)
        }
        pub const fn max_clock_drift_ms() -> u64 {
            1_000
        }
        pub const fn key_activation_lead_blocks() -> u64 {
            1
        }
        pub const fn key_overlap_grace_blocks() -> u64 {
            8
        }
        pub const fn key_expiry_grace_blocks() -> u64 {
            0
        }
        pub fn key_allowed_algorithms() -> Vec<Algorithm> {
            vec![Algorithm::BlsNormal]
        }
        pub mod npos {
            use core::num::NonZeroU64;
            use iroha_primitives::numeric::Quantity;
            pub const fn max_validators() -> u32 {
                31
            }
            pub fn min_self_bond() -> Quantity {
                Quantity::from(1_000_u64)
            }
            pub fn min_nomination_bond() -> Quantity {
                Quantity::one()
            }
            pub const fn finality_margin_blocks() -> u64 {
                8
            }
            pub const fn evidence_horizon_blocks() -> u64 {
                7_200
            }
            pub const fn activation_lag_blocks() -> u64 {
                1
            }
            pub const fn slashing_delay_blocks() -> u64 {
                3_600
            }
            pub const fn epoch_length_blocks() -> NonZeroU64 {
                nonzero_ext::nonzero!(3_600_u64)
            }
        }
    }
    pub mod block {
        use core::num::NonZeroU64;
        use nonzero_ext::nonzero;
        /// Default value for [`Parameters::MaxTransactionsInBlock`]
        pub const fn max_transactions() -> NonZeroU64 {
            nonzero!(2_u64.pow(9))
        }
    }
    pub mod transaction {
        use core::num::{NonZeroU16, NonZeroU64};
        use nonzero_ext::nonzero;
        pub const fn max_signatures() -> NonZeroU64 {
            nonzero!(16_u64)
        }
        pub const fn max_instructions() -> NonZeroU64 {
            // Keep in sync with iroha_config defaults::transaction::max_instructions.
            nonzero!(100_000_u64)
        }
        pub const fn ivm_bytecode_size() -> NonZeroU64 {
            nonzero!(4 * 2_u64.pow(20))
        }
        pub const fn max_tx_bytes() -> NonZeroU64 {
            // Default total transaction wire-size cap set to 10 MiB.
            nonzero!(10_485_760_u64)
        }
        pub const fn max_decompressed_bytes() -> NonZeroU64 {
            // Default post-decompression budget aligns with max_tx_bytes until
            // additional compression formats are supported.
            max_tx_bytes()
        }
        pub const fn max_metadata_depth() -> NonZeroU16 {
            // Default metadata nesting limit: 1 (metadata map) + up to 7 nested structures.
            nonzero!(8_u16)
        }
        pub const fn max_time_to_live_ms() -> NonZeroU64 {
            // Bound signed replay validity to one day unless genesis/governance chooses less.
            nonzero!(86_400_000_u64)
        }
    }
    pub mod smart_contract {
        use core::num::NonZeroU64;
        use nonzero_ext::nonzero;
        pub const fn fuel() -> NonZeroU64 {
            nonzero!(55_000_000_u64)
        }
        pub const fn memory() -> NonZeroU64 {
            nonzero!(1_048_576_u64)
        }
        pub const fn execution_depth() -> u8 {
            3
        }
        pub const fn max_output_items() -> NonZeroU64 {
            nonzero!(4_096_u64)
        }
        pub const fn max_output_bytes() -> NonZeroU64 {
            nonzero!(8_388_608_u64)
        }
    }
}
impl Default for SumeragiParameters {
    fn default() -> Self {
        use defaults::sumeragi::*;
        Self {
            block_cadence_ms: block_cadence_ms(),
            max_clock_drift_ms: max_clock_drift_ms(),
            key_activation_lead_blocks: key_activation_lead_blocks(),
            key_overlap_grace_blocks: key_overlap_grace_blocks(),
            key_expiry_grace_blocks: key_expiry_grace_blocks(),
            key_allowed_algorithms: key_allowed_algorithms(),
            payload_retry_interval_ms: payload_retry_interval_ms(),
            exec_budget_ms: exec_budget_ms(),
            apply_budget_ms: apply_budget_ms(),
            max_block_bytes: max_block_bytes(),
            epoch_length_blocks: epoch_length_blocks(),
            demotion_window: demotion_window(),
        }
    }
}
impl Default for BlockParameters {
    fn default() -> Self {
        Self::new(defaults::block::max_transactions())
    }
}

impl JsonSerialize for BlockParameters {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        json_support::write_field(out, &mut first, "max_transactions", &self.max_transactions);
        json_support::write_field(
            out,
            &mut first,
            "max_time_trigger_invocations",
            &self.max_time_trigger_invocations,
        );
        json_support::write_field(out, &mut first, "execution_output", &self.execution_output);
        json_support::write_field(out, &mut first, "fastpq_source", &self.fastpq_source);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(
                out,
                &mut first,
                "max_transactions",
                &self.max_transactions,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_time_trigger_invocations",
                &self.max_time_trigger_invocations,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "execution_output",
                &self.execution_output,
            )?;
            json_support::write_field_to(out, &mut first, "fastpq_source", &self.fastpq_source)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for BlockParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let mut map = json_support::expect_object(value, "BlockParameters")?;
        let max_transactions = map
            .remove("max_transactions")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_transactions"))
            .transpose()?
            .unwrap_or_else(defaults::block::max_transactions);
        let max_time_trigger_invocations =
            json_support::parse_value_as(&map.remove("max_time_trigger_invocations").ok_or_else(
                || json::Error::Message("missing max_time_trigger_invocations".into()),
            )?)?;
        let execution_output = json_support::parse_value_as(
            &map.remove("execution_output")
                .ok_or_else(|| json::Error::Message("missing execution_output".into()))?,
        )?;
        let fastpq_source = json_support::parse_value_as(
            &map.remove("fastpq_source")
                .ok_or_else(|| json::Error::Message("missing fastpq_source".into()))?,
        )?;
        json_support::ensure_no_extra(map)?;
        Ok(Self {
            max_transactions,
            max_time_trigger_invocations,
            execution_output,
            fastpq_source,
        })
    }
}
impl Default for TransactionParameters {
    fn default() -> Self {
        use defaults::transaction::*;
        Self::with_max_signatures(
            max_signatures(),
            max_instructions(),
            ivm_bytecode_size(),
            max_tx_bytes(),
            max_decompressed_bytes(),
            max_metadata_depth(),
        )
    }
}
impl Default for SmartContractParameters {
    fn default() -> Self {
        use defaults::smart_contract::*;
        Self {
            fuel: fuel(),
            memory: memory(),
            execution_depth: execution_depth(),
            max_output_items: max_output_items(),
            max_output_bytes: max_output_bytes(),
        }
    }
}
impl FromIterator<Parameter> for Parameters {
    fn from_iter<T: IntoIterator<Item = Parameter>>(iter: T) -> Self {
        iter.into_iter().fold(Parameters::default(), |mut acc, x| {
            acc.set_parameter(x);
            acc
        })
    }
}
impl Parameters {
    /// Largest framed signed transaction these parameters admit and a proposer on `route`
    /// can include.
    ///
    /// See [`max_includable_transaction_bytes`].
    #[must_use]
    pub const fn max_includable_transaction_bytes(&self, route: TransactionInclusionRoute) -> u64 {
        max_includable_transaction_bytes(
            self.transaction.max_tx_bytes,
            self.sumeragi.max_block_bytes,
            route,
        )
    }
    /// Check the framed canonical length of a signed transaction before submitting it.
    ///
    /// SDK preflight, queue admission and proposer selection share this bound for the same
    /// `route`, so a transaction that passes is within the selection budget of a proposer
    /// on the route it has when it is admitted. [`TransactionInclusionRoute::Global`] is
    /// the bound of a transaction routed to lane zero and a sufficient condition for every
    /// other route: the global proposer can select such a transaction directly or as the
    /// rescue of a stalled lane. A [`TransactionInclusionRoute::NativeLane`] result holds
    /// only for a transaction the committed routing rules send to that lane; the node
    /// derives the route itself and refuses a lane-zero transaction above the global budget
    /// whatever a lane would carry.
    ///
    /// The bound is not a promise of inclusion. A transaction above the global budget is
    /// carried by its lane's proposer only: the global rescue selects within the global
    /// budget and skips it. If that lane stalls or closes, or the routing rules stop
    /// sending the transaction there, it stays queued until it expires.
    ///
    /// # Errors
    /// The transaction is larger than [`Self::max_includable_transaction_bytes`] on `route`.
    pub const fn check_signed_transaction_bytes(
        &self,
        encoded_bytes: u64,
        route: TransactionInclusionRoute,
    ) -> Result<(), TransactionNeverIncludable> {
        let max_bytes = self.max_includable_transaction_bytes(route);
        if encoded_bytes > max_bytes {
            return Err(TransactionNeverIncludable {
                encoded_bytes,
                max_bytes,
            });
        }
        Ok(())
    }
    /// Convert [`Self`] into iterator of individual parameters
    pub fn parameters(&self) -> impl Iterator<Item = Parameter> + '_ {
        self.sumeragi
            .parameters()
            .map(Parameter::Sumeragi)
            .chain(self.block.parameters().map(Parameter::Block))
            .chain(self.transaction.parameters().map(Parameter::Transaction))
            .chain(self.executor.parameters().map(Parameter::Executor))
            .chain(
                self.smart_contract
                    .parameters()
                    .map(Parameter::SmartContract),
            )
            .chain(self.custom.values().cloned().map(Parameter::Custom))
    }
    /// Set `parameter` value to corresponding parameter in `self`
    pub fn set_parameter(&mut self, parameter: Parameter) {
        macro_rules! apply_parameter {
            ($($container:ident($param:ident.$field:ident) => $single:ident::$variant:ident),* $(,)?) => {
                match parameter {
                    $(
                    Parameter::$container($single::$variant(next)) => {
                        self.$param.$field = next;
                    }
                    )*
                    Parameter::Custom(next) => {
                        self.custom.insert(next.id.clone(), next);
                    }
                }
            };
        }
        apply_parameter!(
            Sumeragi(sumeragi.max_clock_drift_ms) => SumeragiParameter::MaxClockDriftMs,
            Sumeragi(sumeragi.payload_retry_interval_ms) => SumeragiParameter::PayloadRetryIntervalMs,
            Sumeragi(sumeragi.exec_budget_ms) => SumeragiParameter::ExecBudgetMs,
            Sumeragi(sumeragi.apply_budget_ms) => SumeragiParameter::ApplyBudgetMs,
            Sumeragi(sumeragi.max_block_bytes) => SumeragiParameter::MaxBlockBytes,
            Sumeragi(sumeragi.epoch_length_blocks) => SumeragiParameter::EpochLengthBlocks,
            Sumeragi(sumeragi.demotion_window) => SumeragiParameter::DemotionWindow,
            Block(block.max_transactions) => BlockParameter::MaxTransactions,
            Block(block.max_time_trigger_invocations) => BlockParameter::MaxTimeTriggerInvocations,
            Block(block.execution_output) => BlockParameter::ExecutionOutput,
            Block(block.fastpq_source) => BlockParameter::FastpqSource,
            Transaction(transaction.max_signatures) => TransactionParameter::MaxSignatures,
            Transaction(transaction.max_instructions) => TransactionParameter::MaxInstructions,
            Transaction(transaction.ivm_bytecode_size) => TransactionParameter::IvmBytecodeSize,
            Transaction(transaction.max_tx_bytes) => TransactionParameter::MaxTxBytes,
            Transaction(transaction.max_decompressed_bytes) => TransactionParameter::MaxDecompressedBytes,
            Transaction(transaction.max_metadata_depth) => TransactionParameter::MaxMetadataDepth,
            Transaction(transaction.max_time_to_live_ms) => TransactionParameter::MaxTimeToLiveMs,
            Transaction(transaction.require_height_ttl) => TransactionParameter::RequireHeightTtl,
            Transaction(transaction.require_sequence) => TransactionParameter::RequireSequence,
            SmartContract(smart_contract.fuel) => SmartContractParameter::Fuel,
            SmartContract(smart_contract.memory) => SmartContractParameter::Memory,
            SmartContract(smart_contract.execution_depth) => SmartContractParameter::ExecutionDepth,
            SmartContract(smart_contract.max_output_items) => SmartContractParameter::MaxOutputItems,
            SmartContract(smart_contract.max_output_bytes) => SmartContractParameter::MaxOutputBytes,
            Executor(executor.fuel) => SmartContractParameter::Fuel,
            Executor(executor.memory) => SmartContractParameter::Memory,
            Executor(executor.execution_depth) => SmartContractParameter::ExecutionDepth,
            Executor(executor.max_output_items) => SmartContractParameter::MaxOutputItems,
            Executor(executor.max_output_bytes) => SmartContractParameter::MaxOutputBytes,
        );
    }
}
/// Consensus handshake metadata helpers used during genesis provisioning.
pub mod consensus_metadata {
    use super::*;
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    static HANDSHAKE_META_ID: LazyLock<CustomParameterId> = LazyLock::new(|| {
        CustomParameterId::new(
            Name::from_str("consensus_handshake_meta")
                .expect("consensus_handshake_meta is a valid Name"),
        )
    });
    /// Identifier of the custom parameter embedding consensus handshake metadata.
    pub fn handshake_meta_id() -> CustomParameterId {
        HANDSHAKE_META_ID.clone()
    }
}
/// Cryptography snapshot metadata helpers used during genesis provisioning.
pub mod crypto_metadata {
    use super::*;
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    static MANIFEST_META_ID: LazyLock<CustomParameterId> = LazyLock::new(|| {
        CustomParameterId::new(
            Name::from_str("crypto_manifest_meta").expect("crypto_manifest_meta is a valid Name"),
        )
    });
    /// Identifier of the custom parameter anchoring the genesis crypto snapshot.
    pub fn manifest_meta_id() -> CustomParameterId {
        MANIFEST_META_ID.clone()
    }
}
/// Confidential registry metadata helpers used during genesis provisioning.
pub mod confidential_metadata {
    use super::*;
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    static REGISTRY_ROOT_ID: LazyLock<CustomParameterId> = LazyLock::new(|| {
        CustomParameterId::new(
            Name::from_str("confidential_registry_root")
                .expect("confidential_registry_root is a valid Name"),
        )
    });
    /// Identifier of the custom parameter anchoring the confidential registry fingerprint.
    pub fn registry_root_id() -> CustomParameterId {
        REGISTRY_ROOT_ID.clone()
    }
}
/// IVM metadata helpers stored in the custom parameter registry.
pub mod ivm_metadata {
    use super::*;
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    static PUBLIC_INPUTS_ID: LazyLock<CustomParameterId> = LazyLock::new(|| {
        CustomParameterId::new(
            Name::from_str("ivm_public_inputs").expect("ivm_public_inputs is a valid Name"),
        )
    });
    /// Identifier of the custom parameter embedding the IVM public input registry.
    pub fn public_inputs_id() -> CustomParameterId {
        PUBLIC_INPUTS_ID.clone()
    }
}

impl JsonSerialize for Parameters {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        json_support::write_field(out, &mut first, "sumeragi", &self.sumeragi);
        json_support::write_field(out, &mut first, "block", &self.block);
        json_support::write_field(out, &mut first, "transaction", &self.transaction);
        json_support::write_field(out, &mut first, "executor", &self.executor);
        json_support::write_field(out, &mut first, "smart_contract", &self.smart_contract);
        if !self.custom.is_empty() {
            json_support::write_field(out, &mut first, "custom", &self.custom);
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(out, &mut first, "sumeragi", &self.sumeragi)?;
            json_support::write_field_to(out, &mut first, "block", &self.block)?;
            json_support::write_field_to(out, &mut first, "transaction", &self.transaction)?;
            json_support::write_field_to(out, &mut first, "executor", &self.executor)?;
            json_support::write_field_to(out, &mut first, "smart_contract", &self.smart_contract)?;
            if !self.custom.is_empty() {
                json_support::write_field_to(out, &mut first, "custom", &self.custom)?;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for Parameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let mut map = json_support::expect_object(value, "Parameters")?;
        let sumeragi = map
            .remove("sumeragi")
            .map(|value| json_support::parse_value_as::<SumeragiParameters>(&value))
            .transpose()?
            .unwrap_or_default();
        let block = map
            .remove("block")
            .map(|value| json_support::parse_value_as::<BlockParameters>(&value))
            .transpose()?
            .unwrap_or_default();
        let transaction = map
            .remove("transaction")
            .map(|value| json_support::parse_value_as::<TransactionParameters>(&value))
            .transpose()?
            .unwrap_or_default();
        let executor = map
            .remove("executor")
            .map(|value| json_support::parse_value_as::<SmartContractParameters>(&value))
            .transpose()?
            .unwrap_or_default();
        let smart_contract = map
            .remove("smart_contract")
            .map(|value| json_support::parse_value_as::<SmartContractParameters>(&value))
            .transpose()?
            .unwrap_or_default();
        let custom = map
            .remove("custom")
            .map(parse_custom_parameters_value)
            .transpose()?
            .unwrap_or_default();
        json_support::ensure_no_extra(map)?;
        Ok(Self {
            sumeragi,
            block,
            transaction,
            executor,
            smart_contract,
            custom,
        })
    }
}
impl SumeragiParameters {
    /// Construct [`Self`]
    pub fn new(block_cadence: Duration, max_clock_drift: Duration) -> Self {
        let block_cadence_ms = block_cadence
            .as_millis()
            .try_into()
            .expect("INTERNAL BUG: Time should fit into u64");
        Self {
            block_cadence_ms: NonZeroU64::new(block_cadence_ms)
                .expect("INTERNAL BUG: block cadence must be non-zero"),
            max_clock_drift_ms: max_clock_drift
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Time should fit into u64"),
            key_activation_lead_blocks: defaults::sumeragi::key_activation_lead_blocks(),
            key_overlap_grace_blocks: defaults::sumeragi::key_overlap_grace_blocks(),
            key_expiry_grace_blocks: defaults::sumeragi::key_expiry_grace_blocks(),
            key_allowed_algorithms: defaults::sumeragi::key_allowed_algorithms(),
            payload_retry_interval_ms: defaults::sumeragi::payload_retry_interval_ms(),
            exec_budget_ms: defaults::sumeragi::exec_budget_ms(),
            apply_budget_ms: defaults::sumeragi::apply_budget_ms(),
            max_block_bytes: defaults::sumeragi::max_block_bytes(),
            epoch_length_blocks: defaults::sumeragi::epoch_length_blocks(),
            demotion_window: defaults::sumeragi::demotion_window(),
        }
    }
    /// Convert [`Self`] into iterator of individual parameters
    pub fn parameters(&self) -> impl Iterator<Item = SumeragiParameter> {
        [
            SumeragiParameter::MaxClockDriftMs(self.max_clock_drift_ms),
            SumeragiParameter::PayloadRetryIntervalMs(self.payload_retry_interval_ms),
            SumeragiParameter::ExecBudgetMs(self.exec_budget_ms),
            SumeragiParameter::ApplyBudgetMs(self.apply_budget_ms),
            SumeragiParameter::MaxBlockBytes(self.max_block_bytes),
            SumeragiParameter::EpochLengthBlocks(self.epoch_length_blocks),
            SumeragiParameter::DemotionWindow(self.demotion_window),
        ]
        .into_iter()
    }
}
impl BlockParameters {
    /// Construct [`Self`]
    pub const fn new(max_transactions: NonZeroU64) -> Self {
        Self {
            max_transactions,
            max_time_trigger_invocations: nonzero_ext::nonzero!(512_u32),
            execution_output: ExecutionOutputPolicyV1::bootstrap(),
            fastpq_source: FastpqSourcePolicyV1::bootstrap(),
        }
    }
    /// Convert [`Self`] into iterator of individual parameters
    pub fn parameters(&self) -> impl Iterator<Item = BlockParameter> {
        [
            BlockParameter::MaxTransactions(self.max_transactions),
            BlockParameter::MaxTimeTriggerInvocations(self.max_time_trigger_invocations),
            BlockParameter::ExecutionOutput(self.execution_output),
            BlockParameter::FastpqSource(self.fastpq_source),
        ]
        .into_iter()
    }
}

impl JsonSerialize for BlockParameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        match self {
            BlockParameter::MaxTransactions(value) => {
                json::write_json_string("MaxTransactions", out);
                out.push(':');
                value.json_serialize(out);
            }
            BlockParameter::MaxTimeTriggerInvocations(value) => {
                json::write_json_string("MaxTimeTriggerInvocations", out);
                out.push(':');
                value.json_serialize(out);
            }
            BlockParameter::ExecutionOutput(value) => {
                json::write_json_string("ExecutionOutput", out);
                out.push(':');
                value.json_serialize(out);
            }
            BlockParameter::FastpqSource(value) => {
                json::write_json_string("FastpqSource", out);
                out.push(':');
                value.json_serialize(out);
            }
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            match self {
                BlockParameter::MaxTransactions(value) => {
                    out.push_str("{\"MaxTransactions\":")?;
                    value.json_serialize_to(out)?;
                }
                BlockParameter::MaxTimeTriggerInvocations(value) => {
                    out.push_str("{\"MaxTimeTriggerInvocations\":")?;
                    value.json_serialize_to(out)?;
                }
                BlockParameter::ExecutionOutput(value) => {
                    out.push_str("{\"ExecutionOutput\":")?;
                    value.json_serialize_to(out)?;
                }
                BlockParameter::FastpqSource(value) => {
                    out.push_str("{\"FastpqSource\":")?;
                    value.json_serialize_to(out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for BlockParameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let map = json_support::expect_object(value, "BlockParameter")?;
        let mut iter = map.into_iter();
        let (field, payload) = iter.next().ok_or_else(|| json::Error::InvalidField {
            field: String::from("BlockParameter"),
            message: String::from("expected single-key object"),
        })?;
        if let Some((extra, _)) = iter.next() {
            return Err(json::Error::UnknownField { field: extra });
        }
        match field.as_str() {
            "MaxTransactions" => Ok(Self::MaxTransactions(json_support::expect_nonzero_u64(
                &payload,
                "MaxTransactions",
            )?)),
            "MaxTimeTriggerInvocations" => Ok(Self::MaxTimeTriggerInvocations(
                json_support::parse_value_as(&payload)?,
            )),
            "ExecutionOutput" => Ok(Self::ExecutionOutput(json_support::parse_value_as(
                &payload,
            )?)),
            "FastpqSource" => Ok(Self::FastpqSource(json_support::parse_value_as(&payload)?)),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}
impl TransactionParameters {
    /// Construct [`Self`] with an explicit maximum signature count.
    pub const fn with_max_signatures(
        max_signatures: NonZeroU64,
        max_instructions: NonZeroU64,
        ivm_bytecode_size: NonZeroU64,
        max_tx_bytes: NonZeroU64,
        max_decompressed_bytes: NonZeroU64,
        max_metadata_depth: NonZeroU16,
    ) -> Self {
        Self {
            max_signatures,
            max_instructions,
            ivm_bytecode_size,
            max_tx_bytes,
            max_decompressed_bytes,
            max_metadata_depth,
            max_time_to_live_ms: defaults::transaction::max_time_to_live_ms(),
            require_height_ttl: false,
            require_sequence: false,
        }
    }
    /// Configure the deterministic maximum signature-bound wall-clock lifetime.
    #[must_use]
    pub const fn with_max_time_to_live_ms(mut self, max_time_to_live_ms: NonZeroU64) -> Self {
        self.max_time_to_live_ms = max_time_to_live_ms;
        self
    }
    /// Configure ingress metadata enforcement (height-based TTL and per-sender sequence checks).
    #[must_use]
    pub const fn with_ingress_enforcement(
        mut self,
        require_height_ttl: bool,
        require_sequence: bool,
    ) -> Self {
        self.require_height_ttl = require_height_ttl;
        self.require_sequence = require_sequence;
        self
    }
    /// Construct [`Self`] using the default signature limit.
    pub const fn new(
        max_instructions: NonZeroU64,
        ivm_bytecode_size: NonZeroU64,
        max_tx_bytes: NonZeroU64,
        max_decompressed_bytes: NonZeroU64,
        max_metadata_depth: NonZeroU16,
    ) -> Self {
        Self::with_max_signatures(
            defaults::transaction::max_signatures(),
            max_instructions,
            ivm_bytecode_size,
            max_tx_bytes,
            max_decompressed_bytes,
            max_metadata_depth,
        )
    }
    /// Convert [`Self`] into iterator of individual parameters
    pub fn parameters(&self) -> impl Iterator<Item = TransactionParameter> {
        [
            TransactionParameter::MaxSignatures(self.max_signatures),
            TransactionParameter::MaxInstructions(self.max_instructions),
            TransactionParameter::IvmBytecodeSize(self.ivm_bytecode_size),
            TransactionParameter::MaxTxBytes(self.max_tx_bytes),
            TransactionParameter::MaxDecompressedBytes(self.max_decompressed_bytes),
            TransactionParameter::MaxMetadataDepth(self.max_metadata_depth),
            TransactionParameter::MaxTimeToLiveMs(self.max_time_to_live_ms),
            TransactionParameter::RequireHeightTtl(self.require_height_ttl),
            TransactionParameter::RequireSequence(self.require_sequence),
        ]
        .into_iter()
    }
}

impl JsonSerialize for TransactionParameters {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        json_support::write_field(out, &mut first, "max_signatures", &self.max_signatures);
        json_support::write_field(out, &mut first, "max_instructions", &self.max_instructions);
        json_support::write_field(
            out,
            &mut first,
            "ivm_bytecode_size",
            &self.ivm_bytecode_size,
        );
        json_support::write_field(out, &mut first, "max_tx_bytes", &self.max_tx_bytes);
        json_support::write_field(
            out,
            &mut first,
            "max_decompressed_bytes",
            &self.max_decompressed_bytes,
        );
        json_support::write_field(
            out,
            &mut first,
            "max_metadata_depth",
            &self.max_metadata_depth,
        );
        json_support::write_field(
            out,
            &mut first,
            "max_time_to_live_ms",
            &self.max_time_to_live_ms,
        );
        json_support::write_field(
            out,
            &mut first,
            "require_height_ttl",
            &self.require_height_ttl,
        );
        json_support::write_field(out, &mut first, "require_sequence", &self.require_sequence);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(out, &mut first, "max_signatures", &self.max_signatures)?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_instructions",
                &self.max_instructions,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "ivm_bytecode_size",
                &self.ivm_bytecode_size,
            )?;
            json_support::write_field_to(out, &mut first, "max_tx_bytes", &self.max_tx_bytes)?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_decompressed_bytes",
                &self.max_decompressed_bytes,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_metadata_depth",
                &self.max_metadata_depth,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_time_to_live_ms",
                &self.max_time_to_live_ms,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "require_height_ttl",
                &self.require_height_ttl,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "require_sequence",
                &self.require_sequence,
            )?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for TransactionParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let mut map = json_support::expect_object(value, "TransactionParameters")?;
        let max_signatures = map
            .remove("max_signatures")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_signatures"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_signatures);
        let max_instructions = map
            .remove("max_instructions")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_instructions"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_instructions);
        let ivm_bytecode_size = map
            .remove("ivm_bytecode_size")
            .map(|value| json_support::expect_nonzero_u64(&value, "ivm_bytecode_size"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::ivm_bytecode_size);
        let max_tx_bytes = map
            .remove("max_tx_bytes")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_tx_bytes"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_tx_bytes);
        let max_decompressed_bytes = map
            .remove("max_decompressed_bytes")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_decompressed_bytes"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_decompressed_bytes);
        let require_height_ttl = map
            .remove("require_height_ttl")
            .map(|value| json_support::expect_bool(&value, "require_height_ttl"))
            .transpose()?
            .unwrap_or(false);
        let max_time_to_live_ms = map
            .remove("max_time_to_live_ms")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_time_to_live_ms"))
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_time_to_live_ms);
        let require_sequence = map
            .remove("require_sequence")
            .map(|value| json_support::expect_bool(&value, "require_sequence"))
            .transpose()?
            .unwrap_or(false);
        let max_metadata_depth = map
            .remove("max_metadata_depth")
            .map(|value| {
                let depth = json_support::expect_nonzero_u64(&value, "max_metadata_depth")?;
                let depth_u16 =
                    u16::try_from(depth.get()).map_err(|_| json::Error::InvalidField {
                        field: String::from("max_metadata_depth"),
                        message: String::from("value exceeds u16::MAX"),
                    })?;
                NonZeroU16::new(depth_u16).ok_or_else(|| json::Error::InvalidField {
                    field: String::from("max_metadata_depth"),
                    message: String::from("value must be non-zero"),
                })
            })
            .transpose()?
            .unwrap_or_else(defaults::transaction::max_metadata_depth);
        json_support::ensure_no_extra(map)?;
        Ok(Self::with_max_signatures(
            max_signatures,
            max_instructions,
            ivm_bytecode_size,
            max_tx_bytes,
            max_decompressed_bytes,
            max_metadata_depth,
        )
        .with_max_time_to_live_ms(max_time_to_live_ms)
        .with_ingress_enforcement(require_height_ttl, require_sequence))
    }
}

impl JsonSerialize for TransactionParameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        match self {
            TransactionParameter::MaxSignatures(value) => {
                json::write_json_string("MaxSignatures", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::MaxInstructions(value) => {
                json::write_json_string("MaxInstructions", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::IvmBytecodeSize(value) => {
                json::write_json_string("IvmBytecodeSize", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::MaxTxBytes(value) => {
                json::write_json_string("MaxTxBytes", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::MaxDecompressedBytes(value) => {
                json::write_json_string("MaxDecompressedBytes", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::MaxMetadataDepth(value) => {
                json::write_json_string("MaxMetadataDepth", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::MaxTimeToLiveMs(value) => {
                json::write_json_string("MaxTimeToLiveMs", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::RequireHeightTtl(value) => {
                json::write_json_string("RequireHeightTtl", out);
                out.push(':');
                value.json_serialize(out);
            }
            TransactionParameter::RequireSequence(value) => {
                json::write_json_string("RequireSequence", out);
                out.push(':');
                value.json_serialize(out);
            }
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                TransactionParameter::MaxSignatures(value) => {
                    out.push_str("\"MaxSignatures\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::MaxInstructions(value) => {
                    out.push_str("\"MaxInstructions\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::IvmBytecodeSize(value) => {
                    out.push_str("\"IvmBytecodeSize\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::MaxTxBytes(value) => {
                    out.push_str("\"MaxTxBytes\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::MaxDecompressedBytes(value) => {
                    out.push_str("\"MaxDecompressedBytes\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::MaxMetadataDepth(value) => {
                    out.push_str("\"MaxMetadataDepth\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::MaxTimeToLiveMs(value) => {
                    out.push_str("\"MaxTimeToLiveMs\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::RequireHeightTtl(value) => {
                    out.push_str("\"RequireHeightTtl\":")?;
                    value.json_serialize_to(out)?;
                }
                TransactionParameter::RequireSequence(value) => {
                    out.push_str("\"RequireSequence\":")?;
                    value.json_serialize_to(out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for TransactionParameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let map = json_support::expect_object(value, "TransactionParameter")?;
        let mut iter = map.into_iter();
        let (field, payload) = iter.next().ok_or_else(|| json::Error::InvalidField {
            field: String::from("TransactionParameter"),
            message: String::from("expected single-key object"),
        })?;
        if let Some((extra, _)) = iter.next() {
            return Err(json::Error::UnknownField { field: extra });
        }
        match field.as_str() {
            "MaxSignatures" => Ok(Self::MaxSignatures(json_support::expect_nonzero_u64(
                &payload,
                "MaxSignatures",
            )?)),
            "MaxInstructions" => Ok(Self::MaxInstructions(json_support::expect_nonzero_u64(
                &payload,
                "MaxInstructions",
            )?)),
            "IvmBytecodeSize" => Ok(Self::IvmBytecodeSize(json_support::expect_nonzero_u64(
                &payload,
                "IvmBytecodeSize",
            )?)),
            "MaxTxBytes" => Ok(Self::MaxTxBytes(json_support::expect_nonzero_u64(
                &payload,
                "MaxTxBytes",
            )?)),
            "MaxDecompressedBytes" => Ok(Self::MaxDecompressedBytes(
                json_support::expect_nonzero_u64(&payload, "MaxDecompressedBytes")?,
            )),
            "MaxMetadataDepth" => Ok(Self::MaxMetadataDepth({
                let depth = json_support::expect_nonzero_u64(&payload, "MaxMetadataDepth")?;
                let value = u16::try_from(depth.get()).map_err(|_| json::Error::InvalidField {
                    field: String::from("MaxMetadataDepth"),
                    message: String::from("value exceeds u16::MAX"),
                })?;
                NonZeroU16::new(value).ok_or_else(|| json::Error::InvalidField {
                    field: String::from("MaxMetadataDepth"),
                    message: String::from("value must be non-zero"),
                })?
            })),
            "MaxTimeToLiveMs" => Ok(Self::MaxTimeToLiveMs(json_support::expect_nonzero_u64(
                &payload,
                "MaxTimeToLiveMs",
            )?)),
            "RequireHeightTtl" => Ok(Self::RequireHeightTtl(json_support::expect_bool(
                &payload,
                "RequireHeightTtl",
            )?)),
            "RequireSequence" => Ok(Self::RequireSequence(json_support::expect_bool(
                &payload,
                "RequireSequence",
            )?)),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}
impl SmartContractParameters {
    /// Convert [`Self`] into iterator of individual parameters
    pub fn parameters(&self) -> impl Iterator<Item = SmartContractParameter> {
        [
            SmartContractParameter::Fuel(self.fuel),
            SmartContractParameter::Memory(self.memory),
            SmartContractParameter::ExecutionDepth(self.execution_depth),
            SmartContractParameter::MaxOutputItems(self.max_output_items),
            SmartContractParameter::MaxOutputBytes(self.max_output_bytes),
        ]
        .into_iter()
    }
}

impl JsonSerialize for SmartContractParameters {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        json_support::write_field(out, &mut first, "fuel", &self.fuel);
        json_support::write_field(out, &mut first, "memory", &self.memory);
        json_support::write_field(out, &mut first, "execution_depth", &self.execution_depth);
        json_support::write_field(out, &mut first, "max_output_items", &self.max_output_items);
        json_support::write_field(out, &mut first, "max_output_bytes", &self.max_output_bytes);
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            let mut first = true;
            json_support::write_field_to(out, &mut first, "fuel", &self.fuel)?;
            json_support::write_field_to(out, &mut first, "memory", &self.memory)?;
            json_support::write_field_to(
                out,
                &mut first,
                "execution_depth",
                &self.execution_depth,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_output_items",
                &self.max_output_items,
            )?;
            json_support::write_field_to(
                out,
                &mut first,
                "max_output_bytes",
                &self.max_output_bytes,
            )?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for SmartContractParameters {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let mut map = json_support::expect_object(value, "SmartContractParameters")?;
        let fuel = map
            .remove("fuel")
            .map(|value| json_support::expect_nonzero_u64(&value, "fuel"))
            .transpose()?
            .unwrap_or_else(defaults::smart_contract::fuel);
        let memory = map
            .remove("memory")
            .map(|value| json_support::expect_nonzero_u64(&value, "memory"))
            .transpose()?
            .unwrap_or_else(defaults::smart_contract::memory);
        let execution_depth = map
            .remove("execution_depth")
            .map(|value| json_support::expect_u8(&value, "execution_depth"))
            .transpose()?
            .unwrap_or_else(defaults::smart_contract::execution_depth);
        let max_output_items = map
            .remove("max_output_items")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_output_items"))
            .transpose()?
            .unwrap_or_else(defaults::smart_contract::max_output_items);
        let max_output_bytes = map
            .remove("max_output_bytes")
            .map(|value| json_support::expect_nonzero_u64(&value, "max_output_bytes"))
            .transpose()?
            .unwrap_or_else(defaults::smart_contract::max_output_bytes);
        json_support::ensure_no_extra(map)?;
        Ok(Self {
            fuel,
            memory,
            execution_depth,
            max_output_items,
            max_output_bytes,
        })
    }
}

impl JsonSerialize for SmartContractParameter {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        match self {
            SmartContractParameter::Fuel(value) => {
                json::write_json_string("Fuel", out);
                out.push(':');
                value.json_serialize(out);
            }
            SmartContractParameter::Memory(value) => {
                json::write_json_string("Memory", out);
                out.push(':');
                value.json_serialize(out);
            }
            SmartContractParameter::ExecutionDepth(value) => {
                json::write_json_string("ExecutionDepth", out);
                out.push(':');
                value.json_serialize(out);
            }
            SmartContractParameter::MaxOutputItems(value) => {
                json::write_json_string("MaxOutputItems", out);
                out.push(':');
                value.json_serialize(out);
            }
            SmartContractParameter::MaxOutputBytes(value) => {
                json::write_json_string("MaxOutputBytes", out);
                out.push(':');
                value.json_serialize(out);
            }
        }
        out.push('}');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            match self {
                SmartContractParameter::Fuel(value) => {
                    out.push_str("\"Fuel\":")?;
                    value.json_serialize_to(out)?;
                }
                SmartContractParameter::Memory(value) => {
                    out.push_str("\"Memory\":")?;
                    value.json_serialize_to(out)?;
                }
                SmartContractParameter::ExecutionDepth(value) => {
                    out.push_str("\"ExecutionDepth\":")?;
                    value.json_serialize_to(out)?;
                }
                SmartContractParameter::MaxOutputItems(value) => {
                    out.push_str("\"MaxOutputItems\":")?;
                    value.json_serialize_to(out)?;
                }
                SmartContractParameter::MaxOutputBytes(value) => {
                    out.push_str("\"MaxOutputBytes\":")?;
                    value.json_serialize_to(out)?;
                }
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result
    }
}

impl JsonDeserialize for SmartContractParameter {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = json::Value::json_deserialize(parser)?;
        let map = json_support::expect_object(value, "SmartContractParameter")?;
        let mut iter = map.into_iter();
        let (field, payload) = iter.next().ok_or_else(|| json::Error::InvalidField {
            field: String::from("SmartContractParameter"),
            message: String::from("expected single-key object"),
        })?;
        if let Some((extra, _)) = iter.next() {
            return Err(json::Error::UnknownField { field: extra });
        }
        match field.as_str() {
            "Fuel" => Ok(Self::Fuel(json_support::expect_nonzero_u64(
                &payload, "Fuel",
            )?)),
            "Memory" => Ok(Self::Memory(json_support::expect_nonzero_u64(
                &payload, "Memory",
            )?)),
            "ExecutionDepth" => Ok(Self::ExecutionDepth(json_support::expect_u8(
                &payload,
                "ExecutionDepth",
            )?)),
            "MaxOutputItems" => Ok(Self::MaxOutputItems(json_support::expect_nonzero_u64(
                &payload,
                "MaxOutputItems",
            )?)),
            "MaxOutputBytes" => Ok(Self::MaxOutputBytes(json_support::expect_nonzero_u64(
                &payload,
                "MaxOutputBytes",
            )?)),
            other => Err(json::Error::UnknownField {
                field: other.to_owned(),
            }),
        }
    }
}
// Norito decoding now relies on derived implementations for parameter types.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter::custom::{CustomParameter, CustomParameterId};
    use core::str::FromStr as _;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    use norito::codec::{DecodeAll as _, Encode as _};
    use norito::json::{Number, Value};
    #[test]
    fn set_custom_parameter() {
        let mut params = Parameters::default();
        let id = CustomParameterId::new(Name::from_str("test").expect("valid"));
        let payload = Json::new(1u32);
        let custom = CustomParameter::new(id.clone(), payload);
        params.set_parameter(Parameter::Custom(custom.clone()));
        assert_eq!(params.custom().get(&id), Some(&custom));
    }
    #[test]
    fn set_block_parameter() {
        let mut params = Parameters::default();
        let max_transactions = NonZeroU64::new(10).unwrap();
        params.set_parameter(Parameter::Block(BlockParameter::MaxTransactions(
            max_transactions,
        )));
        assert_eq!(params.block().max_transactions(), max_transactions);
    }
    #[test]
    fn smart_contract_output_limits_are_governed_and_roundtrip() {
        let mut params = Parameters::default();
        let max_items = NonZeroU64::new(17).expect("non-zero item limit");
        let max_bytes = NonZeroU64::new(32_768).expect("non-zero byte limit");
        params.set_parameter(Parameter::SmartContract(
            SmartContractParameter::MaxOutputItems(max_items),
        ));
        params.set_parameter(Parameter::SmartContract(
            SmartContractParameter::MaxOutputBytes(max_bytes),
        ));
        params.set_parameter(Parameter::Executor(SmartContractParameter::MaxOutputItems(
            max_items,
        )));
        params.set_parameter(Parameter::Executor(SmartContractParameter::MaxOutputBytes(
            max_bytes,
        )));
        assert_eq!(params.smart_contract().max_output_items(), max_items);
        assert_eq!(params.smart_contract().max_output_bytes(), max_bytes);
        assert_eq!(params.executor().max_output_items(), max_items);
        assert_eq!(params.executor().max_output_bytes(), max_bytes);
        let bytes = params.encode();
        let decoded =
            Parameters::decode_all(&mut bytes.as_slice()).expect("decode governed parameters");
        assert_eq!(decoded, params);

        {
            let json = norito::json::to_json(&params.smart_contract())
                .expect("serialize smart-contract parameters");
            let decoded: SmartContractParameters =
                norito::json::from_str(&json).expect("decode smart-contract parameters");
            assert_eq!(decoded.max_output_items(), max_items);
            assert_eq!(decoded.max_output_bytes(), max_bytes);
        }
    }

    #[test]
    fn smart_contract_output_limits_reject_zero() {
        let json = r#"{"max_output_items":0}"#;
        norito::json::from_str::<SmartContractParameters>(json)
            .expect_err("zero output item limit must fail");
        let json = r#"{"max_output_bytes":0}"#;
        norito::json::from_str::<SmartContractParameters>(json)
            .expect_err("zero output byte limit must fail");
    }
    #[test]
    fn sumeragi_parameter_norito_roundtrip() {
        let value = SumeragiParameter::MaxClockDriftMs(1_000);
        let bytes = value.encode();
        let decoded = SumeragiParameter::decode_all(&mut bytes.as_slice())
            .expect("decode Sumeragi parameter");
        assert_eq!(value, decoded);
    }
    #[test]
    fn sumeragi_parameters_norito_roundtrip() {
        let params = SumeragiParameters::default();
        // Encode as a stable tuple and reconstruct (append-only order)
        let bytes = params.encode();
        let mut cursor = bytes.as_slice();
        let dec = SumeragiParameters::decode_all(&mut cursor).expect("decode sumeragi parameters");
        assert_eq!(params, dec);
        // Skip bare codec path; headerful Norito is the canonical test path
        // JSON path: ensure defaults parse and roundtrip

        {
            let j = norito::json::to_json(&params).expect("json ser");
            let parsed: SumeragiParameters = norito::json::from_str(&j).expect("json de");
            assert_eq!(params, parsed);
        }
    }

    fn every_sumeragi_parameter_variant() -> [SumeragiParameter; 7] {
        [
            SumeragiParameter::MaxClockDriftMs(1_500),
            SumeragiParameter::PayloadRetryIntervalMs(NonZeroU64::new(7_000).unwrap()),
            SumeragiParameter::ExecBudgetMs(NonZeroU64::new(3_000).unwrap()),
            SumeragiParameter::ApplyBudgetMs(NonZeroU64::new(900).unwrap()),
            SumeragiParameter::MaxBlockBytes(NonZeroU32::new(2 * 1024 * 1024).unwrap()),
            SumeragiParameter::EpochLengthBlocks(NonZeroU64::new(7_200).unwrap()),
            SumeragiParameter::DemotionWindow(NonZeroU64::new(256).unwrap()),
        ]
    }

    #[test]
    fn sumeragi_parameter_defaults_match_the_consensus_core() {
        let params = SumeragiParameters::default();
        assert_eq!(params.block_cadence_ms.get(), 1_000);
        assert_eq!(params.payload_retry_interval_ms.get(), 5_000);
        assert_eq!(params.exec_budget_ms.get(), 4_000);
        assert_eq!(params.apply_budget_ms.get(), 1_000);
        assert_eq!(params.max_block_bytes.get(), 4 * 1024 * 1024);
        assert_eq!(params.epoch_length_blocks.get(), 3_600);
        assert_eq!(params.demotion_window.get(), 128);
        // The on-chain defaults are the core's §9.3 defaults and pass its §9.4 validation.
        let chain = iroha_sumeragi::types::ChainParams {
            block_time: params.block_cadence_ms.get(),
            payload_retry_interval: params.payload_retry_interval_ms.get(),
            e_max: params.exec_budget_ms.get(),
            a_max: params.apply_budget_ms.get(),
            max_block_bytes: params.max_block_bytes.get(),
            epoch_length: params.epoch_length_blocks.get(),
        };
        assert_eq!(chain, iroha_sumeragi::types::ChainParams::default());
        let transport = u64::from(params.max_block_bytes.get())
            + u64::from(iroha_sumeragi::pacemaker::FRAME_OVERHEAD);
        iroha_sumeragi::pacemaker::validate_chain(&chain, transport)
            .expect("default chain parameters are valid");
        assert_eq!(
            SumeragiParameters::new(Duration::from_millis(1_000), Duration::ZERO).demotion_window,
            params.demotion_window
        );
    }

    #[test]
    fn sumeragi_parameter_every_variant_round_trips() {
        for value in every_sumeragi_parameter_variant() {
            let bytes = value.encode();
            let decoded = SumeragiParameter::decode_all(&mut bytes.as_slice())
                .expect("decode Sumeragi parameter");
            assert_eq!(value, decoded);
            let json = norito::json::to_json(&value).expect("json");
            assert_eq!(
                json,
                format!("{{\"{}\":{}}}", value.json_tag(), value.value_u64())
            );
            let parsed: SumeragiParameter = norito::json::from_str(&json).expect("json de");
            assert_eq!(parsed, value);
            let wrapped = Parameter::Sumeragi(value);
            let json = norito::json::to_json(&wrapped).expect("json");
            let parsed: Parameter = norito::json::from_str(&json).expect("json de");
            assert_eq!(parsed, wrapped);
        }
    }

    #[test]
    fn sumeragi_parameter_json_rejects_zero_and_out_of_range_values() {
        for tag in [
            "PayloadRetryIntervalMs",
            "ExecBudgetMs",
            "ApplyBudgetMs",
            "MaxBlockBytes",
            "EpochLengthBlocks",
            "DemotionWindow",
        ] {
            let json = format!("{{\"{tag}\":0}}");
            assert!(
                norito::json::from_str::<SumeragiParameter>(&json).is_err(),
                "zero `{tag}` must fail"
            );
        }
        assert!(
            norito::json::from_str::<SumeragiParameter>(r#"{"MaxBlockBytes":4294967296}"#).is_err()
        );
        assert!(norito::json::from_str::<SumeragiParameter>(r#"{"BlockCadenceMs":1000}"#).is_err());
        assert!(norito::json::from_str::<SumeragiParameter>(r#"{"MaxClockDriftMs":0}"#).is_ok());
    }

    #[test]
    fn sumeragi_parameter_value_and_genesis_only() {
        let values = every_sumeragi_parameter_variant();
        assert_eq!(
            values.map(|value| value.value_u64()),
            [1_500, 7_000, 3_000, 900, 2 * 1024 * 1024, 7_200, 256]
        );
        assert_eq!(
            values.map(|value| value.is_genesis_only()),
            [false, false, false, false, false, false, true]
        );
        let tags = values.map(|value| value.json_tag());
        let unique: std::collections::BTreeSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len());
    }

    #[test]
    fn sumeragi_parameters_set_and_enumerate_every_variant() {
        let mut params = Parameters::default();
        for value in every_sumeragi_parameter_variant() {
            params.set_parameter(Parameter::Sumeragi(value));
        }
        let sumeragi = params.sumeragi();
        assert_eq!(sumeragi.max_clock_drift_ms, 1_500);
        assert_eq!(sumeragi.payload_retry_interval_ms.get(), 7_000);
        assert_eq!(sumeragi.exec_budget_ms.get(), 3_000);
        assert_eq!(sumeragi.apply_budget_ms.get(), 900);
        assert_eq!(sumeragi.max_block_bytes.get(), 2 * 1024 * 1024);
        assert_eq!(sumeragi.epoch_length_blocks.get(), 7_200);
        assert_eq!(sumeragi.demotion_window.get(), 256);
        assert_eq!(
            sumeragi.parameters().collect::<Vec<_>>(),
            every_sumeragi_parameter_variant().to_vec()
        );
        // Every settable Sumeragi parameter survives the individual-parameter round trip.
        let rebuilt: Parameters = params.parameters().collect();
        assert_eq!(
            rebuilt.sumeragi().parameters().collect::<Vec<_>>(),
            every_sumeragi_parameter_variant().to_vec()
        );
    }

    #[test]
    fn sumeragi_parameters_json_new_fields_default_when_absent_and_round_trip() {
        let parsed: SumeragiParameters =
            norito::json::from_str(r#"{"block_cadence_ms":500}"#).expect("json de");
        assert_eq!(parsed.block_cadence_ms.get(), 500);
        assert_eq!(
            parsed.payload_retry_interval_ms,
            defaults::sumeragi::payload_retry_interval_ms()
        );
        assert_eq!(
            parsed.demotion_window,
            defaults::sumeragi::demotion_window()
        );
        let custom = SumeragiParameters {
            payload_retry_interval_ms: NonZeroU64::new(9_000).unwrap(),
            max_block_bytes: NonZeroU32::new(1_024).unwrap(),
            demotion_window: NonZeroU64::new(512).unwrap(),
            ..SumeragiParameters::default()
        };
        let json = norito::json::to_json(&custom).expect("json");
        for field in [
            "\"payload_retry_interval_ms\":9000",
            "\"exec_budget_ms\":4000",
            "\"apply_budget_ms\":1000",
            "\"max_block_bytes\":1024",
            "\"epoch_length_blocks\":3600",
            "\"demotion_window\":512",
        ] {
            assert!(json.contains(field), "{field} missing from {json}");
        }
        let parsed: SumeragiParameters = norito::json::from_str(&json).expect("json de");
        assert_eq!(parsed, custom);
        let bytes = custom.encode();
        let decoded = SumeragiParameters::decode_all(&mut bytes.as_slice()).expect("decode");
        assert_eq!(decoded, custom);
        for field in [
            "payload_retry_interval_ms",
            "exec_budget_ms",
            "apply_budget_ms",
            "max_block_bytes",
            "epoch_length_blocks",
            "demotion_window",
        ] {
            let json = format!(r#"{{"{field}":0}}"#);
            assert!(
                norito::json::from_str::<SumeragiParameters>(&json).is_err(),
                "zero `{field}` must fail"
            );
        }
    }

    #[test]
    fn consensus_mode_conversions_and_json() {
        for (mode, legacy, json) in [
            (
                ConsensusMode::Permissioned,
                SumeragiConsensusMode::Permissioned,
                r#"{"mode":"permissioned","details":null}"#,
            ),
            (
                ConsensusMode::Npos,
                SumeragiConsensusMode::Npos,
                r#"{"mode":"npos","details":null}"#,
            ),
        ] {
            assert_eq!(ConsensusMode::from(legacy), mode);
            assert_eq!(SumeragiConsensusMode::from(mode), legacy);
            assert_eq!(norito::json::to_json(&mode).expect("json"), json);
            assert_eq!(
                norito::json::from_str::<ConsensusMode>(json).expect("json de"),
                mode
            );
            let bytes = mode.encode();
            assert_eq!(
                ConsensusMode::decode_all(&mut bytes.as_slice()).expect("decode"),
                mode
            );
        }
        assert!(ConsensusMode::Permissioned.is_permissioned());
        assert!(!ConsensusMode::Npos.is_permissioned());
        // The consensus-module path keeps resolving to the same type until WP9.
        let consensus_mode: crate::block::consensus::ConsensusMode = ConsensusMode::Npos;
        assert_eq!(consensus_mode, ConsensusMode::Npos);
    }

    #[test]
    fn sumeragi_parameters_json_rejects_zero_cadence() {
        let json = r#"{"block_cadence_ms":0}"#;
        norito::json::from_str::<SumeragiParameters>(json).expect_err("zero cadence must fail");
    }

    #[test]
    fn sumeragi_parameters_json_rejects_every_retired_field() {
        for field in [
            "block_time_ms",
            "commit_time_ms",
            "min_finality_ms",
            "pacing_factor_bps",
            "collectors_k",
            "collectors_redundant_send_r",
            "da_enabled",
            "next_mode",
            "mode_activation_height",
        ] {
            let json = format!(r#"{{"block_cadence_ms":100,"{field}":1}}"#);
            assert!(
                norito::json::from_str::<SumeragiParameters>(&json).is_err(),
                "retired field `{field}` must fail"
            );
        }
    }
    #[test]
    fn sumeragi_npos_retains_original_decoder_refusal_and_retries_same_bytes() {
        let expected = SumeragiNposParameters::default();
        let custom = expected.clone().into_custom_parameter();
        let original = custom.payload().get().clone();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let error = norito::with_decode_limits_scope(limits, || {
            SumeragiNposParameters::from_custom_parameter(&custom)
        })
        .unwrap_err();
        assert!(matches!(
            error,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. }
            )
        ));
        assert_eq!(custom.payload().get(), &original);
        assert_eq!(
            SumeragiNposParameters::from_custom_parameter(&custom).unwrap(),
            Some(expected)
        );
        let foreign =
            CustomParameter::new("unrelated_parameter".parse().unwrap(), Json::new(false));
        assert!(
            norito::with_decode_limits_scope(limits, || {
                SumeragiNposParameters::from_custom_parameter(&foreign)
            })
            .unwrap()
            .is_none()
        );
        let malformed =
            CustomParameter::new(SumeragiNposParameters::parameter_id(), Json::new(false));
        assert!(
            matches!(SumeragiNposParameters::from_custom_parameter(&malformed), Err(error)
            if !error.is_decode_resource_limit())
        );
        let invalid = SumeragiNposParameters {
            max_validators: 5,
            ..SumeragiNposParameters::default()
        };
        assert!(matches!(
            SumeragiNposParameters::from_custom_parameter(&invalid.into_custom_parameter()),
            Err(norito::json::Error::InvalidField { .. })
        ));
    }

    #[test]
    fn sumeragi_npos_synthetic_identity_is_exact_and_validation_never_allocates() {
        use crate::{
            amx_prepare_streaming_allocations::PhysicalObservation, asset::AssetDefinitionId,
        };

        let synthetic = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("nexus.universal").unwrap(),
            "xor".parse().unwrap(),
        );
        assert_eq!(
            AssetDefinitionId::from_uuid_bytes(
                SumeragiNposParameters::REJECTED_SYNTHETIC_XOR_ASSET_BYTES,
            )
            .unwrap(),
            synthetic
        );
        let valid = SumeragiNposParameters::default();
        let zero_seed = SumeragiNposParameters {
            epoch_seed: [0; 32],
            ..valid.clone()
        };
        let synthetic_and_zero_seed = SumeragiNposParameters {
            xor_asset_definition_id: synthetic,
            ..zero_seed.clone()
        };
        for (parameters, expected) in [
            (&valid, Ok(())),
            (&zero_seed, Err("epoch_seed must not be all zero")),
            (
                &synthetic_and_zero_seed,
                Err(
                    "NPoS must use the network's canonical XOR asset, not synthetic nexus.universal/xor",
                ),
            ),
        ] {
            let observation = PhysicalObservation::start();
            let result = parameters.validate();
            let requests = observation.snapshot().requests();
            drop(observation);
            assert_eq!(requests, [0; 3]);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn sumeragi_npos_rejects_retired_unsupported_election_controls() {
        let expected = SumeragiNposParameters::default();
        let canonical = norito::json::to_value(&expected).expect("canonical NPoS parameters");
        let custom = CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            Json::from_norito_value_ref(&canonical).unwrap(),
        );
        assert_eq!(
            SumeragiNposParameters::from_custom_parameter(&custom).unwrap(),
            Some(expected)
        );
        for field in [
            "max_nominator_concentration_pct",
            "seat_band_pct",
            "max_entity_correlation_pct",
        ] {
            for value in [0_u64, 25, 100] {
                let mut retired = canonical.clone();
                retired
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), value.into());
                let custom = CustomParameter::new(
                    SumeragiNposParameters::parameter_id(),
                    Json::from_norito_value_ref(&retired).unwrap(),
                );
                assert!(
                    SumeragiNposParameters::from_custom_parameter(&custom).is_err(),
                    "unsupported signed policy {field}={value} must not be ignored"
                );
            }
        }
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_rejects_string_wrapped_payload() {
        let expected = SumeragiNposParameters::default();
        let wrapped = Json::new(norito::json::to_json(&expected).expect("serialize npos payload"));
        let custom = CustomParameter::new(SumeragiNposParameters::parameter_id(), wrapped);
        assert!(
            SumeragiNposParameters::from_custom_parameter(&custom).is_err(),
            "string-wrapped compatibility payload must be rejected"
        );
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_rejects_numeric_string_payload() {
        let expected = SumeragiNposParameters::default();
        let mut payload =
            norito::json::to_value(&expected).expect("serialize npos payload to json value");
        let map = payload
            .as_object_mut()
            .expect("npos payload should serialize as object");
        for field in [
            "max_validators",
            "finality_margin_blocks",
            "evidence_horizon_blocks",
            "activation_lag_blocks",
            "slashing_delay_blocks",
            "epoch_length_blocks",
        ] {
            let value = map
                .get_mut(field)
                .unwrap_or_else(|| panic!("missing `{field}` in npos payload"));
            let number = value
                .as_u64()
                .unwrap_or_else(|| panic!("`{field}` should serialize as number"));
            *value = norito::json::Value::String(number.to_string());
        }
        for field in ["min_self_bond", "min_nomination_bond"] {
            assert!(
                map.get(field)
                    .and_then(norito::json::Value::as_str)
                    .is_some(),
                "Quantity field `{field}` must retain its canonical JSON string encoding"
            );
        }
        let custom = CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            Json::from_norito_value_ref(&payload).expect("serialize compatibility payload"),
        );
        assert!(
            SumeragiNposParameters::from_custom_parameter(&custom).is_err(),
            "numeric-string compatibility payload must be rejected"
        );
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_accepts_epoch_seed_hex_string_payload() {
        let expected = SumeragiNposParameters::default();
        let mut payload =
            norito::json::to_value(&expected).expect("serialize npos payload to json value");
        let map = payload
            .as_object_mut()
            .expect("npos payload should serialize as object");
        let mut hex_seed = String::with_capacity(64);
        for byte in expected.epoch_seed() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            hex_seed.push(HEX[(byte >> 4) as usize] as char);
            hex_seed.push(HEX[(byte & 0x0F) as usize] as char);
        }
        map.insert(
            "epoch_seed".to_owned(),
            norito::json::Value::String(hex_seed),
        );
        let custom = CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            Json::from_norito_value_ref(&payload).expect("serialize compatibility payload"),
        );
        let decoded = SumeragiNposParameters::from_custom_parameter(&custom)
            .expect("decode hex epoch seed payload")
            .expect("matching policy identifier");
        assert_eq!(decoded, expected);
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_rejects_epoch_seed_with_nested_quotes() {
        let expected = SumeragiNposParameters::default();
        let mut hex_seed = String::with_capacity(64);
        for byte in expected.epoch_seed() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            hex_seed.push(HEX[(byte >> 4) as usize] as char);
            hex_seed.push(HEX[(byte & 0x0F) as usize] as char);
        }
        let mut payload =
            norito::json::to_value(&expected).expect("serialize npos payload to json value");
        let map = payload
            .as_object_mut()
            .expect("npos payload should serialize as object");
        map.insert(
            "epoch_seed".to_owned(),
            norito::json::Value::String(format!("\"{hex_seed}\"")),
        );
        let custom = CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            Json::from_norito_value_ref(&payload).expect("serialize compatibility payload"),
        );
        assert!(
            SumeragiNposParameters::from_custom_parameter(&custom).is_err(),
            "nested-quoted compatibility payload must be rejected"
        );
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_accepts_valid_payload() {
        let payload = r#"{"activation_lag_blocks":1,"epoch_length_blocks":3600,"epoch_seed":"1111111111111111111111111111111111111111111111111111111111111111","evidence_horizon_blocks":7200,"finality_margin_blocks":8,"max_validators":31,"min_nomination_bond":"1","min_self_bond":"1000","slashing_delay_blocks":3600,"xor_asset_definition_id":"6TEAJqbb8oEPmLncoNiMRbLEK6tw"}"#;
        let custom = CustomParameter::new(
            SumeragiNposParameters::parameter_id(),
            payload
                .parse::<Json>()
                .expect("fixture payload should be valid json"),
        );
        assert!(
            SumeragiNposParameters::from_custom_parameter(&custom)
                .unwrap()
                .is_some(),
            "real chain payload should decode"
        );
    }
    #[test]
    fn sumeragi_npos_rejects_accountability_window_beyond_committed_capacity() {
        let mut parameters = SumeragiNposParameters {
            slashing_delay_blocks: 3_601,
            ..SumeragiNposParameters::default()
        };
        assert_eq!(
            parameters.validate(),
            Err(
                "evidence_horizon_blocks + slashing_delay_blocks must not exceed three epoch lengths"
            )
        );

        parameters.slashing_delay_blocks = 3_600;
        parameters
            .validate()
            .expect("four complete validator rosters fit the committed evidence table");
    }
    #[test]
    fn sumeragi_npos_json_rejects_missing_and_zero_epoch_seed() {
        let valid = norito::json::to_value(&SumeragiNposParameters::default())
            .expect("serialize valid NPoS parameters");
        for retired in ["k_aggregators", "redundant_send_r", "unknown"] {
            let mut payload = valid.clone();
            payload
                .as_object_mut()
                .expect("NPoS payload object")
                .insert(retired.to_owned(), norito::json::Value::from(1_u64));
            assert!(
                norito::json::value::from_value::<SumeragiNposParameters>(payload).is_err(),
                "unknown or retired field `{retired}` must fail closed"
            );
        }
        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("NPoS payload object")
            .remove("epoch_seed");
        assert!(
            norito::json::value::from_value::<SumeragiNposParameters>(missing).is_err(),
            "missing signed epoch seed must fail"
        );
        let mut zero = valid;
        zero.as_object_mut().expect("NPoS payload object").insert(
            "epoch_seed".to_owned(),
            norito::json::Value::String("00".repeat(32)),
        );
        assert!(
            norito::json::value::from_value::<SumeragiNposParameters>(zero).is_err(),
            "all-zero signed epoch seed must fail"
        );
    }

    fn handshake_metadata_fixture() -> ConsensusHandshakeMetadata {
        ConsensusHandshakeMetadata {
            mode: SumeragiConsensusMode::Permissioned,
            block_cadence_ms: NonZeroU64::new(1_000).unwrap(),
            wire_protocol_version: u32::from(crate::sumeragi::PROTOCOL_VERSION),
            consensus_fingerprint: ConsensusFingerprint::new([0xab; 32]),
            sumeragi_context:
                crate::block::consensus::SumeragiGenesisContextParameters::recommended(),
        }
    }

    #[test]
    fn handshake_metadata_rejects_arbitrary_bls_domain() {
        let mut value = norito::json::to_value(&handshake_metadata_fixture())
            .expect("serialize handshake metadata");
        value.as_object_mut().expect("metadata object").insert(
            "bls_domain".to_owned(),
            Value::String("attacker-selected-domain".to_owned()),
        );
        norito::json::value::from_value::<ConsensusHandshakeMetadata>(value)
            .expect_err("BLS domain is mode-derived and must not be accepted from genesis");
    }

    #[test]
    fn handshake_metadata_requires_signed_sumeragi_context_and_rejects_retired_authority() {
        let fixture = handshake_metadata_fixture();
        let value = norito::json::to_value(&fixture).expect("serialize handshake metadata");
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .expect("metadata object")
            .remove("sumeragi_context");
        norito::json::value::from_value::<ConsensusHandshakeMetadata>(missing)
            .expect_err("signed Sumeragi context must be mandatory");
        let mut retired = value;
        retired.as_object_mut().expect("metadata object").insert(
            "kagemusha_mint_finality".to_owned(),
            Value::Object(std::collections::BTreeMap::default()),
        );
        norito::json::value::from_value::<ConsensusHandshakeMetadata>(retired)
            .expect_err("the retired mint-finality authority is an unknown field");
    }

    #[test]
    fn handshake_metadata_validation_is_strict() {
        let baseline = handshake_metadata_fixture();
        baseline.validate().expect("canonical metadata");
        for version in [0, 2, 3, 4, 5, 7, 8, 99] {
            let mut bad_version = baseline;
            bad_version.wire_protocol_version = version;
            assert!(
                bad_version.validate().is_err(),
                "retired or unsupported version {version}"
            );
        }
        let mut bad_context = baseline;
        bad_context.sumeragi_context.da_layout.parity_shards = 0;
        assert!(bad_context.validate().is_err());
    }

    #[test]
    fn handshake_metadata_rejects_legacy_and_noncanonical_fingerprint_shapes() {
        let baseline = handshake_metadata_fixture();
        for malformed in [
            "ab".repeat(32),
            format!("0x{}", "AB".repeat(32)),
            format!("0x{}", "ab".repeat(31)),
        ] {
            let mut value = norito::json::to_value(&baseline).expect("serialize metadata");
            value
                .as_object_mut()
                .expect("metadata object")
                .insert("consensus_fingerprint".to_owned(), Value::String(malformed));
            norito::json::value::from_value::<ConsensusHandshakeMetadata>(value)
                .expect_err("noncanonical fingerprint must fail");
        }
        let mut legacy = norito::json::to_value(&baseline).expect("serialize metadata");
        let fields = legacy.as_object_mut().expect("metadata object");
        fields.insert(
            "wire_proto_versions".to_owned(),
            Value::Array(vec![Value::Number(Number::U64(u64::from(
                crate::sumeragi::PROTOCOL_VERSION,
            )))]),
        );
        norito::json::value::from_value::<ConsensusHandshakeMetadata>(legacy)
            .expect_err("legacy plural protocol list must fail");
    }
    #[test]
    fn default_ivm_heap_limits_fill_the_abi_v1_window() {
        let parameters = Parameters::default();
        assert_eq!(
            parameters.smart_contract().memory().get(),
            IVM_HEAP_MAX_BYTES
        );
        assert_eq!(parameters.executor().memory().get(), IVM_HEAP_MAX_BYTES);
    }
    #[test]
    fn sumeragi_npos_from_custom_parameter_rejects_trailing_comma_payload() {
        let payload = r#"{"xor_asset_definition_id":"6TEAJqbb8oEPmLncoNiMRbLEK6tw","epoch_seed":"1111111111111111111111111111111111111111111111111111111111111111","max_validators":31,"min_self_bond":"1","min_nomination_bond":"1","finality_margin_blocks":8,"evidence_horizon_blocks":7200,"activation_lag_blocks":1,"slashing_delay_blocks":3600,"epoch_length_blocks":3600,}"#;
        assert!(
            Json::from_raw_json(payload.to_owned()).is_err(),
            "invalid JSON must be rejected before it can enter a custom parameter"
        );
    }
}
