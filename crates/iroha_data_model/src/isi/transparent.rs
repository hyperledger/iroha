use super::*;
use crate::asset::id::AssetId;
use core::num::NonZeroU16;
use iroha_crypto::PublicKey;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;

use norito::json::{FastJsonWrite, JsonSerialize};
use std::fmt::Display;
iroha_data_model_derive::model_single! {
    /// Generic instruction for setting a chain-wide config parameter.
    #[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Constructor)]
    #[derive(Decode, Encode)]
    #[derive(iroha_schema::IntoSchema)]
    #[display("SET `{_0}`")]
    #[repr(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::transparent::SetParameter")]
    pub struct SetParameter(pub Parameter);
}
isi! {
    /// Generic instruction to set key value at the object.
    #[norito_schema(name = "iroha_data_model::isi::transparent::SetKeyValue")]
    pub struct SetKeyValue<O: Identifiable> {
        /// Where to set key value.
        pub object: O::Id,
        /// Key.
        pub key: Name,
        /// Value.
        pub value: Json,
    }
}
impl SetKeyValue<Domain> {
    /// Constructs a new [`SetKeyValue`] for a [`Domain`] with the given `key` and `value`.
    pub fn domain(domain_id: DomainId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            object: domain_id,
            key,
            value: value.into(),
        }
    }
}
impl SetKeyValue<Account> {
    /// Constructs a new [`SetKeyValue`] for an [`Account`] with the given `key` and `value`.
    pub fn account(account_id: AccountId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            object: account_id,
            key,
            value: value.into(),
        }
    }
}
impl SetKeyValue<AssetDefinition> {
    /// Constructs a new [`SetKeyValue`] for an [`AssetDefinition`] with the given `key` and `value`.
    pub fn asset_definition(
        asset_definition_id: AssetDefinitionId,
        key: Name,
        value: impl Into<Json>,
    ) -> Self {
        Self {
            object: asset_definition_id,
            key,
            value: value.into(),
        }
    }
}
impl SetKeyValue<Nft> {
    /// Constructs a new [`SetKeyValue`] for an [`Nft`] with the given `key` and `value`.
    pub fn nft(nft_id: NftId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            object: nft_id,
            key,
            value: value.into(),
        }
    }
}
impl SetKeyValue<Rwa> {
    /// Constructs a new [`SetKeyValue`] for an [`Rwa`] with the given `key` and `value`.
    pub fn rwa(rwa_id: RwaId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            object: rwa_id,
            key,
            value: value.into(),
        }
    }
}
impl SetKeyValue<Trigger> {
    /// Constructs a new [`SetKeyValue`] for a [`Trigger`] with the given `key` and `value`.
    pub fn trigger(trigger_id: TriggerId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            object: trigger_id,
            key,
            value: value.into(),
        }
    }
}
isi! {
    /// Set metadata on a concrete asset balance (`AssetId`).
    #[norito_schema(name = "iroha_data_model::isi::transparent::SetAssetKeyValue")]
    pub struct SetAssetKeyValue {
        /// Asset to edit.
        pub asset: AssetId,
        /// Metadata key.
        pub key: Name,
        /// Metadata value stored as JSON.
        pub value: Json,
    }
}
impl SetAssetKeyValue {
    /// Convenience constructor for asset metadata edits.
    pub fn new(asset: AssetId, key: Name, value: impl Into<Json>) -> Self {
        Self {
            asset,
            key,
            value: value.into(),
        }
    }
}
impl_display! {
    SetAssetKeyValue => "SET `{}` = `{}` ON ASSET `{}`", key, value, asset
}
impl_display! {
    SetKeyValue<O>
    where
        O: Identifiable,
        O::Id: Display,
    =>
    "SET `{}` = `{}` IN `{}`",
    key, value, object,
}
impl_into_box! {
    SetKeyValue<Domain> |
    SetKeyValue<Account> |
    SetKeyValue<AssetDefinition> |
    SetKeyValue<Nft> |
    SetKeyValue<Trigger>
=> SetKeyValueBox
}
isi! {
    /// Generic instruction to remove key value at the object.
    #[norito_schema(name = "iroha_data_model::isi::transparent::RemoveKeyValue")]
    pub struct RemoveKeyValue<O: Identifiable> {
        /// From where to remove key value.
        pub object: O::Id,
        /// Key of the pair to remove.
        pub key: Name,
    }
}
impl RemoveKeyValue<Domain> {
    /// Constructs a new [`RemoveKeyValue`] for a [`Domain`] with the given `key`.
    pub fn domain(domain_id: DomainId, key: Name) -> Self {
        Self {
            object: domain_id,
            key,
        }
    }
}
impl RemoveKeyValue<Account> {
    /// Constructs a new [`RemoveKeyValue`] for an [`Account`] with the given `key`.
    pub fn account(account_id: AccountId, key: Name) -> Self {
        Self {
            object: account_id,
            key,
        }
    }
}
impl RemoveKeyValue<AssetDefinition> {
    /// Constructs a new [`RemoveKeyValue`] for an [`AssetDefinition`] with the given `key`.
    pub fn asset_definition(asset_definition_id: AssetDefinitionId, key: Name) -> Self {
        Self {
            object: asset_definition_id,
            key,
        }
    }
}
impl RemoveKeyValue<Nft> {
    /// Constructs a new [`RemoveKeyValue`] for an [`Nft`] with the given `key`.
    pub fn nft(nft_id: NftId, key: Name) -> Self {
        Self {
            object: nft_id,
            key,
        }
    }
}
impl RemoveKeyValue<Rwa> {
    /// Constructs a new [`RemoveKeyValue`] for an [`Rwa`] with the given `key`.
    pub fn rwa(rwa_id: RwaId, key: Name) -> Self {
        Self {
            object: rwa_id,
            key,
        }
    }
}
impl RemoveKeyValue<Trigger> {
    /// Constructs a new [`RemoveKeyValue`] for a [`Trigger`] with the given `key`.
    pub fn trigger(trigger_id: TriggerId, key: Name) -> Self {
        Self {
            object: trigger_id,
            key,
        }
    }
}
isi! {
    /// Remove a metadata key from a concrete asset balance (`AssetId`).
    #[norito_schema(name = "iroha_data_model::isi::transparent::RemoveAssetKeyValue")]
    pub struct RemoveAssetKeyValue {
        /// Asset to edit.
        pub asset: AssetId,
        /// Metadata key to remove.
        pub key: Name,
    }
}
impl RemoveAssetKeyValue {
    /// Convenience constructor for removing asset metadata.
    pub fn new(asset: AssetId, key: Name) -> Self {
        Self { asset, key }
    }
}
impl_display! {
    RemoveAssetKeyValue => "REMOVE `{}` FROM ASSET `{}`", key, asset
}
impl_display! {
    RemoveKeyValue<O>
    where
        O: Identifiable,
        O::Id: Display,
    =>
    "REMOVE `{}` from `{}`",
    key, object,
}
impl_into_box! {
    RemoveKeyValue<Domain> |
    RemoveKeyValue<Account> |
    RemoveKeyValue<AssetDefinition> |
    RemoveKeyValue<Nft> |
    RemoveKeyValue<Trigger>
=> RemoveKeyValueBox
}
isi! {
    /// Add a signatory to an account's multisig specification.
    #[norito_schema(name = "iroha_data_model::isi::transparent::AddSignatory")]
    pub struct AddSignatory {
        /// Account whose multisig spec is updated.
        pub account: AccountId,
        /// Public key to add as a signatory (weight defaults to 1).
        pub signatory: PublicKey,
    }
}
impl AddSignatory {
    /// Construct a signatory-add instruction.
    pub fn new(account: AccountId, signatory: PublicKey) -> Self {
        Self { account, signatory }
    }
}
isi! {
    /// Remove a signatory from an account's multisig specification.
    #[norito_schema(name = "iroha_data_model::isi::transparent::RemoveSignatory")]
    pub struct RemoveSignatory {
        /// Account whose multisig spec is updated.
        pub account: AccountId,
        /// Public key to remove.
        pub signatory: PublicKey,
    }
}
impl RemoveSignatory {
    /// Construct a signatory-remove instruction.
    pub fn new(account: AccountId, signatory: PublicKey) -> Self {
        Self { account, signatory }
    }
}
isi! {
    /// Set the quorum threshold for an account's multisig specification.
    #[norito_schema(name = "iroha_data_model::isi::transparent::SetAccountQuorum")]
    pub struct SetAccountQuorum {
        /// Account whose multisig spec is updated.
        pub account: AccountId,
        /// Required approval weight (must be non-zero).
        pub quorum: NonZeroU16,
    }
}
impl SetAccountQuorum {
    /// Construct an account quorum update.
    pub fn new(account: AccountId, quorum: NonZeroU16) -> Self {
        Self { account, quorum }
    }
}
impl_display! {
    AddSignatory => "ADD SIGNATORY `{}` TO `{}`", signatory, account
}
impl_display! {
    RemoveSignatory => "REMOVE SIGNATORY `{}` FROM `{}`", signatory, account
}
impl_display! {
    SetAccountQuorum => "SET QUORUM `{}` FOR `{}`", quorum, account
}
isi! {
    /// Generic instruction for granting permission to an entity.
    #[norito_schema(name = "iroha_data_model::isi::transparent::Grant")]
    pub struct Grant<O, D: Identifiable> {
        /// Object to grant.
        pub object: O,
        /// Entity to which to grant this token.
        pub destination: D::Id,
    }
}
impl Grant<Permission, Account> {
    /// Constructs a new [`Grant`] for a [`Permission`].
    pub fn account_permission(permission: impl Into<Permission>, to: AccountId) -> Self {
        Self {
            object: permission.into(),
            destination: to,
        }
    }
}
impl Grant<RoleId, Account> {
    /// Constructs a new [`Grant`] for a [`Role`].
    pub fn account_role(role_id: RoleId, to: AccountId) -> Self {
        Self {
            object: role_id,
            destination: to,
        }
    }
}
impl Grant<Permission, Role> {
    /// Constructs a new [`Grant`] for giving a [`Permission`] to [`Role`].
    pub fn role_permission(permission: impl Into<Permission>, to: RoleId) -> Self {
        Self {
            object: permission.into(),
            destination: to,
        }
    }
}
impl_display! {
    Grant<O, D>
    where
        O: Display,
        D: Identifiable,
        D::Id: Display,
    =>
    "GRANT `{}` TO `{}`",
    object,
    destination,
}
impl_into_box! {
    Grant<Permission, Account> |
    Grant<RoleId, Account> |
    Grant<Permission, Role>
=> GrantBox
}
isi! {
    /// Generic instruction for revoking permission from an entity.
    #[norito_schema(name = "iroha_data_model::isi::transparent::Revoke")]
    pub struct Revoke<O, D: Identifiable> {
        /// Object to revoke.
        pub object: O,
        /// Entity which is being revoked this token from.
        pub destination: D::Id,
    }
}
impl Revoke<Permission, Account> {
    /// Constructs a new [`Revoke`] for a [`Permission`].
    pub fn account_permission(permission: impl Into<Permission>, from: AccountId) -> Self {
        Self {
            object: permission.into(),
            destination: from,
        }
    }
}
impl Revoke<RoleId, Account> {
    /// Constructs a new [`Revoke`] for a [`Role`].
    pub fn account_role(role_id: RoleId, from: AccountId) -> Self {
        Self {
            object: role_id,
            destination: from,
        }
    }
}
impl Revoke<Permission, Role> {
    /// Constructs a new [`Revoke`] for removing a [`Permission`] from [`Role`].
    pub fn role_permission(permission: impl Into<Permission>, from: RoleId) -> Self {
        Self {
            object: permission.into(),
            destination: from,
        }
    }
}
impl_display! {
    Revoke<O, D>
    where
        O: Display,
        D: Identifiable,
        D::Id: Display,
    =>
    "REVOKE `{}` FROM `{}`",
    object,
    destination,
}
impl_into_box! {
    Revoke<Permission, Account> |
    Revoke<RoleId, Account> |
    Revoke<Permission, Role>
=> RevokeBox
}
// NOTE: `BuiltInInstruction` is blanket-implemented for all `T: Instruction + Encode`
// in `isi::mod`. The following specializations duplicated that behaviour and caused
// conflicting impl errors (E0119). They are intentionally removed to rely on the
// blanket implementation.
isi! {
    /// Instruction to execute specified trigger
    #[derive(Display)]
    #[display("EXECUTE `{trigger}`")]
    #[norito_schema(name = "iroha_data_model::isi::transparent::ExecuteTrigger")]
    pub struct ExecuteTrigger {
        /// Id of a trigger to execute
        pub trigger: TriggerId,
        /// Arguments to trigger execution
        pub args: Json,
    }
}
impl ExecuteTrigger {
    /// Constructor for [`Self`]
    pub fn new(trigger: TriggerId) -> Self {
        Self {
            trigger,
            args: Json::new(norito::json!({})),
        }
    }
    /// Add trigger execution args
    #[must_use]
    pub fn with_args<T: norito::json::JsonSerialize + 'static>(mut self, args: T) -> Self {
        self.args = Json::new(args);
        self
    }
}
impl From<ExecuteTrigger> for super::InstructionBox {
    fn from(instruction: ExecuteTrigger) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
isi! {
    /// Generic instruction for upgrading runtime objects.
    #[derive(Constructor, Display)]
    #[display("UPGRADE")]
    #[repr(transparent)]
    #[norito_schema(name = "iroha_data_model::isi::transparent::Upgrade")]
    pub struct Upgrade {
        /// Object to upgrade.
        pub executor: Executor,
    }
}

impl norito::json::FastJsonWrite for SetParameter {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.0, out)
    }
}

impl norito::json::JsonDeserialize for SetParameter {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let parameter = <Parameter as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        Ok(Self(parameter))
    }
}

impl norito::json::FastJsonWrite for Upgrade {
    fn write_json(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.executor, out);
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::JsonSerialize::json_serialize_to(&self.executor, out)
    }
}

impl norito::json::JsonDeserialize for Upgrade {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let executor = <Executor as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        Ok(Self { executor })
    }
}
isi! {
    /// Instruction to print logs
    #[derive(Constructor, Display)]
    #[display("LOG({level}): {msg}")]
    #[norito_schema(name = "iroha_data_model::isi::transparent::Log")]
    pub struct Log {
        /// Message log level
        pub level: Level,
        /// Msg to be logged
        pub msg: String,
    }
}
impl From<Log> for super::InstructionBox {
    fn from(instruction: Log) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Log {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let level = super::decode_aos_canonical_field::<Level>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let msg = super::decode_aos_slice_field::<String>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { level, msg }, offset))
    }
}
isi! {
    /// Custom executor-defined instruction envelope.
    ///
    /// `CustomInstruction` is a standardized wrapper to carry executor-specific instructions
    /// without forking the data model. It serializes via Norito and is transported on-chain like
    /// other ISI. The default executor in `iroha_core` does not execute it and will panic if
    /// encountered; production use requires a custom executor that recognizes and handles the
    /// payload deterministically on every validating peer.
    ///
    /// Intended usage
    /// - Private/consortium deployments or prototyping: implement a custom
    ///   executor that downcasts `InstructionBox` to `CustomInstruction` and
    ///   interprets its `payload` deterministically. Advertise supported custom
    ///   instruction identifiers in `ExecutorDataModel::instructions`.
    /// - Public networks: avoid; prefer Kotodama contracts for application logic
    ///   or upstream new built-in ISI for platform features. Divergent executors
    ///   will fork consensus.
    ///
    /// With Norito and IVM
    /// - Norito: `CustomInstruction` derives `Encode`/`Decode` (via the module
    ///   macro); the payload is stored as `Json` (deterministic Norito encoding).
    ///   Round-trips are stable provided the registry includes `CustomInstruction`.
    /// - IVM: Kotodama targets IVM bytecode (`.to`) and is the recommended way
    ///   to express application logic. `CustomInstruction` is for executor-level
    ///   extensions; keep execution deterministic and avoid hardware-dependent
    ///   behavior. Ensure all validators run identical executor binaries.
    ///
    /// Note: When enabling custom instructions, remember to populate
    /// [`ExecutorDataModel::instructions`] during executor migration so peers can
    /// advertise support and clients can validate payload identifiers.
    ///
    /// # Examples
    /// - See `data_model/samples/executor_custom_data_model/{simple_isi.rs,complex_isi.rs}`
    ///   for wrapping domain-specific ISI into `CustomInstruction` and dispatching
    ///   in a custom executor.
    #[derive(Display)]
    #[display("CUSTOM({payload})")]
    #[norito_schema(name = "iroha_data_model::isi::transparent::CustomInstruction")]
    pub struct CustomInstruction {
        pub payload: Json,
    }
}
impl CustomInstruction {
    /// Constructor
    pub fn new(payload: impl Into<Json>) -> Self {
        Self {
            payload: payload.into(),
        }
    }
}
isi! {
    /// Placeholder instruction used when decoding an ISI payload fails.
    ///
    /// Nodes may choose to decode malformed instruction payloads into this sentinel value instead
    /// of panicking. The runtime executor must reject it deterministically.
    ///
    /// Dev note: This instruction is not intended to be submitted by clients.
    #[derive(Display)]
    #[display("INVALID_INSTRUCTION({wire_id}, {payload_hash:?}): {message}")]
    #[norito_schema(name = "iroha_data_model::isi::transparent::InvalidInstruction")]
    pub struct InvalidInstruction {
        /// Wire identifier of the instruction that failed to decode.
        pub wire_id: String,
        /// Hash of the raw instruction payload bytes.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub payload_hash: [u8; 32],
        /// Human-readable decode failure message (best-effort).
        pub message: String,
    }
}
impl InvalidInstruction {
    /// Stable wire identifier for invalid instruction placeholders.
    pub const WIRE_ID: &'static str = "iroha.invalid_instruction";
    /// Construct a new invalid instruction placeholder.
    #[must_use]
    pub fn new(
        wire_id: impl Into<String>,
        payload_hash: [u8; 32],
        message: impl Into<String>,
    ) -> Self {
        Self {
            wire_id: wire_id.into(),
            payload_hash,
            message: message.into(),
        }
    }
}
// Seal implementations
impl crate::seal::Instruction for SetParameter {}
impl crate::seal::Instruction for SetKeyValueBox {}
impl crate::seal::Instruction for RemoveKeyValueBox {}
impl crate::seal::Instruction for GrantBox {}
impl crate::seal::Instruction for RevokeBox {}
impl crate::seal::Instruction for CustomInstruction {}
impl crate::seal::Instruction for InvalidInstruction {}
impl crate::seal::Instruction for SetKeyValue<Domain> {}
impl crate::seal::Instruction for SetKeyValue<AssetDefinition> {}
impl crate::seal::Instruction for SetKeyValue<Account> {}
impl crate::seal::Instruction for SetKeyValue<Nft> {}
impl crate::seal::Instruction for SetKeyValue<Trigger> {}
impl crate::seal::Instruction for SetAssetKeyValue {}
impl crate::seal::Instruction for RemoveKeyValue<Domain> {}
impl crate::seal::Instruction for RemoveKeyValue<AssetDefinition> {}
impl crate::seal::Instruction for RemoveKeyValue<Account> {}
impl crate::seal::Instruction for RemoveKeyValue<Nft> {}
impl crate::seal::Instruction for RemoveKeyValue<Trigger> {}
impl crate::seal::Instruction for RemoveAssetKeyValue {}
impl crate::seal::Instruction for AddSignatory {}
impl crate::seal::Instruction for RemoveSignatory {}
impl crate::seal::Instruction for SetAccountQuorum {}
impl crate::seal::Instruction for Grant<Permission, Account> {}
impl crate::seal::Instruction for Grant<RoleId, Account> {}
impl crate::seal::Instruction for Grant<Permission, Role> {}
impl crate::seal::Instruction for Revoke<Permission, Account> {}
impl crate::seal::Instruction for Revoke<RoleId, Account> {}
impl crate::seal::Instruction for Revoke<Permission, Role> {}
impl crate::seal::Instruction for ExecuteTrigger {}
impl crate::seal::Instruction for Upgrade {}
impl crate::seal::Instruction for Log {}
impl<'a> norito::core::DecodeFromSlice<'a> for SetParameter {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let parameter = super::decode_aos_canonical_field::<Parameter>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self(parameter), offset))
    }
}
impl<'a, O> norito::core::DecodeFromSlice<'a> for SetKeyValue<O>
where
    O: Identifiable,
    O::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    Self: norito::codec::Decode,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let object = super::decode_aos_canonical_field::<O::Id>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let key = super::decode_aos_slice_field::<Name>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let value = super::decode_aos_canonical_field::<Json>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { object, key, value }, offset))
    }
}
impl<'a, O> norito::core::DecodeFromSlice<'a> for RemoveKeyValue<O>
where
    O: Identifiable,
    O::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    Self: norito::codec::Decode,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let object = super::decode_aos_canonical_field::<O::Id>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let key = super::decode_aos_slice_field::<Name>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { object, key }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for SetAssetKeyValue {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let asset = super::decode_aos_canonical_field::<AssetId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let key = super::decode_aos_slice_field::<Name>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let value = super::decode_aos_canonical_field::<Json>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { asset, key, value }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RemoveAssetKeyValue {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let asset = super::decode_aos_canonical_field::<AssetId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let key = super::decode_aos_slice_field::<Name>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { asset, key }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for AddSignatory {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let account = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let signatory = super::decode_aos_canonical_field::<PublicKey>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { account, signatory }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for RemoveSignatory {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let account = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let signatory = super::decode_aos_canonical_field::<PublicKey>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { account, signatory }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for SetAccountQuorum {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let account = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let quorum = super::decode_aos_canonical_field::<NonZeroU16>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { account, quorum }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for super::SetKeyValueBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Domain(super::decode_aos_slice_field::<SetKeyValue<Domain>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            1 => Self::Account(super::decode_aos_slice_field::<SetKeyValue<Account>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::AssetDefinition(super::decode_aos_slice_field::<
                SetKeyValue<AssetDefinition>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            3 => Self::Nft(super::decode_aos_slice_field::<SetKeyValue<Nft>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            4 => Self::Trigger(super::decode_aos_slice_field::<SetKeyValue<Trigger>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid SetKeyValueBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for super::RemoveKeyValueBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Domain(super::decode_aos_slice_field::<RemoveKeyValue<Domain>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            1 => Self::Account(super::decode_aos_slice_field::<RemoveKeyValue<Account>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::AssetDefinition(super::decode_aos_slice_field::<
                RemoveKeyValue<AssetDefinition>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            3 => Self::Nft(super::decode_aos_slice_field::<RemoveKeyValue<Nft>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            4 => Self::Trigger(super::decode_aos_slice_field::<RemoveKeyValue<Trigger>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid RemoveKeyValueBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
impl<'a, O, D> norito::core::DecodeFromSlice<'a> for Grant<O, D>
where
    O: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    D: Identifiable,
    D::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    Self: norito::codec::Decode,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let object = super::decode_aos_canonical_field::<O>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let destination = super::decode_aos_canonical_field::<D::Id>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                object,
                destination,
            },
            offset,
        ))
    }
}
impl<'a, O, D> norito::core::DecodeFromSlice<'a> for Revoke<O, D>
where
    O: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    D: Identifiable,
    D::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    Self: norito::codec::Decode,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let object = super::decode_aos_canonical_field::<O>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let destination = super::decode_aos_canonical_field::<D::Id>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                object,
                destination,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for super::GrantBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Permission(super::decode_aos_slice_field::<Grant<Permission, Account>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            1 => Self::Role(super::decode_aos_slice_field::<Grant<RoleId, Account>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::RolePermission(super::decode_aos_slice_field::<Grant<Permission, Role>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid GrantBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for super::RevokeBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Permission(
                super::decode_aos_slice_field::<Revoke<Permission, Account>>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?,
            ),
            1 => Self::Role(super::decode_aos_slice_field::<Revoke<RoleId, Account>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::RolePermission(super::decode_aos_slice_field::<Revoke<Permission, Role>>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid RevokeBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ExecuteTrigger {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let trigger = super::decode_aos_canonical_field::<TriggerId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let args = super::decode_aos_canonical_field::<Json>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { trigger, args }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Upgrade {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let executor = super::decode_aos_canonical_field::<Executor>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { executor }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for CustomInstruction {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let payload = super::decode_aos_canonical_field::<Json>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { payload }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for InvalidInstruction {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let wire_id = super::decode_aos_canonical_field::<String>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let payload_hash = super::decode_aos_byte_array_field::<32>(bytes, &mut offset, flags)?;
        let message = super::decode_aos_canonical_field::<String>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                wire_id,
                payload_hash,
                message,
            },
            offset,
        ))
    }
}
// Allow direct conversion into `InstructionBox` for common built-in instructions
impl From<SetParameter> for super::InstructionBox {
    fn from(instruction: SetParameter) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Stable wire IDs for instruction encoding
impl SetParameter {
    /// Norito wire identifier for parameter updates.
    pub const WIRE_ID: &'static str = "iroha.set_parameter";
}
impl ExecuteTrigger {
    /// Norito wire identifier for trigger execution.
    pub const WIRE_ID: &'static str = "iroha.execute_trigger";
}
impl Upgrade {
    /// Norito wire identifier for runtime upgrades.
    pub const WIRE_ID: &'static str = "iroha.upgrade";
}
impl Log {
    /// Norito wire identifier for log instructions.
    pub const WIRE_ID: &'static str = "iroha.log";
}
impl CustomInstruction {
    /// Norito wire identifier for custom Kotodama instructions.
    pub const WIRE_ID: &'static str = "iroha.custom";
}

impl<O> FastJsonWrite for SetKeyValue<O>
where
    O: Identifiable,
    O::Id: JsonSerialize,
{
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"object\":");
        JsonSerialize::json_serialize(&self.object, out);
        out.push_str(",\"key\":");
        JsonSerialize::json_serialize(&self.key, out);
        out.push_str(",\"value\":");
        JsonSerialize::json_serialize(&self.value, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"object\":")?;
            JsonSerialize::json_serialize_to(&self.object, out)?;
            out.push_str(",\"key\":")?;
            JsonSerialize::json_serialize_to(&self.key, out)?;
            out.push_str(",\"value\":")?;
            JsonSerialize::json_serialize_to(&self.value, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for SetAssetKeyValue {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"asset\":");
        JsonSerialize::json_serialize(&self.asset, out);
        out.push_str(",\"key\":");
        JsonSerialize::json_serialize(&self.key, out);
        out.push_str(",\"value\":");
        JsonSerialize::json_serialize(&self.value, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"asset\":")?;
            JsonSerialize::json_serialize_to(&self.asset, out)?;
            out.push_str(",\"key\":")?;
            JsonSerialize::json_serialize_to(&self.key, out)?;
            out.push_str(",\"value\":")?;
            JsonSerialize::json_serialize_to(&self.value, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl<O> FastJsonWrite for RemoveKeyValue<O>
where
    O: Identifiable,
    O::Id: JsonSerialize,
{
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"object\":");
        JsonSerialize::json_serialize(&self.object, out);
        out.push_str(",\"key\":");
        JsonSerialize::json_serialize(&self.key, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"object\":")?;
            JsonSerialize::json_serialize_to(&self.object, out)?;
            out.push_str(",\"key\":")?;
            JsonSerialize::json_serialize_to(&self.key, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for RemoveAssetKeyValue {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"asset\":");
        JsonSerialize::json_serialize(&self.asset, out);
        out.push_str(",\"key\":");
        JsonSerialize::json_serialize(&self.key, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"asset\":")?;
            JsonSerialize::json_serialize_to(&self.asset, out)?;
            out.push_str(",\"key\":")?;
            JsonSerialize::json_serialize_to(&self.key, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl<O, D> FastJsonWrite for Grant<O, D>
where
    O: JsonSerialize,
    D: Identifiable,
    D::Id: JsonSerialize,
{
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"object\":");
        JsonSerialize::json_serialize(&self.object, out);
        out.push_str(",\"destination\":");
        JsonSerialize::json_serialize(&self.destination, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"object\":")?;
            JsonSerialize::json_serialize_to(&self.object, out)?;
            out.push_str(",\"destination\":")?;
            JsonSerialize::json_serialize_to(&self.destination, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl<O, D> FastJsonWrite for Revoke<O, D>
where
    O: JsonSerialize,
    D: Identifiable,
    D::Id: JsonSerialize,
{
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"object\":");
        JsonSerialize::json_serialize(&self.object, out);
        out.push_str(",\"destination\":");
        JsonSerialize::json_serialize(&self.destination, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"object\":")?;
            JsonSerialize::json_serialize_to(&self.object, out)?;
            out.push_str(",\"destination\":")?;
            JsonSerialize::json_serialize_to(&self.destination, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for ExecuteTrigger {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"trigger\":");
        JsonSerialize::json_serialize(&self.trigger, out);
        out.push_str(",\"args\":");
        JsonSerialize::json_serialize(&self.args, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"trigger\":")?;
            JsonSerialize::json_serialize_to(&self.trigger, out)?;
            out.push_str(",\"args\":")?;
            JsonSerialize::json_serialize_to(&self.args, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for Log {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"level\":");
        JsonSerialize::json_serialize(&self.level, out);
        out.push_str(",\"msg\":");
        JsonSerialize::json_serialize(&self.msg, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"level\":")?;
            JsonSerialize::json_serialize_to(&self.level, out)?;
            out.push_str(",\"msg\":")?;
            JsonSerialize::json_serialize_to(&self.msg, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}
impl From<Upgrade> for super::InstructionBox {
    fn from(instruction: Upgrade) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<CustomInstruction> for super::InstructionBox {
    fn from(instruction: CustomInstruction) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<InvalidInstruction> for super::InstructionBox {
    fn from(instruction: InvalidInstruction) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for smart contract manifest registration instruction
impl From<super::smart_contract_code::RegisterSmartContractCode> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::RegisterSmartContractCode) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for smart contract instance deactivation instruction
impl From<super::smart_contract_code::DeactivateContractInstance> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::DeactivateContractInstance) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for smart contract bytecode registration instruction
impl From<super::smart_contract_code::RegisterSmartContractBytes> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::RegisterSmartContractBytes) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for smart contract bytecode upload instructions
impl From<super::smart_contract_code::UploadSmartContractCodeChunk> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::UploadSmartContractCodeChunk) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::FinalizeSmartContractCodeUpload> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::FinalizeSmartContractCodeUpload) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::CancelSmartContractCodeUpload> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::CancelSmartContractCodeUpload) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for smart contract bytecode removal instruction
impl From<super::smart_contract_code::RemoveSmartContractBytes> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::RemoveSmartContractBytes) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for contract instance activation instruction
impl From<super::smart_contract_code::ActivateContractInstance> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::ActivateContractInstance) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::SetContractParliamentDelegation> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::SetContractParliamentDelegation) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::OfferContractOwnership> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::OfferContractOwnership) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::AcceptContractOwnership> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::AcceptContractOwnership) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
impl From<super::smart_contract_code::CancelContractOwnershipOffer> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::CancelContractOwnershipOffer) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for atomic contract deployment instruction
impl From<super::smart_contract_code::CommitContractDeployment> for super::InstructionBox {
    fn from(instruction: super::smart_contract_code::CommitContractDeployment) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Allow direct conversion for governance citizenship instructions.
#[cfg(feature = "governance")]
impl From<super::governance::RegisterCitizen> for super::InstructionBox {
    fn from(instruction: super::governance::RegisterCitizen) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
#[cfg(feature = "governance")]
impl From<super::governance::UnregisterCitizen> for super::InstructionBox {
    fn from(instruction: super::governance::UnregisterCitizen) -> Self {
        super::Instruction::into_instruction_box(Box::new(instruction))
    }
}
// Convenience accessor to avoid re-decoding `Parameter` in executors
impl SetParameter {
    /// Borrow the underlying `Parameter` value
    pub fn inner(&self) -> &Parameter {
        &self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use norito::core::DecodeFromSlice;
    fn public_key(seed: u8) -> PublicKey {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked transparent ISI fixture keypair");
        key_pair.public_key().clone()
    }
    fn account(seed: u8) -> AccountId {
        AccountId::new(public_key(seed))
    }
    fn asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        )
    }
    fn asset_id() -> AssetId {
        AssetId::of(asset_definition(), account(0x51))
    }
    fn permission(name: &str) -> Permission {
        Permission::new(name.to_owned(), Json::new(()))
    }
    fn role_id(name: &str) -> RoleId {
        name.parse().expect("role id")
    }

    fn assert_exact_json<T: norito::json::JsonSerialize>(value: &T) {
        let legacy = norito::json::to_json(value).expect("serialize legacy JSON");
        assert_eq!(
            norito::json::to_json_bounded(value, legacy.len()).expect("serialize at exact bound"),
            legacy
        );
        assert_eq!(
            norito::json::to_json_bounded(value, legacy.len() - 1),
            Err(norito::json::BoundedJsonError::BodyTooLarge)
        );
    }

    #[test]
    fn transparent_instruction_json_families_have_exact_checked_bounds() {
        let key: Name = "memo".parse().expect("metadata key");
        let holder = account(0x70);
        let asset = asset_id();
        let role = role_id("auditor");
        assert_exact_json(&SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireSequence(true),
        )));
        assert_exact_json(&Upgrade::new(Executor::new(
            crate::transaction::executable::IvmBytecode::from_compiled(vec![1, 2, 3]),
        )));
        assert_exact_json(&SetKeyValue::account(
            holder.clone(),
            key.clone(),
            Json::new(1_u32),
        ));
        assert_exact_json(&SetAssetKeyValue::new(
            asset.clone(),
            key.clone(),
            Json::new("value"),
        ));
        assert_exact_json(&RemoveKeyValue::account(holder.clone(), key.clone()));
        assert_exact_json(&RemoveAssetKeyValue::new(asset, key));
        assert_exact_json(&Grant::account_role(role.clone(), holder.clone()));
        assert_exact_json(&Revoke::account_role(role, holder));
        assert_exact_json(
            &ExecuteTrigger::new("nightly_tick".parse().expect("trigger id"))
                .with_args(norito::json!({"a": 1_u32})),
        );
        assert_exact_json(&Log::new(Level::INFO, "checked".to_owned()));
    }
    fn assert_registry_decodes_name<T>(
        registry: &crate::isi::InstructionRegistry,
        name: &str,
        value: T,
    ) where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        let (payload, flags) = norito::codec::encode_with_header_flags(&value);
        let framed =
            norito::core::frame_bare_with_header_flags::<T>(&payload, flags).expect("frame isi");
        let decoded = crate::isi::InstructionRegistry::decode(registry, name, &framed)
            .unwrap_or_else(|| panic!("registered {name}"))
            .unwrap_or_else(|err| panic!("decode {name}: {err}"));
        assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
    }
    fn assert_registry_decodes_registered_type<T>(
        registry: &crate::isi::InstructionRegistry,
        value: T,
    ) where
        T: crate::isi::Instruction
            + norito::codec::Encode
            + 'static
            + norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        let wire_id = registry
            .wire_id(std::any::type_name::<T>())
            .expect("instruction type has an explicit wire identifier");
        assert_registry_decodes_name(registry, wire_id, value);
    }
    #[test]
    fn log_getters_expose_level_and_message() {
        let log = Log::new(Level::INFO, "hello ffi".to_owned());
        assert_eq!(*log.level(), Level::INFO);
        assert_eq!(log.msg(), "hello ffi");
    }
    #[test]
    fn set_remove_key_value_decode_from_slice_roundtrips() {
        let key: Name = "memo".parse().expect("metadata key");
        let account = account(0x52);
        let trigger: TriggerId = "nightly_tick".parse().expect("trigger id");
        let set = SetKeyValue::account(account.clone(), key.clone(), Json::new(1_u32));
        let set_bytes = set.encode();
        let (decoded, used) =
            SetKeyValue::<Account>::decode_from_slice(&set_bytes).expect("decode set account");
        assert_eq!(used, set_bytes.len());
        assert_eq!(decoded, set);
        let set = SetKeyValue::trigger(trigger.clone(), key.clone(), Json::new("on"));
        let set_bytes = set.encode();
        let (decoded, used) =
            SetKeyValue::<Trigger>::decode_from_slice(&set_bytes).expect("decode set trigger");
        assert_eq!(used, set_bytes.len());
        assert_eq!(decoded, set);
        let remove = RemoveKeyValue::account(account, key.clone());
        let remove_bytes = remove.encode();
        let (decoded, used) = RemoveKeyValue::<Account>::decode_from_slice(&remove_bytes)
            .expect("decode remove account");
        assert_eq!(used, remove_bytes.len());
        assert_eq!(decoded, remove);
        let remove = RemoveKeyValue::trigger(trigger, key);
        let remove_bytes = remove.encode();
        let (decoded, used) = RemoveKeyValue::<Trigger>::decode_from_slice(&remove_bytes)
            .expect("decode remove trigger");
        assert_eq!(used, remove_bytes.len());
        assert_eq!(decoded, remove);
    }
    #[test]
    fn asset_key_value_decode_from_slice_roundtrips() {
        let key: Name = "memo".parse().expect("metadata key");
        let set = SetAssetKeyValue::new(asset_id(), key.clone(), Json::new(2_u32));
        let set_bytes = set.encode();
        let (decoded, used) =
            SetAssetKeyValue::decode_from_slice(&set_bytes).expect("decode asset set");
        assert_eq!(used, set_bytes.len());
        assert_eq!(decoded, set);
        let remove = RemoveAssetKeyValue::new(asset_id(), key);
        let remove_bytes = remove.encode();
        let (decoded, used) =
            RemoveAssetKeyValue::decode_from_slice(&remove_bytes).expect("decode asset remove");
        assert_eq!(used, remove_bytes.len());
        assert_eq!(decoded, remove);
    }
    #[test]
    fn signatory_quorum_decode_from_slice_roundtrips() {
        let account = account(0x57);
        let signatory = public_key(0x58);
        let add = AddSignatory::new(account.clone(), signatory.clone());
        let add_bytes = add.encode();
        let (decoded, used) = AddSignatory::decode_from_slice(&add_bytes).expect("decode add");
        assert_eq!(used, add_bytes.len());
        assert_eq!(decoded, add);
        let remove = RemoveSignatory::new(account.clone(), signatory);
        let remove_bytes = remove.encode();
        let (decoded, used) =
            RemoveSignatory::decode_from_slice(&remove_bytes).expect("decode remove");
        assert_eq!(used, remove_bytes.len());
        assert_eq!(decoded, remove);
        let quorum = SetAccountQuorum::new(account, NonZeroU16::new(2).expect("nonzero quorum"));
        let quorum_bytes = quorum.encode();
        let (decoded, used) =
            SetAccountQuorum::decode_from_slice(&quorum_bytes).expect("decode quorum");
        assert_eq!(used, quorum_bytes.len());
        assert_eq!(decoded, quorum);
    }
    #[test]
    fn signatory_quorum_default_registry_decodes_canonical_wire_ids() {
        let registry = crate::isi::registry::default();
        let account = account(0x59);
        let signatory = public_key(0x5a);
        assert_registry_decodes_registered_type(
            &registry,
            AddSignatory::new(account.clone(), signatory.clone()),
        );
        assert_registry_decodes_registered_type(
            &registry,
            RemoveSignatory::new(account.clone(), signatory),
        );
        assert_registry_decodes_registered_type(
            &registry,
            SetAccountQuorum::new(account, NonZeroU16::new(3).expect("nonzero quorum")),
        );
    }
    #[test]
    fn set_parameter_decode_from_slice_roundtrips() {
        let instruction = SetParameter::new(Parameter::Transaction(
            crate::parameter::TransactionParameter::RequireSequence(true),
        ));
        let bytes = instruction.encode();
        let (decoded, used) =
            SetParameter::decode_from_slice(&bytes).expect("decode set parameter");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, instruction);
    }
    #[test]
    fn set_parameter_registry_decodes_stable_id() {
        let registry = crate::isi::registry::default();
        assert_registry_decodes_name(
            &registry,
            SetParameter::WIRE_ID,
            SetParameter::new(Parameter::Transaction(
                crate::parameter::TransactionParameter::RequireSequence(true),
            )),
        );
    }
    #[test]
    fn key_value_boxes_registry_decode_stable_ids() {
        let key: Name = "memo".parse().expect("metadata key");
        let domain = DomainId::try_new("wonderland", "universal").expect("domain id");
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<SetKeyValueBox>(SetKeyValueBox::WIRE_ID)
            .register_with_id_slice::<RemoveKeyValueBox>(RemoveKeyValueBox::WIRE_ID);
        let set_cases = [
            SetKeyValueBox::Domain(SetKeyValue::domain(
                domain.clone(),
                key.clone(),
                Json::new(1_u32),
            )),
            SetKeyValueBox::Account(SetKeyValue::account(
                account(0x53),
                key.clone(),
                Json::new(2_u32),
            )),
            SetKeyValueBox::AssetDefinition(SetKeyValue::asset_definition(
                asset_definition(),
                key.clone(),
                Json::new(3_u32),
            )),
        ];
        for value in set_cases {
            let (payload, flags) = norito::codec::encode_with_header_flags(&value);
            let framed =
                norito::core::frame_bare_with_header_flags::<SetKeyValueBox>(&payload, flags)
                    .expect("frame set key value box");
            let decoded = crate::isi::InstructionRegistry::decode(
                &registry,
                SetKeyValueBox::WIRE_ID,
                &framed,
            )
            .expect("registered set key value box")
            .expect("decode set key value box");
            assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
        }
        let remove_cases = [
            RemoveKeyValueBox::Domain(RemoveKeyValue::domain(domain, key.clone())),
            RemoveKeyValueBox::Account(RemoveKeyValue::account(account(0x54), key.clone())),
            RemoveKeyValueBox::AssetDefinition(RemoveKeyValue::asset_definition(
                asset_definition(),
                key,
            )),
        ];
        for value in remove_cases {
            let (payload, flags) = norito::codec::encode_with_header_flags(&value);
            let framed =
                norito::core::frame_bare_with_header_flags::<RemoveKeyValueBox>(&payload, flags)
                    .expect("frame remove key value box");
            let decoded = crate::isi::InstructionRegistry::decode(
                &registry,
                RemoveKeyValueBox::WIRE_ID,
                &framed,
            )
            .expect("registered remove key value box")
            .expect("decode remove key value box");
            assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
        }
    }
    #[test]
    fn grant_revoke_decode_from_slice_roundtrips() {
        let holder = account(0x55);
        let role = role_id("auditor");
        let grant = Grant::account_permission(permission("can_read"), holder.clone());
        let grant_bytes = grant.encode();
        let (decoded, used) = Grant::<Permission, Account>::decode_from_slice(&grant_bytes)
            .expect("decode account permission grant");
        assert_eq!(used, grant_bytes.len());
        assert_eq!(decoded, grant);
        let grant = Grant::account_role(role.clone(), holder.clone());
        let grant_bytes = grant.encode();
        let (decoded, used) = Grant::<RoleId, Account>::decode_from_slice(&grant_bytes)
            .expect("decode account role grant");
        assert_eq!(used, grant_bytes.len());
        assert_eq!(decoded, grant);
        let grant = Grant::role_permission(permission("can_audit"), role.clone());
        let grant_bytes = grant.encode();
        let (decoded, used) = Grant::<Permission, Role>::decode_from_slice(&grant_bytes)
            .expect("decode role permission grant");
        assert_eq!(used, grant_bytes.len());
        assert_eq!(decoded, grant);
        let revoke = Revoke::account_permission(permission("can_read"), holder.clone());
        let revoke_bytes = revoke.encode();
        let (decoded, used) = Revoke::<Permission, Account>::decode_from_slice(&revoke_bytes)
            .expect("decode account permission revoke");
        assert_eq!(used, revoke_bytes.len());
        assert_eq!(decoded, revoke);
        let revoke = Revoke::account_role(role.clone(), holder);
        let revoke_bytes = revoke.encode();
        let (decoded, used) = Revoke::<RoleId, Account>::decode_from_slice(&revoke_bytes)
            .expect("decode account role revoke");
        assert_eq!(used, revoke_bytes.len());
        assert_eq!(decoded, revoke);
        let revoke = Revoke::role_permission(permission("can_audit"), role);
        let revoke_bytes = revoke.encode();
        let (decoded, used) = Revoke::<Permission, Role>::decode_from_slice(&revoke_bytes)
            .expect("decode role permission revoke");
        assert_eq!(used, revoke_bytes.len());
        assert_eq!(decoded, revoke);
    }
    #[test]
    fn grant_revoke_boxes_registry_decode_stable_ids() {
        let holder = account(0x56);
        let role = role_id("operator");
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<GrantBox>(GrantBox::WIRE_ID)
            .register_with_id_slice::<RevokeBox>(RevokeBox::WIRE_ID);
        let grant_cases = [
            GrantBox::Permission(Grant::account_permission(
                permission("can_read"),
                holder.clone(),
            )),
            GrantBox::Role(Grant::account_role(role.clone(), holder.clone())),
            GrantBox::RolePermission(Grant::role_permission(
                permission("can_operate"),
                role.clone(),
            )),
        ];
        for value in grant_cases {
            let (payload, flags) = norito::codec::encode_with_header_flags(&value);
            let framed = norito::core::frame_bare_with_header_flags::<GrantBox>(&payload, flags)
                .expect("frame grant box");
            let decoded =
                crate::isi::InstructionRegistry::decode(&registry, GrantBox::WIRE_ID, &framed)
                    .expect("registered grant box")
                    .expect("decode grant box");
            assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
        }
        let revoke_cases = [
            RevokeBox::Permission(Revoke::account_permission(
                permission("can_read"),
                holder.clone(),
            )),
            RevokeBox::Role(Revoke::account_role(role.clone(), holder)),
            RevokeBox::RolePermission(Revoke::role_permission(permission("can_operate"), role)),
        ];
        for value in revoke_cases {
            let (payload, flags) = norito::codec::encode_with_header_flags(&value);
            let framed = norito::core::frame_bare_with_header_flags::<RevokeBox>(&payload, flags)
                .expect("frame revoke box");
            let decoded =
                crate::isi::InstructionRegistry::decode(&registry, RevokeBox::WIRE_ID, &framed)
                    .expect("registered revoke box")
                    .expect("decode revoke box");
            assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
        }
    }
    #[test]
    fn trigger_upgrade_custom_decode_from_slice_roundtrips() {
        let trigger: TriggerId = "nightly_tick".parse().expect("trigger id");
        let execute_without_args = ExecuteTrigger::new(trigger.clone());
        let execute_without_args_bytes = execute_without_args.encode();
        let (decoded_without_args, used_without_args) =
            ExecuteTrigger::decode_from_slice(&execute_without_args_bytes)
                .expect("decode execute trigger without args");
        assert_eq!(used_without_args, execute_without_args_bytes.len());
        assert_eq!(decoded_without_args, execute_without_args);
        let execute = ExecuteTrigger::new(trigger).with_args(norito::json!({"a": 1_u32}));
        let execute_bytes = execute.encode();
        let (decoded, used) =
            ExecuteTrigger::decode_from_slice(&execute_bytes).expect("decode execute trigger");
        assert_eq!(used, execute_bytes.len());
        assert_eq!(decoded, execute);
        let executor = Executor::new(crate::transaction::executable::IvmBytecode::from_compiled(
            vec![1, 2, 3],
        ));
        let upgrade = Upgrade::new(executor);
        let upgrade_bytes = upgrade.encode();
        let (decoded, used) = Upgrade::decode_from_slice(&upgrade_bytes).expect("decode upgrade");
        assert_eq!(used, upgrade_bytes.len());
        assert_eq!(decoded, upgrade);
        let custom = CustomInstruction::new(Json::new(()));
        let custom_bytes = custom.encode();
        let (decoded, used) =
            CustomInstruction::decode_from_slice(&custom_bytes).expect("decode custom");
        assert_eq!(used, custom_bytes.len());
        assert_eq!(decoded, custom);
        let invalid = InvalidInstruction::new("iroha.unknown", [0xAB; 32], "bad payload");
        let invalid_bytes = invalid.encode();
        let (decoded, used) =
            InvalidInstruction::decode_from_slice(&invalid_bytes).expect("decode invalid");
        assert_eq!(used, invalid_bytes.len());
        assert_eq!(decoded, invalid);
    }
    #[test]
    fn trigger_upgrade_custom_registry_decode_stable_ids() {
        let registry = crate::isi::registry::default();
        let trigger: TriggerId = "nightly_tick".parse().expect("trigger id");
        assert_registry_decodes_name(
            &registry,
            ExecuteTrigger::WIRE_ID,
            ExecuteTrigger::new(trigger).with_args(norito::json!({"a": 1_u32})),
        );
        let executor = Executor::new(crate::transaction::executable::IvmBytecode::from_compiled(
            vec![1, 2, 3],
        ));
        assert_registry_decodes_name(&registry, Upgrade::WIRE_ID, Upgrade::new(executor));
        assert_registry_decodes_name(
            &registry,
            CustomInstruction::WIRE_ID,
            CustomInstruction::new(Json::new(())),
        );
        assert_registry_decodes_name(
            &registry,
            InvalidInstruction::WIRE_ID,
            InvalidInstruction::new("iroha.unknown", [0xAB; 32], "bad payload"),
        );
    }
}

#[cfg(test)]
mod frame_owner_identity_tests {
    //! Frame roots observed in the original codec before the identity cutover.

    #[test]
    fn captured_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<super::SetParameter>(
            "iroha_data_model::isi::transparent::SetParameter",
        );
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::{account, asset, audit};

    #[test]
    fn original_set_key_value_checked_container_retains_bytes_errors_and_depth() {
        audit(&SetKeyValue::account(
            account(61),
            "nested".parse().unwrap(),
            iroha_primitives::json::Json::new(vec![1_u64, 2]),
        ));
    }

    #[test]
    fn original_set_asset_key_value_checked_container_retains_bytes_errors_and_depth() {
        audit(&SetAssetKeyValue::new(
            asset(),
            "nested".parse().unwrap(),
            iroha_primitives::json::Json::new(vec![1_u64, 2]),
        ));
    }

    #[test]
    fn original_remove_key_value_checked_container_retains_bytes_errors_and_depth() {
        audit(&RemoveKeyValue::account(
            account(61),
            "nested".parse().unwrap(),
        ));
    }

    #[test]
    fn original_remove_asset_key_value_checked_container_retains_bytes_errors_and_depth() {
        audit(&RemoveAssetKeyValue::new(
            asset(),
            "nested".parse().unwrap(),
        ));
    }

    #[test]
    fn original_grant_checked_container_retains_bytes_errors_and_depth() {
        audit(&Grant::account_role(
            "original_role".parse().unwrap(),
            account(61),
        ));
    }

    #[test]
    fn original_revoke_checked_container_retains_bytes_errors_and_depth() {
        audit(&Revoke::account_role(
            "original_role".parse().unwrap(),
            account(61),
        ));
    }

    #[test]
    fn original_execute_trigger_checked_container_retains_bytes_errors_and_depth() {
        audit(&ExecuteTrigger::new("original_trigger".parse().unwrap()).with_args(vec![1_u64, 2]));
    }

    #[test]
    fn original_log_checked_container_retains_bytes_errors_and_depth() {
        audit(&Log::new(crate::Level::INFO, "original \n message".into()));
    }

    #[test]
    fn original_grant_checked_container_preserves_manual_leaf_without_fast_or_clone() {
        let leaf = crate::checked_container_refusal_controls::RefusingLeaf(std::cell::Cell::new(0));
        let value = Grant::<_, crate::account::Account> {
            object: leaf,
            destination: crate::checked_container_refusal_controls::account(61),
        };
        crate::checked_container_refusal_controls::audit_leaf_refusal("{\"object\":", |out| {
            norito::json::FastJsonWrite::write_json_to(&value, out)
        });
        assert_eq!(value.object.0.get(), 1);
    }

    #[test]
    fn original_revoke_checked_container_preserves_manual_leaf_without_fast_or_clone() {
        let leaf = crate::checked_container_refusal_controls::RefusingLeaf(std::cell::Cell::new(0));
        let value = Revoke::<_, crate::account::Account> {
            object: leaf,
            destination: crate::checked_container_refusal_controls::account(61),
        };
        crate::checked_container_refusal_controls::audit_leaf_refusal("{\"object\":", |out| {
            norito::json::FastJsonWrite::write_json_to(&value, out)
        });
        assert_eq!(value.object.0.get(), 1);
    }
}
