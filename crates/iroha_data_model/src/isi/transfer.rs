use super::*;
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;

use norito::json::{FastJsonWrite, JsonSerialize};
use std::{fmt::Display, format, string::String};
isi! {
    /// Generic instruction for a transfer of an object from the identifiable source to the identifiable destination.
    #[norito_schema(name = "iroha_data_model::isi::transfer::Transfer")]
    pub struct Transfer<S: Identifiable, O, D: Identifiable> {
        /// Source object `Id`.
        pub source: S::Id,
        /// Object which should be transferred.
        pub object: O,
        /// Destination object `Id`.
        pub destination: D::Id,
    }
}
impl Transfer<Account, DomainId, Account> {
    /// Constructs a new [`Transfer`] for a [`Domain`].
    pub fn domain(from: AccountId, domain_id: DomainId, to: AccountId) -> Self {
        Self {
            source: from,
            object: domain_id,
            destination: to,
        }
    }
}
impl Transfer<Account, AssetDefinitionId, Account> {
    /// Constructs a new [`Transfer`] for an [`AssetDefinition`].
    pub fn asset_definition(
        from: AccountId,
        asset_definition_id: AssetDefinitionId,
        to: AccountId,
    ) -> Self {
        Self {
            source: from,
            object: asset_definition_id,
            destination: to,
        }
    }
}
impl Transfer<Asset, Quantity, Account> {
    /// Constructs a new [`Transfer`] for a non-negative [`Asset`] quantity.
    pub fn asset_quantity(asset_id: AssetId, quantity: impl Into<Quantity>, to: AccountId) -> Self {
        Self {
            source: asset_id,
            object: quantity.into(),
            destination: to,
        }
    }
}
impl Transfer<Account, NftId, Account> {
    /// Constructs a new [`Transfer`] for an [`Nft`].
    pub fn nft(from: AccountId, nft_id: NftId, to: AccountId) -> Self {
        Self {
            source: from,
            object: nft_id,
            destination: to,
        }
    }
}
impl_display! {
    Transfer<S, O, D>
    where
        S: Identifiable,
        S::Id: Display,
        O: Display,
        D: Identifiable,
        D::Id: Display,
    =>
    "TRANSFER `{}` FROM `{}` TO `{}`",
    object,
    source,
    destination,
}
impl_into_box! {
    Transfer<Account, DomainId, Account> |
    Transfer<Account, AssetDefinitionId, Account> |
    Transfer<Asset, Quantity, Account> | Transfer<Account, NftId, Account>
=> TransferBox
}
isi_box! {
    /// Enum with all supported [`Transfer`] instructions.
    ///
    /// Dev note: this is an enum that groups concrete `Transfer<_, _, _>`
    /// variants (not a heap box).
    #[norito_schema(name = "iroha_data_model::isi::transfer::TransferBox")]
    pub enum TransferBox {
        /// Transfer [`Domain`] to another [`Account`].
        Domain(Transfer<Account, DomainId, Account>),
        /// Transfer [`AssetDefinition`] to another [`Account`].
        AssetDefinition(Transfer<Account, AssetDefinitionId, Account>),
        /// Transfer [`Asset`] to another [`Account`].
        Asset(Transfer<Asset, Quantity, Account>),
        /// Transfer [`Nft`] to another [`Account`].
        Nft(Transfer<Account, NftId, Account>),
    }
}
enum_type! {
    #[norito_schema(name = "iroha_data_model::isi::transfer::TransferType")]
    pub(crate) enum TransferType {
        Domain,
        AssetDefinition,
        Asset,
        Nft,
    }
}
// Seal implementations
impl crate::seal::Instruction for TransferBox {}
impl crate::seal::Instruction for Transfer<Account, DomainId, Account> {}
impl crate::seal::Instruction for Transfer<Account, AssetDefinitionId, Account> {}
impl crate::seal::Instruction for Transfer<Asset, Quantity, Account> {}
impl crate::seal::Instruction for Transfer<Account, NftId, Account> {}
impl<'a, S, O, D> norito::core::DecodeFromSlice<'a> for Transfer<S, O, D>
where
    S: Identifiable,
    S::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    O: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    D: Identifiable,
    D::Id: for<'de> norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
    Self: norito::codec::Decode,
{
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let source = super::decode_aos_canonical_field::<S::Id>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
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
                source,
                object,
                destination,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for TransferBox {
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
            0 => Self::Domain(super::decode_aos_slice_field::<
                Transfer<Account, DomainId, Account>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            1 => Self::AssetDefinition(super::decode_aos_slice_field::<
                Transfer<Account, AssetDefinitionId, Account>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            2 => Self::Asset(super::decode_aos_slice_field::<
                Transfer<Asset, Quantity, Account>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            3 => Self::Nft(super::decode_aos_slice_field::<
                Transfer<Account, NftId, Account>,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?, flags
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid TransferBox tag {tag}"
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
// Stable wire ID for encoding
impl TransferBox {
    /// Norito wire identifier for boxed transfer instructions.
    pub const WIRE_ID: &'static str = "iroha.transfer";
}
isi! {
    /// Single entry within a [`TransferAssetBatch`] instruction.
    #[norito_schema(name = "iroha_data_model::isi::transfer::TransferAssetBatchEntry")]
    pub struct TransferAssetBatchEntry {
        /// Caller-selected identifier used to correlate this leg with its receipt.
        leg_id: String,
        /// Account sending the asset.
        from: AccountId,
        /// Account receiving the asset.
        to: AccountId,
        /// Asset definition being transferred.
        asset_definition: AssetDefinitionId,
        /// Amount to transfer.
        amount: Quantity,
    }
}
impl TransferAssetBatchEntry {
    /// Construct a new batch entry with a deterministic identifier.
    ///
    /// Public SDKs should prefer [`Self::with_leg_id`] so business identifiers are
    /// visible in the submitted payload and returned receipt.
    #[must_use]
    pub fn new(
        from: AccountId,
        to: AccountId,
        asset_definition: AssetDefinitionId,
        amount: impl Into<Quantity>,
    ) -> Self {
        let amount = amount.into();
        let leg_id = format!("{from}>{to}:{asset_definition}:{amount}");
        Self {
            leg_id,
            from,
            to,
            asset_definition,
            amount,
        }
    }
    /// Construct a new batch entry with an explicit receipt correlation identifier.
    #[must_use]
    pub fn with_leg_id(
        leg_id: impl Into<String>,
        from: AccountId,
        to: AccountId,
        asset_definition: AssetDefinitionId,
        amount: impl Into<Quantity>,
    ) -> Self {
        Self {
            leg_id: leg_id.into(),
            from,
            to,
            asset_definition,
            amount: amount.into(),
        }
    }
}
/// Settlement semantics for [`TransferAssetBatch`].
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::codec::Decode,
    norito::codec::Encode,
    iroha_schema::IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[norito(tag = "mode", content = "value")]
#[repr(u8)]
pub enum BatchMode {
    /// Any rejected leg rejects the transaction and rolls back every leg.
    #[default]
    Atomic,
    /// Leg-local admission or policy failures reject only that leg and execution continues.
    ///
    /// Batch structure remains transaction-fatal. Participant accounts must
    /// already exist so a rejected independent leg cannot leak implicit
    /// account-creation state or fees into a passing sibling leg.
    Independent,
}
isi! {
    /// Deterministic batch transfer instruction covering multiple `Transfer::asset_quantity` calls.
    #[norito_schema(name = "iroha_data_model::isi::transfer::TransferAssetBatch")]
    pub struct TransferAssetBatch {
        /// Whether failures roll back the whole batch or only the affected leg.
        mode: BatchMode,
        /// Ordered transfer entries executed sequentially.
        entries: Vec<TransferAssetBatchEntry>,
    }
}
impl TransferAssetBatch {
    /// Stable wire identifier for Norito encoding.
    pub const WIRE_ID: &'static str = "iroha.transfer_batch";
    /// Construct a new batch instruction.
    #[must_use]
    pub fn new(entries: Vec<TransferAssetBatchEntry>) -> Self {
        Self {
            mode: BatchMode::Atomic,
            entries,
        }
    }
    /// Construct an independently settling batch instruction.
    #[must_use]
    pub fn independent(entries: Vec<TransferAssetBatchEntry>) -> Self {
        Self {
            mode: BatchMode::Independent,
            entries,
        }
    }
    /// Set explicit batch settlement semantics.
    #[must_use]
    pub fn with_mode(mut self, mode: BatchMode) -> Self {
        self.mode = mode;
        self
    }
}
impl crate::seal::Instruction for TransferAssetBatch {}
impl<'a> norito::core::DecodeFromSlice<'a> for TransferAssetBatchEntry {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let leg_id = super::decode_aos_canonical_field::<String>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let from = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let to = super::decode_aos_canonical_field::<AccountId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let asset_definition = super::decode_aos_canonical_field::<AssetDefinitionId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let amount = super::decode_aos_canonical_field::<Quantity>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((
            Self {
                leg_id,
                from,
                to,
                asset_definition,
                amount,
            },
            offset,
        ))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for TransferAssetBatch {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let mut offset = 0usize;
        let mode = super::decode_aos_canonical_field::<BatchMode>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        let entries = super::decode_aos_slice_field::<Vec<TransferAssetBatchEntry>>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { mode, entries }, offset))
    }
}
impl From<TransferAssetBatch> for InstructionBox {
    fn from(instruction: TransferAssetBatch) -> Self {
        InstructionBox::from_boxed(Box::new(instruction))
    }
}

impl<S, O, D> FastJsonWrite for Transfer<S, O, D>
where
    S: Identifiable,
    S::Id: JsonSerialize,
    O: JsonSerialize,
    D: Identifiable,
    D::Id: JsonSerialize,
{
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"source\":");
        JsonSerialize::json_serialize(&self.source, out);
        out.push_str(",\"object\":");
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
            out.push_str("{\"source\":")?;
            JsonSerialize::json_serialize_to(&self.source, out)?;
            out.push_str(",\"object\":")?;
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

impl FastJsonWrite for TransferAssetBatchEntry {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"leg_id\":");
        JsonSerialize::json_serialize(&self.leg_id, out);
        out.push(',');
        out.push_str("\"from\":");
        JsonSerialize::json_serialize(&self.from, out);
        out.push_str(",\"to\":");
        JsonSerialize::json_serialize(&self.to, out);
        out.push_str(",\"asset_definition\":");
        JsonSerialize::json_serialize(&self.asset_definition, out);
        out.push_str(",\"amount\":");
        JsonSerialize::json_serialize(&self.amount, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"leg_id\":")?;
            JsonSerialize::json_serialize_to(&self.leg_id, out)?;
            out.push_str(",\"from\":")?;
            JsonSerialize::json_serialize_to(&self.from, out)?;
            out.push_str(",\"to\":")?;
            JsonSerialize::json_serialize_to(&self.to, out)?;
            out.push_str(",\"asset_definition\":")?;
            JsonSerialize::json_serialize_to(&self.asset_definition, out)?;
            out.push_str(",\"amount\":")?;
            JsonSerialize::json_serialize_to(&self.amount, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

impl FastJsonWrite for TransferAssetBatch {
    fn write_json(&self, out: &mut String) {
        out.push('{');
        out.push_str("\"mode\":");
        JsonSerialize::json_serialize(&self.mode, out);
        out.push(',');
        out.push_str("\"entries\":");
        JsonSerialize::json_serialize(&self.entries, out);
        out.push('}');
    }
    fn write_json_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push_str("{\"mode\":")?;
            JsonSerialize::json_serialize_to(&self.mode, out)?;
            out.push_str(",\"entries\":")?;
            JsonSerialize::json_serialize_to(&self.entries, out)?;
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_primitives::numeric::{Numeric, NumericOperationError};
    use norito::core::DecodeFromSlice;
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked transfer fixture account keypair");
        AccountId::new(key_pair.public_key().clone())
    }
    fn asset_definition() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "rose".parse().expect("asset name"),
        )
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
    fn transfer_json_families_match_legacy_bytes_at_exact_bounds() {
        let from = account(0x0a);
        let to = account(0x0b);
        assert_exact_json(&Transfer::asset_quantity(
            AssetId::of(asset_definition(), from.clone()),
            7_u32,
            to.clone(),
        ));
        let entry =
            TransferAssetBatchEntry::with_leg_id("invoice", from, to, asset_definition(), 9_u32);
        assert_exact_json(&entry);
        assert_exact_json(&TransferAssetBatch::independent(vec![entry]));
    }
    #[test]
    fn transfer_decode_from_slice_roundtrips_asset_quantity() {
        let from = account(0x11);
        let to = account(0x22);
        let asset_id = AssetId::of(asset_definition(), from);
        let transfer = Transfer::asset_quantity(asset_id, 7_u32, to);
        let bytes = transfer.encode();
        let (decoded, used) =
            Transfer::<Asset, Quantity, Account>::decode_from_slice(&bytes).expect("decode");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, transfer);
    }
    #[test]
    fn negative_asset_quantity_cannot_decode_as_transfer() {
        let from = account(0x19);
        let to = account(0x29);
        let negative = Numeric::new(-25_i32, 1);
        assert_eq!(
            Quantity::try_from_numeric(negative.clone()),
            Err(NumericOperationError::NegativeQuantity)
        );
        let forged = Transfer::<Asset, Numeric, Account> {
            source: AssetId::of(asset_definition(), from),
            object: negative,
            destination: to,
        };
        assert!(
            Transfer::<Asset, Quantity, Account>::decode_from_slice(&forged.encode()).is_err(),
            "negative signed payload must not decode as an asset transfer"
        );
    }
    #[test]
    fn transfer_box_registry_decodes_stable_id_from_misaligned_payload() {
        let from = account(0x33);
        let to = account(0x44);
        let asset_id = AssetId::of(asset_definition(), from);
        let transfer_box = TransferBox::Asset(Transfer::asset_quantity(asset_id, 11_u32, to));
        let (payload, flags) = norito::codec::encode_with_header_flags(&transfer_box);
        let framed = norito::core::frame_bare_with_header_flags::<TransferBox>(&payload, flags)
            .expect("frame transfer box");
        let mut misaligned = Vec::with_capacity(framed.len() + 1);
        misaligned.push(0xAA);
        misaligned.extend_from_slice(&framed);
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<TransferBox>(TransferBox::WIRE_ID);
        let decoded = crate::isi::InstructionRegistry::decode(
            &registry,
            TransferBox::WIRE_ID,
            &misaligned[1..],
        )
        .expect("registered transfer box")
        .expect("decode transfer box");
        assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
    }
    #[test]
    fn transfer_asset_batch_decode_from_slice_roundtrips() {
        let from = account(0x55);
        let to = account(0x66);
        let definition = asset_definition();
        let batch = TransferAssetBatch::independent(vec![
            TransferAssetBatchEntry::with_leg_id(
                "invoice-1",
                from.clone(),
                to.clone(),
                definition.clone(),
                1_u32,
            ),
            TransferAssetBatchEntry::with_leg_id("invoice-2", to, from, definition, 2_u32),
        ]);
        let bytes = batch.encode();
        let (decoded, used) = TransferAssetBatch::decode_from_slice(&bytes).expect("decode batch");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, batch);
        assert_eq!(decoded.mode, BatchMode::Independent);
        assert_eq!(decoded.entries[0].leg_id, "invoice-1");
        assert_eq!(decoded.entries[1].leg_id, "invoice-2");
    }
    #[test]
    fn transfer_asset_batch_registry_decodes_stable_id() {
        let from = account(0x77);
        let to = account(0x88);
        let batch = TransferAssetBatch::new(vec![TransferAssetBatchEntry::new(
            from,
            to,
            asset_definition(),
            3_u32,
        )]);
        let (payload, flags) = norito::codec::encode_with_header_flags(&batch);
        let framed =
            norito::core::frame_bare_with_header_flags::<TransferAssetBatch>(&payload, flags)
                .expect("frame batch");
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<TransferAssetBatch>(TransferAssetBatch::WIRE_ID);
        let decoded = crate::isi::InstructionRegistry::decode(
            &registry,
            TransferAssetBatch::WIRE_ID,
            &framed,
        )
        .expect("registered transfer batch")
        .expect("decode transfer batch");
        assert_eq!(crate::isi::Instruction::dyn_encode(&*decoded), payload);
    }
}

#[cfg(test)]
mod checked_container_cleanup_tests {
    //! Original owning writer refusal and nested-depth controls.
    use super::*;
    use crate::checked_container_refusal_controls::{account, asset, audit, definition};

    #[test]
    fn original_transfer_checked_container_retains_bytes_errors_and_depth() {
        audit(&Transfer::asset_quantity(asset(), 7_u32, account(62)));
    }

    #[test]
    fn original_batch_entry_checked_container_retains_bytes_errors_and_depth() {
        audit(&TransferAssetBatchEntry::with_leg_id(
            "original",
            account(61),
            account(62),
            definition(),
            7_u32,
        ));
    }

    #[test]
    fn original_batch_transfer_checked_container_retains_bytes_errors_and_depth() {
        audit(&TransferAssetBatch::new(vec![
            TransferAssetBatchEntry::with_leg_id(
                "original",
                account(61),
                account(62),
                definition(),
                7_u32,
            ),
        ]));
        audit(&TransferAssetBatch::independent(vec![
            TransferAssetBatchEntry::with_leg_id(
                "original",
                account(61),
                account(62),
                definition(),
                7_u32,
            ),
        ]));
    }
}
