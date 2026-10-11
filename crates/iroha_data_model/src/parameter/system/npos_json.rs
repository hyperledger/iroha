//! One `NPoS` JSON record kernel and its original-pool destination.
//!
//! This is decoded parameter custody, not signed-genesis authentication. The
//! enclosing source/decoder/State owner scopes refunds and retains source authority.

use std::alloc::Layout;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_primitives::numeric::{ChargedQuantity, QuantityJsonAdmissionError};

use crate::asset::AssetDefinitionId;

use super::{CustomParameter, JsonDeserialize, NonZeroU64, Quantity, SumeragiNposParameters, json};

/// Original JSON failure or exact admission refusal of the `NPoS` record/leaf.
#[derive(Debug)]
pub enum SumeragiNposJsonAdmissionError {
    /// Original syntax, scalar validation or cumulative decoder limit.
    Json(json::Error),
    /// Exact original-pool or physical allocator refusal before graph construction.
    Allocation(ChargedBufferError),
}
impl From<json::Error> for SumeragiNposJsonAdmissionError {
    fn from(error: json::Error) -> Self {
        Self::Json(error)
    }
}
impl From<ChargedBufferError> for SumeragiNposJsonAdmissionError {
    fn from(error: ChargedBufferError) -> Self {
        Self::Allocation(error)
    }
}
impl From<QuantityJsonAdmissionError> for SumeragiNposJsonAdmissionError {
    fn from(error: QuantityJsonAdmissionError) -> Self {
        match error {
            QuantityJsonAdmissionError::Json(error) => Self::Json(error),
            QuantityJsonAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}
impl core::fmt::Display for SumeragiNposJsonAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(error) => error.fmt(formatter),
            Self::Allocation(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for SumeragiNposJsonAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

// This charged record includes its nested allocation ledger. Field order destroys
// both canonical quantities before their exact digit charges; ChargedBuffer then
// frees this backing before refunding its own charge. No separate heap/control
// allocation is introduced for the ledger.
struct AdmittedRecord {
    value: SumeragiNposParameters,
    bond_charges: [AllocationCharge; 2],
}

/// One immutable canonical `NPoS` value with exact original-pool record and digit backing.
///
/// The single funded record contains the value before both original digit charges.
/// There is no Clone, mutable access or ordinary-value extraction. This owner is
/// not proof of a signature, genesis identity, committee or application authority.
/// The caller still admits enclosing owner/control storage, original source and
/// validation/error scratch, and defers refunds beyond State/storage guards.
// The original signed-genesis reader retains this record at its exact instruction.
// TODO(S6): fund election-policy validation/authority graphs and its Quantity clones
// at their own original boundaries; this record does not cover those later owners.
pub struct AdmittedSumeragiNposParameters {
    record: ChargedBuffer<AdmittedRecord>,
}
impl AdmittedSumeragiNposParameters {
    /// Exact backing layout, including the two original native-digit charge slots.
    #[must_use]
    pub fn allocation_layout() -> Layout {
        Layout::new::<AdmittedRecord>()
    }

    /// Decode the canonical record directly into original funded leaves and backing.
    ///
    /// The existing object/string/decimal kernels preserve lexical and field order.
    /// Keys and temporary identity/seed/quantity text use the same finite pool and
    /// retire after their original field. Successful digit backing moves exactly
    /// once into the final record, without cloning, reencoding or postcharging.
    /// The inherited decoder context is never replaced or reset. Refusal retires
    /// this attempt's partial field owners; it does not retain resumable progress.
    ///
    /// # Errors
    /// Preserves ordinary diagnostics and typed original decoder/pool refusal.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, SumeragiNposJsonAdmissionError> {
        decode_record(parser, &mut AdmittedDestination { budget })
    }

    /// Decode only a matching original custom parameter, retaining its second validation.
    ///
    /// # Errors
    /// Preserves the matching payload's exact failure, including trailing bytes and
    /// the existing custom-parameter validation label. An unrelated ID is absent.
    pub fn from_custom_parameter(
        custom: &CustomParameter,
        budget: &AllocationBudget,
    ) -> Result<Option<Self>, SumeragiNposJsonAdmissionError> {
        if custom.id != SumeragiNposParameters::parameter_id() {
            return Ok(None);
        }
        let mut parser = json::Parser::new(custom.payload().get());
        parser.preflight_document()?;
        parser.skip_ws();
        let owner = Self::try_decode_json(&mut parser, budget)?;
        parser.finish_document()?;
        owner
            .get()
            .validate()
            .map_err(|message| json::Error::InvalidField {
                field: SumeragiNposParameters::PARAMETER_ID_STR.to_owned(),
                message: message.to_owned(),
            })?;
        Ok(Some(owner))
    }

    /// Borrow the original value without separating it from its allocation ledger.
    /// Ordinary clones from this borrow are independent and cannot inherit these charges.
    #[must_use]
    pub fn get(&self) -> &SumeragiNposParameters {
        &self.record.as_slice()[0].value
    }

    /// Require exact pool identity for the record and both original digit allocations.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.record.belongs_to(budget)
            && self.record.as_slice()[0]
                .bond_charges
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
}
impl core::fmt::Debug for AdmittedSumeragiNposParameters {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("AdmittedSumeragiNposParameters")
            .field(self.get())
            .finish()
    }
}

struct AdmittedText(ChargedBuffer<u8>);
impl AsMut<[u8]> for AdmittedText {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        core::str::from_utf8(self.0.as_slice())
            .expect("the sole JSON string kernel produces valid UTF-8")
    }
}
fn admit_text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<AdmittedText, SumeragiNposJsonAdmissionError> {
    let mut text = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        text.push_reserved(0);
    }
    Ok(AdmittedText(text))
}
trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Bond;
    type Record;
    type Output;
    fn admit_record(&mut self) -> Result<Self::Record, Self::Error>;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error>;
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error>;
    fn parse_bond(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Bond, Self::Error>;
    fn finish(
        &mut self,
        record: Self::Record,
        fields: RecordFields<Self::Bond>,
    ) -> Result<Self::Output, Self::Error>;
}
struct OrdinaryDestination;
impl Destination for OrdinaryDestination {
    type Error = json::Error;
    type Text = String;
    type Bond = Quantity;
    type Record = ();
    type Output = SumeragiNposParameters;
    fn admit_record(&mut self) -> Result<(), json::Error> {
        Ok(())
    }
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a>, json::Error> {
        parser.parse_key()
    }
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<String, json::Error> {
        parser.parse_string()
    }
    fn parse_bond(&mut self, parser: &mut json::Parser<'_>) -> Result<Quantity, json::Error> {
        Quantity::json_deserialize(parser)
    }
    fn finish(
        &mut self,
        (): (),
        fields: RecordFields<Quantity>,
    ) -> Result<SumeragiNposParameters, json::Error> {
        Ok(fields.into_value(|self_bond, nomination_bond| (self_bond, nomination_bond)))
    }
}
struct AdmittedDestination<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for AdmittedDestination<'_> {
    type Error = SumeragiNposJsonAdmissionError;
    type Text = AdmittedText;
    type Bond = ChargedQuantity;
    type Record = ChargedBuffer<AdmittedRecord>;
    type Output = AdmittedSumeragiNposParameters;
    fn admit_record(&mut self) -> Result<Self::Record, Self::Error> {
        Ok(ChargedBuffer::new(1, self.budget)?)
    }
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, AdmittedText>, Self::Error> {
        parser.parse_key_with_buffer(|length| admit_text(length, self.budget))
    }
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<AdmittedText, Self::Error> {
        parser.parse_string_with_buffer(|length| admit_text(length, self.budget))
    }
    fn parse_bond(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<ChargedQuantity, Self::Error> {
        Ok(ChargedQuantity::try_decode_json(parser, self.budget)?)
    }
    #[allow(unsafe_code)]
    fn finish(
        &mut self,
        mut record: Self::Record,
        fields: RecordFields<ChargedQuantity>,
    ) -> Result<Self::Output, Self::Error> {
        // Declare the charge scratch first, so the assembled value retires first on
        // unwind. After exact move-only extraction there is no fallible operation
        // until both values and charges are installed in their closed funded record.
        let mut charges = None;
        let value = fields.into_value(|self_bond, nomination_bond| {
            // SAFETY: neither value/backing is cloned or grown. Both original
            // charges move immediately with the values into the closed record;
            // its value field retires before those charges on every later path.
            let (self_value, self_charge) = unsafe { self_bond.into_allocation_parts() };
            let (nomination_value, nomination_charge) =
                unsafe { nomination_bond.into_allocation_parts() };
            charges = Some([self_charge, nomination_charge]);
            (self_value, nomination_value)
        });
        record.push_reserved(AdmittedRecord {
            value,
            bond_charges: charges.expect("the sole field assembly moves both original bonds"),
        });
        let owner = AdmittedSumeragiNposParameters { record };
        validate_outer(owner.get())?;
        Ok(owner)
    }
}

struct RecordFields<B> {
    xor_asset_definition_id: AssetDefinitionId,
    epoch_seed: [u8; 32],
    max_validators: u32,
    min_self_bond: B,
    min_nomination_bond: B,
    finality_margin_blocks: u64,
    evidence_horizon_blocks: u64,
    activation_lag_blocks: u64,
    slashing_delay_blocks: u64,
    epoch_length_blocks: NonZeroU64,
}
impl<B> RecordFields<B> {
    fn into_value(
        self,
        move_bonds: impl FnOnce(B, B) -> (Quantity, Quantity),
    ) -> SumeragiNposParameters {
        let (min_self_bond, min_nomination_bond) =
            move_bonds(self.min_self_bond, self.min_nomination_bond);
        SumeragiNposParameters {
            xor_asset_definition_id: self.xor_asset_definition_id,
            epoch_seed: self.epoch_seed,
            max_validators: self.max_validators,
            min_self_bond,
            min_nomination_bond,
            finality_margin_blocks: self.finality_margin_blocks,
            evidence_horizon_blocks: self.evidence_horizon_blocks,
            activation_lag_blocks: self.activation_lag_blocks,
            slashing_delay_blocks: self.slashing_delay_blocks,
            epoch_length_blocks: self.epoch_length_blocks,
        }
    }
}

pub(super) fn decode_ordinary(
    parser: &mut json::Parser<'_>,
) -> Result<SumeragiNposParameters, json::Error> {
    decode_record(parser, &mut OrdinaryDestination)
}
pub(super) fn validate_outer(value: &SumeragiNposParameters) -> Result<(), json::Error> {
    value
        .validate()
        .map_err(|message| json::Error::InvalidField {
            field: "SumeragiNposParameters".to_owned(),
            message: message.to_owned(),
        })
}

// This is the exact original derive-era named-field relation, shared by both
// destinations. In particular preflight precedes object consumption; duplicate
// and unknown refusal precede value parsing; comma continuation still attempts
// a key (and rejects a trailing comma); missing fields follow declaration order.
fn decode_record<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<D::Output, D::Error> {
    parser.skip_ws();
    parser.preflight_object_entries()?;
    parser.expect(b'{')?;
    parser.skip_ws();
    let record = destination.admit_record()?;
    let mut xor_asset_definition_id: Option<AssetDefinitionId> = None;
    let mut epoch_seed: Option<[u8; 32]> = None;
    let mut max_validators: Option<u32> = None;
    let mut min_self_bond: Option<D::Bond> = None;
    let mut min_nomination_bond: Option<D::Bond> = None;
    let mut finality_margin_blocks: Option<u64> = None;
    let mut evidence_horizon_blocks: Option<u64> = None;
    let mut activation_lag_blocks: Option<u64> = None;
    let mut slashing_delay_blocks: Option<u64> = None;
    let mut epoch_length_blocks: Option<NonZeroU64> = None;
    if !parser.try_consume_char(b'}')? {
        loop {
            parser.skip_ws();
            let key = destination.parse_key(parser)?;
            let text = match &key {
                json::KeyRef::Borrowed(value) => *value,
                json::KeyRef::Owned(value) => value.as_ref(),
            };
            match text {
                "xor_asset_definition_id" => {
                    if xor_asset_definition_id.is_some() {
                        return Err(json::Error::duplicate_field("xor_asset_definition_id").into());
                    }
                    let text = destination.parse_text(parser)?;
                    let value = AssetDefinitionId::parse_json_address_text(text.as_ref())?;
                    xor_asset_definition_id = Some(value);
                }
                "epoch_seed" => {
                    if epoch_seed.is_some() {
                        return Err(json::Error::duplicate_field("epoch_seed").into());
                    }
                    let text = destination.parse_text(parser)?;
                    let value =
                        <[u8; 32] as json::JsonObjectKeyOwned>::from_json_key_text(text.as_ref())?;
                    epoch_seed = Some(value);
                }
                "max_validators" => {
                    if max_validators.is_some() {
                        return Err(json::Error::duplicate_field("max_validators").into());
                    }
                    let value = <u32 as JsonDeserialize>::json_deserialize(parser)?;
                    max_validators = Some(value);
                }
                "min_self_bond" => {
                    if min_self_bond.is_some() {
                        return Err(json::Error::duplicate_field("min_self_bond").into());
                    }
                    let value = destination.parse_bond(parser)?;
                    min_self_bond = Some(value);
                }
                "min_nomination_bond" => {
                    if min_nomination_bond.is_some() {
                        return Err(json::Error::duplicate_field("min_nomination_bond").into());
                    }
                    let value = destination.parse_bond(parser)?;
                    min_nomination_bond = Some(value);
                }
                "finality_margin_blocks" => {
                    if finality_margin_blocks.is_some() {
                        return Err(json::Error::duplicate_field("finality_margin_blocks").into());
                    }
                    let value = <u64 as JsonDeserialize>::json_deserialize(parser)?;
                    finality_margin_blocks = Some(value);
                }
                "evidence_horizon_blocks" => {
                    if evidence_horizon_blocks.is_some() {
                        return Err(json::Error::duplicate_field("evidence_horizon_blocks").into());
                    }
                    let value = <u64 as JsonDeserialize>::json_deserialize(parser)?;
                    evidence_horizon_blocks = Some(value);
                }
                "activation_lag_blocks" => {
                    if activation_lag_blocks.is_some() {
                        return Err(json::Error::duplicate_field("activation_lag_blocks").into());
                    }
                    let value = <u64 as JsonDeserialize>::json_deserialize(parser)?;
                    activation_lag_blocks = Some(value);
                }
                "slashing_delay_blocks" => {
                    if slashing_delay_blocks.is_some() {
                        return Err(json::Error::duplicate_field("slashing_delay_blocks").into());
                    }
                    let value = <u64 as JsonDeserialize>::json_deserialize(parser)?;
                    slashing_delay_blocks = Some(value);
                }
                "epoch_length_blocks" => {
                    if epoch_length_blocks.is_some() {
                        return Err(json::Error::duplicate_field("epoch_length_blocks").into());
                    }
                    let value = <NonZeroU64 as JsonDeserialize>::json_deserialize(parser)?;
                    epoch_length_blocks = Some(value);
                }
                _ => return Err(json::Error::unknown_field(text).into()),
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    destination.finish(
        record,
        RecordFields {
            xor_asset_definition_id: xor_asset_definition_id
                .ok_or_else(|| json::Error::missing_field("xor_asset_definition_id"))?,
            epoch_seed: epoch_seed.ok_or_else(|| json::Error::missing_field("epoch_seed"))?,
            max_validators: max_validators
                .ok_or_else(|| json::Error::missing_field("max_validators"))?,
            min_self_bond: min_self_bond
                .ok_or_else(|| json::Error::missing_field("min_self_bond"))?,
            min_nomination_bond: min_nomination_bond
                .ok_or_else(|| json::Error::missing_field("min_nomination_bond"))?,
            finality_margin_blocks: finality_margin_blocks
                .ok_or_else(|| json::Error::missing_field("finality_margin_blocks"))?,
            evidence_horizon_blocks: evidence_horizon_blocks
                .ok_or_else(|| json::Error::missing_field("evidence_horizon_blocks"))?,
            activation_lag_blocks: activation_lag_blocks
                .ok_or_else(|| json::Error::missing_field("activation_lag_blocks"))?,
            slashing_delay_blocks: slashing_delay_blocks
                .ok_or_else(|| json::Error::missing_field("slashing_delay_blocks"))?,
            epoch_length_blocks: epoch_length_blocks
                .ok_or_else(|| json::Error::missing_field("epoch_length_blocks"))?,
        },
    )
}

#[cfg(test)]
mod tests;
