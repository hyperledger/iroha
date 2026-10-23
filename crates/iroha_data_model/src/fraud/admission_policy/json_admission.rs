//! Shared ordinary/admitted field kernels for the entire fraud policy graph.

use std::fmt;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_crypto::{
    ChargedPublicKey, PreparedPublicKeyDecode, PublicKey, PublicKeyJsonAdmissionError,
};
use norito::json::{self, JsonDeserialize};

use super::{FraudAdmissionAttesterV1, FraudAdmissionPolicyV1, FraudRiskBandV1};

/// Original JSON/key cause or exact original-pool destination refusal.
#[derive(Debug, thiserror::Error)]
pub enum FraudPolicyJsonAdmissionError {
    /// Original JSON syntax and scoped resource identity.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Original typed public-key scalar/decoder cause.
    #[error(transparent)]
    Codec(#[from] norito::Error),
    /// Exact original finite-pool or physical allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}
impl From<PublicKeyJsonAdmissionError> for FraudPolicyJsonAdmissionError {
    fn from(error: PublicKeyJsonAdmissionError) -> Self {
        match error {
            PublicKeyJsonAdmissionError::Json(error) => Self::Json(error),
            PublicKeyJsonAdmissionError::Codec(error) => Self::Codec(error),
            PublicKeyJsonAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}

/// Exact typed fraud-policy graph with its original array, string and key custody.
///
/// The immutable value drops before every original charge, then the ledger
/// destroys its own backing before refund. No Clone or safe extraction can detach
/// this ownership. Like ordinary JSON decoding, this preserves typed structure;
/// the caller must still run policy validation and establish source authority.
/// Enclosing owner/source/diagnostic and crypto scratch custody remain separate.
pub struct AdmittedFraudAdmissionPolicy {
    value: FraudAdmissionPolicyV1,
    charges: ChargedBuffer<AllocationCharge>,
}
impl AdmittedFraudAdmissionPolicy {
    /// Construct the protocol's allocation-free empty projection in this pool.
    /// This is only the documented default for an absent optional policy, never
    /// a substitute for an explicit malformed parameter or monetary authority.
    ///
    /// # Errors
    /// Preserves the original custody refusal; no input decoding is performed.
    pub fn try_protocol_default(
        budget: &AllocationBudget,
    ) -> Result<Self, FraudPolicyJsonAdmissionError> {
        let charges = ChargedBuffer::new(0, budget)?;
        Ok(Self {
            value: FraudAdmissionPolicyV1::protocol_default(),
            charges,
        })
    }

    /// Decode directly using the caller's parser, finite pool and decoder context.
    ///
    /// # Errors
    /// Preserves the original JSON/key/resource refusal; partial leaves retire.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, FraudPolicyJsonAdmissionError> {
        decode_policy(parser, &mut AdmittedDestination { budget })
    }
    /// Borrow the exact typed policy without separating original custody.
    #[must_use]
    pub fn get(&self) -> &FraudAdmissionPolicyV1 {
        &self.value
    }
    /// Require the same original pool for the ledger and every retained leaf.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.charges.belongs_to(budget)
            && self
                .charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    /// Number of original payload allocation charges, excluding ledger backing.
    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.charges.as_slice().len()
    }
    /// Move the exact immutable graph and original charged ledger into a larger owner.
    ///
    /// # Safety
    /// Keep every original allocation immutable and alive until it is destroyed
    /// before its original charge. Do not clone, grow or export any backing while
    /// leaving custody behind. The recipient must fund its own enclosing storage.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(
        self,
    ) -> (FraudAdmissionPolicyV1, ChargedBuffer<AllocationCharge>) {
        (self.value, self.charges)
    }
}
impl fmt::Debug for AdmittedFraudAdmissionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AdmittedFraudAdmissionPolicy")
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
        core::str::from_utf8(self.0.as_slice()).expect("sole JSON string kernel emits UTF-8")
    }
}
fn admit_text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<AdmittedText, FraudPolicyJsonAdmissionError> {
    let mut text = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        text.push_reserved(0);
    }
    Ok(AdmittedText(text))
}
struct AdmittedAttester {
    value: FraudAdmissionAttesterV1,
    charges: [AllocationCharge; 2],
}
struct AdmittedList {
    values: ChargedBuffer<FraudAdmissionAttesterV1>,
    charges: ChargedBuffer<AllocationCharge>,
}
impl AdmittedList {
    fn new(
        entries: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, FraudPolicyJsonAdmissionError> {
        let bytes = entries
            .checked_mul(core::mem::size_of::<FraudAdmissionAttesterV1>())
            .ok_or(json::Error::DecodeResourceLimit)?;
        norito::core::reserve_decode_allocation(bytes)
            .map_err(json::Error::from_decode_resource)?;
        let count = entries
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(iroha_allocation::AllocationRefusal::DemandOverflow)
            .map_err(ChargedBufferError::Admission)?;
        // Ledger precedes values, so partial construction drops the values first.
        let charges = ChargedBuffer::new(count, budget)?;
        let values = ChargedBuffer::new(entries, budget)?;
        Ok(Self { values, charges })
    }
    fn push(&mut self, attester: AdmittedAttester) {
        let AdmittedAttester { value, charges } = attester;
        self.values.push_reserved(value);
        for charge in charges {
            self.charges.push_reserved(charge);
        }
    }
}
trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Key;
    type Attester;
    type List;
    type Output;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error>;
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error>;
    fn parse_public_key(&mut self, parser: &mut json::Parser<'_>)
    -> Result<Self::Key, Self::Error>;
    fn parse_list(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::List, Self::Error>;
    fn finish_attester(&mut self, engine: Self::Text, key: Self::Key) -> Self::Attester;
    fn finish_policy(&mut self, fields: PolicyFields<Self::List>) -> Self::Output;
}
struct OrdinaryDestination;
impl Destination for OrdinaryDestination {
    type Error = json::Error;
    type Text = String;
    type Key = PublicKey;
    type Attester = FraudAdmissionAttesterV1;
    type List = Vec<FraudAdmissionAttesterV1>;
    type Output = FraudAdmissionPolicyV1;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a>, Self::Error> {
        parser.parse_key()
    }
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<String, Self::Error> {
        parser.parse_string()
    }
    fn parse_public_key(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Self::Key, Self::Error> {
        PublicKey::json_deserialize(parser)
    }
    fn parse_list(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::List, Self::Error> {
        Vec::<FraudAdmissionAttesterV1>::json_deserialize(parser)
    }
    fn finish_attester(&mut self, engine_id: String, public_key: PublicKey) -> Self::Attester {
        FraudAdmissionAttesterV1 {
            engine_id,
            public_key,
        }
    }
    fn finish_policy(&mut self, fields: PolicyFields<Self::List>) -> Self::Output {
        fields.into_value(|values| values)
    }
}
struct AdmittedDestination<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for AdmittedDestination<'_> {
    type Error = FraudPolicyJsonAdmissionError;
    type Text = AdmittedText;
    type Key = ChargedPublicKey;
    type Attester = AdmittedAttester;
    type List = AdmittedList;
    type Output = AdmittedFraudAdmissionPolicy;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error> {
        parser.parse_key_with_buffer(|length| admit_text(length, self.budget))
    }
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error> {
        parser.parse_string_with_buffer(|length| admit_text(length, self.budget))
    }
    fn parse_public_key(
        &mut self,
        parser: &mut json::Parser<'_>,
    ) -> Result<Self::Key, Self::Error> {
        Ok(PreparedPublicKeyDecode::try_from_json(parser, self.budget)?)
    }
    fn parse_list(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::List, Self::Error> {
        let budget = self.budget;
        parser.parse_array_with(
            |entries| AdmittedList::new(entries, budget),
            |parser| decode_attester(parser, &mut AdmittedDestination { budget }),
            AdmittedList::push,
        )
    }
    #[allow(unsafe_code)]
    fn finish_attester(&mut self, engine: Self::Text, key: Self::Key) -> Self::Attester {
        // SAFETY: exact string/key allocations move once into the private value;
        // both original charges follow and drop only after that value is freed.
        let (engine, engine_charge) = unsafe { engine.0.into_allocation_parts() };
        let engine_id = unsafe { String::from_utf8_unchecked(engine) };
        let (public_key, key_charge) = unsafe { key.into_allocation_parts() };
        AdmittedAttester {
            value: FraudAdmissionAttesterV1 {
                engine_id,
                public_key,
            },
            charges: [engine_charge, key_charge],
        }
    }
    #[allow(unsafe_code)]
    fn finish_policy(&mut self, fields: PolicyFields<Self::List>) -> Self::Output {
        let mut retained_charges = None;
        let value = fields.into_value(|list| {
            let AdmittedList {
                values,
                mut charges,
            } = list;
            // SAFETY: this fixed array and every nested leaf are moved unchanged
            // into the final owner. Its complete ledger is already admitted.
            let (values, charge) = unsafe { values.into_allocation_parts() };
            charges.push_reserved(charge);
            retained_charges = Some(charges);
            values
        });
        AdmittedFraudAdmissionPolicy {
            value,
            charges: retained_charges.expect("one exact attester list transferred"),
        }
    }
}
struct PolicyFields<L> {
    version: u8,
    enabled: bool,
    required_minimum_band: Option<FraudRiskBandV1>,
    missing_assessment_permitted: bool,
    attesters: L,
}
impl<L> PolicyFields<L> {
    fn into_value(
        self,
        move_list: impl FnOnce(L) -> Vec<FraudAdmissionAttesterV1>,
    ) -> FraudAdmissionPolicyV1 {
        FraudAdmissionPolicyV1 {
            version: self.version,
            enabled: self.enabled,
            required_minimum_band: self.required_minimum_band,
            missing_assessment_permitted: self.missing_assessment_permitted,
            attesters: move_list(self.attesters),
        }
    }
}
fn key_text<'a, T: AsRef<str>>(key: &'a json::KeyRef<'_, T>) -> &'a str {
    match key {
        json::KeyRef::Borrowed(text) => text,
        json::KeyRef::Owned(text) => text.as_ref(),
    }
}
pub(super) fn decode_ordinary_policy(
    parser: &mut json::Parser<'_>,
) -> Result<FraudAdmissionPolicyV1, json::Error> {
    decode_policy(parser, &mut OrdinaryDestination)
}
pub(super) fn decode_ordinary_attester(
    parser: &mut json::Parser<'_>,
) -> Result<FraudAdmissionAttesterV1, json::Error> {
    decode_attester(parser, &mut OrdinaryDestination)
}
pub(super) fn decode_ordinary_band(
    parser: &mut json::Parser<'_>,
) -> Result<FraudRiskBandV1, json::Error> {
    decode_band(parser, &mut OrdinaryDestination)
}

// This unit-enum envelope preserves the former derive exactly, including a
// required null content field, ignored unknown envelope fields and tag validation
// after all envelope fields. The second parser borrows the exact source slice;
// it never replaces the active cumulative decoder context or observer.
fn decode_band<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<FraudRiskBandV1, D::Error> {
    parser.skip_ws();
    parser.preflight_object_entries()?;
    parser.expect(b'{')?;
    parser.skip_ws();
    let mut tag = None;
    let mut raw = None;
    if !parser.try_consume_char(b'}')? {
        loop {
            parser.skip_ws();
            let key = destination.parse_key(parser)?;
            match key_text(&key) {
                "band" => {
                    if tag.is_some() {
                        return Err(json::Error::duplicate_field("band").into());
                    }
                    tag = Some(destination.parse_text(parser)?);
                }
                "value" => {
                    if raw.is_some() {
                        return Err(json::Error::duplicate_field("value").into());
                    }
                    raw = Some(parser.raw_value_slice()?);
                }
                _ => parser.skip_value_lexical()?,
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    let tag = tag.ok_or_else(|| json::Error::Message("missing `band` field".into()))?;
    let raw = raw.ok_or_else(|| json::Error::missing_field("value"))?;
    let band = tag
        .as_ref()
        .parse::<FraudRiskBandV1>()
        .map_err(|_| json::Error::Message("unknown JSON enum variant".into()))?;
    let mut content = json::Parser::new(raw);
    content.parse_null()?;
    content.skip_ws();
    if !content.eof() {
        return Err(json::Error::Message(format!(
            "unexpected content for unit variant `{}`",
            tag.as_ref()
        ))
        .into());
    }
    Ok(band)
}
fn decode_attester<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<D::Attester, D::Error> {
    parser.skip_ws();
    parser.preflight_object_entries()?;
    parser.expect(b'{')?;
    parser.skip_ws();
    let mut engine = None;
    let mut key = None;
    if !parser.try_consume_char(b'}')? {
        loop {
            parser.skip_ws();
            let field = destination.parse_key(parser)?;
            match key_text(&field) {
                "engine_id" => {
                    if engine.is_some() {
                        return Err(json::Error::duplicate_field("engine_id").into());
                    }
                    engine = Some(destination.parse_text(parser)?);
                }
                "public_key" => {
                    if key.is_some() {
                        return Err(json::Error::duplicate_field("public_key").into());
                    }
                    key = Some(destination.parse_public_key(parser)?);
                }
                text => return Err(json::Error::unknown_field(text).into()),
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    Ok(destination.finish_attester(
        engine.ok_or_else(|| json::Error::missing_field("engine_id"))?,
        key.ok_or_else(|| json::Error::missing_field("public_key"))?,
    ))
}
fn decode_policy<D: Destination>(
    parser: &mut json::Parser<'_>,
    destination: &mut D,
) -> Result<D::Output, D::Error> {
    parser.skip_ws();
    parser.preflight_object_entries()?;
    parser.expect(b'{')?;
    parser.skip_ws();
    let mut version = None;
    let mut enabled = None;
    let mut minimum = None;
    let mut permitted = None;
    let mut attesters = None;
    if !parser.try_consume_char(b'}')? {
        loop {
            parser.skip_ws();
            let field = destination.parse_key(parser)?;
            match key_text(&field) {
                "version" => {
                    if version.is_some() {
                        return Err(json::Error::duplicate_field("version").into());
                    }
                    version = Some(u8::json_deserialize(parser)?);
                }
                "enabled" => {
                    if enabled.is_some() {
                        return Err(json::Error::duplicate_field("enabled").into());
                    }
                    enabled = Some(bool::json_deserialize(parser)?);
                }
                "required_minimum_band" => {
                    if minimum.is_some() {
                        return Err(json::Error::duplicate_field("required_minimum_band").into());
                    }
                    minimum = Some(if parser.try_consume_null()? {
                        None
                    } else {
                        Some(decode_band(parser, destination)?)
                    });
                }
                "missing_assessment_permitted" => {
                    if permitted.is_some() {
                        return Err(
                            json::Error::duplicate_field("missing_assessment_permitted").into()
                        );
                    }
                    permitted = Some(bool::json_deserialize(parser)?);
                }
                "attesters" => {
                    if attesters.is_some() {
                        return Err(json::Error::duplicate_field("attesters").into());
                    }
                    attesters = Some(destination.parse_list(parser)?);
                }
                text => return Err(json::Error::unknown_field(text).into()),
            }
            parser.skip_ws();
            if parser.try_consume_char(b',')? {
                continue;
            }
            parser.expect(b'}')?;
            break;
        }
    }
    Ok(destination.finish_policy(PolicyFields {
        version: version.ok_or_else(|| json::Error::missing_field("version"))?,
        enabled: enabled.ok_or_else(|| json::Error::missing_field("enabled"))?,
        required_minimum_band: minimum.unwrap_or(None),
        missing_assessment_permitted: permitted
            .ok_or_else(|| json::Error::missing_field("missing_assessment_permitted"))?,
        attesters: attesters.ok_or_else(|| json::Error::missing_field("attesters"))?,
    }))
}

#[cfg(test)]
mod tests;
