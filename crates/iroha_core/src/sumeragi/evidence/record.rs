//! Original immutable proof/offender custody with independently copied penalty metadata.
//!
//! Canonical snapshot input is a claim, never authentication. Restore constructs every
//! retained graph allocation from the caller's original pool before copying it; the existing
//! native-history restoration verifier still supplies authority. Current/undo/COW clones share
//! only the immutable body. TODO(S8): enclosing MV/JSON source maps, diagnostic projections,
//! native proof-decoder/canonical-pair scratch and general retry-resume remain separate owners.

use std::{fmt, mem::ManuallyDrop, ops::Deref};

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedShared};
use iroha_data_model::block::consensus::{
    Evidence, EvidenceAttribution, EvidencePenaltyStatus, EvidenceRecord,
};
use norito::{
    core::{Encoder, SerializePayload},
    json::{self, JsonDeserialize, JsonSerialize, MapVisitor, Parser, SeqVisitor},
};

use crate::{
    state::EvidencePreparationError, sumeragi::evidence_history::FundedEvidenceAttribution,
};

/// Canonical immutable fields, exposed only through an original charged body borrow.
#[derive(Debug, PartialEq, Eq)]
pub struct EvidenceRecordBodyFields {
    /// Original canonical proof bytes; a borrowed clone is a separate diagnostic graph.
    pub evidence: Evidence,
    /// Canonical offender attribution; runtime authentication remains independent.
    pub attribution: EvidenceAttribution,
}

/// Snapshot syntax and exact local funding refusal remain distinct at the State owner.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceRecordRestoreError {
    /// Original canonical JSON, key or native-proof failure.
    #[error(transparent)]
    Json(json::Error),
    /// Exact active logical decode-resource origin; no diagnostic string replaces it.
    #[error("snapshot evidence decode-resource refusal: {0}")]
    Logical(#[source] json::Error),
    /// Exact original pool, allocator or logical decoder refusal.
    #[error(transparent)]
    Preparation(#[from] EvidencePreparationError),
}
impl From<json::Error> for EvidenceRecordRestoreError {
    fn from(error: json::Error) -> Self {
        if error.is_decode_resource_limit() {
            Self::Logical(error)
        } else {
            Self::Json(error)
        }
    }
}
impl From<iroha_allocation::ChargedBufferError> for EvidenceRecordRestoreError {
    fn from(error: iroha_allocation::ChargedBufferError) -> Self {
        EvidencePreparationError::from(error).into()
    }
}
impl From<iroha_crypto::PublicKeyJsonAdmissionError> for EvidenceRecordRestoreError {
    fn from(error: iroha_crypto::PublicKeyJsonAdmissionError) -> Self {
        match error {
            iroha_crypto::PublicKeyJsonAdmissionError::Json(error) => error.into(),
            iroha_crypto::PublicKeyJsonAdmissionError::Codec(error) => {
                if error.is_decode_resource_limit() {
                    Self::Logical(json::Error::from_decode_resource(error))
                } else {
                    Self::Json(json::Error::InvalidField {
                        field: "peer_id".into(),
                        message: "invalid public key".into(),
                    })
                }
            }
            iroha_crypto::PublicKeyJsonAdmissionError::Allocation(error) => error.into(),
        }
    }
}

// The proof charge remains outside the offender ledger because actual admission captures
// proof bytes in the preparation pool and offender keys in the execution pool. Their distinct
// original namespaces are preserved; no foreign ledger is silently relabeled.
pub(in crate::sumeragi) struct EvidenceRecordBody {
    fields: ManuallyDrop<iroha_allocation::RetainedPayload<EvidenceRecordBodyFields>>,
    proof_charge: ManuallyDrop<AllocationCharge>,
    // Test-only mutation owns the same finite original pool; it never creates a namespace.
    #[cfg(test)]
    budget: AllocationBudget,
}
impl EvidenceRecordBody {
    pub(in crate::sumeragi) fn reserve(
        budget: &AllocationBudget,
    ) -> Result<iroha_allocation::ReservedChargedShared<Self>, EvidencePreparationError> {
        let layout = ChargedShared::<Self>::allocation_layout();
        let charge = budget
            .try_reserve(layout)
            .map_err(EvidencePreparationError::Admission)?
            .try_split(layout)
            .map_err(|_| EvidencePreparationError::Invariant)?;
        ChargedShared::reserve_from_charge(charge).map_err(|(charge, error)| {
            drop(charge);
            match error {
                iroha_allocation::SharedFromChargeError::Allocator { layout } => {
                    EvidencePreparationError::Allocator {
                        requested_bytes: layout.size(),
                    }
                }
                iroha_allocation::SharedFromChargeError::LayoutMismatch { .. } => {
                    EvidencePreparationError::Invariant
                }
            }
        })
    }
    #[allow(unsafe_code)]
    pub(in crate::sumeragi) fn initialize(
        shell: iroha_allocation::ReservedChargedShared<Self>,
        frame: ChargedBuffer<u8>,
        attribution: FundedEvidenceAttribution,
        budget: &AllocationBudget,
    ) -> ChargedShared<Self> {
        debug_assert!(shell.belongs_to(budget));
        // No fallible work follows either raw move. The immutable fields and both original
        // charge owners enter this one shell; exact Vec capacities are never changed.
        let (native, proof_charge) = unsafe { frame.into_allocation_parts() };
        let proof_charge = ManuallyDrop::new(proof_charge);
        let fields = attribution.into_record_fields(Evidence { native });
        shell.initialize(Self {
            fields: ManuallyDrop::new(fields),
            proof_charge,
            #[cfg(test)]
            budget: budget.clone(),
        })
    }
    pub(in crate::sumeragi) fn canonical(&self) -> &EvidenceRecordBodyFields {
        self.fields.get()
    }
    pub(in crate::sumeragi) fn attribution_belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.fields.belongs_to(budget)
    }
    #[cfg(test)]
    // Execution namespace only: offender vector/key ledger plus this shared shell.
    // The proof charge is excluded even when snapshot restore uses the same pool.
    pub(in crate::sumeragi) fn execution_allocation_bytes(&self) -> Option<usize> {
        self.fields
            .allocation_bytes()?
            .checked_add(ChargedShared::<Self>::allocation_layout().size())
    }
    pub(in crate::sumeragi) fn proof_belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.proof_charge.belongs_to(budget)
    }
}
impl Drop for EvidenceRecordBody {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // If any payload destructor unwinds, neither nested offender ledger nor proof
        // charge is falsely released. A normal return establishes physical retirement.
        unsafe {
            ManuallyDrop::drop(&mut self.fields);
        }
        unsafe {
            ManuallyDrop::drop(&mut self.proof_charge);
        }
    }
}

/// World evidence value sharing original immutable graphs while copying lifecycle scalars.
///
/// There is no budgetless Deserialize/JsonDeserialize or mutable-body escape. Restored
/// claims enter through the explicit original-pool parser and are reauthenticated by the
/// existing native-history verifier before State use. Encoding retains the canonical DTO.
pub struct RetainedEvidenceRecord {
    body: ChargedShared<EvidenceRecordBody>,
    /// Original carrier height.
    pub recorded_at_height: u64,
    /// Original carrier view.
    pub recorded_at_view: u64,
    /// Original carrier timestamp.
    pub recorded_at_ms: u64,
    /// Independently copied pending/applied metadata; this never mutates an undo body.
    pub penalty_status: EvidencePenaltyStatus,
}
impl RetainedEvidenceRecord {
    pub(in crate::sumeragi) fn from_body(
        body: ChargedShared<EvidenceRecordBody>,
        height: u64,
        view: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            body,
            recorded_at_height: height,
            recorded_at_view: view,
            recorded_at_ms: timestamp,
            penalty_status: EvidencePenaltyStatus::Pending,
        }
    }
    /// Produce an independent canonical audit/wire DTO. This copy does not inherit funding
    /// from the immutable World owner; its enclosing diagnostic output owner remains open.
    pub fn canonical_projection(&self) -> EvidenceRecord {
        EvidenceRecord {
            evidence: self.evidence.clone(),
            attribution: self.attribution.clone(),
            recorded_at_height: self.recorded_at_height,
            recorded_at_view: self.recorded_at_view,
            recorded_at_ms: self.recorded_at_ms,
            penalty_status: self.penalty_status,
        }
    }
    /// Fund an explicitly synthetic test claim; no native authority is manufactured.
    /// Existing malformed-record tests intentionally require invalid proof/attribution claims.
    ///
    /// # Errors
    /// Returns the exact original-pool refusal or canonical attribution parsing failure.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn from_fixture(
        record: EvidenceRecord,
        budget: &AllocationBudget,
    ) -> Result<Self, EvidenceRecordRestoreError> {
        let mut frame = ChargedBuffer::new(record.evidence.native_frame().len(), budget)?;
        frame
            .append(record.evidence.native_frame())
            .map_err(|_| EvidencePreparationError::Invariant)?;
        let text = json::to_json(&record.attribution)?;
        let mut parser = Parser::new(&text);
        let attribution = super::super::evidence_history::restore_attribution(&mut parser, budget)?;
        parser.skip_ws();
        if !parser.eof() {
            return Err(json::Error::Message("trailing characters".into()).into());
        }
        let shell = EvidenceRecordBody::reserve(budget)?;
        let body = EvidenceRecordBody::initialize(shell, frame, attribution, budget);
        let mut retained = Self::from_body(
            body,
            record.recorded_at_height,
            record.recorded_at_view,
            record.recorded_at_ms,
        );
        retained.penalty_status = record.penalty_status;
        Ok(retained)
    }
    fn view(&self) -> RecordView<'_> {
        RecordView {
            evidence: norito::core::PayloadRef(&self.evidence),
            attribution: norito::core::PayloadRef(&self.attribution),
            recorded_at_height: self.recorded_at_height,
            recorded_at_view: self.recorded_at_view,
            recorded_at_ms: self.recorded_at_ms,
            penalty_status: self.penalty_status,
        }
    }
    #[cfg(test)]
    pub(crate) fn shares_body(&self, other: &Self) -> bool {
        ChargedShared::ptr_eq(&self.body, &other.body)
    }
    #[cfg(test)]
    pub(crate) fn body_belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.body.budget.same_pool(budget)
            && self.body.belongs_to(budget)
            && self.body.attribution_belongs_to(budget)
    }
    #[cfg(test)]
    pub(crate) fn proof_belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.body.proof_belongs_to(budget)
    }
    // Actual bytes in the requested original namespace. A same-pool restored record
    // includes its proof exactly once; live admission normally uses a separate pool.
    #[cfg(test)]
    pub(crate) fn allocation_bytes_in(&self, budget: &AllocationBudget) -> Option<usize> {
        let mut bytes = if self.body_belongs_to(budget) {
            self.body.execution_allocation_bytes()?
        } else {
            0
        };
        if self.proof_belongs_to(budget) {
            bytes = bytes.checked_add(self.body.proof_charge.layout().size())?;
        }
        Some(bytes)
    }
}
impl Clone for RetainedEvidenceRecord {
    fn clone(&self) -> Self {
        #[cfg(all(test, sumeragi_core_mutation = "HC181"))]
        {
            // Deliberately restore the old COW recopy bug under the actual original
            // finite pool. Canonical values stay equal; physical original custody does not.
            Self::from_fixture(self.canonical_projection(), &self.body.budget)
                .expect("the named original record control admits its finite fixture")
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC181")))]
        {
            Self {
                body: self.body.clone(),
                recorded_at_height: self.recorded_at_height,
                recorded_at_view: self.recorded_at_view,
                recorded_at_ms: self.recorded_at_ms,
                penalty_status: self.penalty_status,
            }
        }
    }
}
impl Deref for RetainedEvidenceRecord {
    type Target = EvidenceRecordBodyFields;
    fn deref(&self) -> &Self::Target {
        self.body.canonical()
    }
}
impl fmt::Debug for RetainedEvidenceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedEvidenceRecord")
            .field("evidence", &self.evidence)
            .field("attribution", &self.attribution)
            .field("recorded_at_height", &self.recorded_at_height)
            .field("recorded_at_view", &self.recorded_at_view)
            .field("recorded_at_ms", &self.recorded_at_ms)
            .field("penalty_status", &self.penalty_status)
            .finish()
    }
}
impl PartialEq for RetainedEvidenceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.body.canonical() == other.body.canonical()
            && self.recorded_at_height == other.recorded_at_height
            && self.recorded_at_view == other.recorded_at_view
            && self.recorded_at_ms == other.recorded_at_ms
            && self.penalty_status == other.penalty_status
    }
}
impl Eq for RetainedEvidenceRecord {}
impl norito::NoritoSchema for RetainedEvidenceRecord {
    fn nominal_name() -> String {
        <EvidenceRecord as norito::NoritoSchema>::nominal_name()
    }
    fn static_nominal_name() -> Option<&'static str> {
        <EvidenceRecord as norito::NoritoSchema>::static_nominal_name()
    }
    fn frame_name() -> String {
        <EvidenceRecord as norito::NoritoSchema>::frame_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        <EvidenceRecord as norito::NoritoSchema>::static_frame_name()
    }
}
#[derive(norito::SerializePayload, norito::json::JsonSerialize)]
struct RecordView<'a> {
    evidence: norito::core::PayloadRef<'a, Evidence>,
    attribution: norito::core::PayloadRef<'a, EvidenceAttribution>,
    recorded_at_height: u64,
    recorded_at_view: u64,
    recorded_at_ms: u64,
    penalty_status: EvidencePenaltyStatus,
}
impl SerializePayload for RetainedEvidenceRecord {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), norito::Error> {
        self.view().serialize(writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        self.view().encoded_len_hint()
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        self.view().encoded_len_exact()
    }
}
impl JsonSerialize for RetainedEvidenceRecord {
    fn json_serialize(&self, out: &mut String) {
        self.view().json_serialize(out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        self.view().json_serialize_to(out)
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, EvidenceRecordRestoreError> {
    value.ok_or_else(|| json::Error::missing_field(field).into())
}
fn duplicate(field: &str) -> EvidenceRecordRestoreError {
    json::Error::duplicate_field(field).into()
}

fn parse_proof(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<u8>, EvidenceRecordRestoreError> {
    let mut object = MapVisitor::new(parser)?;
    let mut native = None;
    while let Some(key) = object.next_key()? {
        match key.as_str() {
            "native" => {
                if native.is_some() {
                    return Err(duplicate("native"));
                }
                native = Some(object.parse_value_with_parser_typed(|parser| {
                    let mut values = SeqVisitor::new(parser)?;
                    let count = values.total_entries();
                    norito::core::reserve_decode_allocation(count)
                        .map_err(json::Error::from_decode_resource)?;
                    let mut bytes = ChargedBuffer::new(count, budget)?;
                    while let Some(byte) = values.next_element_with_parser_typed(|parser| {
                        Ok::<_, EvidenceRecordRestoreError>(u8::json_deserialize(parser)?)
                    })? {
                        bytes.push_reserved(byte);
                    }
                    values.finish()?;
                    Ok::<_, EvidenceRecordRestoreError>(bytes)
                })?);
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    object.finish()?;
    required(native, "native")
}

/// Parse one original canonical record claim, funding every retained field before its copy.
/// Each proof or attribution field is validated when encountered, in the same JSON field
/// order as the canonical DTO. The immutable claim grants no execution authority; history
/// restoration remains mandatory.
pub(crate) fn parse_record(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<RetainedEvidenceRecord, EvidenceRecordRestoreError> {
    let mut map = MapVisitor::new(parser)?;
    let mut proof = None;
    let mut attribution = None;
    let mut height = None;
    let mut view = None;
    let mut timestamp = None;
    let mut status = None;
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "evidence" => {
                if proof.is_some() {
                    return Err(duplicate("evidence"));
                }
                let bytes =
                    map.parse_value_with_parser_typed(|parser| parse_proof(parser, budget))?;
                // Borrow the exact paid bytes for the existing native validator. It accepts
                // no body/schema fallback. Its decoded scratch remains an explicit TODO.
                Evidence::decode_native_frame(bytes.as_slice()).map_err(|error| match error {
                    iroha_sumeragi::message::CodecError::Resource(error) => {
                        EvidenceRecordRestoreError::Preparation(
                            EvidencePreparationError::DecodeResource(error),
                        )
                    }
                    other => {
                        EvidenceRecordRestoreError::Json(json::Error::Message(other.to_string()))
                    }
                })?;
                proof = Some(bytes);
            }
            "attribution" => {
                if attribution.is_some() {
                    return Err(duplicate("attribution"));
                }
                attribution = Some(map.parse_value_with_parser_typed(|parser| {
                    super::super::evidence_history::restore_attribution(parser, budget)
                })?);
            }
            "recorded_at_height" => {
                if height.is_some() {
                    return Err(duplicate("recorded_at_height"));
                }
                height = Some(map.parse_value::<u64>()?);
            }
            "recorded_at_view" => {
                if view.is_some() {
                    return Err(duplicate("recorded_at_view"));
                }
                view = Some(map.parse_value::<u64>()?);
            }
            "recorded_at_ms" => {
                if timestamp.is_some() {
                    return Err(duplicate("recorded_at_ms"));
                }
                timestamp = Some(map.parse_value::<u64>()?);
            }
            "penalty_status" => {
                if status.is_some() {
                    return Err(duplicate("penalty_status"));
                }
                status = Some(map.parse_value::<EvidencePenaltyStatus>()?);
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    map.finish()?;
    // Preserve canonical derived missing-field order before any shared-shell admission.
    let proof = required(proof, "evidence")?;
    let attribution = required(attribution, "attribution")?;
    let height = required(height, "recorded_at_height")?;
    let view = required(view, "recorded_at_view")?;
    let timestamp = required(timestamp, "recorded_at_ms")?;
    let status = required(status, "penalty_status")?;
    let shell = EvidenceRecordBody::reserve(budget)?;
    let body = EvidenceRecordBody::initialize(shell, proof, attribution, budget);
    let mut record = RetainedEvidenceRecord::from_body(body, height, view, timestamp);
    record.penalty_status = status;
    Ok(record)
}

fn parse_values(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<
    std::collections::BTreeMap<iroha_crypto::Hash, RetainedEvidenceRecord>,
    EvidenceRecordRestoreError,
> {
    use norito::json::JsonKeyCodec;
    let mut map = MapVisitor::new(parser)?;
    let mut rows = std::collections::BTreeMap::new();
    while let Some(key) = map.next_key()? {
        let parsed = iroha_crypto::Hash::decode_json_key(key.as_str())?;
        let value = map.parse_value_with_parser_typed(|parser| parse_record(parser, budget))?;
        if rows.insert(parsed, value).is_some() {
            return Err(json::Error::duplicate_field(key.as_str()).into());
        }
    }
    map.finish()?;
    Ok(rows)
}
fn parse_undo(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<
    std::collections::BTreeMap<iroha_crypto::Hash, Option<RetainedEvidenceRecord>>,
    EvidenceRecordRestoreError,
> {
    use norito::json::JsonKeyCodec;
    let mut map = MapVisitor::new(parser)?;
    let mut rows = std::collections::BTreeMap::new();
    while let Some(key) = map.next_key()? {
        let parsed = iroha_crypto::Hash::decode_json_key(key.as_str())?;
        let value = map.parse_value_with_parser_typed(|parser| {
            if parser.try_consume_null()? {
                return Ok(None);
            }
            let mut present = MapVisitor::new(parser)?;
            let mut value = None;
            while let Some(key) = present.next_key()? {
                if key.as_str() != "value" {
                    return Err(json::Error::unknown_field(key.as_str()).into());
                }
                if value.is_some() {
                    return Err(duplicate("value"));
                }
                value = Some(
                    present.parse_value_with_parser_typed(|parser| parse_record(parser, budget))?,
                );
            }
            present.finish()?;
            Ok::<_, EvidenceRecordRestoreError>(Some(required(value, "value")?))
        })?;
        if rows.insert(parsed, value).is_some() {
            return Err(json::Error::duplicate_field(key.as_str()).into());
        }
    }
    map.finish()?;
    Ok(rows)
}

/// Restore both explicit graph generations before installing either original map.
/// Input/table controls and canonical comparison scratch keep their existing owners.
pub(crate) fn restore_storage(
    raw: &str,
    budget: &AllocationBudget,
) -> Result<
    mv::storage::Storage<iroha_crypto::Hash, RetainedEvidenceRecord>,
    EvidenceRecordRestoreError,
> {
    let mut parser = Parser::new(raw);
    let mut map = MapVisitor::new(&mut parser)?;
    let mut current = None;
    let mut undo = None;
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "revert" => {
                if undo.is_some() {
                    return Err(duplicate("revert"));
                }
                undo =
                    Some(map.parse_value_with_parser_typed(|parser| parse_undo(parser, budget))?);
            }
            "blocks" => {
                if current.is_some() {
                    return Err(duplicate("blocks"));
                }
                current =
                    Some(map.parse_value_with_parser_typed(|parser| parse_values(parser, budget))?);
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    map.finish()?;
    parser.skip_ws();
    if !parser.eof() {
        return Err(json::Error::Message("trailing characters".into()).into());
    }
    let undo = required(undo, "revert")?;
    let current = required(current, "blocks")?;
    Ok(mv::storage::Storage::from_snapshot_parts(current, undo))
}

#[cfg(test)]
mod tests;
