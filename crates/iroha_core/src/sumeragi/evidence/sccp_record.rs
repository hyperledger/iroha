//! Charged closed SCCP record claims; custody is not execution or restore authority.
//!
//! The executing-parent handler consumes prepared custody in its atomic child.
//! Snapshot parsing remains structural; native history restoration does not acquire
//! SCCP verification authority from this representation.

use super::{
    EvidenceRecordBodyFields, EvidenceRecordRestoreError as Error, RecordOwner,
    RetainedEvidenceRecord,
};
use crate::state::EvidencePreparationError as Preparation;
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer, ChargedShared,
    RetainedPayload,
};
use iroha_data_model::block::consensus::{
    EvidenceAttribution, EvidenceOffender, EvidenceRecord, EvidenceScope, RecordedEvidenceV1,
};
use iroha_data_model::sccp::native::{SccpForgeryOffenderV1, SccpForgeryRecordV1};
use norito::json::{self, JsonDeserialize as _, MapVisitor, Parser};
use std::{alloc::Layout, mem::ManuallyDrop};

enum Fields {
    Constructed(RetainedPayload<EvidenceRecordBodyFields>),
    Decoded(DecodedFields),
}
struct DecodedFields {
    fields: ManuallyDrop<EvidenceRecordBodyFields>,
    allowance: ManuallyDrop<AllocationReservation>,
}
impl Drop for DecodedFields {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: immutable private graph retires before its conservative decode allowance.
        unsafe {
            ManuallyDrop::drop(&mut self.fields);
            ManuallyDrop::drop(&mut self.allowance);
        }
    }
}
pub(super) struct SccpRecordBody {
    fields: Fields,
    #[cfg(all(test, sumeragi_core_mutation = "HC181"))]
    budget: AllocationBudget,
}
impl SccpRecordBody {
    pub(super) fn canonical(&self) -> &EvidenceRecordBodyFields {
        match &self.fields {
            Fields::Constructed(p) => p.get(),
            Fields::Decoded(p) => &p.fields,
        }
    }
    #[cfg(all(test, sumeragi_core_mutation = "HC181"))]
    pub(super) fn budget(&self) -> &AllocationBudget {
        &self.budget
    }
    #[cfg(test)]
    pub(super) fn graph_belongs_to(&self, budget: &AllocationBudget) -> bool {
        match &self.fields {
            Fields::Constructed(p) => p.belongs_to(budget),
            Fields::Decoded(p) => p.allowance.belongs_to(budget),
        }
    }
    #[cfg(test)]
    pub(super) fn allocation_bytes(&self) -> Option<usize> {
        let graph = match &self.fields {
            Fields::Constructed(p) => p.allocation_bytes()?,
            Fields::Decoded(p) => p.allowance.remaining_bytes(),
        };
        graph.checked_add(ChargedShared::<Self>::allocation_layout().size())
    }
}
fn invalid(message: &'static str) -> Error {
    json::Error::Message(message.into()).into()
}
fn codec(e: norito::core::Error) -> Preparation {
    e.decode_resource_error()
        .map_or(Preparation::Invariant, Preparation::DecodeResource)
}
fn prepaid(e: iroha_allocation::PrepaidBufferError) -> Preparation {
    match e {
        iroha_allocation::PrepaidBufferError::Reservation(_) => Preparation::Invariant,
        iroha_allocation::PrepaidBufferError::Allocation(e) => Preparation::from(e),
    }
}
fn shared(e: iroha_allocation::PrepaidSharedError) -> Preparation {
    match e {
        iroha_allocation::PrepaidSharedError::Reservation(_) => Preparation::Invariant,
        iroha_allocation::PrepaidSharedError::Allocator { requested_bytes } => {
            Preparation::Allocator { requested_bytes }
        }
    }
}
fn overflow() -> Preparation {
    Preparation::Admission(iroha_allocation::AllocationRefusal::DemandOverflow)
}

#[derive(Clone, Copy)]
pub(super) enum MaterialKind {
    Native,
    SccpForgery,
}

/// Fund the complete discriminator pass, including escaped keys and enum strings.
/// Only a fixed closed tag escapes; scratch retires before the original allowance.
pub(super) fn material_kind(raw: &str, budget: &AllocationBudget) -> Result<MaterialKind, Error> {
    let mut controls = budget
        .try_reserve_layouts([norito::core::DecodeBudgetContext::allocation_layout()])
        .map_err(Preparation::Admission)?;
    let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
    let _allowance = budget
        .try_reserve_bytes(available)
        .map_err(Preparation::Admission)?;
    let context = norito::core::DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, available, usize::MAX),
        &mut controls,
    )
    .map_err(shared)?;
    context.with(|| decode_material_kind(raw))
}

/// Inspect only the required closed envelope discriminator; no decoded graph or fallback.
fn decode_material_kind(raw: &str) -> Result<MaterialKind, Error> {
    let mut p = Parser::new(raw);
    let mut map = MapVisitor::new(&mut p)?;
    let mut seen = 0u8;
    let mut material = None;
    while let Some(key) = map.next_key()? {
        let bit = match key.as_str() {
            "evidence" => 1,
            "attribution" => 2,
            "recorded_at_height" => 4,
            "recorded_at_view" => 8,
            "recorded_at_ms" => 16,
            "penalty_status" => 32,
            other => return Err(json::Error::unknown_field(other).into()),
        };
        if seen & bit != 0 {
            return Err(json::Error::duplicate_field(key.as_str()).into());
        }
        seen |= bit;
        match key.as_str() {
            "evidence" => {
                material = Some(map.parse_value_with_parser(|p| p.raw_value_slice())?);
                break;
            }
            // Preserve the canonical first invalid field when a common field precedes
            // the material. This entire temporary prefix is originally funded.
            "attribution" => {
                map.parse_value::<EvidenceAttribution>()?;
            }
            "recorded_at_height" | "recorded_at_view" | "recorded_at_ms" => {
                map.parse_value::<u64>()?;
            }
            "penalty_status" => {
                map.parse_value::<iroha_data_model::block::consensus::EvidencePenaltyStatus>()?;
            }
            _ => unreachable!("closed field name"),
        }
    }
    let raw = material.ok_or_else(|| json::Error::missing_field("evidence"))?;
    // The selected exact decoder validates the whole source; this pass stops at
    // the discriminator so later fields cannot pre-empt earlier semantic errors.
    let mut p = Parser::new(raw);
    let mut map = MapVisitor::new(&mut p)?;
    let mut kind = None;
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "kind" => {
                if kind.is_some() {
                    return Err(json::Error::duplicate_field("kind").into());
                }
                kind = Some(map.parse_value::<String>()?);
            }
            "value" => {
                map.parse_value_with_parser(|p| p.raw_value_slice())?;
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    map.finish()?;
    match kind.as_deref() {
        Some("native") => Ok(MaterialKind::Native),
        Some("sccp_forgery") => Ok(MaterialKind::SccpForgery),
        Some(_) => Err(invalid("unknown JSON enum variant")),
        None => Err(json::Error::missing_field("kind").into()),
    }
}

/// Structural closed-material/scope join. No signature, dedup or historic authority claim.
fn validate(fields: &EvidenceRecordBodyFields) -> Result<(), Error> {
    use iroha_data_model::sumeragi_finality::certified_result::SccpFinalityHeaderV1;
    use iroha_sccp::v1::finality::QcFixedV1;
    let RecordedEvidenceV1::SccpForgery(record) = &fields.evidence else {
        return Err(invalid("SCCP custody requires SCCP material"));
    };
    record
        .validate_shape()
        .map_err(|_| invalid("invalid SCCP record shape"))?;
    let a = &fields.attribution;
    if a.scope
        != (EvidenceScope::SccpGeneration {
            generation: record.generation,
        })
        || a.height != record.start_height
        || !a.safety_violation
        || a.offenders.len() != record.offenders.len()
    {
        return Err(invalid("SCCP material and attribution differ"));
    }
    let x = SccpFinalityHeaderV1::parse(&record.evidence.header)
        .map_err(|_| invalid("invalid SCCP header"))?;
    let qc = QcFixedV1::parse(&record.evidence.qc).map_err(|_| invalid("invalid SCCP QC"))?;
    if !x.is_active()
        || x.generation() != record.generation
        || x.committee_root() != a.authority_generation
        || qc.epoch != a.epoch
        || qc.epoch_context != a.context_id
    {
        return Err(invalid(
            "SCCP signed coordinates differ from stored attribution",
        ));
    }
    for (signed, attributed) in record.offenders.iter().zip(&a.offenders) {
        if signed.signer != attributed.signer
            || attributed.lane_stake.is_some()
            || qc.signers & (1u32 << signed.signer) == 0
        {
            return Err(invalid("SCCP offender/attribution mismatch"));
        }
        let (algorithm, material) = attributed
            .peer_id
            .public_key()
            .borrowed_parts()
            .map_err(|_| invalid("invalid SCCP peer key envelope"))?;
        if algorithm != iroha_crypto::Algorithm::BlsNormal || material.len() != 48 {
            return Err(invalid("SCCP attribution is not a native BLS peer"));
        }
    }
    Ok(())
}

pub(super) fn decode_json(
    raw: &str,
    budget: &AllocationBudget,
) -> Result<RetainedEvidenceRecord, Error> {
    let bytes = ChargedShared::<SccpRecordBody>::allocation_layout()
        .size()
        .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
        .ok_or_else(overflow)?;
    let mut control = budget
        .try_reserve_bytes(bytes)
        .map_err(Preparation::Admission)?;
    let shell = ChargedShared::reserve_from(&mut control).map_err(shared)?;
    let available = budget.limit_bytes().saturating_sub(budget.reserved_bytes());
    let allowance = budget
        .try_reserve_bytes(available)
        .map_err(Preparation::Admission)?;
    let context = norito::core::DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, available, usize::MAX),
        &mut control,
    )
    .map_err(shared)?;
    let source = context.with(|| {
        let mut p = Parser::new(raw);
        let record = EvidenceRecord::json_deserialize(&mut p)?;
        p.skip_ws();
        if !p.eof() {
            return Err(json::Error::Message("trailing evidence JSON".into()));
        }
        Ok::<_, json::Error>(record)
    })?;
    let (height, view, time, status) = (
        source.recorded_at_height,
        source.recorded_at_view,
        source.recorded_at_ms,
        source.penalty_status,
    );
    let mut decoded = DecodedFields {
        fields: ManuallyDrop::new(EvidenceRecordBodyFields {
            evidence: source.evidence,
            attribution: source.attribution,
        }),
        allowance: ManuallyDrop::new(allowance),
    };
    validate(&decoded.fields)?;
    // Preserve cumulative decoder demand conservatively, including temporary work.
    let used = usize::try_from(context.consumed_allocated_bytes()).map_err(|_| overflow())?;
    let retained = decoded
        .allowance
        .try_partition_bytes(used)
        .map_err(|_| Preparation::Invariant)?;
    drop(std::mem::replace(&mut *decoded.allowance, retained));
    let body = shell.initialize(SccpRecordBody {
        fields: Fields::Decoded(decoded),
        #[cfg(all(test, sumeragi_core_mutation = "HC181"))]
        budget: budget.clone(),
    });
    Ok(RetainedEvidenceRecord {
        body: RecordOwner::Sccp(body),
        recorded_at_height: height,
        recorded_at_view: view,
        recorded_at_ms: time,
        penalty_status: status,
    })
}

/// Private funded materialization from an actual source-bound verifier and selected signer mask.
/// The execution handler alone joins this custody with deduplication and atomic publication.
pub(crate) struct PreparedSccpRecord {
    body: ChargedShared<SccpRecordBody>,
    parent: crate::state::NativeExecutionTip,
    execution_height: u64,
    liability_clock: u64,
    evidence_id: [u8; 32],
}

impl PreparedSccpRecord {
    /// Exact evidence identifier fixed by the verified certificate.
    pub(crate) fn evidence_id(&self) -> [u8; 32] {
        self.evidence_id
    }
    /// Borrow originally funded immutable fields for publication preparation.
    pub(crate) fn fields(&self) -> &EvidenceRecordBodyFields {
        self.body.canonical()
    }
    /// Preserve the prepared immutable graph and set Pending only at its actual execution
    /// context. The caller still owns atomic offence/max/event publication and R-EX.
    pub(crate) fn into_record(
        self,
        transaction: &crate::state::StateTransaction<'_, '_>,
    ) -> Result<RetainedEvidenceRecord, Preparation> {
        use crate::state::StateReadOnly as _;
        let header = &transaction._curr_block;
        if transaction.native_execution_tip() != Some(self.parent)
            || self.parent.height().checked_add(1) != Some(header.height().get())
            || header.height().get() != self.execution_height
            || *crate::smartcontracts::isi::sccp::store::liability_clock::get(&*transaction.world)
                != self.liability_clock
            || header.prev_block_hash() != Some(self.parent.iroha_hash())
            || header.creation_time_ms <= self.parent.creation_time_ms()
        {
            return Err(Preparation::Invariant);
        }
        Ok(RetainedEvidenceRecord {
            body: RecordOwner::Sccp(self.body),
            recorded_at_height: header.height().get(),
            recorded_at_view: header.view_change_index,
            recorded_at_ms: header.creation_time_ms,
            penalty_status: iroha_data_model::block::consensus::EvidencePenaltyStatus::Pending,
        })
    }
}
/// Fund immutable record custody from the exact verified observation and selected new signers.
pub(crate) fn prepare_claim(
    candidate: &crate::smartcontracts::isi::sccp::forgery::VerifiedForgeryCandidate<'_>,
    new_signers: u32,
    budget: &AllocationBudget,
) -> Result<PreparedSccpRecord, Preparation> {
    use iroha_crypto::{Algorithm, PreparedPublicKeyDecode, PublicKeyDecodeAdmissionError};
    use iroha_model_base::peer::PeerId;
    if new_signers == 0 || new_signers & !candidate.qc().signers != 0 {
        return Err(Preparation::Invariant);
    }
    let count = usize::try_from(new_signers.count_ones()).map_err(|_| overflow())?;
    let offender_layout = Layout::array::<SccpForgeryOffenderV1>(count).map_err(|_| overflow())?;
    let attribution_layout = Layout::array::<EvidenceOffender>(count).map_err(|_| overflow())?;
    let (mut ledger_count, mut bytes, mut overflowed) = (
        count.checked_add(3).ok_or_else(overflow)?,
        offender_layout
            .size()
            .checked_add(attribution_layout.size())
            .and_then(|bytes| bytes.checked_add(Layout::new::<SccpForgeryRecordV1>().size()))
            .ok_or_else(overflow)?,
        false,
    );
    for (signer, _, member) in candidate.signers() {
        if new_signers & (1 << signer) == 0 {
            continue;
        }
        let member = member.ok_or(Preparation::Invariant)?;
        member
            .validator
            .for_each_admission_clone_layout(|layout| {
                match (
                    ledger_count.checked_add(1),
                    bytes.checked_add(layout.size()),
                ) {
                    (Some(n), Some(b)) => {
                        ledger_count = n;
                        bytes = b;
                    }
                    _ => overflowed = true,
                }
            })
            .map_err(codec)?;
    }
    if overflowed {
        return Err(overflow());
    }
    bytes = bytes
        .checked_add(
            Layout::array::<AllocationCharge>(ledger_count)
                .map_err(|_| overflow())?
                .size(),
        )
        .and_then(|n| n.checked_add(ChargedShared::<SccpRecordBody>::allocation_layout().size()))
        .ok_or_else(overflow)?;
    let mut original = budget
        .try_reserve_bytes(bytes)
        .map_err(Preparation::Admission)?;
    let mut ledger =
        ChargedBuffer::from_reservation(ledger_count, &mut original).map_err(prepaid)?;
    let shell = ChargedShared::reserve_from(&mut original).map_err(shared)?;
    let mut material = ChargedBuffer::from_reservation(1, &mut original).map_err(prepaid)?;
    let mut offenders = ChargedBuffer::from_reservation(count, &mut original).map_err(prepaid)?;
    let mut peers = ChargedBuffer::from_reservation(count, &mut original).map_err(prepaid)?;
    for (signer, key, member) in candidate.signers() {
        if new_signers & (1 << signer) == 0 {
            continue;
        }
        let member = member.ok_or(Preparation::Invariant)?;
        let peer = PreparedPublicKeyDecode::try_from_material(Algorithm::BlsNormal, key, budget)
            .map_err(|e| match e {
                PublicKeyDecodeAdmissionError::Allocation(e) => Preparation::from(e),
                PublicKeyDecodeAdmissionError::Codec(e) => codec(e),
            })?;
        let mut mismatch = false;
        member
            .validator
            .for_each_admission_clone_layout(|layout| match original.try_split(layout) {
                Ok(c) => ledger.push_reserved(c),
                Err(_) => mismatch = true,
            })
            .map_err(codec)?;
        if mismatch {
            return Err(Preparation::Invariant);
        }
        let account = member.validator.try_clone_for_admission().map_err(codec)?;
        offenders.push_reserved(SccpForgeryOffenderV1 {
            signer,
            lane_id: member.lane_id,
            validator: account,
            activation_height: member.activation_height,
        });
        // SAFETY: the exact key backing and charge immediately enter immutable graph custody.
        #[allow(unsafe_code)]
        let (peer, charge) = unsafe { peer.into_allocation_parts() };
        ledger.push_reserved(charge);
        peers.push_reserved(EvidenceOffender {
            signer,
            peer_id: PeerId::new(peer),
            lane_stake: None,
        });
    }
    #[allow(unsafe_code)]
    let (offenders, charge) = unsafe { offenders.into_allocation_parts() };
    ledger.push_reserved(charge);
    #[allow(unsafe_code)]
    let (peers, charge) = unsafe { peers.into_allocation_parts() };
    ledger.push_reserved(charge);
    let generation = candidate.generation();
    material.push_reserved(SccpForgeryRecordV1 {
        evidence: candidate.evidence().clone(),
        rule: candidate.rule(),
        generation: generation.generation,
        start_height: generation.start_height,
        offenders,
    });
    // SAFETY: exactly one initialized record and capacity one use the same size,
    // alignment and global allocator as Box. The original box charge joins the
    // retained ledger; no fallible operation separates the backing from its owner.
    #[allow(unsafe_code)]
    let (material, material_charge) = unsafe { material.into_allocation_parts() };
    ledger.push_reserved(material_charge);
    let mut material = ManuallyDrop::new(material);
    #[allow(unsafe_code)]
    let material = unsafe { Box::from_raw(material.as_mut_ptr()) };
    let fields = EvidenceRecordBodyFields {
        evidence: RecordedEvidenceV1::SccpForgery(material),
        attribution: EvidenceAttribution {
            scope: EvidenceScope::SccpGeneration {
                generation: generation.generation,
            },
            instance: candidate.instance().0,
            height: generation.start_height,
            epoch: candidate.qc().epoch,
            context_id: candidate.qc().epoch_context,
            authority_generation: generation.committee_root,
            offenders: peers,
            safety_violation: true,
        },
    };
    // SAFETY: the exact record Box, both Vec backings, every account clone and compact
    // peer key have original charges in the ledger; fields own no other allocations.
    #[allow(unsafe_code)]
    let fields = unsafe { RetainedPayload::try_new(fields, ledger, budget) }.map_err(
        |(fields, ledger, _)| {
            drop(fields);
            drop(ledger);
            Preparation::Invariant
        },
    )?;
    validate(fields.get()).map_err(|_| Preparation::Invariant)?;
    let body = shell.initialize(SccpRecordBody {
        fields: Fields::Constructed(fields),
        #[cfg(all(test, sumeragi_core_mutation = "HC181"))]
        budget: budget.clone(),
    });
    Ok(PreparedSccpRecord {
        body,
        parent: candidate.parent(),
        execution_height: candidate.execution_height(),
        liability_clock: candidate.liability_clock(),
        evidence_id: candidate.evidence_id(),
    })
}

#[cfg(test)]
#[path = "sccp_record/tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn fixture_record() -> EvidenceRecord {
    tests::claim()
}
