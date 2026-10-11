//! Total original Credited evidence, fixed selector and no-op result owner.

use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{Bit, GlueChip, UintChip, Word, bytes::tape::BytesChip};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    incoming::ArchiveIncomingObjects,
    require_task,
    results::{ArchiveResultClaims, ArchiveResultTag},
};
use crate::{
    a_relation::{
        bounded_word,
        context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
        own::OwnPolicy,
        schedule::{OperationTask, constrain_sigma_selector},
    },
    operation_relation::{
        incoming_statement::{DynamicStatementCells, StatementView},
        objects::{
            credit_opening::CreditOpeningCells,
            predicates::all,
            status::{
                CreditedCells, EvidenceKind, ReceiveEvidenceCells, ReceiveEvidenceInputs,
                StatusCells, StatusInputs,
            },
        },
    },
};

/// Original bytes selected by the fixed Archive evidence class.
#[derive(Clone, Copy)]
pub enum ArchiveEvidenceSource<'a> {
    /// Receive's statement is the exact incoming sigma statement in the context.
    Receive {
        /// Original99-byte Credited transcript, including original component addresses.
        credited: &'a [Value<u8>],
    },
    /// Status carries a folded head, without a sigma proof or predecessor package.
    Status {
        /// Original99-byte Credited transcript.
        credited: &'a [Value<u8>],
        /// Exact26 native statement words carried with the folded head.
        statement: &'a [Word<Fp>; 26],
        /// Original162-byte `CreditStatus` transcript.
        status: &'a [Value<u8>],
        /// Exact1125-byte credit membership opening.
        opening: &'a [Value<u8>],
    },
}

fn bind_object(
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    objects: &[ContextObjectCells],
    index: usize,
    spec: ContextObjectSpec,
    actual: &ContextObjectCells,
) -> Result<(), Error> {
    if plan.object_specs().get(index) != Some(&spec) {
        return Err(Error::Synthesis);
    }
    let expected = objects.get(index).ok_or(Error::Synthesis)?;
    for (a, b) in actual
        .commitment_words()
        .iter()
        .zip(expected.commitment_words())
    {
        GlueChip::assert_equal(region, a, &b)?;
    }
    Ok(())
}

/// Fixed statement/Credited fields and Status-only original tapes after slot13.
/// The last result object is supplied by `ArchiveResultPlan`, separately.
/// # Errors
/// Non-Archive variant or impossible fixed-size conversion.
pub fn evidence_specs(variant: Variant) -> Result<Vec<ContextObjectSpec>, Error> {
    super::require_variant(variant)?;
    let mut capacities = vec![26 * 32, CreditedCells::BYTES];
    if variant == Variant::ArchiveStatus {
        capacities.extend([StatusCells::BYTES, CreditOpeningCells::BYTES]);
    }
    capacities
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            Ok(ContextObjectSpec {
                tag: u32::try_from(15 + i).map_err(|_| Error::BoundsFailure)?,
                capacity: u32::try_from(n).map_err(|_| Error::BoundsFailure)?,
            })
        })
        .collect()
}

/// Bind original evidence and derive its complete body/identity/credit verdict.
///
/// Incoming proof and receipt-signature verdicts have separate mandatory owners.
/// Every content address and own evidence digest binds even on no-op; canonical
/// mismatch to a supplied component is never a discretionary soft failure.
/// # Errors
/// Wrong task/kind/schema, changed original component, wrong fixed sigma selector,
/// missing incoming context or layout failure.
#[allow(
    clippy::too_many_arguments,
    reason = "one fixed owner binds all original evidence to the exact shared context"
)]
pub fn constrain_evidence(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    stage: u32,
    input: &ContextInputs<'_>,
    claims: &ArchiveResultClaims,
    policy: OwnPolicy,
    objects: &ArchiveIncomingObjects,
    source: ArchiveEvidenceSource<'_>,
) -> Result<(), Error> {
    require_task(plan, stage, OperationTask::ArchiveEvidence)?;
    claims.bind_context(region, plan, input)?;
    let valid = derive_evidence(chip, bytes, region, plan, input, policy, objects, source)?;
    claims.bind_derived(
        region,
        plan,
        stage,
        input,
        ArchiveResultTag::Evidence,
        &valid,
    )
}

// Return the exact circuit-derived proposal for native witness preparation.
// The staged Evidence owner still binds this predicate to its committed claim.
#[allow(
    clippy::too_many_arguments,
    reason = "the same predicate retains every original evidence source and context"
)]
pub(crate) fn derive_evidence(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    input: &ContextInputs<'_>,
    policy: OwnPolicy,
    objects: &ArchiveIncomingObjects,
    source: ArchiveEvidenceSource<'_>,
) -> Result<Bit<Fp>, Error> {
    objects.bind_context(region, plan, input)?;
    evidence_predicate(
        chip,
        bytes,
        region,
        plan,
        EvidencePredicateInputs {
            own_statement: input.own_statement,
            incoming_statement: input.incoming_statement,
            incoming_public: input.incoming.map(|v| v.public),
            objects: input.objects,
            incoming_selector: input
                .q_instances
                .first()
                .and_then(|q| q.get(2))
                .and_then(|c| c.get(1)),
        },
        policy,
        objects,
        source,
    )
}

// Exact original-only inputs. No Q0 frame, mode, result or verifier verdict is present.
#[derive(Clone, Copy)]
pub(crate) struct EvidencePredicateInputs<'a> {
    pub(crate) own_statement: &'a crate::operation_relation::statement::StatementCells,
    pub(crate) incoming_statement:
        Option<&'a crate::operation_relation::incoming_statement::IncomingStatementCells>,
    pub(crate) incoming_public: Option<&'a crate::a_relation::IncomingLineageCells>,
    pub(crate) objects: &'a [ContextObjectCells],
    pub(crate) incoming_selector: Option<&'a iroha_plonk_recursion::codec::ScalarCells<Ep>>,
}

// Shared raw evidence predicate. The owning stage retains its task, full context
// and Q0 selector binding; native evaluation supplies the exact installed selector.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evidence_predicate(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut Region<'_, Fp>,
    plan: &ContextPlan,
    input: EvidencePredicateInputs<'_>,
    policy: OwnPolicy,
    objects: &ArchiveIncomingObjects,
    source: ArchiveEvidenceSource<'_>,
) -> Result<Bit<Fp>, Error> {
    let variant = plan.operation().frame().variant();
    let specs = evidence_specs(variant)?;
    let payment = input
        .objects
        .get(7)
        .ok_or(Error::Synthesis)?
        .authenticated_digest();
    let raw_digest = input
        .objects
        .get(13)
        .ok_or(Error::Synthesis)?
        .authenticated_digest();
    GlueChip::assert_equal(
        region,
        objects.request().credit_id(),
        &input.own_statement.fields()[17],
    )?;
    let relation = core::array::from_fn(|i| input.own_statement.fields()[1 + i].clone());
    let provider = policy.provider(chip, region)?;
    let (credited_bytes, kind, digest, valid, statement) = match source {
        ArchiveEvidenceSource::Receive { credited } => {
            if variant != Variant::ArchiveReceive {
                return Err(Error::Synthesis);
            }
            let statement = input.incoming_statement.ok_or(Error::Synthesis)?;
            let selector = bounded_word(
                chip,
                region,
                input.incoming_selector.ok_or(Error::Synthesis)?,
            )?;
            let lanes = chip.operation_lanes()?;
            let mut uint = UintChip::new(lanes.glue, lanes.range);
            let zero = uint
                .glue()
                .is_zero(region, objects.request().object().word(15)?)?;
            let recorded = uint.glue().not(region, &zero)?;
            let expected = constrain_sigma_selector(&mut uint, region, 4, recorded.word())?;
            GlueChip::assert_equal(region, &selector, &expected)?;
            let evidence = ReceiveEvidenceCells::bind(
                &mut uint,
                lanes.hash,
                region,
                &ReceiveEvidenceInputs {
                    statement,
                    receipt: objects.receipt(),
                    request: objects.request(),
                    receiver: objects.receiver(),
                    relation: &relation,
                    provider: &provider,
                    payment_digest: payment,
                    proof_digest: raw_digest,
                },
            )?;
            (
                credited,
                EvidenceKind::Receive,
                evidence.digest().clone(),
                evidence.valid().clone(),
                statement.fields().clone(),
            )
        }
        ArchiveEvidenceSource::Status {
            credited,
            statement,
            status,
            opening,
        } => {
            if variant != Variant::ArchiveStatus {
                return Err(Error::Synthesis);
            }
            let head = input.incoming_public.ok_or(Error::Synthesis)?.checked();
            let status_run = bytes.run(
                region,
                status,
                &StatusCells::primary_segments(),
                &StatusCells::secondary_segments(),
            )?;
            let opening_run = bytes.run(
                region,
                opening,
                &CreditOpeningCells::primary_segments(),
                &CreditOpeningCells::secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let mut uint = UintChip::new(lanes.glue, lanes.range);
            let dynamic =
                DynamicStatementCells::constrain(&mut uint, lanes.hash, region, statement)?;
            let carried = StatusCells::carried_proof_digest(&mut uint, region, &status_run)?;
            let lanes = chip.operation_lanes()?;
            let opening = CreditOpeningCells::from_run(
                lanes.glue,
                lanes.range,
                lanes.hash,
                region,
                &opening_run,
            )?;
            let lanes = chip.operation_lanes()?;
            let evidence = StatusCells::from_run(
                &mut UintChip::new(lanes.glue, lanes.range),
                lanes.hash,
                region,
                &status_run,
                &StatusInputs {
                    statement: &dynamic,
                    receipt: objects.receipt(),
                    lineage: head,
                    lineage_digest: raw_digest,
                    proof_digest: &carried,
                    opening: &opening,
                    provider: &provider,
                    relation: &relation,
                    request: objects.request(),
                    receiver: objects.receiver(),
                    payment_digest: payment,
                },
            )?;
            for (index, spec, digest, run) in [
                (16, specs[2], evidence.digest(), &status_run),
                (17, specs[3], opening.digest(), &opening_run),
            ] {
                let actual = ContextObjectCells::from_exact_run(chip, region, spec, digest, run)?;
                bind_object(region, plan, input.objects, index, spec, &actual)?;
            }
            (
                credited,
                EvidenceKind::Status,
                evidence.digest().clone(),
                evidence.valid().clone(),
                statement.clone(),
            )
        }
    };
    let actual = ContextObjectCells::from_internal_words(chip, region, specs[0], &statement)?;
    bind_object(region, plan, input.objects, 14, specs[0], &actual)?;
    let run = bytes.run(
        region,
        credited_bytes,
        &CreditedCells::primary_segments(),
        &CreditedCells::secondary_segments(),
    )?;
    let lanes = chip.operation_lanes()?;
    let mut uint = UintChip::new(lanes.glue, lanes.range);
    let credited = CreditedCells::from_run(
        &mut uint,
        lanes.hash,
        region,
        &run,
        kind,
        &[
            objects.request().credit_id().clone(),
            payment.clone(),
            digest,
        ],
    )?;
    GlueChip::assert_equal(region, credited.digest(), &input.own_statement.fields()[18])?;
    let valid = all(uint.glue(), region, &[valid, credited.valid().clone()])?;
    let actual =
        ContextObjectCells::from_exact_run(chip, region, specs[1], credited.digest(), &run)?;
    bind_object(region, plan, input.objects, 15, specs[1], &actual)?;
    Ok(valid)
}
