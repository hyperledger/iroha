//! Fixed A-split context framing; every continuation input is rebound by hash.

use super::results::{
    RECEIVE_OPENING_DOMAIN, RECEIVE_RESULTS_DOMAIN, ReceiveResultClaims, ReceiveResultPlan,
};
use super::schedule::OperationTask;
use super::{AProofPlan, LineagePublicCells, ProofMessageCells, VerifiedQCells, VestaClaimCells};
use crate::operation_relation::{
    incoming_statement::{IncomingStatementCells, StatementView},
    state::StateCells,
    statement::StatementCells,
};
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fp};
use iroha_plonk::{
    cs::InstanceType,
    frontend::{Error, Region, Value},
};
use iroha_plonk_gadgets::{
    GlueChip, Uint, Word,
    bytes::{
        tape::{ByteOrder, ByteRun, SegmentSpec},
        variable::ActiveBytes,
    },
    ecc::NonIdentityPoint,
};
use iroha_plonk_recursion::{
    accumulation_circuit::{FoldInputCells, FoldSource},
    codec::ScalarCells,
    obligation::{ModeCells, ledger::Variant},
    verifier::VerifierChip,
};

/// Separate digest domain for an internal split context, never a lineage head.
pub const CONTEXT_DOMAIN: [u8; 8] = *b"kgwctx_1";
/// Fixed-stage internal frame domain, distinct from context and final lineage.
pub const STAGE_DOMAIN: [u8; 8] = *b"kgwlink1";
const TAPE_DOMAIN: [u8; 8] = *b"kgwctap1";
const ACTIVE_TAPE_DOMAIN: [u8; 8] = *b"kgwcact1";
const INTERNAL_WORDS_DOMAIN: [u8; 8] = *b"kgwciw_1";

#[cfg(test)]
mod tests;

fn push_q_context(
    words: &mut Vec<Word<Fp>>,
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    value: &ScalarCells<Ep>,
    ty: InstanceType,
    receive: bool,
) -> Result<(), Error> {
    if receive && matches!(ty, InstanceType::Bounded | InstanceType::Bits(0..=253)) {
        // Fixed descriptor bounds are strict subsets of Fp. Prove the exact
        // bound before recomposition, even before the hard Q owner executes.
        let valid = value.instance_type(&mut chip.uint(), region, ty)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        words.push(chip.uint().glue().linear(
            region,
            &[
                (Fp::ONE, value.lo().word()),
                (Fp::from(2).pow_vartime([128]), value.hi().word()),
            ],
            Fp::ZERO,
        )?);
    } else {
        words.extend([value.lo().word().clone(), value.hi().word().clone()]);
    }
    Ok(())
}

/// Append an injective encoding of all256 message bits as two128-bit words.
/// The verifier's bounded `(lo128, hi127, top1)` representation permits exact
/// recomposition of its high half without a field reduction or byte assumption.
fn push_message_context(
    words: &mut Vec<Word<Fp>>,
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    message: &iroha_plonk_gadgets::bytes::element::LeElement<Fp>,
) -> Result<(), Error> {
    let high = chip.uint().glue().linear(
        region,
        &[
            (Fp::ONE, message.hi().word()),
            (Fp::from(2).pow_vartime([127]), message.top().word()),
        ],
        Fp::ZERO,
    )?;
    words.extend([message.lo().word().clone(), high]);
    Ok(())
}

/// A circuit-fixed context category and exact carrier or canonical-word size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextObjectSpec {
    /// Unique nonzero category within this context schema.
    pub tag: u32,
    /// Fixed payload capacity, excluding its LE32 actual-length prefix;
    /// internal word commitments use exactly32 bytes per canonical native word.
    pub capacity: u32,
}
/// Exact object digest, length and separately typed byte/word commitment.
#[derive(Clone, Debug)]
pub struct ContextObjectCells {
    spec: ContextObjectSpec,
    authenticated_digest: Word<Fp>,
    length: Uint<Fp, 32>,
    tape_digest: Word<Fp>,
}
impl ContextObjectCells {
    /// Commit circuit-internal native field words under a separate typed domain.
    ///
    /// This carries proposed results or private arrays between fixed owners;
    /// it does not authenticate their semantics or claim an original byte tape.
    /// The schema's capacity is exactly32 times the fixed word count, using the
    /// unique canonical field encoding as its size convention. Tags, count and
    /// all words enter the hash. The owning tasks must derive or constrain every
    /// proposed value against this same commitment before key admission.
    /// # Errors
    /// Zero tag/count, wrong fixed capacity, overflow or layout failure.
    pub fn from_internal_words(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        spec: ContextObjectSpec,
        words: &[Word<Fp>],
    ) -> Result<Self, Error> {
        let count = u32::try_from(words.len()).map_err(|_| Error::BoundsFailure)?;
        if spec.tag == 0 || count == 0 || count.checked_mul(32) != Some(spec.capacity) {
            return Err(Error::Synthesis);
        }
        let mut framed = [spec.tag, count]
            .map(|v| chip.uint().glue().constant(region, Fp::from(u64::from(v))))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        framed.extend_from_slice(words);
        let digest = chip.hash_words(region, u64::from_le_bytes(INTERNAL_WORDS_DOMAIN), &framed)?;
        Ok(Self {
            spec,
            authenticated_digest: digest.clone(),
            length: chip
                .uint()
                .constant::<32>(region, u128::from(spec.capacity))?,
            tape_digest: digest,
        })
    }

    pub(super) fn commitment_words(&self) -> [Word<Fp>; 3] {
        [
            self.authenticated_digest.clone(),
            self.length.word().clone(),
            self.tape_digest.clone(),
        ]
    }
    /// Digest of the object parsed from this same committed byte tape.
    pub const fn authenticated_digest(&self) -> &Word<Fp> {
        &self.authenticated_digest
    }

    /// Retain an original active raw object, including malformed short/long data.
    ///
    /// The capacity is fixed by the context schema. The exact active length and
    /// length-prefixed original bytes are bound independently of any semantic
    /// decoder output. The operation must derive `authenticated_digest` from
    /// this same source; this context commitment alone does not authenticate it.
    /// # Errors
    /// Wrong capacity/tag, incompatible sponge lane or synthesis failure.
    pub fn from_active(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        spec: ContextObjectSpec,
        authenticated_digest: &Word<Fp>,
        raw: &ActiveBytes<Fp>,
    ) -> Result<Self, Error> {
        if spec.tag == 0 || usize::try_from(spec.capacity).ok() != Some(raw.run().len()) {
            return Err(Error::Synthesis);
        }
        let lanes = chip.operation_lanes()?;
        let mut uint = iroha_plonk_gadgets::UintChip::new(lanes.glue, lanes.range);
        let original = raw.packed().length_prefixed(&mut uint, region)?.digest(
            &mut uint,
            lanes.hash.sponge_mut()?,
            region,
            u64::from_le_bytes(ACTIVE_TAPE_DOMAIN),
        )?;
        let tag = uint
            .glue()
            .constant(region, Fp::from(u64::from(spec.tag)))?;
        let capacity = uint
            .glue()
            .constant(region, Fp::from(u64::from(spec.capacity)))?;
        let tape_digest = chip.hash_words(
            region,
            u64::from_le_bytes(ACTIVE_TAPE_DOMAIN),
            &[tag, capacity, raw.length().word().clone(), original],
        )?;
        Ok(Self {
            spec,
            authenticated_digest: authenticated_digest.clone(),
            length: raw.length().clone(),
            tape_digest,
        })
    }
    /// Commit an exact fixed-size object tape, prepending its pinned LE32 length.
    /// This reuses the bounded semantic parser's tape instead of assigning a
    /// second copy. It is for hard canonical own objects; variable-length soft
    /// incoming carriers must use `from_run` with their actual length bytes.
    ///
    /// # Errors
    /// Wrong fixed capacity, missing bounded segments, or layout failure.
    pub fn from_exact_run(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        spec: ContextObjectSpec,
        authenticated_digest: &Word<Fp>,
        run: &ByteRun<Fp>,
    ) -> Result<Self, Error> {
        use iroha_plonk_gadgets::bytes::PBytes;
        if spec.tag == 0 || usize::try_from(spec.capacity).ok() != Some(run.len()) {
            return Err(Error::Synthesis);
        }
        let mut tape = PBytes::new();
        tape.push_constant(&spec.capacity.to_le_bytes());
        for segment in run.primary() {
            tape.push_bounded_split(
                &mut chip.uint(),
                region,
                &segment.bounded().ok_or(Error::Synthesis)?,
            )?;
        }
        let length = chip
            .uint()
            .constant::<32>(region, u128::from(spec.capacity))?;
        let tag = chip
            .uint()
            .glue()
            .constant(region, Fp::from(u64::from(spec.tag)))?;
        let capacity = chip
            .uint()
            .glue()
            .constant(region, Fp::from(u64::from(spec.capacity)))?;
        let mut words = vec![tag, capacity];
        words.extend(
            tape.chunk_words(chip.uint().glue(), region)?
                .iter()
                .map(|v| v.word().clone()),
        );
        let tape_digest = chip.hash_words(region, u64::from_le_bytes(TAPE_DOMAIN), &words)?;
        Ok(Self {
            spec,
            authenticated_digest: authenticated_digest.clone(),
            length,
            tape_digest,
        })
    }

    /// Bind an object identity and its exact fixed carrier bytes.
    /// The operation/Q relation must authenticate `authenticated_digest` and
    /// tie it to these bytes; the context retains that binding across all stages.
    /// Actual lengths above the buffer capacity remain representable for soft
    /// malformed-input verdicts. The framing itself never claims authentication.
    ///
    /// # Errors
    /// Wrong fixed capacity/chunking, missing LE32 segment or layout failure.
    pub fn from_run(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        spec: ContextObjectSpec,
        authenticated_digest: &Word<Fp>,
        run: &ByteRun<Fp>,
    ) -> Result<Self, Error> {
        if spec.tag == 0
            || run.len()
                != usize::try_from(spec.capacity)
                    .map_err(|_| Error::BoundsFailure)?
                    .checked_add(4)
                    .ok_or(Error::BoundsFailure)?
        {
            return Err(Error::Synthesis);
        }
        let mut offset = 0;
        for segment in run.primary() {
            let expected = (run.len() - offset).min(31);
            if segment.spec() != SegmentSpec::little(offset, expected)
                || segment.spec().order != ByteOrder::Little
            {
                return Err(Error::Synthesis);
            }
            offset += expected;
        }
        if offset != run.len() {
            return Err(Error::Synthesis);
        }
        let length = chip.uint().range_check::<32>(
            region,
            run.secondary_segment(SegmentSpec::little(0, 4))?.word(),
        )?;
        let tag = chip
            .uint()
            .glue()
            .constant(region, Fp::from(u64::from(spec.tag)))?;
        let capacity = chip
            .uint()
            .glue()
            .constant(region, Fp::from(u64::from(spec.capacity)))?;
        let mut words = vec![tag, capacity];
        words.extend(run.primary().iter().map(|s| s.word().clone()));
        let tape_digest = chip.hash_words(region, u64::from_le_bytes(TAPE_DOMAIN), &words)?;
        Ok(Self {
            spec,
            authenticated_digest: authenticated_digest.clone(),
            length,
            tape_digest,
        })
    }
}
/// State opening plus the exact public lineage prefix used by a split half.
#[derive(Clone, Copy, Debug)]
pub struct ContextState<'a> {
    /// Constrained 33-word core and 8-word rest opening.
    pub state: &'a StateCells,
    /// Corresponding public lineage header.
    pub public: &'a LineagePublicCells,
}
/// Hard predecessor context, including both deferred transport obligations.
#[derive(Clone, Copy, Debug)]
pub struct ContextPredecessor<'a> {
    /// Canonical state opening used after the split.
    pub state: &'a StateCells,
    /// Exact predecessor lineage public fields.
    pub public: &'a LineagePublicCells,
    /// Original checked full-k Pallas accumulator.
    pub pallas: &'a FoldInputCells<Ep>,
    /// Original checked full-k Vesta accumulator.
    pub vesta: &'a VestaClaimCells,
}
/// Incoming proof source selected by the fixed context schema.
#[derive(Clone, Copy, Debug)]
pub enum ContextIncomingProof<'a> {
    /// A frame without a fixed Receive owner retains each exact verifier message.
    Messages(&'a ProofMessageCells),
    /// Receive retains its exact active Omega tape in fixed object slot4.
    /// The mandatory Proofs owner derives every verifier message from that tape;
    /// non-owner stages neither assign nor hash a second decoded message copy.
    ReceiveActive,
}
/// Original incoming lineage and both checked transport claims.
#[derive(Clone, Copy, Debug)]
pub struct ContextIncoming<'a> {
    /// Original incoming prefix and mandatory total structural validity.
    pub public: &'a super::IncomingLineageCells,
    /// Checked original claim or its deterministic decoder dummy.
    pub pallas: &'a FoldInputCells<Ep>,
    /// Circuit-fixed original proof source representation.
    pub proof: ContextIncomingProof<'a>,
    /// Checked original Vesta claim or its deterministic decoder dummy.
    pub vesta: &'a VestaClaimCells,
}
/// Every input a continuation can consume, in a circuit-fixed schema.
/// No boolean here asserts that operation semantics have been checked.
pub struct ContextInputs<'a> {
    /// Validated own statement, of the plan's exact variant.
    pub own_statement: &'a StatementCells,
    /// Expected Send/Receive statement, present for incoming-sigma variants.
    pub incoming_statement: Option<&'a IncomingStatementCells>,
    /// Absent exactly for Bootstrap.
    pub predecessor: Option<ContextPredecessor<'a>>,
    /// Current operation's state opening and public header.
    pub successor: ContextState<'a>,
    /// Original incoming lineage, only in incoming-Omega variants.
    pub incoming: Option<ContextIncoming<'a>>,
    /// Exact Q instance columns, in the operation's fixed descriptor order.
    pub q_instances: &'a [Vec<Vec<ScalarCells<Ep>>>],
    /// Fixed object/tape schema; order and capacities cannot be witness-chosen.
    pub objects: &'a [ContextObjectCells],
    /// Global incoming modes: transported P, Omega opening, V, then sigma.
    pub modes: &'a [ModeCells<Fp>],
    /// Native corrections for incoming P and Omega opening, in that order.
    pub pallas_corrections: &'a [NonIdentityPoint<Fp>],
    /// Canonical foreign correction for incoming V, when present. Incoming
    /// sigma correction coordinates belong solely to the hard Q relation.
    pub vesta_corrections: &'a [[ScalarCells<Ep>; 2]],
    /// Complete five-result commitment only for a complete Receive task plan.
    /// These claims must be derived and bound by their typed owning stages.
    pub receive_results: Option<&'a ReceiveResultClaims>,
}
/// Immutable operation/partition schema committed by both split halves.
#[derive(Clone, Debug)]
pub struct ContextPlan {
    operation: AProofPlan,
    stage_q: Vec<Vec<usize>>,
    predecessor_stage: Option<usize>,
    stage_tasks: Vec<Vec<OperationTask>>,
    objects: Vec<ContextObjectSpec>,
    constants: Vec<Fp>,
    receive_results: Option<ReceiveResultPlan>,
}
impl ContextPlan {
    /// Assign proposed Receive object commitments in this plan's exact order.
    /// Each triple is `(object digest, original byte length, tape digest)`.
    ///
    /// These cells only retain a proposal across stages. They do not authenticate
    /// an object, certify a parse, or supply a soft verdict. The fixed Objects,
    /// Proofs and Authorization/Signatures owners must recompute and copy-bind
    /// their exact tapes before the complete stage catalog can be admitted.
    /// This avoids rehashing every unrelated tape in every continuation.
    ///
    /// # Errors
    /// Not a complete Receive task plan, wrong number of commitments, or layout
    /// failure. Lengths outside `UInt32` are unsatisfiable.
    pub fn assign_receive_object_claims(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        values: &[[Value<Fp>; 3]],
    ) -> Result<Vec<ContextObjectCells>, Error> {
        if self.receive_results.is_none()
            || self.objects.len() != 11
            || values.len() != self.objects.len()
        {
            return Err(Error::Synthesis);
        }
        self.objects
            .iter()
            .zip(values)
            .map(|(spec, values)| {
                let [authenticated_digest, length, tape_digest] = chip
                    .uint()
                    .glue()
                    .witnesses(region, values)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let length = chip.uint().range_check::<32>(region, &length)?;
                Ok(ContextObjectCells {
                    spec: *spec,
                    authenticated_digest,
                    length,
                    tape_digest,
                })
            })
            .collect()
    }

    /// Assign proposed quota object triples under the complete fixed owner plan.
    ///
    /// These commitments retain proposed object digests, lengths and tape hashes;
    /// they do not prove byte provenance. Every signed original is recomputed by
    /// the mandatory Effects and authorization owners, while the mandatory merge
    /// owner binds the signed issue time and window count. Root-only stages may
    /// retain these claims without decoding all unrelated signed objects again.
    ///
    /// # Errors
    /// Wrong variant, incomplete task set, different object schema or count,
    /// or layout failure. Lengths outside `UInt32` are unsatisfiable.
    pub fn assign_quota_object_claims(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        values: &[[Value<Fp>; 3]],
    ) -> Result<Vec<ContextObjectCells>, Error> {
        let variant = self.operation.frame().variant();
        if variant != Variant::RefreshQuotaShare
            || self.objects != super::refresh::RefreshObjects::context_specs(variant)?
            || values.len() != self.objects.len()
        {
            return Err(Error::Synthesis);
        }
        OperationTask::validate(variant, &self.stage_tasks)?;
        self.objects
            .iter()
            .zip(values)
            .map(|(spec, values)| {
                let [authenticated_digest, length, tape_digest] = chip
                    .uint()
                    .glue()
                    .witnesses(region, values)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let length = chip.uint().range_check::<32>(region, &length)?;
                Ok(ContextObjectCells {
                    spec: *spec,
                    authenticated_digest,
                    length,
                    tape_digest,
                })
            })
            .collect()
    }

    /// Retain proposed Archive source commitments under its complete owner plan.
    ///
    /// This is only a context assignment, never evidence of byte provenance.
    /// The fixed Archive dispatcher requires the current authorization,
    /// retained Payment, original proof, evidence and signature owners to
    /// recompute each category before terminal mode and map closure. Every
    /// continuation binds these same proposed triples through `D_ctx`.
    /// # Errors
    /// Wrong variant, incomplete task ownership, noncanonical source schema,
    /// wrong value count, or layout failure. Lengths must fit `UInt32`.
    pub fn assign_archive_object_claims(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        values: &[[Value<Fp>; 3]],
    ) -> Result<Vec<ContextObjectCells>, Error> {
        use super::archive::{results::ArchiveResultPlan, stage::ArchiveStagePlan};
        use iroha_plonk_recursion::obligation::ledger::Variant;
        let variant = self.operation.frame().variant();
        let expected_count = match variant {
            Variant::ArchiveReceive => 17,
            Variant::ArchiveStatus => 19,
            _ => return Err(Error::Synthesis),
        };
        if self.objects.len() != expected_count
            || values.len() != expected_count
            || self.objects
                != ArchiveStagePlan::context_specs(
                    variant,
                    self.objects[9].capacity as usize,
                    self.objects[10].capacity as usize,
                    self.objects[13].capacity as usize,
                )?
        {
            return Err(Error::Synthesis);
        }
        ArchiveResultPlan::new(self, expected_count - 1)?;
        self.objects
            .iter()
            .zip(values)
            .map(|(spec, values)| {
                let [authenticated_digest, length, tape_digest] = chip
                    .uint()
                    .glue()
                    .witnesses(region, values)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let length = chip.uint().range_check::<32>(region, &length)?;
                Ok(ContextObjectCells {
                    spec: *spec,
                    authenticated_digest,
                    length,
                    tape_digest,
                })
            })
            .collect()
    }

    /// Pin a nonempty initial Q partition and every source Q key identity.
    /// W's key is pinned only in A2: placing it in A1 would create a VK cycle.
    ///
    /// # Errors
    /// Empty/out-of-range partition, repeated/zero object tags or key mismatch.
    pub fn new(
        operation: AProofPlan,
        first_q: usize,
        objects: Vec<ContextObjectSpec>,
    ) -> Result<Self, Error> {
        let total = operation.q_count();
        if first_q > total {
            return Err(Error::Synthesis);
        }
        let predecessor = operation.frame().has_predecessor().then_some(1);
        Self::with_schedule(
            operation,
            vec![(0..first_q).collect(), (first_q..total).collect()],
            predecessor,
            objects,
        )
    }

    /// Two stages with the hard predecessor P/opening pair assigned to A1.
    /// An empty first Q set is allowed only because the predecessor is hard.
    ///
    /// # Errors
    /// Missing predecessor, out-of-range partition or invalid object schema.
    pub fn with_predecessor_first(
        operation: AProofPlan,
        first_q: usize,
        objects: Vec<ContextObjectSpec>,
    ) -> Result<Self, Error> {
        let total = operation.q_count();
        if first_q > total {
            return Err(Error::Synthesis);
        }
        Self::with_schedule(
            operation,
            vec![(0..first_q).collect(), (first_q..total).collect()],
            Some(0),
            objects,
        )
    }

    /// Pin every ordered Q partition and the hard predecessor's exact stage.
    /// Every Q appears exactly once, and only the last stage can emit a lineage.
    /// Stage0 needs a real Pallas obligation: Q or the hard predecessor pair.
    /// Incoming mode-selected Pallas claims belong to the last stage.
    ///
    /// # Errors
    /// Fewer than two stages, missing/duplicate/reordered Q indices, invalid
    /// predecessor stage, empty first obligation set, or bad object schema.
    pub fn with_schedule(
        operation: AProofPlan,
        stage_q: Vec<Vec<usize>>,
        predecessor_stage: Option<usize>,
        objects: Vec<ContextObjectSpec>,
    ) -> Result<Self, Error> {
        let tasks = vec![Vec::new(); stage_q.len()];
        Self::build(operation, stage_q, predecessor_stage, objects, tasks)
    }
    /// Pin the exact operation task owner stage in the same context as Q keys.
    /// Every required task must occur once. The owning circuit must execute
    /// those constraints; metadata alone never proves an operation transition.
    /// Generic frame component plans intentionally have empty task lists.
    ///
    /// # Errors
    /// Wrong stage count, unsupported operation, missing/duplicate/relabelled
    /// task, or noncanonical task ordering.
    pub fn with_operation_tasks(self, tasks: Vec<Vec<OperationTask>>) -> Result<Self, Error> {
        if tasks.len() != self.stage_count() {
            return Err(Error::Synthesis);
        }
        OperationTask::validate(self.operation.frame().variant(), &tasks)?;
        Self::build(
            self.operation,
            self.stage_q,
            self.predecessor_stage,
            self.objects,
            tasks,
        )
    }
    fn build(
        operation: AProofPlan,
        stage_q: Vec<Vec<usize>>,
        predecessor_stage: Option<usize>,
        objects: Vec<ContextObjectSpec>,
        stage_tasks: Vec<Vec<OperationTask>>,
    ) -> Result<Self, Error> {
        if stage_q.len() < 2
            || predecessor_stage.is_some() != operation.frame().has_predecessor()
            || predecessor_stage.is_some_and(|i| i >= stage_q.len())
            || (stage_q[0].is_empty() && predecessor_stage != Some(0))
            || objects.iter().any(|s| s.tag == 0)
        {
            return Err(Error::Synthesis);
        }
        let mut seen = vec![false; operation.q_count()];
        for group in &stage_q {
            if group.windows(2).any(|w| w[0] >= w[1]) {
                return Err(Error::Synthesis);
            }
            for index in group {
                let used = seen.get_mut(*index).ok_or(Error::Synthesis)?;
                if *used {
                    return Err(Error::Synthesis);
                }
                *used = true;
            }
        }
        if seen.iter().any(|used| !used) {
            return Err(Error::Synthesis);
        }
        for (i, spec) in objects.iter().enumerate() {
            if objects[..i].iter().any(|p| p.tag == spec.tag) {
                return Err(Error::Synthesis);
            }
        }
        let variant = Variant::ALL
            .iter()
            .position(|v| *v == operation.frame().variant())
            .ok_or(Error::Synthesis)?
            + 1;
        let mut constants = [
            1,
            variant,
            1,
            predecessor_stage.map_or(0, |i| i + 1),
            stage_q.len(),
            operation.q_count(),
            objects.len(),
        ]
        .into_iter()
        .map(|v| {
            u64::try_from(v)
                .map(Fp::from)
                .map_err(|_| Error::BoundsFailure)
        })
        .collect::<Result<Vec<_>, _>>()?;
        for (group, tasks) in stage_q.iter().zip(&stage_tasks) {
            constants.push(Fp::from(
                u64::try_from(group.len()).map_err(|_| Error::BoundsFailure)?,
            ));
            for index in group {
                constants.push(Fp::from(
                    u64::try_from(*index).map_err(|_| Error::BoundsFailure)?,
                ));
            }
            constants.push(Fp::from(
                u64::try_from(tasks.len()).map_err(|_| Error::BoundsFailure)?,
            ));
            constants.extend(tasks.iter().map(|task| Fp::from(u64::from(task.code()))));
        }
        for index in 0..operation.q_count() {
            let q = operation.q(index).ok_or(Error::Synthesis)?;
            constants.push(
                q.key
                    .kagemusha_digest(q.verifier().binding())
                    .map_err(|_| Error::Synthesis)?,
            );
            for limb in q.verifier().binding().digest().chunks_exact(16) {
                constants.push(Fp::from_u128(u128::from_le_bytes(
                    limb.try_into().map_err(|_| Error::Synthesis)?,
                )));
            }
            let d = q.verifier().binding().descriptor();
            constants.push(Fp::from(
                u64::try_from(d.instance_lengths.len()).map_err(|_| Error::BoundsFailure)?,
            ));
            constants.extend(d.instance_lengths.iter().map(|n| Fp::from(u64::from(*n))));
        }
        for spec in &objects {
            constants.extend([
                Fp::from(u64::from(spec.tag)),
                Fp::from(u64::from(spec.capacity)),
            ]);
        }
        let receive_results = if matches!(
            operation.frame().variant(),
            Variant::Receive | Variant::ReceiveRenewed
        ) && stage_tasks.iter().any(|tasks| !tasks.is_empty())
        {
            let plan = ReceiveResultPlan::from_tasks(operation.frame().variant(), &stage_tasks)?;
            // This fixed Receive schema binds original active tape slot4 once,
            // with parsing assigned to the mandatory Proofs owner. It cannot be
            // confused with a frame retaining explicit decoded message cells.
            constants.extend([
                Fp::from(u64::from_le_bytes(*b"kgwcrcv1")),
                Fp::from(4),
                Fp::from(3),
                Fp::from(u64::from_le_bytes(*b"kgwcqtp1")),
            ]);
            constants.extend([
                Fp::from(u64::from_le_bytes(RECEIVE_RESULTS_DOMAIN)),
                Fp::from(5),
            ]);
            for (tag, owner) in plan.schema() {
                constants.extend([Fp::from(u64::from(tag)), Fp::from(u64::from(owner))]);
            }
            constants.extend([
                Fp::from(u64::from_le_bytes(RECEIVE_OPENING_DOMAIN)),
                Fp::from(35),
            ]);
            // Receive's deferred opening is interpreted only under these
            // exact fixed proof programs; the carried key is bound by public18.
            constants.push(Fp::from(u64::from_le_bytes(*b"kgwrcls1")));
            for binding in std::iter::once(operation.omega().ok_or(Error::Synthesis)?.binding())
                .chain(
                    (0..2)
                        .map(|slot| {
                            operation
                                .sigma
                                .class(slot)
                                .map(|class| class.verifier().binding())
                        })
                        .collect::<Option<Vec<_>>>()
                        .ok_or(Error::Synthesis)?,
                )
            {
                constants.push(Fp::from(u64::from(binding.descriptor().k)));
                for limb in binding.digest().chunks_exact(16) {
                    constants.push(Fp::from_u128(u128::from_le_bytes(
                        limb.try_into().map_err(|_| Error::Synthesis)?,
                    )));
                }
            }
            Some(plan)
        } else {
            None
        };
        Ok(Self {
            operation,
            stage_q,
            predecessor_stage,
            stage_tasks,
            objects,
            constants,
            receive_results,
        })
    }
    /// Complete result ownership fixed by an actual Receive task schedule.
    /// Generic frame components and other operations have no result plan.
    pub const fn receive_results(&self) -> Option<ReceiveResultPlan> {
        self.receive_results
    }
    /// Fixed ordered external object categories and byte capacities.
    pub fn object_specs(&self) -> &[ContextObjectSpec] {
        &self.objects
    }
    /// Fixed version/variant/partition, source key identities and object schema.
    /// These words prefix the circuit context preimage in the exact returned order.
    pub fn schema(&self) -> &[Fp] {
        &self.constants
    }
    /// The complete operation plan, retained across all stages.
    pub const fn operation(&self) -> &AProofPlan {
        &self.operation
    }
    /// Number of Q slots assigned to the initial stage.
    pub fn first_q_count(&self) -> usize {
        self.stage_q[0].len()
    }
    /// Fixed number of A stages; only the last stage can emit a lineage.
    pub fn stage_count(&self) -> usize {
        self.stage_q.len()
    }
    /// Exact ordered Q indices assigned to a stage, with no repetitions.
    pub fn q_partition(&self, stage: usize) -> Option<&[usize]> {
        self.stage_q.get(stage).map(Vec::as_slice)
    }
    /// Fixed operation tasks assigned to this stage. Empty for a frame-only
    /// component; the task schema itself is never an authentication verdict.
    pub fn operation_tasks(&self, stage: usize) -> Option<&[OperationTask]> {
        self.stage_tasks.get(stage).map(Vec::as_slice)
    }
    /// Stage containing the hard predecessor P/opening pair; absent for Bootstrap.
    pub const fn predecessor_stage(&self) -> Option<usize> {
        self.predecessor_stage
    }
    /// Whether the predecessor pair is closed into A1's carried claim.
    pub const fn predecessor_in_first(&self) -> bool {
        matches!(self.predecessor_stage, Some(0))
    }
    /// Exact fixed global incoming-mode count in the root context.
    pub fn mode_count(&self) -> usize {
        3 * usize::from(self.operation.frame().has_incoming())
            + usize::from(self.operation.sigma.slot_count() == 2)
    }
    /// Recompute the complete immutable operation context, excluding stage claims.
    /// The consumer must additionally bind the appropriate verified Q partition
    /// using [`Self::bind_q_partition`] and verify W or produce the A1 proof.
    ///
    /// # Errors
    /// Wrong variant, presence, group size/order or layout failure.
    pub fn digest(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: &ContextInputs<'_>,
    ) -> Result<Word<Fp>, Error> {
        let incoming_sigma = self.operation.sigma.slot_count() == 2;
        let incoming_omega = self.operation.frame().has_incoming();
        if input.own_statement.variant() != self.operation.frame().variant()
            || input.predecessor.is_some() != self.operation.frame().has_predecessor()
            || input.incoming.is_some() != incoming_omega
            || input.incoming_statement.is_some() != incoming_sigma
            || input.q_instances.len() != self.operation.q_count()
            || input.objects.len() != self.objects.len()
            || input.modes.len() != self.mode_count()
            || input.pallas_corrections.len() != 2 * usize::from(incoming_omega)
            || input.vesta_corrections.len() != usize::from(incoming_omega)
            || input.receive_results.is_some() != self.receive_results.is_some()
        {
            return Err(Error::Synthesis);
        }
        let mut words = self
            .constants
            .iter()
            .map(|v| chip.uint().glue().constant(region, *v))
            .collect::<Result<Vec<_>, _>>()?;
        words.extend(input.own_statement.fields().iter().cloned());
        if let Some(statement) = input.incoming_statement {
            words.extend(statement.fields().iter().cloned());
        }
        if let Some(pred) = input.predecessor {
            pred.state
                .bind_lineage(&mut chip.uint(), region, pred.public)?;
            words.extend(pred.state.core().iter().cloned());
            words.extend(pred.state.rest().iter().cloned());
            words.extend(pred.public.fields().iter().cloned());
            push_pallas(&mut words, pred.pallas)?;
            if pred.vesta.source_k() != 16 {
                return Err(Error::Synthesis);
            }
            words.extend(pred.vesta.words());
        }
        let state = input.successor;
        state
            .state
            .bind_lineage(&mut chip.uint(), region, state.public)?;
        words.extend(state.state.core().iter().cloned());
        words.extend(state.state.rest().iter().cloned());
        words.extend(state.public.fields().iter().cloned());
        if let Some(incoming) = input.incoming {
            words.extend(incoming.public.fields().iter().cloned());
            words.push(incoming.public.valid().word().clone());
            push_pallas(&mut words, incoming.pallas)?;
            if incoming.vesta.source_k() != 16 {
                return Err(Error::Synthesis);
            }
            words.extend(incoming.vesta.words());
            match self.incoming_proof_binding(input)? {
                super::proof::IncomingProofBinding::Messages(proof) => {
                    words.push(proof.length().word().clone());
                    for message in proof.messages() {
                        push_message_context(&mut words, chip, region, message)?;
                    }
                }
                super::proof::IncomingProofBinding::ReceiveActive(_) => {
                    // Exact original length/tape commitment is included below
                    // in fixed slot4. The Proofs owner derives the only message
                    // view that can supply the authenticated opening/result.
                }
            }
        }
        for (index, columns) in input.q_instances.iter().enumerate() {
            let d = self
                .operation
                .q(index)
                .ok_or(Error::Synthesis)?
                .verifier()
                .binding()
                .descriptor();
            if columns.len() != d.instance_lengths.len()
                || columns
                    .iter()
                    .zip(&d.instance_lengths)
                    .any(|(c, n)| c.len() != *n as usize)
            {
                return Err(Error::Synthesis);
            }
            let types = d.instance_types.as_ref().ok_or(Error::Synthesis)?;
            if types.len() != columns.len() {
                return Err(Error::Synthesis);
            }
            for (column, ty) in columns.iter().zip(types) {
                for value in column {
                    push_q_context(
                        &mut words,
                        chip,
                        region,
                        value,
                        *ty,
                        self.receive_results.is_some(),
                    )?;
                }
            }
        }
        for (spec, object) in self.objects.iter().zip(input.objects) {
            if spec != &object.spec {
                return Err(Error::Synthesis);
            }
            words.extend(object.commitment_words());
        }
        if let Some(plan) = self.receive_results {
            words.extend(
                input
                    .receive_results
                    .ok_or(Error::Synthesis)?
                    .context_words(plan)?,
            );
        }
        for mode in input.modes {
            words.extend([
                mode.accept().word().clone(),
                mode.trivial().word().clone(),
                mode.corrected().word().clone(),
            ]);
        }
        for point in input.pallas_corrections {
            words.extend([point.x().clone(), point.y().clone()]);
        }
        for coordinates in input.vesta_corrections {
            for value in coordinates {
                words.extend([value.lo().word().clone(), value.hi().word().clone()]);
            }
        }
        chip.hash_words(region, u64::from_le_bytes(CONTEXT_DOMAIN), &words)
    }

    /// Bind an immutable context and its exact carried Pallas claim to one
    /// circuit-fixed internal A stage. The next stage recomputes this digest
    /// before hard-verifying the immediately preceding W key. Earlier claims
    /// remain in the P/V folds; no historical hash trace is required.
    ///
    /// # Errors
    /// Terminal/out-of-range stage, non-k16 claim or synthesis failure.
    pub fn stage_digest(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: usize,
        context: &Word<Fp>,
        carried: &FoldInputCells<Ep>,
    ) -> Result<Word<Fp>, Error> {
        let ordinal = stage.checked_add(1).ok_or(Error::BoundsFailure)?;
        if ordinal >= self.stage_count() {
            return Err(Error::Synthesis);
        }
        let mut words = [
            Fp::ONE,
            *self.schema().get(1).ok_or(Error::Synthesis)?,
            Fp::from(u64::try_from(ordinal).map_err(|_| Error::BoundsFailure)?),
        ]
        .into_iter()
        .map(|value| chip.uint().glue().constant(region, value))
        .collect::<Result<Vec<_>, _>>()?;
        words.push(context.clone());
        push_pallas(&mut words, carried)?;
        chip.hash_words(region, u64::from_le_bytes(STAGE_DOMAIN), &words)
    }

    pub(super) fn incoming_proof_binding(
        &self,
        input: &ContextInputs<'_>,
    ) -> Result<super::proof::IncomingProofBinding, Error> {
        use super::proof::IncomingProofBinding;
        match (
            input.incoming.ok_or(Error::Synthesis)?.proof,
            self.receive_results,
        ) {
            (ContextIncomingProof::Messages(proof), None) => {
                let omega = self.operation.omega().ok_or(Error::Synthesis)?;
                if proof.messages().len().checked_mul(32) != Some(omega.proof_length()) {
                    return Err(Error::Synthesis);
                }
                Ok(IncomingProofBinding::Messages(proof.clone()))
            }
            (ContextIncomingProof::ReceiveActive, Some(_))
                if self.objects.len() == 11 && input.objects.len() == 11 =>
            {
                Ok(IncomingProofBinding::ReceiveActive(
                    input.objects[4].commitment_words(),
                ))
            }
            _ => Err(Error::Synthesis),
        }
    }
    /// Copy-bind exactly one fixed Q partition to its hard verifier outputs.
    /// The stage index selects a circuit-fixed Q partition. All stages hash
    /// every Q instance, preventing deferred-instance substitution.
    ///
    /// # Errors
    /// Missing, duplicate, reordered or wrong-shaped Q outputs; layout failure.
    pub fn bind_q_partition(
        &self,
        region: &mut Region<'_, Fp>,
        input: &ContextInputs<'_>,
        verified: &[VerifiedQCells],
        stage: usize,
    ) -> Result<(), Error> {
        let indices = self.q_partition(stage).ok_or(Error::Synthesis)?;
        if verified.len() != indices.len() || input.q_instances.len() != self.operation.q_count() {
            return Err(Error::Synthesis);
        }
        for (expected, q) in indices.iter().copied().zip(verified) {
            let fixed = self.operation.q(expected).ok_or(Error::Synthesis)?;
            let digest = fixed
                .key
                .kagemusha_digest(fixed.verifier().binding())
                .map_err(|_| Error::Synthesis)?;
            GlueChip::assert_constant(region, &q.key_digest, digest)?;
            let columns = &input.q_instances[expected];
            if q.index != expected || q.instances.len() != columns.len() {
                return Err(Error::Synthesis);
            }
            for (actual, wanted) in q.instances.iter().zip(columns) {
                if actual.len() != wanted.len() {
                    return Err(Error::Synthesis);
                }
                for (a, b) in actual.iter().zip(wanted) {
                    GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
                    GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
                }
            }
        }
        Ok(())
    }
}
fn push_pallas(words: &mut Vec<Word<Fp>>, claim: &FoldInputCells<Ep>) -> Result<(), Error> {
    if claim.source() != FoldSource::Fixed(16) {
        return Err(Error::Synthesis);
    }
    words.extend([
        claim.source_k().clone(),
        claim.g().x().clone(),
        claim.g().y().clone(),
    ]);
    for value in claim.challenges() {
        words.extend([value.lo().word().clone(), value.hi().word().clone()]);
    }
    Ok(())
}
