//! Source-bound native SCCP forgery verification and executing-parent publication (§4.9).
//!
//! This is a committed-view precheck, not instruction admission or an evidence record.
//! A candidate borrows the retained generation and submission. It neither snapshots a
//! caller-authored committee nor grants execution, penalty, fee or queue authority.
//!
//! Ingress, proposer selection and the direct sole-signed entrypoint have distinct
//! owners. They share the exact native relation and permanent dedup query; execution
//! always rechecks its original parent and S0 clock. Penalty and R-EX integration are
//! required before the operation is release-qualified.

use iroha_data_model::sccp::generation::{
    SccpAnchorV1, SccpGenerationMemberV1, next_liability_clock_v1,
};
use std::sync::atomic::Ordering;
use std::time::Instant;

use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_crypto::{
    Hash,
    bls::consensus::{ConsensusAggregateScratch, ConsensusDigest},
};
use iroha_data_model::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::native::SccpForgeryRuleV1,
    sumeragi_finality::certified_result::{SccpFinalityHeaderV1, outer_result},
};
use iroha_sccp::v1::{
    evidence::{anchor_chunk_position, forgery_evidence_id},
    finality::{QcFixedV1, check_signers, commit_preimage},
};
use iroha_sumeragi::{preimage::TAG_INSTANCE, types::Hash32};

use super::{
    anchors::{SccpAnchorLookupError, lookup_anchor},
    generation_record::RetainedSccpGeneration,
    params,
    read::native::SccpNativeReadControl,
    store,
};
use super::{eligibility::Current, original_read::OriginalRead};
use crate::state::{NativeExecutionTip, StateReadOnly, StateView, WorldReadOnly};

mod execution;
pub mod keeper;
mod restoration;
pub(crate) use execution::{ForgeryExecutionError, execute_forgery};
pub(crate) use restoration::SccpRestore;

/// Protocol refusals stay separate from local source, allocation, deadline or stop refusals.
#[derive(Clone, Debug, thiserror::Error)]
#[allow(
    variant_size_differences,
    reason = "local admission refusal must retain its original inline retry owner without allocating"
)]
pub enum ForgeryVerificationError {
    /// No SCCP claim or no E1–E4 mismatch against this observation.
    #[error("not SCCP forgery evidence")]
    NotEvidence,
    /// The generation's liability or required anchor has expired.
    #[error("SCCP evidence expired")]
    EvidenceExpired,
    /// The claimed generation is later than the current retained generation.
    #[error("unknown SCCP generation")]
    EvidenceUnknownGeneration,
    /// Exact-quorum native certificate verification failed.
    #[error("bad SCCP forgery certificate signature")]
    BadSignature,
    /// The signed past height is in a completed chunk and needs its original witness.
    #[error("SCCP anchor witness required")]
    WitnessRequired,
    /// The submitted anchor path fails the retained completed root.
    #[error("bad SCCP anchor witness")]
    BadWitness,
    /// This view lacks an internally consistent original native source.
    #[error("SCCP forgery source unavailable: {0}")]
    Unavailable(&'static str),
    /// The authenticated root is not Global; offered X cannot change its scope.
    #[error("SCCP forgery requires the original Global root")]
    UnsupportedScope,
    /// The caller's original finite pool refused the exact pairing scratch demand.
    #[error(transparent)]
    Allocation(#[from] AllocationRefusal),
    /// The caller's admitted worker was cancelled.
    #[error("SCCP forgery verification cancelled")]
    Cancelled,
    /// The original caller deadline expired.
    #[error("SCCP forgery verification deadline expired")]
    Deadline,
}

type Result<T> = core::result::Result<T, ForgeryVerificationError>;

/// Verified steps 1–6 against one committed observation, **before** deduplication.
///
/// No decoder, public constructor or owned-record conversion exists. Borrowed member
/// accounts retain their generation's original funding/lifetime. A later observation must
/// reverify: E2 may cease to be evidence and the liability window may close. This candidate
/// must never be used as an execution receipt or to bypass the ingress pairing-rate owner.
/// Copies keep the same borrowed observation; they are not one-shot admission tokens.
#[derive(Clone, Copy)]
pub struct VerifiedForgeryCandidate<'a> {
    evidence: &'a SubmitSccpForgeryEvidenceV1,
    generation: &'a RetainedSccpGeneration,
    parent: NativeExecutionTip,
    execution_height: u64,
    liability_clock: u64,
    instance: Hash32,
    qc: QcFixedV1,
    result: [u8; 32],
    message: [u8; 32],
    rule: SccpForgeryRuleV1,
}

impl<'a> VerifiedForgeryCandidate<'a> {
    /// Borrow the exact submission that supplied X, QC, signature and optional witness.
    #[must_use]
    pub const fn evidence(&self) -> &'a SubmitSccpForgeryEvidenceV1 {
        self.evidence
    }
    /// Borrow the original generation, including unchanged G6 lane/account/activation binds.
    #[must_use]
    pub const fn generation(&self) -> &'a RetainedSccpGeneration {
        self.generation
    }
    /// The immutable executed tip used for this observation; never a tip reconstructed from X.
    #[must_use]
    pub const fn parent(&self) -> NativeExecutionTip {
        self.parent
    }
    /// Hypothetical next height of this committed-view precheck, not an execution grant.
    #[must_use]
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }
    /// Liability clock advanced from the original parent and supplied transaction time.
    #[must_use]
    pub const fn liability_clock(&self) -> u64 {
        self.liability_clock
    }
    /// The original Global instance, independent of signed QC epoch/context assertions.
    #[must_use]
    pub const fn instance(&self) -> Hash32 {
        self.instance
    }
    /// Signed QC fields; epoch and context are signed assertions, not scheduling authority.
    #[must_use]
    pub const fn qc(&self) -> &QcFixedV1 {
        &self.qc
    }
    /// Raw SHA-256 certified result, without Iroha marker normalization.
    #[must_use]
    pub const fn result(&self) -> &[u8; 32] {
        &self.result
    }
    /// Actual allowlisted native Commit message digest.
    #[must_use]
    pub const fn message(&self) -> &[u8; 32] {
        &self.message
    }
    /// First matching E1–E4 rule, after successful signature verification.
    #[must_use]
    pub const fn rule(&self) -> SccpForgeryRuleV1 {
        self.rule
    }
    /// Exact evidence identity; it does not establish absence from the offence index.
    #[must_use]
    pub fn evidence_id(&self) -> [u8; 32] {
        forgery_evidence_id(self.generation.generation, &self.message, self.qc.signers)
    }
    /// Every set signer bit in canonical order, with its original optional G6 member.
    /// `None` is unslashable and must not be replaced by a current peer/key lookup.
    pub fn signers(
        &self,
    ) -> impl Iterator<Item = (u32, &'a [u8; 48], Option<&'a SccpGenerationMemberV1>)> + '_ {
        let generation = self.generation;
        (0_u32..)
            .zip(generation.keys.iter().zip(&generation.members))
            .filter(move |(index, _)| self.qc.signers & (1_u32 << index) != 0)
            .map(|(index, (key, member))| (index, key, member.as_ref()))
    }
}

/// Verify §4.9 steps 1–6 against an already acquired committed view.
///
/// `transaction_time_ms` is the original transaction's creation time at precheck. The
/// original caller pool funds exactly one native pairing context; its backing is released
/// before its charge. All source/member graphs remain borrowed, all temporary key lists
/// are stack bounded, and there is no state write. Local refusal is not a bad-evidence verdict.
///
/// # Errors
/// Preserves step order: claim, generation/root, E0, signature, first mismatch. It also
/// preserves typed source/local resource refusals. This is deliberately **not** the §4.9
/// ingress admission pipeline, whose cheap mismatch/dedup/rate checks precede pairing.
pub fn verify_committed<'a>(
    view: &'a StateView<'_>,
    evidence: &'a SubmitSccpForgeryEvidenceV1,
    transaction_time_ms: u64,
    budget: &AllocationBudget,
    control: SccpNativeReadControl<'_>,
) -> Result<VerifiedForgeryCandidate<'a>> {
    check_control(control)?;
    let parameters =
        params::parameters(view.world()).ok_or(ForgeryVerificationError::NotEvidence)?;
    let header = SccpFinalityHeaderV1::parse(&evidence.header)
        .map_err(|_| ForgeryVerificationError::NotEvidence)?;
    if !header.is_active() || header.network_id() != *view.network_id().as_bytes() {
        return Err(ForgeryVerificationError::NotEvidence);
    }
    let (parent, instance) = original_source(view)?;
    let execution_height =
        parent
            .height()
            .checked_add(1)
            .ok_or(ForgeryVerificationError::Unavailable(
                "next height overflows",
            ))?;
    let liability_clock = next_liability_clock_v1(
        *store::liability_clock::get(view.world()),
        parent.creation_time_ms(),
        transaction_time_ms,
        parameters.committee_heartbeat_ms,
    );
    verify_observation(
        Current(view.world()),
        evidence,
        header,
        Observation {
            parent,
            instance,
            execution_height,
            liability_clock,
        },
        budget,
        VerificationControl::Read(control),
    )
}

#[derive(Clone, Copy)]
struct Observation {
    parent: NativeExecutionTip,
    instance: Hash32,
    execution_height: u64,
    liability_clock: u64,
}

/// Node-local scheduling control only; it grants no evidence or execution authority.
/// Synchronous ingress/execution already has bounded one-pairing work and no read deadline.
#[derive(Clone, Copy)]
pub(crate) enum VerificationControl<'a> {
    Read(SccpNativeReadControl<'a>),
    Synchronous,
}
impl VerificationControl<'_> {
    fn check(self) -> Result<()> {
        match self {
            Self::Read(control) => check_control(control),
            Self::Synchronous => Ok(()),
        }
    }
}

fn verify_observation<'a>(
    world: impl OriginalRead<'a> + 'a,
    evidence: &'a SubmitSccpForgeryEvidenceV1,
    header: SccpFinalityHeaderV1,
    observation: Observation,
    budget: &AllocationBudget,
    control: VerificationControl<'_>,
) -> Result<VerifiedForgeryCandidate<'a>> {
    let Observation {
        parent,
        instance,
        execution_height,
        liability_clock,
    } = observation;
    let current = world.committee_current();
    let generation = generation_for_claim(world, &header, current, liability_clock)?;
    let qc = QcFixedV1::parse(&evidence.qc).map_err(|_| ForgeryVerificationError::BadSignature)?;
    let result = outer_result(&header, &qc.result_body).0;
    let message = verify_signature(
        generation,
        instance,
        &header,
        &qc,
        &evidence.aggregate_signature,
        budget,
        control,
    )?;
    control.check()?;
    let rule = mismatch_for_observation(
        world,
        evidence,
        &header,
        generation,
        observation,
        &qc,
        result,
    )?;
    control.check()?;
    Ok(VerifiedForgeryCandidate {
        evidence,
        generation,
        parent,
        execution_height,
        liability_clock,
        instance,
        qc,
        result,
        message,
        rule,
    })
}

fn mismatch_for_observation<'a>(
    world: impl OriginalRead<'a> + 'a,
    evidence: &SubmitSccpForgeryEvidenceV1,
    header: &SccpFinalityHeaderV1,
    generation: &RetainedSccpGeneration,
    observation: Observation,
    qc: &QcFixedV1,
    result: [u8; 32],
) -> Result<SccpForgeryRuleV1> {
    let Observation {
        parent,
        execution_height,
        ..
    } = observation;
    first_mismatch(
        generation,
        execution_height,
        header.height(),
        qc,
        result,
        || {
            let (chunk, _) = anchor_chunk_position(header.height()).ok_or(
                ForgeryVerificationError::Unavailable("invalid anchor height"),
            )?;
            let witness_anchor = evidence.anchor.as_ref().map(|w| SccpAnchorV1 {
                core_hash: w.core_hash,
                result: w.result,
            });
            let witness = witness_anchor
                .as_ref()
                .zip(evidence.anchor.as_ref())
                .map(|(a, w)| (a, &w.path));
            #[cfg(all(test, sumeragi_core_mutation = "HC317"))]
            let parent_core_hash = *parent.iroha_hash().as_ref();
            #[cfg(not(all(test, sumeragi_core_mutation = "HC317")))]
            let parent_core_hash = parent.core_hash().0;
            lookup_anchor(
                parent.height(),
                SccpAnchorV1 {
                    core_hash: parent_core_hash,
                    result: parent.result().0,
                },
                world.anchor_open(),
                header.height(),
                world.anchor_chunk(chunk),
                witness,
            )
            .map_err(anchor_error)
        },
    )
}

/// Cheap source-bound ingress observation before the node-wide pairing gate.
/// There is no conversion into a record or verified candidate without the actual pairing.
#[derive(Clone, Copy)]
pub(crate) struct ForgeryPrecheck<'a> {
    evidence: &'a SubmitSccpForgeryEvidenceV1,
    generation: &'a RetainedSccpGeneration,
    observation: Observation,
    qc: QcFixedV1,
    result: [u8; 32],
    message: [u8; 32],
    rule: SccpForgeryRuleV1,
}
impl<'a> ForgeryPrecheck<'a> {
    /// Borrow the original retained generation and G6 member bindings.
    pub(crate) fn generation(&self) -> &'a RetainedSccpGeneration {
        self.generation
    }
    /// Read parsed signed fields without assigning scheduling authority.
    pub(crate) fn qc(&self) -> &QcFixedV1 {
        &self.qc
    }
    /// Exact native Commit digest used by the pairing and node LRU.
    pub(crate) fn message(&self) -> &[u8; 32] {
        &self.message
    }
}

/// Run the cheap ingress claim/generation/E0/mismatch checks against one retained view.
/// The caller must perform permanent dedup, original node LRU and rate admission before
/// `verify_prechecked`. This function neither performs a pairing nor admits a transaction.
pub(crate) fn prepare_committed<'a>(
    view: &'a StateView<'_>,
    evidence: &'a SubmitSccpForgeryEvidenceV1,
    transaction_time_ms: u64,
) -> Result<ForgeryPrecheck<'a>> {
    let parameters =
        params::parameters(view.world()).ok_or(ForgeryVerificationError::NotEvidence)?;
    let header = SccpFinalityHeaderV1::parse(&evidence.header)
        .map_err(|_| ForgeryVerificationError::NotEvidence)?;
    if !header.is_active() || header.network_id() != *view.network_id().as_bytes() {
        return Err(ForgeryVerificationError::NotEvidence);
    }
    let (parent, instance) = original_source(view)?;
    let execution_height =
        parent
            .height()
            .checked_add(1)
            .ok_or(ForgeryVerificationError::Unavailable(
                "next height overflows",
            ))?;
    let liability_clock = next_liability_clock_v1(
        *store::liability_clock::get(view.world()),
        parent.creation_time_ms(),
        transaction_time_ms,
        parameters.committee_heartbeat_ms,
    );
    let observation = Observation {
        parent,
        instance,
        execution_height,
        liability_clock,
    };
    let generation = generation_for_claim(
        Current(view.world()),
        &header,
        *store::committee_current::get(view.world()),
        liability_clock,
    )?;
    let qc = QcFixedV1::parse(&evidence.qc).map_err(|_| ForgeryVerificationError::BadSignature)?;
    check_signers(qc.signers, generation.keys.len())
        .map_err(|_| ForgeryVerificationError::BadSignature)?;
    let result = outer_result(&header, &qc.result_body).0;
    let rule = mismatch_for_observation(
        Current(view.world()),
        evidence,
        &header,
        generation,
        observation,
        &qc,
        result,
    )?;
    let preimage = commit_preimage(&instance.0, &qc, header.height(), &result);
    let digest =
        ConsensusDigest::from_preimage(&preimage).ok_or(ForgeryVerificationError::BadSignature)?;
    Ok(ForgeryPrecheck {
        evidence,
        generation,
        observation,
        qc,
        result,
        message: *digest.as_bytes(),
        rule,
    })
}

/// Perform the actual native pairing after the original node's rate/duplicate gate.
/// Synchronous ingress has bounded one-pairing work; it does not invent a read timeout.
pub(crate) fn verify_prechecked<'a>(
    precheck: &ForgeryPrecheck<'a>,
    budget: &AllocationBudget,
) -> Result<VerifiedForgeryCandidate<'a>> {
    let header = SccpFinalityHeaderV1::parse(&precheck.evidence.header)
        .map_err(|_| ForgeryVerificationError::NotEvidence)?;
    let message = verify_signature(
        precheck.generation,
        precheck.observation.instance,
        &header,
        &precheck.qc,
        &precheck.evidence.aggregate_signature,
        budget,
        VerificationControl::Synchronous,
    )?;
    if message != precheck.message {
        return Err(ForgeryVerificationError::Unavailable(
            "prepared signature message changed",
        ));
    }
    Ok(VerifiedForgeryCandidate {
        evidence: precheck.evidence,
        generation: precheck.generation,
        parent: precheck.observation.parent,
        instance: precheck.observation.instance,
        execution_height: precheck.observation.execution_height,
        liability_clock: precheck.observation.liability_clock,
        qc: precheck.qc,
        result: precheck.result,
        message,
        rule: precheck.rule,
    })
}

/// Exact permanent offence selection shared by ingress, proposal and executing preparation.
/// This is a funded map query, not signature or execution authority. Repeated keys in a
/// malformed member list cannot make one validator become two new offences.
pub(crate) fn new_signers(
    world: &impl WorldReadOnly,
    generation: &RetainedSccpGeneration,
    signers: u32,
    budget: &AllocationBudget,
) -> core::result::Result<u32, crate::state::sccp_forgery_custody::ForgeryStorageError> {
    use crate::state::sccp_forgery_custody::{ForgeryStorageError, OffenceKey};
    if !generation.is_well_formed() || check_signers(signers, generation.keys.len()).is_err() {
        return Err(ForgeryStorageError::Invalid);
    }
    let mut selected = 0_u32;
    for (index, member) in generation.members.iter().enumerate() {
        if signers & (1_u32 << index) == 0 {
            continue;
        }
        let Some(member) = member else {
            continue;
        };
        if generation.members[..index]
            .iter()
            .enumerate()
            .any(|(earlier, other)| {
                selected & (1_u32 << earlier) != 0
                    && other.as_ref().is_some_and(|other| {
                        other.lane_id == member.lane_id && other.validator == member.validator
                    })
            })
        {
            continue;
        }
        let key = OffenceKey::try_copy(
            generation.generation,
            member.lane_id,
            &member.validator,
            budget,
        )?;
        if store::forgery_offences::get(world, &key).is_none() {
            selected |= 1_u32 << index;
        }
    }
    Ok(selected)
}

/// Recheck an honest proposal's evidence against its exact retained committed parent.
/// The candidate time must be computed from all selected inputs. Removing evidence may
/// change that time, so the builder must recompute/recheck before sealing; no receipt here
/// can be reused as execution authority. Ingress LRU/rate limits do not apply to this check.
pub(crate) fn verify_for_proposal(
    view: &StateView<'_>,
    expected_parent: &iroha_data_model::block::SignedBlock,
    evidence: &SubmitSccpForgeryEvidenceV1,
    canonical_time_ms: u64,
    budget: &AllocationBudget,
) -> core::result::Result<(), ForgeryExecutionError> {
    let parameters =
        params::parameters(view.world()).ok_or(ForgeryVerificationError::NotEvidence)?;
    let header = SccpFinalityHeaderV1::parse(&evidence.header)
        .map_err(|_| ForgeryVerificationError::NotEvidence)?;
    if !header.is_active() || header.network_id() != *view.network_id().as_bytes() {
        return Err(ForgeryVerificationError::NotEvidence.into());
    }
    let (parent, instance) = original_source(view)?;
    if expected_parent.hash() != parent.iroha_hash()
        || expected_parent.header().height().get() != parent.height()
        || expected_parent.header().creation_time_ms != parent.creation_time_ms()
        || canonical_time_ms <= parent.creation_time_ms()
    {
        return Err(ForgeryVerificationError::Unavailable(
            "proposal parent/time differs from original tip",
        )
        .into());
    }
    let execution_height =
        parent
            .height()
            .checked_add(1)
            .ok_or(ForgeryVerificationError::Unavailable(
                "next height overflows",
            ))?;
    let liability_clock = next_liability_clock_v1(
        *store::liability_clock::get(view.world()),
        parent.creation_time_ms(),
        canonical_time_ms,
        parameters.committee_heartbeat_ms,
    );
    let checked = verify_observation(
        Current(view.world()),
        evidence,
        header,
        Observation {
            parent,
            instance,
            execution_height,
            liability_clock,
        },
        budget,
        VerificationControl::Synchronous,
    )?;
    if new_signers(
        view.world(),
        checked.generation(),
        checked.qc().signers,
        budget,
    )? == 0
    {
        return Err(ForgeryExecutionError::EvidenceDuplicate);
    }
    Ok(())
}

fn generation_for_claim<'a>(
    world: impl OriginalRead<'a> + 'a,
    header: &SccpFinalityHeaderV1,
    current: u64,
    liability_clock: u64,
) -> Result<&'a RetainedSccpGeneration> {
    let generation =
        world
            .generation(header.generation())
            .ok_or(if header.generation() <= current {
                ForgeryVerificationError::EvidenceExpired
            } else {
                ForgeryVerificationError::EvidenceUnknownGeneration
            })?;
    if header.committee_root() != generation.committee_root {
        return Err(ForgeryVerificationError::NotEvidence);
    }
    if generation.generation != header.generation() || !generation.is_well_formed() {
        return Err(ForgeryVerificationError::Unavailable(
            "retained generation is inconsistent",
        ));
    }
    if !cfg!(all(test, sumeragi_core_mutation = "HC316"))
        && !generation.is_liable(current, liability_clock)
    {
        return Err(ForgeryVerificationError::EvidenceExpired);
    }
    Ok(generation)
}

fn original_source(view: &impl StateReadOnly) -> Result<(NativeExecutionTip, Hash32)> {
    let parent = view
        .native_execution_tip()
        .ok_or(ForgeryVerificationError::Unavailable(
            "original native tip is absent",
        ))?;
    if u64::try_from(view.height()) != Ok(parent.height())
        || view
            .height()
            .checked_sub(1)
            .and_then(|i| view.block_hashes().get(i))
            != Some(&parent.iroha_hash())
        || view
            .block_hashes()
            .get(0)
            .map(|h| NetworkId::from_genesis_hash(*h))
            != Some(*view.network_id())
    {
        return Err(ForgeryVerificationError::Unavailable(
            "tip, journal and network disagree",
        ));
    }
    let scope = parent.root_scope();
    if scope != SumeragiRootScope::Global {
        return Err(ForgeryVerificationError::UnsupportedScope);
    }
    // Exact preimage::instance_id, streamed through BlsCrypto's native hash relation. The
    // generic helper builds a Vec; this fixed Global derivation allocates no chain-label copy.
    let instance = Hash32(
        Hash::new_from_chunks(&[
            TAG_INSTANCE,
            view.network_id().as_bytes(),
            view.chain_id().as_str().as_bytes(),
            &[scope.instance_kind().byte()],
            &0_u32.to_be_bytes(),
        ])
        .into(),
    );
    Ok((parent, instance))
}

fn verify_signature(
    generation: &RetainedSccpGeneration,
    instance: Hash32,
    header: &SccpFinalityHeaderV1,
    qc: &QcFixedV1,
    signature: &[u8; 96],
    budget: &AllocationBudget,
    control: VerificationControl<'_>,
) -> Result<[u8; 32]> {
    check_signers(qc.signers, generation.keys.len())
        .map_err(|_| ForgeryVerificationError::BadSignature)?;
    let mut selected = [[0_u8; 48]; 31];
    let mut count = 0;
    for (index, key) in generation.keys.iter().enumerate() {
        if qc.signers & (1_u32 << index) != 0 {
            selected[count] = *key;
            count += 1;
        }
    }
    let result = outer_result(header, &qc.result_body).0;
    let preimage = commit_preimage(&instance.0, qc, header.height(), &result);
    let digest =
        ConsensusDigest::from_preimage(&preimage).ok_or(ForgeryVerificationError::BadSignature)?;
    control.check()?;
    let mut scratch = ConsensusAggregateScratch::new(|bytes| budget.try_reserve_bytes(bytes))?;
    let valid = scratch.verify_fast_aggregate_committed(&selected[..count], &digest, signature);
    drop(scratch);
    control.check()?;
    if !valid {
        return Err(ForgeryVerificationError::BadSignature);
    }
    Ok(*digest.as_bytes())
}

fn first_mismatch(
    generation: &RetainedSccpGeneration,
    execution_height: u64,
    height: u64,
    qc: &QcFixedV1,
    result: [u8; 32],
    anchor: impl FnOnce() -> Result<SccpAnchorV1>,
) -> Result<SccpForgeryRuleV1> {
    if height < generation.start_height
        || generation
            .end
            .as_ref()
            .is_some_and(|end| height > end.end_height)
    {
        return Ok(SccpForgeryRuleV1::E1);
    }
    if height >= execution_height {
        return Ok(SccpForgeryRuleV1::E2);
    }
    let original = anchor()?;
    if qc.block_hash != original.core_hash {
        return Ok(SccpForgeryRuleV1::E3);
    }
    if result != original.result && !cfg!(all(test, sumeragi_core_mutation = "HC315")) {
        return Ok(SccpForgeryRuleV1::E4);
    }
    Err(ForgeryVerificationError::NotEvidence)
}

fn anchor_error(error: SccpAnchorLookupError) -> ForgeryVerificationError {
    match error {
        SccpAnchorLookupError::InvalidHeight => {
            ForgeryVerificationError::Unavailable("inconsistent anchor layout")
        }
        SccpAnchorLookupError::WitnessRequired => ForgeryVerificationError::WitnessRequired,
        SccpAnchorLookupError::BadWitness => ForgeryVerificationError::BadWitness,
        SccpAnchorLookupError::EvidenceExpired => ForgeryVerificationError::EvidenceExpired,
    }
}

fn check_control(control: SccpNativeReadControl<'_>) -> Result<()> {
    if control.stop.load(Ordering::Acquire) {
        return Err(ForgeryVerificationError::Cancelled);
    }
    if Instant::now() >= control.deadline {
        return Err(ForgeryVerificationError::Deadline);
    }
    Ok(())
}

#[cfg(test)]
#[path = "forgery/tests.rs"]
pub(crate) mod tests;
