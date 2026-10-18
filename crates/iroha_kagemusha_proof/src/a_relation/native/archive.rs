//! Native Archive originals and the complete shared source plan (lean lineage).
//!
//! Both evidence forms use the mandatory Archive owners and full envelope domains.
//! A proves the own step inline, so no own sigma or current credential enters the
//! native inputs: the own receipt is the only own signed object. Decoded soft
//! fields and result bits are proposals, never native acceptance certificates.
//! Only the compiled owners can authenticate them. The fixed producer imports one
//! original key at a time and retains canonical source-bound A/W checkpoints.
//! TODO: qualify both complete evidence chains and final Omega before installing
//! terminal artifacts or admitting this producer to a monetary wallet provider.

use core::fmt;

mod circuit;
pub use circuit::{PredicateInputs, StageCircuit};
mod prepare;
pub use prepare::Prepared;
mod session;
pub use session::{
    ACheckpoint, CheckpointKind, CheckpointLayout, Prover, RetainedSession, Session, Terminal,
    WCheckpoint,
};

use iroha_pasta::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};
use iroha_plonk::{VerifyingKey, cs::InstanceType, pcs::ipa::PinnedParams};
use iroha_plonk_recursion::{AccumulatorT, FoldInput, obligation::ledger::Variant};

use crate::{
    a_relation::{
        AProofPlan,
        archive::{
            MAX_RECEIVE_SIGMA_RAW_BYTES, MAX_STATUS_OMEGA_RAW_BYTES, stage::ArchiveStagePlan,
        },
        context::ContextPlan,
        own::OwnPolicy,
        receive::{MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES, PAYMENT_RAW_PROOF_BUDGET},
        schedule::sigma_selector,
    },
    admin_sigma::ArchiveWitness,
    q_sigma::{QSigmaPlan, native::IncomingMode},
    tree::IndexedRemove,
};

/// `ArchiveReceive` original-source/Q stages, joined by eight authenticated
/// continuations; one stage verifies the incoming-only `Q_sigma`.
pub const RECEIVE_A_STAGE_COUNT: usize = 9;
/// `ArchiveStatus` has no `Q_sigma`: eight stages and seven continuations.
pub const STATUS_A_STAGE_COUNT: usize = 8;
/// Fixed internal source profile; each exact key is pinned by its W continuation.
pub const INTERNAL_RANGE_BUSES: usize = 4;
/// Fixed terminal source profile shared with the common Omega catalog.
pub const TERMINAL_RANGE_BUSES: usize = 3;

/// Native Archive intake/proof failure; no failure changes a monetary head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Original local checkpoint read refusal; no invalid-input or proof verdict completed.
    DecodeResource(norito::core::DecodeLocalRefusal),
    /// Explicit cancellation; no proof failure or burn verdict is produced.
    Cancelled,
    /// The installed schema, key, source profile or parameters differ.
    Artifact,
    /// An exact original shape, envelope bound or canonical claim differs.
    Input,
    /// A hard proof or selected obligation fails verification.
    Proof,
    /// A compiled source cannot be assigned or proved.
    Prover,
}
impl From<super::proving::Error> for Error {
    fn from(error: super::proving::Error) -> Self {
        match error {
            super::proving::Error::Cancelled => Self::Cancelled,
            super::proving::Error::Artifact => Self::Artifact,
            super::proving::Error::Prover => Self::Prover,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native Archive: {self:?}")
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeResource(original) => Some(original),
            _ => None,
        }
    }
}
impl From<norito::core::DecodeAttemptError> for Error {
    fn from(error: norito::core::DecodeAttemptError) -> Self {
        error
            .into_local_refusal()
            .map_or(Self::Input, Self::DecodeResource)
    }
}
impl Error {
    /// Whether the operation was cancelled instead of proving an invalid input.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

impl From<super::support::Error> for Error {
    fn from(error: super::support::Error) -> Self {
        match error {
            super::support::Error::Cancelled => Self::Cancelled,
            super::support::Error::Input => Self::Input,
            super::support::Error::Proof => Self::Proof,
        }
    }
}

/// Actual local Q proof and its exact exported columns.
#[derive(Clone, Debug)]
pub struct QInput {
    /// Descriptor-sized native proof bytes.
    pub proof: Vec<u8>,
    /// Original columns, including every soft verdict and obligation.
    pub instances: Vec<Vec<Fq>>,
}

/// Exact hard predecessor proof and complete transported obligations.
#[derive(Clone, Debug)]
pub struct PredecessorInput {
    /// Unframed proof under the installed common Omega key.
    pub proof: Vec<u8>,
    /// Original canonical Pallas claim.
    pub pallas: [u8; 544],
    /// Original canonical Vesta claim.
    pub vesta: [u8; 544],
}

/// The immutable Payment retained after irreversible Send.
#[derive(Clone, Debug)]
pub struct RetainedPayment {
    /// Request, payer Credential, Send Receipt and quoted receiver Credential.
    pub signed: [Vec<u8>; 4],
    /// Original163-byte semantic Payment transcript.
    pub payment: Vec<u8>,
    /// All26 original Send statement words, including the pending descriptor.
    pub statement: [Fp; 26],
    /// Original public320 plus Omega proof and both full claims.
    pub omega: Vec<u8>,
    /// Original unframed Send sigma; its historical validity is not inferred here.
    pub sigma: Vec<u8>,
}

/// Original `CreditStatus` decoder and obligation proposals.
/// Every field must be derived again by its fixed circuit owner.
#[derive(Clone, Debug)]
pub struct StatusWitness {
    /// Exact original decoded lineage, or the decoder's fixed safe fields.
    pub public: [Fp; 18],
    /// Proposed total public-decoder result.
    pub public_valid: bool,
    /// Original decoded Pallas claim, possibly non-deciding.
    pub pallas: AccumulatorT<Ep>,
    /// Original decoded Vesta claim, possibly non-deciding.
    pub vesta: AccumulatorT<Eq>,
    /// Original soft-verifier opening, including its fixed failure dummy.
    pub opening: FoldInput<Ep>,
    /// Original-P, Omega-opening and original-V modes, in that order.
    pub modes: [IncomingMode; 3],
    /// Same-challenge corrected original-P and Omega-opening commitments.
    pub pallas_corrections: [EpAffine; 2],
    /// Same-challenge corrected original-V commitment.
    pub vesta_correction: EqAffine,
}

/// Full exact incoming evidence selected by the installed operation variant.
#[derive(Clone, Debug)]
pub enum Evidence {
    /// Original Receive or renewed-Receive sigma evidence.
    Receive {
        /// Exact statement carried with the incoming sigma.
        statement: [Fp; 26],
        /// Original receiver Receipt, including its raw signature.
        receipt: Vec<u8>,
        /// Entire original sigma, including any over-descriptor tail.
        sigma: Vec<u8>,
        /// Original99-byte Credited transcript.
        credited: Vec<u8>,
        /// Incoming sigma obligation mode also exported by Q0.
        mode: IncomingMode,
    },
    /// Original folded-head membership evidence.
    Status {
        /// Exact26-word statement carried with the folded head.
        statement: [Fp; 26],
        /// Original folded operation Receipt, including its raw signature.
        receipt: Vec<u8>,
        /// Original public320 plus Omega proof and both claims.
        omega: Vec<u8>,
        /// Original99-byte Credited transcript.
        credited: Vec<u8>,
        /// Original162-byte `CreditStatus` transcript.
        status: Vec<u8>,
        /// Original1125-byte credit membership opening.
        credit_opening: Vec<u8>,
        /// Untrusted decoded fields, soft opening and correction proposals.
        witness: Box<StatusWitness>,
    },
}

/// Post-Advance originals retained for the complete Archive proof.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// Own state openings and exact tag5 statement.
    pub state: ArchiveWitness,
    /// Core relink/clear and adjusted-lineage relink/clear paths, in that order.
    pub removals: [IndexedRemove<Fp>; 2],
    /// Own Receipt, hard-verified under the predecessor payment key.
    pub own: Vec<u8>,
    /// Exact locally retained Send Payment.
    pub retained: RetainedPayment,
    /// Incoming complete evidence, including malformed soft originals.
    pub evidence: Evidence,
    /// Proposed Proofs, Evidence and Signatures bits. These grant no authority.
    pub results: [bool; 3],
    /// Every installed Q in order: `ArchiveReceive`'s incoming-only `Q_sigma`,
    /// then the merged signature leaf (own receipt hard, incoming receipt soft).
    pub q: Vec<QInput>,
    /// Actual hard predecessor under the same installed common Omega key.
    pub predecessor: PredecessorInput,
}

/// Fixed shared owner plan and common-key continuity for native Archive.
#[derive(Clone, Debug)]
pub struct Plan {
    stage: ArchiveStagePlan,
    policy: OwnPolicy,
    predecessor_key: VerifyingKey<Ep>,
    pallas: PinnedParams<Ep>,
    vesta: PinnedParams<Eq>,
}
impl Plan {
    /// Pin all source capacities, owners, the incoming sigma class and the common
    /// Omega key. The plan must prove the own step inline: no own sigma, and an
    /// incoming-only `Q_sigma` exactly for `ArchiveReceive`.
    /// Metadata construction neither authenticates an artifact nor proves a stage.
    /// # Errors
    /// Wrong variant, Q/part/sigma profile, continuity key or envelope capacity.
    pub fn new(
        operation: AProofPlan,
        policy: OwnPolicy,
        predecessor_key: VerifyingKey<Ep>,
        pallas: PinnedParams<Ep>,
        vesta: PinnedParams<Eq>,
    ) -> Result<Self, Error> {
        let (receive, stages) = match operation.frame().variant() {
            Variant::ArchiveReceive => (true, RECEIVE_A_STAGE_COUNT),
            Variant::ArchiveStatus => (false, STATUS_A_STAGE_COUNT),
            _ => return Err(Error::Artifact),
        };
        if operation.q_count() != 1 + usize::from(receive)
            || !operation.frame().has_predecessor()
            || operation.frame().has_incoming() == receive
            || !operation.is_inline()
            || operation.has_incoming_sigma() != receive
            || operation.frame().part_source_k() != 16
        {
            return Err(Error::Artifact);
        }
        pallas.require_k(16).map_err(|_| Error::Artifact)?;
        vesta.require_k(16).map_err(|_| Error::Artifact)?;
        if receive {
            let incoming = operation
                .sigma_class(QSigmaPlan::INCOMING)
                .ok_or(Error::Artifact)?;
            if !matches!(incoming.verifier().binding().descriptor().k, 12 | 14)
                || incoming.verifier().proof_length() > MAX_RECEIVE_SIGMA_RAW_BYTES
                || sigma_selector(4, 0)
                    .and_then(|index| incoming.selector_key_digest(index))
                    .is_none()
            {
                return Err(Error::Artifact);
            }
        }
        let predecessor = operation.omega().ok_or(Error::Artifact)?;
        let d = predecessor.binding().descriptor();
        let transport = predecessor
            .proof_length()
            .checked_add(2 * 544)
            .ok_or(Error::Artifact)?;
        if predecessor_key.descriptor_digest() != predecessor.binding().digest()
            || d.k != 16
            || d.instance_lengths != [1, 2, 16]
            || d.instance_types.as_deref()
                != Some(&[
                    InstanceType::Bounded,
                    InstanceType::Field,
                    InstanceType::Bounded,
                ])
            || transport > MAX_STATUS_OMEGA_RAW_BYTES - 320
        {
            return Err(Error::Artifact);
        }
        predecessor_key
            .kagemusha_digest(predecessor.binding())
            .map_err(|_| Error::Artifact)?;
        let stage = ArchiveStagePlan::full(operation, policy).map_err(|_| Error::Artifact)?;
        if stage.context().stage_count() != stages {
            return Err(Error::Artifact);
        }
        Ok(Self {
            stage,
            policy,
            predecessor_key,
            pallas,
            vesta,
        })
    }

    /// Complete immutable source plan used by both evidence variants.
    pub const fn stage(&self) -> &ArchiveStagePlan {
        &self.stage
    }
    /// Fixed scheme/provider/root scope shared by every original-source owner.
    pub const fn policy(&self) -> OwnPolicy {
        self.policy
    }
    /// Complete fixed context, owner schedule and Q assignment.
    pub const fn context(&self) -> &ContextPlan {
        self.stage.context()
    }
    /// Exact installed common Omega verifier, never selected by incoming evidence.
    pub const fn predecessor_key(&self) -> &VerifyingKey<Ep> {
        &self.predecessor_key
    }
    /// Pinned native Pallas parameters.
    pub const fn pallas(&self) -> &PinnedParams<Ep> {
        &self.pallas
    }
    /// Pinned native Vesta parameters.
    pub const fn vesta(&self) -> &PinnedParams<Eq> {
        &self.vesta
    }

    /// Check exact original shapes without judging soft evidence or admitting proofs.
    /// In particular, a bounded incoming length mismatch remains an input to the
    /// total verifier. The retained Payment joint bound is unconditional.
    /// # Errors
    /// Wrong evidence class, fixed transcript size or envelope bound.
    pub fn validate_original_shapes(&self, input: &Inputs) -> Result<(), Error> {
        let specs = self.context().object_specs();
        let exact = |slot: usize, bytes: &[u8]| {
            if bytes.len() == specs[slot].capacity as usize {
                Ok(())
            } else {
                Err(Error::Input)
            }
        };
        exact(0, &input.own)?;
        for (i, raw) in input.retained.signed.iter().enumerate() {
            exact(i + 1, raw)?;
        }
        exact(5, &input.retained.payment)?;
        check_retained_sizes(input.retained.omega.len(), input.retained.sigma.len())?;
        match (
            &input.evidence,
            self.context().operation().frame().variant(),
        ) {
            (
                Evidence::Receive {
                    receipt,
                    sigma,
                    credited,
                    ..
                },
                Variant::ArchiveReceive,
            ) => {
                exact(10, receipt)?;
                exact(13, credited)?;
                if sigma.len() > MAX_RECEIVE_SIGMA_RAW_BYTES {
                    return Err(Error::Input);
                }
            }
            (
                Evidence::Status {
                    receipt,
                    omega,
                    credited,
                    status,
                    credit_opening,
                    ..
                },
                Variant::ArchiveStatus,
            ) => {
                exact(10, receipt)?;
                exact(13, credited)?;
                exact(14, status)?;
                exact(15, credit_opening)?;
                if omega.len() > MAX_STATUS_OMEGA_RAW_BYTES {
                    return Err(Error::Input);
                }
            }
            _ => return Err(Error::Input),
        }
        Ok(())
    }
}

fn check_retained_sizes(omega: usize, sigma: usize) -> Result<(), Error> {
    if omega > MAX_OMEGA_RAW_BYTES
        || sigma > MAX_SIGMA_RAW_BYTES
        || omega
            .checked_add(sigma)
            .is_none_or(|sum| sum > PAYMENT_RAW_PROOF_BUDGET)
    {
        return Err(Error::Input);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_original_envelope_is_joint_inclusive_and_overflow_safe() {
        assert_eq!(check_retained_sizes(5406, 3520), Ok(()));
        assert_eq!(check_retained_sizes(5406, 0), Ok(()));
        assert_eq!(check_retained_sizes(0, 0), Ok(()));
        for (omega, sigma) in [
            (5407, 3520),
            (5406, 3521),
            (5407, 0),
            (0, 3521),
            (usize::MAX, 1),
        ] {
            assert_eq!(check_retained_sizes(omega, sigma), Err(Error::Input));
        }
    }
}
