//! Bounded, contiguous native finality verification for deployment observations.
//!
//! Trust starts at independently authenticated signed genesis or an operator-selected complete
//! native checkpoint. Every successor is verified; a supplied committee, context digest or proof
//! is never promoted to its own trust root. Fresh BLS attestations require `2f + 1` distinct
//! members of the authenticated tip committee. The native checkpoint retains exact predecessor
//! decisions, allowing one-block-lagging members to count across an epoch boundary.
//!
//! Height-one outputs have no QC. They require a certified successor or independent committee
//! attestations; merely constructing a verifier does not authenticate genesis execution.
//!
//! Certificates, committees and epoch handoffs are checked by the data model's contiguous
//! [`SumeragiFinalityVerifier`]: each successor must carry an exact `2f + 1` commit certificate
//! of the committee that its authenticated predecessor scheduled, and an epoch boundary's
//! certified result is the only source of the next committee. Work is proportional to new
//! blocks rather than new epochs: parent-result, schedule and beacon-seed bindings are checked
//! between adjacent certified blocks, and the canonical checkpoint retains the exact decisions
//! of the tip's two predecessors.
//!
//! An observation verifies one contiguous prefix, each height at most once, and places every
//! member's claimed tip on it. A claim that fails verification or exceeds the budget is reported
//! for that member alone, so a Byzantine member cannot abort the observation or spend the budget
//! that honest tips need. A checkpoint lagging by more than one observation budget is caught up
//! across observations ([`FinalityError::CatchingUp`]) or explicitly in pages
//! ([`FinalityVerifier::catch_up`]).

use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, SignedBlock},
    sumeragi_finality::{
        EpochValidationScope, FinalityError as NativeFinalityError, FinalityValidator,
        ScheduledSlot, SumeragiFinalityAttestation, SumeragiFinalityCheckpoint,
        SumeragiFinalityProof, SumeragiFinalityVerifier, VerifiedSumeragiBlock,
    },
};
use iroha_model_base::peer::PeerId;
use std::{
    cmp::Reverse,
    collections::BTreeMap,
    num::NonZeroU64,
    sync::{Arc, OnceLock},
};

/// Smallest committee: `f = 1`.
pub const MIN_COMMITTEE_MEMBERS: usize = 4;

/// Largest committee permitted by the Sumeragi protocol (`f = 10`).
pub const MAX_COMMITTEE_MEMBERS: usize = iroha_data_model::sumeragi::epoch::MAX_VALIDATORS;

/// Size of an exact `3f + 1` committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitteeSize(usize);

impl CommitteeSize {
    /// Accept `members = 3f + 1` with `f >= 1` and at most
    /// [`MAX_COMMITTEE_MEMBERS`].
    ///
    /// # Errors
    ///
    /// [`FinalityError::CommitteeSize`] for any other size.
    pub fn new(members: usize) -> Result<Self, FinalityError> {
        if (MIN_COMMITTEE_MEMBERS..=MAX_COMMITTEE_MEMBERS).contains(&members)
            && (members - 1).is_multiple_of(3)
        {
            Ok(Self(members))
        } else {
            Err(FinalityError::CommitteeSize { members })
        }
    }

    /// Number of members, `3f + 1`.
    pub const fn members(self) -> usize {
        self.0
    }

    /// Byzantine members tolerated, `f`.
    pub const fn faults(self) -> usize {
        (self.0 - 1) / 3
    }

    /// Exact certificate and minimum attestation quorum, `2f + 1`.
    pub const fn quorum(self) -> usize {
        self.members() - self.faults()
    }
}

/// Maximum successor proofs processed by one advance or complete observation.
pub const MAX_ADVANCE_PROOFS: usize = 4096;
/// Maximum canonical block bytes processed by one advance or complete observation.
pub const MAX_ADVANCE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum distinct peers queried by one observation across committee changes.
pub const MAX_OBSERVATION_PEERS: usize = 4 * MAX_COMMITTEE_MEMBERS;

/// Genesis and chain label the caller authenticated independently of the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisAnchor {
    /// Independently selected genesis-derived network.
    pub network_id: NetworkId,
    /// Chain label used for native consensus instance derivation.
    pub chain_id: String,
    /// Original signed genesis whose signature the caller authenticated.
    pub genesis: SignedBlock,
    /// Exact ordered native BLS committee and possession proofs selected with genesis.
    pub validators: Vec<FinalityValidator>,
}

/// A raw source statement or an immutable statement authenticated by its exact SDK read.
///
/// Both forms still require the observation's independently selected peer, challenge and
/// network, and the same contiguous chain and committee-membership checks. Raw statements
/// additionally undergo full structural and node-signature verification on admission.
#[derive(Debug)]
pub enum FinalityAttestation {
    /// An arbitrary source statement with no retained authentication provenance.
    Raw(SumeragiFinalityAttestation),
    /// A statement constructed only by the SDK's strict, request-bound response reader.
    Authenticated(iroha::client::AuthenticatedFinalityAttestation),
}

impl FinalityAttestation {
    /// Borrow the statement without promoting it to chain or committee authority.
    #[must_use]
    pub fn attestation(&self) -> &SumeragiFinalityAttestation {
        match self {
            Self::Raw(attestation) => attestation,
            Self::Authenticated(attestation) => attestation.attestation(),
        }
    }
}

impl From<SumeragiFinalityAttestation> for FinalityAttestation {
    fn from(attestation: SumeragiFinalityAttestation) -> Self {
        Self::Raw(attestation)
    }
}

/// Untrusted transport for native proof frames and challenged node statements.
pub trait FinalitySource {
    /// Transport failure.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Fetch the exact native proof at `height`.
    ///
    /// # Errors
    /// Any transport failure.
    fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error>;
    /// Fetch `peer`'s fresh native durable-tip attestation over `challenge`.
    ///
    /// # Errors
    /// Any transport failure.
    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> Result<FinalityAttestation, Self::Error>;
    /// Read a bounded batch in request order. HTTP transports can overlap independent peers.
    /// Each result still needs the caller's independent committee and chain verification.
    fn latest_attestations(
        &self,
        peers: &[PeerId],
        challenge: &[u8; 32],
    ) -> Vec<Result<FinalityAttestation, Self::Error>> {
        peers
            .iter()
            .map(|peer| self.latest_attestation(peer, challenge))
            .collect()
    }
}

/// A durable tip that one committee member attested to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestedTip {
    /// Height of the attested tip.
    pub height: NonZeroU64,
    /// Hash of the attested tip.
    pub block_hash: HashOf<BlockHeader>,
}

/// What became of one committee member's attestation.
#[derive(Debug)]
pub enum AttestationOutcome {
    /// It verified, and the member's tip is final on the verified chain.
    Verified(AttestedTip),
    /// It failed verification.
    Rejected(FinalityError),
    /// The source could not fetch it.
    Unreachable(String),
    /// None was supplied.
    Missing,
}

/// Attestations tallied against a checkpoint.
#[derive(Debug)]
pub struct AttestationQuorum {
    /// Checkpoint height the attestations were verified against.
    pub height: NonZeroU64,
    /// Checkpoint block hash.
    pub block_hash: HashOf<BlockHeader>,
    /// Verified attestations required, `2f + 1`.
    pub required: usize,
    /// One outcome per committee member, in roster order.
    pub peers: Vec<(PeerId, AttestationOutcome)>,
}

impl AttestationQuorum {
    /// Number of distinct members whose attestation verified.
    pub fn verified(&self) -> usize {
        self.peers
            .iter()
            .filter(|(_, outcome)| matches!(outcome, AttestationOutcome::Verified(_)))
            .count()
    }
}

/// Why an independently anchored native finality observation failed.
#[derive(Debug, thiserror::Error)]
pub enum FinalityError {
    /// The roster is not exact `3f + 1` within deployment bounds.
    #[error("invalid deployment committee size {members}")]
    CommitteeSize {
        /// Roster size found.
        members: usize,
    },
    /// The response belongs to another network.
    #[error("expected network {expected}, got {actual}")]
    WrongNetwork {
        /// Selected network.
        expected: NetworkId,
        /// Response network.
        actual: NetworkId,
    },
    /// Genesis differs from the independently selected root.
    #[error("genesis differs from the selected root")]
    WrongGenesis,
    /// The source returned another height.
    #[error("expected height {expected}, got {actual}")]
    UnexpectedHeight {
        /// Requested height.
        expected: u64,
        /// Returned height.
        actual: u64,
    },
    /// Checkpoints never move backward.
    #[error("tip {height} precedes checkpoint {checkpoint}")]
    StaleTip {
        /// Current checkpoint height.
        checkpoint: u64,
        /// Offered height.
        height: u64,
    },
    /// An attestation exceeds the verified prefix.
    #[error("tip {height} exceeds checkpoint {checkpoint}")]
    AheadOfCheckpoint {
        /// Current checkpoint height.
        checkpoint: u64,
        /// Offered height.
        height: u64,
    },
    /// A lagging tip lacks a retained authenticated parent decision.
    #[error("tip {height} is outside the retained prefix at checkpoint {checkpoint}")]
    OutsideRetainedPrefix {
        /// Current checkpoint height.
        checkpoint: u64,
        /// Offered height.
        height: u64,
    },
    /// Native structural, cryptographic, schedule or exact-decision verification failed.
    #[error("native finality: {0}")]
    Native(#[from] NativeFinalityError),
    /// Original signed genesis could not be read; local decoder refusal stays typed.
    #[error("native genesis read: {0}")]
    Genesis(#[from] iroha_data_model::sumeragi_finality::GenesisReadError),
    /// Original checkpoint decoder fields; the caller owns retry and format-limit policy.
    #[error("native checkpoint decoder resource: {0}")]
    DecodeResource(#[source] norito::core::DecodeAttemptError),
    /// A zero challenge permits replay.
    #[error("the attestation challenge must be nonzero")]
    ZeroChallenge,
    /// The statement answers another request.
    #[error("the attestation answers another challenge")]
    StaleChallenge,
    /// The signer is not in the authenticated current committee.
    #[error("attesting node {peer} is not in the authenticated committee")]
    NotInCommittee {
        /// Rejected signer.
        peer: Box<PeerId>,
    },
    /// A queried node was substituted.
    #[error("asked {expected}, received a statement from {actual}")]
    UnexpectedPeer {
        /// Queried node.
        expected: Box<PeerId>,
        /// Returned signer.
        actual: Box<PeerId>,
    },
    /// Too few distinct current members supplied valid fresh statements.
    #[error("{} of {} required committee members attested", .0.verified(), .0.required)]
    InsufficientAttestations(Box<AttestationQuorum>),
    /// Members claim tips beyond what one observation budget verified. The next observation
    /// continues from the verified successors. A durable owner may retain that certified prefix,
    /// but this error never establishes a fresh committee quorum or readiness.
    #[error("verified through height {verified}, members claim up to {claimed}; observe again")]
    CatchingUp {
        /// Last height this observation verified.
        verified: u64,
        /// Highest tip a member claimed beyond the budget.
        claimed: u64,
    },
    /// The requested work exceeds a finite observation budget.
    #[error("finality observation exceeds its {0} budget")]
    ResourceLimit(&'static str),
    /// An untrusted transport failed.
    #[error("finality source: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<iroha_data_model::sumeragi_finality::FinalityReadError> for FinalityError {
    fn from(error: iroha_data_model::sumeragi_finality::FinalityReadError) -> Self {
        use iroha_data_model::sumeragi_finality::FinalityReadError;
        match error {
            FinalityReadError::Invalid(error) => Self::Native(error),
            FinalityReadError::Genesis(error) => Self::Genesis(error),
            FinalityReadError::DecodeResource(resource) => Self::DecodeResource(resource),
        }
    }
}

impl FinalityError {
    fn transport(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Source(Box::new(error))
    }
}

struct Budget {
    proofs: usize,
    bytes: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            proofs: MAX_ADVANCE_PROOFS,
            bytes: MAX_ADVANCE_BYTES,
        }
    }
    /// Why this budget cannot cover `proof`, without spending anything.
    fn refuses(&self, proof: &SumeragiFinalityProof) -> Option<&'static str> {
        if self.proofs == 0 {
            Some("proof count")
        } else if proof.block_wire.len() > self.bytes {
            Some("proof bytes")
        } else {
            None
        }
    }
    fn charge(&mut self, proof: &SumeragiFinalityProof) -> Result<(), FinalityError> {
        if let Some(reason) = self.refuses(proof) {
            return Err(FinalityError::ResourceLimit(reason));
        }
        self.proofs -= 1;
        self.bytes -= proof.block_wire.len();
        Ok(())
    }
}

/// An independently anchored certified prefix; fresh readiness requires a successful observation.
#[derive(Debug, Clone)]
pub struct FinalityVerifier {
    /// Exact selected immutable image; verifier clones share storage, never advancement.
    checkpoint: Arc<SumeragiFinalityCheckpoint>,
    /// Successors an observation verified before its budget ran out, awaiting a fresh quorum.
    /// The next observation continues from here. The durable runtime owner may explicitly
    /// retain them as a certificate-only checkpoint while still returning CatchingUp.
    pending: Option<SumeragiFinalityCheckpoint>,
    /// Successful authentication of this exact immutable checkpoint's original tip only.
    /// Clones share the derived capability until one publishes a different checkpoint.
    verified_tip: Arc<OnceLock<VerifiedSumeragiBlock>>,
}

impl PartialEq for FinalityVerifier {
    fn eq(&self, other: &Self) -> bool {
        self.checkpoint == other.checkpoint && self.pending == other.pending
    }
}
impl Eq for FinalityVerifier {}

impl FinalityVerifier {
    /// Initialize from authenticated signed genesis and its result-only native frame.
    /// Height-one execution still requires a successor or fresh quorum attestations.
    ///
    /// # Errors
    /// Wrong network, genesis, committee, chain label or malformed native material.
    pub fn from_genesis(
        anchor: &GenesisAnchor,
        genesis: &SumeragiFinalityProof,
    ) -> Result<Self, FinalityError> {
        let actual = NetworkId::from_genesis_hash(anchor.genesis.hash());
        if actual != anchor.network_id {
            return Err(FinalityError::WrongNetwork {
                expected: anchor.network_id,
                actual,
            });
        }
        CommitteeSize::new(anchor.validators.len())?;
        if genesis.height() != 1 {
            return Err(FinalityError::UnexpectedHeight {
                expected: 1,
                actual: genesis.height(),
            });
        }
        if genesis.block_header.hash() != anchor.genesis.hash() {
            return Err(FinalityError::WrongGenesis);
        }
        let mut verifier = SumeragiFinalityVerifier::new(
            &anchor.genesis,
            &anchor.chain_id,
            anchor.validators.clone(),
        )?;
        verifier.verify(genesis)?;
        Ok(Self {
            checkpoint: Arc::new(verifier.export_checkpoint(genesis)?),
            pending: None,
            verified_tip: Arc::new(OnceLock::new()),
        })
    }

    /// Resume from independently selected local checkpoint bytes, never a responding peer's claim.
    ///
    /// # Errors
    /// Wrong selected network or chain label, or inconsistent native checkpoint.
    pub fn from_checkpoint(
        checkpoint: SumeragiFinalityCheckpoint,
        expected_network: NetworkId,
        expected_chain: &str,
    ) -> Result<Self, FinalityError> {
        Self::from_checkpoint_with_validation(checkpoint, expected_network, expected_chain, None)
    }

    pub(crate) fn from_checkpoint_with_validation(
        checkpoint: SumeragiFinalityCheckpoint,
        expected_network: NetworkId,
        expected_chain: &str,
        validation: Option<&mut EpochValidationScope>,
    ) -> Result<Self, FinalityError> {
        let validation = if norito::core::decode_limits_active() {
            None
        } else {
            validation
        };
        SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
            checkpoint,
            &expected_network,
            expected_chain,
            validation,
            |checkpoint, native, verified_tip| {
                // The original importer discarded this verifier before the committee check.
                drop(native);
                CommitteeSize::new(checkpoint.tip().committee.len())?;
                Ok(Self {
                    checkpoint: Arc::new(checkpoint),
                    pending: None,
                    verified_tip: Arc::new(OnceLock::from(verified_tip)),
                })
            },
        )?
    }

    /// Complete native checkpoint to persist for independently authenticated restart.
    pub fn checkpoint(&self) -> &SumeragiFinalityCheckpoint {
        self.checkpoint.as_ref()
    }
    /// Move only previously native-verified successors into the durable owner's certified prefix.
    /// This supplies no fresh attestation quorum; the owner must retain the CatchingUp refusal.
    pub(crate) fn promote_verified_progress(&mut self) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        self.replace_checkpoint(pending);
        true
    }
    /// Authenticate the exact retained tip for execution-bound receipts and public record proofs.
    /// This capability inherits this verifier's independently selected checkpoint; the caller
    /// must not replace it with a response-selected checkpoint to authenticate a receipt.
    ///
    /// # Errors
    /// The retained native checkpoint or its certified execution decision is inconsistent.
    pub fn verified_tip(&self) -> Result<VerifiedSumeragiBlock, FinalityError> {
        self.verified_tip_ref().cloned()
    }
    /// Borrow the exact authenticated tip retained by this immutable checkpoint owner.
    /// Read-only scope gates require no owned result graph. Failed authentication is never
    /// stored; independently supplied proofs and every new checkpoint still require their
    /// original verification, and the returned reference cannot outlive this owner.
    ///
    /// # Errors
    /// The original selected checkpoint's native authentication or decoder resource refusal.
    pub(crate) fn verified_tip_ref(&self) -> Result<&VerifiedSumeragiBlock, FinalityError> {
        if let Some(verified) = self.verified_tip.get() {
            return Ok(verified);
        }
        self.retain_verified_tip()
    }
    // Keep cold native import scratch outside the warm borrowed read's frame. Authentication
    // completes before the immutable OnceLock publication, as in the original owned accessor.
    #[inline(never)]
    fn retain_verified_tip(&self) -> Result<&VerifiedSumeragiBlock, FinalityError> {
        Ok(
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                self.checkpoint.as_ref(),
                &self.checkpoint.network_id(),
                self.checkpoint.chain_id(),
                |_, native, verified| {
                    drop(native);
                    // Racing immutable callers may both verify; only successful canonical results are kept.
                    self.verified_tip.get_or_init(|| verified)
                },
            )?,
        )
    }
    /// Replace the checkpoint and detach only this owner's derived tip capability.
    fn replace_checkpoint(&mut self, checkpoint: SumeragiFinalityCheckpoint) {
        self.checkpoint = Arc::new(checkpoint);
        self.verified_tip = Arc::new(OnceLock::new());
    }
    /// Size of the exact committee that certified the tip.
    pub fn committee_size(&self) -> CommitteeSize {
        CommitteeSize(self.checkpoint.tip().committee.len())
    }
    fn native(&self) -> Result<SumeragiFinalityVerifier, FinalityError> {
        Ok(SumeragiFinalityVerifier::from_trusted_checkpoint(
            &self.checkpoint,
            &self.checkpoint.network_id(),
            self.checkpoint.chain_id(),
        )?)
    }
    fn members(&self) -> Vec<PeerId> {
        committee_peers(self.checkpoint.tip())
    }

    /// Verify every successor through `tip`, atomically replacing the checkpoint.
    /// Returns the number of intermediate proofs fetched; the supplied tip is not fetched again.
    ///
    /// # Errors
    /// Any missing, reordered, altered or invalid successor; bounded-work exhaustion; stale tip.
    pub fn advance<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        tip: &SumeragiFinalityProof,
    ) -> Result<usize, FinalityError> {
        self.advance_with_budget(source, tip, &mut Budget::new())
    }
    fn advance_with_budget<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        tip: &SumeragiFinalityProof,
        budget: &mut Budget,
    ) -> Result<usize, FinalityError> {
        let current = self.checkpoint.height();
        let height = tip.height();
        if height < current {
            return Err(FinalityError::StaleTip {
                checkpoint: current,
                height,
            });
        }
        if height == current {
            budget.charge(tip)?;
            self.native()?
                .verify_same_decision(self.checkpoint.tip(), tip)?;
            return Ok(0);
        }
        if height - current > budget.proofs as u64 {
            return Err(FinalityError::ResourceLimit("proof count"));
        }
        let mut native = self.native()?;
        let mut fetched = 0;
        for expected in current + 1..height {
            let proof = source
                .finality_proof(NonZeroU64::new(expected).expect("successor is positive"))
                .map_err(FinalityError::transport)?;
            if proof.height() != expected {
                return Err(FinalityError::UnexpectedHeight {
                    expected,
                    actual: proof.height(),
                });
            }
            budget.charge(&proof)?;
            CommitteeSize::new(proof.committee.len())?;
            native.verify(&proof)?;
            fetched += 1;
        }
        budget.charge(tip)?;
        CommitteeSize::new(tip.committee.len())?;
        native.verify(tip)?;
        self.replace_checkpoint(native.export_checkpoint(tip)?);
        self.pending = None;
        Ok(fetched)
    }

    /// Verify one bounded page of contiguous successors toward `target` and publish its last
    /// verified successor as the new checkpoint; returns the resulting checkpoint height.
    ///
    /// Unlike [`Self::observe`], this publishes certificate-verified successors without a fresh
    /// committee quorum, for callers that choose to persist that progress. A page ends at
    /// `target`, after [`MAX_ADVANCE_PROOFS`] successors, or before the successor that would
    /// exceed [`MAX_ADVANCE_BYTES`]. Every successor is verified as in [`Self::advance`];
    /// `target` only bounds the work and never selects trust. A target at or below the
    /// checkpoint fetches nothing.
    ///
    /// # Errors
    /// A transport failure, a wrong height, an invalid successor, or a first successor that
    /// alone exceeds the byte budget. The checkpoint is unchanged on error.
    pub fn catch_up<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        target: NonZeroU64,
    ) -> Result<u64, FinalityError> {
        self.catch_up_with_budget(source, target, &mut Budget::new())
    }
    fn catch_up_with_budget<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        target: NonZeroU64,
        budget: &mut Budget,
    ) -> Result<u64, FinalityError> {
        let current = self.checkpoint.height();
        if target.get() <= current {
            return Ok(current);
        }
        let mut prefix = Prefix::new(&self.checkpoint)?;
        match prefix.fetch_through(source, target.get(), budget) {
            Ok(()) => {}
            Err(FinalityError::ResourceLimit(_)) if prefix.height() > current => {}
            Err(error) => return Err(error),
        }
        self.replace_checkpoint(prefix.checkpoint()?);
        self.pending = None;
        Ok(self.checkpoint.height())
    }

    /// Verify a current member's fresh attestation against the exact retained native prefix.
    /// At most one block of lag is accepted; no arbitrary same-epoch decision is trusted.
    ///
    /// # Errors
    /// Invalid identity/signature/challenge, wrong network, nonmember, future or unretained tip.
    pub fn verify_attestation(
        &self,
        challenge: &[u8; 32],
        attestation: &SumeragiFinalityAttestation,
    ) -> Result<AttestedTip, FinalityError> {
        verify_identity(self.checkpoint.network_id(), challenge, attestation)?;
        if !self.members().contains(&attestation.body.node_id) {
            return Err(FinalityError::NotInCommittee {
                peer: Box::new(attestation.body.node_id.clone()),
            });
        }
        let tip = &attestation.body.finality_proof;
        let height = tip.height();
        let checkpoint = self.checkpoint.height();
        if height > checkpoint {
            return Err(FinalityError::AheadOfCheckpoint { checkpoint, height });
        }
        if height < checkpoint.saturating_sub(1) {
            return Err(FinalityError::OutsideRetainedPrefix { checkpoint, height });
        }
        self.native()?.verify_retained_decision(tip)?;
        Ok(AttestedTip {
            height: tip.block_header.height(),
            block_hash: tip.block_header.hash(),
        })
    }

    /// Count distinct authenticated committee members; duplicate statements count once.
    ///
    /// # Errors
    /// Zero challenge or insufficient valid committee statements, with per-peer outcomes.
    pub fn attestation_quorum(
        &self,
        challenge: &[u8; 32],
        attestations: &[SumeragiFinalityAttestation],
    ) -> Result<AttestationQuorum, FinalityError> {
        require_challenge(challenge)?;
        let mut peers = self
            .members()
            .into_iter()
            .map(|p| (p, AttestationOutcome::Missing))
            .collect::<Vec<_>>();
        for attestation in attestations {
            let Some((_, outcome)) = peers
                .iter_mut()
                .find(|(p, _)| *p == attestation.body.node_id)
            else {
                continue;
            };
            if !matches!(outcome, AttestationOutcome::Verified(_)) {
                *outcome = self
                    .verify_attestation(challenge, attestation)
                    .map_or_else(AttestationOutcome::Rejected, AttestationOutcome::Verified);
            }
        }
        let quorum = AttestationQuorum {
            height: self.checkpoint.tip().block_header.height(),
            block_hash: self.checkpoint.block_hash(),
            required: self.committee_size().quorum(),
            peers,
        };
        if quorum.verified() >= quorum.required {
            Ok(quorum)
        } else {
            Err(FinalityError::InsufficientAttestations(Box::new(quorum)))
        }
    }

    /// Query current and authenticated next-committee members, verify the certified chain toward
    /// their claimed tips, and publish the new checkpoint only when a fresh quorum of its
    /// committee attests tips on that chain.
    ///
    /// One contiguous prefix is verified per observation, each height at most once. Claims are
    /// taken highest first: the source supplies the blocks below a claim and the member's own
    /// proof only its claimed tip. A claim whose proof fails verification or exceeds the budget
    /// is reported for that member alone; it never aborts the observation and never spends the
    /// budget that other claims need. Members whose exact tips were verified anywhere in the
    /// prefix count, across committee boundaries, but at most one scheduling epoch back.
    ///
    /// When members claim tips beyond one observation budget, the observation returns
    /// [`FinalityError::CatchingUp`] and keeps the successors it verified for the next
    /// observation, which continues from them. This method changes its checkpoint only on fresh
    /// quorum success; a durable owner may separately retain the verified prefix while returning
    /// CatchingUp and requiring a new challenged observation for readiness.
    ///
    /// # Errors
    /// Zero challenge, peer budget exhaustion, [`FinalityError::CatchingUp`], or insufficient
    /// valid attestations.
    pub fn observe<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        challenge: &[u8; 32],
    ) -> Result<AttestationQuorum, FinalityError> {
        self.observe_with_budget(source, challenge, &mut Budget::new())
    }
    fn observe_with_budget<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        challenge: &[u8; 32],
        budget: &mut Budget,
    ) -> Result<AttestationQuorum, FinalityError> {
        require_challenge(challenge)?;
        let network = self.checkpoint.network_id();
        let mut prefix = Prefix::new(self.pending.as_ref().unwrap_or(self.checkpoint.as_ref()))?;
        let mut reads = BTreeMap::new();
        // Why a member's own proof could not extend the prefix: invalid or over budget.
        let mut unverified = BTreeMap::new();
        let mut source_failed_at = None;
        loop {
            let count = reads.len();
            read_members(&prefix, source, challenge, network, &mut reads)?;
            if reads.len() == count {
                break;
            }
            let mut claims = reads
                .iter()
                .filter_map(|(peer, read)| match read {
                    Read::Claim(attestation) => Some((peer, &attestation.body.finality_proof)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            claims.sort_by_key(|(_, proof)| Reverse(proof.height()));
            prefix.extend(
                source,
                &claims,
                budget,
                &mut source_failed_at,
                &mut unverified,
            );
        }
        let claimed = unverified
            .iter()
            .filter(|(_, error)| matches!(error, FinalityError::ResourceLimit(_)))
            .filter_map(|(peer, _)| match reads.get(peer) {
                Some(Read::Claim(attestation)) => Some(attestation.body.finality_proof.height()),
                _ => None,
            })
            .max();
        let verified = prefix.height();
        let report = prefix.report(&mut reads, &mut unverified)?;
        if report.verified() >= report.required {
            self.replace_checkpoint(prefix.checkpoint()?);
            if !norito::core::decode_limits_active() {
                // The published checkpoint contains this exact already verified prefix tip.
                // Keep that capability in its existing owner; newly offered witnesses still
                // require their own native verification. An enclosing decoder keeps the
                // original cold follow-up read and its physical allocation/refusal behavior.
                self.verified_tip.get_or_init(|| prefix.verified);
            }
            self.pending = None;
            return Ok(report);
        }
        match claimed {
            Some(claimed) if verified > prefix.start => {
                self.pending = Some(prefix.checkpoint()?);
                Err(FinalityError::CatchingUp { verified, claimed })
            }
            _ => {
                self.pending = None;
                Err(FinalityError::InsufficientAttestations(Box::new(report)))
            }
        }
    }
}

fn committee_peers(proof: &SumeragiFinalityProof) -> Vec<PeerId> {
    proof
        .committee
        .iter()
        .map(|validator| PeerId::new(validator.public_key.clone()))
        .collect()
}

/// One committee member's response to an observation's challenge.
enum Read {
    /// The source could not fetch a statement.
    Unreachable(String),
    /// Another node's statement came back.
    Substituted(Box<PeerId>),
    /// The statement failed its challenge, network, signature or consistency check.
    Invalid(Box<FinalityError>),
    /// A valid challenge-bound statement whose tip is still to be placed on the verified chain.
    Claim(Box<SumeragiFinalityAttestation>),
}

impl Read {
    fn new(
        response: Result<FinalityAttestation, String>,
        peer: &PeerId,
        challenge: &[u8; 32],
        network: NetworkId,
    ) -> Self {
        match response {
            Err(error) => Self::Unreachable(error),
            Ok(attestation) if attestation.attestation().body.node_id != *peer => {
                Self::Substituted(Box::new(attestation.attestation().body.node_id.clone()))
            }
            Ok(attestation) => {
                if let Err(error) =
                    verify_request_binding(network, challenge, attestation.attestation())
                {
                    return Self::Invalid(Box::new(error));
                }
                match attestation {
                    FinalityAttestation::Raw(attestation) => match attestation.verify() {
                        Ok(()) => Self::Claim(Box::new(attestation)),
                        Err(error) => Self::Invalid(Box::new(error.into())),
                    },
                    // The private SDK carrier retains the exact statement it already checked.
                    // Request rebinding above and trusted prefix placement below remain fresh.
                    FinalityAttestation::Authenticated(attestation) => {
                        Self::Claim(Box::new(attestation.into_attestation()))
                    }
                }
            }
        }
    }
}

/// Read each current and scheduled next committee member of the prefix tip, once per observation.
fn read_members<S: FinalitySource + ?Sized>(
    prefix: &Prefix,
    source: &S,
    challenge: &[u8; 32],
    network: NetworkId,
    reads: &mut BTreeMap<PeerId, Read>,
) -> Result<(), FinalityError> {
    let peers = prefix
        .members()?
        .into_iter()
        .filter(|peer| !reads.contains_key(peer))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if reads.len() + peers.len() > MAX_OBSERVATION_PEERS {
        return Err(FinalityError::ResourceLimit("peer count"));
    }
    let responses = source.latest_attestations(&peers, challenge);
    if responses.len() != peers.len() {
        return Err(FinalityError::ResourceLimit(
            "attestation batch cardinality",
        ));
    }
    for (peer, response) in peers.into_iter().zip(responses) {
        let read = Read::new(
            response.map_err(|error| error.to_string()),
            &peer,
            challenge,
            network,
        );
        reads.insert(peer, read);
    }
    Ok(())
}

/// A contiguous prefix verified from one starting checkpoint. It retains every decision it
/// verified, so a member's tip anywhere in it is checked against the exact certified decision at
/// that height.
struct Prefix {
    native: SumeragiFinalityVerifier,
    tip: SumeragiFinalityProof,
    verified: VerifiedSumeragiBlock,
    start: u64,
}

impl Prefix {
    fn new(checkpoint: &SumeragiFinalityCheckpoint) -> Result<Self, FinalityError> {
        let (native, verified) = if norito::core::decode_limits_active() {
            // An enclosing decoder owner retains the original two physical reads and their
            // cumulative allocation charges, including refusal during the second read.
            let native = SumeragiFinalityVerifier::from_trusted_checkpoint(
                checkpoint,
                &checkpoint.network_id(),
                checkpoint.chain_id(),
            )?;
            let verified = native.verify_retained_decision(checkpoint.tip())?;
            (native, verified)
        } else {
            // Complete import already authenticates this exact immutable tip. Keep its
            // capability; newly supplied member witnesses still use independent placement.
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                checkpoint,
                &checkpoint.network_id(),
                checkpoint.chain_id(),
                |_, native, verified| (native, verified),
            )?
        };
        Ok(Self {
            native,
            tip: checkpoint.tip().clone(),
            verified,
            start: checkpoint.height(),
        })
    }
    fn height(&self) -> u64 {
        self.tip.height()
    }
    fn checkpoint(&self) -> Result<SumeragiFinalityCheckpoint, FinalityError> {
        Ok(self.native.export_checkpoint(&self.tip)?)
    }
    /// The tip's committee and the committee its certified result schedules next.
    fn members(&self) -> Result<Vec<PeerId>, FinalityError> {
        let mut members = committee_peers(&self.tip);
        if let ScheduledSlot::Ready(next) = &self.verified.commitment().schedule.next {
            CommitteeSize::new(next.epoch.committee.len())?;
            members.extend(
                next.epoch
                    .committee
                    .iter()
                    .map(|member| member.validator.clone()),
            );
        }
        Ok(members)
    }
    /// Admit `proof` as the next block; nothing changes on failure.
    fn push(&mut self, proof: &SumeragiFinalityProof) -> Result<(), FinalityError> {
        CommitteeSize::new(proof.committee.len())?;
        self.verified = self.native.verify(proof)?;
        self.tip = proof.clone();
        Ok(())
    }
    /// Verify the source's successors through `height`, keeping the verified progress when the
    /// budget ([`FinalityError::ResourceLimit`]) or the source (any other error) stops it first.
    fn fetch_through<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        height: u64,
        budget: &mut Budget,
    ) -> Result<(), FinalityError> {
        while self.height() < height {
            let expected = self.height() + 1;
            if budget.proofs == 0 {
                return Err(FinalityError::ResourceLimit("proof count"));
            }
            let proof = source
                .finality_proof(NonZeroU64::new(expected).expect("successor is positive"))
                .map_err(FinalityError::transport)?;
            if proof.height() != expected {
                return Err(FinalityError::UnexpectedHeight {
                    expected,
                    actual: proof.height(),
                });
            }
            budget.charge(&proof)?;
            self.push(&proof)?;
        }
        Ok(())
    }
    /// Extend toward members' claims, highest first, until a pass adds nothing. The source
    /// supplies every block it can below a claim, and a member's own proof extends the prefix
    /// only at that member's claimed height, so a lower member's proof never displaces a source
    /// block. A failed claim is recorded for its member alone and is not retried.
    fn extend<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        claims: &[(&PeerId, &SumeragiFinalityProof)],
        budget: &mut Budget,
        source_failed_at: &mut Option<u64>,
        unverified: &mut BTreeMap<PeerId, FinalityError>,
    ) {
        loop {
            let before = self.height();
            for (peer, proof) in claims {
                if proof.height() <= self.height() || unverified.contains_key(*peer) {
                    continue;
                }
                if let Err(Some(error)) = self.reach(source, proof, budget, source_failed_at) {
                    unverified.insert((*peer).clone(), error);
                }
            }
            if self.height() == before {
                break;
            }
        }
    }
    /// Extend through one claimed tip. `Err(None)` means the source cannot supply a block below
    /// it yet; a later pass retries once other claims have extended the prefix.
    fn reach<S: FinalitySource + ?Sized>(
        &mut self,
        source: &S,
        proof: &SumeragiFinalityProof,
        budget: &mut Budget,
        source_failed_at: &mut Option<u64>,
    ) -> Result<(), Option<FinalityError>> {
        let parent = proof.height() - 1;
        // The source is not asked again at or above a height it already failed to supply.
        let limit = source_failed_at.map_or(parent, |failed| parent.min(failed.saturating_sub(1)));
        match self.fetch_through(source, limit, budget) {
            Ok(()) => {}
            Err(error @ FinalityError::ResourceLimit(_)) => return Err(Some(error)),
            Err(_) => {
                *source_failed_at = Some(self.height() + 1);
                return Err(None);
            }
        }
        if self.height() < parent {
            return Err(None);
        }
        // A member's own proof spends budget only once it verifies, so invalid claims cannot
        // starve the others.
        if let Some(reason) = budget.refuses(proof) {
            return Err(Some(FinalityError::ResourceLimit(reason)));
        }
        self.push(proof).map_err(Some)?;
        budget.charge(proof).map_err(Some)
    }
    /// Report every member of the tip's committee against this prefix.
    fn report(
        &self,
        reads: &mut BTreeMap<PeerId, Read>,
        unverified: &mut BTreeMap<PeerId, FinalityError>,
    ) -> Result<AttestationQuorum, FinalityError> {
        let epoch = self
            .verified
            .commitment()
            .schedule
            .current
            .authorization
            .epoch;
        let peers = committee_peers(&self.tip)
            .into_iter()
            .map(|peer| {
                let outcome = match reads.remove(&peer) {
                    None => AttestationOutcome::Missing,
                    Some(Read::Unreachable(error)) => AttestationOutcome::Unreachable(error),
                    Some(Read::Substituted(actual)) => {
                        AttestationOutcome::Rejected(FinalityError::UnexpectedPeer {
                            expected: Box::new(peer.clone()),
                            actual,
                        })
                    }
                    Some(Read::Invalid(error)) => AttestationOutcome::Rejected(*error),
                    Some(Read::Claim(attestation)) => self
                        .place(
                            &attestation.body.finality_proof,
                            epoch,
                            unverified.remove(&peer),
                        )
                        .map_or_else(AttestationOutcome::Rejected, AttestationOutcome::Verified),
                };
                (peer, outcome)
            })
            .collect();
        Ok(AttestationQuorum {
            height: self.tip.block_header.height(),
            block_hash: self.tip.block_header.hash(),
            required: CommitteeSize::new(self.tip.committee.len())?.quorum(),
            peers,
        })
    }
    /// Place a member's claimed tip on this prefix. `unverified` says why the member's own proof
    /// could not extend the prefix, if it tried.
    fn place(
        &self,
        proof: &SumeragiFinalityProof,
        epoch: u64,
        unverified: Option<FinalityError>,
    ) -> Result<AttestedTip, FinalityError> {
        let checkpoint = self.height();
        let height = proof.height();
        match unverified {
            Some(error) if !matches!(error, FinalityError::ResourceLimit(_)) => return Err(error),
            budget if height > checkpoint => {
                return Err(
                    budget.unwrap_or(FinalityError::AheadOfCheckpoint { checkpoint, height })
                );
            }
            _ => {}
        }
        // The starting checkpoint retains its tip's parent, but not that parent's parent.
        if height + 1 < self.start {
            return Err(FinalityError::OutsideRetainedPrefix { checkpoint, height });
        }
        // Only this complete immutable witness already produced the retained capability.
        // Equal block hashes alone cannot reuse it: a different header, canonical body,
        // committee or proof of possession still needs independent native verification.
        // An enclosing decoder keeps the original physical read and allocation charges.
        let verified_epoch = if !norito::core::decode_limits_active() && proof == &self.tip {
            self.verified
                .commitment()
                .schedule
                .current
                .authorization
                .epoch
        } else {
            self.native
                .verify_retained_decision(proof)?
                .commitment()
                .schedule
                .current
                .authorization
                .epoch
        };
        if verified_epoch < epoch.saturating_sub(1) {
            return Err(FinalityError::OutsideRetainedPrefix { checkpoint, height });
        }
        Ok(AttestedTip {
            height: proof.block_header.height(),
            block_hash: proof.block_header.hash(),
        })
    }
}

fn verify_identity(
    network: NetworkId,
    challenge: &[u8; 32],
    attestation: &SumeragiFinalityAttestation,
) -> Result<(), FinalityError> {
    verify_request_binding(network, challenge, attestation)?;
    attestation.verify()?;
    // Structural consistency binds the decoded genesis to the selected network; the tip
    // still requires exact retained-decision or contiguous-successor authentication.
    Ok(())
}

fn verify_request_binding(
    network: NetworkId,
    challenge: &[u8; 32],
    attestation: &SumeragiFinalityAttestation,
) -> Result<(), FinalityError> {
    require_challenge(challenge)?;
    if attestation.body.challenge != *challenge {
        return Err(FinalityError::StaleChallenge);
    }
    if attestation.body.network_id != network {
        return Err(FinalityError::WrongNetwork {
            expected: network,
            actual: attestation.body.network_id,
        });
    }
    Ok(())
}

fn require_challenge(challenge: &[u8; 32]) -> Result<(), FinalityError> {
    if *challenge == [0; 32] {
        Err(FinalityError::ZeroChallenge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
