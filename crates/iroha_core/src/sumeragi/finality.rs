//! Portable finality and challenged node statements from the current certified chain.

mod compact_source;
mod cursor;
mod interval;
mod proof_destination;
pub use compact_source::{
    NativeCommitCertificateDataV1, NativeCommitCertificateReadErrorV1, read_commit_certificate,
};
pub use cursor::{
    NativeCurrentFinalityV1, NativeFinalityAtHeightV1, NativeFinalityCursorErrorV1,
    NativeFinalityCursorV1,
};
pub use interval::{
    NativeFinalityProofInterval, NativeFinalityProofIntervalError,
    NativeFinalityProofIntervalLimits, NativeFinalityProofSource, build_proof_interval,
};
pub use proof_destination::ProofDestinationError;

use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    sumeragi::SumeragiStatus,
    sumeragi_finality::{
        FinalityError, FinalityValidator, SumeragiFinalityAttestation,
        SumeragiFinalityAttestationBody, SumeragiFinalityBundle, SumeragiFinalityCheckpoint,
        SumeragiFinalityProof, SumeragiFinalityVerifier,
    },
};
use norito::codec::Encode as _;

use super::{
    certified_chain::{
        CertifiedBlock, CertifiedChain, ChainReadError, QcVerification, proof_source_append,
        proof_source_start,
    },
    node::NodeIdentity,
};
use crate::state::StateReadOnly;

/// Why a current portable proof could not be served.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProofError {
    /// No current certified frame can be read for this height.
    #[error(transparent)]
    Chain(#[from] ChainReadError),
    /// The historical committee cannot independently verify this certificate.
    #[error("height {0} lacks an independently verified commit certificate")]
    UnverifiedCommittee(u64),
    /// Canonical framing failed.
    #[error("cannot encode certified block: {0}")]
    Encoding(String),
    /// The portable verifier rejected the produced proof.
    #[error(transparent)]
    Portable(#[from] FinalityError),
    /// The captured original execution source refused a current-tip certificate.
    #[error(transparent)]
    NativeExecution(iroha_data_model::query::error::QueryExecutionFail),
    /// Original local history acquisition has not completed.
    #[error(transparent)]
    Deferred(crate::execution_attempt::ExecutionDeferred),
}

impl From<crate::execution_attempt::ExecutionAttemptError<ChainReadError>> for ProofError {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<ChainReadError>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => Self::Chain(error),
            crate::execution_attempt::ExecutionAttemptError::Deferred(local) => {
                Self::Deferred(local)
            }
        }
    }
}

/// Build the current embedded-certificate proof from one immutable state view.
///
/// # Errors
/// Missing/corrupt frames, unavailable authenticated committees or invalid certificates.
pub fn build_proof(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<SumeragiFinalityProof, ProofError> {
    let chain = CertifiedChain::new(view)?;
    proof_from_chain(&chain, height)
}

/// A bounded sequential proof producer borrowed only within [`with_proof_reader`].
///
/// Each emitted proof passes the original native and independent portable checks.
/// Reuse additionally requires fresh complete native prefix bytes to match an ordered
/// digest of genuinely verified canonical receipts, before and after the read. The
/// source's original descriptor, index and namespace barriers still apply. A changed
/// or unavailable source discards every retained graph before the original standalone
/// producer retries; this local byte fence is never finality authority or a trust root.
pub struct FinalityProofReader<'v, V: StateReadOnly> {
    view: &'v V,
    chain: Option<CertifiedChain<'v, V>>,
    #[cfg(test)]
    after_verified: Option<&'v dyn Fn()>,
    #[cfg(test)]
    before_verified: Option<&'v dyn Fn()>,
}

/// Produce sequential proofs within one borrowed immutable State cut.
///
/// The native cursor is acquired lazily and dropped before return or unwind. The
/// immutable State view pins configured network, chain and original block hashes;
/// it does not freeze Kura files. Fresh original native byte scans therefore join
/// the cursor's authenticated source before reuse and before exposing a new proof.
pub fn with_proof_reader<V: StateReadOnly, R>(
    view: &V,
    read: impl FnOnce(&mut FinalityProofReader<'_, V>) -> R,
) -> R {
    let mut reader = FinalityProofReader {
        view,
        chain: None,
        #[cfg(test)]
        after_verified: None,
        #[cfg(test)]
        before_verified: None,
    };
    read(&mut reader)
}

impl<V: StateReadOnly> FinalityProofReader<'_, V> {
    /// Read an independently checked proof from the original certified source.
    ///
    /// An enclosing decode-limit scope always uses [`build_proof`] after dropping
    /// any warm cursor. No source scan, byte capture or warm validation replaces
    /// the original physical charges or typed refusal under that caller's budget.
    /// Earlier/equal reads use the native genesis reset. Every refusal discards
    /// the cursor; missing or changed byte custody selects the original producer.
    ///
    /// # Errors
    /// The original source, certificate, resource and portable errors from [`build_proof`].
    pub fn proof(&mut self, height: u64) -> Result<SumeragiFinalityProof, ProofError> {
        if norito::core::decode_limits_active() {
            drop(self.chain.take());
            return build_proof(self.view, height);
        }
        if let Some(chain) = self.chain.as_ref() {
            let unchanged = chain.proof_source_cut().is_some_and(|(at, original)| {
                current_prefix_source(self.view, at) == Some(original)
            });
            if !unchanged {
                drop(self.chain.take());
                return build_proof(self.view, height);
            }
        }
        #[cfg(test)]
        if let Some(change_original) = self.before_verified.take() {
            change_original();
        }
        let result = match self.chain.as_ref() {
            Some(chain) => proof_from_chain(chain, height),
            None => {
                let mut chain = CertifiedChain::new(self.view)?;
                chain.enable_proof_source_cut();
                let result = proof_from_chain(&chain, height);
                if result.is_ok() {
                    self.chain = Some(chain);
                }
                result
            }
        };
        match result {
            Err(error) => {
                // A warm verifier's source/physical failure cannot replace the
                // fresh producer's exact diagnosis after all retained owners retire.
                drop(error);
                drop(self.chain.take());
                build_proof(self.view, height)
            }
            Ok(proof) => {
                #[cfg(test)]
                if let Some(change_original) = self.after_verified.take() {
                    change_original();
                }
                let unchanged = self
                    .chain
                    .as_ref()
                    .and_then(CertifiedChain::proof_source_cut)
                    .is_some_and(|(at, original)| {
                        current_prefix_source(self.view, at) == Some(original)
                    });
                if unchanged {
                    Ok(proof)
                } else {
                    // No cached graph or offered DTO remains while the original
                    // producer independently diagnoses the current native source.
                    drop(proof);
                    drop(self.chain.take());
                    build_proof(self.view, height)
                }
            }
        }
    }
}

// Read no codec graph, create no capacity, and retain no per-height table. Every
// raw destination is owned by the original finite execution pool and released
// before the next frame. A loss/refusal only disables reuse; the original producer
// remains the sole error/authentication owner after all cached graphs are dropped.
fn current_prefix_source(view: &impl StateReadOnly, height: u64) -> Option<Hash> {
    let hashes = view.block_hashes();
    let count = usize::try_from(height).ok()?;
    if count == 0 || count > hashes.len() {
        return None;
    }
    let budget = view.execution_budget();
    let first = view.kura().native_frame_read(1, *hashes.first()?).ok()??;
    let mut digest = proof_source_start();
    for (index, expected) in hashes.iter().take(count).enumerate() {
        let at = u64::try_from(index.checked_add(1)?).ok()?;
        let source = view.kura().native_frame_read(at, *expected).ok()??;
        if !first.same_journal_image(&source) {
            return None;
        }
        let length = source.wire_len();
        let bytes = source.read(length, &budget).ok()??;
        digest = proof_source_append(digest, at, length, Hash::new(bytes.as_slice()));
    }
    let after = view.kura().native_frame_read(1, *hashes.first()?).ok()??;
    first.same_journal_image(&after).then_some(digest)
}

fn proof_from_chain<V: StateReadOnly>(
    chain: &CertifiedChain<'_, V>,
    height: u64,
) -> Result<SumeragiFinalityProof, ProofError> {
    proof_from_certified(chain.certified(height)?, height)
}

fn proof_from_certified(
    certified: CertifiedBlock,
    height: u64,
) -> Result<SumeragiFinalityProof, ProofError> {
    if !matches!(
        (height, certified.verification()),
        (1, QcVerification::Genesis) | (2.., QcVerification::Verified)
    ) {
        return Err(ProofError::UnverifiedCommittee(height));
    }
    let proof = SumeragiFinalityProof {
        block_header: certified.block().header(),
        block_wire: certified
            .block()
            .encode_wire()
            .map_err(|error| ProofError::Encoding(error.to_string()))?,
        // The complete certified read already authenticates this exact
        // historical epoch. Project its original keys/PoPs without a second
        // prefix read; portable verification below remains independent.
        committee: certified
            .commitment()
            .schedule
            .current
            .committee
            .iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            })
            .collect(),
    };
    // The native reader verifies exact BLS quorums and source-bound execution before serving.
    // Portable checks additionally enforce the independent client framing contract.
    proof.decode_checked()?;
    Ok(proof)
}

/// Export a portable checkpoint from the node's authenticated native history.
///
/// The returned checkpoint is suitable for local response self-checks. Remote
/// clients must select their own trust root independently of the served response.
/// Each iteration retains at most three portable decisions; original Core history
/// verification and its resource limits remain owned by `CertifiedChain`.
///
/// # Errors
/// Missing history, invalid finality or any failure to retain the exact checkpoint.
pub fn build_checkpoint(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<SumeragiFinalityCheckpoint, ProofError> {
    let chain = CertifiedChain::new(view)?;
    // Refuse an unavailable target before walking any prefix.
    let tip = proof_from_chain(&chain, height)?;
    let genesis = proof_from_chain(&chain, 1)?;
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        &view.chain_id().to_string(),
        genesis.committee.clone(),
    )?;
    for at in 1..=height {
        let proof = if at == height {
            tip.clone()
        } else {
            proof_from_chain(&chain, at)?
        };
        verifier.verify(&proof)?;
        let checkpoint = verifier.export_checkpoint(&proof)?;
        if at == height {
            return Ok(checkpoint);
        }
        verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            view.network_id(),
            &view.chain_id().to_string(),
        )?;
    }
    Err(ProofError::UnverifiedCommittee(height))
}

/// Build a network-bound current proof bundle from one immutable state view.
///
/// # Errors
/// See [`build_proof`].
pub fn build_bundle(
    view: &impl StateReadOnly,
    height: u64,
) -> Result<SumeragiFinalityBundle, ProofError> {
    Ok(SumeragiFinalityBundle {
        network_id: *view.network_id(),
        finality_proof: build_proof(view, height)?,
    })
}

/// Why a challenged current-driver capture cannot be signed.
#[derive(Debug, thiserror::Error)]
pub enum AttestationBuildError {
    /// Genesis is not committed.
    #[error("cannot attest an empty state")]
    EmptyState,
    /// The state height cannot fit on the wire.
    #[error("committed height exceeds u64")]
    HeightOverflow,
    /// Requested and immutable state-tip heights differ.
    #[error("requested height {requested} is not durable tip {committed}")]
    HeightIsNotDurableTip {
        /// Requested height.
        requested: u64,
        /// Immutable applied height.
        committed: u64,
    },
    /// A separately sampled driver status has not reached exactly this applied tip.
    #[error("driver status and durable tip heights differ")]
    StatusHeightMismatch,
    /// The current driver stopped or halted.
    #[error("consensus requires restart")]
    RestartRequired,
    /// Status contradicts its current consensus instance or its local identity.
    #[error("current driver status is inconsistent")]
    InvalidStatus,
    /// The supplied signer is not the installed BLS node key.
    #[error("attestation signer is not the installed BLS node key")]
    InvalidSigner,
    /// The tip proof is unavailable or invalid.
    #[error("tip proof unavailable: {0}")]
    FinalityProof(ProofError),
    /// The genesis proof is unavailable or invalid.
    #[error("genesis proof unavailable: {0}")]
    GenesisFinalityProof(ProofError),
    /// The final exact body failed consistency validation.
    #[error(transparent)]
    InvalidBody(FinalityError),
    /// The current installed node wall clock is before the Unix epoch, zero or overflowing.
    #[error("current node Unix clock is unavailable")]
    ClockUnavailable,
    /// Signing failed.
    #[error("node signing failed: {0}")]
    Signing(String),
}

/// Whether the actual driver's public status is internally coherent.
#[must_use]
pub fn status_is_consistent(status: &SumeragiStatus) -> bool {
    status.stage <= 2
        && status.applied_height <= status.committed_height
        && status.height >= status.committed_height
        && status.height <= status.committed_height.saturating_add(1)
}

/// Sign an exact durable-tip capture using the installed current node identity.
///
/// Past H2, ordinary State-backed captures join the current certificate to the
/// genesis successor through the original execution ancestry. Every native frame
/// remains required, while intervening local quorum witnesses need no independent
/// re-verification. Standalone exports and active Norito callers retain their
/// full-prefix verification contract.
///
/// # Errors
/// Missing proofs, mismatched heights/identity/instance, halted state or invalid signing.
pub fn build_attestation(
    view: &impl StateReadOnly,
    status: SumeragiStatus,
    identity: &NodeIdentity,
    build_fingerprint: Hash,
    height: u64,
    challenge: [u8; 32],
    signer: &KeyPair,
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    use AttestationBuildError as Error;
    if signer.algorithm() != Algorithm::BlsNormal
        || identity.node_id.public_key() != signer.public_key()
    {
        return Err(Error::InvalidSigner);
    }
    if status.is_halted() {
        return Err(Error::RestartRequired);
    }
    if !status_is_consistent(&status)
        || status
            .signer
            .as_ref()
            .is_some_and(|key| key != identity.node_id.public_key())
    {
        return Err(Error::InvalidStatus);
    }
    let committed = u64::try_from(view.block_hashes().len()).map_err(|_| Error::HeightOverflow)?;
    let genesis_block_hash = view
        .block_hashes()
        .first()
        .copied()
        .ok_or(Error::EmptyState)?;
    if height != committed {
        return Err(Error::HeightIsNotDurableTip {
            requested: height,
            committed,
        });
    }
    // The active caller keeps its original full-prefix recipe and cumulative charges.
    // Ordinary current captures use this same State generation's original execution tip.
    // One reverse source walk joins the target to H2 and genesis, checking both
    // selected QCs/availability and the exact separately projected genesis result.
    // No producer cursor, source verdict or challenge is retained across calls.
    let (genesis_finality_proof, finality_proof) = {
        let proof_chain =
            CertifiedChain::new(view).map_err(|error| Error::GenesisFinalityProof(error.into()))?;
        let (genesis_decision, genesis) =
            attestation_genesis_proof(&proof_chain).map_err(Error::GenesisFinalityProof)?;
        let tip = if height == 1 {
            genesis.clone()
        } else if height > 2 && !norito::core::decode_limits_active() {
            current_execution_proof(&proof_chain, height, genesis_decision)
                .map_err(Error::FinalityProof)?
        } else {
            proof_from_chain(&proof_chain, height).map_err(Error::FinalityProof)?
        };
        (genesis, tip)
    };
    finish_attestation(
        view,
        status,
        identity,
        build_fingerprint,
        challenge,
        signer,
        AttestationProofs {
            committed,
            genesis_block_hash,
            genesis: genesis_finality_proof,
            tip: finality_proof,
        },
    )
}

// Coordinates of the exact native receipt projected into the returned genesis proof.
// A signed genesis proposal alone never authenticates its attached execution R.
struct GenesisDecision {
    block_hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    core_hash: iroha_sumeragi::types::Hash32,
    result: iroha_sumeragi::types::Hash32,
}

// Only the portable proof and its Copy source coordinates leave this genesis phase.
// The consumed native receipt's large stack slots retire before the tip walk begins.
#[inline(never)]
fn attestation_genesis_proof<V: StateReadOnly>(
    chain: &CertifiedChain<'_, V>,
) -> Result<(GenesisDecision, SumeragiFinalityProof), ProofError> {
    let native_genesis = chain.certified(1)?;
    let decision = GenesisDecision {
        block_hash: native_genesis.block_hash(),
        core_hash: native_genesis.core_hash(),
        result: native_genesis.result(),
    };
    let proof = proof_from_certified(native_genesis, 1)?;
    Ok((decision, proof))
}

// Current statements retain every native ancestry read, but need not independently
// reverify each intervening local QC after that execution was published into State.
// Generic proof, checkpoint and sequential export keep their full-prefix contracts.
fn current_execution_proof<V: StateReadOnly>(
    chain: &CertifiedChain<'_, V>,
    height: u64,
    genesis: GenesisDecision,
) -> Result<SumeragiFinalityProof, ProofError> {
    let target = usize::try_from(height)
        .ok()
        .and_then(std::num::NonZeroUsize::new)
        .ok_or(ChainReadError::NotInView { height })?;
    // The existing single reverse walk retains bounded receipts and uses the original
    // State allocation pool. No codec scope, allowance or imported trust is installed.
    chain
        .certified_with_ancestor_from_execution_into(
            target,
            |_, _| Ok(()),
            |_| Ok(std::num::NonZeroUsize::new(2)),
            |tip, anchor| finish_current_execution_proof(tip, anchor, height, genesis),
        )
        .map_err(|error| match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                ProofError::NativeExecution(error)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(local) => {
                ProofError::Deferred(local)
            }
        })?
}

// Receipt unpacking, genesis joining and portable projection run only after the original
// reverse walk has returned. No target/ancestor Result tuple occupies its decoder ancestry.
// The parameter order preserves anchor-before-tip retirement on an early refusal.
#[inline(never)]
fn finish_current_execution_proof(
    tip: CertifiedBlock,
    anchor: Option<CertifiedBlock>,
    height: u64,
    genesis: GenesisDecision,
) -> Result<SumeragiFinalityProof, ProofError> {
    let anchor = anchor.ok_or(ProofError::UnverifiedCommittee(2))?;
    if anchor.height() != 2
        || anchor.block().header().prev_block_hash() != Some(genesis.block_hash)
        || !anchor.header().is_some_and(|header| {
            header.parent_hash == genesis.core_hash && header.parent_result == genesis.result
        })
    {
        return Err(ChainReadError::Discontinuous { height: 2 }.into());
    }
    drop(anchor);
    // Clients still receive and independently verify the same complete portable proof.
    proof_from_certified(tip, height)
}

// Only the two genuinely produced portable proofs and Copy source projections leave
// the producer phase. No native prefix, authority or source guard crosses this seam.
struct AttestationProofs {
    committed: u64,
    genesis_block_hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    // Match the original local proof drop order on an early tail refusal.
    tip: SumeragiFinalityProof,
    genesis: SumeragiFinalityProof,
}

// The fresh source/instance fence and its native owner retain their original lifetime
// through body validation, signing and final verification. Their stack slots do not
// exist while the independent proof producer is decoding its certificates.
#[inline(never)]
fn finish_attestation(
    view: &impl StateReadOnly,
    status: SumeragiStatus,
    identity: &NodeIdentity,
    build_fingerprint: Hash,
    challenge: [u8; 32],
    signer: &KeyPair,
    proofs: AttestationProofs,
) -> Result<SumeragiFinalityAttestation, AttestationBuildError> {
    use AttestationBuildError as Error;
    let chain = CertifiedChain::new(view).map_err(|error| Error::FinalityProof(error.into()))?;
    if status.instance != chain.instance().0 {
        return Err(Error::InvalidStatus);
    }
    // Only a height mismatch after successful proof and identity validation is retryable.
    if status.applied_height != proofs.committed || status.committed_height != proofs.committed {
        return Err(Error::StatusHeightMismatch);
    }
    let observed_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|reading| u64::try_from(reading.as_millis()).ok())
        .filter(|reading| *reading != 0)
        .ok_or(Error::ClockUnavailable)?;
    let body = SumeragiFinalityAttestationBody {
        challenge,
        observed_at_unix_ms,
        network_id: *view.network_id(),
        node_id: identity.node_id.clone(),
        node_fingerprint: Hash::new(identity.node_id.encode()),
        build_fingerprint,
        config_fingerprint: identity.config_fingerprint,
        genesis_block_hash: proofs.genesis_block_hash,
        genesis_finality_proof: proofs.genesis,
        status,
        finality_proof: proofs.tip,
    };
    body.validate_consistency().map_err(Error::InvalidBody)?;
    let signature = SignatureOf::try_from_hash(signer.private_key(), body.signing_hash())
        .map_err(|error| Error::Signing(error.to_string()))?;
    let attestation = SumeragiFinalityAttestation { body, signature };
    if norito::core::decode_limits_active() {
        // An enclosing owner retains the original second body decode and its charges/refusals.
        attestation.verify().map_err(Error::InvalidBody)?;
    } else {
        // This exact immutable body already passed complete consistency checks above. Its
        // move into the statement changes no proof or binding; verify the fresh signature
        // without repeating both independent native proof decodes in this same invocation.
        attestation
            .signature
            .verify_hash(
                attestation.body.node_id.public_key(),
                attestation.body.signing_hash(),
            )
            .map_err(|error| Error::InvalidBody(FinalityError(error.to_string())))?;
    }
    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    };

    // The normal-stack native fixture completes before the later proof-reader
    // assertion frame exists. Its genuinely signed prefix and original State
    // remain owned by this helper throughout both independent reads.
    #[inline(never)]
    fn with_original_finality_boundary(assert_original: fn(&CertifiedTestChain)) {
        let mut chain = Box::new(CertifiedTestChain::npos_boundary_fixture());
        chain.commit(Vec::new());
        assert_eq!(chain.height(), 10);
        assert_original(&chain);
    }

    // Independent test oracle: exactly one complete native certified read. It
    // does not call the producer or the separate proof_committee read, and it
    // retains the unchanged canonical output, including every original PoP.
    #[inline(never)]
    fn original_finality_from_one_certified_read<V: StateReadOnly>(
        view: &V,
        height: u64,
        require_native_boundary: bool,
    ) -> Result<SumeragiFinalityProof, ProofError> {
        let reader = CertifiedChain::new(view)?;
        let original = reader.certified(height)?;
        assert_eq!(original.height(), height);
        assert_eq!(
            original.verification(),
            if height == 1 {
                QcVerification::Genesis
            } else {
                QcVerification::Verified
            }
        );
        if require_native_boundary {
            let qc = original.commit_qc().expect("genuine boundary CommitQC");

            assert_eq!(qc.signers.count_ones(), 3);

            assert!(original.commitment().schedule.boundary.is_some());
        }
        Ok(SumeragiFinalityProof {
            block_header: original.block().header(),
            block_wire: original
                .block()
                .encode_wire()
                .expect("original canonical signed frame"),
            committee: original
                .commitment()
                .schedule
                .current
                .committee
                .iter()
                .map(|member| FinalityValidator {
                    public_key: member.validator.public_key().clone(),
                    proof_of_possession: member.proof_of_possession.clone(),
                })
                .collect(),
        })
    }

    #[inline(never)]
    fn assert_single_certified_finality_source(
        chain: &CertifiedTestChain,
        height: u64,
        expected_frames: &[u64],
        expected_qcs: &[u64],
        require_native_boundary: bool,
    ) {
        use crate::sumeragi::certified_chain::relation_counts;

        let view = chain.state().view();
        let (original, once) = relation_counts::measure(|| {
            original_finality_from_one_certified_read(&view, height, require_native_boundary)
        });
        let original = original.expect("the exact signed original prefix authenticates once");
        assert_eq!(once.frames, expected_frames);
        assert_eq!(once.qcs, expected_qcs);
        assert!(original.decode_checked().is_ok());

        let (produced, served) = relation_counts::measure(|| build_proof(&view, height));
        let produced = produced.expect("ordinary current-source proof producer");
        assert_eq!(
            produced, original,
            "same header, canonical signed bytes and exact epoch PoPs"
        );
        assert_eq!(produced.height(), height);
        assert!(produced.decode_checked().is_ok());
        assert_eq!(
            served.frames, once.frames,
            "portable producer must use the same already authenticated source instead of reading its committee again"
        );
        assert_eq!(
            served.qcs, once.qcs,
            "the committee projection must not repeat the complete native quorum verification"
        );
    }

    #[test]
    fn portable_genesis_proof_uses_one_authenticated_frame_relation() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
            .expect("actual signed genesis and retained State");
        assert_single_certified_finality_source(&chain, 1, &[1, 1], &[], false);
    }

    #[test]
    fn portable_proof_uses_one_authenticated_prefix_for_exact_committee() {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
            .expect("actual signed genesis and retained State");
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        assert_single_certified_finality_source(&chain, 3, &[1, 3, 2], &[2, 3], false);
    }

    #[test]
    fn portable_native_boundary_proof_uses_one_authenticated_prefix_and_original_quorum() {
        with_original_finality_boundary(
            assert_portable_native_boundary_proof_uses_one_authenticated_prefix_and_original_quorum,
        );
    }

    #[inline(never)]
    fn assert_portable_native_boundary_proof_uses_one_authenticated_prefix_and_original_quorum(
        chain: &CertifiedTestChain,
    ) {
        assert_single_certified_finality_source(
            chain,
            10,
            &[1, 10, 2, 3, 4, 5, 6, 7, 8, 9],
            &[2, 3, 4, 5, 6, 7, 8, 9, 10],
            true,
        );
    }

    #[test]
    fn portable_proof_uses_current_embedded_certificates_and_rejects_subquorum() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit_at(20_000, Vec::new());
        let proof = build_proof(&chain.state().view(), 2).unwrap();
        assert_eq!(proof.height(), 2);
        assert_eq!(proof.committee.len(), 4);
        assert!(proof.decode_checked().is_ok());
        assert!(build_proof(&chain.state().view(), 1).is_ok());
        assert!(build_proof(&chain.state().view(), 0).is_err());
        assert!(build_proof(&chain.state().view(), 3).is_err());

        let mut invalid =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        invalid.commit_at(20_000, Vec::new());
        invalid.corrupt_local_quorum_for_test(2, Signers::BelowQuorum);
        assert!(matches!(
            build_proof(&invalid.state().view(), 2),
            Err(ProofError::Chain(ChainReadError::Certificate { .. }))
        ));
    }
    #[test]
    fn original_checkpoint_binary_refusal_is_local_and_retries_exact_original_source() {
        use crate::execution_attempt::ExecutionDeferred;
        use iroha_data_model::block::decode_framed_signed_block;
        use ivm::error::ExecutionDeferral;
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000))
            .expect("original signed State genesis");
        chain.commit(Vec::new());
        let view = chain.state().view();
        let checkpoint = build_checkpoint(&view, 2).unwrap();
        let original = checkpoint.encode_canonical().unwrap();
        let chain_id = view.chain_id().to_string();
        let wire = chain
            .genesis()
            .canonical_resultless_proposal()
            .unwrap()
            .encode_wire()
            .unwrap();
        let limits = |allocation| {
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
        };
        let producer =
            norito::with_decode_limits_scope(limits(0), || decode_framed_signed_block(&wire))
                .unwrap_err();
        assert_eq!(
            producer.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        assert!(
            matches!(producer.into_error().decode_resource_error(), Some(
            norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
        ) if attempted > 0)
        );
        let read = || {
            SumeragiFinalityVerifier::from_trusted_checkpoint(
                &checkpoint,
                &chain.network_id(),
                &chain_id,
            )
        };
        let error =
            norito::with_decode_limits_scope(limits(0), || read().map_err(ProofError::from))
                .unwrap_err();
        let expected = ExecutionDeferred::from(ExecutionDeferral::ActiveMemoryCapacity);
        assert!(
            matches!(&error, ProofError::Deferred(local) if local == &expected),
            "{error:?}"
        );
        assert_eq!(checkpoint.encode_canonical().unwrap(), original);
        let retried = read().unwrap();
        assert_eq!(
            retried.export_checkpoint(checkpoint.tip()).unwrap(),
            checkpoint
        );
        let (retained, retried_with_outer) =
            norito::with_decode_limits_scope(limits(8 * 1024 * 1024), || {
                let inner = norito::with_decode_limits_scope(limits(0), read).unwrap_err();
                let retained = ProofError::from(inner);
                assert!(
                    matches!(&retained, ProofError::Deferred(local) if local == &expected),
                    "the original inner refusal survives its caller scope: {retained:?}"
                );
                (retained, read().unwrap())
            });
        assert!(
            matches!(&retained, ProofError::Deferred(local) if local == &expected),
            "the captured original refusal survives all caller scopes: {retained:?}"
        );
        assert_eq!(
            retried_with_outer
                .export_checkpoint(checkpoint.tip())
                .unwrap(),
            checkpoint
        );
        // A new canonical attempt cannot borrow the retired attempt's opaque origin.
        let reintroduced = norito::with_decode_limits_scope(limits(8 * 1024 * 1024), || {
            let inner = norito::with_decode_limits_scope(limits(0), read).unwrap_err();
            let iroha_data_model::sumeragi_finality::FinalityReadError::DecodeResource(original) =
                inner
            else {
                panic!("the actual checkpoint read must retain its original decoder error");
            };
            assert_eq!(
                original.kind(),
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
            );
            let stale = original.into_error();
            let recaptured =
                norito::core::classify_decode_attempt(|| Err::<(), _>(stale)).unwrap_err();
            assert_eq!(
                recaptured.kind(),
                norito::core::DecodeAttemptErrorKind::Invalid
            );
            ProofError::from(
                iroha_data_model::sumeragi_finality::FinalityReadError::DecodeResource(recaptured),
            )
        });
        assert!(
            matches!(reintroduced, ProofError::Portable(_)),
            "a fresh observer rejects the retired origin: {reintroduced:?}"
        );
        // Copied diagnostic numbers carry no original emitting layer or attempt family.
        let reconstructed = norito::with_decode_limits_scope(limits(0), || {
            let error = norito::core::classify_decode_attempt(|| {
                Err::<(), _>(norito::Error::TotalAllocationExceeded {
                    attempted: 1,
                    limit: 0,
                })
            })
            .unwrap_err();
            assert_eq!(error.kind(), norito::core::DecodeAttemptErrorKind::Invalid);
            ProofError::from(
                iroha_data_model::sumeragi_finality::FinalityReadError::DecodeResource(error),
            )
        });
        assert!(
            matches!(reconstructed, ProofError::Portable(_)),
            "copied numbers cannot mint local admission provenance: {reconstructed:?}"
        );
        assert_eq!(checkpoint.encode_canonical().unwrap(), original);
    }

    #[test]
    fn native_checkpoint_continues_the_exact_original_prefix() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let view = chain.state().view();
        let checkpoint = build_checkpoint(&view, 2).unwrap();
        assert_eq!(checkpoint.height(), 2);
        assert_eq!(checkpoint.network_id(), chain.network_id());
        let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &chain.network_id(),
            &view.chain_id().to_string(),
        )
        .unwrap();
        let next = build_proof(&view, 3).unwrap();
        assert_eq!(verifier.verify(&next).unwrap().header(), next.block_header);
        assert!(build_checkpoint(&view, 0).is_err());
        assert!(build_checkpoint(&view, 4).is_err());
    }

    #[test]
    fn portable_builder_verifies_original_boundary_commit_quorum() {
        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        chain.commit(Vec::new());
        let proof = build_proof(&chain.state().view(), 10).unwrap();
        assert_eq!(proof.height(), 10);
        assert!(proof.decode_checked().is_ok());
    }

    #[test]
    fn native_attestation_signs_actual_current_unix_reading_separately_from_block_time() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 10_000)).unwrap();
        chain.commit_at(20_000, Vec::new());
        let signer = KeyPair::from_seed(vec![0xC1; 32], Algorithm::BlsNormal);
        let identity = NodeIdentity {
            node_id: iroha_model_base::peer::PeerId::new(signer.public_key().clone()),
            config_fingerprint: Hash::new(b"actual test native configuration"),
        };
        let status = SumeragiStatus {
            protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: identity.config_fingerprint,
            beacon_horizon: None,
            instance: chain.instance().0,
            height: 3,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 100,
            committed_height: 2,
            applied_height: 2,
            awaiting: false,
            signer: Some(signer.public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: iroha_data_model::sumeragi::SumeragiFootprint::default(),
        };
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let original = build_attestation(
            &chain.state().view(),
            status,
            &identity,
            Hash::new(b"actual test native executable"),
            2,
            [41; 32],
            &signer,
        )
        .unwrap();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let observed = u128::from(original.body.observed_at_unix_ms);
        assert!(observed >= before && observed <= after);
        assert_ne!(
            original.body.observed_at_unix_ms,
            original.body.finality_proof.block_header.creation_time_ms
        );
        original.verify().unwrap();
        let mut changed = original;
        changed.body.observed_at_unix_ms += 1;
        assert!(
            changed.verify().is_err(),
            "the exact current reading belongs to the node's signature"
        );
    }
}

#[cfg(test)]
#[path = "finality/attestation_tests.rs"]
mod attestation_tests;

impl From<iroha_data_model::sumeragi_finality::FinalityReadError> for ProofError {
    fn from(error: iroha_data_model::sumeragi_finality::FinalityReadError) -> Self {
        use iroha_data_model::sumeragi_finality::FinalityReadError;
        match error {
            FinalityReadError::Invalid(error) => Self::Portable(error),
            FinalityReadError::DecodeResource(original) => {
                let completed = |error: norito::core::DecodeAttemptError| {
                    Self::Portable(FinalityError(error.to_string()))
                };
                if cfg!(all(test, sumeragi_core_mutation = "HC52")) {
                    return completed(original);
                }
                match crate::execution_attempt::canonical_decode_attempt_error(original, completed)
                {
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    crate::execution_attempt::ExecutionAttemptError::Deferred(local) => {
                        Self::Deferred(local)
                    }
                }
            }
            FinalityReadError::Genesis(error) => {
                match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                    Self::Encoding(error.to_string())
                }) {
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        Self::Deferred(reason)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "finality/proof_reader_tests.rs"]
mod proof_reader_tests;
