//! Native source-complete paired-Pasta Commit attestations and original-execution publication.
//!
//! A verifier consumes only the exact core signing statement, its canonical result preimage
//! and one compact paired signature. The result's complete epoch must hash to the context the
//! core already authenticated for that height. No local execution cache, World lookup, quorum
//! subset or obsolete height context grants verification authority.

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, ChargedBuffer, ChargedShared,
    PrepaidSharedError, RetainedPayload,
    release::{ReleaseNotification, ReleaseWait},
};
use iroha_data_model::{
    NetworkId,
    isi::kagemusha_v1::{
        KAGEMUSHA_CHAIN_VERSION_V1, KagemushaFinalityTrustAnchorV1,
        KagemushaMintFinalityAuthorityGenerationV1, KagemushaMintFinalitySealBundleV1,
        KagemushaMintFinalitySealMessageV1, KagemushaMintFinalityValidatorSealV1,
        KagemushaPastaSchnorrSignatureV1, kagemusha_mint_finality_root_v1,
    },
    sumeragi_finality::{SumeragiFinalityProof, SumeragiFinalityVerifier},
};
use iroha_sumeragi::{
    crypto::{AttestOutcome, AttestationVerifier, Attestor, verify_attestations},
    message::{AttestationSignature, BlockHeader, CommitAttestation, Qc, ResultWitness},
    preimage::AttestationStatement,
    types::{Committee, Hash32, PublicKey, ValidatorIndex},
};
use std::sync::{Mutex, TryLockError};

use super::{
    commitment::{ExecutionResultCommitment, result_of_preimage},
    crypto::core_key,
};
use crate::zk::kagemusha_v1_recursion::{
    KagemushaMintFinalityLocalAuthorityV1, kagemusha_mint_finality_empty_root_v1,
    verify_kagemusha_mint_finality_validator_seal_v1,
};

const SEAL_BYTES: usize = 4 + 4 * 32;

/// Pure verifier pinned to the actual network and native consensus instance.
#[derive(Clone, Copy, Debug)]
pub struct NativePastaVerifier {
    instance: Hash32,
    network: NetworkId,
}
impl NativePastaVerifier {
    /// Pin the verifier to the configured instance and signed-genesis network.
    #[must_use]
    pub const fn new(instance: Hash32, network: NetworkId) -> Self {
        Self { instance, network }
    }

    /// Check the same native seal relation against an already-decoded original result.
    /// The caller must independently bind this immutable graph to the exact witness bytes
    /// and result hash. This relation does not authenticate the enclosing certificate.
    pub(super) fn verify_decoded_share(
        &self,
        height: u64,
        signer: ValidatorIndex,
        key: &PublicKey,
        source: AttestationStatement,
        result: &ExecutionResultCommitment,
        signature: &[u8],
    ) -> bool {
        if source.instance != self.instance || source.height != height {
            return false;
        }
        let Ok(message) = message_from_result(self.instance, self.network, source, result) else {
            return false;
        };
        let Some(member) = result.schedule.current.committee.get(signer as usize) else {
            return false;
        };
        if core_key(member.validator.public_key()).ok().as_ref() != Some(key) {
            return false;
        }
        let Some(seal) = decode_seal(signature) else {
            return false;
        };
        seal.validator_index == signer
            && verify_kagemusha_mint_finality_validator_seal_v1(
                &result.schedule.current.authority,
                &message,
                &seal,
            )
            .is_ok()
    }
}
impl AttestationVerifier for NativePastaVerifier {
    fn verify(
        &self,
        height: u64,
        signer: ValidatorIndex,
        key: &PublicKey,
        statement: &[u8],
        witness: &ResultWitness,
        signature: &[u8],
    ) -> bool {
        let Some(source) = AttestationStatement::parse(statement) else {
            return false;
        };
        if source.instance != self.instance
            || source.height != height
            || result_of_preimage(witness.as_slice()) != source.result
        {
            return false;
        }
        let Ok(result) = ExecutionResultCommitment::decode(witness.as_slice()) else {
            return false;
        };
        self.verify_decoded_share(height, signer, key, source, &result, signature)
    }
}

/// Why an original execution cannot produce a native Pasta receipt.
#[derive(Debug, thiserror::Error)]
pub enum NativeAttestationError {
    /// Original result, preimage, immutable witness or shared control has another source.
    #[error("native attestation differs from its original execution source")]
    Source,
    /// The exact native header or execution projection does not define one valid statement.
    #[error("invalid native attestation statement: {0}")]
    Statement(String),
    /// The provisioned private custody does not own this exact authenticated generation seat.
    #[error("native Pasta custody cannot sign this generation: {0}")]
    Custody(String),
    /// Original pool refused the actual mailbox control allocation.
    #[error(transparent)]
    Admission(AllocationRefusal),
    /// The admitted mailbox control allocation was physically refused.
    #[error(transparent)]
    Allocator(PrepaidSharedError),
}

/// Reconstruct the unique recursive-mint message from one source-complete native statement.
/// This performs no finality check: callers must authenticate the enclosing exact-quorum
/// certificate and epoch separately. It never signs or consults local state.
///
/// # Errors
/// Rejects malformed canonical R, another instance/network/epoch/height, changed result bytes
/// or an inconsistent top-up projection. A flagged rejected top-up has the canonical empty root.
pub fn native_seal_message(
    instance: Hash32,
    network: NetworkId,
    statement: &[u8],
    result_preimage: &[u8],
) -> Result<KagemushaMintFinalitySealMessageV1, NativeAttestationError> {
    let source = AttestationStatement::parse(statement).ok_or(NativeAttestationError::Source)?;
    if result_of_preimage(result_preimage) != source.result {
        return Err(NativeAttestationError::Source);
    }
    let result = ExecutionResultCommitment::decode(result_preimage)
        .map_err(|error| NativeAttestationError::Statement(error.to_string()))?;
    message_from_result(instance, network, source, &result)
}

/// Verify the selected native decision and every exact-quorum paired Pasta share, then
/// project the original certificate into the recursive mint circuit's canonical witness.
/// The anchor must be selected independently of the response. This returns witness data,
/// not monetary authority: callers must still verify the release-pinned recursive proof.
///
/// # Errors
/// Rejects genesis, another selected decision/network, an unflagged certificate, changed
/// result witness, malformed shares, wrong signer attribution, or any invalid Pasta equation.
pub(crate) fn verify_native_mint_finality_bundle(
    proof: &SumeragiFinalityProof,
    anchor: &KagemushaFinalityTrustAnchorV1,
) -> Result<
    (
        KagemushaMintFinalitySealBundleV1,
        KagemushaMintFinalityAuthorityGenerationV1,
    ),
    String,
> {
    if proof.height() <= 1 || proof.height() != anchor.checkpoint.height() {
        return Err("mint finality must be the selected non-genesis native decision".into());
    }
    if anchor.network_id != anchor.checkpoint.network_id() {
        return Err("mint finality anchor belongs to another network".into());
    }
    let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &anchor.checkpoint,
        &anchor.network_id,
        anchor.checkpoint.chain_id(),
    )
    .map_err(|error| format!("invalid native mint checkpoint: {error}"))?;
    let verified = verifier
        .verify_same_decision(anchor.checkpoint.tip(), proof)
        .map_err(|error| format!("invalid selected native mint decision: {error}"))?;
    let certificate = verified
        .block()
        .commit_certificate()
        .ok_or_else(|| "native mint certificate is missing".to_owned())?;
    let qc: Qc = norito::decode_canonical(certificate.commit_qc())
        .map_err(|error| format!("invalid native mint CommitQC: {error}"))?;
    if !qc.needs_attestations()
        || qc.attestation_witness.as_ref().map(ResultWitness::as_slice)
            != Some(certificate.result_preimage())
    {
        return Err(
            "native mint requires flagged attestations of the exact result preimage".into(),
        );
    }
    let current = &verified.commitment().schedule.current;
    let keys = current
        .committee
        .iter()
        .map(|member| core_key(member.validator.public_key()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid native mint committee: {error}"))?;
    let committee = Committee::new(keys)
        .map_err(|error| format!("invalid native mint committee: {error:?}"))?;
    verify_attestations(
        &NativePastaVerifier::new(verifier.instance(), anchor.network_id),
        &committee,
        &qc,
    )
    .map_err(|error| format!("invalid native paired Pasta attestations: {error:?}"))?;
    let message = native_seal_message(
        verifier.instance(),
        anchor.network_id,
        &qc.statement(),
        certificate.result_preimage(),
    )
    .map_err(|error| error.to_string())?;
    let seals = qc
        .attestations
        .iter()
        .map(|share| {
            decode_seal(share.as_slice())
                .ok_or_else(|| "malformed native paired Pasta share".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bundle = KagemushaMintFinalitySealBundleV1 { message, seals };
    bundle.validate().map_err(|error| error.to_string())?;
    Ok((bundle, current.authority.clone()))
}

fn message_from_result(
    instance: Hash32,
    network: NetworkId,
    source: AttestationStatement,
    result: &ExecutionResultCommitment,
) -> Result<KagemushaMintFinalitySealMessageV1, NativeAttestationError> {
    let invalid = |reason: String| NativeAttestationError::Statement(reason);
    result
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let current = &result.schedule.current;
    if source.instance != instance
        || source.height != result.height
        || current.network_id != network
        || source.epoch.epoch != current.authorization.epoch
        || source.epoch.context.0 != current.context_id().map_err(invalid)?
    {
        return Err(NativeAttestationError::Source);
    }
    let next = result
        .schedule
        .boundary
        .as_ref()
        .map(|boundary| boundary.next.authorization);
    let (count, root) = (
        result.execution.kagemusha_top_up_count,
        result.execution.kagemusha_top_up_root,
    );
    let root = match (count, root) {
        (0, None) => kagemusha_mint_finality_root_v1(
            kagemusha_mint_finality_empty_root_v1().map_err(|error| invalid(error.to_string()))?,
        ),
        (count, Some(root)) if count > 0 => root,
        _ => {
            return Err(invalid(
                "required commit has inconsistent top-up count and root".into(),
            ));
        }
    };
    let message = KagemushaMintFinalitySealMessageV1 {
        version: KAGEMUSHA_CHAIN_VERSION_V1,
        epoch_authorization: current.authorization,
        validator_count: u32::try_from(current.authority.validators.len())
            .map_err(|_| NativeAttestationError::Source)?,
        network_id: network,
        block_height: source.height,
        native_instance: source.instance.0,
        native_epoch_context: source.epoch.context.0,
        native_block_hash: source.block_hash.0,
        native_result: source.result.0,
        kagemusha_top_up_root: root,
        kagemusha_top_up_count: count,
        next_epoch_authorization: next,
    };
    message
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(message)
}

// The sole compact share encoding is index_be32 followed by Eq nonce/response and Ep
// nonce/response. Canonical scalar/point validation belongs to the genuine Pasta verifier.
/// Encode the sole compact native paired seal, including its exact canonical seat index.
#[must_use]
pub fn encode_native_seal(seal: KagemushaMintFinalityValidatorSealV1) -> AttestationSignature {
    let mut bytes = [0; SEAL_BYTES];
    bytes[..4].copy_from_slice(&seal.validator_index.to_be_bytes());
    for (chunk, value) in bytes[4..].chunks_exact_mut(32).zip([
        seal.eq_proof_signature.nonce_commitment,
        seal.eq_proof_signature.response,
        seal.ep_proof_signature.nonce_commitment,
        seal.ep_proof_signature.response,
    ]) {
        chunk.copy_from_slice(&value);
    }
    AttestationSignature::try_from_slice(&bytes)
        .expect("fixed paired signature fits protocol bound")
}
fn decode_seal(bytes: &[u8]) -> Option<KagemushaMintFinalityValidatorSealV1> {
    if bytes.len() != SEAL_BYTES {
        return None;
    }
    let mut fields = bytes[4..].chunks_exact(32);
    Some(KagemushaMintFinalityValidatorSealV1 {
        validator_index: u32::from_be_bytes(bytes[..4].try_into().ok()?),
        eq_proof_signature: KagemushaPastaSchnorrSignatureV1 {
            nonce_commitment: fields.next()?.try_into().ok()?,
            response: fields.next()?.try_into().ok()?,
        },
        ep_proof_signature: KagemushaPastaSchnorrSignatureV1 {
            nonce_commitment: fields.next()?.try_into().ok()?,
            response: fields.next()?.try_into().ok()?,
        },
    })
}

/// Move-only proof that the native worker signed its exact retained original execution.
/// Private fields prevent a decoded or remote frame from minting a local execution receipt.
pub(crate) struct LocalCommitAttestation {
    source: AttestationStatement,
    key: [u8; 48],
    attestation: CommitAttestation,
}

impl LocalCommitAttestation {
    /// Borrow the witness already retained by a genuine original receipt; grants no capability.
    #[cfg(test)]
    pub(crate) fn witness_for_test(&self) -> &ResultWitness {
        &self.attestation.witness
    }
}

/// Sign only the exact original retained result and separately admitted identical witness.
/// The caller retains every owner across local refusal, then publishes this receipt before Valid.
///
/// # Errors
/// Returns the same witness owner on every source, statement or custody failure.
pub(crate) fn attest_original(
    custody: &KagemushaMintFinalityLocalAuthorityV1,
    verifier: NativePastaVerifier,
    header: &BlockHeader,
    result: &RetainedPayload<ExecutionResultCommitment>,
    preimage: &ChargedBuffer<u8>,
    witness: ResultWitness,
    budget: &AllocationBudget,
) -> Result<LocalCommitAttestation, (ResultWitness, NativeAttestationError)> {
    let checked = (|| {
        if !header.attest
            || !result.belongs_to(budget)
            || !preimage.belongs_to(budget)
            || !witness.admitted_to(budget)
            || preimage.as_slice() != witness.as_slice()
        {
            return Err(NativeAttestationError::Source);
        }
        let source = AttestationStatement {
            instance: header.instance,
            epoch: header.epoch,
            height: header.height,
            block_hash: header.hash(&super::crypto::BlsCrypto::new()),
            result: result_of_preimage(preimage.as_slice()),
        };
        // The private retained execution owner must be the exact canonical preimage being signed.
        // Count/stream compare through a nonallocating writer rather than cloning/encoding R.
        let mut compare = CompareWriter {
            expected: preimage.as_slice(),
            used: 0,
        };
        norito::core::write_canonical_to_writer(result.get(), &mut compare)
            .map_err(|error| NativeAttestationError::Statement(error.to_string()))?;
        if compare.used != preimage.as_slice().len() {
            return Err(NativeAttestationError::Source);
        }
        let message =
            message_from_result(verifier.instance, verifier.network, source, result.get())?;
        let signer = custody
            .signer_for_authority(&result.get().schedule.current.authority)
            .map_err(|error| NativeAttestationError::Custody(error.to_string()))?;
        let member = result
            .get()
            .schedule
            .current
            .committee
            .get(signer.validator_index() as usize)
            .ok_or(NativeAttestationError::Source)?;
        let key =
            core_key(member.validator.public_key()).map_err(|_| NativeAttestationError::Source)?;
        let key: [u8; 48] = key
            .as_bytes()
            .try_into()
            .map_err(|_| NativeAttestationError::Source)?;
        let signature = encode_native_seal(
            signer
                .sign(&message)
                .map_err(|error| NativeAttestationError::Custody(error.to_string()))?,
        );
        Ok((source, key, signature))
    })();
    match checked {
        Ok((source, key, signature)) => Ok(LocalCommitAttestation {
            source,
            key,
            attestation: CommitAttestation { witness, signature },
        }),
        Err(error) => Err((witness, error)),
    }
}
struct CompareWriter<'a> {
    expected: &'a [u8],
    used: usize,
}
impl std::io::Write for CompareWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        if self.expected.get(self.used..end) != Some(bytes) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.used = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Mailbox {
    instance: Hash32,
    key: [u8; 48],
    provisioned: bool,
    budget: AllocationBudget,
    receipt: Mutex<Option<LocalCommitAttestation>>,
    released: ReleaseNotification,
}
/// Nonblocking core adapter. It only borrows already-signed original execution receipts.
pub(crate) struct NativePastaAttestor {
    mailbox: ChargedShared<Mailbox>,
}
/// Sole serialized native worker publisher, sharing the original funded mailbox control.
pub(crate) struct NativeAttestationPublisher {
    mailbox: ChargedShared<Mailbox>,
}

/// Admit one process-lived bounded mailbox and its release control from the original State pool.
/// Native mutex storage and future waiter registrations remain separate allocation owners.
///
/// # Errors
/// Rejects a malformed consensus key or original-pool control allocation refusal.
pub(crate) fn channel(
    instance: Hash32,
    key: &PublicKey,
    provisioned: bool,
    budget: &AllocationBudget,
) -> Result<(NativePastaAttestor, NativeAttestationPublisher), NativeAttestationError> {
    let key = key
        .as_bytes()
        .try_into()
        .map_err(|_| NativeAttestationError::Source)?;
    let release_layout = ReleaseNotification::allocation_layout::<AllocationCharge>();
    let mut reservation = budget
        .try_reserve_layouts([
            ChargedShared::<Mailbox>::allocation_layout(),
            release_layout,
        ])
        .map_err(NativeAttestationError::Admission)?;
    let release_charge = reservation.try_split(release_layout).map_err(|error| {
        NativeAttestationError::Allocator(PrepaidSharedError::Reservation(error))
    })?;
    let released =
        ReleaseNotification::try_new_charged(release_charge).map_err(|(charge, error)| {
            drop(charge);
            NativeAttestationError::Allocator(PrepaidSharedError::Allocator {
                requested_bytes: error.layout().size(),
            })
        })?;
    let mailbox = ChargedShared::from_reservation(
        Mailbox {
            instance,
            key,
            provisioned,
            budget: budget.clone(),
            receipt: Mutex::new(None),
            released,
        },
        &mut reservation,
    )
    .map_err(|(_, error)| NativeAttestationError::Allocator(error))?;
    Ok((
        NativePastaAttestor {
            mailbox: mailbox.clone(),
        },
        NativeAttestationPublisher { mailbox },
    ))
}
/// Publication refusal separates transient contention from terminal source/poison failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AttestationPublishError {
    /// The exact original receipt does not belong to this mailbox.
    Source,
    /// A short concurrent nonblocking read currently owns the mailbox lock.
    Busy(ReleaseWait),
    /// A previous panic poisoned the publication owner; recovery is required.
    Poisoned,
}
impl NativeAttestationPublisher {
    /// Exact local consensus key; observers must skip signing outside their authenticated seat.
    pub(crate) fn key(&self) -> &[u8; 48] {
        &self.mailbox.key
    }

    /// Publish the same original source, preserving the receipt on every typed refusal.
    pub(crate) fn publish(
        &self,
        receipt: LocalCommitAttestation,
    ) -> Result<(), (LocalCommitAttestation, AttestationPublishError)> {
        if receipt.source.instance != self.mailbox.instance
            || receipt.key != self.mailbox.key
            || !receipt
                .attestation
                .witness
                .admitted_to(&self.mailbox.budget)
        {
            return Err((receipt, AttestationPublishError::Source));
        }
        let release = self.mailbox.released.observe();
        let mut slot = match self.mailbox.receipt.try_lock() {
            Ok(slot) => self.mailbox.released.poisoning_guard(slot),
            Err(TryLockError::WouldBlock) => {
                return Err((receipt, AttestationPublishError::Busy(release)));
            }
            Err(TryLockError::Poisoned(error)) => {
                drop(self.mailbox.released.poisoning_guard(error.into_inner()));
                return Err((receipt, AttestationPublishError::Poisoned));
            }
        };
        let retired = slot.replace(receipt);
        drop(slot);
        drop(retired);
        Ok(())
    }
    /// Discard a receipt before dropping its corresponding unretained original execution.
    pub(crate) fn discard(&self, height: u64, keep: &[Hash32]) -> bool {
        let slot = match self.mailbox.receipt.lock() {
            Ok(slot) => slot,
            Err(error) => {
                drop(self.mailbox.released.poisoning_guard(error.into_inner()));
                return false;
            }
        };
        let mut slot = self.mailbox.released.poisoning_guard(slot);
        let retired = if slot.as_ref().is_some_and(|receipt| {
            receipt.source.height != height || !keep.contains(&receipt.source.block_hash)
        }) {
            slot.take()
        } else {
            None
        };
        drop(slot);
        drop(retired);
        true
    }
}
impl NativePastaAttestor {
    /// Hold the actual shared mailbox lock while the attached worker retries publication.
    #[cfg(test)]
    pub(crate) fn with_locked_receipt_for_test<T>(&self, action: impl FnOnce() -> T) -> T {
        let guard = self
            .mailbox
            .receipt
            .lock()
            .expect("fixture mailbox is not poisoned");
        let _guard = self.mailbox.released.poisoning_guard(guard);
        action()
    }
}
impl Attestor for NativePastaAttestor {
    fn attest(&self, height: u64, key: &PublicKey, statement: &[u8]) -> AttestOutcome {
        if !self.mailbox.provisioned || key.as_bytes() != self.mailbox.key {
            return AttestOutcome::NoAuthority;
        }
        let Some(source) = AttestationStatement::parse(statement) else {
            return AttestOutcome::NoAuthority;
        };
        if source.instance != self.mailbox.instance || source.height != height {
            return AttestOutcome::NoAuthority;
        }
        let slot = match self.mailbox.receipt.try_lock() {
            Ok(slot) => self.mailbox.released.poisoning_guard(slot),
            Err(TryLockError::WouldBlock) => return AttestOutcome::Pending,
            Err(TryLockError::Poisoned(error)) => {
                drop(self.mailbox.released.poisoning_guard(error.into_inner()));
                return AttestOutcome::NoAuthority;
            }
        };
        match slot.as_ref().filter(|receipt| receipt.source == source) {
            Some(receipt) => AttestOutcome::Attested(receipt.attestation.clone()),
            None => AttestOutcome::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::{
        certified_chain::CertifiedChain,
        test_chain::{CertifiedTestChain, Signers},
    };
    use iroha_crypto::{Hash, HashOf};
    use iroha_sumeragi::preimage::att_preimage;

    #[test]
    fn mailbox_and_release_control_require_original_pool_admission_before_allocation() {
        let mailbox_bytes = ChargedShared::<Mailbox>::allocation_layout().size();
        let release_bytes = ReleaseNotification::allocation_layout::<AllocationCharge>().size();
        let required = mailbox_bytes + release_bytes;
        let budget = AllocationBudget::new(required - 1);
        let key = PublicKey::new(vec![7; 48]).unwrap();
        let Err(NativeAttestationError::Admission(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            ..
        })) = channel(Hash32([1; 32]), &key, true, &budget)
        else {
            panic!("the original pool must fund both controls before either allocation")
        };
        assert_eq!(requested_bytes, required);
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(required);
        let blocker = budget.try_reserve_bytes(1).unwrap();
        let Err(NativeAttestationError::Admission(AllocationRefusal::Capacity {
            requested_bytes,
            ..
        })) = channel(Hash32([1; 32]), &key, true, &budget)
        else {
            panic!("occupied original credits must refuse both controls atomically")
        };
        assert_eq!(requested_bytes, required);
        assert_eq!(budget.reserved_bytes(), 1);
        drop(blocker);
        let (attestor, publisher) = channel(Hash32([1; 32]), &key, true, &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), required);
        let release = publisher.mailbox.released.observe();
        drop(attestor);
        assert_eq!(budget.reserved_bytes(), required);
        drop(publisher);
        assert_eq!(budget.reserved_bytes(), release_bytes);
        drop(release);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn mailbox_poison_is_observed_only_after_the_original_guard_releases() {
        let budget = AllocationBudget::new(1 << 20);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let key = PublicKey::new(vec![7; 48]).unwrap();
        let (attestor, publisher) = channel(Hash32([1; 32]), &key, true, &budget).unwrap();
        let release = publisher.mailbox.released.observe();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            attestor.with_locked_receipt_for_test(|| {
                assert!(!release.is_poisoned());
                panic!("release the actual poisoned mailbox guard")
            });
        }));
        assert!(unwind.is_err());
        assert!(release.is_poisoned());
        use std::task::{Context, Poll, Waker};
        let mut context = Context::from_waker(Waker::noop());
        let discard_wait = publisher.mailbox.released.observe();
        assert_eq!(
            registration.poll_wait(&discard_wait, &mut context),
            Poll::Pending
        );
        assert!(!publisher.discard(0, &[]));
        assert_eq!(
            registration.poll_wait(&discard_wait, &mut context),
            Poll::Ready(())
        );

        let source = AttestationStatement {
            instance: Hash32([1; 32]),
            epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
            height: 10,
            block_hash: Hash32([2; 32]),
            result: Hash32([3; 32]),
        };
        let mut backing = ChargedBuffer::new(4, &budget).unwrap();
        backing.append(&[1, 2, 3, 4]).unwrap();
        let pointer = backing.as_slice().as_ptr();
        let witness = ResultWitness::from_charged(backing, &budget)
            .unwrap_or_else(|(_, error)| panic!("admit original witness: {error:?}"));
        let receipt = LocalCommitAttestation {
            source,
            key: [7; 48],
            attestation: CommitAttestation {
                witness,
                signature: AttestationSignature::try_from_slice(&[9]).unwrap(),
            },
        };
        let publish_wait = publisher.mailbox.released.observe();
        assert_eq!(
            registration.poll_wait(&publish_wait, &mut context),
            Poll::Pending
        );
        let (receipt, error) = publisher.publish(receipt).unwrap_err();
        assert_eq!(error, AttestationPublishError::Poisoned);
        assert_eq!(receipt.attestation.witness.as_slice().as_ptr(), pointer);
        assert_eq!(
            registration.poll_wait(&publish_wait, &mut context),
            Poll::Ready(())
        );

        let statement = att_preimage(
            &source.instance,
            &source.epoch,
            source.height,
            &source.block_hash,
            &source.result,
        );
        let attest_wait = publisher.mailbox.released.observe();
        assert_eq!(
            registration.poll_wait(&attest_wait, &mut context),
            Poll::Pending
        );
        assert!(matches!(
            attestor.attest(10, &key, &statement),
            AttestOutcome::NoAuthority
        ));
        assert_eq!(
            registration.poll_wait(&attest_wait, &mut context),
            Poll::Ready(())
        );
    }

    #[test]
    fn native_mint_witness_requires_independent_tip_and_actual_pasta_equations() {
        use crate::sumeragi::finality::{build_checkpoint, build_proof};
        use iroha_data_model::block::CommitCertificate;

        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let proof = build_proof(&view, 10).unwrap();
        let anchor = KagemushaFinalityTrustAnchorV1 {
            network_id: chain.network_id(),
            checkpoint: build_checkpoint(&view, 10).unwrap(),
        };
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &anchor.checkpoint,
            &anchor.network_id,
            anchor.checkpoint.chain_id(),
        )
        .unwrap();
        let verified = verifier
            .verify_same_decision(anchor.checkpoint.tip(), &proof)
            .unwrap();
        let (bundle, authority) = verify_native_mint_finality_bundle(&proof, &anchor).unwrap();
        assert_eq!(authority, verified.commitment().schedule.current.authority);
        assert_eq!(bundle.seals.len(), 3);
        assert_eq!(bundle.message.kagemusha_top_up_count, 0);
        assert!(bundle.message.next_epoch_authorization.is_some());

        let certificate = verified.block().commit_certificate().unwrap();
        let qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
        let with_qc = |qc: &Qc| {
            let mut block = verified.block().clone();
            block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                norito::encode_canonical(qc).unwrap(),
                certificate.result_preimage().to_vec(),
                certificate.availability().to_vec(),
            )));
            SumeragiFinalityProof {
                block_header: block.header(),
                block_wire: block.encode_wire().unwrap(),
                committee: proof.committee.clone(),
            }
        };
        let alternative_qc = chain.commit_qc(
            10,
            verified.core_hash(),
            verified.result(),
            true,
            Signers::LastThree,
        );
        let alternative = with_qc(&alternative_qc);
        let (alternative_bundle, alternative_authority) =
            verify_native_mint_finality_bundle(&alternative, &anchor).unwrap();
        assert_eq!(alternative_authority, authority);
        assert_eq!(alternative_bundle.message, bundle.message);
        assert_ne!(alternative_bundle.seals, bundle.seals);

        for index in [0, 4, 36, 68, 100] {
            let mut altered = qc.clone();
            let mut share = altered.attestations[0].as_slice().to_vec();
            share[index] ^= 1;
            altered.attestations[0] = AttestationSignature::try_from_slice(&share).unwrap();
            let candidate = with_qc(&altered);
            // Portable finality authenticates the BLS decision, not these Pasta equations.
            verifier
                .verify_same_decision(anchor.checkpoint.tip(), &candidate)
                .unwrap();
            assert!(verify_native_mint_finality_bundle(&candidate, &anchor).is_err());
        }
        let mut absent = qc.clone();
        absent.attestation_witness = None;
        assert!(verify_native_mint_finality_bundle(&with_qc(&absent), &anchor).is_err());
        let mut substituted = qc.clone();
        let mut bytes = certificate.result_preimage().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        substituted.attestation_witness = Some(ResultWitness::from_untrusted(bytes).unwrap());
        assert!(verify_native_mint_finality_bundle(&with_qc(&substituted), &anchor).is_err());
        let older_anchor = KagemushaFinalityTrustAnchorV1 {
            network_id: anchor.network_id,
            checkpoint: build_checkpoint(&view, 9).unwrap(),
        };
        assert!(verify_native_mint_finality_bundle(&proof, &older_anchor).is_err());
        let unflagged = build_proof(&view, 9).unwrap();
        let unflagged_block = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &older_anchor.checkpoint,
            &older_anchor.network_id,
            older_anchor.checkpoint.chain_id(),
        )
        .unwrap()
        .verify_same_decision(older_anchor.checkpoint.tip(), &unflagged)
        .unwrap();
        let unflagged_qc: Qc = norito::decode_canonical(
            unflagged_block
                .block()
                .commit_certificate()
                .unwrap()
                .commit_qc(),
        )
        .unwrap();
        assert!(!unflagged_qc.needs_attestations());
        assert!(verify_native_mint_finality_bundle(&unflagged, &older_anchor).is_err());
        let genesis = build_proof(&view, 1).unwrap();
        let genesis_anchor = KagemushaFinalityTrustAnchorV1 {
            network_id: anchor.network_id,
            checkpoint: build_checkpoint(&view, 1).unwrap(),
        };
        assert!(verify_native_mint_finality_bundle(&genesis, &genesis_anchor).is_err());
        let mut foreign = anchor.clone();
        foreign.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed([0xE9; 32]),
        ));
        assert!(verify_native_mint_finality_bundle(&proof, &foreign).is_err());
    }

    #[test]
    fn actual_boundary_pasta_is_source_complete_and_subset_independent() {
        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let certified = reader.certified(10).unwrap();
        let header = certified.header().unwrap();
        assert!(header.attest);
        // Empty refers to the mint result; the boundary still executes original signed work.
        assert!(header.payload_len > 0, "the boundary carries actual work");
        assert_eq!(certified.block().external_transactions().len(), 1);
        assert_eq!(certified.commitment().execution.kagemusha_top_up_count, 0);
        assert!(
            certified
                .commitment()
                .execution
                .kagemusha_top_up_root
                .is_none()
        );
        let qc = certified.commit_qc().unwrap();
        let current = &certified.commitment().schedule.current;
        let config = super::super::schedule::ScheduledConfig {
            height: 10,
            epoch: current.clone(),
            params: certified.commitment().schedule.next.params().clone(),
        }
        .height_config()
        .unwrap();
        let crypto = crate::sumeragi::crypto::BlsCrypto::new();
        crypto
            .admit_committee(
                current
                    .committee
                    .iter()
                    .map(|m| (m.validator.public_key(), m.proof_of_possession.as_slice())),
            )
            .unwrap();
        let verifier = NativePastaVerifier::new(chain.instance(), chain.network_id());
        iroha_sumeragi::crypto::Verifier::new(
            &crypto,
            &chain.instance(),
            &header.epoch,
            &config.committee,
        )
        .verify_qc(&verifier, qc)
        .unwrap();
        let other = chain.commit_qc(
            10,
            certified.core_hash(),
            certified.result(),
            true,
            Signers::LastThree,
        );
        iroha_sumeragi::crypto::Verifier::new(
            &crypto,
            &chain.instance(),
            &header.epoch,
            &config.committee,
        )
        .verify_qc(&verifier, &other)
        .unwrap();
        assert_ne!(qc.signers, other.signers);
        assert_eq!(qc.attestation_witness, other.attestation_witness);
        let witness = qc.attestation_witness.as_ref().unwrap();
        let statement = qc.statement();
        let original = AttestationStatement::parse(&statement).unwrap();
        let projected = native_seal_message(
            chain.instance(),
            chain.network_id(),
            &statement,
            witness.as_slice(),
        )
        .unwrap();
        assert_eq!(projected.native_instance, original.instance.0);
        assert_eq!(projected.native_epoch_context, original.epoch.context.0);
        assert_eq!(projected.native_block_hash, original.block_hash.0);
        assert_eq!(projected.native_result, original.result.0);
        assert_eq!(projected.epoch_authorization.epoch, original.epoch.epoch);

        let key = core_key(current.committee[0].validator.public_key()).unwrap();
        let signature = qc.attestations[0].as_slice();
        assert!(verifier.verify(10, 0, &key, &statement, witness, signature));
        assert!(!verifier.verify(11, 0, &key, &statement, witness, signature));
        assert!(!verifier.verify(10, 1, &key, &statement, witness, signature));
        let wrong_key = core_key(current.committee[1].validator.public_key()).unwrap();
        assert!(!verifier.verify(10, 0, &wrong_key, &statement, witness, signature));
        for index in [0, 4, 36, 68, 100] {
            let mut changed = signature.to_vec();
            changed[index] ^= 1;
            assert!(!verifier.verify(10, 0, &key, &statement, witness, &changed));
        }
        let mut changed = witness.as_slice().to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let changed = ResultWitness::from_untrusted(changed).unwrap();
        assert!(!verifier.verify(10, 0, &key, &statement, &changed, signature));
        let changes: [fn(&mut AttestationStatement); 6] = [
            |source| source.instance.0[0] ^= 1,
            |source| source.epoch.epoch += 1,
            |source| source.epoch.context.0[31] ^= 1,
            |source| source.height += 1,
            |source| source.block_hash.0[0] ^= 1,
            |source| source.result.0[0] ^= 1,
        ];
        for change in changes {
            let mut source = original;
            change(&mut source);
            let changed = att_preimage(
                &source.instance,
                &source.epoch,
                source.height,
                &source.block_hash,
                &source.result,
            );
            assert!(!verifier.verify(10, 0, &key, &changed, witness, signature));
        }
        let foreign = NativePastaVerifier::new(Hash32([0x77; 32]), chain.network_id());
        assert!(!foreign.verify(10, 0, &key, &statement, witness, signature));
    }

    #[test]
    fn actual_mailbox_contention_retains_original_receipt_and_source() {
        let budget = AllocationBudget::new(1 << 20);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let key = PublicKey::new(vec![7; 48]).unwrap();
        let source = AttestationStatement {
            instance: Hash32([1; 32]),
            epoch: iroha_sumeragi::testing::TEST_EPOCH.id,
            height: 10,
            block_hash: Hash32([2; 32]),
            result: Hash32([3; 32]),
        };
        let (attestor, publisher) = channel(source.instance, &key, true, &budget).unwrap();
        let mut backing = ChargedBuffer::new(4, &budget).unwrap();
        backing.append(&[1, 2, 3, 4]).unwrap();
        let pointer = backing.as_slice().as_ptr();
        let witness = ResultWitness::from_charged(backing, &budget)
            .unwrap_or_else(|(_, error)| panic!("admit original witness: {error:?}"));
        let receipt = LocalCommitAttestation {
            source,
            key: [7; 48],
            attestation: CommitAttestation {
                witness,
                signature: AttestationSignature::try_from_slice(&[9]).unwrap(),
            },
        };
        use std::task::{Context, Poll, Waker};
        let mut context = Context::from_waker(Waker::noop());
        let (receipt, wait) = attestor.with_locked_receipt_for_test(|| {
            let (receipt, error) = publisher.publish(receipt).err().unwrap();
            let AttestationPublishError::Busy(release) = error else {
                panic!("actual mailbox lock must retain its original release source")
            };
            let wait = release;
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            let foreign = ReleaseNotification::default();
            drop(foreign.guard(()));
            assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Pending);
            (receipt, wait)
        });
        assert_eq!(registration.poll_wait(&wait, &mut context), Poll::Ready(()));
        assert_eq!(receipt.attestation.witness.as_slice().as_ptr(), pointer);
        assert!(publisher.publish(receipt).is_ok());
        let statement = att_preimage(
            &source.instance,
            &source.epoch,
            source.height,
            &source.block_hash,
            &source.result,
        );
        let AttestOutcome::Attested(share) = attestor.attest(10, &key, &statement) else {
            panic!("original receipt")
        };
        assert_eq!(share.witness.as_slice().as_ptr(), pointer);
        assert!(share.witness.admitted_to(&budget));
        assert!(publisher.discard(11, &[]));
        assert!(matches!(
            attestor.attest(10, &key, &statement),
            AttestOutcome::Pending
        ));
        assert_eq!(
            share.witness.as_slice(),
            &[1, 2, 3, 4],
            "retained vote still owns its real backing"
        );
    }
}
