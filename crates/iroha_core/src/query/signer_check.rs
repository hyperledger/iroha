//! Exact signed native custody Check execution and same-State finalized lineage.
//!
//! This crate-private owner authenticates closed native Check purposes. It never
//! accepts an eligibility callback, supplies a clock, or turns a caller-provided history into
//! authority. Purpose-owned wrappers must check current custody and both UTC endpoints before
//! producing their distinct successes. Historical finality alone is not a current-authority read.

use crate::state::{State, StateReadOnly, StateView, TransactionsReadOnly};
use iroha_crypto::{Algorithm, HashOf, Signature};
use iroha_data_model::{
    account::AccountId,
    block::consensus::HeightContextId,
    isi::{
        InstructionBox,
        musubi::CheckMusubiPinOutboxV1,
        sorafs::{
            MutateSorafsFinalPromotionAccountCustody, MutateSorafsFinalPromotionAuthority,
            MutateSorafsReleaseManifestAuthority, MutateSorafsStreamTokenAuthority,
            MutateSorafsStreamTokenGateway, MutateSorafsTopologyAuthority,
        },
    },
    sorafs::{
        final_promotion_account_custody::FinalPromotionAccountCustodyActionV1,
        final_promotion_authority::FinalPromotionAuthorityActionV1,
        release_manifest_authority::ReleaseManifestActionV1,
        stream_token_authority::StreamTokenAuthorityActionV1,
        stream_token_gateway::native::StreamTokenGatewayActionV1,
        topology_authority::TopologyActionV1,
    },
    transaction::{
        Executable, SignedTransaction, TransactionBuilder, TransactionEntrypoint,
        TransactionPayload,
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Maximum canonical signed External frame bytes for native final-promotion transactions.
/// This is a structural capacity bound, not signing, spending, custody or currentness authority.
pub const FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1: usize = 64 * 1024;
const MAX_ROUND: Duration = Duration::from_secs(60);
/// Maximum canonical lineage a one-use native Check may replay from its trusted floor.
/// Shared preflight runs before any Kura finality or block-body read.
const MAX_NATIVE_CHECK_HISTORY_BLOCKS_V1: u64 = 4_096;

fn check_history_span_v1(floor_height: u64, applied_height: u64) -> Result<(), Error> {
    if applied_height
        .checked_sub(floor_height)
        .and_then(|distance| distance.checked_add(1))
        .is_none_or(|span| span > MAX_NATIVE_CHECK_HISTORY_BLOCKS_V1)
    {
        return Err(Error::Finality);
    }
    Ok(())
}

/// Shared proof failures, mapped into each purpose's payload-free public errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCheckErrorV1 {
    Invalid,
    Expired,
    Entropy,
    Transaction,
    NotApplied,
    Finality,
    Execution,
}
use NativeCheckErrorV1 as Error;

/// Independent coordinates, not a decoded authority capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCheckFloorV1 {
    pub(crate) height: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) context_id: HeightContextId,
}
impl NativeCheckFloorV1 {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.height == 0 || self.block_hash == [0; 32] || *self.context_id.0.as_ref() == [0; 32]
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
}

/// Original monotonic lifetime, started before pure expectation validation and entropy.
/// There is no Clone, decoded constructor or renewal method.
pub(crate) struct NativeCheckRoundV1 {
    started: Instant,
    max_elapsed: Duration,
    challenge: Option<[u8; 32]>,
    bound: bool,
}
impl NativeCheckRoundV1 {
    pub(crate) fn start(max_elapsed: Duration) -> Result<Self, Error> {
        let started = Instant::now();
        if max_elapsed.is_zero() || max_elapsed > MAX_ROUND {
            return Err(Error::Invalid);
        }
        Ok(Self {
            started,
            max_elapsed,
            challenge: None,
            bound: false,
        })
    }
    /// Bind a caller's already-established absolute deadline without a phase-local renewal.
    pub(crate) fn start_until(deadline: Instant) -> Result<Self, Error> {
        let started = Instant::now();
        let max_elapsed = deadline
            .checked_duration_since(started)
            .ok_or(Error::Expired)?;
        if max_elapsed.is_zero() {
            return Err(Error::Expired);
        }
        if max_elapsed > MAX_ROUND {
            return Err(Error::Invalid);
        }
        Ok(Self {
            started,
            max_elapsed,
            challenge: None,
            bound: false,
        })
    }
    /// Called only after the purpose wrapper's pure preflight, once per prepared attempt.
    pub(crate) fn issue_challenge(&mut self) -> Result<[u8; 32], Error> {
        self.ensure_live()?;
        if self.challenge.is_some() {
            return Err(Error::Invalid);
        }
        // Mark spent before entropy; an error cannot be retried on this round.
        self.challenge = Some([0; 32]);
        let mut challenge = [0; 32];
        rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut challenge)
            .map_err(|_| Error::Entropy)?;
        if challenge == [0; 32] {
            return Err(Error::Entropy);
        }
        self.ensure_live()?;
        self.challenge = Some(challenge);
        Ok(challenge)
    }
    /// The unchanged absolute end of this original monotonic lifetime.
    pub(crate) fn deadline(&self) -> Instant {
        self.started + self.max_elapsed
    }
    pub(crate) fn ensure_live(&self) -> Result<(), Error> {
        if self.started.elapsed() >= self.max_elapsed {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.started = Instant::now() - Duration::from_secs(61);
    }
}

/// Closed native purposes; none can substitute for another's proof consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCustodyCheckPurposeV1 {
    FinalPromotion,
    FinalPromotionAccount,
    ReleaseManifest,
    StreamToken,
    /// Native gateway readback; cannot stand in for signer or private-key authority.
    StreamTokenGateway,
    /// Exact current Musubi inventory readback, without Queue authority.
    MusubiPinOutbox,
    /// Proof binding only; role-16 Core execution and current authority remain closed.
    Topology,
}
/// Purpose-typed native instructions can enter the common proof path.
///
/// The role-13 and role-16 variants bind signed Checks to execution evidence only. Their
/// Core instructions remain closed and cannot produce signer or topology authority.
#[derive(Clone, Copy)]
pub(crate) enum NativeCustodyCheckRefV1<'a> {
    FinalPromotion(&'a MutateSorafsFinalPromotionAuthority),
    FinalPromotionAccount(&'a MutateSorafsFinalPromotionAccountCustody),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "release-manifest native Check has no production caller yet"
        )
    )]
    ReleaseManifest(&'a MutateSorafsReleaseManifestAuthority),
    StreamToken(&'a MutateSorafsStreamTokenAuthority),
    StreamTokenGateway(&'a MutateSorafsStreamTokenGateway),
    MusubiPinOutbox(&'a CheckMusubiPinOutboxV1),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "topology native Check has no production caller yet"
        )
    )]
    Topology(&'a MutateSorafsTopologyAuthority),
}
impl NativeCustodyCheckRefV1<'_> {
    fn coordinates(
        &self,
    ) -> Result<
        (
            NativeCustodyCheckPurposeV1,
            [u8; 32],
            [u8; 32],
            u64,
            [u8; 32],
            Option<HeightContextId>,
        ),
        Error,
    > {
        match self {
            Self::FinalPromotion(instruction) => {
                let FinalPromotionAuthorityActionV1::Check(check) = &instruction.action else {
                    return Err(Error::Transaction);
                };
                Ok((
                    NativeCustodyCheckPurposeV1::FinalPromotion,
                    check.challenge,
                    check.network_id,
                    check.minimum_height,
                    check.minimum_block_hash,
                    None,
                ))
            }
            Self::FinalPromotionAccount(instruction) => {
                let FinalPromotionAccountCustodyActionV1::Check(check) = &instruction.action else {
                    return Err(Error::Transaction);
                };
                Ok((
                    NativeCustodyCheckPurposeV1::FinalPromotionAccount,
                    check.challenge,
                    check.network_id,
                    check.minimum_height,
                    check.minimum_block_hash,
                    None,
                ))
            }
            Self::ReleaseManifest(instruction) => {
                let ReleaseManifestActionV1::Check(check) = &instruction.action else {
                    return Err(Error::Transaction);
                };
                // This binds a signed role-13 Check only to exact execution evidence. Its Core
                // instruction remains closed, so this cannot grant signer-operation authority.
                Ok((
                    NativeCustodyCheckPurposeV1::ReleaseManifest,
                    check.challenge,
                    check.network_id,
                    check.floor.height,
                    check.floor.block_hash,
                    None,
                ))
            }
            Self::StreamToken(instruction) => {
                let StreamTokenAuthorityActionV1::Check(check) = &instruction.request.action else {
                    return Err(Error::Transaction);
                };
                Ok((
                    NativeCustodyCheckPurposeV1::StreamToken,
                    check.challenge,
                    instruction.request.network_id,
                    check.floor.height,
                    check.floor.block_hash,
                    Some(check.floor.context_id),
                ))
            }
            Self::StreamTokenGateway(instruction) => {
                let StreamTokenGatewayActionV1::Check(check) = &instruction.request.action else {
                    return Err(Error::Transaction);
                };
                Ok((
                    NativeCustodyCheckPurposeV1::StreamTokenGateway,
                    check.challenge,
                    *instruction.request.network_id.as_bytes(),
                    check.floor.height,
                    check.floor.block_hash,
                    Some(check.floor.context_id),
                ))
            }
            Self::MusubiPinOutbox(instruction) => {
                // The binder preserves the original codec errors while bounding both canonical
                // frames. Coordinate extraction itself must remain pure field validation.
                instruction
                    .validate_fields()
                    .map_err(|_| Error::Transaction)?;
                Ok((
                    NativeCustodyCheckPurposeV1::MusubiPinOutbox,
                    instruction.challenge,
                    *instruction.network_id.as_bytes(),
                    instruction.floor.height,
                    instruction.floor.block_hash,
                    Some(instruction.floor.context_id),
                ))
            }
            Self::Topology(instruction) => {
                let TopologyActionV1::Check(check) = &instruction.transition.action else {
                    return Err(Error::Transaction);
                };
                // The signed role-16 Check carries height/hash, while the independent floor
                // owner supplies the context ID. This is proof plumbing, not topology authority.
                Ok((
                    NativeCustodyCheckPurposeV1::Topology,
                    check.challenge,
                    check.network_id,
                    check.floor.height,
                    check.floor.block_hash,
                    None,
                ))
            }
        }
    }
    fn matches_instruction(&self, candidate: &InstructionBox) -> bool {
        match self {
            Self::FinalPromotion(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::FinalPromotionAccount(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::ReleaseManifest(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::StreamToken(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::StreamTokenGateway(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::Topology(value) => candidate.as_any().downcast_ref() == Some(*value),
            Self::MusubiPinOutbox(value) => candidate.as_any().downcast_ref() == Some(*value),
        }
    }
    #[cfg(test)]
    fn instruction(&self) -> InstructionBox {
        match self {
            Self::FinalPromotion(instruction) => (*instruction).clone().into(),
            Self::FinalPromotionAccount(instruction) => (*instruction).clone().into(),
            Self::ReleaseManifest(instruction) => (*instruction).clone().into(),
            Self::StreamToken(instruction) => (*instruction).clone().into(),
            Self::StreamTokenGateway(instruction) => (*instruction).clone().into(),
            Self::Topology(instruction) => (*instruction).clone().into(),
            Self::MusubiPinOutbox(instruction) => (*instruction).clone().into(),
        }
    }
}

/// Frozen signed envelope and independent coordinates. Only exact native binding constructs it.
pub(crate) struct BoundNativeCheckV1 {
    purpose: NativeCustodyCheckPurposeV1,
    chain_id: binding::BoundChainId,
    network_id: [u8; 32],
    floor: NativeCheckFloorV1,
    started: Instant,
    max_elapsed: Duration,
    challenge: [u8; 32],
    entry: binding::SignedCheckOwner,
    entry_bytes: iroha_allocation::ChargedBuffer<u8>,
}
impl BoundNativeCheckV1 {
    pub(crate) fn canonical_external(&self) -> &[u8] {
        self.entry_bytes.as_slice()
    }

    pub(crate) fn signed_transaction(&self) -> &SignedTransaction {
        self.entry.signed_transaction()
    }
}

mod binding;
pub use binding::NativeCheckBindingErrorV1;
pub(crate) use binding::{BindingFailure, BindingScope, SignedCheckAttempt, bind_signed_check_v1};

/// Structural envelope sizing only; no signature, custody, action or fee approval is established.
pub(crate) fn validate_account_transaction_envelope_v1(
    payload: &TransactionPayload,
) -> Result<(), Error> {
    crate::query::signer_check::with_native_check_read_limits(|| {
        // Bound the borrowed input before decoding it into the canonical builder. The same sole
        // envelope ceiling bounds this necessary payload prefix, without estimating wire overhead.
        if norito::canonical_frame_len(payload).map_err(|_| Error::Transaction)?
            > FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1
            || payload.attachments.is_some()
            || validate_native_signatory_v1(&payload.authority).is_err()
        {
            return Err(Error::Transaction);
        }
        let frame = bounded_frame(payload)?;
        let payload = norito::decode_canonical::<TransactionPayload>(&frame)
            .map_err(|_| Error::Transaction)?;
        let builder = TransactionBuilder::from_payload(payload).map_err(|_| Error::Transaction)?;
        // The ordinary builder has no multisig authorization. A single Ed25519 signature is
        // always 64 bytes, so this private, invalid placeholder has its exact canonical layout.
        // Neither this synthetic transaction nor its bytes may escape as signing authority.
        let entry = TransactionEntrypoint::External(
            builder.build_with_signature(Signature::from_bytes(&[0; 64])),
        );
        bounded_entry(&entry).map(|_| ())
    })
}

/// The first-release native profile has one Ed25519 account and no algorithm fallback.
pub(crate) fn validate_native_signatory_v1(authority: &AccountId) -> Result<(), Error> {
    if authority
        .try_signatory()
        .and_then(|key| key.try_algorithm().ok())
        != Some(Algorithm::Ed25519)
    {
        return Err(Error::Transaction);
    }
    Ok(())
}

/// Retain the exact native External frame without cloning the borrowed signed graph.
/// Executor callers must retain local refusal; a query facade may project a payload-free error.
pub(crate) fn native_signed_transaction_frame_attempt_v1(
    signed: &SignedTransaction,
) -> Result<Vec<u8>, crate::execution_attempt::ExecutionAttemptError<Error>> {
    validate_native_signed_profile_v1(signed)?;
    let frame = bounded_frame_attempt(signed)?;
    let owned = norito::decode_canonical::<SignedTransaction>(&frame)
        .map_err(native_codec_attempt_error)?;
    native_signed_entry_frame_v1(&TransactionEntrypoint::External(owned))
}

fn validate_native_signed_profile_v1(
    signed: &SignedTransaction,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<Error>> {
    validate_native_signatory_v1(signed.authority())?;
    if signed.network_id().is_none()
        || signed.time_to_live().is_none()
        || signed.attachments().is_some()
        || signed.multisig_signatures().is_some()
        || signed.payload().validate_fee_payment_intent().is_err()
    {
        return Err(Error::Transaction.into());
    }
    Ok(())
}

/// Sole canonical signed native profile. Action, independent scope, spending and current custody
/// remain the caller's owners; no successful structural/signature check grants those authorities.
/// Local codec and allocation refusals retain their original attempt classification.
pub(crate) fn native_signed_entry_frame_v1(
    entry: &TransactionEntrypoint,
) -> Result<Vec<u8>, crate::execution_attempt::ExecutionAttemptError<Error>> {
    let TransactionEntrypoint::External(signed) = entry else {
        return Err(Error::Transaction.into());
    };
    validate_native_signed_profile_v1(signed)?;
    let bytes = bounded_frame_attempt(entry)?;
    let hash = HashOf::try_new(signed.payload()).map_err(native_codec_attempt_error)?;
    iroha_crypto::verify_signature_borrowed(
        &signed.signature().0,
        signed
            .authority()
            .try_signatory()
            .ok_or(Error::Transaction)?,
        hash.as_ref(),
    )
    .map_err(|_| Error::Transaction)?;
    Ok(bytes)
}

fn native_codec_attempt_error(
    error: norito::Error,
) -> crate::execution_attempt::ExecutionAttemptError<Error> {
    crate::execution_attempt::norito_decode_attempt_error(error, |_| Error::Transaction)
}

pub(crate) fn bounded_entry(entry: &TransactionEntrypoint) -> Result<Vec<u8>, Error> {
    bounded_frame(entry)
}

fn bounded_frame<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    bounded_frame_attempt(value).map_err(|_| Error::Transaction)
}

fn bounded_frame_attempt<T: norito::NoritoSerialize>(
    value: &T,
) -> Result<Vec<u8>, crate::execution_attempt::ExecutionAttemptError<Error>> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::core::encoded_frame_len(value).map_err(native_codec_attempt_error)?;
    if length > FINAL_PROMOTION_NATIVE_TRANSACTION_MAX_BYTES_V1 {
        return Err(Error::Transaction.into());
    }
    norito::core::to_bytes_bounded(value, length).map_err(|error| {
        native_codec_attempt_error(match error {
            norito::core::BoundedEncodeError::Serialization(error) => error,
            norito::core::BoundedEncodeError::AllocationFailed { bytes } => {
                norito::Error::AllocationFailed {
                    bytes: bytes as u64,
                }
            }
            // The same borrowed value was counted immediately before encoding.
            norito::core::BoundedEncodeError::FrameTooLarge { .. } => norito::Error::LengthMismatch,
        })
    })
}

/// Actual same-State view retained until the purpose wrapper finishes eligibility checks.
/// This private execution proof is not itself a fresh-custody success.
pub(crate) struct AuthenticatedCheckExecutionCutV1<'state, 'bound> {
    view: StateView<'state>,
    data: execution::CheckExecutionDataV1,
    bound: &'bound mut Option<BoundNativeCheckV1>,
}
impl AuthenticatedCheckExecutionCutV1<'_, '_> {
    pub(crate) fn view(&self) -> &StateView<'_> {
        &self.view
    }
    pub(crate) const fn check_height(&self) -> u64 {
        self.data.check_height
    }
    pub(crate) const fn applied_floor(&self) -> NativeCheckFloorV1 {
        self.data.applied_floor
    }
    pub(crate) const fn entry_hash(&self) -> HashOf<TransactionEntrypoint> {
        self.data.entry_hash
    }
    /// Discharge the exact original binding retained throughout proof and late eligibility checks.
    pub(crate) fn into_verified_entry(self) -> (iroha_allocation::ChargedBuffer<u8>, [u8; 32]) {
        let bound = self
            .bound
            .take()
            .expect("verified original binding remains in its exclusive slot");
        (bound.entry_bytes, self.data.check_block_hash)
    }
}

mod certified_walk;
pub(crate) use certified_walk::{
    SignerCertifiedBlockV1, SignerCertifiedWalkV1, with_native_check_read_limits,
};

mod execution;
pub(crate) use execution::{BorrowedCheckExecutionCutV1, PreparedCheckExecutionV1};

/// Authenticate the exact Check while borrowing its original slot through late purpose checks.
pub(crate) fn authenticate_applied_check_v1<'state, 'bound>(
    state: &'state Arc<State>,
    purpose: NativeCustodyCheckPurposeV1,
    bound: &'bound mut Option<BoundNativeCheckV1>,
    round: &NativeCheckRoundV1,
) -> Result<
    AuthenticatedCheckExecutionCutV1<'state, 'bound>,
    crate::execution_attempt::ExecutionAttemptError<Error>,
> {
    with_native_check_read_limits(|| {
        round.ensure_live()?;
        let view = state.view();
        let mut proof = PreparedCheckExecutionV1::new(&view, purpose, bound, round)?;
        let chain = SignerCertifiedWalkV1::new(&view)?;
        // Retain one iterator in place: IntoIterator moves only its mutable reference,
        // not its parent/successor owners. The exact same view and cumulative source
        // allowance remain borrowed throughout every block and late proof check.
        let mut walk = chain.walk(proof.floor_height(), proof.applied_height());
        for block in &mut walk {
            round.ensure_live()?;
            match block {
                Ok(block) => proof.consume(&block)?,
                Err(error) => return Err(error),
            }
        }
        drop(walk);
        let (data, bound) = proof.finish()?.into_parts();
        drop(chain);
        Ok(AuthenticatedCheckExecutionCutV1 { view, data, bound })
    })
}

#[cfg(any(test, feature = "iroha-core-tests"))]
pub(crate) mod fixture;

#[cfg(test)]
mod tests;
