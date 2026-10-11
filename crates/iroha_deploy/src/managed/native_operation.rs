//! Shared immutable authorization terms and exact native transaction evidence.
//! This owner never signs or sends instructions; purpose-closed wallet planners own dispatch.

use super::{Error, Result, service_authority::ServiceAuthority};
use crate::verify::{
    finality::{AttestationQuorum, FinalityError, FinalitySource, FinalityVerifier},
    http::HttpFinalitySource,
};
use iroha::client::Client;
use iroha_crypto::HashOf;
use iroha_data_model::{
    asset::AssetDefinitionId,
    block::BlockHeader,
    sumeragi_finality::{EpochValidationScope, SumeragiFinalityCheckpoint},
    transaction::{FeePaymentIntent, SignedTransaction, TransactionEntrypoint},
};
use iroha_fs::{PrivateDirectory, PublishMode};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::{BoundedTransactionOptions, OperationReport};
use norito::{Decode, Encode};
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const MAX_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
const MAX_REPLAY_SUCCESSORS: u64 = 16;

#[path = "native_operation/attempts.rs"]
pub(super) mod attempts;

#[path = "native_operation/authorization.rs"]
pub(super) mod authorization;

/// Independent successful inclusion of the exact original signed wallet transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedTransactionFinality {
    /// Original signed transaction identity, whose exact wire was independently compared.
    pub transaction_hash: HashOf<SignedTransaction>,
    /// Original certified execution carrier height.
    pub height: u64,
    /// Original authenticated Iroha carrier header hash.
    pub block_hash: HashOf<BlockHeader>,
    /// Authenticated carrier timestamp assigned by native execution, in Unix milliseconds.
    pub block_time_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::Fees")]
pub(super) struct Fees {
    fee_payment: FeePaymentIntent,
    max_total_fees: BTreeMap<AssetDefinitionId, Quantity>,
}
impl Fees {
    pub(super) fn from_options(options: &BoundedTransactionOptions) -> Result<Self> {
        validate_options(options)?;
        Ok(Self {
            fee_payment: options.fee_payment.clone(),
            max_total_fees: options.max_total_fees.clone(),
        })
    }
    pub(super) fn validate(&self) -> Result<()> {
        validate_fees(&self.fee_payment, &self.max_total_fees)
    }
    pub(super) fn options(&self, deadline: Instant) -> BoundedTransactionOptions {
        BoundedTransactionOptions {
            fee_payment: self.fee_payment.clone(),
            max_total_fees: self.max_total_fees.clone(),
            deadline,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::native_operation::Terms")]
pub(crate) struct Terms {
    pub requested_deadline_unix_ms: u64,
    pub signing_deadline_unix_ms: u64,
    pub(super) fees: Fees,
}

impl Terms {
    pub fn new(deadline_unix_ms: u64, options: &BoundedTransactionOptions) -> Result<Self> {
        validate_options(options)?;
        require_deadline(options.deadline)?;
        let now = now_ms()?;
        if deadline_unix_ms <= now || deadline_unix_ms == u64::MAX {
            return Err(invalid(
                "original native operation UTC authorization is expired or unbounded",
            ));
        }
        let remaining = options.deadline.saturating_duration_since(Instant::now());
        let io_end = now
            .checked_add(
                u64::try_from(remaining.as_millis())
                    .map_err(|_| invalid("native operation deadline exceeds bound"))?,
            )
            .ok_or_else(|| invalid("native operation deadline overflow"))?;
        if io_end <= now {
            return Err(invalid("native operation signing budget elapsed"));
        }
        Ok(Self {
            requested_deadline_unix_ms: deadline_unix_ms,
            signing_deadline_unix_ms: deadline_unix_ms.min(io_end),
            fees: Fees::from_options(options)?,
        })
    }
    pub fn options(&self, deadline: Instant) -> BoundedTransactionOptions {
        self.fees.options(deadline)
    }
    pub fn signing_deadline(&self, deadline: Instant) -> Result<Instant> {
        require_deadline(deadline)?;
        let remaining = self
            .signing_deadline_unix_ms
            .checked_sub(now_ms()?)
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("original native operation signing interval expired"))?;
        Ok(deadline.min(
            Instant::now()
                .checked_add(Duration::from_millis(remaining))
                .ok_or_else(|| invalid("native operation monotonic deadline overflow"))?,
        ))
    }
    pub(crate) fn matches(
        &self,
        deadline_unix_ms: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        validate_options(options)?;
        if self.requested_deadline_unix_ms != deadline_unix_ms
            || self.fees != Fees::from_options(options)?
        {
            return Err(invalid(
                "original native operation UTC or fee authorization changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.requested_deadline_unix_ms == 0
            || self.requested_deadline_unix_ms == u64::MAX
            || self.signing_deadline_unix_ms == 0
            || self.signing_deadline_unix_ms > self.requested_deadline_unix_ms
        {
            return Err(invalid(
                "invalid original native operation signing authorization",
            ));
        }
        self.fees.validate()
    }
}

fn validate_options(options: &BoundedTransactionOptions) -> Result<()> {
    validate_fees(&options.fee_payment, &options.max_total_fees)
}
fn validate_fees(
    fee_payment: &FeePaymentIntent,
    max_total_fees: &BTreeMap<AssetDefinitionId, Quantity>,
) -> Result<()> {
    if max_total_fees.len() > 16
        || fee_payment.charge_limits().len() > 16
        || !matches!(fee_payment, FeePaymentIntent::Authority(_))
        || max_total_fees.values().any(Quantity::is_zero)
    {
        return Err(invalid(
            "native operation fees require bounded authority-paid maxima",
        ));
    }
    fee_payment
        .validate()
        .map_err(|_| invalid("invalid native operation fee authorization"))
}

pub(super) fn encode<T: norito::NoritoSerialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    if norito::canonical_frame_len(value)
        .map_err(|_| invalid("cannot size native operation record"))?
        > maximum
    {
        return Err(invalid("native operation record exceeds byte bound"));
    }
    norito::encode_canonical(value).map_err(|_| invalid("cannot encode native operation record"))
}
pub(crate) fn read_optional(
    directory: &PrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    // Initial absence is admitted by the native owner, after its unconditional custody exit.
    // Move the sole successful allocation; later native errors cannot become absence.
    Ok(directory
        .read_optional(name, maximum)?
        .map(|mut bytes| std::mem::take(&mut *bytes)))
}
pub(super) fn require_empty(directory: &PrivateDirectory) -> Result<()> {
    if !directory.entries(0)?.is_empty() {
        return Err(invalid("native operation journal has no original request"));
    }
    Ok(())
}

impl ServiceAuthority {
    pub(super) fn observe_finality(&mut self, deadline: Instant) -> Result<FinalityVerifier> {
        self.observe_finality_with_source(deadline, |height, deadline| {
            self.source(height, deadline)
        })
        .map(|(verifier, _)| verifier)
    }

    // One cursor and fresh-challenge owner; component fixtures replace only the source.
    // The count describes this same verified quorum, never a second observation.
    pub(super) fn observe_finality_with_source<S: FinalitySource>(
        &self,
        deadline: Instant,
        source: impl Fn(u64, Instant) -> Result<S>,
    ) -> Result<(FinalityVerifier, usize)> {
        require_deadline(deadline)?;
        let retained = read_optional(
            &self.directory,
            "current-checkpoint.nrt",
            MAX_CHECKPOINT_BYTES,
        )?;
        // A seed is only a previously certified immutable receipt from this joined advance.
        // Retained cursors keep their independent native bytes; no current verdict is shared.
        let seed = if retained.is_none() {
            self.certificate_seed()?
        } else {
            None
        };
        let mut verifier = if let Some(bytes) = retained {
            self.decode_checkpoint(&bytes)?
        } else if let Some(seed) = &seed {
            seed.verifier()
        } else {
            let source = source(1, deadline)?;
            let proof = source
                .finality_proof(NonZeroU64::new(1).expect("positive genesis"))
                .map_err(|_| invalid("cannot read original genesis result"))?;
            FinalityVerifier::from_genesis(&self.genesis, &proof)
                .map_err(|_| invalid("original genesis finality differs"))?
        };
        let result = source(verifier.checkpoint().height(), deadline).and_then(|source| {
            let observation = verifier.observe(&source, &rand::random());
            let verified = observation.as_ref().map_or(0, AttestationQuorum::verified);
            if let Some(seed) = &seed {
                self.validate_profile()?;
                seed.revalidate()?;
                require_deadline(deadline)?;
            }
            retain_observation(&self.directory, &mut verifier, observation)?;
            Ok(verified)
        });
        // Close source custody on every ordinary result, including source construction refusal.
        // A certificate never substitutes for an available source or a fresh attestation quorum.
        if let Some(seed) = &seed {
            self.validate_profile()?;
            seed.revalidate()?;
            require_deadline(deadline)?;
        }
        let verified = result?;
        Ok((verifier, verified))
    }

    pub(super) fn source(&self, height: u64, deadline: Instant) -> Result<HttpFinalitySource> {
        HttpFinalitySource::new(
            self.config.network_id,
            NonZeroU64::new(height).ok_or_else(|| invalid("zero native operation checkpoint"))?,
            self.peers
                .iter()
                .map(|(_, client)| client.clone())
                .collect(),
            self.peers.clone(),
            deadline,
        )
        .map_err(|_| invalid("invalid native operation finality source"))
    }

    pub(super) fn retained_finality(
        &self,
        directory: &PrivateDirectory,
        transaction: &SignedTransaction,
    ) -> Result<Option<ManagedTransactionFinality>> {
        retained_carrier_using(directory, transaction, |bytes| {
            self.decode_checkpoint(bytes)
        })
    }

    pub(super) fn advance_carrier(
        &self,
        directory: &PrivateDirectory,
        original_checkpoint: &[u8],
        transaction: &SignedTransaction,
        report: &OperationReport,
        observed: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<Option<ManagedTransactionFinality>> {
        let height = report
            .data
            .get("evidence")
            .and_then(|e| e.get("block_height"))
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| invalid("Applied native operation observation has no carrier hint"))?;
        self.advance_carrier_with_source(
            directory,
            original_checkpoint,
            transaction,
            CarrierTarget {
                height,
                observed_height: observed.checkpoint().height(),
                observed: Some(observed),
                deadline,
            },
            |height, deadline| self.source(height, deadline),
        )
    }

    /// An authenticated native row may supply the same non-authoritative carrier height hint.
    /// Original wire, successful execution and the complete certified replay remain mandatory.
    pub(super) fn advance_carrier_at(
        &self,
        directory: &PrivateDirectory,
        original_checkpoint: &[u8],
        transaction: &SignedTransaction,
        height: u64,
        observed_height: u64,
        deadline: Instant,
    ) -> Result<Option<ManagedTransactionFinality>> {
        self.advance_carrier_with_source(
            directory,
            original_checkpoint,
            transaction,
            CarrierTarget {
                height,
                observed_height,
                observed: None,
                deadline,
            },
            |height, deadline| self.source(height, deadline),
        )
    }

    // Production and genuine fixtures use the same native selection and publication owner.
    // The injected source changes transport only; it cannot construct an observed receipt.
    pub(super) fn advance_carrier_with_source<S: FinalitySource>(
        &self,
        directory: &PrivateDirectory,
        original_checkpoint: &[u8],
        transaction: &SignedTransaction,
        target: CarrierTarget<'_>,
        source: impl FnOnce(u64, Instant) -> Result<S>,
    ) -> Result<Option<ManagedTransactionFinality>> {
        let original_verifier = self.decode_checkpoint(original_checkpoint)?;
        if target.height <= original_verifier.checkpoint().height() {
            return Err(invalid(
                "native operation carrier predates its original request",
            ));
        }
        if target.height > target.observed_height {
            return Ok(None);
        }
        // Applied is only a replaceable lookup hint. A false earlier hint cannot irreversibly
        // pin a carrier or prevent replaying the original transaction at its actual height.
        let progress = read_optional(directory, "replay.nrt", MAX_CHECKPOINT_BYTES)?
            .map(|bytes| self.decode_checkpoint(&bytes))
            .transpose()?;
        let handoff = (!norito::core::decode_limits_active() && progress.is_none())
            .then_some(target.observed)
            .flatten()
            .filter(|observed| {
                original_verifier.checkpoint().height() > 1
                    && observed.checkpoint().height() == target.height
                    && original_verifier.checkpoint().height().checked_add(1) == Some(target.height)
            });
        let mut verifier = replay_start(original_verifier, progress, target.height)?;
        // Keep the existing endpoint/network/deadline constructor even when the native proof
        // was already delivered by the immediately preceding fresh quorum.
        let source = source(verifier.checkpoint().height(), target.deadline)?;
        let finalized = match handoff {
            Some(observed) => {
                self.validate_profile()?;
                require_deadline(target.deadline)?;
                let result = retain_observed_carrier(
                    directory,
                    transaction,
                    &mut verifier,
                    observed,
                    target.deadline,
                );
                // Close original profile custody and the unchanged clock on every result.
                self.validate_profile()?;
                require_deadline(target.deadline)?;
                result?
            }
            None => retain_carrier_progress(
                directory,
                transaction,
                &mut verifier,
                target.height,
                &source,
            )?,
        };
        if finalized.is_some() {
            self.remember_certificate(directory, &verifier)?;
        }
        Ok(finalized)
    }
}

// The observed owner is supplied only by the same post-Apply fresh quorum. A numeric frontier
// remains sufficient for renewal/recovery, which always keep their independent replay.
pub(super) struct CarrierTarget<'a> {
    pub(super) height: u64,
    pub(super) observed_height: u64,
    pub(super) observed: Option<&'a FinalityVerifier>,
    pub(super) deadline: Instant,
}

fn retain_observed_carrier(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    original: &mut FinalityVerifier,
    observed: &FinalityVerifier,
    deadline: Instant,
) -> Result<Option<ManagedTransactionFinality>> {
    let parent = original
        .verified_tip_ref()
        .map_err(|_| invalid("invalid original native operation checkpoint"))?;
    let child = observed
        .verified_tip_ref()
        .map_err(|_| invalid("invalid observed native operation carrier"))?;
    child
        .verify_immediate_global_successor_of(
            parent,
            original.checkpoint().network_id(),
            original.checkpoint().chain_id(),
        )
        .map_err(|_| invalid("observed carrier is not the exact original native successor"))?;
    if observed.checkpoint().network_id() != original.checkpoint().network_id()
        || observed.checkpoint().chain_id() != original.checkpoint().chain_id()
    {
        return Err(invalid(
            "observed carrier changed original network or chain",
        ));
    }
    require_deadline(deadline)?;
    *original = observed.clone();
    retain_verified_carrier(
        directory,
        transaction,
        original,
        original.checkpoint().height(),
        true,
    )
    .map(|outcome| outcome.map(|outcome| outcome.finality))
}

/// Retain a bounded verified replay from the sole finality-source abstraction. Test sources
/// execute the original generated native chain; no decoded report supplies successful inclusion.
pub(crate) fn retain_carrier_progress<S: FinalitySource + ?Sized>(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    verifier: &mut FinalityVerifier,
    height: u64,
    source: &S,
) -> Result<Option<ManagedTransactionFinality>> {
    retain_carrier_execution_progress(directory, transaction, verifier, height, source, true)
        .map(|outcome| outcome.map(|outcome| outcome.finality))
}

/// Historical exact transaction outcome. This conveys no permission or current registry fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeTransactionExecution {
    pub(crate) finality: ManagedTransactionFinality,
    pub(crate) applied: bool,
}

pub(crate) fn retain_carrier_execution_progress<S: FinalitySource + ?Sized>(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    verifier: &mut FinalityVerifier,
    height: u64,
    source: &S,
    require_success: bool,
) -> Result<Option<NativeTransactionExecution>> {
    let target = height.min(
        verifier
            .checkpoint()
            .height()
            .saturating_add(MAX_REPLAY_SUCCESSORS),
    );
    verifier
        .catch_up(
            source,
            NonZeroU64::new(target).ok_or_else(|| invalid("zero native operation carrier"))?,
        )
        .map_err(|_| invalid("original native operation carrier replay unavailable"))?;
    retain_verified_carrier(directory, transaction, verifier, height, require_success)
}

// Preserve one publication order for independently replayed and already observed carriers.
fn retain_verified_carrier(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    verifier: &FinalityVerifier,
    height: u64,
    require_success: bool,
) -> Result<Option<NativeTransactionExecution>> {
    let bytes = checkpoint_bytes(verifier)?;
    directory.write_atomic("replay.nrt", &bytes, PublishMode::Replace)?;
    if verifier.checkpoint().height() != height {
        return Ok(None);
    }
    let finalized = verify_carrier_execution(verifier, transaction, require_success)?;
    directory.write_atomic("carrier.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(Some(finalized))
}

pub(crate) fn retained_carrier_execution(
    directory: &PrivateDirectory,
    network: iroha_data_model::NetworkId,
    chain: &str,
    transaction: &SignedTransaction,
) -> Result<Option<NativeTransactionExecution>> {
    read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)?
        .map(|bytes| {
            verify_carrier_execution(
                &decode_checkpoint(&bytes, network, chain)?,
                transaction,
                false,
            )
        })
        .transpose()
}

// Optional post-replay reporting only. Required predecessor, authorization and native carrier
// checks stay with their callers and must complete before this projection can be skipped.
pub(super) fn optional_current<T>(
    requested: bool,
    observed: Option<&FinalityVerifier>,
    read: impl FnOnce(&FinalityVerifier) -> Result<T>,
) -> Option<T> {
    if !requested {
        return None;
    }
    observed.and_then(|verifier| read(verifier).ok())
}

// Every candidate is checked by the supplied SDK operation against the same independently
// authenticated block. This helper owns only bounded endpoint iteration, never proof authority.
pub(super) fn read_selected_peers<T>(
    peers: &[(PeerId, Client)],
    deadline: Instant,
    mut read: impl FnMut(&Client, Instant) -> Result<T>,
) -> Result<T> {
    for (_, client) in peers {
        require_deadline(deadline)?;
        if let Ok(value) = read(
            client,
            deadline.min(Instant::now() + Duration::from_secs(5)),
        ) {
            require_deadline(deadline)?;
            return Ok(value);
        }
    }
    Err(invalid(
        "fresh native operation presence or absence proof unavailable",
    ))
}

pub(crate) fn decode_checkpoint(
    bytes: &[u8],
    network: iroha_data_model::NetworkId,
    chain: &str,
) -> Result<FinalityVerifier> {
    decode_checkpoint_with_validation(bytes, network, chain, None)
}

pub(super) fn decode_checkpoint_with_validation(
    bytes: &[u8],
    network: iroha_data_model::NetworkId,
    chain: &str,
    mut validation: Option<&mut EpochValidationScope>,
) -> Result<FinalityVerifier> {
    // The current outer owner wins even if this operation warmed before it was entered.
    if norito::core::decode_limits_active() {
        validation = None;
    }
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("native operation checkpoint exceeds bound"));
    }
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical_with_validation(
        bytes,
        validation.as_deref_mut(),
    )
    .map_err(|_| invalid("invalid retained native operation checkpoint"))?;
    FinalityVerifier::from_checkpoint_with_validation(checkpoint, network, chain, validation)
        .map_err(|_| invalid("retained native operation checkpoint changed network or chain"))
}

#[cfg(test)]
pub(crate) fn retained_carrier(
    directory: &PrivateDirectory,
    network: iroha_data_model::NetworkId,
    chain: &str,
    transaction: &SignedTransaction,
) -> Result<Option<ManagedTransactionFinality>> {
    retained_carrier_using(directory, transaction, |bytes| {
        decode_checkpoint(bytes, network, chain)
    })
}

pub(super) fn retained_carrier_using(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    checkpoint: impl FnOnce(&[u8]) -> Result<FinalityVerifier>,
) -> Result<Option<ManagedTransactionFinality>> {
    // Re-read actual native custody before every use. Only the caller's existing immutable
    // checkpoint importer differs; transaction signature and successful inclusion stay fresh.
    read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)?
        .map(|bytes| verify_carrier(&checkpoint(&bytes)?, transaction))
        .transpose()
}

pub(crate) fn retain_observation(
    directory: &PrivateDirectory,
    verifier: &mut FinalityVerifier,
    observation: std::result::Result<AttestationQuorum, FinalityError>,
) -> Result<()> {
    // Native component failures need the original per-peer cause before the public
    // managed result closes it into its existing classification. Success stays silent.
    #[cfg(test)]
    if let Err(error) = &observation {
        eprintln!("native finality observation refused: {error:?}");
    }
    match &observation {
        Ok(_) => {}
        Err(FinalityError::CatchingUp { .. }) => {
            if !verifier.promote_verified_progress() {
                return Err(invalid(
                    "native operation catch-up omitted its verified prefix",
                ));
            }
        }
        Err(_) => return Err(invalid("fresh native operation quorum unavailable")),
    }
    directory.write_atomic(
        "current-checkpoint.nrt",
        &checkpoint_bytes(verifier)?,
        PublishMode::Replace,
    )?;
    observation.map(|_| ()).map_err(|_| {
        invalid("native operation finality is catching up; a fresh quorum is still required")
    })
}

pub(crate) fn replay_start(
    original: FinalityVerifier,
    progress: Option<FinalityVerifier>,
    hint: u64,
) -> Result<FinalityVerifier> {
    if hint <= original.checkpoint().height() {
        return Err(invalid(
            "native operation carrier predates original authorization",
        ));
    }
    if let Some(progress) = progress {
        if progress.checkpoint().network_id() != original.checkpoint().network_id()
            || progress.checkpoint().chain_id() != original.checkpoint().chain_id()
            || progress.checkpoint().height() < original.checkpoint().height()
        {
            return Err(invalid(
                "native operation replay left its original certified prefix",
            ));
        }
        if progress.checkpoint().height() <= hint {
            return Ok(progress);
        }
    }
    Ok(original)
}

pub(crate) fn verify_carrier(
    verifier: &FinalityVerifier,
    transaction: &SignedTransaction,
) -> Result<ManagedTransactionFinality> {
    verify_carrier_execution(verifier, transaction, true).map(|outcome| outcome.finality)
}

fn verify_carrier_execution(
    verifier: &FinalityVerifier,
    transaction: &SignedTransaction,
    require_success: bool,
) -> Result<NativeTransactionExecution> {
    let verified = verifier
        .verified_tip_ref()
        .map_err(|_| invalid("invalid original native operation carrier"))?;
    verified
        .verify_global_scope(
            verifier.checkpoint().network_id(),
            verifier.checkpoint().chain_id(),
        )
        .map_err(|_| invalid("native operation carrier is not the selected Global root"))?;
    transaction
        .verify_signature()
        .map_err(|_| invalid("invalid original native operation signature"))?;
    if transaction.network_id() != Some(&verifier.checkpoint().network_id()) {
        return Err(invalid(
            "native operation transaction network differs from carrier",
        ));
    }
    let wire = transaction
        .encode_wire_v1()
        .map_err(|_| invalid("invalid original native operation wire"))?;
    let mut found = None;
    for (index, entrypoint) in verified.block().network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(candidate) = entrypoint else {
            continue;
        };
        if candidate.hash() != transaction.hash() {
            continue;
        }
        let input_index = u32::try_from(index)
            .map_err(|_| invalid("native operation carrier index exceeds bound"))?;
        if found.is_some()
            || candidate
                .encode_wire_v1()
                .map_err(|_| invalid("invalid carrier transaction wire"))?
                != wire
        {
            return Err(invalid(
                "native operation carrier lacks exact successful original execution",
            ));
        }
        let output = verified
            .block()
            .network_output_at(input_index)
            .ok_or_else(|| {
                invalid("native operation carrier lacks exact successful original execution")
            })?;
        let applied = output.1.result.as_ref().is_ok();
        if require_success && !applied {
            return Err(invalid(
                "native operation carrier lacks exact successful original execution",
            ));
        }
        found = Some(applied);
    }
    let Some(applied) = found else {
        return Err(invalid(
            "original native operation transaction absent from certified carrier",
        ));
    };
    Ok(NativeTransactionExecution {
        applied,
        finality: ManagedTransactionFinality {
            transaction_hash: transaction.hash(),
            height: verified.height(),
            block_hash: verified.header().hash(),
            block_time_ms: verified.header().creation_time_ms,
        },
    })
}

pub(crate) fn checkpoint_bytes(verifier: &FinalityVerifier) -> Result<Vec<u8>> {
    let bytes = verifier
        .checkpoint()
        .encode_canonical()
        .map_err(|_| invalid("cannot encode native operation checkpoint"))?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("native operation checkpoint exceeds bound"));
    }
    Ok(bytes)
}
// Call only around local existing-only custody validation. Remote/source failures retain their
// own classification; a decoder result never supplies current service authority.
pub(in crate::managed) fn require_retained_material<T>(value: Result<T>) -> Result<T> {
    value.map_err(|error| match error {
        Error::Bootstrap(_) | Error::NativeDeadline => error,
        _error => {
            #[cfg(test)]
            deadline_diagnostics::retained_error(&_error);
            super::ManagedBootstrapFailure::RetainedMaterial.into()
        }
    })
}

pub(super) fn invalid(message: &'static str) -> Error {
    Error::Invalid(message.into())
}
pub(super) fn require_deadline(deadline: Instant) -> Result<()> {
    if deadline <= Instant::now() {
        #[cfg(test)]
        deadline_diagnostics::deadline_refused();
        return Err(Error::NativeDeadline);
    }
    Ok(())
}
pub(crate) fn now_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("invalid UTC clock"))?
            .as_millis(),
    )
    .map_err(|_| invalid("UTC clock exceeds native operation bounds"))
}

#[cfg(test)]
#[path = "native_operation/test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "native_operation/deadline_diagnostics.rs"]
pub(in crate::managed) mod deadline_diagnostics;

#[cfg(test)]
#[path = "native_operation/deadline_tests.rs"]
mod deadline_tests;

#[cfg(test)]
#[path = "native_operation/optional_read_tests.rs"]
mod optional_read_tests;

#[cfg(test)]
#[path = "native_operation/optional_admission_tests.rs"]
mod optional_admission_tests;
