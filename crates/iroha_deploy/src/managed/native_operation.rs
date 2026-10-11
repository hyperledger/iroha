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
    sumeragi_finality::SumeragiFinalityCheckpoint,
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

pub(super) const MAX_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
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
pub(super) struct Terms {
    pub requested_deadline_unix_ms: u64,
    pub signing_deadline_unix_ms: u64,
    pub fees: Fees,
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
    pub(super) fn matches(
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
    pub(super) fn validate(&self) -> Result<()> {
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
pub(super) fn read_optional(
    directory: &PrivateDirectory,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    match directory.read(name, maximum) {
        Ok(bytes) => Ok(Some(bytes.to_vec())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            directory.revalidate()?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
pub(super) fn require_empty(directory: &PrivateDirectory) -> Result<()> {
    if !directory.entries(0)?.is_empty() {
        return Err(invalid("native operation journal has no original request"));
    }
    Ok(())
}

impl ServiceAuthority {
    pub(super) fn observe_finality(&mut self, deadline: Instant) -> Result<FinalityVerifier> {
        require_deadline(deadline)?;
        let retained = read_optional(
            &self.directory,
            "current-checkpoint.nrt",
            MAX_CHECKPOINT_BYTES,
        )?;
        let mut verifier = if let Some(bytes) = retained {
            self.decode_checkpoint(&bytes)?
        } else {
            let source = self.source(1, deadline)?;
            let proof = source
                .finality_proof(NonZeroU64::new(1).expect("positive genesis"))
                .map_err(|_| invalid("cannot read original genesis result"))?;
            FinalityVerifier::from_genesis(&self.genesis, &proof)
                .map_err(|_| invalid("original genesis finality differs"))?
        };
        let source = self.source(verifier.checkpoint().height(), deadline)?;
        let observation = verifier.observe(&source, &rand::random());
        retain_observation(&self.directory, &mut verifier, observation)?;
        Ok(verifier)
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
        retained_carrier(
            directory,
            self.config.network_id,
            &self.config.chain.to_string(),
            transaction,
        )
    }

    pub(super) fn advance_carrier(
        &self,
        directory: &PrivateDirectory,
        original_checkpoint: &[u8],
        transaction: &SignedTransaction,
        report: &OperationReport,
        observed_height: u64,
        deadline: Instant,
    ) -> Result<Option<ManagedTransactionFinality>> {
        let height = report
            .data
            .get("evidence")
            .and_then(|e| e.get("block_height"))
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| invalid("Applied native operation observation has no carrier hint"))?;
        self.advance_carrier_at(
            directory,
            original_checkpoint,
            transaction,
            height,
            observed_height,
            deadline,
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
        let original_verifier = self.decode_checkpoint(original_checkpoint)?;
        if height <= original_verifier.checkpoint().height() {
            return Err(invalid(
                "native operation carrier predates its original request",
            ));
        }
        if height > observed_height {
            return Ok(None);
        }
        // Applied is only a replaceable lookup hint. A false earlier hint cannot irreversibly
        // pin a carrier or prevent replaying the original transaction at its actual height.
        let progress = read_optional(directory, "replay.nrt", MAX_CHECKPOINT_BYTES)?
            .map(|bytes| self.decode_checkpoint(&bytes))
            .transpose()?;
        let mut verifier = replay_start(original_verifier, progress, height)?;
        let source = self.source(verifier.checkpoint().height(), deadline)?;
        retain_carrier_progress(directory, transaction, &mut verifier, height, &source)
    }
}

/// Retain a bounded verified replay from the sole finality-source abstraction. Test sources
/// execute the original generated native chain; no decoded report supplies successful inclusion.
pub(crate) fn retain_carrier_progress(
    directory: &PrivateDirectory,
    transaction: &SignedTransaction,
    verifier: &mut FinalityVerifier,
    height: u64,
    source: &impl FinalitySource,
) -> Result<Option<ManagedTransactionFinality>> {
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
    let bytes = checkpoint_bytes(verifier)?;
    directory.write_atomic("replay.nrt", &bytes, PublishMode::Replace)?;
    if verifier.checkpoint().height() != height {
        return Ok(None);
    }
    let finalized = verify_carrier(verifier, transaction)?;
    directory.write_atomic("carrier.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(Some(finalized))
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

pub(super) fn decode_checkpoint(
    bytes: &[u8],
    network: iroha_data_model::NetworkId,
    chain: &str,
) -> Result<FinalityVerifier> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("native operation checkpoint exceeds bound"));
    }
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(bytes)
        .map_err(|_| invalid("invalid retained native operation checkpoint"))?;
    FinalityVerifier::from_checkpoint(checkpoint, network, chain)
        .map_err(|_| invalid("retained native operation checkpoint changed network or chain"))
}

pub(crate) fn retained_carrier(
    directory: &PrivateDirectory,
    network: iroha_data_model::NetworkId,
    chain: &str,
    transaction: &SignedTransaction,
) -> Result<Option<ManagedTransactionFinality>> {
    read_optional(directory, "carrier.nrt", MAX_CHECKPOINT_BYTES)?
        .map(|bytes| verify_carrier(&decode_checkpoint(&bytes, network, chain)?, transaction))
        .transpose()
}

pub(crate) fn retain_observation(
    directory: &PrivateDirectory,
    verifier: &mut FinalityVerifier,
    observation: std::result::Result<AttestationQuorum, FinalityError>,
) -> Result<()> {
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
    let verified = verifier
        .verified_tip()
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
    let mut found = false;
    for (index, entrypoint) in verified.block().network_entrypoints().enumerate() {
        let TransactionEntrypoint::External(candidate) = entrypoint else {
            continue;
        };
        if candidate.hash() != transaction.hash() {
            continue;
        }
        let input_index = u32::try_from(index)
            .map_err(|_| invalid("native operation carrier index exceeds bound"))?;
        if found
            || candidate
                .encode_wire_v1()
                .map_err(|_| invalid("invalid carrier transaction wire"))?
                != wire
            || !verified
                .block()
                .network_output_at(input_index)
                .is_some_and(|(_, output)| output.result.as_ref().is_ok())
        {
            return Err(invalid(
                "native operation carrier lacks exact successful original execution",
            ));
        }
        found = true;
    }
    if !found {
        return Err(invalid(
            "original native operation transaction absent from certified carrier",
        ));
    }
    Ok(ManagedTransactionFinality {
        transaction_hash: transaction.hash(),
        height: verified.height(),
        block_hash: verified.header().hash(),
        block_time_ms: verified.header().creation_time_ms,
    })
}

pub(super) fn checkpoint_bytes(verifier: &FinalityVerifier) -> Result<Vec<u8>> {
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
        Error::Bootstrap(_) => error,
        _ => super::ManagedBootstrapFailure::RetainedMaterial.into(),
    })
}

pub(super) fn invalid(message: &'static str) -> Error {
    Error::Invalid(message.into())
}
pub(super) fn require_deadline(deadline: Instant) -> Result<()> {
    if deadline <= Instant::now() {
        return Err(invalid(
            "native operation I/O deadline elapsed; retain original journals",
        ));
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
