//! Daemon-only assembly of configured native State authority and separate software credentials.
use super::*;
use crate::signer_operation::journal::{SignerJournalInventoryPoolV1, SignerReceiptPurposeV1};
use iroha_config::parameters::actual::SorafsStorage;
use iroha_core::queue::Queue;
use iroha_torii::sorafs::{
    StreamTokenApprovedCustodyAnchorV1, StreamTokenSignerClientV1, StreamTokenSignerPinsV1,
    StreamTokenStateObserverClientV1,
};

/// Complete native runtime assembled only after same-State current custody and keys agree.
pub struct NativeStreamTokenRuntimeV1 {
    /// Canonical private producer client; no raw role signature API is exposed.
    pub signer: Arc<dyn StreamTokenSignerClientV1>,
    /// Separate configured observer over current native State and fresh native Checks.
    pub observer: Arc<dyn StreamTokenStateObserverClientV1>,
    /// Actual current native finalized custody floor bound to complete public trust pins.
    pub anchor: StreamTokenApprovedCustodyAnchorV1,
}
/// Assemble the explicitly selected native software runtime against the daemon's State and queue.
///
/// # Errors
/// Rejects incomplete or mismatched custody, unsafe credentials, shared key identities, unsupported
/// local custody or an unavailable private journal. No transaction is submitted during startup.
pub fn build_native_stream_token_runtime_v1(
    storage: &SorafsStorage,
    state: Arc<State>,
    queue: Arc<Queue>,
) -> Result<Option<NativeStreamTokenRuntimeV1>, SignerStreamTokenErrorV1> {
    let Some(config) = storage
        .stream_tokens
        .signer
        .as_ref()
        .and_then(|signer| signer.native.as_ref())
    else {
        return Ok(None);
    };
    let invalid = || SignerStreamTokenErrorV1::Operation(SignerOperationErrorV1::InvalidOperation);
    let pins = StreamTokenSignerPinsV1::from_config(
        storage,
        state.view().chain_id().as_ref(),
        *state.network_id_ref().as_bytes(),
    )
    .map_err(|_| invalid())?
    .ok_or_else(invalid)?;
    let binding = pins.binding().clone();
    if !binding.runtime_handle.starts_with("software://")
        || !binding.key_handle.starts_with("software://")
        || !(100..=60_000).contains(&config.timeout_ms)
        || storage
            .stream_tokens
            .signer
            .as_ref()
            .ok_or_else(invalid)?
            .clock_uncertainty_ms
            > 5_000
    {
        return Err(invalid());
    }
    let operator_key = config.operator.try_signatory().ok_or_else(invalid)?;
    let observer_key = &pins.observer_trust().public_key;
    if operator_key == &binding.public_key
        || operator_key == &pins.custody_trust().public_key
        || operator_key == observer_key
    {
        return Err(invalid());
    }
    let timeout = Duration::from_millis(config.timeout_ms);
    let transactions = NativeTransactionsV1::new(
        Arc::clone(&state),
        queue,
        config.operator.clone(),
        transactions::load_key(&config.operator_credential, operator_key)?,
        transactions::load_key(&config.observer_credential, observer_key)?,
        config.fee_payment.clone(),
        timeout,
    )?;
    let record = crate::runtime_credential::load_bounded_runtime_credential_v1(
        &config.custody_record,
        1,
        sorafs_manifest::signer::custody::SIGNER_CUSTODY_MAX_BYTES_V1,
    )
    .map_err(|_| SignerStreamTokenErrorV1::Operation(SignerOperationErrorV1::StateUnavailable))?
    .to_vec();
    let source = Arc::new(NativeStreamTokenSourceV1 {
        state,
        binding: binding.clone(),
        custody_record: record.clone(),
        custody_trust: pins.custody_trust().clone(),
        transactions,
        timeout,
        uncertainty_ms: storage
            .stream_tokens
            .signer
            .as_ref()
            .ok_or_else(invalid)?
            .clock_uncertainty_ms,
    });
    let current = source.capture([0; 32])?;
    if current.operator != config.operator {
        return Err(invalid());
    }
    let context = source.context(&current.control, current.anchor)?;
    verify_signer_custody_use_v1(&record, &binding, pins.custody_trust(), &context)
        .map_err(SignerOperationErrorV1::Custody)?;
    let anchor = StreamTokenApprovedCustodyAnchorV1::new(pins.config_digest(), current.anchor)
        .map_err(|_| invalid())?;
    let pool = SignerJournalInventoryPoolV1::new(storage.signer_journal_inventory)?;
    let journal = SignerReceiptJournalV1::open(
        &config.receipt_journal,
        SignerReceiptPurposeV1::StreamToken,
        &pool,
    )?;
    let observer = Arc::new(observer::NativeStreamTokenObserverV1 {
        source: Arc::clone(&source),
        handle: pins.observer_handle().to_owned(),
        trust: pins.observer_trust().clone(),
        record: record.clone(),
    });
    let source: Arc<dyn SignerOperationStateSourceV1> = source;
    let signer = Arc::new(
        SignerStreamTokenServiceV1::from_software_supervisor_credential(
            &config.signer_credential,
            binding,
            record,
            pins.custody_trust().clone(),
            Some(source),
            journal,
        )?,
    );
    Ok(Some(NativeStreamTokenRuntimeV1 {
        signer,
        observer,
        anchor,
    }))
}
