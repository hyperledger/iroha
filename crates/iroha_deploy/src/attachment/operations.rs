//! Exact parent transactions and retained pre-dispatch finality for attachment recovery.

use super::*;
use iroha::{client::Client, config::Config};
use iroha_data_model::private_dataspace::PrivateDataspaceAnchorState;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, OperationReport, OperationStatus,
    PrivateRootAnchorRequest, PrivateRootRegistrationRequest,
};
use std::{num::NonZeroU64, time::Instant};

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::PendingParentKindV1")]
pub(super) enum PendingKind {
    Registration,
    Anchor {
        previous: PrivateDataspaceAnchorState,
        anchor: PrivateDataspaceAnchor,
    },
}

#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::attachment::PendingParentOperationV1")]
pub(super) struct PendingOperation {
    kind: PendingKind,
    checkpoint: Vec<u8>,
    replay: Option<super::replay::ParentReplay>,
}

impl PendingOperation {
    pub(super) fn validate(&self, identity: &AttachmentIdentity) -> Result<()> {
        self.verifier(identity)?;
        if let Some(replay) = &self.replay {
            replay.validate(identity, &self.verifier(identity)?)?;
        }
        if let PendingKind::Anchor { previous, anchor } = &self.kind {
            if previous.registration() != identity.registration() {
                return Err(AttachmentError::Invalid(
                    "pending anchor selected another child",
                ));
            }
            let mut next = previous.clone();
            if next.apply(anchor)? != PrivateDataspaceAnchorOutcome::Advanced {
                return Err(AttachmentError::Invalid(
                    "pending anchor does not advance its retained cursor",
                ));
            }
        }
        Ok(())
    }

    fn verifier(&self, identity: &AttachmentIdentity) -> Result<FinalityVerifier> {
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&self.checkpoint)
            .map_err(|_| AttachmentError::Invalid("invalid operation finality checkpoint"))?;
        Ok(FinalityVerifier::from_checkpoint(
            checkpoint,
            identity.parent_network_id,
            &identity.parent_chain_id,
        )?)
    }

    pub(super) fn target(&self, identity: &AttachmentIdentity) -> Result<PrivateDataspaceCursor> {
        match &self.kind {
            PendingKind::Registration => Ok(identity.registration.genesis_cursor),
            PendingKind::Anchor { previous, anchor } => {
                let mut next = previous.clone();
                next.apply(anchor)?;
                Ok(next.cursor())
            }
        }
    }

    fn journal_name(&self) -> Result<String> {
        match &self.kind {
            PendingKind::Registration => Ok("registration".into()),
            PendingKind::Anchor { anchor, .. } => Ok(format!("anchor-{}", anchor.height()?)),
        }
    }
}

/// Separate exact-transaction observation and independently authenticated parent anchoring.
#[derive(Clone, Copy, Debug)]
pub struct AttachmentProgress {
    /// Configured node's exact saved-transaction observation, if this call needed a transaction.
    /// `Applied` alone is insufficient to claim parent anchoring.
    pub transaction_status: Option<OperationStatus>,
    /// Last durably verified parent anchoring fact, possibly predating the current private tip.
    pub confirmed: Option<ConfirmedAnchor>,
    /// Exact prepared/dispatched operation still requires reconciliation.
    pub pending: bool,
}

impl AttachmentStore {
    /// Prepare, submit at most once, and independently verify one compact parent operation.
    ///
    /// A retained operation always resumes first. Otherwise an unregistered root prepares its
    /// registration; a registered root accepts the supplied next child certificate. `None` means
    /// no new child work. All retries preserve the original signed transaction, fee ceilings,
    /// child decision and pre-dispatch parent checkpoint. The checkpoint lets recovery verify
    /// the original carrier even after the shared parent's latest tip has advanced beyond it.
    /// Each call verifies at most sixteen replay successors under the native byte budget and
    /// durably retains progress. A captured independently observed parent tip must agree with
    /// this contiguous replay before the original carrier receipt can complete the operation.
    /// Call again while `pending` is true, using the caller's overall scheduling deadline.
    ///
    /// This method neither starts private validators nor obtains an SNS lease or faucet funds.
    /// The shared provisioning owner supplies those before creating this exact attachment.
    ///
    /// # Errors
    /// Unsafe custody, unapproved endpoint, changed signer/network/operation/budget, expired HTTP
    /// budget, failed independent native verification, or an invalid original parent write.
    /// Unresolved transaction observations return `pending = true` without signing again.
    pub fn advance_parent<S: crate::verify::finality::FinalitySource + ?Sized>(
        &mut self,
        parent_config: &Config,
        bootstrap: &AuthenticatedBootstrap,
        parent: &mut ParentFinalityStore,
        source: &S,
        options: &BoundedTransactionOptions,
        next_anchor: Option<&PrivateDataspaceAnchor>,
    ) -> Result<AttachmentProgress> {
        self.revalidate()?;
        require_deadline(options.deadline)?;
        self.validate_parent_context(parent_config, bootstrap, parent)?;
        if self.record.pending.is_none() {
            self.require_active()?;
        }
        let challenge = rand::random::<[u8; 32]>();
        parent.observe(source, &challenge)?;
        if self.record.pending.is_none() {
            self.require_active()?;
            let kind = if self.confirmed().is_none() {
                PendingKind::Registration
            } else if let Some(anchor) = next_anchor {
                if self.anchor_instruction(anchor)?.is_none() {
                    return Ok(self.progress(None));
                }
                PendingKind::Anchor {
                    previous: self
                        .confirmed_child_state()
                        .ok_or(AttachmentError::Invalid("missing confirmed child"))?
                        .clone(),
                    anchor: anchor.clone(),
                }
            } else {
                return Ok(self.progress(None));
            };
            let pending =
                PendingOperation {
                    kind,
                    checkpoint: parent.verifier().checkpoint().encode_canonical().map_err(
                        |_| AttachmentError::Invalid("cannot retain pre-dispatch checkpoint"),
                    )?,
                    replay: None,
                };
            pending.validate(&self.record.identity)?;
            let mut record = self.record.clone();
            record.pending = Some(pending);
            self.publish(&record, PublishMode::Replace)?;
            self.record = record;
        }
        let pending = self
            .record
            .pending
            .clone()
            .ok_or(AttachmentError::Invalid("missing pending parent operation"))?;
        let transaction_root = self.directory.ensure_child("transactions")?;
        let journal = transaction_root.path().join(pending.journal_name()?);
        let account = AccountService::new(parent_config.clone())
            .and_then(|account| match &self.cancellation {
                Some(signal) => account.with_cancellation(Arc::clone(signal)),
                None => Ok(account),
            })
            .and_then(|account| account.with_deadline(options.deadline))
            .map_err(|_| {
                AttachmentError::Operation("cannot open the exact parent wallet context")
            })?;
        let report = match &pending.kind {
            PendingKind::Registration => {
                let request = PrivateRootRegistrationRequest {
                    alias: self.record.identity.alias.clone(),
                    expected_ownership_generation: self.record.identity.ownership_generation,
                    registration: self.record.identity.registration.clone(),
                    options: options.clone(),
                };
                if pending.replay.is_some() {
                    account
                        .verify_private_root_registration_journal(&journal, &request)
                        .map_err(|_| {
                            AttachmentError::Operation(
                                "saved registration differs from exact request",
                            )
                        })?;
                    None
                } else {
                    let preparation = account
                        .inspect_private_root_registration_preparation(&journal, &request)
                        .map_err(|_| {
                            AttachmentError::Operation(
                                "parent preparation differs from exact request",
                            )
                        })?;
                    let needs_prepare = match preparation.phase() {
                        iroha_wallet::operations::NativePreparationPhase::Missing
                        | iroha_wallet::operations::NativePreparationPhase::RequestOnly
                        | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => true,
                        iroha_wallet::operations::NativePreparationPhase::Signed => false,
                        iroha_wallet::operations::NativePreparationPhase::Retired => {
                            return Err(AttachmentError::Operation(
                                "original parent request was retired",
                            ));
                        }
                    };
                    if needs_prepare {
                        account
                            .prepare_private_root_registration(&request, &journal)
                            .map_err(|_| {
                                AttachmentError::Operation(
                                    "registration preparation failed; retain its exact journal",
                                )
                            })?;
                    }
                    Some(account.submit_private_root_registration(&journal, &request))
                }
            }
            PendingKind::Anchor { previous, anchor } => {
                let request = PrivateRootAnchorRequest {
                    state: previous.clone(),
                    anchor: anchor.clone(),
                    options: options.clone(),
                };
                if pending.replay.is_some() {
                    account
                        .verify_private_root_anchor_journal(&journal, &request)
                        .map_err(|_| {
                            AttachmentError::Operation("saved anchor differs from exact request")
                        })?;
                    None
                } else {
                    let preparation = account
                        .inspect_private_root_anchor_preparation(&journal, &request)
                        .map_err(|_| {
                            AttachmentError::Operation(
                                "parent preparation differs from exact request",
                            )
                        })?;
                    let needs_prepare = match preparation.phase() {
                        iroha_wallet::operations::NativePreparationPhase::Missing
                        | iroha_wallet::operations::NativePreparationPhase::RequestOnly
                        | iroha_wallet::operations::NativePreparationPhase::PayloadRetained => true,
                        iroha_wallet::operations::NativePreparationPhase::Signed => false,
                        iroha_wallet::operations::NativePreparationPhase::Retired => {
                            return Err(AttachmentError::Operation(
                                "original parent request was retired",
                            ));
                        }
                    };
                    if needs_prepare {
                        account
                            .prepare_private_root_anchor(&request, &journal)
                            .map_err(|_| {
                                AttachmentError::Operation(
                                    "anchor preparation failed; retain its exact journal",
                                )
                            })?;
                    }
                    Some(account.submit_private_root_anchor(&journal, &request))
                }
            }
        }
        .transpose()
        .map_err(|_| {
            AttachmentError::Operation("exact parent operation requires journal recovery")
        })?;
        let mut pending = pending;
        if let Some(report) = report {
            if report.status != OperationStatus::Applied {
                return Ok(self.progress(Some(report.status)));
            }
            pending.replay = Some(super::replay::ParentReplay::new(
                &self.record.identity,
                &pending.verifier(&self.record.identity)?,
                carrier_height(&report)?,
                parent.verifier(),
            )?);
            self.publish_pending(pending.clone())?;
        }
        let replay = pending.replay.as_mut().ok_or(AttachmentError::Invalid(
            "applied operation has no retained replay context",
        ))?;
        require_deadline(options.deadline)?;
        replay.advance_page(&self.record.identity, source)?;
        // Publication precedes the separate inclusion read. A temporarily unavailable record
        // never discards a successfully verified bounded page of parent history.
        self.publish_pending(pending.clone())?;
        let replay = pending
            .replay
            .as_mut()
            .ok_or(AttachmentError::Invalid("missing pending replay"))?;
        if let Some(height) = replay.needs_carrier_proof() {
            require_deadline(options.deadline)?;
            let client = Client::builder(parent_config.clone())
                .build()
                .map_err(|_| {
                    AttachmentError::Operation("cannot construct exact parent receipt client")
                })?
                .with_request_deadline(options.deadline);
            let proof = client
                .get_private_dataspace_record_proof(self.record.identity.dataspace_id(), height)
                .map_err(|_| {
                    AttachmentError::Operation(
                        "original parent record proof is unavailable; resume the exact operation",
                    )
                })?;
            replay.retain_carrier(&self.record.identity, proof)?;
            self.publish_pending(pending.clone())?;
        }
        if let Some((proof, verifier)) = pending
            .replay
            .as_ref()
            .ok_or(AttachmentError::Invalid("missing pending replay"))?
            .completed(&self.record.identity)?
        {
            self.confirm_completed_operation(proof, &verifier)?;
        }
        Ok(self.progress(Some(OperationStatus::Applied)))
    }

    fn validate_parent_context(
        &self,
        config: &Config,
        bootstrap: &AuthenticatedBootstrap,
        parent: &ParentFinalityStore,
    ) -> Result<()> {
        let identity = &self.record.identity;
        let release = bootstrap.release();
        if config.network_id != identity.parent_network_id
            || config.chain.to_string() != identity.parent_chain_id
            || config.account != identity.owner
            || parent.network_name() != identity.parent_name
            || parent.generation() != identity.parent_generation
            || parent.verifier().checkpoint().network_id() != identity.parent_network_id
            || parent.verifier().checkpoint().chain_id() != identity.parent_chain_id
            || release.network_name != identity.parent_name
            || release.generation != identity.parent_generation
            || release.network_id != identity.parent_network_id
            || release.chain_id != identity.parent_chain_id
            || !release
                .torii_roots
                .iter()
                .any(|root| root == config.torii_api_url.as_str())
        {
            return Err(AttachmentError::Invalid(
                "wallet endpoint, signer or parent generation differs from the authenticated attachment",
            ));
        }
        Ok(())
    }

    fn progress(&self, transaction_status: Option<OperationStatus>) -> AttachmentProgress {
        AttachmentProgress {
            transaction_status,
            confirmed: self.confirmed(),
            pending: self.record.pending.is_some(),
        }
    }

    fn publish_pending(&mut self, pending: PendingOperation) -> Result<()> {
        pending.validate(&self.record.identity)?;
        let mut record = self.record.clone();
        record.pending = Some(pending);
        self.publish(&record, PublishMode::Replace)?;
        self.record = record;
        Ok(())
    }
}

pub(super) fn require_deadline(deadline: Instant) -> Result<()> {
    if deadline <= Instant::now() {
        return Err(AttachmentError::Operation(
            "attachment deadline elapsed; retained work remains resumable",
        ));
    }
    Ok(())
}

pub(super) fn carrier_height(report: &OperationReport) -> Result<NonZeroU64> {
    report
        .data
        .get("evidence")
        .and_then(|evidence| evidence.get("block_height"))
        .and_then(norito::json::Value::as_u64)
        .and_then(NonZeroU64::new)
        .filter(|height| height.get() > 1)
        .ok_or(AttachmentError::Invalid(
            "exact applied operation lacks its parent carrier height",
        ))
}

#[cfg(test)]
mod tests;
