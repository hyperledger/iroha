//! One existing workflow round owns original source/secret/proof custody.
use super::*;
use iroha::workflow::{CustodyHandleV1, WorkflowJournalV1, WorkflowStorageError};
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn driver_identity() -> DriverIdentityV1 {
    DriverIdentityV1 {
        id: "private_settlement_preparation".into(),
        schema_version: 1,
    }
}
pub struct NoPreparationEffects(pub WorkflowBindingV1);
impl WorkflowAccount for NoPreparationEffects {
    fn binding(&self) -> WorkflowBindingV1 {
        self.0.clone()
    }
    fn sign<'a>(
        &'a self,
        _: &'a [u8],
    ) -> WorkflowFuture<'a, std::result::Result<iroha::workflow::SignedStepTransaction, StepFailure>>
    {
        Box::pin(async {
            Err(StepFailure::new(
                WorkflowErrorCode::UnsupportedOperation,
                "preparation has no transaction signer",
            ))
        })
    }
    fn identify(&self, _: &[u8]) -> std::result::Result<TransactionIdentityV1, StepFailure> {
        Err(StepFailure::new(
            WorkflowErrorCode::UnsupportedOperation,
            "preparation has no transaction identity",
        ))
    }
}
impl WorkflowLedger for NoPreparationEffects {
    fn dispatch<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async {
            DispatchOutcome::Refused {
                detail: "preparation has no ledger dispatch".into(),
            }
        })
    }
    fn committed_outcome<'a>(
        &'a self,
        _: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async {
            CommittedOutcome::ReadFailed {
                detail: "preparation has no ledger observation".into(),
            }
        })
    }
}
pub struct PreparationDriver {
    account: AccountClient,
    request: OneCallPrivateSettlementRequest,
    storage: Arc<dyn WorkflowStorage>,
    artifacts: Arc<FilePrivateSettlementArtifacts>,
    source: Arc<dyn PrivateSettlementContextSource>,
    wallet: Arc<dyn PrivateSettlementWallet>,
    verifier: Mutex<SumeragiFinalityVerifier>,
    reads: AtomicUsize,
    error: Mutex<Option<OneCallPrivateSettlementError>>,
    worker: Arc<tokio::sync::Semaphore>,
}
fn lock<T>(
    value: &Mutex<T>,
) -> std::result::Result<std::sync::MutexGuard<'_, T>, OneCallPrivateSettlementError> {
    value
        .lock()
        .map_err(|_| OneCallPrivateSettlementError::Capacity)
}
fn storage_error(error: WorkflowStorageError) -> OneCallPrivateSettlementError {
    OneCallPrivateSettlementError::Provider(eyre::Report::new(error))
}
impl PreparationDriver {
    pub fn new(
        account: AccountClient,
        request: OneCallPrivateSettlementRequest,
        storage: Arc<dyn WorkflowStorage>,
        artifacts: Arc<FilePrivateSettlementArtifacts>,
        source: Arc<dyn PrivateSettlementContextSource>,
        wallet: Arc<dyn PrivateSettlementWallet>,
        verifier: SumeragiFinalityVerifier,
    ) -> Self {
        Self {
            account,
            request,
            storage,
            artifacts,
            source,
            wallet,
            verifier: Mutex::new(verifier),
            reads: AtomicUsize::new(0),
            error: Mutex::new(None),
            worker: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
    pub fn begin_call(
        &self,
        reads: usize,
    ) -> std::result::Result<(), OneCallPrivateSettlementError> {
        self.reads.store(reads, Ordering::Relaxed);
        *lock(&self.error)? = None;
        Ok(())
    }
    pub fn settlement_handoff(
        &self,
        options: &PrivateSettlementRunOptions,
    ) -> std::result::Result<
        (SumeragiFinalityVerifier, PrivateSettlementRunOptions),
        OneCallPrivateSettlementError,
    > {
        let remaining = u16::try_from(self.reads.load(Ordering::Relaxed))
            .ok()
            .and_then(std::num::NonZeroU16::new)
            .ok_or(OneCallPrivateSettlementError::Capacity)?;
        let mut options = *options;
        options.max_finality_proof_reads = remaining;
        Ok((lock(&self.verifier)?.clone(), options))
    }
    pub fn take_error(
        &self,
    ) -> std::result::Result<Option<OneCallPrivateSettlementError>, OneCallPrivateSettlementError>
    {
        Ok(lock(&self.error)?.take())
    }
    fn remember(&self, error: OneCallPrivateSettlementError) -> StepFailure {
        // A transient operational category, never a terminal ledger/round verdict.
        // Keep the original typed owner for the public caller; persist no provider detail.
        let code = error.workflow_code();
        if let Ok(mut slot) = self.error.lock() {
            *slot = Some(error);
        }
        StepFailure::new(
            code,
            "private preparation original cause retained outside journal",
        )
    }
    async fn selected_block(
        &self,
    ) -> std::result::Result<VerifiedSumeragiBlock, OneCallPrivateSettlementError> {
        let height = self.request.intent().authority_context_height;
        loop {
            let next = lock(&self.verifier)?
                .authenticated_height()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(OneCallPrivateSettlementError::Binding)?;
            self.reads
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
            let target = next.min(height);
            let proof = self
                .account
                .get_sumeragi_finality_proof_async(
                    NonZeroU64::new(target).ok_or(OneCallPrivateSettlementError::Binding)?,
                    SumeragiRootScope::Global,
                )
                .await
                .map_err(OneCallPrivateSettlementError::Provider)?;
            if proof.height() != target {
                return Err(OneCallPrivateSettlementError::Binding);
            }
            let block = if next > height {
                lock(&self.verifier)?.verify_retained_decision(&proof)?
            } else {
                lock(&self.verifier)?.verify(&proof)?
            };
            if target == height {
                return Ok(block);
            }
        }
    }
    fn status(
        &self,
        context: RoundContext<'_>,
    ) -> std::result::Result<RoundStatusReport, OneCallPrivateSettlementError> {
        if context.step_index != 0
            || context.descriptor.intent_digest != self.request.0.digest
            || context.journal.identity.request_context_digest != self.request.0.digest
        {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        Ok(RoundStatusReport {
            round_id: context.round_id,
            context_digest: self.request.0.digest,
            participants: Vec::new(),
        })
    }
    async fn originals(
        &self,
        round: Digest32,
        may_prepare: bool,
    ) -> std::result::Result<Option<Vec<Artifact>>, OneCallPrivateSettlementError> {
        let block = Arc::new(self.selected_block().await?);
        // The storage owner retains the original per-round proof lease across network waits
        // and moves it into each native worker. It is not cloneable: cancellation cannot
        // release custody while that worker still holds secrets or publishes its artifact.
        let lease_id = WorkflowId::from_bytes(domain_digest(
            b"iroha:private-settlement:proof-worker:v1\0",
            &[&round],
        ));
        let mut lease = self
            .storage
            .acquire_runner(&lease_id)
            .map_err(storage_error)?;
        let request = self.request.clone();
        let selectors = PrivateSettlementContextRequestV1 {
            pools: request
                .intent()
                .legs
                .iter()
                .map(|leg| PrivateSettlementPoolKeyV1 {
                    route: leg.route,
                    pool_id: leg.pool_id,
                })
                .collect(),
        };
        selectors.validate()?;
        let context_key = ArtifactKey {
            request: request.0.digest,
            round,
            ordinal: 0,
        };
        let artifacts = self.artifacts.clone();
        let maximum = request.0.max_artifact_bytes;
        let permit = self
            .worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
        let (original, original_lease) = run_private_settlement_worker(permit, move || {
            (artifacts.read_context(context_key, maximum), lease)
        })
        .await?;
        lease = original_lease;
        let (proof, context_length, publish) = if let Some((proof, length)) = original? {
            (proof, length, false)
        } else {
            if !may_prepare {
                return Ok(None);
            }
            let proof = self
                .source
                .fetch(request.intent().authority_context_height, selectors.clone())
                .await?;
            let length = norito::canonical_frame_len(&proof)?;
            if length > maximum {
                return Err(OneCallPrivateSettlementError::Capacity);
            }
            (proof, length, true)
        };
        if context_length > request.0.max_total_artifact_bytes {
            return Err(OneCallPrivateSettlementError::Capacity);
        }
        let permit = self
            .worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
        let artifacts = self.artifacts.clone();
        let original_block = block.clone();
        let (original, original_lease) = run_private_settlement_worker(permit, move || {
            let result = (|| -> std::result::Result<_, OneCallPrivateSettlementError> {
                proof.verify(
                    request.intent().network_id,
                    request.0.schema,
                    &selectors,
                    &original_block,
                )?;
                // Public mismatches on any later leg must refuse before the first wallet
                // opening or reservation. Reuse the producer's Model-owned exact join.
                for (index, member) in proof.contexts.iter().enumerate() {
                    let selected = member.verify(
                        request.intent().network_id,
                        request.0.schema,
                        selectors.pools[index],
                        &original_block,
                    )?;
                    selected
                        .verify_intent(request.intent(), request.intent().legs[index].ordinal)?;
                    if selected.pool_cut().block_time_ms() < request.0.minimum_context_time_ms {
                        return Err(OneCallPrivateSettlementError::Binding);
                    }
                }
                let digest = domain_digest(
                    b"iroha:private-settlement:original-contexts:v1\0",
                    &[&norito::encode_canonical(&proof)?],
                );
                // All exact selected context is durable before the first wallet call. One
                // physical source and one atomic encrypted file prevent partial-cut stranding.
                if publish {
                    artifacts.publish_context(context_key, &proof, maximum)?;
                }
                Ok((Arc::new(proof), digest))
            })();
            (result, lease)
        })
        .await?;
        lease = original_lease;
        let (contexts, context_digest) = original?;
        let mut complete = Vec::with_capacity(self.request.intent().legs.len());
        let mut bytes = context_length;
        for index in 0..self.request.intent().legs.len() {
            let request = self.request.clone();
            let key = ArtifactKey {
                request: request.0.digest,
                round,
                ordinal: request.intent().legs[index].ordinal,
            };
            let contexts = contexts.clone();
            let permit = self
                .worker
                .clone()
                .try_acquire_owned()
                .map_err(|_| OneCallPrivateSettlementError::Capacity)?;
            let artifacts = self.artifacts.clone();
            let wallet = self.wallet.clone();
            let block = block.clone();
            let (result,original_lease)=run_private_settlement_worker(permit,move||{
                let result=(|| -> std::result::Result<Option<(Artifact,usize)>,OneCallPrivateSettlementError> {
                    let leg=&request.intent().legs[index];
                    let context=contexts.contexts[index].verify(request.intent().network_id,request.0.schema,
                        PrivateSettlementPoolKeyV1{route:leg.route,pool_id:leg.pool_id},&block)?;
                    if context.pool_cut().block_time_ms()<request.0.minimum_context_time_ms {
                        return Err(OneCallPrivateSettlementError::Binding);
                    }
                    let existing=artifacts.read(key,request.0.max_artifact_bytes)?;
                    let (artifact,length)=if let Some(existing)=existing {
                        validate_artifact(&request,&context,context_digest,&existing.0)?; existing
                    } else {
                        if !may_prepare {return Ok(None);}
                        let terms=&request.0.terms[index];
                        let opening=wallet.open_policy(request.intent(),leg.ordinal,terms)?;
                        let verified=context.verify_openings(&opening.governance,&opening.policy,&terms.asset,
                            opening.governance.body.asset_binding_salt,request.intent().expiry_height)?;
                        let secrets=wallet.reserve_or_reopen(round,request.intent(),leg.ordinal,terms)?;
                        let plaintext=secrets.plaintext();
                        let asset_matches = plaintext.asset_definition_id == terms.asset;
                        let reimbursement_matches = plaintext.sponsor_reimbursement_amount == terms.reimbursement;
                        if plaintext.payer!=terms.payer || plaintext.recipient!=terms.recipient
                            || !asset_matches || plaintext.amount!=terms.amount
                            || !reimbursement_matches || plaintext.memo!=terms.memo {
                            return Err(OneCallPrivateSettlementError::Binding);
                        }
                        let prepared=prepare_atomic_private_settlement_leg_v1(request.intent(),leg.ordinal,
                            &verified,secrets,request.0.padding)?;
                        let artifact=Artifact{key,context_id:context.pool_cut().context_id(),context_digest,
                            statement:prepared.statement,proof:prepared.proof,delta:prepared.delta,
                            capsule:prepared.audit_capsule,policy:opening.policy,authority:context.authority().clone(),
                            retention_height:request.0.retention_height};
                        validate_artifact(&request,&context,context_digest,&artifact)?;
                        let length=norito::canonical_frame_len(&artifact)?;
                        if bytes.checked_add(length).is_none_or(|n|n>request.0.max_total_artifact_bytes) {
                            return Err(OneCallPrivateSettlementError::Capacity);
                        }
                        artifacts.publish(&artifact,request.0.max_artifact_bytes)?;
                        (artifact,length)
                    };
                    if bytes.checked_add(length).is_none_or(|n|n>request.0.max_total_artifact_bytes) {
                        return Err(OneCallPrivateSettlementError::Capacity);
                    }
                    Ok(Some((artifact,length)))
                })();
                (result,lease)
            }).await?;
            lease = original_lease;
            let Some((artifact, length)) = result? else {
                return Ok(None);
            };
            bytes = bytes
                .checked_add(length)
                .ok_or(OneCallPrivateSettlementError::Capacity)?;
            complete.push(artifact);
        }
        Ok(Some(complete))
    }

    async fn report(
        &self,
        context: RoundContext<'_>,
        may_prepare: bool,
    ) -> std::result::Result<RoundReport, OneCallPrivateSettlementError> {
        let status = self.status(context)?;
        let Some(artifacts) = self.originals(context.round_id, may_prepare).await? else {
            return Ok(RoundReport::Waiting(status));
        };
        let digests = artifacts
            .iter()
            .map(Artifact::digest)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(RoundReport::Completed {
            status,
            transcript: norito::encode_canonical(&digests)?,
            custody_handles: vec![CustodyHandleV1 {
                label: "encrypted_prepared_artifacts".into(),
                reference: context.round_id.to_vec(),
            }],
        })
    }
    pub async fn recovered_request(
        &self,
        journal: Option<&WorkflowJournalV1>,
    ) -> std::result::Result<PrivateSettlementRequest, OneCallPrivateSettlementError> {
        let journal = journal.ok_or(OneCallPrivateSettlementError::Pending)?;
        let round = journal.steps[0]
            .round
            .as_ref()
            .ok_or(OneCallPrivateSettlementError::Binding)?;
        let round_id = round
            .round_id
            .ok_or(OneCallPrivateSettlementError::Binding)?;
        if !journal.steps[0].is_done() {
            return Err(OneCallPrivateSettlementError::Pending);
        }
        let Some(artifacts) = self.originals(round_id, false).await? else {
            return Err(OneCallPrivateSettlementError::Pending);
        };
        let digests = artifacts
            .iter()
            .map(Artifact::digest)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let recorded: Vec<Digest32> = norito::decode_canonical(
            round
                .transcript
                .as_deref()
                .ok_or(OneCallPrivateSettlementError::Binding)?,
        )?;
        if recorded != digests {
            return Err(OneCallPrivateSettlementError::Binding);
        }
        let inputs = artifacts
            .into_iter()
            .map(Artifact::into_input)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let bundle = finalize_atomic_private_settlement_provisional_bundle_v1(
            self.request.intent().clone(),
            inputs,
        )
        .map_err(AtomicPrivateSettlementPreparationErrorV1::Wallet)?;
        Ok(PrivateSettlementRequest::new(
            bundle.materials,
            self.request.0.endpoints.clone(),
            self.request.0.max_carrier_bytes,
        )?)
    }
}
fn validate_artifact(
    request: &OneCallPrivateSettlementRequest,
    context: &iroha_data_model::nexus::VerifiedPrivateSettlementContextV1<'_>,
    context_digest: Digest32,
    artifact: &Artifact,
) -> std::result::Result<(), OneCallPrivateSettlementError> {
    let statement = &artifact.statement;
    if artifact.context_digest != context_digest
        || artifact.context_id != context.pool_cut().context_id()
        || artifact.authority != *context.authority()
        || artifact.retention_height != request.0.retention_height
        || statement.old_root != context.pool_cut().pool().root
        || statement.old_epoch != context.pool_cut().pool().epoch
        || artifact.policy.policy_digest != context.pool_cut().governance().audit_policy_digest
    {
        return Err(OneCallPrivateSettlementError::Binding);
    }
    for nullifier in &statement.nullifiers {
        context.pool_cut().verify_nullifier_absent(*nullifier)?;
    }
    for output in &statement.output_commitments {
        context.pool_cut().verify_output_absent(*output)?;
    }
    AtomicPrivateSettlementProvisionalLegInputV1::new(
        artifact.prepared(),
        artifact.policy.clone(),
        artifact.authority.clone(),
        artifact.retention_height,
    )
    .map_err(AtomicPrivateSettlementPreparationErrorV1::Wallet)?;
    verify_atomic_private_settlement_intent_v1(
        request.intent(),
        statement,
        *request.intent().network_id.as_genesis_hash().as_ref(),
        request.intent().authority_context_height,
        &artifact.proof,
    )
    .map_err(AtomicPrivateSettlementPreparationErrorV1::Proof)?;
    Ok(())
}
impl WorkflowDriver for PreparationDriver {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn supports_round_continuation(&self) -> bool {
        true
    }
    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, std::result::Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            self.report(context, true)
                .await
                .map_err(|e| self.remember(e))
        })
    }
    fn recover_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, std::result::Result<RoundRecovery, StepFailure>> {
        Box::pin(async move {
            self.report(context, false)
                .await
                .map(RoundRecovery::Found)
                .map_err(|e| self.remember(e))
        })
    }
    fn continue_round<'a>(
        &'a self,
        context: RoundContext<'a>,
        observed: RoundStatusReport,
    ) -> WorkflowFuture<'a, std::result::Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            if self.status(context).map_err(|e| self.remember(e))? != observed {
                return Err(self.remember(OneCallPrivateSettlementError::Binding));
            }
            self.report(context, true)
                .await
                .map_err(|e| self.remember(e))
        })
    }
}
