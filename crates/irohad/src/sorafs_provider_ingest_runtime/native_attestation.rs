//! Native approval-only signing and supervision over the sole completed-bundle capture driver.
//!
//! The inventory acknowledges local durable retention. Registry inclusion remains independently
//! owned by the archive manager's existing publication transaction journal.

use super::native_software::NativeResolverV1;
use super::*;
use iroha_crypto::SignatureOf;
use iroha_data_model::musubi::{
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1,
    MusubiProviderBundleVerificationApprovalV1,
};
use sorafs_node::provider_attestation_native::{
    NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1, NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1,
    NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1, NativeMusubiProviderAttestationCustodyV1,
};
use std::path::Path;

const APPROVAL_LIMITS: DecodeLimits = DecodeLimits::new(
    4096,
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1,
    65_536,
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1 * 4,
    32,
);
// A source-check job may authenticate native blocks larger than its attestation payload. This
// local work ceiling never changes canonical admission; unavailable source capacity is retryable.
const APPROVAL_JOB_LIMITS: DecodeLimits = DecodeLimits::new(
    64 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
    512 * 1024 * 1024,
    128,
);

/// One native ordinary-open journal and the exact dedicated-key approval owner.
pub struct NativeAttestationV1 {
    custody: NativeMusubiProviderAttestationCustodyV1,
    signer: Arc<NativeApprovalV1>,
}
impl NativeAttestationV1 {
    pub(super) fn open(
        root: &Path,
        network_id: NetworkId,
        resolver: Arc<NativeResolverV1>,
        config: &SorafsProviderAttestationJournal,
    ) -> Result<Self> {
        let policy = provider_attestation_journal_policy(config)?;
        let policy_digest = policy.digest()?;
        let controller_digest =
            musubi_provider_attestation_controller_policy_digest_v1(&resolver.completion_signer)?;
        for (actual, handle, digest) in [
            (
                &config.clock,
                NATIVE_PROVIDER_ATTESTATION_CLOCK_HANDLE_V1,
                policy_digest,
            ),
            (
                &config.inventory,
                NATIVE_PROVIDER_ATTESTATION_INVENTORY_HANDLE_V1,
                policy_digest,
            ),
            (
                &config.approval_signer,
                NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1,
                controller_digest,
            ),
        ] {
            if actual.handle != handle || actual.revision != 1 || actual.policy_digest != digest {
                bail!("native provider-attestation qualification binding rejected");
            }
        }
        // Ordinary startup never initializes or repairs a missing original journal.
        let custody = NativeMusubiProviderAttestationCustodyV1::open(
            root,
            network_id,
            resolver.provider,
            policy,
        )
        .wrap_err("open original native provider-attestation custody")?;
        Ok(Self {
            custody,
            signer: Arc::new(NativeApprovalV1 {
                resolver,
                network_id,
                controller_digest,
                jobs: Arc::new(tokio::sync::Semaphore::new(1)),
            }),
        })
    }

    pub(crate) fn compose(
        &self,
        node: &NodeHandle,
        coordinator: ProviderIngestCompletedMusubiCaptureCoordinatorV1,
        state: Arc<State>,
        config: &SorafsProviderAttestationJournal,
    ) -> Result<(
        ProviderIngestCompletedMusubiAttestationDriverV1,
        Arc<dyn MusubiProviderAttestationInventoryReaderV1>,
    )> {
        let inventory: Arc<dyn MusubiProviderAttestationInventoryRuntimeV1> =
            self.custody.inventory();
        let driver = compose_inert_completed_musubi_attestation_driver_v1(
            node,
            coordinator,
            self.custody.runtime(),
            state,
            self.signer.network_id,
            config,
            self.signer.clone(),
            inventory,
        )?;
        // The publication factory receives the same storage owner, with no write/signing surface.
        let reader: Arc<dyn MusubiProviderAttestationInventoryReaderV1> = self.custody.inventory();
        Ok((driver, reader))
    }
}

#[derive(Clone)]
struct NativeApprovalV1 {
    resolver: Arc<NativeResolverV1>,
    network_id: NetworkId,
    controller_digest: [u8; 32],
    jobs: Arc<tokio::sync::Semaphore>,
}
impl NativeApprovalV1 {
    fn check_request(
        &self,
        payload: &MusubiProviderBundleVerificationPayloadV1,
        observed: sorafs_node::provider_ingest_outbox::ProviderIngestFinalizedCursorV1,
        completion_claim_digest: [u8; 32],
        signer_policy: ProviderIngestCompletionSignerPolicyV1,
    ) -> std::result::Result<(), MusubiProviderAttestationSignerErrorV1> {
        let rejected = MusubiProviderAttestationSignerErrorV1::Rejected;
        if payload.validate().is_err()
            || payload.binding.network_id != self.network_id
            || payload.binding.provider_id != self.resolver.provider
            || payload.binding.completed_by != self.resolver.completion_signer
            || payload.binding.completion_authority.completion_signer
                != self.resolver.completion_signer
            || payload.binding.completion_authority.signer_policy
                != self.resolver.config.completion_signer_policy
            || signer_policy != self.resolver.config.completion_signer_policy
            || completion_claim_digest == [0; 32]
        {
            return Err(rejected);
        }
        let state = self.resolver.state().map_err(map_signer_error)?;
        if state.network_id_ref() != &self.network_id {
            return Err(rejected);
        }
        let view = state.view();
        if !self
            .resolver
            .eligible(view.world(), &payload.binding.completion_authority)
        {
            return Err(rejected);
        }
        for (height, hash) in [
            (observed.height, observed.block_hash),
            (
                payload.binding.finalized_anchor.height,
                payload.binding.finalized_anchor.block_hash,
            ),
        ] {
            iroha_core::query::signer_finality::verify_signer_finality_v1(&view, height, hash)
                .map_err(|error| map_execution_attempt(&error))?;
        }
        let finalized_now = view
            .latest_block()
            .map_err(|error| map_execution_attempt(&error))?
            .ok_or(rejected)?
            .header()
            .creation_time()
            .as_secs();
        let now = finalized_now.max(super::native_software::native_now_unix_ms()? / 1000);
        if iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
            &view,
            self.resolver.provider,
            now,
        )
        // This existing query facade intentionally hides source diagnostics. Refusal does not
        // establish that the provider was rejected; only an authenticated None does.
        .map_err(|_| MusubiProviderAttestationSignerErrorV1::Unavailable)?
        .is_none()
        {
            return Err(rejected);
        }
        Ok(())
    }
}
fn map_execution_attempt<E>(
    error: &iroha_core::execution_attempt::ExecutionAttemptError<E>,
) -> MusubiProviderAttestationSignerErrorV1 {
    match error {
        iroha_core::execution_attempt::ExecutionAttemptError::Deferred(_) => {
            MusubiProviderAttestationSignerErrorV1::Unavailable
        }
        iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => {
            MusubiProviderAttestationSignerErrorV1::Rejected
        }
    }
}
fn map_signer_error(
    error: ProviderIngestCompletionSignerErrorV1,
) -> MusubiProviderAttestationSignerErrorV1 {
    match error {
        ProviderIngestCompletionSignerErrorV1::Unavailable => {
            MusubiProviderAttestationSignerErrorV1::Unavailable
        }
        ProviderIngestCompletionSignerErrorV1::Rejected => {
            MusubiProviderAttestationSignerErrorV1::Rejected
        }
    }
}
impl MusubiProviderAttestationSignerV1 for NativeApprovalV1 {
    fn runtime_handle(&self) -> &str {
        NATIVE_PROVIDER_ATTESTATION_APPROVAL_HANDLE_V1
    }
    fn authority(&self) -> &AccountId {
        &self.resolver.completion_signer
    }
    fn qualification(
        &self,
    ) -> std::result::Result<
        MusubiProviderAttestationSignerQualificationV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        Ok(MusubiProviderAttestationSignerQualificationV1 {
            version: 1,
            adapter_revision: 1,
            adapter_policy_digest: self.controller_digest,
            signer_policy: self.resolver.config.completion_signer_policy,
            authority: self.resolver.completion_signer.clone(),
            controller_policy_digest: self.controller_digest,
        })
    }
    fn signer_policy(&self) -> ProviderIngestCompletionSignerPolicyV1 {
        self.resolver.config.completion_signer_policy
    }
    fn current_eligibility(
        &self,
    ) -> std::result::Result<
        ProviderIngestCompletionSignerPolicyV1,
        MusubiProviderAttestationSignerErrorV1,
    > {
        let view = self.resolver.state().map_err(map_signer_error)?.view();
        let authority = view
            .world()
            .provider_ingest_completion_authorities()
            .get(&self.resolver.provider)
            .ok_or(MusubiProviderAttestationSignerErrorV1::Rejected)?;
        if !self.resolver.eligible(view.world(), authority) {
            return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
        }
        Ok(authority.signer_policy)
    }
    fn approve<'a>(
        &'a self,
        request: &'a ProviderIngestMusubiAttestationApprovalRequestV1,
    ) -> MusubiProviderAttestationApprovalFutureV1<'a> {
        Box::pin(async move {
            fn unavailable<T>(_: T) -> MusubiProviderAttestationSignerErrorV1 {
                MusubiProviderAttestationSignerErrorV1::Unavailable
            }
            // Capture only this opaque request's bounded canonical payload and immutable scalar
            // evidence. No thread-local guard crosses an await or a worker-thread boundary.
            let bytes = norito::with_decode_limits_scope(APPROVAL_LIMITS, || {
                let length = norito::canonical_frame_len(request.payload()).map_err(unavailable)?;
                if length > MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1 {
                    return Err(MusubiProviderAttestationSignerErrorV1::Rejected);
                }
                norito::core::reserve_decode_allocation(length).map_err(unavailable)?;
                norito::encode_canonical(request.payload()).map_err(unavailable)
            })?;
            // Charge the worker's complete bounded allowance to any original caller before spawn.
            norito::core::reserve_decode_allocation(
                APPROVAL_JOB_LIMITS.max_total_allocated_bytes(),
            )
            .map_err(unavailable)?;
            let permit = self.jobs.clone().try_acquire_owned().map_err(unavailable)?;
            tokio::runtime::Handle::try_current().map_err(unavailable)?;
            let signer = self.clone();
            let observed = request.observed_finalized_cursor();
            let completion_claim_digest = request.completion_claim_digest();
            let signer_policy = request.signer_policy();
            let result = crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    // Caller cancellation cannot release this slot before physical completion.
                    let _permit = permit;
                    norito::with_decode_limits_scope(APPROVAL_JOB_LIMITS, || {
                        let payload: MusubiProviderBundleVerificationPayloadV1 =
                            norito::decode_canonical_with_limits(&bytes, APPROVAL_LIMITS)
                                .map_err(unavailable)?;
                        signer.check_request(
                            &payload,
                            observed,
                            completion_claim_digest,
                            signer_policy,
                        )?;
                        let signature = SignatureOf::try_from_hash(
                            signer.resolver.key.private_key(),
                            payload.signing_hash(),
                        )
                        .map_err(unavailable)?;
                        norito::core::reserve_decode_allocation(std::mem::size_of::<
                            MusubiProviderBundleVerificationApprovalV1,
                        >())
                        .map_err(unavailable)?;
                        let mut approvals = Vec::new();
                        approvals.try_reserve_exact(1).map_err(unavailable)?;
                        approvals.push(MusubiProviderBundleVerificationApprovalV1 {
                            public_key: signer.resolver.key.public_key().clone(),
                            signature,
                        });
                        let attestation =
                            MusubiProviderBundleVerificationAttestationV1 { payload, approvals };
                        signer.check_request(
                            &attestation.payload,
                            observed,
                            completion_claim_digest,
                            signer_policy,
                        )?;
                        Ok(attestation)
                    })
                }),
            )
            .await
            .map_err(unavailable)??;
            result
                .verify(&request.payload().binding)
                .map_err(|_| MusubiProviderAttestationSignerErrorV1::Rejected)?;
            Ok(result)
        })
    }
}

/// Supervise the existing bounded driver. Cancellation leaves exact retained journal recovery.
pub fn start(
    mut driver: ProviderIngestCompletedMusubiAttestationDriverV1,
    scan_interval_ms: u64,
    shutdown_signal: ShutdownSignal,
) -> Result<Child> {
    if scan_interval_ms == 0 {
        bail!("provider-attestation scan interval must be finite and positive");
    }
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(scan_interval_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown_signal.receive() => break,
                _ = interval.tick() => {
                    let result = tokio::select! {
                        biased;
                        () = shutdown_signal.receive() => break,
                        result = driver.drive_one_bounded_page() => result,
                    };
                    if let Err(error) = result {
                        assert!(error.is_retryable(), "native provider-attestation driver stopped: {error}");
                        iroha_logger::warn!(%error, "native provider-attestation step deferred");
                    }
                }
            }
        }
    });
    Ok(Child::new(task, OnShutdown::Wait(SHUTDOWN_WAIT_FLOOR)))
}

#[cfg(test)]
#[path = "native_attestation/tests.rs"]
mod tests;
