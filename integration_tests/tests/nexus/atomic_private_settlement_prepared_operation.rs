//! Genuine N3 orchestration through the public prepared SDK operation.
//! Journal-boundary interruptions are not process crashes; peer restarts remain separate.

use super::*;
use iroha::{
    client::{
        PrivateSettlementOperation, PrivateSettlementRequest, PrivateSettlementResult,
        PrivateSettlementRunOptions,
    },
    workflow::{
        Digest32, FileWorkflowStorage, WorkflowId, WorkflowJournalV1, WorkflowRunnerLease,
        WorkflowStorage, WorkflowStorageDurability, WorkflowStorageError, WorkflowStorageErrorKind,
    },
};
use iroha_data_model::{
    nexus::{
        PrivateSettlementPhaseCertificateV1, PrivateSettlementPrepareBarrierV1,
        PrivateSettlementSidecarAvailabilityV1,
    },
    parameter::system::ConsensusMode,
    sumeragi_finality::{
        SignedGenesisPinsV1, SumeragiFinalityVerifier, authenticate_signed_genesis_v1,
    },
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Real file custody with one deliberate acknowledgement loss after durable CAS.
struct CheckpointStorage {
    inner: FileWorkflowStorage,
    stop_after: Arc<Mutex<Option<usize>>>,
    interrupted: Arc<AtomicBool>,
}
impl WorkflowStorage for CheckpointStorage {
    fn durability(&self) -> WorkflowStorageDurability {
        self.inner.durability()
    }
    fn load(&self, id: &WorkflowId) -> std::result::Result<Option<Vec<u8>>, WorkflowStorageError> {
        self.inner.load(id)
    }
    fn acquire_runner(
        &self,
        id: &WorkflowId,
    ) -> std::result::Result<Box<dyn WorkflowRunnerLease>, WorkflowStorageError> {
        self.inner.acquire_runner(id)
    }
    fn compare_and_store(
        &self,
        id: &WorkflowId,
        expected: Option<&Digest32>,
        record: &[u8],
    ) -> std::result::Result<(), WorkflowStorageError> {
        let mut stop = self.stop_after.lock().map_err(|_| {
            WorkflowStorageError::new(
                WorkflowStorageErrorKind::Unavailable,
                "checkpoint controller unavailable",
            )
        })?;
        let reached = match *stop {
            Some(step) => WorkflowJournalV1::decode_record(record)
                .map_err(|_| {
                    WorkflowStorageError::new(
                        WorkflowStorageErrorKind::Unavailable,
                        "checkpoint candidate is invalid",
                    )
                })?
                .steps
                .get(step)
                .is_some_and(|step| step.is_done()),
            None => false,
        };
        self.inner.compare_and_store(id, expected, record)?;
        if reached {
            *stop = None;
            self.interrupted.store(true, Ordering::SeqCst);
            return Err(WorkflowStorageError::new(
                WorkflowStorageErrorKind::WriteUncertain,
                "injected SDK journal acknowledgement loss after durable phase CAS",
            ));
        }
        Ok(())
    }
}

pub(super) struct PreparedSdkFlow {
    account: iroha::client::AccountClient,
    request: PrivateSettlementRequest,
    storage: Arc<CheckpointStorage>,
    journal_path: PathBuf,
    original_genesis: Vec<u8>,
    pins: SignedGenesisPinsV1,
    id: WorkflowId,
}
impl PreparedSdkFlow {
    pub(super) fn new(
        network: &Network,
        sponsor: &Client,
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
        endpoints: Vec<Vec<Url>>,
        journal_path: &Path,
    ) -> Result<Self> {
        let genesis = network.genesis().0;
        let original_genesis = genesis.encode_wire()?;
        let mut roster = network
            .validators()
            .iter()
            .map(|peer| peer.id())
            .collect::<Vec<_>>();
        roster.sort();
        let pins = SignedGenesisPinsV1 {
            chain_id: network.chain_id().to_string(),
            network_id: network.network_id(),
            genesis_hash: genesis.hash(),
            signed_genesis_sha256: Sha256::digest(&original_genesis).into(),
            genesis_public_key: iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR
                .public_key()
                .clone(),
            roster,
            mode: ConsensusMode::Npos,
        };
        let account = sponsor.client().account_client()?;
        let request = PrivateSettlementRequest::new(
            materials.to_vec(),
            endpoints,
            PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1 as u64,
        )?;
        let storage = Arc::new(CheckpointStorage {
            inner: FileWorkflowStorage::open_or_create(journal_path)?,
            stop_after: Arc::new(Mutex::new(None)),
            interrupted: Arc::new(AtomicBool::new(false)),
        });
        let verifier = Self::verifier(&original_genesis, &pins)?;
        let id = account
            .private_settlement(request.clone(), storage.clone(), verifier)?
            .id();
        Ok(Self {
            account,
            request,
            storage,
            journal_path: journal_path.to_owned(),
            original_genesis,
            pins,
            id,
        })
    }
    fn verifier(wire: &[u8], pins: &SignedGenesisPinsV1) -> Result<SumeragiFinalityVerifier> {
        let authenticated = authenticate_signed_genesis_v1(wire, pins)?;
        Ok(SumeragiFinalityVerifier::new(
            authenticated.block(),
            &pins.chain_id,
            authenticated.validators().to_vec(),
        )?)
    }
    fn open(&self) -> Result<PrivateSettlementOperation> {
        Ok(self.account.private_settlement(
            self.request.clone(),
            Arc::new(CheckpointStorage {
                inner: FileWorkflowStorage::open_or_create(&self.journal_path)?,
                stop_after: self.storage.stop_after.clone(),
                interrupted: self.storage.interrupted.clone(),
            }),
            Self::verifier(&self.original_genesis, &self.pins)?,
        )?)
    }
    fn options() -> PrivateSettlementRunOptions {
        PrivateSettlementRunOptions {
            workflow: iroha::workflow::WorkflowRunOptions {
                observation_timeout: FINALITY_TIMEOUT,
                poll_interval: POLL_INTERVAL,
                retransmit_identical_bytes: false,
                retry_rejected_step: false,
            },
            ..Default::default()
        }
    }
    pub(super) fn journal(&self) -> Result<WorkflowJournalV1> {
        let bytes = self
            .storage
            .load(&self.id)?
            .ok_or_else(|| eyre!("original SDK journal absent"))?;
        Ok(WorkflowJournalV1::decode_record(&bytes)?)
    }
    pub(super) fn interrupt_after(
        &self,
        runtime: &tokio::runtime::Runtime,
        step: usize,
    ) -> Result<()> {
        *self.storage.stop_after.lock().unwrap() = Some(step);
        self.storage.interrupted.store(false, Ordering::SeqCst);
        let operation = self.open()?;
        let outcome = runtime.block_on(operation.run(&Self::options()));
        ensure!(
            self.storage.interrupted.load(Ordering::SeqCst),
            "SDK did not reach selected durable checkpoint {step}: {outcome:?}"
        );
        ensure!(
            outcome.is_err(),
            "injected journal uncertainty must return to the caller"
        );
        ensure!(
            self.journal()?.steps[step].is_done(),
            "acknowledgement loss cannot erase durable phase completion"
        );
        Ok(())
    }
    pub(super) fn await_independent_audit(&self, runtime: &tokio::runtime::Runtime) -> Result<()> {
        let operation = self.open()?;
        let outcome = runtime.block_on(operation.run(&Self::options()));
        ensure!(
            matches!(outcome, Err(iroha::client::PrivateSettlementError::Workflow(ref error))
                if error.step_index == Some(1)
                    && error.code == iroha::workflow::WorkflowErrorCode::LocalResourceUnavailable),
            "unaudited operation must stop specifically at Prepare: {outcome:?}"
        );
        let journal = self.journal()?;
        ensure!(
            journal.steps[0].is_done()
                && !journal.steps[1].is_done()
                && journal.steps[2]
                    .transaction
                    .as_ref()
                    .is_none_or(|tx| tx.attempts.is_empty()),
            "missing audit cannot authorize Register"
        );
        // The caller next obtains a roster-pinned, BLS-authenticated quorum auditor
        // view of the exact Collecting material. This generic, deliberately redacted
        // phase error alone does not establish the missing-audit cause. Only approvals
        // change before this exact request/journal resumes to a verified Prepare QC.
        Ok(())
    }
    pub(super) fn round<T>(&self, step: usize) -> Result<T>
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        let journal = self.journal()?;
        let bytes = journal.steps[step]
            .round
            .as_ref()
            .and_then(|round| round.transcript.as_deref())
            .ok_or_else(|| eyre!("SDK phase transcript absent"))?;
        Ok(norito::decode_canonical(bytes)?)
    }
    pub(super) fn availability_checkpoint(&self) -> Result<Vec<u8>> {
        self.journal()?.steps[0]
            .round
            .as_ref()
            .and_then(|round| round.transcript.clone())
            .ok_or_else(|| eyre!("original availability checkpoint absent"))
    }
    pub(super) fn availability_manifest(
        &self,
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
    ) -> Result<AtomicPrivateSettlementV1> {
        let certificates: Vec<PrivateSettlementSidecarAvailabilityV1> = self.round(0)?;
        ensure!(certificates.len() == materials.len());
        let mut manifest = materials[0].manifest.clone();
        for (ordinal, certificate) in certificates.iter().enumerate() {
            ensure!(certificate.body == materials[ordinal].availability_body);
            manifest.legs[ordinal].availability_certificate_digest = certificate.digest()?;
        }
        manifest.validate()?;
        Ok(manifest)
    }
    pub(super) fn barrier(
        &self,
        manifest: AtomicPrivateSettlementV1,
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
    ) -> Result<PrivateSettlementPrepareBarrierV1> {
        SdkClient::build_private_settlement_prepare_barrier_v1(
            manifest,
            &materials
                .iter()
                .map(|m| m.committee_authority.clone())
                .collect::<Vec<_>>(),
            materials.iter().map(|m| m.delta.clone()).collect(),
            self.round::<Vec<PrivateSettlementPhaseCertificateV1>>(1)?,
        )
    }
    pub(super) fn finish(
        &self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<PrivateSettlementResult> {
        Ok(runtime.block_on(self.open()?.run(&Self::options()))?)
    }
    pub(super) fn recover(
        &self,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<iroha::client::VerifiedPrivateSettlementReceipt> {
        runtime
            .block_on(self.open()?.recover(&Self::options()))?
            .receipt
            .ok_or_else(|| eyre!("SDK readonly recovery omitted original verified receipt"))
    }
}

/// Measure only representations of already produced opaque artifacts; never persist their bytes.
pub(super) fn artifact_sizes(
    materials: &[PrivateSettlementProvisionalLegMaterialV1],
    manifest: &AtomicPrivateSettlementV1,
    certificates: &[PrivateSettlementSidecarAvailabilityV1],
) -> Result<norito::json::Value> {
    use iroha::client::PrivateSettlementAvailabilityShareRequestV1;
    use iroha_data_model::nexus::PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1;
    let http_bound = iroha_config::parameters::defaults::torii::MAX_CONTENT_LEN.0;
    let mut rows = Vec::with_capacity(materials.len());
    for (ordinal, (material, certificate)) in materials.iter().zip(certificates).enumerate() {
        ensure!(
            material.proof.len() == 2_527_280,
            "genuine APZ1 finite profile must retain its exact maximum valid proof geometry"
        );
        ensure!(material.proof.len() <= PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1);
        let material_json = norito::json::to_value(material)?;
        let proof_base64_bytes = material_json
            .get("proof")
            .and_then(|proof| proof.as_str())
            .ok_or_else(|| eyre!("proof representation must be the canonical base64 field"))?
            .len();
        ensure!(proof_base64_bytes == 3_369_708);
        let availability = PrivateSettlementAvailabilityShareRequestV1 {
            material: material.clone(),
        };
        let upload = PrivateSettlementLegUploadRequestV1 {
            manifest: manifest.clone(),
            audit_policy: material.audit_policy.clone(),
            committee_authority: material.committee_authority.clone(),
            payload: material.payload_with_certificate(certificate.clone()),
        };
        let availability_json_bytes = norito::json::to_vec(&availability)?.len();
        let upload_json_bytes = norito::json::to_vec(&upload)?.len();
        ensure!(
            (availability_json_bytes as u64) <= http_bound
                && (upload_json_bytes as u64) <= http_bound,
            "genuine proof requests exceed the configured default HTTP bound"
        );
        rows.push(norito::json!({
            "leg_ordinal": ordinal,
            "proof_bytes": (material.proof.len()),
            "proof_base64_bytes": proof_base64_bytes,
            "material_norito_bytes": (norito::encode_canonical(material)?.len()),
            "availability_request_json_bytes": availability_json_bytes,
            "upload_request_json_bytes": upload_json_bytes,
            "upload_request_norito_bytes": (norito::encode_canonical(&upload)?.len()),
            "capsule_norito_bytes": (norito::encode_canonical(&material.audit_capsule)?.len()),
            "http_body_bound_bytes": http_bound,
            "proof_bound_bytes": PRIVATE_SETTLEMENT_MAX_PROOF_BYTES_V1,
        }));
    }
    Ok(norito::json!({ "legs": rows }))
}

/// Original receipt evidence supplies the exact signed carrier; no replacement identity is built.
pub(super) fn original_finalization(
    receipt: &iroha::client::VerifiedPrivateSettlementReceipt,
) -> Result<PrivateSettlementBundleSubmitRequestV1> {
    let TransactionEntrypoint::External(transaction) = receipt.evidence().entrypoint() else {
        return Err(eyre!("verified direct Finalize carrier was not external"));
    };
    ensure!(transaction.hash() == receipt.transaction_hash());
    ensure!(transaction.encode_wire_v1()?.len() <= PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1);
    ensure!(
        receipt.nexus_fee_receipt().is_some(),
        "genuine funded Finalize needs an authenticated fee receipt"
    );
    Ok(PrivateSettlementBundleSubmitRequestV1 {
        transaction: transaction.clone(),
    })
}

/// Qualify the final-tip traffic condition independently from receipt authenticity.
/// Every observed node must remain exactly at the original Finalize height.
pub(super) fn require_final_tip(
    observations: impl IntoIterator<Item = (usize, u64)>,
    finalized_height: u64,
) -> Result<()> {
    ensure!(finalized_height > 1, "Finalize must follow signed genesis");
    let mut seen = false;
    for (peer_index, height) in observations {
        seen = true;
        ensure!(
            height == finalized_height,
            "validator #{peer_index} tip {height} differs from original Finalize height {finalized_height}"
        );
    }
    ensure!(seen, "final-tip observations omitted every validator");
    Ok(())
}

#[test]
fn final_tip_control_rejects_later_traffic_and_incomplete_recovery() {
    assert!(require_final_tip([(0, 9), (1, 9)], 9).is_ok());
    assert!(require_final_tip([(0, 9), (1, 10)], 9).is_err());
    assert!(require_final_tip([(0, 9), (1, 8)], 9).is_err());
    assert!(require_final_tip([], 9).is_err());
    assert!(require_final_tip([(0, 1)], 1).is_err());
}
