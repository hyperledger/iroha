//! Shared N3 assertions with a prepared baseline and genuine cold SDK continuations.
//! The parent retains original caller inputs and public evidence, never cold proof/witness owners.
//! Context transport uses the fixture's explicit all-ledger reader authority; complete World
//! hash preimages are privileged disclosure, not a G3 selective/complete-State privacy claim.
use super::*;
use iroha::client::{PrivateSettlementRunOptions, VerifiedPrivateSettlementReceipt};
use iroha::workflow::{FileWorkflowStorage, WorkflowId, WorkflowJournalV1, WorkflowStorage};
use iroha_data_model::nexus::{
    PrivateSettlementBundleLegMaterialV1, PrivateSettlementPhaseCertificateV1,
    PrivateSettlementPrepareBarrierV1, PrivateSettlementProofIntentV1,
    PrivateSettlementSidecarAvailabilityV1, private_settlement_reimbursement_terms_commitment_v1,
};
use iroha_fs::PrivateDirectory;
use std::{cell::RefCell, path::PathBuf};

#[path = "atomic_private_settlement_onecall/child.rs"]
mod child;
#[path = "atomic_private_settlement_onecall/wallet.rs"]
mod wallet;

/// A single finite functional-case budget, including proof work and all cold/validator restarts.
/// Individual observation calls retain the existing five-minute bound; continuations never
/// renew this original hour. This is a diagnostic limit, not a production performance claim.
const COLD_CASE_LIMIT: Duration = Duration::from_secs(60 * 60);

pub(super) fn intent(
    network: iroha_data_model::NetworkId,
    height: u64,
    expiry: u64,
    governed: &[GovernedLeg],
) -> Result<PrivateSettlementProofIntentV1> {
    let fee = bounded_nexus_fee();
    let digest = PrivateSettlementProofIntentV1::fee_intent_digest(&fee)?;
    let first = governed
        .first()
        .ok_or_else(|| eyre!("missing reimbursement leg"))?;
    let reimbursement = private_settlement_reimbursement_terms_commitment_v1(
        network,
        0,
        first.route,
        &ALICE_ID,
        &first.governance.body.asset_definition_id,
        5,
        digest,
        expiry,
        private_settlement_reimbursement_terms_salt_for_terms(
            network, height, expiry, digest, first,
        ),
    )?;
    Ok(PrivateSettlementProofIntentV1::new(
        network,
        height,
        expiry,
        ALICE_ID.clone(),
        fee,
        reimbursement,
        0,
        governed
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| PrivateSettlementBundleLegMaterialV1 {
                ordinal: ordinal as u8,
                route: leg.route,
                pool_id: leg.governance.body.pool_id,
                asset_binding_commitment: leg.governance.body.asset_binding_commitment,
                audit_policy_digest: leg.policy.policy_digest,
            })
            .collect(),
    )?)
}

/// Public and encrypted-material bindings only, measured inside the original producer process.
#[derive(Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "integration_tests::private_onecall::PreparedPublic")]
pub(super) struct PreparedPublic {
    manifest: AtomicPrivateSettlementV1,
    sidecar_digests: Vec<Hash>,
    deltas: Vec<PrivateSettlementDeltaV1>,
    proof_lengths: Vec<u64>,
    size_json: Vec<u8>,
}
fn sidecar_digest(
    policy: &PrivateSettlementAuditPolicyV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    statement: &PrivateSettlementProofStatementV1,
    delta: &PrivateSettlementDeltaV1,
    capsule: &iroha_data_model::nexus::PrivateSettlementAuditCapsuleV1,
) -> Result<Hash> {
    Ok(Hash::new(norito::encode_canonical(&(
        policy.clone(),
        authority.clone(),
        statement.clone(),
        delta.clone(),
        capsule.clone(),
    ))?))
}
impl PreparedPublic {
    fn from_materials(
        materials: &[PrivateSettlementProvisionalLegMaterialV1],
        certificates: &[PrivateSettlementSidecarAvailabilityV1],
    ) -> Result<Self> {
        ensure!(materials.len() == PARTICIPANT_COUNT && certificates.len() == materials.len());
        let mut manifest = materials[0].manifest.clone();
        let mut sidecar_digests = Vec::new();
        for (index, (material, certificate)) in materials.iter().zip(certificates).enumerate() {
            ensure!(certificate.body == material.availability_body);
            manifest.legs[index].availability_certificate_digest = certificate.digest()?;
            sidecar_digests.push(sidecar_digest(
                &material.audit_policy,
                &material.committee_authority,
                &material.statement,
                &material.delta,
                &material.audit_capsule,
            )?);
        }
        manifest.validate()?;
        Ok(Self {
            size_json: norito::json::to_vec(&prepared_operation::artifact_sizes(
                materials,
                &manifest,
                certificates,
            )?)?,
            manifest,
            sidecar_digests,
            deltas: materials
                .iter()
                .map(|material| material.delta.clone())
                .collect(),
            proof_lengths: materials
                .iter()
                .map(|material| material.proof.len() as u64)
                .collect(),
        })
    }
    fn validate_intent(&self, intent: &PrivateSettlementProofIntentV1) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            self.manifest.proof_intent() == *intent,
            "prepared report replaced original payment terms"
        );
        ensure!(
            self.sidecar_digests.len() == PARTICIPANT_COUNT
                && self.deltas.len() == PARTICIPANT_COUNT
                && self.proof_lengths == vec![2_527_280; PARTICIPANT_COUNT],
            "incomplete genuine material report"
        );
        Ok(())
    }
}

pub(super) enum N3SdkFlow {
    Prepared {
        flow: prepared_operation::PreparedSdkFlow,
        materials: Vec<PrivateSettlementProvisionalLegMaterialV1>,
    },
    Cold(ColdFlow),
}
impl N3SdkFlow {
    pub(super) fn new(
        cold: bool,
        network: &Network,
        sponsor: &Client,
        governed: Vec<GovernedLeg>,
        committees: &[CommitteeEndpoints],
        intent: &PrivateSettlementProofIntentV1,
        policy_activation: u64,
    ) -> Result<Self> {
        let directory = tempfile::tempdir_in(network.env_dir())?.keep();
        PrivateDirectory::open_or_create(&directory)?;
        let endpoints = committees
            .iter()
            .map(|committee| committee.endpoints.clone())
            .collect::<Vec<_>>();
        if cold {
            return Ok(Self::Cold(ColdFlow::new(
                network,
                sponsor,
                intent.clone(),
                policy_activation,
                endpoints,
                directory,
            )?));
        }
        let manifest = proof_manifest(
            network.network_id(),
            intent.authority_context_height,
            intent.expiry_height,
            &governed,
        )?;
        ensure!(
            manifest.proof_intent() == *intent,
            "prepared and cold public intent projections differ"
        );
        let jobs: [(GovernedLeg, Hash); 3] = governed
            .into_iter()
            .zip(committees)
            .map(|(leg, committee)| Ok((leg, committee.authority.digest()?)))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| eyre!("exactly three proof jobs required"))?;
        let prepared = collect_three_smoke_phase_jobs_v1(
            SmokeLegJobPhaseV1::Proof,
            jobs,
            |ordinal, (leg, authority)| {
                let timing = SmokeDiagnosticSpanV1::start(
                    SmokeDiagnosticPhaseV1::ClientLegConstruction,
                    Some(ordinal),
                );
                let prepared = prepare_leg(ordinal, leg, &manifest, authority)?;
                timing.complete();
                Ok(prepared)
            },
        )?;
        let materials = provisional_materials(manifest, &prepared, committees)?;
        let flow = prepared_operation::PreparedSdkFlow::new(
            network,
            sponsor,
            &materials,
            endpoints,
            &directory.join("prepared-settlement"),
        )?;
        Ok(Self::Prepared { flow, materials })
    }
    pub(super) fn interrupt_after(
        &self,
        runtime: &tokio::runtime::Runtime,
        step: usize,
    ) -> Result<()> {
        match self {
            Self::Prepared { flow, .. } => flow.interrupt_after(runtime, step),
            Self::Cold(flow) => {
                flow.invoke(runtime, child::Mode::Checkpoint(u8::try_from(step)?))?;
                Ok(())
            }
        }
    }
    pub(super) fn await_independent_audit(&self, runtime: &tokio::runtime::Runtime) -> Result<()> {
        match self {
            Self::Prepared { flow, .. } => flow.await_independent_audit(runtime),
            Self::Cold(flow) => {
                flow.invoke(runtime, child::Mode::Unaudited)?;
                let journal = flow.journal()?;
                ensure!(
                    journal.steps[0].is_done()
                        && !journal.steps[1].is_done()
                        && journal.steps[2]
                            .transaction
                            .as_ref()
                            .is_none_or(|tx| tx.attempts.is_empty()),
                    "missing audit cannot authorize Register"
                );
                Ok(())
            }
        }
    }
    pub(super) fn round<T>(&self, step: usize) -> Result<T>
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        match self {
            Self::Prepared { flow, .. } => flow.round(step),
            Self::Cold(flow) => {
                let journal = flow.journal()?;
                let bytes = journal
                    .steps
                    .get(step)
                    .and_then(|row| row.round.as_ref())
                    .and_then(|round| round.transcript.as_deref())
                    .ok_or_else(|| eyre!("original phase transcript absent"))?;
                Ok(norito::decode_canonical(bytes)?)
            }
        }
    }
    pub(super) fn availability_checkpoint(&self) -> Result<Vec<u8>> {
        match self {
            Self::Prepared { flow, .. } => flow.availability_checkpoint(),
            Self::Cold(flow) => flow.journal()?.steps[0]
                .round
                .as_ref()
                .and_then(|round| round.transcript.clone())
                .ok_or_else(|| eyre!("original availability checkpoint absent")),
        }
    }
    fn public(&self) -> Result<PreparedPublic> {
        match self {
            Self::Prepared { materials, .. } => PreparedPublic::from_materials(
                materials,
                &self.round::<Vec<PrivateSettlementSidecarAvailabilityV1>>(0)?,
            ),
            Self::Cold(flow) => flow
                .public
                .borrow()
                .clone()
                .ok_or_else(|| eyre!("original prepared report absent")),
        }
    }
    pub(super) fn availability_manifest(&self) -> Result<AtomicPrivateSettlementV1> {
        Ok(self.public()?.manifest)
    }
    pub(super) fn artifact_sizes(&self) -> Result<norito::json::Value> {
        Ok(norito::json::from_slice(&self.public()?.size_json)?)
    }
    pub(super) fn require_original_sidecar(
        &self,
        ordinal: usize,
        policy: &PrivateSettlementAuditPolicyV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        statement: &PrivateSettlementProofStatementV1,
        delta: &PrivateSettlementDeltaV1,
        capsule: &iroha_data_model::nexus::PrivateSettlementAuditCapsuleV1,
    ) -> Result<()> {
        let original = self.public()?;
        ensure!(
            original.sidecar_digests.get(ordinal)
                == Some(&sidecar_digest(
                    policy, authority, statement, delta, capsule
                )?),
            "authenticated auditor view replaced original prepared material"
        );
        ensure!(original.deltas.get(ordinal) == Some(delta));
        Ok(())
    }
    pub(super) fn barrier(
        &self,
        manifest: AtomicPrivateSettlementV1,
        committees: &[CommitteeEndpoints],
    ) -> Result<PrivateSettlementPrepareBarrierV1> {
        SdkClient::build_private_settlement_prepare_barrier_v1(
            manifest,
            &committees
                .iter()
                .map(|committee| committee.authority.clone())
                .collect::<Vec<_>>(),
            self.public()?.deltas,
            self.round::<Vec<PrivateSettlementPhaseCertificateV1>>(1)?,
        )
    }
    pub(super) fn finish(
        &self,
        runtime: &tokio::runtime::Runtime,
        sponsor: &Client,
        barrier: &PrivateSettlementPrepareBarrierV1,
    ) -> Result<VerifiedPrivateSettlementReceipt> {
        match self {
            Self::Prepared { flow, .. } => Ok(flow.finish(runtime)?.receipt),
            Self::Cold(flow) => flow.verified(runtime, sponsor, barrier, child::Mode::Finish),
        }
    }
    pub(super) fn recover(
        &self,
        runtime: &tokio::runtime::Runtime,
        sponsor: &Client,
        barrier: &PrivateSettlementPrepareBarrierV1,
    ) -> Result<VerifiedPrivateSettlementReceipt> {
        match self {
            Self::Prepared { flow, .. } => flow.recover(runtime),
            Self::Cold(flow) => flow.verified(runtime, sponsor, barrier, child::Mode::ReadOnly),
        }
    }
    pub(super) fn require_original_deadline(&self) -> Result<()> {
        if let Self::Cold(flow) = self {
            require_cold_deadline(flow.deadline)?;
        }
        Ok(())
    }
    pub(super) fn write_evidence(
        &self,
        root: &std::path::Path,
    ) -> Result<Vec<SmokeEvidenceFileV1>> {
        self.require_original_deadline()?;
        let Self::Cold(flow) = self else {
            return Err(eyre!("cold custody evidence requires cold operation"));
        };
        let children = flow.children.borrow();
        ensure!(
            children.len() == 28,
            "cold campaign requires twelve boundary children and sixteen post-restart recoveries"
        );
        let mut files = Vec::new();
        let mut records = Vec::new();
        for (index, (record, report, stdout, stderr)) in children.iter().enumerate() {
            files.push(write_smoke_evidence_bytes(
                root,
                &format!("sdk-child-{index:02}.norito"),
                report,
                ".norito",
                child::CHILD_REPORT_MAX,
            )?);
            files.push(write_smoke_evidence_bytes(
                root,
                &format!("sdk-child-{index:02}-stdout.log"),
                stdout,
                ".log",
                child::CHILD_LOG_MAX,
            )?);
            files.push(write_smoke_evidence_bytes(
                root,
                &format!("sdk-child-{index:02}-stderr.log"),
                stderr,
                ".log",
                child::CHILD_LOG_MAX,
            )?);
            records.push(record.clone());
        }
        let originals = flow.original_artifacts.borrow();
        let originals = originals
            .as_ref()
            .ok_or_else(|| eyre!("original encrypted artifact inventory absent"))?
            .iter()
            .map(|(name, hash)| norito::json!({"name": name, "hash": (hash.to_string())}))
            .collect::<Vec<_>>();
        let evidence = norito::json!({"version": 1, "operation": "one_call_cold_process",
            "child_test": (child::test_filter()?), "children": records, "encrypted_originals": originals,
            "original_case_limit_ms": (COLD_CASE_LIMIT.as_millis() as u64),
            "original_deadline_unix_ms": (flow.input.deadline_unix_ms),
            "child_report_bound_bytes": (child::CHILD_REPORT_MAX), "child_log_bound_bytes": (child::CHILD_LOG_MAX),
            "read_only_before_every_continuation": true});
        files.push(write_smoke_evidence(
            root,
            "sdk-process-custody.json",
            &evidence,
        )?);
        self.require_original_deadline()?;
        Ok(files)
    }
}

pub(super) struct ColdFlow {
    input: child::ChildInput,
    deadline: Instant,
    sequence: RefCell<u64>,
    pids: RefCell<Vec<u32>>,
    children: RefCell<Vec<(norito::json::Value, Vec<u8>, Vec<u8>, Vec<u8>)>>,
    public: RefCell<Option<PreparedPublic>>,
    original_artifacts: RefCell<Option<Vec<(String, Hash)>>>,
    preparation_id: RefCell<Option<[u8; 32]>>,
    settlement_id: RefCell<Option<[u8; 32]>>,
}
impl ColdFlow {
    fn new(
        network: &Network,
        sponsor: &Client,
        intent: PrivateSettlementProofIntentV1,
        policy_activation: u64,
        endpoints: Vec<Vec<Url>>,
        directory: PathBuf,
    ) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(COLD_CASE_LIMIT)
            .ok_or_else(|| eyre!("cold case clock overflow"))?;
        let deadline_unix_ms = child::unix_ms()?
            .checked_add(u64::try_from(COLD_CASE_LIMIT.as_millis())?)
            .ok_or_else(|| eyre!("cold deadline overflow"))?;
        let original_genesis = network.genesis().0.encode_wire()?;
        // Capture these from the original Network owner before serializing untrusted child transport.
        let pins = child::Pins::from_network(network, &original_genesis)?;
        let key = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        ensure!(key.iter().any(|b| *b != 0));
        let custody = PrivateDirectory::open_or_create(&directory)?;
        for name in ["journals", "wallet-reservations", "encrypted-artifacts"] {
            custody.create_child(name)?;
        }
        let input = child::ChildInput {
            intent,
            policy_activation,
            original_genesis,
            pins,
            endpoint: sponsor.client().endpoint().to_string(),
            endpoints: endpoints
                .iter()
                .map(|row| row.iter().map(ToString::to_string).collect())
                .collect(),
            account_chain_discriminant: sponsor.client().account_chain_discriminant(),
            custody_path: directory
                .to_str()
                .ok_or_else(|| eyre!("non-UTF8 custody path"))?
                .to_owned(),
            invocation: [0; 32],
            mode: child::Mode::ReadOnly,
            sequence: 0,
            deadline_unix_ms,
            schema: iroha_core::state::State::native_world_schema_hash_v1()
                .map_err(|e| eyre!(e))?,
            minimum_context_time_ms: network
                .genesis()
                .0
                .header()
                .creation_time()
                .as_millis()
                .try_into()?,
            artifact_key: *key,
        };
        child::verifier(&input)?;
        Ok(Self {
            input,
            deadline,
            sequence: RefCell::new(0),
            pids: RefCell::new(Vec::new()),
            children: RefCell::new(Vec::new()),
            public: RefCell::new(None),
            original_artifacts: RefCell::new(None),
            preparation_id: RefCell::new(None),
            settlement_id: RefCell::new(None),
        })
    }
    fn journal(&self) -> Result<WorkflowJournalV1> {
        let id = self
            .settlement_id
            .borrow()
            .ok_or_else(|| eyre!("original settlement identity absent"))?;
        let storage = FileWorkflowStorage::open_or_create(
            PathBuf::from(&self.input.custody_path).join("journals"),
        )?;
        let bytes = storage
            .load(&WorkflowId::from_bytes(id))?
            .ok_or_else(|| eyre!("original settlement journal absent"))?;
        Ok(WorkflowJournalV1::decode_record(&bytes)?)
    }
    fn invoke(
        &self,
        runtime: &tokio::runtime::Runtime,
        mode: child::Mode,
    ) -> Result<child::ChildReport> {
        if mode != child::Mode::ReadOnly {
            let read = self.invoke_once(runtime, child::Mode::ReadOnly)?;
            ensure!(read.openings == 0 && read.reservations == 0);
        }
        self.invoke_once(runtime, mode)
    }
    fn invoke_once(
        &self,
        runtime: &tokio::runtime::Runtime,
        mode: child::Mode,
    ) -> Result<child::ChildReport> {
        ensure!(
            Instant::now() < self.deadline,
            "original cold case deadline elapsed"
        );
        let mut input = self.input.clone();
        input.mode = mode;
        input.invocation = rand::random();
        input.sequence = *self.sequence.borrow();
        *self.sequence.borrow_mut() = input
            .sequence
            .checked_add(1)
            .ok_or_else(|| eyre!("child sequence overflow"))?;
        let root = PrivateDirectory::open_or_create(&input.custody_path)?;
        let before = child::custody_snapshot(&root)?;
        let completed = child::spawn(runtime, &input, self.deadline)?;
        let report = completed.report;
        if self.public.borrow().is_some() || mode == child::Mode::ReadOnly {
            ensure!(
                report.openings == 0 && report.reservations == 0,
                "cold original recovery reopened wallet material or reserved again"
            );
        } else {
            ensure!(
                mode == child::Mode::Checkpoint(0)
                    && report.openings == PARTICIPANT_COUNT as u64
                    && report.reservations == PARTICIPANT_COUNT as u64,
                "initial genuine proof preparation did not use exactly the original three wallet notes"
            );
        }
        ensure!(
            !self.pids.borrow().contains(&report.pid),
            "cold SDK reused a prior process PID"
        );
        self.pids.borrow_mut().push(report.pid);
        for (slot, observed) in [
            (&self.preparation_id, Some(report.preparation_id)),
            (&self.settlement_id, report.settlement_id),
        ] {
            let mut retained = slot.borrow_mut();
            if let Some(original) = *retained {
                ensure!(
                    observed == Some(original),
                    "cold original operation identity changed"
                );
            } else if observed.is_some() {
                *retained = observed;
            }
        }
        let after = child::custody_snapshot(&root)?;
        if mode == child::Mode::ReadOnly {
            ensure!(
                before == after,
                "read-only recovery changed wallet/artifact originals or journal effect identities"
            );
            ensure!(report.openings == 0 && report.reservations == 0);
        }
        if let Some(prepared) = &report.prepared {
            prepared.validate_intent(&self.input.intent)?;
            let mut original = self.public.borrow_mut();
            if let Some(original) = &*original {
                ensure!(
                    original == prepared,
                    "cold resume replaced original material report"
                );
            } else {
                *original = Some(prepared.clone());
            }
            let artifacts = child::artifact_snapshot(&root)?;
            let mut original = self.original_artifacts.borrow_mut();
            if let Some(original) = &*original {
                ensure!(
                    *original == artifacts,
                    "cold resume replaced encrypted originals"
                );
            } else {
                *original = Some(artifacts);
            }
        }
        let record = norito::json!({"sequence": (input.sequence), "mode": (mode.label()), "pid": (report.pid),
            "input_binding": (input.binding()?.to_string()), "report_sha256": (sha256_hex(&completed.report_bytes)),
            "report_bytes": (completed.report_bytes.len() as u64), "stdout_sha256": (sha256_hex(&completed.stdout)),
            "stderr_sha256": (sha256_hex(&completed.stderr)), "preparation_id": (hex::encode(report.preparation_id)),
            "settlement_id": (report.settlement_id.map(hex::encode)), "openings": (report.openings), "reservations": (report.reservations),
            "read_only_custody_unchanged": (mode == child::Mode::ReadOnly),
            "original_artifacts_unchanged": (report.prepared.is_some())});
        self.children.borrow_mut().push((
            record,
            completed.report_bytes,
            completed.stdout,
            completed.stderr,
        ));
        Ok(report)
    }
    fn verified(
        &self,
        runtime: &tokio::runtime::Runtime,
        sponsor: &Client,
        barrier: &PrivateSettlementPrepareBarrierV1,
        mode: child::Mode,
    ) -> Result<VerifiedPrivateSettlementReceipt> {
        let report = self.invoke(runtime, mode)?;
        let receipt = report
            .receipt
            .ok_or_else(|| eyre!("child omitted original verified receipt"))?;
        let evidence = report
            .evidence
            .ok_or_else(|| eyre!("child omitted original successful execution evidence"))?;
        let mut verifier = child::verifier(&self.input)?;
        // Match the existing SDK's finite 64-read admission, without raising any resource cap.
        ensure!(
            (2..=u64::from(
                PrivateSettlementRunOptions::default()
                    .max_finality_proof_reads
                    .get()
            ))
                .contains(&receipt.finalized_height)
        );
        let verified = runtime.block_on(async {
            let mut block = None;
            for height in 1..=receipt.finalized_height {
                let proof = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(self.deadline),
                    sponsor.client().get_sumeragi_finality_proof_async(
                        std::num::NonZeroU64::new(height).unwrap(),
                        iroha_data_model::block::consensus::SumeragiRootScope::Global,
                    ),
                )
                .await??;
                ensure!(proof.height() == height);
                block = Some(verifier.verify(&proof)?);
            }
            VerifiedPrivateSettlementReceipt::verify_recovered(
                &block.ok_or_else(|| eyre!("final block absent"))?,
                barrier,
                evidence,
            )
            .map_err(eyre::Report::new)
        })?;
        ensure!(
            verified.receipt() == &receipt,
            "reported receipt differs from independently verified successful execution"
        );
        Ok(verified)
    }
}

fn require_cold_deadline(deadline: Instant) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "original cold case deadline elapsed before successful result publication"
    );
    Ok(())
}

#[test]
fn cold_final_evidence_cannot_renew_or_outlive_original_deadline() {
    assert!(require_cold_deadline(Instant::now() + Duration::from_secs(60)).is_ok());
    assert!(require_cold_deadline(Instant::now()).is_err());
    assert!(require_cold_deadline(Instant::now() - Duration::from_secs(1)).is_err());
}
