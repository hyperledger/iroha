//! Authenticated cross-host checkpoints retained independently of runtime signing inputs.

use super::super::host_pair::{
    HostPhaseClaimsV1, HostPhaseV1, SignedHostPhaseV1, verify_checkpoint_chain,
};
use super::*;

pub(super) fn load_checkpoints(
    root: &Path,
    admitted: &AdmittedReset,
    maximum: usize,
    require_complete: bool,
) -> Result<Vec<SignedHostPhaseV1>> {
    if maximum > 3 {
        return Err(eyre!(
            "host checkpoint count exceeds the closed phase protocol"
        ));
    }
    let directory = iroha_fs::PrivateDirectory::open(root)?;
    let mut chain = Vec::with_capacity(maximum);
    let mut missing = false;
    for sequence in 1..=maximum {
        let name = format!("checkpoint-{sequence}.json");
        let body = if require_complete {
            directory
                .read(&name, super::super::host_pair::MAX_CHECKPOINT_BYTES)
                .map(Some)
        } else {
            directory.read_optional(&name, super::super::host_pair::MAX_CHECKPOINT_BYTES)
        }
        .wrap_err("retained cross-host checkpoint is unavailable")?;
        let Some(body) = body else {
            missing = true;
            continue;
        };
        if missing {
            return Err(eyre!(
                "retained cross-host checkpoint chain has a missing predecessor"
            ));
        }
        let checkpoint: SignedHostPhaseV1 = json::from_slice(&body)?;
        if checkpoint.digest()? != sha256_hex(&body) {
            return Err(eyre!(
                "retained cross-host checkpoint is not its canonical signed body"
            ));
        }
        chain.push(checkpoint);
    }
    if let Some(last) = chain.last() {
        verify_checkpoint_chain(
            &chain,
            &admitted.inventory,
            &admitted.inventory_sha256,
            &admitted.authorization_sha256,
            admitted.authorization.claims.execution_expires_at_unix_ms,
            last.claims.phase,
        )?;
    }
    directory.revalidate()?;
    Ok(chain)
}

/// The receiving custodian verifies the complete chain before accepting any cross-host phase.
pub(super) fn admit_request_checkpoints(
    request: &HostRequestV1,
    action: HostAction,
    inventory: &InventoryV1,
    inventory_sha256: &str,
    authorization_sha256: &str,
    expires_at: u64,
) -> Result<()> {
    let required = match action {
        HostAction::EdgeStage | HostAction::EdgeCutover | HostAction::EdgeVerify => {
            Some(HostPhaseV1::CandidateFrontier)
        }
        HostAction::Seal | HostAction::Cleanup => Some(HostPhaseV1::DeploymentProven),
        HostAction::Rollback => {
            if request.phase_checkpoints.len() > 2 {
                return Err(eyre!(
                    "rollback cannot carry a proven global deployment checkpoint"
                ));
            }
            request
                .phase_checkpoints
                .last()
                .map(|value| value.claims.phase)
        }
        _ => {
            if !request.phase_checkpoints.is_empty() {
                return Err(eyre!("this action cannot carry cross-host checkpoints"));
            }
            None
        }
    };
    if let Some(required) = required {
        verify_checkpoint_chain(
            &request.phase_checkpoints,
            inventory,
            inventory_sha256,
            authorization_sha256,
            expires_at,
            required,
        )?;
    }
    Ok(())
}

impl<R: ProcessRunner> OpenSshTransport<'_, R> {
    pub(super) fn checkpoints_for_action(
        &self,
        action: HostAction,
    ) -> Result<Vec<SignedHostPhaseV1>> {
        match action {
            HostAction::EdgeStage | HostAction::EdgeCutover | HostAction::EdgeVerify => {
                load_checkpoints(&self.local_receipt_root, self.admitted, 1, true)
            }
            HostAction::Seal | HostAction::Cleanup => {
                load_checkpoints(&self.local_receipt_root, self.admitted, 3, true)
            }
            HostAction::Rollback => {
                load_checkpoints(&self.local_receipt_root, self.admitted, 2, false)
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(super) fn retain_phase(&self, phase: HostPhaseV1, evidence: &json::Value) -> Result<()> {
        let count = usize::from(phase.sequence());
        let existing = load_checkpoints(&self.local_receipt_root, self.admitted, count, false)?;
        if existing.len() == count {
            return Ok(());
        }
        if existing.len() + 1 != count {
            return Err(eyre!(
                "host phase cannot skip its authenticated predecessor"
            ));
        }
        let inventory = &self.admitted.inventory;
        let operator = self
            .runtime
            .validator_operator_key
            .as_ref()
            .ok_or_else(|| {
                eyre!("host phase signing requires retained dedicated operator custody")
            })?;
        validate_pinned_validator_operator_key(operator, inventory)?;
        let key = crate::operator_key::load_operator_key_pair_fd(u32::try_from(
            operator.file.as_raw_fd(),
        )?)?;
        let claims = HostPhaseClaimsV1 {
            schema: "iroha.taira.public-reset.host-phase-checkpoint.v1".into(),
            phase,
            deployment_id: inventory.deployment_id.clone(),
            inventory_sha256: self.admitted.inventory_sha256.clone(),
            authorization_sha256: self.admitted.authorization_sha256.clone(),
            authorization_nonce: inventory.authorization_nonce.clone(),
            host_pair_sha256: inventory.hosts.digest()?,
            guest_host_identity_sha256: inventory
                .hosts
                .validator_guest
                .endpoint
                .host_identity_sha256
                .clone(),
            native_edge_host_identity_sha256: inventory
                .hosts
                .native_edge
                .endpoint
                .host_identity_sha256
                .clone(),
            guest_custody_root: inventory.hosts.validator_guest.custody_root.clone(),
            native_edge_custody_root: inventory.hosts.native_edge.custody_root.clone(),
            source_commit: inventory.revision.commit.clone(),
            next_genesis_hash: inventory.next_genesis_hash.clone(),
            evidence_sha256: sha256_hex(json::to_json(evidence)?.as_bytes()),
            predecessor_sha256: existing.last().map(SignedHostPhaseV1::digest).transpose()?,
            execution_expires_at_unix_ms: self
                .admitted
                .authorization
                .claims
                .execution_expires_at_unix_ms,
        };
        let checkpoint = SignedHostPhaseV1::sign(claims, &key)?;
        checkpoint.verify(
            inventory,
            &self.admitted.inventory_sha256,
            &self.admitted.authorization_sha256,
            self.admitted
                .authorization
                .claims
                .execution_expires_at_unix_ms,
            existing.last(),
        )?;
        revalidate_pinned(operator, "host phase operator custody")?;
        let directory = iroha_fs::PrivateDirectory::open(&self.local_receipt_root)?;
        directory.write_atomic(
            format!("checkpoint-{count}.json"),
            json::to_json(&checkpoint)?.as_bytes(),
            iroha_fs::PublishMode::CreateNew,
        )?;
        directory.sync()?;
        load_checkpoints(&self.local_receipt_root, self.admitted, count, true)?;
        Ok(())
    }

    /// Obtain fresh challenged finality over every admitted public TLS route.
    pub(super) fn verify_public_frontier(&mut self, timeout_secs: u64) -> Result<json::Value> {
        self.verify_frontier(timeout_secs, true)
    }

    pub(super) fn verify_candidate_frontier(&mut self, timeout_secs: u64) -> Result<json::Value> {
        self.verify_frontier(timeout_secs, false)
    }

    fn verify_frontier(&mut self, timeout_secs: u64, public: bool) -> Result<json::Value> {
        use crate::taira_dataspace_deploy::{AuthenticatedHeightObserverV1, HeightObservationV1};
        require_forward_lease_budget(self.admitted, timeout_secs)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(timeout_secs))
            .ok_or_else(|| eyre!("public finality deadline overflow"))?;
        let inventory = &self.admitted.inventory;
        let first = &inventory.validators[0];
        let mut wire = self.closure.stream_file(&first.slug, "genesis")?;
        wire.rewind()?;
        let mut bytes = Vec::new();
        wire.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 32 * 1024 * 1024
            || sha256_hex(&bytes) != artifact(&first.artifacts, "genesis")?.sha256
        {
            return Err(eyre!(
                "public finality genesis differs from its admitted artifact"
            ));
        }
        let genesis = beacon::plan_genesis(inventory, &bytes)?;
        let peers = if public {
            beacon::public_peers(inventory)?
        } else {
            beacon::peers(inventory)?
        };
        let mut observer =
            AuthenticatedHeightObserverV1::new(&genesis, &inventory.chain_id, peers)?;
        let clients = if public {
            self.beacon_public_clients(deadline)?
        } else {
            self.beacon_clients(deadline)?
        };
        loop {
            ensure_authorization_current(self.admitted)?;
            self.runtime.revalidate(self.admitted, deadline, false)?;
            match observer.observe(&clients, inventory.chain_discriminant, deadline)? {
                HeightObservationV1::Verified(evidence) => {
                    let report = norito::json!({ "schema": "iroha.taira.public-reset.route-finality.v1", "public_tls": public, "evidence": evidence });
                    let name = if public {
                        "public-finality.json"
                    } else {
                        "candidate-frontier.json"
                    };
                    if self.read_local_receipt(name)?.is_none() {
                        self.publish_local_receipt(name, &report)?;
                    }
                    return Ok(report);
                }
                HeightObservationV1::Pending => {
                    if Instant::now() >= deadline {
                        return Err(eyre!(
                            "public TLS routes did not prove the admitted network finality before deadline"
                        ));
                    }
                    std::thread::sleep(
                        Duration::from_millis(100)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }
}
