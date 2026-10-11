//! Portable authentication of allocation originals. Saved observations are never finality authority.

use super::*;

pub(in crate::taira_dataspace_deploy) struct OriginalCompletion {
    value: CompletionV1,
    pub(in crate::taira_dataspace_deploy) runtime_update: Option<json::Value>,
    pub(in crate::taira_dataspace_deploy) effective_trust_file: Option<String>,
}

impl OriginalCompletion {
    pub(in crate::taira_dataspace_deploy) fn decode(name: &str, bytes: &[u8]) -> Result<Self> {
        let mut object: json::Value = json::from_slice(bytes)?;
        let version = object.get("schema_version").and_then(json::Value::as_u64);
        let (runtime_update, effective_trust_file) = if version == Some(2) {
            require(
                json::to_vec(&object)? == bytes,
                "completion original is not canonical",
            )?;
            let map = object
                .as_object_mut()
                .ok_or_else(|| eyre!("completion is not an object"))?;
            let update = map
                .remove("runtime_update")
                .ok_or_else(|| eyre!("completion has no runtime update"))?;
            let file = map
                .remove("verification_trust_file")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or_else(|| eyre!("completion has no effective trust original"))?;
            map.insert("schema_version".into(), norito::json!(1));
            (Some(update), Some(file))
        } else {
            require(version == Some(1), "unknown completion schema")?;
            (None, None)
        };
        let value: CompletionV1 = json::from_value(object)?;
        if version == Some(1) {
            require(
                json::to_vec(&value)? == bytes,
                "completion original is not canonical",
            )?;
        }
        let suffix = hex::encode(value.challenge);
        require(
            value.challenge != [0; 32]
                && name == format!("completion-{suffix}.json")
                && value.peers.len() == VERIFICATION_PEERS
                && value.peers.iter().all(|p| {
                    p.height > 0
                        && p.transactions.len() == PHASES.len()
                        && p.carriers.len() == PHASES.len()
                }),
            "completion identity or peer count differs",
        )?;
        require(
            effective_trust_file
                .as_deref()
                .is_none_or(|file| file == format!("verification-trust-{suffix}.json")),
            "completion selects another effective trust file",
        )?;
        Ok(Self {
            value,
            runtime_update,
            effective_trust_file,
        })
    }

    pub(in crate::taira_dataspace_deploy) fn files(&self) -> Result<BTreeSet<String>> {
        let max = self
            .value
            .peers
            .iter()
            .map(|p| p.height)
            .max()
            .ok_or_else(|| eyre!("no completion peers"))?;
        require(
            max <= 100_000,
            "completion proof prefix exceeds export bound",
        )?;
        let mut files = (1..=max)
            .map(|h| format!("proof-{h:020}.json"))
            .collect::<BTreeSet<_>>();
        for peer in &self.value.peers {
            for carrier in &peer.carriers {
                require(
                    carrier.height > 0
                        && carrier.height <= peer.height
                        && carrier.file == format!("carrier-{:020}.nrt", carrier.height),
                    "completion carrier locator differs",
                )?;
                files.insert(carrier.file.clone());
            }
        }
        Ok(files)
    }

    /// Replay independently authenticated proofs and exact successful phase membership.
    /// Native live completion additionally checked current catalog/namespace/process state;
    /// those historical HTTP observations do not become portable signed assertions.
    pub(in crate::taira_dataspace_deploy) fn replay(
        &self,
        plan: &PlanV1,
        trust: &TrustV1,
        prepared: &[(PreparedV1, SignedTransaction)],
        retained_tips: &runtime_update::RetainedTips,
        mut read: impl FnMut(&str, usize) -> Result<Vec<u8>>,
    ) -> Result<(Vec<json::Value>, Vec<json::Value>)> {
        let value = &self.value;
        require(
            value.operation_id == plan.operation_id
                && value.intent_sha256 == plan.intent_sha256
                && value.network_id == plan.manifest.network_id
                && prepared.len() == PHASES.len(),
            "completion differs from the exact allocation plan",
        )?;
        verification_origins(trust, &value.verification_origins)?;
        let authority = trust.authority(plan.manifest.network_id)?;
        let maximum = value.peers.iter().map(|p| p.height).max().unwrap();
        self.files()?;
        let mut needed = BTreeSet::from([1]);
        for peer in &value.peers {
            needed.insert(peer.height);
            needed.extend(peer.carriers.iter().map(|c| c.height));
        }
        needed.extend(retained_tips.heights());
        require(
            needed.iter().all(|height| *height <= maximum),
            "runtime retained tip exceeds the completed authenticated prefix",
        )?;
        let mut proofs = BTreeMap::new();
        let mut verifier = authority.verifier()?;
        for height in 1..=maximum {
            let bytes = read(&format!("proof-{height:020}.json"), MAX_BYTES)?;
            let proof: SumeragiFinalityProof = json::from_slice(&bytes)?;
            require(
                json::to_vec(&proof)? == bytes && proof.block_header.height().get() == height,
                "allocation proof is noncanonical, missing or reordered",
            )?;
            authority.roster(&proof)?;
            if height == 1 {
                verifier = authority.anchor(&proof)?;
            } else {
                verifier.verify(&proof)?;
            }
            if needed.contains(&height) {
                proofs.insert(height, proof);
            }
        }
        // Every retained historical height was included above and authenticated by
        // the same native genesis/QC walk before any runtime claim is accepted.
        retained_tips
            .verify_authenticated_prefix(&proofs, value.peers.iter().map(|peer| peer.height))?;
        let genesis = &proofs[&1];
        let mut phases: Option<Vec<json::Value>> = None;
        let mut peers = Vec::new();
        for (peer, selected) in value.peers.iter().zip(&trust.peers) {
            require(
                peer.peer_id == selected.peer_id,
                "completion peer order or selection differs",
            )?;
            validate_attestation(&authority, selected, value.challenge, &peer.attestation)?;
            let tip = &proofs[&peer.height];
            verifier
                .verify_same_decision(genesis, &peer.attestation.body.genesis_finality_proof)?;
            verifier.verify_same_decision(tip, &peer.attestation.body.finality_proof)?;
            require(
                peer.block_hash == tip.block_header.hash()
                    && peer
                        .attestation
                        .body
                        .finality_proof
                        .block_header
                        .height()
                        .get()
                        == peer.height,
                "completion peer height or block differs from signed attestation",
            )?;
            let mut peer_phases = Vec::new();
            for ((observed, carrier), (retained, transaction)) in
                peer.transactions.iter().zip(&peer.carriers).zip(prepared)
            {
                let height = matching_applied_height(
                    &retained.transaction_hash,
                    &observed.global_status,
                    &observed.peer_status,
                )?
                .ok_or_else(|| eyre!("completion contains a pending phase"))?;
                require(
                    observed.phase == retained.phase
                        && observed.state == "applied_verification_pending"
                        && observed.transaction_hash.as_ref() == Some(&retained.transaction_hash)
                        && observed.instructions == retained.instructions
                        && observed.alias_plan == retained.alias_plan
                        && observed.signed_transaction_wire_sha256
                            == digest(&transaction.encode_wire_v1()?)
                        && height == carrier.height
                        && height <= peer.height,
                    "completion phase differs from signed preparation",
                )?;
                let details = observed
                    .committed
                    .as_ref()
                    .ok_or_else(|| eyre!("completion has no committed phase"))?;
                require(
                    details.hash == retained.transaction_hash,
                    "completion detail changed the requested transaction hash",
                )?;
                let committed = &details.transaction;
                let TransactionEntrypoint::External(actual) = committed.entrypoint() else {
                    eyre::bail!("completed phase is not external");
                };
                require(
                    actual.encode_wire_v1()? == transaction.encode_wire_v1()?,
                    "completed phase changed exact signed wire",
                )?;
                let proof = &proofs[&height];
                require(
                    committed.block_hash() == &proof.block_header.hash(),
                    "phase carrier differs from authenticated proof",
                )?;
                let certified = verifier.verify_same_decision(proof, proof)?;
                certified.verify_committed_transaction(&authority.network, committed)?;
                let maximum = iroha_data_model::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1;
                let wire = read(&carrier.file, maximum)?;
                require(
                    digest(&wire) == carrier.wire_sha256
                        && wire == certified.canonical_executed_wire()?,
                    "carrier original differs from authenticated executed wire",
                )?;
                peer_phases.push(norito::json!({"phase":(retained.phase.clone()), "transaction_hash":(retained.transaction_hash.clone()),
                    "height":(height.to_string()), "block_hash":(proof.block_header.hash().to_string()),
                    "signed_wire_sha256":(observed.signed_transaction_wire_sha256.clone())}));
            }
            if let Some(expected) = &phases {
                require(
                    expected == &peer_phases,
                    "four peers disagree on allocation carriers",
                )?;
            } else {
                phases = Some(peer_phases);
            }
            peers.push(norito::json!({"peer_id":(selected.peer_id.to_string()), "torii_origin":(selected.torii_origin.clone()),
                "node_fingerprint":(selected.node_fingerprint.to_string()), "build_fingerprint":(selected.build_fingerprint.to_string()),
                "config_fingerprint":(selected.config_fingerprint.to_string()), "height":(peer.height.to_string()),
                "block_hash":(peer.block_hash.to_string())}));
        }
        Ok((phases.unwrap(), peers))
    }
}

#[cfg(test)]
#[path = "taira_dataspace_deploy_authority_replay_tests.rs"]
mod tests;
