//! Genuine C claim through ordinary four-validator Unload and exact retained retries.
use super::*;
use iroha_data_model::{
    ValidationFail,
    isi::error::InstructionExecutionError,
    transaction::{TransactionResult, error::TransactionRejectionReason},
};
use iroha_torii_shared::PipelineTransactionStatusResponse;

fn state_rejection(
    transaction: HashOf<SignedTransaction>,
    response: Option<&PipelineTransactionStatusResponse>,
) -> Result<Option<u64>> {
    let Some(response) = response else {
        return Ok(None);
    };
    let fixed =
        iroha::client::TransactionFinalityFailure::from_response(transaction, response.clone())?;
    ensure!(
        response.status.kind == "Rejected",
        "non-rejection status for invalid claim"
    );
    if fixed.is_none() {
        return Ok(None);
    }
    let height = response
        .status
        .block_height
        .ok_or_else(|| eyre!("state rejection height absent"))?;
    ensure!(height > 1, "state rejection cannot be genesis");
    Ok(Some(height))
}

fn claim_failure<'a>(
    result: &'a TransactionResult,
    expected: &TransactionRejectionReason,
) -> Result<&'a TransactionRejectionReason> {
    let reason = result
        .0
        .as_ref()
        .err()
        .ok_or_else(|| eyre!("invalid claim applied"))?;
    ensure!(
        matches!(
            reason,
            TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::InvariantViolation(_)
            ))
        ),
        "unrelated execution failure cannot qualify invalid-claim rejection"
    );
    ensure!(
        reason == expected,
        "certified failure differs from the exact invalid claim"
    );
    Ok(reason)
}

// Keep full canonical DATA in bounded originals; the compact handoff only pins them.
fn canonical_observation<T: norito::NoritoSerialize>(
    output: &Path,
    name: &str,
    value: &T,
    maximum: usize,
) -> Result<norito::json::Value> {
    let bytes = norito::encode_canonical(value)?;
    ensure!(
        bytes.len() <= maximum,
        "canonical observation exceeds bound"
    );
    publish(output, name, &bytes)
}

fn failed_execution(
    verified: &VerifiedSumeragiBlock,
    network: &Network,
    signed: &SignedTransaction,
    expected: &TransactionRejectionReason,
) -> Result<Option<CommittedTransaction>> {
    let block = verified.block();
    let Some(index) = block
        .network_entrypoints()
        .position(|entry| entry.hash().as_ref() == signed.hash().as_ref())
    else {
        return Ok(None);
    };
    verified.verify_global_scope(network.network_id(), &network.chain_id().to_string())?;
    let input_index = u32::try_from(index)?;
    let entrypoint = block
        .network_entrypoint_at(index)
        .ok_or_else(|| eyre!("failed entrypoint absent"))?
        .clone();
    let iroha_data_model::transaction::TransactionEntrypoint::External(actual) = &entrypoint else {
        bail!("external failed original required")
    };
    ensure!(
        norito::encode_canonical(actual)? == norito::encode_canonical(signed)?
            && actual.network_id() == Some(&network.network_id())
            && actual.verify_signature().is_ok(),
        "failed transaction original differs"
    );
    let (output_index, _) = block
        .network_output_at(input_index)
        .ok_or_else(|| eyre!("failed output absent"))?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or_else(|| eyre!("failed output index"))?
        .clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(input_index)
            .ok_or_else(|| eyre!("failed input proof absent"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or_else(|| eyre!("failed output proof absent"))?,
        output,
    };
    ensure!(
        committed.verify_inclusion_in_block(block),
        "failed execution membership differs"
    );
    claim_failure(committed.result(), expected)?;
    Ok(Some(committed))
}

fn refused(
    network: &Network,
    output: &Path,
    seed: u8,
    signed: SignedTransaction,
    expected: &TransactionRejectionReason,
    name: &str,
) -> Result<norito::json::Value> {
    let before = committed_height(network)?;
    let signed_original = canonical_observation(
        output,
        &format!("{name}-signed.norito"),
        &signed,
        ORIGINAL_MAX,
    )?;
    let mut originals = vec![
        signed_original,
        canonical_observation(
            output,
            &format!("{name}-expected-reason.norito"),
            expected,
            16 << 10,
        )?,
    ];
    File::open(output)?.sync_all()?;
    let client = running_peer(network)?.client_for(&account(seed), key(seed).private_key().clone());
    let error = client
        .submit_transaction_and_wait(&signed)
        .expect_err("foreign Unload must not succeed");
    ensure!(
        error
            .downcast_ref::<iroha::client::TransactionDispatchOutcomeUnknownError>()
            .is_none(),
        "dispatch ambiguity is not a refusal"
    );
    let submission_error = format!("{error:#}").into_bytes();
    ensure!(
        submission_error.len() <= ORIGINAL_MAX,
        "submission error exceeds evidence bound"
    );
    originals.push(publish(
        output,
        &format!("{name}-submission-error.txt"),
        &submission_error,
    )?);
    let mut statuses = Vec::new();
    let mut state_heights = Vec::new();
    for (index, peer) in network.peers().iter().enumerate() {
        let status = peer
            .client()
            .client()
            .get_transaction_status_response_global(signed.hash())?;
        let state_height = state_rejection(signed.hash(), status.as_ref())?;
        state_heights.extend(state_height);
        originals.push(canonical_observation(
            output,
            &format!("{name}-status-{index}.norito"),
            &status,
            16 << 10,
        )?);
        statuses.push(norito::json!({"peer_id":(peer.id().to_string()), "response":status, "state_rejection_height":state_height}));
    }
    let after = committed_height(network)?;
    let history = prefix(network, after)?;
    let mut verifier = native(network)?;
    let mut committed_failure = None;
    for proof in history {
        let verified = verifier.verify(&proof)?;
        if let Some(committed) = failed_execution(&verified, network, &signed, expected)? {
            ensure!(committed_failure.is_none(), "duplicate foreign transaction");
            committed_failure = Some(verified.height());
            originals.push(canonical_observation(
                output,
                &format!("{name}-committed.norito"),
                &committed,
                ORIGINAL_MAX,
            )?);
            originals.push(canonical_observation(
                output,
                &format!("{name}-reason.norito"),
                claim_failure(committed.result(), expected)?,
                16 << 10,
            )?);
        }
    }
    ensure!(
        state_heights
            .iter()
            .all(|height| Some(*height) == committed_failure),
        "state rejection does not match native-certified failure"
    );
    let snapshots = balances(network, [900, 0, 100, 0])?;
    let qualified = committed_failure.is_some();
    let observation = norito::json::to_vec(&norito::json!({
        "name":name, "phase":"submitted", "transaction_hash_hex":(hex::encode(signed.hash().as_ref())),
        "height_before":before, "height_after":after, "committed_failure_height":committed_failure,
        "originals":originals, "peer_statuses":statuses, "balances":snapshots,
        "authoritative_rejection_observed":qualified, "adversarial_input_rejection_qualified":qualified,
        "scope":"Certified exact execution reason qualifies rejection. Redacted pre-route errors remain observations; their local canonical decoder failure is recorded separately and never creates network authority."
    }))?;
    ensure!(
        observation.len() <= 16 << 10,
        "negative observation manifest bound"
    );
    let original = publish(output, &format!("{name}-observation.json"), &observation)?;
    Ok(
        norito::json!({"name":name, "transaction_hash_hex":(hex::encode(signed.hash().as_ref())), "qualified":qualified, "observation_original":original}),
    )
}

pub(super) fn run(
    network: &Network,
    root: &Path,
    command: &norito::json::Value,
    setup_sha: &str,
    funded_bytes: &[u8],
) -> Result<Vec<u8>> {
    let funded: norito::json::Value = norito::json::from_slice(funded_bytes)?;
    let (exchange_path, exchange_bytes) = selected(command, "exchange", 16 << 10)?;
    let exchange: norito::json::Value = norito::json::from_slice(&exchange_bytes)?;
    ensure!(
        exchange["schema"].as_str() == Some("iroha.kagemusha.native-abc-result.v1"),
        "native exchange schema"
    );
    ensure!(
        exchange["source_pins"] == funded["source_pins"]
            && exchange["target_sha256"] == funded["target_sha256"]
            && exchange["executed_ledger_setup_sha256"].as_str() == Some(setup_sha),
        "foreign native campaign"
    );
    ensure!(
        digest(&exchange["c_account_digest"])? == kagemusha_wallet_account_digest_v1(&account(43))?,
        "foreign C account"
    );
    let source = exchange_path
        .parent()
        .ok_or_else(|| eyre!("exchange parent"))?;
    let claim_bytes = read(
        &source.join("c-unload-claim.norito"),
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
        exchange["c_unload_claim_sha256"]
            .as_str()
            .ok_or_else(|| eyre!("claim pin"))?,
    )?;
    let (target_path, target_bytes) = selected(command, "target", 16 << 10)?;
    ensure!(
        hash(&target_bytes) == funded["target_sha256"].as_str().unwrap_or_default(),
        "selected target differs"
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes)?;
    let scheme_id = digest(&target["scheme_id"])?;
    let (_, pack) = selected(command, "verifier_pack", VERIFIER_PACK_MAX_BYTES_V1)?;
    let installed = InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id,
            manifest_digest: digest(&target["manifest_digest"])?,
        },
    )?;
    let claim = KagemushaWalletUnloadClaimV1::decode_canonical(&claim_bytes, &scheme_id)?;
    ensure!(
        claim.account == account(43)
            && claim.credential.body.wallet_id == digest(&exchange["c_wallet_id"])?,
        "exact retained C scope required"
    );
    let asset: KagemushaWalletAssetScopeV1 = canonical(&original(
        target_path.parent().unwrap(),
        &target,
        "files",
        "asset.norito",
        4096,
    )?)?;
    ensure!(
        claim.credential.body.asset_digest == asset.asset_digest(),
        "claim asset differs from executed registration"
    );
    let paid = claim.verify(installed.verifier().scheme())?;
    ensure!(
        (paid.amount, paid.account_payout, paid.online_charge) == (100, 100, 0),
        "exact C payout required"
    );
    // Admit all negative DATA before the successful payout. The signed fixture uses
    // C's existing software test key, but is never a provider transition or released claim.
    let bad_source = &exchange["c_unload_bad_sigma_claim"];
    ensure!(
        bad_source["name"].as_str() == Some("c-unload-bad-sigma-claim.norito")
            && bad_source["mutation"].as_str() == Some("sigma_ipa_f_plus_one")
            && bad_source["model_verified"].as_bool() == Some(true)
            && bad_source["native_proof_rejected"].as_bool() == Some(true)
            && bad_source["adversarial_fixture_signatures"].as_u64() == Some(1),
        "native bad-sigma fixture grammar"
    );
    let bad_sigma_bytes = read(
        &source.join("c-unload-bad-sigma-claim.norito"),
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
        bad_source["sha256"]
            .as_str()
            .ok_or_else(|| eyre!("negative claim pin"))?,
    )?;
    ensure!(
        bad_source["bytes"].as_u64() == Some(bad_sigma_bytes.len() as u64),
        "negative claim extent differs"
    );
    let bad_sigma = KagemushaWalletUnloadClaimV1::decode_canonical(&bad_sigma_bytes, &scheme_id)?;
    let mut bad_payout = bad_sigma.verify(installed.verifier().scheme())?;
    ensure!(
        bad_payout.package != paid.package,
        "negative proof must change its package digest"
    );
    bad_payout.package = paid.package; // Only the proof/receipt-dependent identity changes.
    ensure!(
        bad_payout == paid,
        "negative fixture changed payout or its public binding"
    );
    ensure!(
        bad_sigma.package.step_proof.bytes.len() == claim.package.step_proof.bytes.len()
            && bad_sigma.package.step_proof.bytes != claim.package.step_proof.bytes,
        "same-length actual sigma mutation required"
    );
    let mut normalized = bad_sigma.clone();
    normalized.package.step_proof.bytes = claim.package.step_proof.bytes.clone();
    normalized.package.receipt = claim.package.receipt.clone();
    ensure!(
        norito::encode_canonical(&normalized)? == claim_bytes,
        "negative fixture changed unrelated claim fields"
    );
    installed
        .verifier()
        .verify_package_proofs(&claim.package, None, Default::default())?;
    ensure!(
        matches!(
            installed.verifier().verify_package_proofs(
                &bad_sigma.package,
                None,
                Default::default()
            ),
            Err(iroha_core_zk::kagemusha_wallet_proofs_v1::Error::Proof)
        ),
        "model-valid negative must fail the actual installed proof verifier"
    );
    balances(network, [900, 0, 0, 100])?;
    let output = root.join("settlement");
    private_directory(&output)?;
    let instruction = KagemushaWalletLedgerV1::new(scheme_id, Action::Unload(claim_bytes.clone()));
    let (transaction, settled_height) = submit(
        network,
        43,
        vec![instruction.clone().into()],
        &output,
        "unload-signed-transaction.norito",
    )?;
    let settled_balances = balances(network, [900, 0, 100, 0])?;
    let client = running_peer(network)?.client_for(&account(43), key(43).private_key().clone());
    // Exact transport retry may return the already applied outcome without a block.
    let retried = client.submit_transaction_and_wait(&transaction)?;
    ensure!(
        retried == transaction.hash(),
        "retained signed retry changed identity"
    );
    balances(network, [900, 0, 100, 0])?;
    let (_, instruction_retry_height) = submit(
        network,
        43,
        vec![instruction.clone().into()],
        &output,
        "unload-instruction-retry-signed.norito",
    )?;
    balances(network, [900, 0, 100, 0])?;
    // Relaying an authentic C claim is permitted; changing its authenticated account is not.
    let mut changed = claim.clone();
    changed.account = account(41);
    ensure!(
        changed.verify(installed.verifier().scheme()).is_err(),
        "foreign-account mutation remained valid"
    );
    let foreign_bytes = norito::encode_canonical(&changed)?;
    let model_error = KagemushaWalletUnloadClaimV1::decode_canonical(&foreign_bytes, &scheme_id)
        .expect_err("changed account must fail canonical model validation");
    let expected_account = TransactionRejectionReason::Validation(
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(
            format!("KAGEMUSHA ledger: {model_error}").into(),
        )),
    );
    let foreign_instruction =
        KagemushaWalletLedgerV1::new(scheme_id, Action::Unload(foreign_bytes));
    let foreign_account = match signed(network, 43, vec![foreign_instruction.clone().into()]) {
        Ok(transaction) => refused(
            network,
            &output,
            43,
            transaction,
            &expected_account,
            "foreign-account",
        )?,
        Err(error) => {
            // Fee quoting performs ordinary routing first. A pre-route refusal has
            // no signed identity and cannot provide transaction or execution authority.
            let error_bytes = format!("{error:#}").into_bytes();
            ensure!(error_bytes.len() <= ORIGINAL_MAX, "preparation error bound");
            let originals = vec![
                canonical_observation(
                    &output,
                    "foreign-account-instruction.norito",
                    &foreign_instruction,
                    ORIGINAL_MAX,
                )?,
                canonical_observation(
                    &output,
                    "foreign-account-expected-reason.norito",
                    &expected_account,
                    16 << 10,
                )?,
                publish(
                    &output,
                    "foreign-account-preparation-error.txt",
                    &error_bytes,
                )?,
            ];
            let snapshots = balances(network, [900, 0, 100, 0])?;
            let observation = norito::json::to_vec(&norito::json!({
                "name":"foreign-account", "phase":"preparation", "transaction_hash_hex":null,
                "committed_failure_height":null, "originals":originals, "peer_statuses":[], "balances":snapshots,
                "authoritative_rejection_observed":false, "adversarial_input_rejection_qualified":false,
                "scope":"Account signing preparation failed before a transaction existed. Exact local model refusal is retained separately. The preparation error is an inconclusive observation, never authenticated network rejection."
            }))?;
            ensure!(
                observation.len() <= 16 << 10,
                "negative observation manifest bound"
            );
            let original = publish(&output, "foreign-account-observation.json", &observation)?;
            norito::json!({"name":"foreign-account", "transaction_hash_hex":null, "qualified":false, "observation_original":original})
        }
    };
    let expected_proof = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvariantViolation(
            format!(
                "KAGEMUSHA ledger: {}",
                iroha_core::kagemusha_wallet_v1::Error::Proof
            )
            .into(),
        ),
    ));
    let altered_proof = refused(
        network,
        &output,
        43,
        signed(
            network,
            43,
            vec![KagemushaWalletLedgerV1::new(scheme_id, Action::Unload(bad_sigma_bytes)).into()],
        )?,
        &expected_proof,
        "bad-sigma",
    )?;
    let account_specific_network_rejection_qualified =
        foreign_account["qualified"].as_bool() == Some(true);
    let native_proof_rejection_qualified = altered_proof["qualified"].as_bool() == Some(true);
    // Routing rejects the account mutation before execution and redacts its precise error.
    // Keep that observation inconclusive; it never blocks actual C confirmation/restart.
    let adversarial_qualified = native_proof_rejection_qualified;
    let through = committed_height(network)?;
    let history = prefix(network, through)?;
    let mut verifier = native(network)?;
    let mut originals = vec![
        publish(&output, "unload-claim.norito", &claim_bytes)?,
        publish(
            &output,
            "unload-instruction.norito",
            &norito::encode_canonical(&instruction)?,
        )?,
        // The signed transaction already exists, so record its retained exact identity.
        norito::json!({"name":"unload-signed-transaction.norito", "bytes":(norito::encode_canonical(&transaction)?.len()), "sha256":(hash(&norito::encode_canonical(&transaction)?))}),
    ];
    let mut settled_hash = None;
    for proof in history {
        let verified = verifier.verify(&proof)?;
        if proof.height() == settled_height {
            inclusion(&verified, network, &transaction)?;
            settled_hash = Some(hex::encode(verified.block().hash().as_ref()));
            originals.push(publish(&output, "unload-block.norito", &proof.block_wire)?);
        }
        originals.push(publish(
            &output,
            &format!("native-proof-{}.norito", proof.height()),
            &norito::encode_canonical(&proof)?,
        )?);
    }
    let result = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.network-unload-settlement.v1", "setup_sha256":setup_sha,
        "source_pins":(exchange["source_pins"].clone()), "network_hex":(hex::encode(network.network_id().as_bytes())), "chain_id":(network.chain_id().to_string()), "instance_hex":(hex::encode(native(network)?.instance().0)),
        "target_sha256":(exchange["target_sha256"].clone()), "receipt_sha256":(funded["receipt_sha256"].clone()), "exchange_sha256":(hash(&exchange_bytes)), "claim_sha256":(hash(&claim_bytes)),
        "settlement_height":settled_height, "last_certified_height":through, "settlement_transaction_hash_hex":(hex::encode(transaction.hash().as_ref())), "settlement_block_hash_hex":(settled_hash.ok_or_else(|| eyre!("settlement absent"))?),
        "adversarial_qualified":adversarial_qualified, "native_proof_rejection_qualified":native_proof_rejection_qualified, "account_specific_network_rejection_qualified":account_specific_network_rejection_qualified, "account_binding_model_refusal":true, "instruction_retry_height":instruction_retry_height, "exact_transaction_retry_returned_original":true,
        "settled_balances":settled_balances, "foreign_account_observation":foreign_account, "altered_proof_observation":altered_proof,
        "originals":originals, "scope":"Actual four-validator settlement, replay and native proof-negative execution. Account binding is checked locally; redacted pre-route refusal does not qualify account-specific network evidence. Same native C confirmation and node-store restart follow separately."
    }))?;
    ensure!(
        result.len() <= 16 << 10,
        "settlement manifest exceeds native consumer bound"
    );
    publish(&output, "settlement.json", &result)?;
    publish(root, "settled.json", &result)?;
    Ok(result)
}

#[test]
fn rejection_status_requires_exact_global_state_and_certified_height() {
    use iroha_torii_shared::PipelineTransactionStatus;
    let hash = HashOf::from_untyped_unchecked(Hash::new(b"kagemusha-invalid-claim"));
    let response = PipelineTransactionStatusResponse::new(
        hash.to_string(),
        PipelineTransactionStatus {
            kind: "Rejected".into(),
            block_height: Some(8),
        },
        "global".into(),
        "state".into(),
    );
    assert_eq!(state_rejection(hash, Some(&response)).unwrap(), Some(8));
    assert_eq!(state_rejection(hash, None).unwrap(), None);
    for source in ["cache", "queue"] {
        let mut changed = response.clone();
        changed.resolved_from = source.into();
        assert_eq!(state_rejection(hash, Some(&changed)).unwrap(), None);
    }
    let mut changed = response.clone();
    changed.hash = Hash::new(b"foreign-claim").to_string();
    assert!(state_rejection(hash, Some(&changed)).is_err());
    let mut changed = response.clone();
    changed.scope = "local".into();
    assert!(state_rejection(hash, Some(&changed)).is_err());
    let mut changed = response.clone();
    changed.resolved_from = "publisher".into();
    assert!(state_rejection(hash, Some(&changed)).is_err());
    for kind in ["Applied", "Expired", "Queued", "unknown"] {
        let mut changed = response.clone();
        changed.status.kind = kind.into();
        assert!(state_rejection(hash, Some(&changed)).is_err());
    }
    for height in [None, Some(0), Some(1)] {
        let mut changed = response.clone();
        changed.status.block_height = height;
        assert!(state_rejection(hash, Some(&changed)).is_err());
    }
}

#[test]
fn claim_failure_requires_typed_instruction_invariant_and_retains_exact_reason() {
    let reason = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvariantViolation("exact invalid-claim detail".into()),
    ));
    let failed = TransactionResult::new(Err(reason.clone()));
    assert_eq!(claim_failure(&failed, &reason).unwrap(), &reason);
    let bytes = norito::encode_canonical(claim_failure(&failed, &reason).unwrap()).unwrap();
    assert_eq!(
        canonical::<TransactionRejectionReason>(&bytes).unwrap(),
        reason
    );
    assert!(claim_failure(&TransactionResult::new(Ok(Vec::new())), &reason).is_err());
    for unrelated in [
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "fee rejection".into(),
        )),
        TransactionRejectionReason::Validation(ValidationFail::TooComplex),
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvariantViolation("different failure".into()),
        )),
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::Conversion("unrelated conversion".into()),
        )),
    ] {
        assert!(claim_failure(&TransactionResult::new(Err(unrelated)), &reason).is_err());
    }
}

#[test]
fn canonical_observation_retains_exact_bytes_and_refuses_oversized_or_replaced_original() {
    let directory = tempfile::tempdir().unwrap();
    let reason = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvariantViolation("retained detail".into()),
    ));
    let bytes = norito::encode_canonical(&reason).unwrap();
    let original =
        canonical_observation(directory.path(), "reason.norito", &reason, bytes.len()).unwrap();
    assert_eq!(original["sha256"].as_str(), Some(hash(&bytes).as_str()));
    assert_eq!(original["bytes"].as_u64(), Some(bytes.len() as u64));
    assert_eq!(
        read(
            &directory.path().join("reason.norito"),
            bytes.len(),
            &hash(&bytes)
        )
        .unwrap(),
        bytes
    );
    assert!(
        canonical_observation(directory.path(), "reason.norito", &reason, bytes.len()).is_err()
    );
    assert!(
        canonical_observation(
            directory.path(),
            "oversized.norito",
            &reason,
            bytes.len() - 1
        )
        .is_err()
    );
    assert!(!directory.path().join("oversized.norito").exists());
}
