//! Separate four-validator Send-fee payout, historical inputs and same-store restart.
//!
//! The controller supplies a fresh dedicated fee target and genuine producer originals.
//! No Receive instruction is submitted to this network; the native producer may already
//! have exercised offline Receive and ArchiveReceive. This does not qualify physical devices.
//! TODO: Compile and run against the integrated current-source catalog and stock nodes.

use super::*;
use iroha_data_model::{
    ValidationFail, isi::error::InstructionExecutionError,
    transaction::error::TransactionRejectionReason,
};

#[path = "fee/world.rs"]
mod world;

const FEE_NAMES: [&str; 3] = ["request.norito", "payment.norito", "fee-claim.norito"];

pub(super) fn require_command(command: &norito::json::Value) -> Result<()> {
    activation::closed(
        command,
        &[
            "schema",
            "phase",
            "setup_sha256",
            "previous_sha256",
            "producer",
            "target",
            "verifier_pack",
        ],
    )?;
    ensure!(
        command["schema"].as_str() == Some("iroha.kagemusha.real-network-command.v1")
            && command["phase"].as_str() == Some("fee-settlement"),
        "exact fee command required"
    );
    digest(&command["setup_sha256"])?;
    digest(&command["previous_sha256"])?;
    for field in ["producer", "target", "verifier_pack"] {
        activation::selection(&command[field])?;
    }
    Ok(())
}

struct Inputs {
    scheme: [u8; 32],
    manifest: [u8; 32],
    producer: Vec<u8>,
    target: Vec<u8>,
    request: Vec<u8>,
    payment: Vec<u8>,
    claim: Vec<u8>,
    activation: KagemushaWalletActivationV1,
    credit: [u8; 32],
    payment_digest: [u8; 32],
}

fn inputs(
    command: &norito::json::Value,
    setup_sha: &str,
    funded: &[u8],
    registered: &registration::Registered,
) -> Result<Inputs> {
    require_command(command)?;
    let funded: norito::json::Value = norito::json::from_slice(funded)?;
    let (producer_path, producer) = selected(command, "producer", 16 << 10)?;
    let result: norito::json::Value = norito::json::from_slice(&producer)?;
    ensure!(
        result["schema"].as_str() == Some("iroha.kagemusha.native-fee-result.v1"),
        "genuine fee producer schema"
    );
    require_inventory(&result, "originals", &FEE_NAMES)?;
    ensure!(
        result["source_pins"] == funded["source_pins"]
            && result["target_sha256"] == funded["target_sha256"]
            && result["receipt_sha256"] == funded["receipt_sha256"]
            && result["executed_ledger_setup_sha256"].as_str() == Some(setup_sha),
        "foreign fee campaign"
    );
    let (target_path, target) = selected(command, "target", 16 << 10)?;
    ensure!(
        hash(&target) == funded["target_sha256"].as_str().unwrap_or_default(),
        "exact funded fee target"
    );
    let target_value: norito::json::Value = norito::json::from_slice(&target)?;
    ensure!(
        target_value["schema"].as_str() == Some("iroha.kagemusha.native-load-target.v1")
            && target_value["variant"].as_str() == Some("fee97-plus3"),
        "dedicated fee incarnation required"
    );
    let scheme = digest(&target_value["scheme_id"])?;
    let manifest = digest(&target_value["manifest_digest"])?;
    ensure!(
        digest(&result["scheme_id"])? == scheme && digest(&result["manifest_digest"])? == manifest,
        "producer catalog differs"
    );
    let source = target_path.parent().ok_or_else(|| eyre!("target parent"))?;
    let asset: KagemushaWalletAssetScopeV1 = canonical(&original(
        source,
        &target_value,
        "files",
        "asset.norito",
        4096,
    )?)?;
    registered.require_target(setup_sha, scheme, manifest, &asset)?;
    let activation = KagemushaWalletActivationV1::decode_canonical(
        &original(
            source,
            &target_value,
            "files",
            "activation.norito",
            KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
        )?,
        &scheme,
    )?;
    ensure!(
        activation.asset == asset
            && activation.credential.body.account_digest
                == kagemusha_wallet_account_digest_v1(&account(41))?,
        "funded payer identity"
    );
    let source = producer_path
        .parent()
        .ok_or_else(|| eyre!("producer parent"))?;
    let request = original(
        source,
        &result,
        "originals",
        FEE_NAMES[0],
        KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1,
    )?;
    let payment = original(
        source,
        &result,
        "originals",
        FEE_NAMES[1],
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    )?;
    let claim = original(
        source,
        &result,
        "originals",
        FEE_NAMES[2],
        KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
    )?;
    let request_value: KagemushaWalletRequestV1 = canonical(&request)?;
    let claim_value = KagemushaWalletFeeClaimV1::decode_canonical(&claim, &scheme)?;
    ensure!(
        norito::encode_canonical(&claim_value.payment)? == payment,
        "Payment payload differs from claim"
    );
    ensure!(
        claim_value.payment.digests()?.payer_credential
            == activation.credential.credential_digest()
            && request_value.body.payer_wallet_id == activation.credential.body.wallet_id
            && request_value.body.payer_account_digest
                == kagemusha_wallet_account_digest_v1(&account(41))?
            && request_value.body.receiver_account_digest
                == kagemusha_wallet_account_digest_v1(&account(42))?
            && claim_value.beneficiary == account(43),
        "exact A/B/fixed-C binding required"
    );
    ensure!(
        (request_value.body.amount, request_value.body.fee) == (97, 3)
            && (
                claim_value.payment.send.statement.next_load,
                claim_value.payment.send.statement.enabled_controls
            ) == (1, 0),
        "exact loaded Send97/fee3 required"
    );
    let (_, pack) = selected(command, "verifier_pack", VERIFIER_PACK_MAX_BYTES_V1)?;
    let installed = InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id: scheme,
            manifest_digest: manifest,
        },
    )?;
    ensure!(
        *installed.verifier().scheme() == registered.scheme,
        "registered scheme differs"
    );
    let verified = claim_value.verify(
        installed.verifier().scheme(),
        &request_value,
        &activation.credential,
        &activation.certificates,
    )?;
    ensure!(verified.fee == 3, "exact fee payout");
    installed.verifier().verify_package_proofs(
        &claim_value.payment.send,
        Some(&request_value.body),
        Default::default(),
    )?;
    Ok(Inputs {
        scheme,
        manifest,
        producer,
        target,
        request,
        payment,
        claim,
        activation,
        credit: verified.credit_id,
        payment_digest: verified.payment,
    })
}

fn missing_reason() -> TransactionRejectionReason {
    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvariantViolation(
            "KAGEMUSHA ledger: ledger record unavailable".into(),
        ),
    ))
}

fn missing_request(
    network: &Network,
    output: &Path,
    instruction: &KagemushaWalletLedgerV1,
) -> Result<norito::json::Value> {
    let before = committed_height(network)?;
    let transaction = signed(network, 42, vec![instruction.clone().into()])?;
    publish(
        output,
        "missing-request-signed.norito",
        &norito::encode_canonical(&transaction)?,
    )?;
    File::open(output)?.sync_all()?;
    let error = running_peer(network)?
        .client_for(&account(42), key(42).private_key().clone())
        .submit_transaction_and_wait(&transaction)
        .expect_err("missing historical Request must be refused");
    ensure!(
        error
            .downcast_ref::<iroha::client::TransactionDispatchOutcomeUnknownError>()
            .is_none(),
        "dispatch ambiguity is not a refusal"
    );
    let history = prefix(
        network,
        before
            .checked_add(1)
            .ok_or_else(|| eyre!("height overflow"))?,
    )?;
    let mut verifier = native(network)?;
    let mut failure = None;
    for proof in &history {
        let block = verifier.verify(proof)?;
        if let Some(committed) =
            settlement::failed_execution(&block, network, &transaction, &missing_reason())?
        {
            ensure!(failure.is_none(), "duplicate failed transaction");
            publish(
                output,
                "missing-request-committed.norito",
                &norito::encode_canonical(&committed)?,
            )?;
            publish(
                output,
                "missing-request-reason.norito",
                &norito::encode_canonical(&missing_reason())?,
            )?;
            failure = Some(block.height());
        }
    }
    let height = failure.ok_or_else(|| eyre!("missing Request refusal not certified"))?;
    ensure!(
        height == before + 1 && committed_height(network)? == height,
        "exact refusal successor"
    );
    let mut statuses = Vec::new();
    for (index, peer) in network.peers().iter().enumerate() {
        let status = peer
            .client()
            .client()
            .get_transaction_status_response_global(transaction.hash())?;
        ensure!(
            settlement::state_rejection(transaction.hash(), status.as_ref())? == Some(height),
            "all four peers must report the same state rejection"
        );
        let original = publish(
            output,
            &format!("missing-request-status-{index}.norito"),
            &norito::encode_canonical(&status)?,
        )?;
        statuses.push(norito::json!({"peer":(peer.id().to_string()), "original":original}));
    }
    Ok(
        norito::json!({"transaction_hash_hex":(hex::encode(transaction.hash().as_ref())), "height":height,
        "peer_statuses":statuses, "typed_missing_request_refusal":true, "adversarial_proof_qualified":false,
        "scope":"Exact certified missing-history execution refusal after retaining the payer credential; not a negative cryptographic proof."}),
    )
}

fn execute(
    network: &Network,
    rt: &Runtime,
    root: &Path,
    input: &Inputs,
    setup_sha: &str,
    funded: &[u8],
    registered: &registration::Registered,
    issuer: &issuer::Issuer,
) -> Result<()> {
    ensure!(
        committed_height(network)? == 5,
        "dedicated fresh funded H5 required"
    );
    let output = root.join("fee-settlement");
    private_directory(&output)?;
    balances(network, [900, 0, 0, 100])?;
    let retained = KagemushaWalletLedgerV1::new(
        input.scheme,
        Action::RetainCredential {
            credential: input.activation.credential.to_canonical_bytes()?,
            certificates: norito::encode_canonical(&input.activation.certificates)?,
        },
    );
    let (_, retained_height) = submit(
        network,
        41,
        vec![retained.into()],
        &output,
        "retain-payer-signed.norito",
    )?;
    ensure!(
        retained_height == 6,
        "payer history precedes missing Request"
    );
    let absent_key = KagemushaWalletPayoutKeyV1::Fee(input.credit).ledger_key(input.scheme);
    let before = world::capture(
        network,
        rt,
        &output,
        "before-refusal",
        [900, 0, 0, 100],
        &absent_key,
        None,
    )?;
    ensure!(before.height == 6, "exact retained-credential cut");
    let instruction =
        KagemushaWalletLedgerV1::new(input.scheme, Action::ClaimFee(input.claim.clone()));
    let refusal = missing_request(network, &output, &instruction)?;
    let refused = world::capture(
        network,
        rt,
        &output,
        "after-refusal",
        [900, 0, 0, 100],
        &absent_key,
        None,
    )?;
    ensure!(refused.height == 7, "exact missing-history cut");
    ensure!(
        before.rows == refused.rows,
        "failed claim changed KAGEMUSHA ledger state"
    );
    let retained =
        KagemushaWalletLedgerV1::new(input.scheme, Action::RetainRequest(input.request.clone()));
    let (_, request_height) = submit(
        network,
        42,
        vec![retained.into()],
        &output,
        "retain-request-signed.norito",
    )?;
    ensure!(request_height == 8, "historical Request successor");
    balances(network, [900, 0, 0, 100])?;
    let (transaction, paid_height) = submit(
        network,
        42,
        vec![instruction.clone().into()],
        &output,
        "fee-paid-signed.norito",
    )?;
    ensure!(paid_height == 9, "exact first fee payout successor");
    let payout = KagemushaWalletPayoutRecordV1 {
        key: KagemushaWalletPayoutKeyV1::Fee(input.credit),
        source: input.payment_digest,
        amount: 3,
        transaction: *transaction.hash().as_ref(),
    };
    // The expected row is accepted only when its exact canonical value matches the certified World.
    let paid = world::capture(
        network,
        rt,
        &output,
        "after-payout",
        [900, 0, 3, 97],
        &absent_key,
        Some(payout),
    )?;
    ensure!(paid.height == paid_height, "exact original payout cut");
    let (retry, retry_height) = submit(
        network,
        41,
        vec![instruction.clone().into()],
        &output,
        "fee-fresh-retry-signed.norito",
    )?;
    ensure!(
        retry.hash() != transaction.hash() && retry_height == 10,
        "fresh instruction retry must execute"
    );
    let retried = world::capture(
        network,
        rt,
        &output,
        "after-fresh-retry",
        [900, 0, 3, 97],
        &absent_key,
        Some(payout),
    )?;
    ensure!(retried.height == retry_height, "exact fresh retry cut");
    ensure!(
        retried.rows == paid.rows,
        "fresh transaction paid twice or rewrote history"
    );
    let client = running_peer(network)?.client_for(&account(42), key(42).private_key().clone());
    ensure!(
        client.submit_transaction_and_wait(&transaction)? == transaction.hash()
            && committed_height(network)? == retry_height,
        "exact transport retry must return original without a block"
    );
    let genesis = network.native_genesis_provisioning_bundle()?.signed_wire;
    let stores = network
        .peers()
        .iter()
        .map(NetworkPeer::kura_store_dir)
        .collect::<Vec<_>>();
    rt.block_on(async { network.shutdown().await });
    issuer.restart_all(network, rt, registered)?;
    wait_for_committed(network, retry_height, network.sync_timeout(), &[])?;
    ensure!(
        network.native_genesis_provisioning_bundle()?.signed_wire == genesis
            && stores
                == network
                    .peers()
                    .iter()
                    .map(NetworkPeer::kura_store_dir)
                    .collect::<Vec<_>>(),
        "same genesis and node stores required"
    );
    let restarted = world::capture(
        network,
        rt,
        &output,
        "after-restart",
        [900, 0, 3, 97],
        &absent_key,
        Some(payout),
    )?;
    ensure!(
        restarted.rows == paid.rows && restarted.height == retry_height,
        "restart changed payout history"
    );
    let client = running_peer(network)?.client_for(&account(42), key(42).private_key().clone());
    ensure!(
        client.submit_transaction_and_wait(&transaction)? == transaction.hash()
            && committed_height(network)? == retry_height,
        "post-restart exact transaction retry changed outcome"
    );
    let (restart_retry, final_height) = submit(
        network,
        43,
        vec![instruction.clone().into()],
        &output,
        "fee-post-restart-retry-signed.norito",
    )?;
    ensure!(
        restart_retry.hash() != transaction.hash()
            && restart_retry.hash() != retry.hash()
            && final_height == 11,
        "post-restart claim retry must have fresh identity"
    );
    let final_cut = world::capture(
        network,
        rt,
        &output,
        "after-restart-retry",
        [900, 0, 3, 97],
        &absent_key,
        Some(payout),
    )?;
    ensure!(
        final_cut.height == final_height,
        "exact post-restart retry cut"
    );
    ensure!(
        final_cut.rows == paid.rows,
        "post-restart retry changed immutable fee history"
    );
    let evidence = world::export_evidence(&output, input, paid_height, payout, &final_cut)?;
    let mut originals = Vec::new();
    for (name, bytes) in [
        ("producer.json", &input.producer),
        ("target.json", &input.target),
        (FEE_NAMES[0], &input.request),
        (FEE_NAMES[1], &input.payment),
        (FEE_NAMES[2], &input.claim),
    ] {
        originals.push(publish(&output, name, bytes)?);
    }
    originals.push(publish(
        &output,
        "fee-instruction.norito",
        &norito::encode_canonical(&instruction)?,
    )?);
    let result = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.network-fee-settlement.v1", "setup_sha256":setup_sha,
        "funding_sha256":(hash(funded)), "producer_sha256":(hash(&input.producer)),
        "payout_height":paid_height, "last_certified_height":final_height,
        "fee_transaction_hash_hex":(hex::encode(transaction.hash().as_ref())),
        "fee_atomic_units":"3", "balances_atomic_units":["900","0","3","97"],
        "missing_history":refusal, "history_unchanged_on_refusal":true,
        "exact_transaction_retries_returned_original":true, "fresh_transaction_retry_heights":[retry_height,final_height],
        "same_four_node_stores_restarted":true, "payout_row_and_ledger_unchanged_through_retries":true,
        "fee_payout_evidence":evidence, "originals":originals,
        "scope":"Four actual validators execute genuine Send fee payout without a submitted Receive, using ordinary historical credential/Request retention. The typed missing-history refusal preserves every KAGEMUSHA row and all monetary balances. All four certified World cuts authenticate the immutable fee payout before/after fresh signed retries and actual same-store restart. Native producer may already have performed offline Receive/ArchiveReceive; native fee acknowledgement is a separate consumer. No physical-device, enabled-controls, online-charge or release qualification."
    }))?;
    ensure!(result.len() <= 16 << 10, "bounded settlement summary");
    publish(root, "completed.json", &result)?;
    File::open(&output)?.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[test]
#[ignore = "owns four actual validators through fresh dedicated fee target, genuine Send97/fee3 and same-store restart; explicit controller and full admitted catalog required"]
fn execute_four_validator_fee_continuation() -> Result<()> {
    init_instruction_registry();
    let root = PathBuf::from(
        std::env::var_os("KAGEMUSHA_REAL_FEE_CAMPAIGN")
            .ok_or_else(|| eyre!("fee campaign output required"))?,
    );
    ensure!(root.is_absolute(), "absolute fee output required");
    private_directory(&root)?;
    let deadline = Instant::now() + Duration::from_secs(7 * 24 * 60 * 60);
    // Ordinary genesis permission grants the diagnostic reader, not monetary authority.
    let builder = network_builder()
        .with_base_seed("kagemusha-real-fee-v1")
        .with_config_layer(|layer| {
            layer.write("chain", "kagemusha-real-fee-acceptance-v1");
        })
        .with_genesis_instruction(Grant::account_permission(
            iroha_executor_data_model::permission::query::CanReadAllLedgerData,
            account(41),
        ));
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(execute_four_validator_fee_continuation),
    )?
    .ok_or_else(|| eyre!("fee qualification cannot skip"))?;
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        fund_fee_successor(&network)?;
        export(&network, &root.join("setup"))?;
        let setup_sha = hash(&fs::read(root.join("setup/setup.json"))?);
        let ready = norito::json::to_vec(
            &norito::json!({"schema":"iroha.kagemusha.real-network-ready.v1",
            "variant":"fee97-plus3", "setup_sha256":(setup_sha.clone()), "network_hex":(hex::encode(network.network_id().as_bytes())),
            "scope":"Same four live processes retained for dedicated fee campaign; no monetary result yet."}),
        )?;
        publish(&root, "ready.json", &ready)?;
        let command = wait_command(
            &network,
            &root,
            "registration",
            &setup_sha,
            &hash(&ready),
            deadline,
        )?;
        let registered = registration::run(&network, &root, &command, &setup_sha)?;
        let command = wait_command(
            &network,
            &root,
            "issuer",
            &setup_sha,
            &hash(&registered.summary),
            deadline,
        )?;
        let issuer = issuer::run(&network, &rt, &root, &command, &setup_sha, &registered)?;
        let command = wait_command(
            &network,
            &root,
            "funding",
            &setup_sha,
            &hash(&issuer.summary),
            deadline,
        )?;
        let funded = funding::run(&network, &root, &command, &setup_sha, &registered, deadline)?;
        let command = wait_command(
            &network,
            &root,
            "fee-settlement",
            &setup_sha,
            &hash(&funded),
            deadline,
        )?;
        let input = inputs(&command, &setup_sha, &funded, &registered)?;
        require_live_campaign(&network, &root, &setup_sha, deadline)?;
        execute(
            &network,
            &rt,
            &root,
            &input,
            &setup_sha,
            &funded,
            &registered,
            &issuer,
        )
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

#[test]
fn fee_command_requires_exact_selections_and_rejects_abc_phase() -> Result<()> {
    let reference = norito::json!({"path":"/private/original", "sha256":(hash(b"original"))});
    let value = norito::json!({"schema":"iroha.kagemusha.real-network-command.v1", "phase":"fee-settlement",
        "setup_sha256":(hash(b"setup")), "previous_sha256":(hash(b"funded")),
        "producer":(reference.clone()), "target":(reference.clone()), "verifier_pack":reference});
    require_command(&value)?;
    for field in ["producer", "target", "verifier_pack"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        ensure!(
            require_command(&changed).is_err(),
            "missing exact input accepted"
        );
    }
    let mut changed = value.clone();
    changed
        .as_object_mut()
        .unwrap()
        .insert("phase".into(), "settlement".into());
    ensure!(require_command(&changed).is_err(), "ABC phase accepted");
    let mut changed = value;
    changed
        .as_object_mut()
        .unwrap()
        .insert("mock_verifier".into(), true.into());
    ensure!(
        require_command(&changed).is_err(),
        "unknown authority field accepted"
    );
    ensure!(
        matches!(missing_reason(), TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(ref text))) if text == "KAGEMUSHA ledger: ledger record unavailable"),
        "exact missing-history reason"
    );
    Ok(())
}
