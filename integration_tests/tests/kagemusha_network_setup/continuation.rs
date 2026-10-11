//! Long-running four-peer monetary owner; external proof work never replaces this Network.
//!
//! TODO: Compile and execute this explicit ignored campaign with independently admitted
//! stock binaries, a new-anchor catalog, genuine native wallets, and same-C confirmation.
use super::*;
use iroha::client::{AccountTransactionDraft, FeeQuoteRequest};
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    asset::AssetBalanceScope,
    isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1,
        load_finality::verify_finalized_kagemusha_wallet_load_event_v1,
    },
    kagemusha::*,
    query::CommittedTransaction,
    sumeragi_finality::VerifiedSumeragiBlock,
};
use iroha_model_base::metadata::Metadata;
use std::{collections::BTreeSet, io::Read as _, path::PathBuf};

const JSON_MAX: usize = 16 << 20;
const ORIGINAL_MAX: usize = 16 << 20;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn digest(value: &norito::json::Value) -> Result<[u8; 32]> {
    let text = value
        .as_str()
        .ok_or_else(|| eyre!("digest string required"))?;
    let bytes: [u8; 32] = hex::decode(text)?
        .try_into()
        .map_err(|_| eyre!("digest extent"))?;
    ensure!(
        bytes != [0; 32] && hex::encode(bytes) == text,
        "canonical nonzero digest"
    );
    Ok(bytes)
}
fn canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'a> T: norito::NoritoDeserialize<'a>,
{
    Ok(norito::decode_canonical_with_limits(
        bytes,
        norito::canonical_decode_limits(bytes.len()),
    )?)
}
fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// These are bounded DATA originals. Their digests do not grant network or wallet authority.
fn read_original(path: &Path, maximum: usize, expected: Option<&str>) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "absolute selected original required");
    if let Some(expected) = expected {
        ensure!(
            expected.len() == 64 && hex::decode(expected)?.len() == 32,
            "SHA-256 pin"
        );
    }
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.file_type().is_file() && before.len() > 0 && before.len() <= maximum as u64,
        "bounded regular original"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        ensure!(
            before.uid() == rustix::process::geteuid().as_raw()
                && before.mode() & 0o077 == 0
                && before.nlink() == 1,
            "private single-link original required"
        );
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            (before.dev(), before.ino()) == (opened.dev(), opened.ino()),
            "original replaced before open"
        );
    }
    ensure!(opened.len() == before.len(), "original extent changed");
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && expected.is_none_or(|expected| hash(&bytes) == expected),
        "original extent or SHA-256 changed"
    );
    let after = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            (
                before.dev(),
                before.ino(),
                before.ctime(),
                before.ctime_nsec(),
                before.mtime(),
                before.mtime_nsec(),
                before.mode(),
                before.nlink()
            ) == (
                after.dev(),
                after.ino(),
                after.ctime(),
                after.ctime_nsec(),
                after.mtime(),
                after.mtime_nsec(),
                after.mode(),
                after.nlink()
            ),
            "original custody changed during read"
        );
    }
    ensure!(after.len() == before.len(), "original changed during read");
    Ok(bytes)
}
fn read(path: &Path, maximum: usize, expected: &str) -> Result<Vec<u8>> {
    read_original(path, maximum, Some(expected))
}

fn require_inventory(manifest: &norito::json::Value, field: &str, names: &[&str]) -> Result<()> {
    let rows = manifest[field]
        .as_array()
        .ok_or_else(|| eyre!("original inventory required"))?;
    let mut observed = BTreeSet::new();
    for row in rows {
        let name = row["name"]
            .as_str()
            .ok_or_else(|| eyre!("original name required"))?;
        ensure!(observed.insert(name), "duplicate original role");
    }
    ensure!(
        observed == names.iter().copied().collect(),
        "exact original roles required"
    );
    Ok(())
}

fn original(
    root: &Path,
    manifest: &norito::json::Value,
    field: &str,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let rows = manifest[field]
        .as_array()
        .ok_or_else(|| eyre!("original inventory required"))?;
    let rows = rows
        .iter()
        .filter(|row| row["name"].as_str() == Some(name))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "exactly one selected role required");
    let row = rows[0];
    let expected = row["sha256"]
        .as_str()
        .ok_or_else(|| eyre!("original pin required"))?;
    let bytes = read(&root.join(name), maximum, expected)?;
    ensure!(
        row["bytes"].as_u64() == Some(bytes.len() as u64),
        "declared original extent"
    );
    Ok(bytes)
}
fn selected(
    command: &norito::json::Value,
    name: &str,
    maximum: usize,
) -> Result<(PathBuf, Vec<u8>)> {
    let path = PathBuf::from(
        command[name]["path"]
            .as_str()
            .ok_or_else(|| eyre!("selected path required"))?,
    );
    let expected = command[name]["sha256"]
        .as_str()
        .ok_or_else(|| eyre!("selected hash required"))?;
    let bytes = read(&path, maximum, expected)?;
    Ok((path, bytes))
}

fn native(network: &Network) -> Result<SumeragiFinalityVerifier> {
    let bundle = network.native_genesis_provisioning_bundle()?;
    let manifest = norito::json::from_slice(&bundle.manifest_json)?;
    let genesis = iroha_genesis::validate_prepared_genesis_bundle(
        &bundle.signed_wire,
        &manifest,
        &bundle.public_key,
        bundle.block_hash,
    )?;
    let roster = genesis
        .validator_pops()
        .iter()
        .map(|(key, pop)| FinalityValidator {
            public_key: key.clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    Ok(SumeragiFinalityVerifier::new(
        genesis.block(),
        &network.chain_id().to_string(),
        roster,
    )?)
}

fn prefix(network: &Network, through: u64) -> Result<Vec<SumeragiFinalityProof>> {
    ensure!(
        through > 0 && through <= 64,
        "bounded observed campaign history"
    );
    wait_for_committed(network, through, network.sync_timeout(), &[])?;
    let mut reference: Vec<SumeragiFinalityProof> = Vec::new();
    for peer in network.peers() {
        ensure!(peer.is_running(), "same four actual peers must remain live");
        let client = peer.client();
        let client = client
            .client()
            .clone()
            .with_request_deadline(Instant::now() + Duration::from_secs(120));
        let mut verifier = native(network)?;
        let mut current = Vec::new();
        for height in 1..=through {
            let proof = client.get_sumeragi_finality_proof(NonZeroU64::new(height).unwrap())?;
            let verified = verifier.verify(&proof)?;
            ensure!(
                proof.height() == height && proof.committee.len() == 4,
                "exact ordered four-seat history"
            );
            if height > 1 {
                let cert = verified
                    .block()
                    .commit_certificate()
                    .ok_or_else(|| eyre!("missing certificate"))?;
                let qc: iroha_sumeragi::message::Qc = canonical(cert.commit_qc())?;
                ensure!(qc.signers.count_ones() == 3, "exact quorum required");
            }
            if !reference.is_empty() {
                ensure!(
                    proof.block_wire == reference[usize::try_from(height - 1)?].block_wire,
                    "peers disagree on canonical certified block"
                );
            }
            current.push(proof);
        }
        if reference.is_empty() {
            reference = current;
        }
    }
    Ok(reference)
}

fn inclusion(
    block: &VerifiedSumeragiBlock,
    network: &Network,
    signed: &SignedTransaction,
) -> Result<()> {
    let body = block.block();
    let index = body
        .network_entrypoints()
        .position(|entry| entry.hash().as_ref() == signed.hash().as_ref())
        .ok_or_else(|| eyre!("exact signed transaction absent"))?;
    let input_index = u32::try_from(index)?;
    let entrypoint = body
        .network_entrypoint_at(index)
        .ok_or_else(|| eyre!("entrypoint missing"))?
        .clone();
    let iroha_data_model::transaction::TransactionEntrypoint::External(actual) = &entrypoint else {
        bail!("external original required")
    };
    ensure!(
        norito::encode_canonical(actual)? == norito::encode_canonical(signed)?,
        "signed original changed"
    );
    let (output_index, _) = body
        .network_output_at(input_index)
        .ok_or_else(|| eyre!("output missing"))?;
    let output = body
        .execution_outputs()
        .get(output_index as usize)
        .ok_or_else(|| eyre!("output index"))?
        .clone();
    let committed = CommittedTransaction {
        block_hash: body.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: body
            .network_input_proof(input_index)
            .ok_or_else(|| eyre!("input membership missing"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: body
            .output_proof(output_index)
            .ok_or_else(|| eyre!("output membership missing"))?,
        output,
    };
    block.verify_committed_transaction(&network.network_id(), &committed)?;
    Ok(())
}

fn signed(
    network: &Network,
    seed: u8,
    instructions: Vec<InstructionBox>,
) -> Result<SignedTransaction> {
    let client = running_peer(network)?.client_for(&account(seed), key(seed).private_key().clone());
    let mut payload = client
        .account_client()
        .prepare_transaction(AccountTransactionDraft::new(
            instructions,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))?;
    let quote = client.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    Ok(client.account_client().sign_transaction(payload)?)
}
fn submit(
    network: &Network,
    seed: u8,
    instructions: Vec<InstructionBox>,
    root: &Path,
    name: &str,
) -> Result<(SignedTransaction, u64)> {
    let transaction = signed(network, seed, instructions)?;
    publish(root, name, &norito::encode_canonical(&transaction)?)?;
    File::open(root)?.sync_all()?; // Retain exact signed retry authority before dispatch.
    let client = running_peer(network)?.client_for(&account(seed), key(seed).private_key().clone());
    let hash = client.submit_transaction_and_wait(&transaction)?;
    ensure!(
        hash == transaction.hash(),
        "submission returned foreign hash"
    );
    let height = committed_height(network)?;
    let history = prefix(network, height)?;
    let mut verifier = native(network)?;
    let mut found = None;
    for proof in history {
        let block = verifier.verify(&proof)?;
        if block
            .block()
            .network_entrypoints()
            .any(|entry| entry.hash().as_ref() == hash.as_ref())
        {
            ensure!(found.is_none(), "transaction appears twice");
            inclusion(&block, network, &transaction)?;
            found = Some(block.height());
        }
    }
    Ok((
        transaction,
        found.ok_or_else(|| eyre!("successful transaction not in certified history"))?,
    ))
}

fn balances(network: &Network, expected: [u128; 4]) -> Result<Vec<norito::json::Value>> {
    let mut snapshots = Vec::new();
    for peer in network.peers() {
        let client = peer.client();
        let assets = client.client().query(FindAssets::new()).execute_all()?;
        let selected = assets
            .iter()
            .filter(|a| a.id().definition() == &definition_id())
            .collect::<Vec<_>>();
        let total = selected
            .iter()
            .try_fold(Quantity::zero(), |sum, a| sum.checked_add(a.value()))
            .map_err(|error| eyre!("balance overflow: {error}"))?;
        ensure!(total == quantity(), "all-bucket conservation failed");
        for (seed, amount) in [41, 42, 43, 95].into_iter().zip(expected) {
            let id = AssetId::of(definition_id(), account(seed));
            let actual = selected
                .iter()
                .find(|asset| asset.id() == &id)
                .map_or_else(Quantity::zero, |asset| asset.value().clone());
            ensure!(
                actual == Quantity::from_canonical_numeric(Numeric::new(amount, SCALE))?,
                "wrong role balance {seed}"
            );
        }
        let definitions = client
            .client()
            .query(FindAssetDefinitions::new())
            .execute_all()?;
        ensure!(
            definitions
                .iter()
                .find(|d| d.id() == &definition_id())
                .is_some_and(|d| d.total_quantity() == &quantity()),
            "supply changed"
        );
        snapshots.push(norito::json!({"peer": (peer.id().to_string()), "balances_atomic": (expected.map(|v| v.to_string()).to_vec()), "all_bucket_total_atomic": (SUPPLY.to_string())}));
    }
    Ok(snapshots)
}

// Explicit controller DATA cancellation is observed only at stage boundaries. It
// requests this owner's normal shutdown and never signals unrelated processes.
fn abort_requested(root: &Path, setup_sha: &str) -> Result<bool> {
    let path = root.join("abort-command.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_original(&path, 16 << 10, None)?;
            let value: norito::json::Value = norito::json::from_slice(&bytes)?;
            ensure!(
                value["schema"].as_str() == Some("iroha.kagemusha.real-network-abort.v1")
                    && value["setup_sha256"].as_str() == Some(setup_sha),
                "foreign abort command"
            );
            digest(&value["failure_sha256"])?;
            publish(root, "abort-accepted.json", &bytes)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn wait_command(
    network: &Network,
    root: &Path,
    phase: &str,
    setup_sha: &str,
    previous_sha: &str,
    deadline: Instant,
) -> Result<norito::json::Value> {
    let path = root.join(format!("{phase}-command.json"));
    loop {
        ensure!(
            !abort_requested(root, setup_sha)?,
            "controller aborted campaign; preserve partial outputs and shut down owned peers"
        );
        ensure!(
            Instant::now() < deadline,
            "campaign deadline reached; retain exact partial state, no automatic restart"
        );
        ensure!(
            network.peers().iter().all(NetworkPeer::is_running),
            "live network owner lost a peer"
        );
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(metadata.file_type().is_file(), "command must be regular");
                ensure!(
                    metadata.len() > 0 && metadata.len() <= 16 << 10,
                    "bounded command"
                );
                let bytes = read_original(&path, 16 << 10, None)?;
                let value: norito::json::Value = norito::json::from_slice(&bytes)?;
                ensure!(
                    value["schema"].as_str() == Some("iroha.kagemusha.real-network-command.v1")
                        && value["phase"].as_str() == Some(phase),
                    "wrong command phase"
                );
                ensure!(
                    value["setup_sha256"].as_str() == Some(setup_sha)
                        && value["previous_sha256"].as_str() == Some(previous_sha),
                    "foreign command chain"
                );
                publish(root, &format!("{phase}-accepted.json"), &bytes)?;
                return Ok(value);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_secs(1))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[path = "continuation/funding.rs"]
mod funding;
#[path = "continuation/settlement.rs"]
mod settlement;

#[test]
#[ignore = "owns four actual validators through fresh-anchor catalog, genuine native ABC, settlement and retained-C confirmation; explicit controller required"]
fn execute_four_validator_monetary_continuation() -> Result<()> {
    init_instruction_registry();
    let root = PathBuf::from(
        std::env::var_os("KAGEMUSHA_REAL_NETWORK_CAMPAIGN")
            .ok_or_else(|| eyre!("campaign output required"))?,
    );
    ensure!(root.is_absolute(), "absolute output required");
    private_directory(&root)?;
    let deadline = Instant::now() + Duration::from_secs(7 * 24 * 60 * 60);
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        network_builder(),
        stringify!(execute_four_validator_monetary_continuation),
    )?
    .ok_or_else(|| eyre!("qualification cannot skip"))?;
    let result = (|| -> Result<()> {
        wait_for_committed(&network, 1, network.sync_timeout(), &[])?;
        fund_fee_successor(&network)?;
        export(&network, &root.join("setup"))?;
        let setup_sha = hash(&fs::read(root.join("setup/setup.json"))?);
        let ready = norito::json::to_vec(
            &norito::json!({"schema":"iroha.kagemusha.real-network-ready.v1", "setup_sha256": (setup_sha.clone()), "network_hex": (hex::encode(network.network_id().as_bytes())), "scope":"Same four live processes retained; no catalog or monetary result yet."}),
        )?;
        publish(&root, "ready.json", &ready)?;
        let command = wait_command(
            &network,
            &root,
            "funding",
            &setup_sha,
            &hash(&ready),
            deadline,
        )?;
        let funded = funding::run(&network, &root, &command, &setup_sha)?;
        let command = wait_command(
            &network,
            &root,
            "settlement",
            &setup_sha,
            &hash(&funded),
            deadline,
        )?;
        let settled = settlement::run(&network, &root, &command, &setup_sha, &funded)?;
        let command = wait_command(
            &network,
            &root,
            "confirmed",
            &setup_sha,
            &hash(&settled),
            deadline,
        )?;
        let (_, confirmation) = selected(&command, "confirmation", 16 << 10)?;
        let result: norito::json::Value = norito::json::from_slice(&confirmation)?;
        ensure!(
            result["schema"].as_str()
                == Some("iroha.kagemusha.native-network-settlement-confirmation.v1")
                && result["settlement_sha256"].as_str() == Some(hash(&settled).as_str())
                && result["new_payment_signatures"].as_u64() == Some(0),
            "exact retained-C confirmation DATA required"
        );
        // The independently admitted native consumer verifies this DATA. The live
        // network gate additionally verifies state before and after real peer restart.
        balances(&network, [900, 0, 100, 0])?;
        let before = network.native_genesis_provisioning_bundle()?.signed_wire;
        let height = committed_height(&network)?;
        rt.block_on(async { network.shutdown().await });
        rt.block_on(network.start_all())?;
        wait_for_committed(&network, height, network.sync_timeout(), &[])?;
        ensure!(
            network.native_genesis_provisioning_bundle()?.signed_wire == before,
            "restart changed genesis"
        );
        prefix(&network, height)?;
        balances(&network, [900, 0, 100, 0])?;
        let settlement: norito::json::Value = norito::json::from_slice(&settled)?;
        let settlement_root = root.join("settlement");
        let transaction: SignedTransaction = canonical(&original(
            &settlement_root,
            &settlement,
            "originals",
            "unload-signed-transaction.norito",
            ORIGINAL_MAX,
        )?)?;
        ensure!(
            transaction.hash().as_ref() == &digest(&settlement["settlement_transaction_hash_hex"])?,
            "retained Unload transaction differs"
        );
        let client =
            running_peer(&network)?.client_for(&account(43), key(43).private_key().clone());
        ensure!(
            client.submit_transaction_and_wait(&transaction)? == transaction.hash(),
            "post-restart transport retry changed identity"
        );
        ensure!(
            committed_height(&network)? == height,
            "post-restart exact transaction retry created a new block"
        );
        balances(&network, [900, 0, 100, 0])?;
        // A fresh transaction bypasses transaction-hash replay handling and must
        // use the durable Unload payout record without transferring funds again.
        let instruction: KagemushaWalletLedgerV1 = canonical(&original(
            &settlement_root,
            &settlement,
            "originals",
            "unload-instruction.norito",
            ORIGINAL_MAX,
        )?)?;
        let (retry, retry_height) = submit(
            &network,
            43,
            vec![instruction.into()],
            &root,
            "post-restart-unload-retry-signed.norito",
        )?;
        ensure!(
            retry.hash() != transaction.hash() && retry_height > height,
            "post-restart instruction retry must execute in a fresh certified block"
        );
        let snapshots = balances(&network, [900, 0, 100, 0])?;
        publish(
            &root,
            "completed.json",
            &norito::json::to_vec(
                &norito::json!({"schema":"iroha.kagemusha.real-network-monetary-result.v1", "setup_sha256":setup_sha, "funding_sha256":(hash(&funded)), "settlement_sha256":(hash(&settled)), "confirmation_sha256":(hash(&confirmation)), "restarted_height":height, "post_restart_exact_transaction_retry_returned_original":true, "post_restart_instruction_retry_height":retry_height, "post_restart_instruction_retry_hash_hex":(hex::encode(retry.hash().as_ref())), "post_restart_instruction_retry_original_sha256":(hash(&norito::encode_canonical(&retry)?)), "balances_after_restart":snapshots, "adversarial_qualified":(settlement["adversarial_qualified"].clone()), "scope":"Real four-validator execution, same-node-store restart and post-restart exact transport/fresh-instruction replay without another payout; genuine-proof/native-consumer evidence selected separately, software platform fixture, no physical device or live bank qualification."}),
            )?,
        )?;
        Ok(())
    })();
    rt.block_on(async { network.shutdown().await });
    result
}

#[test]
fn selected_original_reads_are_bounded_private_and_pinned() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let bytes = b"retained original";
    publish(root, "original", bytes)?;
    let path = root.join("original");
    ensure!(
        read(&path, bytes.len(), &hash(bytes))? == bytes,
        "exact pinned original"
    );
    ensure!(
        read_original(&path, bytes.len(), None)? == bytes,
        "bounded unpinned command DATA"
    );
    ensure!(
        read(&path, bytes.len() - 1, &hash(bytes)).is_err(),
        "extent before read"
    );
    ensure!(
        read(&path, bytes.len(), &hash(b"different")).is_err(),
        "changed pin"
    );
    let sparse = root.join("sparse");
    publish(root, "sparse", b"x")?;
    OpenOptions::new()
        .write(true)
        .open(&sparse)?
        .set_len(1 << 30)?;
    ensure!(
        read_original(&sparse, 16 << 10, None).is_err(),
        "no unbounded preliminary allocation"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let link = root.join("link");
        symlink(&path, &link)?;
        ensure!(
            read_original(&link, bytes.len(), None).is_err(),
            "symlink source"
        );
        let hard = root.join("hard");
        fs::hard_link(&path, &hard)?;
        ensure!(
            read_original(&path, bytes.len(), None).is_err(),
            "multiply linked source"
        );
        fs::remove_file(hard)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        ensure!(
            read_original(&path, bytes.len(), None).is_err(),
            "public source"
        );
    }
    Ok(())
}

#[test]
fn inventory_refuses_duplicate_missing_and_unknown_roles() -> Result<()> {
    let valid = norito::json!({"files":[{"name":"one"},{"name":"two"}]});
    require_inventory(&valid, "files", &["one", "two"])?;
    for rows in [
        vec!["one"],
        vec!["one", "one"],
        vec!["one", "two", "three"],
        vec!["one", "../two"],
    ] {
        let changed = norito::json!({"files":(rows.into_iter().map(|name| norito::json!({"name":name})).collect::<Vec<_>>())});
        ensure!(
            require_inventory(&changed, "files", &["one", "two"]).is_err(),
            "changed inventory"
        );
    }
    Ok(())
}

#[test]
fn abort_requires_exact_setup_and_failure_pins() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let setup_sha = hash(b"setup");
    ensure!(
        !abort_requested(directory.path(), &setup_sha)?,
        "no abort yet"
    );
    publish(
        directory.path(),
        "abort-command.json",
        &norito::json::to_vec(
            &norito::json!({"schema":"iroha.kagemusha.real-network-abort.v1",
                       "setup_sha256":setup_sha, "failure_sha256":(hash(b"failure"))}),
        )?,
    )?;
    ensure!(
        abort_requested(directory.path(), &hash(b"different")).is_err(),
        "foreign setup"
    );
    ensure!(
        abort_requested(directory.path(), &hash(b"setup"))?,
        "owned normal shutdown"
    );
    ensure!(
        directory.path().join("abort-accepted.json").is_file(),
        "retained abort original"
    );
    Ok(())
}
