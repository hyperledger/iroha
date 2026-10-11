//! Ordinary network Register/Install/Activate/IssueLoad and authenticated event capture.
use super::*;

pub(super) fn run(
    network: &Network,
    root: &Path,
    command: &norito::json::Value,
    setup_sha: &str,
) -> Result<Vec<u8>> {
    ensure!(
        committed_height(network)? == 2,
        "fresh exact H1/H2 selected anchor required"
    );
    let output = root.join("funding");
    private_directory(&output)?;
    let (path, bytes) = selected(command, "target", 16 << 10)?;
    let target: norito::json::Value = norito::json::from_slice(&bytes)?;
    ensure!(
        target["schema"].as_str() == Some("iroha.kagemusha.native-load-target.v1"),
        "target schema"
    );
    require_inventory(
        &target,
        "files",
        &[
            "account.norito",
            "asset.norito",
            "credential.norito",
            "certificates.norito",
            "bootstrap.norito",
            "activation.norito",
            "issue-load.norito",
        ],
    )?;
    ensure!(
        target["executed_ledger_setup_sha256"].as_str() == Some(setup_sha),
        "foreign executed setup"
    );
    let anchor = native(network)?;
    ensure!(
        target["native_chain_id"].as_str() == Some(network.chain_id().to_string().as_str())
            && digest(&target["native_instance"])? == anchor.instance().0,
        "foreign target network instance"
    );
    ensure!(
        target["native_initial_epoch_sha256"].as_str()
            == Some(hash(&norito::encode_canonical(anchor.initial_epoch())?).as_str()),
        "foreign epoch original"
    );
    let source = path.parent().ok_or_else(|| eyre!("target parent"))?;
    let owner: AccountId = canonical(&original(source, &target, "files", "account.norito", 4096)?)?;
    let asset: KagemushaWalletAssetScopeV1 =
        canonical(&original(source, &target, "files", "asset.norito", 4096)?)?;
    let setup: norito::json::Value =
        norito::json::from_slice(&read(&root.join("setup/setup.json"), 16 << 10, setup_sha)?)?;
    ensure!(
        owner == account(41)
            && asset
                == canonical::<KagemushaWalletAssetScopeV1>(&original(
                    &root.join("setup"),
                    &setup,
                    "originals",
                    "asset.norito",
                    4096
                )?)?,
        "target account or exact executed incarnation differs"
    );
    let scheme_id = digest(&target["scheme_id"])?;
    let manifest = digest(&target["manifest_digest"])?;
    let (_, pack) = selected(command, "verifier_pack", VERIFIER_PACK_MAX_BYTES_V1)?;
    let admitted = InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id,
            manifest_digest: manifest,
        },
    )?;
    let scheme = *admitted.verifier().scheme();
    ensure!(
        scheme.network_id == *network.network_id().as_bytes(),
        "verifier pack network"
    );
    let activation_bytes = original(
        source,
        &target,
        "files",
        "activation.norito",
        KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    )?;
    let activation = KagemushaWalletActivationV1::decode_canonical(&activation_bytes, &scheme_id)?;
    ensure!(
        activation.asset == asset
            && activation.credential.body.account_digest
                == kagemusha_wallet_account_digest_v1(&owner)?,
        "activation account/asset"
    );
    ensure!(
        activation.credential.to_canonical_bytes()?
            == original(
                source,
                &target,
                "files",
                "credential.norito",
                KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
            )?,
        "credential original"
    );
    ensure!(
        norito::encode_canonical(&activation.certificates)?
            == original(source, &target, "files", "certificates.norito", 32768)?,
        "certificate originals"
    );
    ensure!(
        norito::encode_canonical(&activation.bootstrap)?
            == original(
                source,
                &target,
                "files",
                "bootstrap.norito",
                KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
            )?,
        "bootstrap original"
    );
    let load: KagemushaWalletLedgerV1 = canonical(&original(
        source,
        &target,
        "files",
        "issue-load.norito",
        4096,
    )?)?;
    let wallet = activation.credential.body.wallet_id;
    let request_id = [201; 32];
    ensure!(
        load == KagemushaWalletLedgerV1::new(
            scheme_id,
            Action::IssueLoad {
                wallet,
                asset: asset.asset_digest(),
                ordinal: 0,
                request_id,
                amount: 100,
                charge: None
            }
        ),
        "exact retained Load instruction"
    );
    let register = KagemushaWalletLedgerV1::new(
        scheme_id,
        Action::Register {
            scheme: scheme.to_canonical_bytes()?,
            asset: norito::encode_canonical(&asset)?,
            reserve: account(95),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let install = KagemushaWalletLedgerV1::new(
        scheme_id,
        Action::InstallVerifierPack {
            asset: asset.asset_digest(),
            manifest_digest: manifest,
            pack,
        },
    );
    let (_, h3) = submit(
        network,
        95,
        vec![register.into(), install.into()],
        &output,
        "register-install-signed.norito",
    )?;
    ensure!(h3 == 3, "unexpected intervening network block");
    let (_, h4) = submit(
        network,
        41,
        vec![KagemushaWalletLedgerV1::new(scheme_id, Action::Activate(activation_bytes)).into()],
        &output,
        "activate-signed.norito",
    )?;
    ensure!(h4 == 4, "unexpected intervening network block");
    let (load_transaction, h5) = submit(
        network,
        41,
        vec![load.into()],
        &output,
        "issue-load-signed.norito",
    )?;
    ensure!(
        h5 == 5,
        "the fixed genuine Load producer requires exact H1..H5"
    );
    let snapshots = balances(network, [900, 0, 0, 100])?;
    let history = prefix(network, 5)?;
    let mut verifier = native(network)?;
    let mut originals = Vec::new();
    let mut blocks = Vec::new();
    let mut last = None;
    let mut previous = None;
    for proof in &history {
        let block = verifier.verify(proof)?;
        originals.push(publish(
            &output,
            &format!("block-{}.wire", proof.height()),
            &proof.block_wire,
        )?);
        originals.push(publish(
            &output,
            &format!("native-proof-{}.norito", proof.height()),
            &norito::encode_canonical(proof)?,
        )?);
        if proof.height() > 1 {
            blocks.push(block_capture(&block)?);
        }
        if proof.height() == 5 {
            inclusion(&block, network, &load_transaction)?;
        }
        if proof.height() == 4 {
            previous = Some(block.clone());
        }
        last = Some(block);
    }
    let block = last.ok_or_else(|| eyre!("funded block missing"))?;
    let previous = previous.ok_or_else(|| eyre!("previous certified block missing"))?;
    let mut exact_receipt = None;
    let mut exact_path = None;
    for peer in network.peers() {
        let client = peer.client_for(&owner, key(41).private_key().clone());
        let client = iroha::blocking::AccountClient::from_client(client.account_client().clone())?;
        let receipt = client
            .kagemusha()
            .load_issuance(&scheme_id, &wallet, &request_id)?;
        ensure!(
            (receipt.ordinal, receipt.amount, receipt.block_height) == (0, 100, 5),
            "live receipt terms"
        );
        // The service returns DATA; only the independently selected signed genesis
        // and original H5 certificate can authorize this receipt's event inclusion.
        let mut finality = client.kagemusha().load_finality(&receipt)?;
        finality.verify(&anchor, &receipt)?;
        let certificate = block
            .block()
            .commit_certificate()
            .ok_or_else(|| eyre!("Load block certificate missing"))?;
        ensure!(
            finality.certificate.consensus_header.as_slice() == certificate.consensus_header()
                && finality.certificate.commit_qc.as_slice() == certificate.commit_qc()
                && finality.certificate.result_preimage.as_slice() == certificate.result_preimage(),
            "live Load finality differs from the original authenticated block"
        );
        let previous_certificate =
            iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1::from_verified(
                &previous,
            )?;
        let original_certificate =
            std::mem::replace(&mut finality.certificate, previous_certificate);
        let substituted_certificate_rejected = finality.verify(&anchor, &receipt).is_err();
        finality.certificate = original_certificate;
        ensure!(
            substituted_certificate_rejected,
            "a previous authenticated certificate must not authorize the live Load receipt"
        );
        let event_path = finality.event_proof;
        let verified = verify_finalized_kagemusha_wallet_load_event_v1(
            &block,
            &event_path,
            network.network_id(),
            &network.chain_id().to_string(),
            &receipt,
        )?;
        ensure!(
            verified.receipt() == &receipt,
            "authenticated receipt differs"
        );
        let mut foreign_receipt = receipt;
        foreign_receipt.amount = foreign_receipt
            .amount
            .checked_add(1)
            .ok_or_else(|| eyre!("amount overflow"))?;
        let foreign_path = iroha_crypto::MerkleProof::from_audit_path(
            event_path.leaf_index() ^ 1,
            event_path.audit_path().to_vec(),
        );
        for (candidate_block, candidate_path, candidate_receipt) in [
            (&block, &event_path, &foreign_receipt),
            (&previous, &event_path, &receipt),
            (&block, &foreign_path, &receipt),
        ] {
            ensure!(
                verify_finalized_kagemusha_wallet_load_event_v1(
                    candidate_block,
                    candidate_path,
                    network.network_id(),
                    &network.chain_id().to_string(),
                    candidate_receipt,
                )
                .is_err(),
                "foreign live receipt, block, or event index accepted"
            );
        }
        let frame = norito::encode_canonical(&receipt)?;
        let path_frame = norito::encode_canonical(&event_path)?;
        if let Some(prior) = &exact_receipt {
            ensure!(prior == &frame, "peers returned different receipt");
        }
        if let Some(prior) = &exact_path {
            ensure!(prior == &path_frame, "peers returned different event proof");
        }
        exact_receipt = Some(frame);
        exact_path = Some(path_frame);
    }
    let receipt_frame = exact_receipt.ok_or_else(|| eyre!("receipt missing"))?;
    let receipt: iroha_data_model::isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1 = canonical(&receipt_frame)?;
    let path: iroha_crypto::MerkleProof<iroha_data_model::events::EventBox> =
        canonical(&exact_path.ok_or_else(|| eyre!("event proof missing"))?)?;
    let commitment = block
        .execution()
        .event_commitment
        .as_ref()
        .ok_or_else(|| eyre!("event commitment missing"))?;
    ensure!(path.audit_path().len() <= 32, "event path bound");
    let mut siblings = [[0u8; 32]; 32];
    for (value, out) in path.audit_path().iter().zip(&mut siblings) {
        if let Some(value) = value {
            *out = *value.as_ref();
        }
    }
    originals.push(publish(&output, "receipt.norito", &receipt_frame)?);
    let mut capture: norito::json::Value = norito::json::from_slice(&original(
        &root.join("setup"),
        &setup,
        "originals",
        "capture.json",
        JSON_MAX,
    )?)?;
    let object = capture
        .as_object_mut()
        .ok_or_else(|| eyre!("capture object required"))?;
    object.insert("scope".into(), "Actual four-validator Register/Install/Activate/IssueLoad and independently verified account-authenticated event proof; no mocked finality.".into());
    object.insert("blocks".into(), norito::json::to_value(&blocks)?);
    object.insert("native_target_sha256".into(), hash(&bytes).into());
    object.insert("originals".into(), norito::json::to_value(&originals)?);
    object.insert("load".into(), norito::json!({
        "result_preimage_hex": (hex::encode(block.commitment().preimage()?)),
        "receipt_frame_hex": (hex::encode(&receipt_frame)), "receipt_transcript_hex": (hex::encode(receipt.transcript()?)), "receipt_digest_hex": (hex::encode(receipt.receipt_digest()?)),
        "event_commitment_root_hex": (hex::encode(commitment.root().as_ref())), "event_commitment_count": (commitment.leaf_count().get()), "event_index": (path.leaf_index()), "event_siblings_hex": (siblings.iter().map(hex::encode).collect::<Vec<_>>())
    }));
    let capture = norito::json::to_vec(&capture)?;
    publish(&output, "capture.json", &capture)?;
    let result = norito::json::to_vec(
        &norito::json!({"schema":"iroha.kagemusha.network-funded-load.v1", "setup_sha256":setup_sha, "target_sha256":(hash(&bytes)), "source_pins":(target["source_pins"].clone()), "capture_sha256":(hash(&capture)), "receipt_sha256":(hash(&receipt_frame)), "balances":snapshots, "load_transaction_hash_hex":(hex::encode(load_transaction.hash().as_ref())), "certified_height":5}),
    )?;
    publish(root, "funded.json", &result)?;
    Ok(result)
}

fn block_capture(block: &VerifiedSumeragiBlock) -> Result<norito::json::Value> {
    let cert = block
        .block()
        .commit_certificate()
        .ok_or_else(|| eyre!("certificate missing"))?;
    let qc: iroha_sumeragi::message::Qc = canonical(cert.commit_qc())?;
    let schedule = &block.commitment().schedule;
    ensure!(
        schedule.boundary.is_none(),
        "unexpected epoch boundary in fixed five-block setup"
    );
    let mut keys = Vec::new();
    let mut pops = Vec::new();
    for member in &schedule.current.committee {
        let (algorithm, bytes) = member.validator.public_key().try_to_bytes()?;
        ensure!(
            algorithm == Algorithm::BlsNormal,
            "canonical committee algorithm"
        );
        keys.push(hex::encode(bytes));
        pops.push(hex::encode(&member.proof_of_possession));
    }
    Ok(
        norito::json!({"height":(block.height()), "result_preimage_hex":(hex::encode(block.commitment().preimage()?)), "result_hash_hex":(hex::encode(block.result().0)), "commit_vote_preimage_hex":(hex::encode(qc.preimage())), "qc_bitmap_hex":(hex::encode(qc.signers.as_bytes())), "qc_aggregate_signature_hex":(hex::encode(qc.agg_sig.0)), "committee_public_keys_hex":keys, "committee_proofs_of_possession_hex":pops, "authenticated_schedule":{"current":{"context_id_hex":(hex::encode(schedule.current.context_id().map_err(|e| eyre!(e))?))}, "boundary":(norito::json::Value::Null)}}),
    )
}
