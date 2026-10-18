//! Native H2–H5 beacon provisioning over the same retained four-validator network.
//!
//! Ordinary peers use `iroha3d`. The maintained DKG helper resolves `iroha3d_taira`
//! only for its native `beacon-bootstrap` worker commands, then provisions a separate
//! disposable provider broker per seat. Keep the returned DKG owner alive throughout
//! the campaign: its private credentials belong to individual seat roots.
use super::super::{account, key};
use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha::{blocking::Client, data_model::prelude::*};
use iroha_core::{
    beacon::credential::global_beacon_partial_signer_public_inventory_digest_v1,
    sumeragi::native_journal::NativeJournalCursor,
};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    sumeragi::finality::{NativeFinalityArtifact, NativeFinalityJournal, NativeFinalityLimits},
    transaction::FeePaymentIntent,
};
use iroha_model_base::peer::PeerId;
use iroha_test_network::{
    DisposableBeaconProviderBinding, DisposableGenesisDkgOutput, Network, read_on_dedicated_thread,
    run_disposable_genesis_dkg,
};
use irohad::{
    IrohaRuntimeProviderBindingsV1,
    external_software_signer::encode_consensus_threshold_credential_bundle_v1,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    num::NonZeroU64,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::Path,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

#[path = "../../support/committee_status.rs"]
mod committee_status;

const INSTALL_HEIGHT: u64 = 5;
const PHASE_BUDGET: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(150);

#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct NativeProviderManifest {
    signer_index: u16,
    validator: PeerId,
    handle: String,
    revision: u64,
    policy_digest: [u8; 32],
}

fn limits() -> NativeFinalityLimits {
    NativeFinalityLimits {
        block_bytes: 32 << 20,
        journal_bytes: 64 << 20,
        block_count: 5,
        allocated_bytes: 512 << 20,
    }
}

fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64 << 20,
        "bounded public DKG original"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn read_output(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len())?;
    ensure!(
        length > 0 && length <= maximum,
        "bounded native seat output"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() == length, "native seat output extent changed");
    Ok(bytes)
}

fn require_height(observed: &[u64], expected: u64) -> Result<()> {
    ensure!(
        observed.len() == 4 && observed.iter().all(|height| *height == expected),
        "every retained voter must be at exact H{expected}: {observed:?}"
    );
    Ok(())
}

fn heights(clients: &[Client], deadline: Instant) -> Result<Vec<u64>> {
    clients
        .iter()
        .map(|client| committee_status::height_until_blocking(client, deadline))
        .collect()
}

fn wait_exact(clients: &[Client], height: u64, deadline: Instant) -> Result<()> {
    loop {
        let observed = heights(clients, deadline)?;
        ensure!(
            observed.len() == 4 && observed.iter().all(|value| *value <= height),
            "native DKG phase H{height} was overtaken: {observed:?}"
        );
        if observed.iter().all(|value| *value == height) {
            return Ok(());
        }
        ensure!(
            POLL < deadline.saturating_duration_since(Instant::now()),
            "native DKG phase deadline elapsed"
        );
        std::thread::sleep(POLL);
    }
}

fn prefix(client: &Client, height: u64, deadline: Instant) -> Result<NativeFinalityJournal> {
    ensure!(
        (2..=INSTALL_HEIGHT).contains(&height),
        "bounded native DKG history"
    );
    let source = client.client().with_request_deadline(deadline);
    let mut journal = NativeFinalityJournal { blocks: Vec::new() };
    let mut bytes = 0_usize;
    for current in 1..=height {
        ensure!(
            Instant::now() < deadline,
            "native DKG finality deadline elapsed"
        );
        let proof = source.get_sumeragi_finality_proof(
            NonZeroU64::new(current).unwrap(),
            SumeragiRootScope::Global,
        )?;
        ensure!(
            proof.height() == current
                && !proof.block_wire.is_empty()
                && proof.block_wire.len() <= limits().block_bytes,
            "native DKG finality source differs from requested bounded height"
        );
        bytes = bytes
            .checked_add(proof.block_wire.len())
            .ok_or_else(|| eyre!("DKG journal extent overflow"))?;
        ensure!(
            bytes <= limits().journal_bytes,
            "native DKG journal exceeds source cap"
        );
        proof.decode_checked(SumeragiRootScope::Global.into())?;
        journal.blocks.push(NativeFinalityArtifact {
            block_wire: proof.block_wire,
        });
    }
    journal
        .validate_source(limits())
        .map_err(|error| eyre!(error))?;
    ensure!(
        Instant::now() < deadline,
        "native DKG finality deadline elapsed"
    );
    Ok(journal)
}

fn require_provider(
    provider: &NativeProviderManifest,
    validator: &PeerId,
    signer_index: u16,
    handle: &str,
    revision: u64,
    digest: [u8; 32],
) -> Result<()> {
    ensure!(
        provider.validator == *validator
            && provider.signer_index == signer_index
            && provider.handle == handle
            && provider.revision == revision
            && provider.policy_digest == digest,
        "native provider manifest differs from its exact completed seat"
    );
    DisposableBeaconProviderBinding {
        handle: provider.handle.clone(),
        revision,
        policy_digest: digest,
    }
    .validate()?;
    Ok(())
}

/// Provision an already started exact-H1 network and retain its native private seat owners.
/// No unrelated transaction may be submitted until this function returns at H5.
pub(crate) fn provision(
    network: &Network,
    runtime: &Runtime,
    root: &Path,
) -> Result<DisposableGenesisDkgOutput> {
    ensure!(
        network.validators().len() == 4 && network.peers().len() == 4,
        "four exact ordinary validators required"
    );
    let original = network.native_genesis_provisioning_bundle()?;
    let admin_key = key(0xCE);
    ensure!(
        &original.public_key == admin_key.public_key(),
        "retained genesis is not the maintained engineering authority"
    );
    let discriminant = original.chain_discriminant;
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
    let clients = network
        .validators()
        .iter()
        .map(|peer| {
            ensure!(
                peer.is_running(),
                "ordinary node must have reached H1 before native DKG"
            );
            Ok(peer.client_for(&account(0xCE), admin_key.private_key().clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    require_height(&heights(&clients, Instant::now() + PHASE_BUDGET)?, 1)?;
    let output = root.join("native-genesis-dkg");
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    File::open(root)?.sync_all()?;
    let dkg = runtime.block_on(run_disposable_genesis_dkg(network, limits(), INSTALL_HEIGHT,
        |height, snapshot, deadline| {
            let clients = clients.clone();
            let output = output.clone();
            async move {
                read_on_dedicated_thread(move || {
                    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
                    ensure!((2..=4).contains(&height), "unexpected native genesis DKG phase");
                    require_height(&heights(&clients, deadline)?, height - 1)?;
                    let public = norito::encode_canonical(snapshot.record())?;
                    let audit = norito::json!({
                        "schema": "iroha.kagemusha.native-genesis-dkg-phase.v1",
                        "height": height,
                        "network_id": (snapshot.record().session.network_id.to_string()),
                        "public_snapshot_sha256": (hex::encode(Sha256::digest(&public))),
                        "purpose": (match height { 2 => "signed-dealer-commitments-complete", 3 => "signed-encrypted-deliveries-complete", _ => "signed-recipient-acceptances-complete" }),
                    });
                    publish(&output, &format!("phase-h{height}-public.norito"), &public)?;
                    publish(&output, &format!("phase-h{height}-audit.json"), &norito::json::to_vec(&audit)?)?;
                    let transaction = committee_status::submit_until(&clients[0], deadline, |bounded| {
                        Ok(bounded.submit(Log::new(Level::INFO, norito::json::to_json(&audit)?), FeePaymentIntent::authority(Vec::new(), None))?)
                    })?;
                    wait_exact(&clients, height, deadline)?;
                    let journal = prefix(&clients[0], height, deadline)?;
                    let carrier = journal.blocks[usize::try_from(height - 1)?].decode_block(limits()).map_err(|error| eyre!(error))?;
                    ensure!(carrier.external_transactions().any(|actual| actual.hash() == transaction)
                        && carrier.output_results().all(|result| result.is_ok()), "phase did not carry the exact successful audit transaction");
                    publish(&output, &format!("phase-h{height}.norito"), &norito::encode_canonical(&journal)?)?;
                    // The maintained DKG helper authenticates this complete native prefix
                    // against the original signed genesis before allowing the next phase.
                    Ok(journal)
                }).await.wrap_err("native DKG phase worker failed")
            }
        }))?;
    let install_bytes = read_output(&dkg.install_instruction_path, 16 << 20)?;
    let install: Vec<InstructionBox> = norito::json::from_slice(&install_bytes)?;
    ensure!(
        install.len() == 1,
        "native genesis install must emit exactly one instruction"
    );
    let instruction = install[0].as_any().downcast_ref::<iroha_data_model::isi::consensus_keys::ApplyThresholdKeyLifecycleCertificateV1>()
        .ok_or_else(|| eyre!("native genesis install has foreign instruction type"))?;
    ensure!(
        instruction.certificate.effective_height == INSTALL_HEIGHT
            && instruction.certificate.action == iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        "native install must have exact H5 authority"
    );
    let deadline = Instant::now() + PHASE_BUDGET;
    require_height(&heights(&clients, deadline)?, 4)?;
    publish(&output, "install-instruction.json", &install_bytes)?;
    publish(
        &output,
        "genesis-public-bundle.json",
        &read_output(&dkg.public_bundle_path, 16 << 20)?,
    )?;
    let transaction = committee_status::submit_until(&clients[0], deadline, |bounded| {
        Ok(bounded.submit_all(install, FeePaymentIntent::authority(Vec::new(), None))?)
    })?;
    wait_exact(&clients, INSTALL_HEIGHT, deadline)?;
    let journal = prefix(&clients[0], INSTALL_HEIGHT, deadline)?;
    let budget = iroha_allocation::AllocationBudget::new(limits().allocated_bytes);
    let mut cursor = NativeJournalCursor::new(
        network.chain_id(),
        network.network_id(),
        SumeragiRootScope::Global,
        limits(),
        &budget,
    )
    .map_err(|error| eyre!(error))?;
    let committed = cursor
        .advance((&journal).into())
        .map_err(|error| eyre!(error))?;
    ensure!(
        committed.height() == INSTALL_HEIGHT
            && committed
                .block()
                .external_transactions()
                .any(|actual| actual.hash() == transaction)
            && committed
                .block()
                .output_results()
                .all(|result| result.is_ok()),
        "native H5 did not install the exact successful certificate"
    );
    let installed_decision = (
        committed.block_hash(),
        committed.core_hash(),
        committed.result(),
    );
    publish(
        &output,
        "installed-h5.norito",
        &norito::encode_canonical(&journal)?,
    )?;
    let expected: BTreeSet<_> = network.validators().iter().map(|peer| peer.id()).collect();
    ensure!(
        dkg.seats.len() == 4
            && dkg
                .seats
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<BTreeSet<_>>()
                == expected,
        "DKG private owners do not cover the exact four validators"
    );
    runtime.block_on(network.shutdown());
    runtime.block_on(async {
        for seat in &dkg.seats {
            let peer = network.validators().iter().find(|peer| peer.id() == seat.validator)
                .ok_or_else(|| eyre!("native DKG seat has no original ordinary peer"))?;
            let provider_bytes = read_output(&seat.provider_path, 256 << 10)?;
            let provider: NativeProviderManifest = norito::json::from_slice(&provider_bytes)?;
            let digest = global_beacon_partial_signer_public_inventory_digest_v1(network.network_id(), &[(dkg.public_session.record(), seat.signer_index)])?;
            require_provider(&provider, &seat.validator, seat.signer_index, &seat.provider_handle, seat.provider_revision, digest)?;
            let catalog = IrohaRuntimeProviderBindingsV1::with_prepared_beacon_inventory_v1(None, &network.chain_id().to_string(), network.network_id(),
                &provider.handle, provider.revision, digest, iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES.get())?
                .export_canonical_v1()?;
            let credential = read_output(&seat.credential_path, 16 << 20)?;
            let bundle = encode_consensus_threshold_credential_bundle_v1(Some(&credential), None)?;
            peer.provision_disposable_runtime_provider_broker(&catalog, bundle, DisposableBeaconProviderBinding {
                handle: provider.handle, revision: provider.revision, policy_digest: digest,
            }).await?;
            publish(&output, &format!("seat-{}-provider.json", seat.signer_index), &provider_bytes)?;
            publish(&output, &format!("seat-{}-catalog.norito", seat.signer_index), &catalog)?;
        }
        network.start_all().await?;
        Ok::<(), eyre::Report>(())
    })?;
    let deadline = Instant::now() + PHASE_BUDGET;
    require_height(&heights(&clients, deadline)?, INSTALL_HEIGHT)?;
    for client in &clients {
        let observed = prefix(client, INSTALL_HEIGHT, deadline)?;
        let mut cursor = NativeJournalCursor::new(
            network.chain_id(),
            network.network_id(),
            SumeragiRootScope::Global,
            limits(),
            &budget,
        )
        .map_err(|error| eyre!(error))?;
        let current = cursor
            .advance((&observed).into())
            .map_err(|error| eyre!(error))?;
        ensure!(
            (current.block_hash(), current.core_hash(), current.result()) == installed_decision,
            "restarted ordinary peer replaced its authenticated H5 decision"
        );
    }
    Ok(dkg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_requires_all_four_exact_predecessors() {
        assert!(require_height(&[1, 1, 1, 1], 1).is_ok());
        for observed in [vec![1, 1, 1], vec![1, 1, 1, 2], vec![1, 1, 1, 0]] {
            assert!(require_height(&observed, 1).is_err());
        }
    }

    #[test]
    fn provider_binding_refuses_foreign_seat_or_inventory() {
        let validator = PeerId::new(key(1).public_key().clone());
        let handle = "software://iroha/global-beacon/disposable-validator-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let provider = NativeProviderManifest {
            signer_index: 1,
            validator: validator.clone(),
            handle: handle.into(),
            revision: 1,
            policy_digest: [1; 32],
        };
        assert!(require_provider(&provider, &validator, 1, handle, 1, [1; 32]).is_ok());
        assert!(require_provider(&provider, &validator, 2, handle, 1, [1; 32]).is_err());
        assert!(require_provider(&provider, &validator, 1, handle, 1, [2; 32]).is_err());
        assert!(
            require_provider(
                &provider,
                &PeerId::new(key(2).public_key().clone()),
                1,
                handle,
                1,
                [1; 32]
            )
            .is_err()
        );
    }
}
