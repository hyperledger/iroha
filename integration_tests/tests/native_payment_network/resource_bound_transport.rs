//! Reuse signed-RS16 process observations and read canonical Kura through its public owner.

use super::*;
use iroha_core::kura::{BlockIndex, BlockStore, Kura};
use iroha_test_network::NetworkPeer;
use std::{fs, fs::File, io::Read, os::unix::fs::MetadataExt as _, path::Path};

#[path = "../nexus/atomic_private_settlement_transport.rs"]
mod observations;

pub(super) fn processes(
    network: &Network,
    runtime: &tokio::runtime::Runtime,
    deadline: Instant,
) -> Result<Vec<u32>> {
    network
        .validators()
        .iter()
        .map(|peer| {
            bounded(runtime, deadline, peer.process_id())?
                .ok_or_else(|| eyre!("original process absent"))
        })
        .collect()
}

fn log_prefix(path: &Path) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink() && before.len() <= 64 * 1024 * 1024
    );
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    ensure!(before.dev() == opened.dev() && before.ino() == opened.ino());
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len())
        .read_to_end(&mut bytes)?;
    let current = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && file.metadata()?.len() >= before.len()
            && current.dev() == before.dev()
            && current.ino() == before.ino()
    );
    if let Some(end) = bytes.iter().rposition(|byte| *byte == b'\n') {
        bytes.truncate(end + 1);
    } else {
        bytes.clear();
    }
    Ok(bytes)
}

pub(super) fn verify_rows(
    network: &Network,
    peer: &NetworkPeer,
    pid: u32,
    verified: &VerifiedSumeragiBlock,
    deadline: Instant,
) -> Result<()> {
    ensure!(Instant::now() < deadline);
    let certificate = verified
        .block()
        .commit_certificate()
        .ok_or_else(|| eyre!("native certificate absent"))?;
    // This exact certificate is already authenticated by the original genesis-rooted verifier.
    let header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(certificate.consensus_header())?;
    let layout = verified.commitment().schedule.current.da_layout;
    ensure!(layout == iroha_sumeragi::availability::recommended_data_availability_layout());
    ensure!(header.payload_len as usize == verified.block().resultless_proposal_wire_len()?);
    ensure!(header.payload_len as usize <= BLOCK_PAYLOAD_CAP);
    let shape = layout.shape(u64::from(header.payload_len))?;
    let key = |id: &iroha_model_base::peer::PeerId| -> Result<String> {
        Ok(hex::encode(
            iroha_data_model::sumeragi_finality::consensus_key(id)?.as_bytes(),
        ))
    };
    let committee = &verified.commitment().schedule.current.committee;
    let author = committee
        .get(header.proposer as usize)
        .ok_or_else(|| eyre!("invalid authenticated proposer"))?;
    let expected = observations::Expected {
        process_id: pid,
        instance: header.instance.to_string(),
        height: verified.height(),
        block: verified.core_hash().to_string(),
        result: verified.result().to_string(),
        availability: header.availability_digest.to_string(),
        payload: header.payload_hash.to_string(),
        bytes: u64::from(header.payload_len),
        epoch: header.epoch.epoch,
        context: header.epoch.context.to_string(),
        proposer: u64::from(header.proposer),
        local_is_author: author.validator == peer.id(),
        local: key(&peer.id())?,
        peers: network
            .all_peers()
            .map(|p| key(&p.id()))
            .collect::<Result<_>>()?,
        k: usize::from(layout.data_shards),
        width: usize::from(layout.data_shards) + usize::from(layout.parity_shards),
        stripes: shape.stripe_count(),
    };
    let snapshot = network
        .startup_snapshot()
        .into_iter()
        .find(|s| s.mnemonic == peer.mnemonic())
        .ok_or_else(|| eyre!("process snapshot absent"))?;
    ensure!(snapshot.is_running);
    let stdout = snapshot
        .logs
        .stdout_log
        .as_ref()
        .ok_or_else(|| eyre!("stdout absent"))?;
    let stderr = snapshot
        .logs
        .stderr_log
        .as_ref()
        .ok_or_else(|| eyre!("stderr absent"))?;
    observations::current_run_log(
        &network.env_dir().join(peer.mnemonic()),
        snapshot.logs.stderr_run_id,
        stdout,
        stderr,
    )?;
    let observed = observations::verify(&log_prefix(stdout)?, &expected)?;
    if !expected.local_is_author {
        ensure!(
            observed.admitted_rows >= expected.k * expected.stripes,
            "follower must admit actual distinct signed RS16 rows"
        );
    }
    ensure!(!observed.audit_lines.is_empty());
    ensure!(Instant::now() < deadline);
    Ok(())
}

pub(super) fn verify_cold_stores(
    network: &Network,
    genesis: &[u8],
    pins: &SignedGenesisPinsV1,
    expected: [HashOf<SignedTransaction>; 2],
    contexts: [iroha_crypto::Hash; 2],
    deadline: Instant,
) -> Result<()> {
    let authenticated = authenticate_signed_genesis_v1(genesis, pins)?;
    for peer in network.validators() {
        ensure!(!peer.is_running(), "inspect the original closed store only");
        let mut store =
            BlockStore::open_read_only(Kura::canonical_storage_path(&peer.kura_store_dir()))?;
        ensure!(
            store.read_index_count()? == 3,
            "maximum carrier recovery must preserve the final tip"
        );
        let mut trusted = verifier(genesis, pins)?;
        for (offset, transaction_hash) in expected.iter().enumerate() {
            ensure!(Instant::now() < deadline);
            let height = offset as u64 + 2;
            let mut indices = [BlockIndex::default()];
            store.read_block_indices(height - 1, &mut indices)?;
            let index = indices[0];
            ensure!(
                index.length > 0
                    && index.length
                        <= iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES as u64
            );
            let wire = store.block_bytes(index.start, index.length)?.to_vec();
            let block = iroha_data_model::block::decode_framed_signed_block(&wire)?;
            ensure!(block.header().height().get() == height);
            let proof = SumeragiFinalityProof {
                block_header: block.header(),
                block_wire: wire,
                committee: authenticated.validators().to_vec(),
            };
            let verified = trusted.verify(&proof)?;
            exact_payment(&verified, *transaction_hash)?;
            ensure!(
                verified.context_id() == contexts[offset],
                "stored certificate differs from the original verified decision"
            );
            let (_, result) = verified
                .block()
                .network_output_at(0)
                .ok_or_else(|| eyre!("stored output absent"))?;
            ensure!(
                result.result.as_ref().is_ok() == (height == 3),
                "Kura must retain the successful/rejected distinction"
            );
        }
    }
    ensure!(Instant::now() < deadline);
    Ok(())
}
