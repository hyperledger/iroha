//! Existing signed full-ledger reads authenticated against the four-peer certified tip.
//!
//! Only this disposable localhost harness uses direct HTTP, like the native AMX fee audit.
//! The production SDK's private-provider HTTPS requirement is unchanged.

use super::*;
use iroha::client::{
    canonical_network_request_signature_message, canonical_request_account_header_value,
    canonical_request_signature_header_value,
};
use iroha_data_model::{
    asset::AssetValue,
    sumeragi_finality::{
        WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
        world_state_value_hash_v1,
    },
};
use iroha_torii_shared::resource_names_state::{
    NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1, NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1,
    NativeResourceNamesStateV1, decode_unverified_native_resource_names_state_v1,
};
use std::sync::atomic::{AtomicU64, Ordering};

const LEDGER: &str = "world.kagemusha_wallet_ledger";

pub(super) struct Cut {
    pub(super) height: u64,
    pub(super) rows: Vec<WorldStateSnapshotEntryV1>,
    snapshot: WorldStateSnapshotV1,
    block: VerifiedSumeragiBlock,
    proofs: Vec<SumeragiFinalityProof>,
}

fn ledger_rows(snapshot: &WorldStateSnapshotV1) -> Result<Vec<WorldStateSnapshotEntryV1>> {
    let rows = snapshot
        .entries
        .iter()
        .filter(|row| row.field_id == LEDGER)
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        rows.iter()
            .all(|row| row.kind == WorldStateElementKindV1::Table && row.key_hash.is_some()),
        "KAGEMUSHA ledger must be native table rows"
    );
    Ok(rows)
}

async fn read_cut(
    network: &Network,
    peer: &NetworkPeer,
) -> Result<(Vec<u8>, NativeResourceNamesStateV1)> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let timestamp: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let nonce = format!(
        "kagemusha-fee-world-{timestamp}-{}",
        NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let challenge: [u8; 32] = Sha256::digest(nonce.as_bytes()).into();
    let url: reqwest::Url = format!(
        "{}{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{}",
        peer.torii_url().trim_end_matches('/'),
        hex::encode(challenge)
    )
    .parse()?;
    let message = canonical_network_request_signature_message(
        &network.network_id(),
        &reqwest::Method::GET,
        &url,
        &[],
        timestamp,
        &nonce,
    )?;
    let signature = iroha_crypto::Signature::new(key(41).private_key(), &message);
    let mut response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(url)
        .header("Accept", "application/x-norito")
        .header("X-Iroha-Finality-Challenge", hex::encode(challenge))
        .header(
            "x-iroha-account",
            canonical_request_account_header_value(&account(41))?,
        )
        .header(
            "x-iroha-signature",
            canonical_request_signature_header_value(&signature)?,
        )
        .header("x-iroha-timestamp-ms", timestamp.to_string())
        .header("x-iroha-nonce", nonce)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "full-ledger read unavailable: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            == Some("application/x-norito"),
        "canonical Norito response required"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().checked_add(chunk.len()).is_some_and(|len| len
                <= NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1
                && len <= ORIGINAL_MAX),
            "bounded World cut required"
        );
        bytes.extend_from_slice(&chunk);
    }
    let cut = decode_unverified_native_resource_names_state_v1(&bytes)?;
    ensure!(
        cut.attestation.body.challenge == challenge
            && cut.attestation.body.network_id == network.network_id()
            && cut.attestation.body.node_id == peer.id(),
        "selected node/network/fresh challenge differs"
    );
    cut.attestation
        .verify(native(network)?.root_scope().into())?;
    Ok((bytes, cut))
}

pub(super) fn capture(
    network: &Network,
    rt: &Runtime,
    output: &Path,
    label: &str,
    expected: [u128; 4],
    payout_key: &KagemushaWalletLedgerKeyV1,
    payout: Option<KagemushaWalletPayoutRecordV1>,
) -> Result<Cut> {
    ensure!(network.peers().len() == 4, "exactly four validators");
    let height = committed_height(network)?;
    let proofs = prefix(network, height)?;
    let mut verifier = native(network)?;
    let mut block = None;
    for proof in &proofs {
        block = Some(verifier.verify(proof)?);
    }
    let block = block.ok_or_else(|| eyre!("certified tip absent"))?;
    let mut snapshot = None;
    let mut observations = Vec::new();
    balances(network, expected)?;
    for (index, peer) in network.peers().iter().enumerate() {
        let (wire, cut) = rt.block_on(read_cut(network, peer))?;
        ensure!(
            cut.attestation.body.status.committed_height == height,
            "exact quiescent certified cut required"
        );
        // Authenticate this node's witness against the retained native decision. Its
        // exact quorum can differ from peer zero while certifying the identical cut.
        let peer_block = finality::same_four_validator_decision(
            &verifier,
            proofs.last().unwrap(),
            &cut.attestation.body.finality_proof,
        )?;
        let world = cut.world_snapshot.authenticate(&peer_block)?;
        ensure!(
            world.schema_hash()
                == iroha_core::state::State::native_world_schema_hash_v1()
                    .map_err(|error| eyre!(error))?,
            "independently selected native schema required"
        );
        let rows = ledger_rows(&cut.world_snapshot)?;
        let payout_key_hash = world_state_value_hash_v1(payout_key)?;
        match payout {
            Some(record) => {
                world.verify_table_value(LEDGER, payout_key, &norito::encode_canonical(&record)?)?
            }
            None => ensure!(
                rows.iter().all(|row| row.key_hash != Some(payout_key_hash)),
                "fee payout already exists"
            ),
        }
        let client = peer.client();
        let definition = client
            .client()
            .query_single(FindAssetDefinitionById::new(definition_id()))?;
        ensure!(
            definition.total_quantity() == &quantity(),
            "monetary supply changed"
        );
        world.verify_table_value("world.asset_definitions", &definition_id(), &definition)?;
        for (seed, amount) in [41, 42, 43, 95].into_iter().zip(expected) {
            let asset =
                AssetId::with_scope(definition_id(), account(seed), AssetBalanceScope::Global);
            if amount == 0 {
                world.verify_asset_absent(&asset)?;
            } else {
                world.verify_table_value(
                    "world.assets",
                    &asset,
                    &AssetValue::new(Quantity::from_canonical_numeric(Numeric::new(
                        amount, SCALE,
                    ))?),
                )?;
            }
        }
        if let Some(prior) = &snapshot {
            ensure!(
                prior == &cut.world_snapshot,
                "four peers disagree on complete certified World"
            );
        }
        observations.push(publish(
            output,
            &format!("{label}-peer-{index}-world-cut.norito"),
            &wire,
        )?);
        snapshot = Some(cut.world_snapshot);
    }
    ensure!(
        committed_height(network)? == height,
        "chain advanced during World observation"
    );
    balances(network, expected)?;
    publish(
        output,
        &format!("{label}-world-observations.json"),
        &norito::json::to_vec(&norito::json!({
        "height":height, "peers":observations, "balances_atomic":(expected.map(|value| value.to_string()).to_vec()),
        "full_world_authenticated":true, "payout_present":(payout.is_some())}))?,
    )?;
    let snapshot = snapshot.ok_or_else(|| eyre!("World cut absent"))?;
    Ok(Cut {
        height,
        rows: ledger_rows(&snapshot)?,
        snapshot,
        block,
        proofs,
    })
}

pub(super) fn export_evidence(
    output: &Path,
    input: &Inputs,
    payout_height: u64,
    payout: KagemushaWalletPayoutRecordV1,
    cut: &Cut,
) -> Result<norito::json::Value> {
    ensure!(
        (6..=cut.height).contains(&payout_height) && cut.height <= 64,
        "bounded fee history"
    );
    let world = cut.snapshot.authenticate(&cut.block)?;
    world.verify_table_value(
        LEDGER,
        &payout.key.ledger_key(input.scheme),
        &norito::encode_canonical(&payout)?,
    )?;
    let directory = output.join("evidence");
    private_directory(&directory)?;
    let mut originals = vec![
        publish(
            &directory,
            "fee-payout.norito",
            &norito::encode_canonical(&payout)?,
        )?,
        publish(
            &directory,
            "world-snapshot.norito",
            &norito::encode_canonical(&cut.snapshot)?,
        )?,
    ];
    for proof in &cut.proofs {
        originals.push(publish(
            &directory,
            &format!("native-proof-{}.norito", proof.height()),
            &norito::encode_canonical(proof)?,
        )?);
    }
    let producer: norito::json::Value = norito::json::from_slice(&input.producer)?;
    let bytes = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.fee-payout-evidence.v1", "origin":"network",
        "producer_sha256":(hash(&input.producer)), "target_sha256":(hash(&input.target)),
        "receipt_sha256":(producer["receipt_sha256"].clone()), "scheme_id":(hex::encode(input.scheme)),
        "manifest_digest":(hex::encode(input.manifest)), "payout_height":payout_height,
        "world_height":(cut.height), "last_certified_height":(cut.height),
        "world_block_hash":(hex::encode(cut.block.block().hash().as_ref())),
        "world_context_id":(hex::encode(world.context_id().as_ref())), "world_root":(hex::encode(world.world_root().as_ref())),
        "world_schema_hash":(hex::encode(world.schema_hash().as_ref())), "originals":originals,
        "scope":"Exact payout value authenticated by all four live peers' same certified complete World after same-store restart and fresh claim replay. Original proofs derive authority from the dedicated selected network genesis; this carrier alone grants none. Native fee acknowledgement is separate."
    }))?;
    ensure!(
        bytes.len() <= 16 << 10,
        "bounded native consumer evidence manifest"
    );
    let result = publish(&directory, "fee-payout-evidence.json", &bytes)?;
    File::open(&directory)?.sync_all()?;
    Ok(
        norito::json!({"path":(directory.join("fee-payout-evidence.json").to_string_lossy().into_owned()), "sha256":(hash(&bytes)), "original":result}),
    )
}

#[test]
fn ledger_row_projection_keeps_all_keys_and_rejects_non_table_rows() -> Result<()> {
    let mut snapshot = WorldStateSnapshotV1 {
        schema_hash: Hash::new(b"schema"),
        entries: vec![
            WorldStateSnapshotEntryV1 {
                field_id: LEDGER.into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(Hash::new(b"one")),
                value_hash: Hash::new(b"original"),
            },
            WorldStateSnapshotEntryV1 {
                field_id: "world.other".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(Hash::new(b"other")),
                value_hash: Hash::new(b"other"),
            },
            WorldStateSnapshotEntryV1 {
                field_id: LEDGER.into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(Hash::new(b"two")),
                value_hash: Hash::new(b"second"),
            },
        ],
    };
    let rows = ledger_rows(&snapshot)?;
    ensure!(rows.len() == 2, "must retain entire KAGEMUSHA table");
    snapshot.entries[0].value_hash = Hash::new(b"changed");
    ensure!(
        ledger_rows(&snapshot)? != rows,
        "row rewrite must remain observable"
    );
    snapshot.entries[0].key_hash = None;
    ensure!(
        ledger_rows(&snapshot).is_err(),
        "invalid table entry accepted"
    );
    Ok(())
}
