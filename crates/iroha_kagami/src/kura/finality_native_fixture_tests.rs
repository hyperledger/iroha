//! Native execution/replay captures through the current bounded finality inspector.
//!
//! The fixture signs exact three-of-four certificates after real World execution;
//! it does not run distributed consensus or execute the declared auxiliary lanes.
//! TODO: qualify distributed lane execution and complete FASTPQ source admission
//! separately. These captures provide no monetary or hardware authority.

use super::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use iroha_core::state::WorldReadOnly;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    block::proofs::TrustedBlockProofAnchor,
    isi::Log,
    sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityVerifier, verify_checkpoint_page,
    },
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder},
};
use iroha_model_base::peer::PeerId;

fn native_capture(lane_count: u32) -> BTreeMap<String, Vec<u8>> {
    let fixture = crate::genesis::native_genesis_fixture_with_instructions(lane_count, Vec::new());
    let signed_genesis = fixture.signed.0.encode_wire().unwrap();
    // Authenticate the originally provisioned manifest/key/hash before observing
    // either the store's report or any SDK proof response.
    let selected = iroha_genesis::validate_prepared_genesis_bundle(
        &signed_genesis,
        &fixture.manifest,
        &fixture.config.genesis.public_key,
        fixture.config.genesis.expected_hash,
    )
    .unwrap();
    let roster = selected
        .validator_pops()
        .iter()
        .map(|(public_key, proof_of_possession)| FinalityValidator {
            public_key: public_key.clone(),
            proof_of_possession: proof_of_possession.clone(),
        })
        .collect::<Vec<_>>();
    assert_eq!(roster.len(), 4);
    let mut consumer = SumeragiFinalityVerifier::new(
        selected.block(),
        fixture.manifest.chain_id().as_ref(),
        roster,
    )
    .unwrap();
    let make_chain = || {
        let validated = iroha_genesis::validate_prepared_genesis_bundle(
            &signed_genesis,
            &fixture.manifest,
            &fixture.config.genesis.public_key,
            fixture.config.genesis.expected_hash,
        )
        .unwrap();
        let mut keys = (0x40..=0x43)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        crate::genesis::prepared_native_test_chain(
            validated,
            &fixture.manifest,
            &fixture.config,
            keys,
            KeyPair::from_seed(vec![0x7D; 32], Algorithm::Ed25519),
            Arc::new(iroha_core::sumeragi::lanes::merge::NoLanes),
        )
        .unwrap()
    };
    let mut chain = make_chain();
    let mut replay = make_chain();
    assert_eq!(chain.genesis().encode_wire().unwrap(), signed_genesis);
    assert_eq!(replay.genesis().encode_wire().unwrap(), signed_genesis);
    assert_eq!(
        chain.state().view().world().sumeragi_lanes().lanes.len(),
        lane_count as usize - 1
    );
    let clock = KeyPair::from_seed(vec![0x7D; 32], Algorithm::Ed25519);
    let asset =
        AssetDefinitionId::parse_address_literal(&fixture.config.nexus.fees.fee_asset_id).unwrap();
    let payer = AssetId::new(asset.clone(), AccountId::new(clock.public_key().clone()));
    let before = chain
        .state()
        .view()
        .world()
        .asset(&payer)
        .unwrap()
        .value()
        .clone()
        .into_inner();
    let mut transaction = TransactionBuilder::new(
        chain.network_id(),
        AccountId::new(clock.public_key().clone()),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                asset,
                1_u64.into(),
            )],
            None,
        ),
    );
    transaction.set_creation_time(
        chain.genesis().header().creation_time()
            + Duration::from_millis(
                fixture
                    .manifest
                    .effective_parameters()
                    .unwrap()
                    .sumeragi()
                    .block_cadence_ms
                    .get()
                    - 1,
            ),
    );
    let transaction = transaction
        .with_instructions([Log::new(
            iroha_data_model::Level::DEBUG,
            "current native execution SDK capture".into(),
        )])
        .sign(clock.private_key());
    transaction.verify_signature().unwrap();
    assert_eq!(chain.commit(vec![transaction.clone()]), [true]);
    let after = chain
        .state()
        .view()
        .world()
        .asset(&payer)
        .unwrap()
        .value()
        .clone()
        .into_inner();
    assert!(
        after < before,
        "actual original signed fee policy must charge execution"
    );
    replay.replay_from(&chain).unwrap();
    assert_eq!(replay.height(), chain.height());
    assert_eq!(
        replay
            .state()
            .view()
            .world()
            .asset(&payer)
            .unwrap()
            .value()
            .clone()
            .into_inner(),
        after
    );
    assert_eq!(
        replay.state().view().world().sumeragi_lanes(),
        chain.state().view().world().sumeragi_lanes()
    );
    let directory = tempfile::tempdir().unwrap();
    let mut store = BlockStore::new(directory.path());
    store.create_files_if_they_do_not_exist().unwrap();
    for height in 1..=2 {
        let original = chain.committed(height);
        let replayed = replay.committed(height);
        assert_eq!(original.result(), replayed.result());
        assert_eq!(original.commitment(), replayed.commitment());
        assert_eq!(
            original.block().encode_wire().unwrap(),
            replayed.block().encode_wire().unwrap()
        );
        store.append_block_to_chain(original.block()).unwrap();
    }
    drop(store);
    let journal_names = ["blocks.index", "blocks.data", "blocks.hashes"];
    let journal_before = journal_names.map(|name| fs::read(directory.path().join(name)).unwrap());
    let mut files = BTreeMap::new();
    let mut proofs = Vec::new();
    let mut root_checkpoint = None;
    for height in 1..=2 {
        let mut output = Vec::new();
        inspect(
            &mut output,
            directory.path(),
            fixture.manifest.chain_id(),
            height,
        )
        .unwrap();
        let report: norito::json::Value = norito::json::from_slice(&output).unwrap();
        assert_eq!(report["external_trust_anchor"].as_bool(), Some(false));
        assert_eq!(
            report["genesis_execution_authenticated"].as_bool(),
            Some(height > 1)
        );
        assert_eq!(report["verified_prefix_end"].as_u64(), Some(height));
        let proof: SumeragiFinalityProof =
            norito::json::from_value(report["finality_proof"].clone()).unwrap();
        let committed = chain.committed(height);
        assert_eq!(proof.block_wire, committed.block().encode_wire().unwrap());
        assert_eq!(proof.committee.len(), 4);
        let verified = consumer.verify(&proof).unwrap();
        assert_eq!(verified.result(), committed.result());
        assert_eq!(verified.commitment(), committed.commitment());
        assert_eq!(
            verified.execution().world_state_root,
            replay
                .committed(height)
                .commitment()
                .execution
                .world_state_root
        );
        let checkpoint = consumer.export_checkpoint(&proof).unwrap();
        let checkpoint_bytes = checkpoint.encode_canonical().unwrap();
        assert_eq!(
            SumeragiFinalityCheckpoint::decode_canonical(&checkpoint_bytes).unwrap(),
            checkpoint
        );
        files.insert(format!("height-{height}-checkpoint.nrt"), checkpoint_bytes);
        files.insert(format!("height-{height}-report.json"), output);
        if height == 1 {
            root_checkpoint = Some(checkpoint);
        } else {
            let certificate = committed.block().commit_certificate().unwrap();
            let qc: iroha_sumeragi::message::Qc =
                norito::decode_canonical(certificate.commit_qc()).unwrap();
            assert_eq!(qc.signers.count_ones(), 3);
            assert_eq!(
                verified.block().external_transactions().collect::<Vec<_>>(),
                vec![&transaction]
            );
            assert!(
                verified
                    .block()
                    .network_output_at(0)
                    .unwrap()
                    .1
                    .result
                    .is_ok()
            );
            let entry_hash = transaction.hash_as_entrypoint();
            let anchor = TrustedBlockProofAnchor::from_verified_finality(
                verified.block(),
                &verified,
                &entry_hash,
            )
            .unwrap();
            let execution = verified
                .block()
                .network_execution_proof(&entry_hash)
                .unwrap();
            assert!(execution.verify(&anchor));
            files.insert(
                "request.nrt".to_owned(),
                norito::encode_canonical(&transaction).unwrap(),
            );
            files.insert(
                "request-proof.nrt".to_owned(),
                norito::encode_canonical(&execution).unwrap(),
            );
            let mut changed = proof.clone();
            changed.block_wire.pop();
            assert!(consumer.verify_retained_decision(&changed).is_err());
            let mut changed = proof.clone();
            changed.block_header = chain.committed(1).block().header();
            assert!(consumer.verify_retained_decision(&changed).is_err());
            let mut changed = proof.clone();
            changed.committee.pop();
            assert!(consumer.verify_retained_decision(&changed).is_err());
        }
        proofs.push(proof);
    }
    let root_checkpoint = root_checkpoint.unwrap();
    let page = verify_checkpoint_page(
        chain.network_id(),
        &root_checkpoint,
        &proofs,
        2,
        16 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(page.tip().result(), chain.committed(2).result());
    assert_eq!(
        page.checkpoint().encode_canonical().unwrap(),
        files["height-2-checkpoint.nrt"]
    );
    files.insert(
        "proof-page.json".to_owned(),
        norito::json::to_vec(&proofs).unwrap(),
    );
    files.insert("signed-genesis.nrt".to_owned(), signed_genesis);
    files.insert(
        "selected-genesis-manifest.json".to_owned(),
        norito::json::to_vec(&fixture.manifest).unwrap(),
    );
    files.insert(
        "selected-genesis-key.txt".to_owned(),
        fixture.config.genesis.public_key.to_string().into_bytes(),
    );
    for (name, before) in journal_names.into_iter().zip(journal_before) {
        assert_eq!(
            fs::read(directory.path().join(name)).unwrap(),
            before,
            "read-only inspector changed original journal"
        );
    }
    files
}

fn native_sdk_captures() -> Vec<norito::json::Value> {
    [1, 4]
        .into_iter()
        .map(|lane_count| {
            let files = native_capture(lane_count)
                .into_iter()
                .map(|(name, bytes)| (name, hex::encode(bytes)))
                .collect::<BTreeMap<_, _>>();
            norito::json!({ "lane_count": lane_count, "files": files })
        })
        .collect()
}

#[test]
fn current_native_execution_and_replay_capture_exact_finality_and_request_bytes() {
    let captures = native_sdk_captures();
    assert_eq!(captures.len(), 2);
    for (capture, lane_count) in captures.iter().zip([1, 4]) {
        assert_eq!(capture["lane_count"].as_u64(), Some(lane_count));
        let files = capture["files"].as_object().unwrap();
        assert_eq!(files.len(), 10);
        for value in files.values() {
            let bytes = hex::decode(value.as_str().unwrap()).unwrap();
            assert!(!bytes.is_empty());
        }
    }
    // Exercise the same owned collection and text codec as the ignored producer,
    // preserving every exact emitted file and the independently selected roots.
    let json = norito::json::to_json(&captures).unwrap();
    assert!(!json.is_empty() && json.len() <= 64 * 1024 * 1024);
    let decoded: Vec<norito::json::Value> = norito::json::from_str(&json).unwrap();
    assert_eq!(decoded, captures);
}

#[test]
#[ignore = "explicit genuine World execution capture for the SDK bridge consumer"]
fn capture_current_native_execution_sdk_fixtures() {
    let captures = native_sdk_captures();
    println!(
        "KAGAMI_NATIVE_EXECUTION_CAPTURE={}",
        norito::json::to_json(&captures).unwrap()
    );
}
