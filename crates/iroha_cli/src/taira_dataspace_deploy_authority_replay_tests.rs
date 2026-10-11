//! Exercise the portable replay with real executed blocks, quorum certificates and
//! four independently signed node attestations. Log transactions deliberately test
//! only replay: the outer authority entry separately verifies allocation instructions.

use super::*;
use iroha_core::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair, SignatureOf};
use iroha_data_model::{
    isi::Log,
    parameter::system::{
        Parameter, SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter,
        SumeragiParameters,
    },
    query::CommittedTransaction,
    sumeragi::{SumeragiFootprint, SumeragiStatus},
    sumeragi_finality::SumeragiFinalityAttestationBody,
    sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneStatus,
    },
};
use iroha_torii_shared::PipelineTransactionStatus;

struct Fixture {
    plan: PlanV1,
    trust: TrustV1,
    completion: OriginalCompletion,
    prepared: Vec<(PreparedV1, SignedTransaction)>,
    originals: BTreeMap<String, Vec<u8>>,
}

fn lane_observation(plan: &PlanV1, trust: &TrustV1) -> SumeragiLaneStatus {
    let genesis =
        iroha_genesis::decode_signed_genesis(&hex::decode(&trust.genesis_signed_wire_hex).unwrap())
            .unwrap();
    SumeragiLaneStatus {
        record: SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: plan.manifest.lane.id,
            dataspace: plan.manifest.lane.dataspace_id,
            incarnation: [42; 32],
            params: SumeragiParameters::default(),
            committee: iroha_genesis::signed_genesis_validator_pops(&genesis)
                .unwrap()
                .into_iter()
                .map(|(key, pop)| SumeragiLaneMember {
                    peer: PeerId::new(key),
                    pop,
                })
                .collect(),
            created_at: 2,
            active_from: 4,
            closing: None,
            anchor_freshness: 1,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 4,
            rescued: 0,
        },
        instance: None,
    }
}

impl Fixture {
    fn new() -> Self {
        Self::with_tip_heights([4, 5, 6, 4])
    }

    fn with_tip_heights(tip_heights: [u64; 4]) -> Self {
        let maximum = *tip_heights.iter().max().unwrap();
        let mut config = TestChainConfig::new(World::new(), 10_000);
        let key = config.genesis_key.clone();
        let chain_id = config.chain_id.clone();
        config.consensus_mode = SumeragiConsensusMode::Npos;
        let npos = SumeragiNposParameters::default();
        config.genesis_parameters = vec![
            Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                npos.epoch_length_blocks,
            )),
            Parameter::Custom(npos.into_custom_parameter()),
        ];
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let keys = (0xC1..=0xC4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        let peers = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let peer_id = PeerId::new(key.public_key().clone());
                PeerV1 {
                    torii_origin: format!("http://127.0.0.1:{}/", 18080 + index),
                    node_fingerprint: Hash::new(peer_id.encode()),
                    peer_id,
                    build_fingerprint: Hash::new(b"selected target"),
                    config_fingerprint: Hash::new(b"selected config"),
                }
            })
            .collect::<Vec<_>>();
        let executed_genesis = chain.committed(1);
        let executed_genesis = executed_genesis.block();
        assert!(executed_genesis.has_results());
        assert_eq!(executed_genesis.hash(), chain.genesis().hash());
        let trust = TrustV1 {
            chain: chain_id,
            account_chain_discriminant: 369,
            genesis_public_key: key.public_key().clone(),
            genesis_signed_wire_hex: hex::encode(executed_genesis.encode_wire().unwrap()),
            peers,
        };
        let mut plan = crate::taira_dataspace_deploy::tests::fixture_plan();
        let template = crate::taira_dataspace_deploy::tests::prepared(&plan);
        plan.manifest.network_id = chain.network_id();
        let mut prepared = Vec::new();
        let mut observations = Vec::new();
        for (index, phase) in PHASES.into_iter().enumerate() {
            let height = index as u64 + 2;
            let instructions: Vec<InstructionBox> =
                vec![Log::new(iroha_data_model::Level::INFO, phase.to_owned()).into()];
            let signed = chain.sign(&key, instructions.clone(), 10_000 + height * 1_000);
            assert_eq!(chain.commit(vec![signed.clone()]), vec![true]);
            let retained = PreparedV1 {
                phase: phase.into(),
                instructions: instructions.clone(),
                signed_transaction_wire_hex: hex::encode(signed.encode_wire_v1().unwrap()),
                transaction_hash: hex::encode(signed.hash().as_ref()),
                ..template.clone()
            };
            let block = chain.committed(height);
            let block = block.block();
            let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
            let (output_index, _) = block.network_output_at(0).unwrap();
            let output = block.execution_outputs()[output_index as usize].clone();
            let transaction = CommittedTransaction {
                block_hash: block.hash(),
                entrypoint_hash: entrypoint.hash(),
                entrypoint_proof: block.network_input_proof(0).unwrap(),
                entrypoint,
                output_hash: HashOf::new(&output),
                output_proof: block.output_proof(output_index).unwrap(),
                output,
            };
            let status = |scope: &str| {
                Some(PipelineTransactionStatusResponse::new(
                    retained.transaction_hash.clone(),
                    PipelineTransactionStatus {
                        kind: "Applied".into(),
                        block_height: Some(height),
                    },
                    scope.into(),
                    "state".into(),
                ))
            };
            observations.push(PhaseObservationV1 {
                phase: phase.into(),
                state: "applied_verification_pending".into(),
                transaction_hash: Some(retained.transaction_hash.clone()),
                instructions,
                signed_transaction_wire_sha256: digest(&signed.encode_wire_v1().unwrap()),
                alias_plan: retained.alias_plan.clone(),
                global_status: status("global"),
                peer_status: status("local"),
                committed: Some(PipelineTransactionDetailsResponse {
                    hash: retained.transaction_hash.clone(),
                    transaction,
                }),
            });
            prepared.push((retained, signed));
        }
        for _ in 5..=maximum {
            chain.commit(Vec::new());
        }
        let proofs = (1..=maximum)
            .map(|height| {
                iroha_core::sumeragi::finality::build_proof(&chain.state().view(), height).unwrap()
            })
            .collect::<Vec<_>>();
        let authority = trust.authority(chain.network_id()).unwrap();
        let mut verifier = authority.verifier().unwrap();
        let mut originals = BTreeMap::new();
        let mut carriers = Vec::new();
        for proof in &proofs {
            let height = proof.height();
            originals.insert(
                format!("proof-{height:020}.json"),
                json::to_vec(proof).unwrap(),
            );
            let certified = verifier.verify(proof).unwrap();
            if (2..=4).contains(&height) {
                let wire = certified.canonical_executed_wire().unwrap();
                let file = format!("carrier-{height:020}.nrt");
                carriers.push((height, file.clone(), digest(&wire)));
                originals.insert(file, wire);
            }
        }
        let challenge = [42; 32];
        let peers = trust
            .peers
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (peer, key))| {
                let height = tip_heights[index];
                let tip = &proofs[height as usize - 1];
                let body = SumeragiFinalityAttestationBody {
                    observed_at_unix_ms: 1_000_000,
                    challenge,
                    network_id: chain.network_id(),
                    node_fingerprint: peer.node_fingerprint,
                    node_id: peer.peer_id.clone(),
                    build_fingerprint: peer.build_fingerprint,
                    config_fingerprint: peer.config_fingerprint,
                    genesis_block_hash: chain.genesis().hash(),
                    genesis_finality_proof: proofs[0].clone(),
                    status: SumeragiStatus {
                        protocol_version: 1,
                        config_fingerprint: peer.config_fingerprint,
                        beacon_horizon: None,
                        instance: chain.instance().0,
                        height: height + 1,
                        view: 0,
                        stage: 0,
                        leader: Some(peer.peer_id.public_key().clone()),
                        proxy_tail: None,
                        high_qc_view: None,
                        level: 0,
                        start_level: 0,
                        t_retx_ms: 100,
                        committed_height: height,
                        applied_height: height,
                        awaiting: false,
                        signer: Some(peer.peer_id.public_key().clone()),
                        unanchored: false,
                        abstaining: false,
                        halted: None,
                        footprint: SumeragiFootprint::default(),
                    },
                    finality_proof: tip.clone(),
                };
                let signature =
                    SignatureOf::try_from_hash(key.private_key(), body.signing_hash()).unwrap();
                PeerReceipt {
                    peer_id: peer.peer_id.clone(),
                    height,
                    block_hash: tip.block_header.hash(),
                    attestation: SumeragiFinalityAttestation { body, signature },
                    transactions: observations.clone(),
                    carriers: carriers
                        .iter()
                        .map(|(height, file, wire_sha256)| CarrierReceipt {
                            height: *height,
                            file: file.clone(),
                            wire_sha256: wire_sha256.clone(),
                        })
                        .collect(),
                    native_lane: lane_observation(&plan, &trust),
                }
            })
            .collect();
        let completion = OriginalCompletion {
            value: CompletionV1 {
                schema_version: 1,
                operation_id: plan.operation_id.clone(),
                intent_sha256: plan.intent_sha256.clone(),
                network_id: chain.network_id(),
                challenge,
                peers,
                verification_origins: trust.peers.iter().map(|p| p.torii_origin.clone()).collect(),
            },
            runtime_update: None,
            effective_trust_file: None,
        };
        Self {
            plan,
            trust,
            completion,
            prepared,
            originals,
        }
    }

    fn replay(&self) -> Result<(Vec<json::Value>, Vec<json::Value>)> {
        self.replay_with_tips(&runtime_update::RetainedTips::default())
    }

    fn replay_with_tips(
        &self,
        tips: &runtime_update::RetainedTips,
    ) -> Result<(Vec<json::Value>, Vec<json::Value>)> {
        self.completion.replay(
            &self.plan,
            &self.trust,
            &self.prepared,
            tips,
            |name, limit| {
                let bytes = self
                    .originals
                    .get(name)
                    .ok_or_else(|| eyre!("missing fixture original"))?;
                require(bytes.len() <= limit, "fixture size bound")?;
                Ok(bytes.clone())
            },
        )
    }
}

#[test]
fn portable_replay_authenticates_real_executions_and_four_attestations() {
    let fixture = Fixture::new();
    let (phases, peers) = fixture.replay().unwrap();
    assert_eq!(phases.len(), 3);
    assert_eq!(peers.len(), 4);
    assert_eq!(phases[0]["height"].as_str(), Some("2"));
    assert_eq!(peers[3]["height"].as_str(), Some("4"));
    assert_eq!(peers[1]["height"].as_str(), Some("5"));
    assert_eq!(peers[2]["height"].as_str(), Some("6"));
    assert_eq!(fixture.completion.files().unwrap().len(), 9);
    let original = json::to_vec(&fixture.completion.value).unwrap();
    let name = format!(
        "completion-{}.json",
        hex::encode(fixture.completion.value.challenge)
    );
    OriginalCompletion::decode(&name, &original).unwrap();
    assert!(OriginalCompletion::decode("completion-wrong.json", &original).is_err());
}

#[test]
fn portable_replay_rejects_gaps_carrier_changes_and_forged_applied_observations() {
    let mut fixture = Fixture::new();
    fixture.replay().unwrap();
    for name in [
        "proof-00000000000000000002.json",
        "carrier-00000000000000000003.nrt",
    ] {
        let bytes = fixture.originals.remove(name).unwrap();
        assert!(fixture.replay().is_err(), "missing {name}");
        fixture.originals.insert(name.into(), bytes);
    }
    let name = "carrier-00000000000000000003.nrt";
    let original = fixture.originals[name].clone();
    fixture.originals.get_mut(name).unwrap()[0] ^= 1;
    assert!(fixture.replay().is_err());
    fixture.originals.insert(name.into(), original.clone());
    let original_carrier = original;
    let original = json::to_vec(&fixture.completion.value).unwrap();
    for mutation in 0..8 {
        fixture.completion.value = json::from_slice(&original).unwrap();
        let peer = &mut fixture.completion.value.peers[0];
        match mutation {
            0 => peer.attestation.body.challenge[0] ^= 1,
            1 => peer.transactions[0].state = "completed".into(),
            2 => peer.transactions[0].committed.as_mut().unwrap().hash = "0".repeat(64),
            3 => {
                let committed = &mut peer.transactions[0].committed.as_mut().unwrap().transaction;
                let changed =
                    HashOf::from_untyped_unchecked(Hash::new(b"tampered output commitment"));
                assert_ne!(committed.output_hash, changed);
                committed.output_hash = changed;
            }
            4 => peer.transactions[0].signed_transaction_wire_sha256 = "0".repeat(64),
            5 => peer.carriers[0].height = 3,
            6 => {
                peer.transactions[0]
                    .peer_status
                    .as_mut()
                    .unwrap()
                    .status
                    .kind = "Queued".into()
            }
            _ => {
                peer.transactions[0]
                    .peer_status
                    .as_mut()
                    .unwrap()
                    .status
                    .kind = "Rejected".into();
            }
        }
        assert_ne!(
            json::to_vec(&fixture.completion.value).unwrap(),
            original,
            "mutation {mutation} must change the original"
        );
        assert!(fixture.replay().is_err(), "mutation {mutation}");
    }
    fixture.completion.value = json::from_slice(&original).unwrap();
    // Another authentic executed carrier cannot be relabelled with updated hashes.
    let different = fixture.originals["carrier-00000000000000000002.nrt"].clone();
    fixture
        .originals
        .insert("carrier-00000000000000000003.nrt".into(), different.clone());
    for peer in &mut fixture.completion.value.peers {
        peer.carriers[1].wire_sha256 = digest(&different);
    }
    assert!(fixture.replay().is_err());
    fixture
        .originals
        .insert("carrier-00000000000000000003.nrt".into(), original_carrier);
    // The target build is authenticated by each independent peer signature.
    fixture.completion.value = json::from_slice(&original).unwrap();
    fixture.trust.peers[0].build_fingerprint = Hash::new(b"another target source");
    assert!(fixture.replay().is_err());
}

fn runtime_checkpoint_claims(height: u64, hash: Hash) -> json::Value {
    norito::json!(
        (1..=4)
            .map(|peer| norito::json!({
                "role":(format!("taira-validator-{peer}")),
                "kura_tip":{"height":height,"hash":(hex::encode(hash.as_ref()))}
            }))
            .collect::<Vec<_>>()
    )
}

#[test]
fn portable_replay_joins_historical_runtime_tips_to_real_authenticated_prefix() {
    // Height five is neither a current peer tip nor an allocation carrier.
    // Replay must explicitly retain it for the historical runtime checkpoint.
    let mut fixture = Fixture::with_tip_heights([6, 6, 7, 6]);
    let proof: SumeragiFinalityProof =
        json::from_slice(&fixture.originals["proof-00000000000000000005.json"]).unwrap();
    let record = runtime_checkpoint_claims(5, proof.block_header.hash().into());
    let claims =
        runtime_update::test_chain_retained_tip_claims(5, proof.block_header.hash().into())
            .unwrap();
    fixture.replay_with_tips(&claims).unwrap();

    let claims =
        runtime_update::test_chain_retained_tip_claims(5, Hash::new(b"different retained block"))
            .unwrap();
    assert!(
        fixture
            .replay_with_tips(&claims)
            .unwrap_err()
            .to_string()
            .contains("differs from authenticated finality")
    );

    let beyond = runtime_checkpoint_claims(8, proof.block_header.hash().into());
    let claims = runtime_update::RetainedTips::from_checkpoint_records([&beyond]).unwrap();
    assert!(
        fixture
            .replay_with_tips(&claims)
            .unwrap_err()
            .to_string()
            .contains("exceeds the completed authenticated prefix")
    );

    // A longer peer prefix must not mask another peer regressing below its own checkpoint.
    let proof7: SumeragiFinalityProof =
        json::from_slice(&fixture.originals["proof-00000000000000000007.json"]).unwrap();
    let beyond_peer = runtime_checkpoint_claims(7, proof7.block_header.hash().into());
    let claims = runtime_update::RetainedTips::from_checkpoint_records([&beyond_peer]).unwrap();
    assert!(
        fixture
            .replay_with_tips(&claims)
            .unwrap_err()
            .to_string()
            .contains("peer's signed current height")
    );

    let claims = runtime_update::RetainedTips::from_checkpoint_records([&record]).unwrap();
    let saved = fixture
        .originals
        .remove("proof-00000000000000000005.json")
        .unwrap();
    assert!(fixture.replay_with_tips(&claims).is_err());
    fixture
        .originals
        .insert("proof-00000000000000000005.json".into(), saved);
    fixture.replay_with_tips(&claims).unwrap();

    // The live completion invokes exactly the same check after ProofPrefix::synchronize.
    let mut prefix = BTreeMap::new();
    prefix.insert(5, proof);
    claims
        .verify_authenticated_prefix(&prefix, [6, 6, 7, 6])
        .unwrap();
    prefix.clear();
    assert!(
        claims
            .verify_authenticated_prefix(&prefix, [6, 6, 7, 6])
            .is_err()
    );
}
