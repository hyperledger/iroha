//! Native deployment trust-input checks; no HTTP or ledger mutation.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};

#[test]
fn deployment_committee_preflight_checks_exact_role_pop_and_both_activation_heights() {
    use iroha_data_model::consensus::{
        ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus,
    };
    let authority = test_trust().authority(test_network_id()).unwrap();
    let records: Vec<_> = authority
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| ConsensusKeyRecord {
            id: ConsensusKeyId::new(ConsensusKeyRole::Committee, format!("parent-{index}")),
            public_key: validator.public_key.clone(),
            pop: Some(validator.proof_of_possession.clone()),
            activation_height: 12,
            expiry_height: Some(14),
            replaces: None,
            // Pending is accepted at its scheduled height by the native lifecycle rule.
            status: ConsensusKeyStatus::Pending,
        })
        .collect();
    validate_committee_snapshot(&authority, &records, 10).unwrap();
    let mut retiring = records.clone();
    retiring[0].status = ConsensusKeyStatus::Retiring;
    validate_committee_snapshot(&authority, &retiring, 10).unwrap();

    for mutation in 0..7 {
        let mut changed = records.clone();
        match mutation {
            0 => changed[0].id.role = ConsensusKeyRole::Validator,
            1 => changed[0].status = ConsensusKeyStatus::Disabled,
            2 => changed[0].activation_height = 13,
            3 => changed[0].expiry_height = Some(13),
            4 => changed[0].pop = None,
            5 => changed[0].pop.as_mut().unwrap()[0] ^= 1,
            _ => {
                changed.remove(0);
            }
        }
        let error = validate_committee_snapshot(&authority, &changed, 10).unwrap_err();
        assert!(
            error.to_string().contains("Committee credential"),
            "{error}"
        );
    }
    assert!(validate_committee_snapshot(&authority, &records, 0).is_err());
    assert!(validate_committee_snapshot(&authority, &records, u64::MAX - 2).is_err());

    // A scheduled replacement with the same trusted key may cover the second height.
    let mut split = records;
    split[0].expiry_height = Some(13);
    let mut replacement = split[0].clone();
    replacement.id = ConsensusKeyId::new(ConsensusKeyRole::Committee, "replacement");
    replacement.activation_height = 13;
    replacement.expiry_height = None;
    split.push(replacement);
    validate_committee_snapshot(&authority, &split, 10).unwrap();
}

#[test]
fn deployment_committee_observation_refreshes_after_proof_replay_and_bounds_head_races() {
    use iroha_data_model::consensus::{
        ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus,
    };
    let authority = test_trust().authority(test_network_id()).unwrap();
    let records: Vec<_> = authority
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| ConsensusKeyRecord {
            id: ConsensusKeyId::new(ConsensusKeyRole::Committee, format!("parent-{index}")),
            public_key: validator.public_key.clone(),
            pop: Some(validator.proof_of_possession.clone()),
            activation_height: 1,
            expiry_height: None,
            replaces: None,
            status: ConsensusKeyStatus::Active,
        })
        .collect();
    for (heights, succeeds, snapshots) in [
        (vec![50, 51, 52, 52], true, 2),
        (vec![9], false, 0),
        (vec![50, 49], false, 1),
        (vec![50, 51, 51, 52, 52, 53], false, 3),
    ] {
        let mut heights = heights.into_iter();
        let mut reads = 0;
        let result = observe_committee_snapshot(
            &authority,
            10,
            || Ok(heights.next().expect("bounded status reads")),
            || {
                reads += 1;
                Ok(records.clone())
            },
        );
        assert_eq!(result.is_ok(), succeeds, "{result:?}");
        assert_eq!(reads, snapshots);
        assert!(heights.next().is_none());
    }
    let mut reads = 0;
    let error = observe_committee_snapshot(
        &authority,
        10,
        || Ok(50),
        || {
            reads += 1;
            eyre::bail!("invalid operator response")
        },
    )
    .unwrap_err();
    assert_eq!(reads, 1);
    assert!(error.to_string().contains("invalid operator response"));
}

#[test]
fn deployment_trust_derives_exact_genesis_roster_and_network() {
    let trust = test_trust();
    let network = test_network_id();
    let authority = trust
        .authority(network)
        .expect("exact public genesis trust");
    assert_eq!(authority.network, network);
    assert_eq!(NetworkId::from_genesis_hash(authority.genesis), network);
    assert_eq!(authority.validators.len(), 4);
    assert_eq!(authority.trusted_genesis.hash(), authority.genesis);
    let mut expected = trust
        .peers
        .iter()
        .map(|peer| peer.peer_id.clone())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        authority
            .validators
            .iter()
            .map(|member| PeerId::new(member.public_key.clone()))
            .collect::<Vec<_>>(),
        expected
    );
    for member in &authority.validators {
        iroha_crypto::bls_normal_pop_verify(&member.public_key, &member.proof_of_possession)
            .expect("native PoP");
    }
    assert_eq!(
        trust,
        test_trust(),
        "public fixture identity must be stable across calls"
    );
    let mut reordered = trust;
    reordered.peers.reverse();
    let reordered = reordered
        .authority(network)
        .expect("explicit peer observation order");
    assert_eq!(reordered.validators, authority.validators);
    assert_eq!(reordered.trusted_genesis, authority.trusted_genesis);
}

#[test]
fn deployment_trust_uses_explicit_chain_and_requires_address_profile() {
    let mut trust = test_trust();
    let original_instance = trust
        .authority(test_network_id())
        .unwrap()
        .verifier()
        .unwrap()
        .instance();
    trust.chain = "private-selected-chain".parse().unwrap();
    trust.account_chain_discriminant = 901;
    let authority = trust.authority(test_network_id()).unwrap();
    assert_eq!(authority.chain, trust.chain);
    assert_ne!(
        authority.verifier().unwrap().instance(),
        original_instance,
        "changing the explicit chain must never fall back to the compiled Taira chain"
    );
    trust.account_chain_discriminant = 0;
    assert!(trust.authority(test_network_id()).is_err());
    for key in ["chain", "account_chain_discriminant"] {
        let mut profile = json::to_value(&test_trust()).unwrap();
        profile.as_object_mut().unwrap().remove(key);
        assert!(
            json::from_value::<TrustV1>(profile).is_err(),
            "missing {key} must not infer a network pin"
        );
    }
}

#[test]
fn deployment_peer_clients_reject_runtime_chain_pin_mismatch_before_io() {
    let trust = test_trust();
    let owner = KeyPair::try_from_seed(vec![0xAF; 32], Algorithm::Ed25519).unwrap();
    let mut context = crate::PrintJsonContext {
        write: Vec::<u8>::new(),
        err_write: Vec::<u8>::new(),
        config: crate::client_config_with_defaults(
            trust.chain.clone(),
            test_network_id(),
            owner,
            trust.account_chain_discriminant,
            trust.peers[0].torii_origin.parse().unwrap(),
        ),
        filesystem_config: crate::client_config::FilesystemConfig::default(),
        offline_fallback: false,
        operator_key_pair: None,
        transaction_metadata: None,
        fee_payment: crate::FeePaymentArgs::default(),
        input_instructions: false,
        output_instructions: false,
        output_format: crate::CliOutputFormat::Json,
        json_lines: false,
        i18n: iroha_i18n::Localizer::new(iroha_i18n::Bundle::Cli, iroha_i18n::Language::English),
    };
    assert_eq!(peer_clients(&context, &trust, &[]).unwrap().len(), 4);
    let routes: Vec<_> = (9100..9104)
        .map(|port| format!("http://127.0.0.1:{port}/"))
        .collect();
    let routed = peer_clients(&context, &trust, &routes).unwrap();
    for (client, origin) in routed.iter().zip(&routes) {
        assert_eq!(client.to_builder().torii_url.as_str(), origin);
    }
    assert_eq!(
        context.config.torii_api_url.as_str(),
        trust.peers[0].torii_origin
    );

    context.config.chain = "other-chain".into();
    assert!(peer_clients(&context, &trust, &[]).is_err());
    context.config.chain = trust.chain.clone();
    context.config.account_chain_discriminant = 901;
    assert!(peer_clients(&context, &trust, &[]).is_err());
}

#[test]
fn deployment_trust_rejects_wrong_network_key_and_changed_genesis_wire() {
    let trust = test_trust();
    let network = test_network_id();
    let wrong_network =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"other genesis")));
    assert!(trust.authority(wrong_network).is_err());
    let mut changed = trust.clone();
    changed.genesis_public_key = KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519)
        .expect("other genesis key")
        .public_key()
        .clone();
    assert!(changed.authority(network).is_err());
    for wire in [
        String::new(),
        trust.genesis_signed_wire_hex.to_uppercase(),
        format!("{}00", trust.genesis_signed_wire_hex),
        "00".repeat(MAX_BYTES / 2 + 1),
    ] {
        let mut changed = trust.clone();
        changed.genesis_signed_wire_hex = wire;
        assert!(changed.authority(network).is_err());
    }
    let mut changed = trust;
    let mut wire = hex::decode(&changed.genesis_signed_wire_hex).expect("wire");
    let last = wire.last_mut().expect("nonempty genesis");
    *last ^= 1;
    changed.genesis_signed_wire_hex = hex::encode(wire);
    assert!(changed.authority(network).is_err());
}

#[test]
fn deployment_trust_requires_four_distinct_genesis_peers_and_public_endpoints() {
    let trust = test_trust();
    let network = test_network_id();
    let mut changed = trust.clone();
    changed.peers.pop();
    assert!(changed.authority(network).is_err());
    let mut changed = trust.clone();
    changed.peers.push(trust.peers[0].clone());
    assert!(changed.authority(network).is_err());
    let mut changed = trust.clone();
    changed.peers[1].peer_id = trust.peers[0].peer_id.clone();
    changed.peers[1].node_fingerprint = trust.peers[0].node_fingerprint;
    assert!(changed.authority(network).is_err());
    let mut changed = trust.clone();
    changed.peers[1].torii_origin = trust.peers[0].torii_origin.clone();
    assert!(
        changed.authority(network).is_ok(),
        "transport is not validator identity"
    );
    assert!(verification_origins(&changed, &[]).is_err());
    let routes: Vec<_> = trust
        .peers
        .iter()
        .map(|peer| peer.torii_origin.clone())
        .collect();
    assert_eq!(verification_origins(&changed, &routes).unwrap(), routes);
    assert_eq!(changed.peers[1].torii_origin, trust.peers[0].torii_origin);
    let mut changed = trust.clone();
    let unknown =
        KeyPair::try_from_seed(vec![92; 32], Algorithm::BlsNormal).expect("foreign validator");
    changed.peers[0].peer_id = PeerId::new(unknown.public_key().clone());
    changed.peers[0].node_fingerprint = Hash::new(changed.peers[0].peer_id.encode());
    assert!(
        changed.authority(network).is_err(),
        "a self-consistent foreign peer cannot bootstrap trust"
    );
    let mut changed = trust.clone();
    changed.peers[0].node_fingerprint = Hash::new(b"foreign node fingerprint");
    assert!(changed.authority(network).is_err());
    for origin in [
        "file:///tmp/",
        "http://user:secret@127.0.0.1:8080/",
        "http://127.0.0.1:8080/?a=1",
        "http://127.0.0.1:8080/#fragment",
        "http://127.0.0.1:8080",
    ] {
        let mut changed = trust.clone();
        changed.peers[0].torii_origin = origin.to_owned();
        assert!(changed.authority(network).is_err(), "{origin}");
    }
}

#[test]
fn deployment_peer_reads_overlap_and_preserve_input_order() {
    use std::sync::{Arc, Condvar, Mutex, mpsc};

    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (started, arrivals) = mpsc::channel();
    let worker_gate = Arc::clone(&gate);
    let worker = std::thread::spawn(move || {
        read_four_peers(&[40, 30, 20, 10], 369, |index, input| {
            started.send(index).expect("observe each started peer");
            let (lock, ready) = &*worker_gate;
            let released = lock.lock().expect("release lock");
            let _released = ready
                .wait_while(released, |released| !*released)
                .expect("release wait");
            Ok(*input)
        })
    });
    let mut observed = Vec::new();
    for _ in 0..VERIFICATION_PEERS {
        match arrivals.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(index) => observed.push(index),
            Err(_) => break,
        }
    }
    // Release even on a failed overlap assertion, so serial regressions cannot deadlock.
    let (lock, ready) = &*gate;
    *lock.lock().expect("release lock") = true;
    ready.notify_all();
    let result = worker
        .join()
        .expect("peer coordinator")
        .expect("peer reads");
    observed.sort_unstable();
    assert_eq!(observed, vec![0, 1, 2, 3], "all four reads must overlap");
    assert_eq!(result, vec![40, 30, 20, 10]);
}

#[test]
fn deployment_peer_reads_reject_non_four_cardinality_before_dispatch() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let dispatched = AtomicUsize::new(0);
    for inputs in [vec![], vec![0; 3], vec![0; 5]] {
        let result = read_four_peers(&inputs, 369, |_, _| {
            dispatched.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(result.is_err(), "peer count {}", inputs.len());
    }
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
}

#[test]
fn deployment_peer_reads_join_all_workers_and_report_first_error() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let finished = AtomicUsize::new(0);
    let result = read_four_peers(&[(); 4], 369, |index, _| -> Result<()> {
        finished.fetch_add(1, Ordering::SeqCst);
        Err(eyre!("peer error {index}"))
    });
    assert_eq!(finished.load(Ordering::SeqCst), 4);
    assert_eq!(
        format!("{:#}", result.expect_err("all peers failed")),
        "validator 1 verification failed: peer error 0"
    );
}

#[test]
fn deployment_peer_reads_inherit_configured_address_profile() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};

    let _caller_profile = ChainDiscriminantGuard::enter(0);
    let profiles = read_four_peers(&[(); 4], 369, |_, _| Ok(chain_discriminant()))
        .expect("worker address profiles");
    assert_eq!(profiles, vec![369; 4]);
    assert_eq!(chain_discriminant(), 0, "caller override must remain local");
}

#[test]
fn deployment_peer_reads_recover_worker_panic_after_joining_all() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let finished = AtomicUsize::new(0);
    let result = read_four_peers(&[(); 4], 369, |index, _| {
        assert_ne!(index, 1, "injected peer worker panic");
        finished.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(finished.load(Ordering::SeqCst), 3);
    assert_eq!(
        format!("{:#}", result.expect_err("second worker panicked")),
        "validator 2 verification failed: validator read worker panicked"
    );
}

#[test]
fn deployment_carrier_results_require_exact_bytes_before_publication() {
    let first = BTreeMap::from([(4, vec![1, 2]), (7, vec![3, 4])]);
    let same = BTreeMap::from([(4, vec![1, 2]), (10, vec![5, 6])]);
    let carriers = consistent_carriers([&first, &same]).expect("identical shared carrier");
    assert_eq!(carriers.len(), 3);
    assert_eq!(carriers[&4], &[1, 2]);
    assert_eq!(carriers[&7], &[3, 4]);
    assert_eq!(carriers[&10], &[5, 6]);
    let changed = BTreeMap::from([(4, vec![1, 9])]);
    let error = consistent_carriers([&first, &same, &changed])
        .expect_err("conflicting authenticated bytes cannot be published");
    assert_eq!(
        error.to_string(),
        "validators returned different canonical carrier bytes"
    );
}

fn peer_progress_status(scope: &str, kind: &str) -> Option<PipelineTransactionStatusResponse> {
    Some(PipelineTransactionStatusResponse {
        hash: "ab".repeat(32),
        scope: scope.into(),
        resolved_from: "state".into(),
        status: iroha_torii_shared::PipelineTransactionStatus {
            kind: kind.into(),
            block_height: (kind == "Applied").then_some(10),
        },
    })
}

#[test]
fn deployment_peer_progress_requires_valid_complete_status_pair() {
    let hash = "ab".repeat(32);
    let queued = peer_progress_status("global", "Queued");
    let local = peer_progress_status("local", "Applied");
    let mut invalid = Vec::new();
    invalid.push(peer_progress_status("local", "FutureStatus"));
    invalid.push(peer_progress_status("global", "Applied"));
    let mut wrong_hash = local.clone();
    wrong_hash.as_mut().unwrap().hash = "cd".repeat(32);
    invalid.push(wrong_hash);
    let mut wrong_source = local.clone();
    wrong_source.as_mut().unwrap().resolved_from = "other".into();
    invalid.push(wrong_source);
    for height in [None, Some(0)] {
        let mut wrong_height = local.clone();
        wrong_height.as_mut().unwrap().status.block_height = height;
        invalid.push(wrong_height);
    }
    for local in invalid {
        for global in [None, queued.clone()] {
            assert!(
                peer_carrier_progress("pending", &hash, &global, &local, 9).is_err(),
                "a pending or absent global response must not hide malformed local status"
            );
        }
    }
}

#[test]
fn deployment_peer_progress_retries_only_pending_or_newer_carrier() {
    let hash = "ab".repeat(32);
    let global = peer_progress_status("global", "Applied");
    let local = peer_progress_status("local", "Applied");
    assert!(matches!(
        peer_carrier_progress("pending", &hash, &None, &local, 9).unwrap(),
        PeerRead::Pending
    ));
    assert!(matches!(
        peer_carrier_progress("applied_verification_pending", &hash, &global, &local, 9).unwrap(),
        PeerRead::Pending
    ));
    for tip in [10, 11] {
        assert!(matches!(
            peer_carrier_progress("applied_verification_pending", &hash, &global, &local, tip)
                .unwrap(),
            PeerRead::Verified(10)
        ));
    }
    for kind in ["Rejected", "Expired"] {
        assert!(
            peer_carrier_progress(
                "failed",
                &hash,
                &None,
                &peer_progress_status("local", kind),
                9
            )
            .is_err()
        );
    }
    for state in ["failed", "unknown", "pending"] {
        assert!(peer_carrier_progress(state, &hash, &global, &local, 9).is_err());
    }
}

#[test]
fn deployment_peer_progress_never_masks_fixed_worker_errors() {
    for fixed_peer in [0, 1, 3] {
        let result = read_four_peers(&[(); 4], 369, |index, _| -> Result<PeerRead<()>> {
            if index == fixed_peer {
                Err(eyre!("fixed invalid proof"))
            } else {
                Ok(PeerRead::Pending)
            }
        });
        let error = match result {
            Ok(_) => panic!("peer progress hid a fixed error"),
            Err(error) => error,
        };
        assert_eq!(
            format!("{error:#}"),
            format!(
                "validator {} verification failed: fixed invalid proof",
                fixed_peer + 1
            )
        );
    }
}

fn typed_attestation_progress_error() -> eyre::Report {
    let key = KeyPair::try_from_seed(vec![96; 32], Algorithm::Ed25519).expect("reporter key");
    let node = PeerId::new(key.public_key().clone());
    let network = test_network_id();
    let response = iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1 {
        requested_height: 10,
        applied_height: 9,
        status_height: 10,
        challenge: [17; 32],
        node_id: node.clone(),
        network_id: network,
    };
    iroha::client::BridgeFinalityAttestationTipMismatch::from_response(
        response,
        NonZeroU64::new(10).unwrap(),
        [17; 32],
        &node,
        network,
    )
    .expect("exact request-bound progress")
    .into()
}

#[test]
fn deployment_attestation_progress_retries_only_exact_sdk_type() {
    assert!(matches!(
        peer_attestation_progress(Ok(42_u8)).unwrap(),
        PeerRead::Verified(42)
    ));
    assert!(matches!(
        peer_attestation_progress::<()>(
            Err(typed_attestation_progress_error()).wrap_err("fresh validator attestation")
        )
        .unwrap(),
        PeerRead::Pending
    ));
    for message in [
        "404 query_validation_failed: Query not found in the live query store",
        "409 bridge_finality_attestation_tip_mismatch",
        "finality tip is changing: requested 10, applied 9, consensus status 10",
        "missing durable finality proof",
        "invalid finality attestation signature",
        "operation deadline exhausted",
    ] {
        let error = match peer_attestation_progress::<()>(Err(eyre!(message))) {
            Ok(_) => panic!("untyped error was retried: {message}"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn deployment_attestation_progress_joins_all_peers_and_preserves_fixed_errors() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for fixed_peer in [0, 1, 2, 3] {
        let reads = AtomicUsize::new(0);
        let result = read_four_peers(&[(); 4], 369, |index, _| {
            reads.fetch_add(1, Ordering::SeqCst);
            peer_attestation_progress::<()>(if index == fixed_peer {
                Err(eyre!("fixed malformed attestation"))
            } else {
                Err(typed_attestation_progress_error())
            })
        });
        assert_eq!(reads.load(Ordering::SeqCst), 4);
        let error = match result {
            Ok(_) => panic!("tip mismatch hid a fixed failure"),
            Err(error) => error,
        };
        assert_eq!(
            format!("{error:#}"),
            format!(
                "validator {} verification failed: fixed malformed attestation",
                fixed_peer + 1
            )
        );
    }
}

#[test]
fn completion_requires_the_selected_running_native_dataspace_lane() {
    use iroha_data_model::{
        parameter::system::SumeragiParameters,
        sumeragi::{PROTOCOL_VERSION, SumeragiFootprint, SumeragiStatus},
        sumeragi_lanes::{
            SumeragiFixedLane, SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLanePolicy,
            SumeragiLaneRecord, SumeragiLaneStatus,
        },
    };
    let manifest = super::super::tests::manifest();
    let genesis = iroha_genesis::decode_signed_genesis(
        &hex::decode(&manifest.finality.genesis_signed_wire_hex).unwrap(),
    )
    .unwrap();
    let committee: Vec<_> = iroha_genesis::signed_genesis_validator_pops(&genesis)
        .unwrap()
        .into_iter()
        .map(|(key, pop)| SumeragiLaneMember {
            peer: PeerId::new(key),
            pop,
        })
        .collect();
    let peer = committee[0].peer.clone();
    let mut policy = SumeragiLanePolicy::for_chain(
        SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.fixed.push(SumeragiFixedLane {
        lane: manifest.lane.id,
        dataspace: manifest.lane.dataspace_id,
        committee: committee.clone(),
    });
    let record = SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: manifest.lane.id,
        dataspace: manifest.lane.dataspace_id,
        incarnation: [42; 32],
        params: policy.lane_params.clone(),
        committee,
        created_at: 2,
        active_from: 4,
        closing: None,
        anchor_freshness: policy.anchor_freshness,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 4,
        rescued: 0,
    };
    let instance = iroha_core::sumeragi::lanes::lane_instance(
        &iroha_core::sumeragi::crypto::BlsCrypto::new(),
        &manifest.network_id,
        &manifest.finality.chain.to_string(),
        &record,
    );
    let live = SumeragiLaneStatus {
        record,
        instance: Some(SumeragiStatus {
            protocol_version: PROTOCOL_VERSION,
            config_fingerprint: Hash::new(b"test-lane"),
            beacon_horizon: None,
            instance: instance.0,
            height: 1,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 250,
            committed_height: 0,
            applied_height: 0,
            awaiting: false,
            signer: Some(peer.public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: SumeragiFootprint::default(),
        }),
    };
    let verify =
        |lanes, height| verify_native_lane_snapshot(&manifest, &policy, lanes, &peer, 2, height);
    assert!(matches!(
        verify(vec![live.clone()], 4).unwrap(),
        PeerRead::Verified(_)
    ));
    assert!(matches!(verify(Vec::new(), 4).unwrap(), PeerRead::Pending));
    assert!(matches!(
        verify(vec![live.clone()], 3).unwrap(),
        PeerRead::Pending
    ));
    let mut starting = live.clone();
    starting.instance = None;
    assert!(matches!(
        verify(vec![starting], 4).unwrap(),
        PeerRead::Pending
    ));
    assert!(verify(vec![live.clone(), live.clone()], 4).is_err());
    for defect in 0..10 {
        let mut broken = live.clone();
        match defect {
            0 => broken.record.dataspace = iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            1 => broken.record.created_at = 1,
            2 => broken.record.active_from = 3,
            3 => broken.record.closing = Some(5),
            4 => broken.record.committee.pop().map(|_| ()).unwrap(),
            5 => broken.record.incarnation = [0; 32],
            6 => broken.instance.as_mut().unwrap().instance = [0; 32],
            7 => broken.instance.as_mut().unwrap().abstaining = true,
            8 => broken.instance.as_mut().unwrap().signer = None,
            _ => broken.record.anchor_freshness = 0,
        }
        assert!(verify(vec![broken], 4).is_err(), "defect {defect}");
    }
    // Policy changes affect future lane incarnations; this lane retains its original rules.
    let mut future_policy = policy.clone();
    future_policy.anchor_freshness += 1;
    future_policy.lane_params.block_cadence_ms =
        NonZeroU64::new(future_policy.lane_params.block_cadence_ms.get() + 1).unwrap();
    assert!(matches!(
        verify_native_lane_snapshot(&manifest, &future_policy, vec![live], &peer, 2, 4).unwrap(),
        PeerRead::Verified(_)
    ));
}

#[test]
fn deployment_verification_routes_refuse_partial_duplicate_or_noncanonical_routes() {
    let trust = test_trust();
    let routes: Vec<_> = trust
        .peers
        .iter()
        .map(|peer| peer.torii_origin.clone())
        .collect();
    assert!(verification_origins(&trust, &routes[..3]).is_err());
    let mut duplicate = routes.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(verification_origins(&trust, &duplicate).is_err());
    for invalid in [
        "file:///tmp/",
        "http://user:secret@localhost/",
        "http://localhost/?query=1",
        "http://localhost/#fragment",
        "http://localhost",
    ] {
        let mut changed = routes.clone();
        changed[0] = invalid.into();
        assert!(verification_origins(&trust, &changed).is_err(), "{invalid}");
    }
}

#[test]
fn deployment_route_override_is_only_admitted_for_read_only_status() {
    use clap::Parser as _;
    let trust = test_trust();
    let original = json::to_vec(&trust).unwrap();
    for action in ["plan", "apply", "status"] {
        let mut argv = vec![
            "iroha",
            "dataspace",
            action,
            "dpn.toml",
            "--trust",
            "trust.json",
        ];
        for peer in &trust.peers {
            argv.extend(["--verification-peer-url", peer.torii_origin.as_str()]);
        }
        let args = crate::Args::try_parse_from(argv).unwrap();
        let crate::Command::Dataspace(command) = args.command else {
            panic!("dataspace command")
        };
        assert_eq!(
            command.verification_origins(&trust).is_ok(),
            action == "status"
        );
        assert_eq!(json::to_vec(&trust).unwrap(), original);
    }
}
