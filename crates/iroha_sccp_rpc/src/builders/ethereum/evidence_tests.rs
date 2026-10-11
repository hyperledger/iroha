//! Ethereum evidence and advance builders over synthetic and recorded chains (spec §4.13.5,
//! §11): the ancestry window edges `E − B = 256 / 257` and `8191 / 8192`, checkpoint anchors
//! and `Backfill` segments, advance stepping under `max_advance_bytes`, and the captured mainnet
//! responses of `fixtures/sccp/rpc/eth/`. Every built piece is verified by the production
//! verifier through [`LightClientReplayV1`].

use std::{collections::BTreeMap, fs, path::PathBuf};

use iroha_data_model::sccp::light_client::SccpLightClientParamsV1;
use iroha_sccp::{
    light_client::{
        self as lc, SccpLcError, ethereum::EthereumLcError, profile::ETHEREUM_MAINNET,
        proof::SccpNormalizedEventV1,
    },
    test_support::ethereum::{
        SYNTHETIC_BEACON_SEED_V1, SyntheticBeaconChainV1, SyntheticBlockFieldsV1,
        execution_header_rlp, execution_of, header_chain, header_rlp_from_rpc_json, history_state,
        mpt_proof_from_rpc_json, receipt_from_rpc_json, receipt_root_and_proof, successful_receipt,
        transfer_log,
    },
    v1::{
        evm_abi::{AbiError, TransferToTairaLogV1},
        hashes::keccak256,
    },
};

use super::*;
use crate::builders::{LightClientReplayV1, MAX_BACKFILL_SEGMENTS};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const PERIOD: u64 = 1_868;
const EVENT: u64 = 20_000_000;
const EMITTER: [u8; 20] = [0x22; 20];
const TX: [u8; 32] = [0x7a; 32];

fn slot(offset: u64) -> u64 {
    PERIOD * SLOTS_PER_PERIOD + offset
}

fn params() -> SccpLightClientParamsV1 {
    SccpLightClientParamsV1::defaults_for(ETH).expect("external network")
}

/// Ethereum data served from memory.
#[derive(Default)]
struct MemorySource {
    finality: Option<EthereumNativeLightClientUpdateV1>,
    updates: BTreeMap<u64, EthereumNativeLightClientUpdateV1>,
    event: Option<EvmEventBlockV1>,
    headers: BTreeMap<u64, Vec<u8>>,
    /// History proofs of the event block by anchor height (the state an endpoint serves).
    history: BTreeMap<u64, EthereumHistoryProofV1>,
}

impl EthereumSource for MemorySource {
    fn finality_update(&self) -> Result<EthereumNativeLightClientUpdateV1, BuildError> {
        self.finality
            .clone()
            .ok_or_else(|| BuildError::Unavailable("no finality".into()))
    }

    fn committee_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<EthereumNativeLightClientUpdateV1>, BuildError> {
        Ok((start_period..start_period + count)
            .filter_map(|period| self.updates.get(&period).cloned())
            .collect())
    }

    fn event_block(&self, _tx_hash: &[u8; 32]) -> Result<EvmEventBlockV1, BuildError> {
        self.event
            .clone()
            .ok_or_else(|| BuildError::Unavailable("not mined".into()))
    }

    fn headers(&self, first: u64, last: u64) -> Result<Vec<Vec<u8>>, BuildError> {
        (first..=last)
            .map(|number| {
                self.headers
                    .get(&number)
                    .cloned()
                    .ok_or_else(|| BuildError::Unavailable(format!("block {number} is not served")))
            })
            .collect()
    }

    fn history_proof(
        &self,
        anchor: u64,
        _event: u64,
        _event_hash: [u8; 32],
    ) -> Result<EthereumHistoryProofV1, BuildError> {
        self.history.get(&anchor).cloned().ok_or_else(|| {
            BuildError::Unavailable(format!("the state of block {anchor} is not served"))
        })
    }
}

fn transfer() -> TransferToTairaLogV1 {
    TransferToTairaLogV1 {
        message_id: [0x99; 32],
        sender: [0x5e; 20],
        nonce: 11,
        payload: vec![1, 2, 3],
    }
}

/// A burn at block `EVENT` and a finalized block `E = EVENT + distance` 10 minutes before
/// `now`, whose state proves the burn's hash through EIP-2935 when `history` is served. The
/// light client was bootstrapped in `PERIOD` with a checkpoint at `E`.
struct Scenario {
    source: MemorySource,
    replay: LightClientReplayV1,
    now: u64,
    anchor: u64,
}

fn scenario(distance: u64, history: bool) -> Scenario {
    let beacon = SyntheticBeaconChainV1::new(SYNTHETIC_BEACON_SEED_V1);
    let now = beacon.slot_unix_ms(slot(1_000));
    let anchor_time = now / 1_000 - 600;
    let receipts = vec![
        successful_receipt(Vec::new()),
        successful_receipt(vec![transfer_log(EMITTER, &transfer())]),
    ];
    let (receipts_root, receipt_proof) = receipt_root_and_proof(&receipts, 1);
    let event_header = execution_header_rlp(&SyntheticBlockFieldsV1 {
        parent_hash: keccak256(&[b"parent"]),
        number: EVENT,
        timestamp: anchor_time - 12 * distance,
        state_root: keccak256(&[b"event-state"]),
        receipts_root,
    });
    let event_hash = keccak256(&[&event_header]);
    let mut headers = BTreeMap::from([(EVENT, event_header.clone())]);
    let mut history_proofs = BTreeMap::new();
    let anchor_header = if distance == 0 {
        event_header.clone()
    } else {
        let links = header_chain(&event_header, usize::try_from(distance - 1).expect("small"));
        let parent = links.last().unwrap_or(&event_header).clone();
        for (number, link) in (EVENT + 1..).zip(links) {
            headers.insert(number, link);
        }
        let (state_root, proof) = history_state(&ETHEREUM_MAINNET, EVENT, event_hash);
        if history {
            history_proofs.insert(EVENT + distance, proof);
        }
        let header = execution_header_rlp(&SyntheticBlockFieldsV1 {
            parent_hash: keccak256(&[&parent]),
            number: EVENT + distance,
            timestamp: anchor_time,
            state_root,
            receipts_root: keccak256(&[b"anchor-receipts"]),
        });
        headers.insert(EVENT + distance, header.clone());
        header
    };
    let anchor = execution_of(&anchor_header);
    let finality = beacon.finality_update_for(anchor, beacon.signature_slot_for(&anchor));
    let initial = lc::verify_bootstrap(
        ETH,
        &params(),
        &beacon.bootstrap_with_execution(slot(990), &anchor),
        now,
    )
    .expect("fresh bootstrap");
    Scenario {
        source: MemorySource {
            finality: Some(finality),
            event: Some(EvmEventBlockV1 {
                header: event_header,
                number: EVENT,
                transaction_index: 1,
                receipt_proof,
            }),
            headers,
            history: history_proofs,
            ..MemorySource::default()
        },
        replay: LightClientReplayV1::installed(ETH, &initial),
        now,
        anchor: EVENT + distance,
    }
}

fn decoded(evidence: &SourceEvidenceV1) -> EthereumSourceProofV1 {
    let SccpSourceProofV1::Ethereum(proof) =
        SccpSourceProofV1::from_frame(evidence.proof.as_bytes()).expect("proof frame")
    else {
        panic!("an Ethereum proof");
    };
    proof
}

fn build(scenario: &Scenario) -> Result<SourceEvidenceV1, BuildError> {
    build_evidence(
        &scenario.source,
        &TX,
        EthereumEventV1::TransferToTaira { log_index: 0 },
        &scenario.replay,
    )
}

/// Verify `evidence` through the production verifier and check it proves the burn.
fn assert_proves_the_burn(scenario: &Scenario, evidence: &SourceEvidenceV1) {
    let verified = scenario
        .replay
        .verify_evidence(evidence, scenario.now)
        .expect("the evidence verifies");
    assert!(matches!(
        verified.event,
        SccpNormalizedEventV1::TransferToTaira { nonce: 11, .. }
    ));
    assert_eq!(verified.event.locator().source_height, EVENT);
}

#[test]
fn finality_anchors_use_header_chains_up_to_256_blocks() {
    for distance in [0, 1, 256] {
        let scenario = scenario(distance, false);
        let evidence = build(&scenario).expect("evidence");
        assert!(evidence.backfills.is_empty());
        let proof = decoded(&evidence);
        assert!(matches!(
            proof.anchor,
            EthereumProofAnchorV1::FinalityUpdate(_)
        ));
        match (distance, &proof.ancestry) {
            (0, EthereumAncestryV1::SameBlock) => {}
            (_, EthereumAncestryV1::HeaderChain(segment)) => {
                assert_eq!(segment.headers.len() as u64, distance);
            }
            (_, other) => panic!("E - B = {distance}: unexpected {other:?}"),
        }
        assert_proves_the_burn(&scenario, &evidence);
    }
}

#[test]
fn history_contract_reaches_257_and_8191_blocks() {
    for distance in [9, 257, 8_191] {
        let scenario = scenario(distance, true);
        let evidence = build(&scenario).expect("evidence");
        assert!(evidence.backfills.is_empty());
        let proof = decoded(&evidence);
        assert!(matches!(
            proof.anchor,
            EthereumProofAnchorV1::FinalityUpdate(_)
        ));
        assert!(
            matches!(proof.ancestry, EthereumAncestryV1::HistoryContract(_)),
            "E - B = {distance} uses the history contract"
        );
        assert_proves_the_burn(&scenario, &evidence);
    }
    // Close to the anchor a short header chain is preferred even when the state is served.
    let scenario = scenario(8, true);
    let proof = decoded(&build(&scenario).expect("evidence"));
    assert!(matches!(proof.ancestry, EthereumAncestryV1::HeaderChain(_)));
}

#[test]
fn beyond_the_windows_evidence_backfills_from_the_checkpoint() {
    // 257 blocks without served state: one backfill from the checkpoint at `E`, then two
    // headers.
    let scenario_257 = scenario(257, false);
    let evidence = build(&scenario_257).expect("evidence");
    assert_eq!(evidence.backfills.len(), 1);
    let proof = decoded(&evidence);
    assert_eq!(
        proof.anchor,
        EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
            source_height: scenario_257.anchor - 255,
        })
    );
    let EthereumAncestryV1::HeaderChain(segment) = &proof.ancestry else {
        panic!("a header chain");
    };
    assert_eq!(segment.headers.len(), 2);
    assert_proves_the_burn(&scenario_257, &evidence);
    // 8 192 blocks are past the EIP-2935 window even with served state: 32 backfills.
    let scenario_8192 = scenario(8_192, true);
    let evidence = build(&scenario_8192).expect("evidence");
    assert_eq!(evidence.backfills.len(), 32);
    assert!(evidence.backfills.len() <= MAX_BACKFILL_SEGMENTS);
    assert!(matches!(
        decoded(&evidence).anchor,
        EthereumProofAnchorV1::StoredCheckpoint(_)
    ));
    assert_proves_the_burn(&scenario_8192, &evidence);
    // Without a retained checkpoint above the burn nothing anchors it.
    let mut bare = scenario(8_192, true);
    bare.replay = LightClientReplayV1::new(
        ETH,
        bare.replay.light_client().expect("installed"),
        bare.replay.sets().expect("sets"),
        Vec::new(),
    );
    assert!(matches!(build(&bare), Err(BuildError::Unavailable(_))));
}

#[test]
fn checkpoint_anchors_serve_a_light_client_without_the_finality_committee() {
    let mut scenario = scenario(300, true);
    let mut light_client = scenario.replay.light_client().expect("installed");
    light_client.head.latest_set_id = PERIOD - 1;
    let checkpoint = scenario
        .replay
        .checkpoint_covering(EVENT)
        .expect("read")
        .expect("checkpoint at E");
    scenario.replay = LightClientReplayV1::new(
        ETH,
        light_client,
        scenario.replay.sets().expect("sets"),
        vec![checkpoint],
    );
    let evidence = build(&scenario).expect("evidence");
    let proof = decoded(&evidence);
    assert_eq!(
        proof.anchor,
        EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
            source_height: scenario.anchor,
        })
    );
    assert!(matches!(
        proof.ancestry,
        EthereumAncestryV1::HistoryContract(_)
    ));
    assert_proves_the_burn(&scenario, &evidence);
}

#[test]
fn unfinalized_and_lying_sources_are_refused() {
    let mut scenario = scenario(4, false);
    let mut event = scenario.source.event.clone().expect("event");
    event.number = scenario.anchor + 1;
    scenario.source.event = Some(event);
    assert!(matches!(build(&scenario), Err(BuildError::Unavailable(_))));
    // A header chain that does not link to the anchor is caught before submission.
    let mut scenario = self::scenario(4, false);
    let wrong = scenario.source.headers[&(EVENT + 1)].clone();
    scenario.source.headers.insert(EVENT + 2, wrong);
    let error = build(&scenario).expect_err("broken links");
    assert!(error.to_string().contains("does not follow"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// Advance stepping
// ---------------------------------------------------------------------------------------------

#[test]
fn advances_step_a_light_client_twelve_periods_behind_under_256_kib() {
    let beacon = SyntheticBeaconChainV1::new(SYNTHETIC_BEACON_SEED_V1);
    let behind = 12;
    let head_period = PERIOD + behind;
    let finalized = head_period * SLOTS_PER_PERIOD + 100;
    let finality =
        beacon.finality_update_for(beacon.synthetic_execution(finalized), finalized + 65);
    let now = beacon.slot_unix_ms(head_period * SLOTS_PER_PERIOD + 300);
    let source = MemorySource {
        finality: Some(finality),
        updates: (PERIOD..head_period)
            .map(|period| (period, beacon.period_update(period)))
            .collect(),
        ..MemorySource::default()
    };
    let initial = lc::verify_bootstrap(
        ETH,
        &params(),
        &beacon.bootstrap_with_execution(slot(64), &beacon.synthetic_execution(slot(64))),
        now,
    )
    .expect("the bootstrap committee is still fresh");
    let mut replay = LightClientReplayV1::installed(ETH, &initial);
    let budget = AdvanceBudgetV1::for_params(&params(), 262_144);
    // In one piece the advance exceeds the keeper's default budget and used to be dropped.
    let whole = build_advance(
        &source,
        PERIOD,
        AdvanceBudgetV1 {
            max_items: 16,
            max_bytes: usize::MAX,
        },
    )
    .expect("advance");
    assert!(whole.len() > budget.max_bytes);
    let mut advances = 0;
    loop {
        let head = replay.light_client().expect("installed").head;
        if head.latest_finalized.source_height == finalized {
            break;
        }
        let advance = build_advance(&source, head.latest_set_id, budget).expect("advance");
        assert!(advance.len() <= budget.max_bytes);
        let delta = replay
            .advance(&advance, now)
            .expect("the stepped advance verifies");
        assert!(delta.moves_head());
        advances += 1;
        assert!(advances <= 3, "the light client catches up in a few steps");
    }
    assert!(advances >= 2);
    assert_eq!(
        replay.light_client().expect("installed").head.latest_set_id,
        head_period
    );
}

// ---------------------------------------------------------------------------------------------
// Captured mainnet responses
// ---------------------------------------------------------------------------------------------

const MAINNET_EVENT: u64 = 26_069_527;
const MAINNET_FINALIZED: u64 = 26_069_545;

fn rpc_json(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp/rpc/eth")
        .join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    norito::json::from_str(&text).expect("captured JSON parses")
}

fn result(value: &Value) -> &Value {
    value.get("result").expect("JSON-RPC result")
}

/// The captured blocks, receipts, history proof and beacon responses as an
/// [`EthereumSource`], and the captured receipt's first three-topic log.
fn mainnet_source(history: bool) -> (MemorySource, u32) {
    let schedule = ETHEREUM_MAINNET.schedule().expect("mainnet");
    let finality =
        update_from_beacon_json(&rpc_json("finality_update.json"), &schedule).expect("finality");
    let updates = rpc_json("updates.json")
        .as_array()
        .expect("update list")
        .iter()
        .map(|update| update_from_beacon_json(update, &schedule).expect("update"))
        .map(|update| {
            let period = update
                .attested_header
                .to_native()
                .expect("header")
                .beacon()
                .slot
                / SLOTS_PER_PERIOD;
            (period, update)
        })
        .collect();
    let headers: BTreeMap<u64, Vec<u8>> = (MAINNET_EVENT..=MAINNET_FINALIZED)
        .map(|number| {
            let block = rpc_json(&format!("block_{number}.json"));
            (number, header_rlp_from_rpc_json(result(&block)))
        })
        .collect();
    let receipts = rpc_json(&format!("receipts_{MAINNET_EVENT}.json"));
    let receipts = result(&receipts).as_array().expect("receipts");
    let entries: Vec<(Vec<u8>, Vec<u8>)> = receipts
        .iter()
        .zip(0_u64..)
        .map(|(receipt, index)| (rlp_encode_u64(index), receipt_from_rpc_json(receipt)))
        .collect();
    let (index, log_index) = receipts
        .iter()
        .enumerate()
        .find_map(|(index, receipt)| {
            receipt
                .get("logs")
                .and_then(Value::as_array)
                .and_then(|logs| {
                    logs.iter().position(|log| {
                        log.get("topics")
                            .and_then(Value::as_array)
                            .is_some_and(|topics| topics.len() == 3)
                    })
                })
                .map(|log_index| (index, log_index))
        })
        .expect("a receipt with a three-topic log");
    let event = EvmEventBlockV1 {
        header: headers[&MAINNET_EVENT].clone(),
        number: MAINNET_EVENT,
        transaction_index: u32::try_from(index).expect("index"),
        receipt_proof: mpt_proof(&entries, &entries[index].0).expect("receipt proof"),
    };
    let mut history_proofs = BTreeMap::new();
    if history {
        let proof = rpc_json("history_proof.json");
        let proof = result(&proof);
        let storage = proof
            .get("storageProof")
            .and_then(Value::as_array)
            .and_then(|proofs| proofs.first())
            .expect("one storage proof");
        history_proofs.insert(
            MAINNET_FINALIZED,
            EthereumHistoryProofV1 {
                account_proof: mpt_proof_from_rpc_json(proof, "accountProof"),
                storage_proof: mpt_proof_from_rpc_json(storage, "proof"),
            },
        );
    }
    (
        MemorySource {
            finality: Some(finality),
            updates,
            event: Some(event),
            headers,
            history: history_proofs,
        },
        u32::try_from(log_index).expect("log index"),
    )
}

#[test]
fn captured_mainnet_responses_build_advances_and_select_ancestry() {
    let (source, log_index) = mainnet_source(true);
    let finality = source.finality.clone().expect("finality");
    let now = ETHEREUM_MAINNET
        .slot_start_ms(finality.signature_slot)
        .expect("time")
        + 60_000;
    let bootstrap = SccpLcBootstrapDataV1::Ethereum(
        bootstrap_from_beacon_json(&rpc_json("bootstrap.json")).expect("bootstrap"),
    )
    .to_bootstrap()
    .expect("bootstrap frame");
    let initial =
        lc::verify_bootstrap(ETH, &params(), &bootstrap, now).expect("captured bootstrap");
    let mut replay = LightClientReplayV1::installed(ETH, &initial);
    let stored = replay.light_client().expect("installed").head.latest_set_id;
    assert_eq!(stored, 1_867);
    let budget = AdvanceBudgetV1::for_params(&params(), 262_144);
    let advance = build_advance(&source, stored, budget).expect("advance");
    replay
        .advance(&advance, now)
        .expect("the captured advance verifies");
    let head = replay.light_client().expect("installed").head;
    assert_eq!(head.latest_set_id, 1_868);
    assert_eq!(head.latest_finalized.source_height, MAINNET_FINALIZED);
    // Mainnet has no SCCP deployment: a built proof passes finality, ancestry and receipt
    // inclusion and stops at the event decoding.
    let not_sccp = || {
        Err(SccpLcError::Ethereum(EthereumLcError::Event(
            AbiError::WrongTopic,
        )))
    };
    let event = EthereumEventV1::TransferToTaira { log_index };
    let evidence = build_evidence(&source, &TX, event, &replay).expect("evidence");
    assert!(matches!(
        decoded(&evidence).ancestry,
        EthereumAncestryV1::HistoryContract(_)
    ));
    assert_eq!(
        replay.verify_evidence(&evidence, now).map(|_| ()),
        not_sccp()
    );
    // An endpoint without the state of `E` falls back to the captured header chain.
    let (stateless, _) = mainnet_source(false);
    let evidence = build_evidence(&stateless, &TX, event, &replay).expect("evidence");
    let EthereumAncestryV1::HeaderChain(segment) = decoded(&evidence).ancestry else {
        panic!("a header chain");
    };
    assert_eq!(
        segment.headers.len() as u64,
        MAINNET_FINALIZED - MAINNET_EVENT
    );
    assert_eq!(
        replay.verify_evidence(&evidence, now).map(|_| ()),
        not_sccp()
    );
}
