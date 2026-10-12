//! Four-validator generic game-session release gate, using RaceV1 only as an application adapter.
//!
//! This starts real peers and never substitutes a verifier or marks a profile qualified.
//! Zero-stake sessions exercise retained inputs, disputes, restart, and genuine native proof
//! settlement while qualification is pending. Every convergence check authenticates the
//! complete original native carrier prefix from the locally signed genesis, including exact
//! quorum certificates, application attestations and witnessed execution commitments. Complete
//! game records are compared independently across every live peer. Consensus fault scenarios
//! belong to the deterministic simulator. Zero-stake settlement does not qualify funded payouts.

use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use std::time::Duration;

use eyre::{Result, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest},
};
use iroha_core_privacy::execution_proofs::{
    compiled_race_profile_v1, prove_race_v1, race_profile_id_v1, race_result_v1,
    race_state_root_v1, race_transcript_root_v1, replay_race_v1, verify_game_proof_for_history_v1,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, Signature};
use iroha_data_model::{
    execution_proofs::{
        ExecutionProofVerificationV1, ExecutionPublicInputsV1, RaceDnfEventV1, RaceInputFrameV1,
        RaceProverRequestV1, RaceReplayV1, RaceTrackV1,
    },
    game::*,
    isi::game::*,
    prelude::*,
    query::game::{FindExecutionProofVerificationById, FindGameSessionById},
    sumeragi_finality::SumeragiFinalityProof,
    transaction::FeePaymentIntent,
};
use iroha_test_network::{
    Network, NetworkBuilder, NetworkPeer, init_instruction_registry, read_on_dedicated_thread,
};
use iroha_test_samples::ALICE_ID;
use norito::codec::Encode;
use tokio::time::{sleep, timeout};
use toml::Table;

fn input_key(slot: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![slot + 41; 32], Algorithm::Ed25519).unwrap()
}

fn fees() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}

fn manifest() -> GameManifestV1 {
    GameManifestV1 {
        version: 1,
        application_id: Hash::new(b"native-game-four-validator-release-gate"),
        profile_id: race_profile_id_v1(),
        application_parameters: RaceTrackV1::NeonTokyo.encode(),
        min_participants: 2,
        max_participants: 2,
        batch_ticks: 6,
        max_ticks: 5400,
        max_input_bytes: 12,
        max_participant_data_bytes: 1,
        access: GameAccessV1::Public,
        payout_policy: GamePayoutPolicyV1::NoPayout,
    }
}

async fn record(client: &Client, session_id: Hash) -> Result<GameSessionRecordV1> {
    let client = client.clone();
    read_on_dedicated_thread(move || {
        Ok(client
            .client()
            .query_single(FindGameSessionById::new(session_id))?)
    })
    .await
}

async fn verification(
    client: &Client,
    verification_id: Hash,
) -> Result<ExecutionProofVerificationV1> {
    let client = client.clone();
    read_on_dedicated_thread(move || {
        Ok(client
            .client()
            .query_single(FindExecutionProofVerificationById::new(verification_id))?)
    })
    .await
}

async fn height(client: &Client) -> Result<u64> {
    Ok(client.client().status().get().await?.blocks)
}

/// Prepare and sign an exact account transaction with its canonical fee quote.
async fn prepare_instruction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
    fee_payment: FeePaymentIntent,
) -> Result<SignedTransaction> {
    let account = client.account_client();
    let instruction: InstructionBox = instruction.into();
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        [instruction],
        fee_payment,
        Metadata::default(),
    ))?;
    let quote = account
        .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
        .await?;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "game fee quote changed the selected payer, sponsor revision, or gas bound"
    );
    payload.fee_payment = quote.intent;
    Ok(account.sign_transaction(payload)?)
}

/// Submit once and require Applied finality before the game-state assertion.
async fn submit_instruction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
    fee_payment: FeePaymentIntent,
) -> Result<HashOf<SignedTransaction>> {
    let transaction = prepare_instruction(client, instruction, fee_payment).await?;
    client
        .account_client()
        .submit_transaction_and_wait(&transaction)
        .await
}

fn signed_checkpoint(
    session: &GameSessionRecordV1,
    checkpoint: GameCheckpointV1,
) -> SignedGameCheckpointV1 {
    let digest = game_message_hash_v1(&session.network_id, "checkpoint", &checkpoint);
    SignedGameCheckpointV1 {
        checkpoint,
        signatures: (0..2)
            .map(|slot| GameSlotSignatureV1 {
                slot,
                signature: Signature::new(input_key(slot).private_key(), digest.as_ref()),
            })
            .collect(),
    }
}

fn challenge(session: &GameSessionRecordV1) -> ChallengeGameSessionV1 {
    let digest = game_message_hash_v1(
        &session.network_id,
        "challenge",
        &(session.session_id, session.epoch, 0_u8),
    );
    ChallengeGameSessionV1 {
        session_id: session.session_id,
        epoch: session.epoch,
        slot: 0,
        signature: Signature::new(input_key(0).private_key(), digest.as_ref()),
    }
}

/// Drive consensus heights with unique ledger transactions, never simulated wall-clock deadlines.
async fn advance_past(client: &Client, deadline: u64) -> Result<()> {
    for ordinal in 0..350_u64 {
        let height = height(client).await?;
        if height > deadline {
            return Ok(());
        }
        submit_instruction(
            client,
            Log::new(
                Level::INFO,
                format!("game deadline {deadline}/{height}/{ordinal}"),
            ),
            fees(),
        )
        .await?;
    }
    Err(eyre!(
        "bounded consensus-height progress did not pass {deadline}"
    ))
}

async fn assert_replicas(
    network: &Network,
    expected: &GameSessionRecordV1,
    expected_running: usize,
) -> Result<()> {
    timeout(Duration::from_secs(120), async {
        loop {
            let running: Vec<_> = network.peers().iter().filter(|peer| peer.is_running()).collect();
            ensure!(running.len() == expected_running, "unexpected live validator count");
            let records = futures_util::future::join_all(running.iter().map(|peer| async move {
                record(&peer.client(), expected.session_id).await
            })).await;
            if records.iter().all(|value| value.as_ref().is_ok_and(|value| value == expected)) {
                let root = Hash::new(expected.encode());
                eprintln!(
                    "generic game record: validators={expected_running}, revision={}, phase={:?}, record_hash={root}, dispute_root={}",
                    expected.revision, expected.phase, expected.dispute_root
                );
                assert_finalized_state_convergence(network, &running).await?;
                return Ok::<(), eyre::Report>(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| eyre!("validators did not converge on exact retained game state"))?
}

/// The endpoint supplies carriers, never the committee used to authenticate them.
async fn finalized_state_observation(
    http: &reqwest::Client,
    peer: &NetworkPeer,
    height: u64,
    network: &Network,
) -> Result<Option<(HashOf<BlockHeader>, Hash)>> {
    let url = peer
        .client()
        .client()
        .endpoint()
        .join(&format!("v1/ledger/state/{height}"))?;
    let mut response = http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(
        response.status().is_success(),
        "ledger-state query failed: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json")),
        "ledger-state carrier is not JSON"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 2 * 1024 * 1024,
            "four-validator finality carrier exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    let value: norito::json::Value = norito::json::from_slice(&bytes)?;
    let fields = value
        .as_object()
        .ok_or_else(|| eyre!("ledger-state carrier is not an object"))?;
    ensure!(
        fields.len() == 5
            && [
                "height",
                "block_hash",
                "witnessed_post_state_root",
                "block_header",
                "finality_proof"
            ]
            .iter()
            .all(|key| fields.contains_key(*key)),
        "unexpected ledger-state carrier fields"
    );
    let reported_height: u64 = norito::json::from_value(value["height"].clone())?;
    let block_hash: HashOf<BlockHeader> = norito::json::from_value(value["block_hash"].clone())?;
    let root: Hash = norito::json::from_value(value["witnessed_post_state_root"].clone())?;
    let header: BlockHeader = norito::json::from_value(value["block_header"].clone())?;
    let proof: SumeragiFinalityProof = norito::json::from_value(value["finality_proof"].clone())?;
    let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&network.genesis().0)?
        .sumeragi_context
        .root_scope;
    let decoded = proof.decode_checked(root_scope.into())?;
    ensure!(
        reported_height == height
            && header.height().get() == height
            && header.hash() == block_hash
            && proof.block_header == header
            && decoded.execution().post_state_root == root,
        "state response does not bind its exact native header and witnessed execution"
    );
    let client = peer.client();
    let mut blocks = read_on_dedicated_thread(move || {
        Ok(client.client().query(FindBlocks::new()).execute_all()?)
    })
    .await?;
    blocks.sort_by_key(|block| block.header().height().get());
    if blocks
        .last()
        .is_none_or(|block| block.header().height().get() < height)
    {
        return Ok(None);
    }
    let original = network.genesis();
    let first = blocks
        .first()
        .ok_or_else(|| eyre!("missing original genesis"))?;
    ensure!(
        first.canonical_resultless_proposal()?.encode_wire()?
            == original.0.canonical_resultless_proposal()?.encode_wire()?,
        "peer history replaced the independently signed genesis"
    );
    // Independent public-history verification owns one finite shared-block pool.
    let budget = iroha_core::state::AllocationBudget::new(32 * 1024 * 1024);
    let genesis = iroha_data_model::block::SharedSignedBlock::try_new(first.clone(), &budget)
        .map_err(|(_, error)| error)?;
    let mut prefix = iroha_core::sumeragi::certified_chain::CertifiedPrefix::new(
        &network.chain_id(),
        network.network_id(),
        genesis,
    )?;
    let mut verified = None;
    for block in blocks
        .into_iter()
        .skip(1)
        .take_while(|block| block.header().height().get() <= height)
    {
        let block = iroha_data_model::block::SharedSignedBlock::try_new(block, &budget)
            .map_err(|(_, error)| error)?;
        let (certified, _) = prefix.push(block)?.into_parts();
        if certified.committed().height() == height {
            verified = Some(certified);
        }
    }
    let certified =
        verified.ok_or_else(|| eyre!("native prefix did not reach requested height"))?;
    let committed = certified.committed();
    ensure!(
        certified
            .commit_qc()
            .is_some_and(|qc| qc.signers.count_ones() == 3)
            && committed.block_hash() == block_hash
            && committed.commitment().execution.post_state_root == root
            && committed.block().encode_wire()? == proof.block_wire,
        "HTTP carrier differs from independently authenticated exact native finality"
    );
    let voters = iroha_core::sumeragi::schedule::genesis_validators(&original)?;
    ensure!(
        voters.len() == 4
            && proof.committee.len() == 4
            && proof
                .committee
                .iter()
                .all(|member| voters.get(&PeerId::new(member.public_key.clone()))
                    == Some(&member.proof_of_possession)),
        "native proof committee differs from the four independently signed genesis voters"
    );
    // Retain the bounded source response only after verifying its complete native prefix.
    let store = peer.kura_store_dir();
    let evidence_dir = store
        .parent()
        .ok_or_else(|| eyre!("peer storage has no evidence parent"))?
        .join("game-finality-evidence");
    std::fs::create_dir_all(&evidence_dir)?;
    std::fs::write(
        evidence_dir.join(format!("{height:020}-ledger-state.json")),
        &bytes,
    )?;
    Ok(Some((block_hash, root)))
}

async fn assert_finalized_state_convergence(
    network: &Network,
    peers: &[&NetworkPeer],
) -> Result<()> {
    let height = futures_util::future::try_join_all(
        peers
            .iter()
            .map(|peer| async move { Ok::<_, eyre::Report>(peer.status().await?.blocks) }),
    )
    .await?
    .into_iter()
    .max()
    .ok_or_else(|| eyre!("no running validators"))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    timeout(Duration::from_secs(90), async {
        loop {
            let mut roots = Vec::new();
            for peer in peers {
                roots.push(finalized_state_observation(&http, peer, height, network).await?);
            }
            if roots.iter().all(Option::is_some) {
                let expected = roots[0].expect("all roots present");
                ensure!(roots.iter().all(|root| *root == Some(expected)),
                    "validators differ in finalized block or execution commitment at height {height}: {roots:?}");
                eprintln!("same-height convergence: validators={}, height={height}, authenticated_block={}, authenticated_execution_post_state_root={}",
                    peers.len(), expected.0, expected.1);
                return Ok::<(), eyre::Report>(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    }).await.map_err(|_| eyre!("same-height finalized native execution convergence timed out"))?
}

/// Submit the original application challenge under current native consensus and compare the
/// complete retained game record. Faulted consensus rounds are qualified in the simulator.
async fn challenge_and_converge(
    network: &Network,
    certified: &GameSessionRecordV1,
) -> Result<GameSessionRecordV1> {
    assert_replicas(network, certified, 4).await?;
    submit_instruction(&network.peers()[0].client(), challenge(certified), fees()).await?;
    let selected = record(&network.peers()[0].client(), certified.session_id).await?;
    ensure!(
        selected.phase == GamePhaseV1::SelectingCheckpoint
            && selected.checkpoint == certified.checkpoint
            && selected.pending_certificate == certified.pending_certificate,
        "native challenge rewrote accepted gameplay evidence"
    );
    assert_replicas(network, &selected, 4).await?;
    Ok(selected)
}

struct ConfigLayer(Table);
impl AsRef<Table> for ConfigLayer {
    fn as_ref(&self) -> &Table {
        &self.0
    }
}

#[test]
#[ignore = "explicit release gate: requires four current native validator binaries"]
fn generic_game_pending_inputs_forfeit_and_restart_four_validators() -> Result<()> {
    // Native genesis/configuration construction and unoptimized AIR verification need
    // the same bounded stack used by the existing blocking network-test runtime.
    // Reserve it for both the test entry and Tokio workers without an ambient env knob.
    const TEST_STACK_BYTES: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .name("native-game-release".to_owned())
        .stack_size(TEST_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(TEST_STACK_BYTES)
                .enable_all()
                .build()?
                .block_on(run_pending_inputs_forfeit_and_restart_four_validators())
        })?
        .join()
        .map_err(|_| eyre!("native game release-gate thread panicked"))?
}

async fn run_pending_inputs_forfeit_and_restart_four_validators() -> Result<()> {
    init_instruction_registry();
    let second_key = input_key(30);
    let second_account = AccountId::new(second_key.public_key().clone());
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_permissioned_consensus()
        .with_block_cadence(Duration::from_millis(500))
        // The test carries the proof inside an ordinary signed typed ISI. Native defaults
        // already permit 10-MiB transactions / 16-MiB DA bodies; the separate TxGossip
        // topic defaults to 256 KiB and needs this explicit test-local transport budget.
        .with_config_layer(|layer| {
            layer
                .write(["network", "max_frame_bytes_tx_gossip"], 8_388_608_i64)
                // This finite local fixture needs a small explicit budget; automatic
                // whole-filesystem headroom is not a reservation for test workloads.
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                );
        })
        .with_genesis_instruction(Register::account(Account::new(second_account.clone())));
    let network = sandbox::start_network_async_or_skip(
        builder,
        stringify!(generic_game_pending_inputs_forfeit_and_restart_four_validators),
    )
    .await?
    .ok_or_else(|| {
        eyre!("four-validator release gate cannot succeed with sandbox startup skipped")
    })?;
    let result = timeout(Duration::from_secs(1_200), async {
        let mut context = network.peers()[0].client().client().to_builder();
        // Allow actual native verification on development-profile validator binaries.
        context.transaction_status_timeout = Duration::from_secs(120);
        let client = Client::from_client(context.build()?)?;
        ensure!(
            !compiled_race_profile_v1().qualified,
            "this gate must exercise the real unqualified zero-stake admission path"
        );
        let second_client =
            network.peers()[1].client_for(&second_account, second_key.private_key().clone());
        let session_id = Hash::new(b"generic-game-retained-frontier-release-v1");
        let asset_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal")?,
            "free_game_gate".parse()?,
        );
        submit_instruction(&client,
            OpenGameSessionV1 {
                session_id,
                manifest: manifest(),
                asset_definition,
                stake: Quantity::zero(),
                join_deadline_height: height(&client).await? + 100,
            },
            fees(),
        ).await?;
        let opened = record(&client, session_id).await?;
        for (slot, entrant) in [(0, &client), (1, &second_client)] {
            submit_instruction(entrant,
                JoinGameSessionV1 {
                    session_id,
                    input_key: input_key(slot).public_key().clone(),
                    application_data: vec![slot],
                    resources: Vec::new(),
                    invitation: None,
                    expected_manifest_hash: opened.manifest_hash,
                    expected_asset_definition: opened.asset_definition.clone(),
                    expected_stake: opened.stake.clone(),
                },
                fees(),
            ).await?;
        }
        submit_instruction(&client, StartGameSessionV1 { session_id }, fees()).await?;
        let started = record(&client, session_id).await?;
        ensure!(
            started.phase == GamePhaseV1::Playing,
            "session did not start"
        );
        ensure!(
            started.participants[0].account == *ALICE_ID,
            "first wallet changed"
        );
        ensure!(started.liability.is_zero(), "free game created a liability");
        assert_replicas(&network, &started, 4).await?;

        // The first certified checkpoint comes from exact native simulation.
        let replay = RaceReplayV1 {
            track: RaceTrackV1::NeonTokyo,
            player_count: 2,
            frames: (0..6)
                .map(|tick| RaceInputFrameV1 {
                    tick,
                    controls: vec![33, 1],
                })
                .collect(),
            dnf_events: vec![],
        };
        let state = replay_race_v1(&replay)?;
        let checkpoint = signed_checkpoint(
            &started,
            GameCheckpointV1 {
                session_id,
                epoch: 0,
                tick: 6,
                transcript_root: race_transcript_root_v1(&started.network_id, &replay),
                state_root: race_state_root_v1(&started.network_id, &state),
                terminal: false,
            },
        );
        let reveals: Vec<_> = (0..2_u8)
            .map(|slot| GameInputRevealV1 {
                session_id,
                epoch: 0,
                start_tick: 6,
                slot,
                payload: (0..6)
                    .flat_map(|_| (if slot == 0 { 41_u16 } else { 21_u16 }).to_le_bytes())
                    .collect(),
                salt: Hash::new([slot, 8, 27, 91]),
            })
            .collect();
        let mut frontier = GameCommitmentSetV1 {
            session_id,
            epoch: 0,
            start_tick: 6,
            parent_transcript_root: checkpoint.checkpoint.transcript_root,
            commitments: reveals
                .iter()
                .map(|input| game_input_commitment_v1(&started.network_id, input))
                .collect(),
            signatures: vec![],
        };
        let digest = game_commitment_set_hash_v1(&started.network_id, &frontier);
        frontier.signatures = (0..2)
            .map(|slot| GameSlotSignatureV1 {
                slot,
                signature: Signature::new(input_key(slot).private_key(), digest.as_ref()),
            })
            .collect();
        submit_instruction(&client,
            CommitGameCheckpointV1 {
                session_id,
                checkpoint: checkpoint.clone(),
                frontier: Some(frontier.clone()),
            },
            fees(),
        ).await?;
        let certified = record(&client, session_id).await?;
        let selected = challenge_and_converge(&network, &certified).await?;
        ensure!(
            selected.phase == GamePhaseV1::SelectingCheckpoint,
            "challenge not applied"
        );
        ensure!(
            selected.checkpoint.as_ref() == Some(&checkpoint),
            "lost certified state"
        );
        ensure!(
            selected.pending_certificate.as_ref() == Some(&frontier),
            "lost certified controls"
        );

        // Even all original signatures cannot replace an already retained checkpoint at its tick.
        let mut conflicting = checkpoint.checkpoint;
        conflicting.state_root = Hash::new(b"forged-same-tick-collision-undo");
        for rejected in [
            CommitGameCheckpointV1 {
                session_id,
                checkpoint: signed_checkpoint(&selected, conflicting),
                frontier: Some(frontier.clone()),
            },
            CommitGameCheckpointV1 {
                session_id,
                checkpoint: checkpoint.clone(),
                frontier: None,
            },
        ] {
            ensure!(
                submit_instruction(&client, rejected, fees()).await.is_err(),
                "replaced retained evidence"
            );
        }
        ensure!(
            submit_instruction(&client, challenge(&selected), fees()).await
                .is_err(),
            "challenge extended deadline"
        );
        ensure!(
            record(&client, session_id).await? == selected,
            "rejection changed game state"
        );

        // Stop one validator before resolution; the exact remaining 3-of-4 committee must progress.
        let layers: Vec<_> = network
            .config_layers()
            .map(|layer| ConfigLayer(layer.into_owned()))
            .collect();
        let restarted = &network.peers()[3];
        restarted.shutdown().await;
        advance_past(&client, selected.deadline_height).await?;
        submit_instruction(&client, AdvanceGameDeadlineV1 { session_id }, fees()).await?;
        let reveal_phase = record(&client, session_id).await?;
        ensure!(
            reveal_phase.phase == GamePhaseV1::ForcedReveal,
            "certified inputs were recommitted"
        );
        ensure!(
            reveal_phase.input_commitments
                == frontier
                    .commitments
                    .iter()
                    .copied()
                    .map(Some)
                    .collect::<Vec<_>>(),
            "changed certified commitments"
        );
        // Anyone with the public matching reveal can relay it; the second player withholds theirs.
        submit_instruction(&second_client,
            RevealGameInputsV1 {
                reveal: reveals[0].clone(),
            },
            fees(),
        ).await?;
        let waiting = record(&client, session_id).await?;
        ensure!(
            waiting.participants.iter().all(|p| p.dnf_at_tick.is_none()),
            "forfeit before deadline"
        );
        ensure!(
            submit_instruction(&client, ExpireGameSessionV1 { session_id }, fees()).await
                .is_err(),
            "active game was refunded"
        );
        advance_past(&client, waiting.deadline_height).await?;
        submit_instruction(&client, AdvanceGameDeadlineV1 { session_id }, fees()).await?;
        let resolved = record(&client, session_id).await?;
        ensure!(
            resolved.phase == GamePhaseV1::AwaitingProof,
            "sole survivor was not awaiting proof"
        );
        ensure!(
            resolved.epoch == 1 && resolved.next_tick == 12,
            "wrong forced-round boundary"
        );
        ensure!(
            resolved.participants[1].dnf_at_tick == Some(6),
            "withholder escaped forfeit"
        );
        ensure!(
            resolved.participants[0].dnf_at_tick.is_none(),
            "matching reveal was ignored"
        );
        ensure!(
            resolved.checkpoint.as_ref() == Some(&checkpoint),
            "unfavorable certified prefix was discarded"
        );
        ensure!(resolved.forced_batches.len() == 1, "missing forced history");
        ensure!(
            resolved.forced_batches[0].inputs == vec![reveals[0].payload.clone(), vec![]],
            "forced controls changed"
        );
        ensure!(
            resolved.forced_batches[0].dnf_slots == vec![1],
            "wrong consensus removal"
        );
        ensure!(
            resolved.transcript_anchors
                == vec![GameTranscriptAnchorV1 {
                    tick: 6,
                    transcript_root: checkpoint.checkpoint.transcript_root
                }],
            "lost authority-shrink anchor"
        );
        ensure!(
            resolved.result.is_none()
                && resolved.verification_id.is_none()
                && resolved.terminal_at_height.is_none(),
            "unproved technical win was settled"
        );
        assert_replicas(&network, &resolved, 3).await?;

        restarted.start_checked(layers.iter(), None).await?;
        assert_replicas(&network, &resolved, 4).await?;
        for late in [
            InstructionBox::from(RevealGameInputsV1 {
                reveal: reveals[1].clone(),
            }),
            AdvanceGameDeadlineV1 { session_id }.into(),
            ExpireGameSessionV1 { session_id }.into(),
        ] {
            ensure!(
                submit_instruction(&client, late, fees()).await.is_err(),
                "closed input round changed without proof"
            );
        }
        ensure!(
            record(&client, session_id).await? == resolved,
            "late evidence changed resolved history"
        );
        assert_replicas(&network, &resolved, 4).await?;

        // The consensus round reserves ticks 6..12, but removal at its start leaves a
        // sole racer. RaceV1 therefore terminates at tick 6 before any of those controls
        // can drive a car. The complete sealed batch is still bound by dispute_root;
        // the pre-removal tick-6 certificate is an intermediate AIR boundary.
        let mut terminal_replay = replay.clone();
        terminal_replay.dnf_events = vec![RaceDnfEventV1 {
            tick: 6,
            slots: vec![1],
        }];
        let terminal_state = replay_race_v1(&terminal_replay)?;
        let ranking = race_result_v1(&terminal_state)?;
        ensure!(ranking.winners == vec![0], "wrong native technical winner");
        let outcome = GameOutcomeV1 {
            terminal_tick: terminal_state.tick,
            winner_slots: ranking.winners.clone(),
            result: ranking.encode(),
        };
        let request = RaceProverRequestV1 {
            statement: ExecutionPublicInputsV1 {
                network_id: resolved.network_id,
                session_id,
                manifest_hash: resolved.manifest_hash,
                roster_hash: resolved.roster_hash,
                transcript_root: race_transcript_root_v1(&resolved.network_id, &terminal_replay),
                dispute_root: resolved.dispute_root,
                outcome_hash: game_message_hash_v1(
                    &resolved.network_id,
                    "session-outcome",
                    &outcome,
                ),
            },
            manifest: resolved.manifest.clone(),
            admission: iroha_data_model::game::GameAdmissionBodyV1::from_session(&resolved),
            replay: terminal_replay,
            checkpoint_state: Some(state),
        };
        let proof_started = std::time::Instant::now();
        let proof = tokio::task::spawn_blocking(move || prove_race_v1(request)).await??;
        verify_game_proof_for_history_v1(
            &proof,
            &resolved.manifest,
            &outcome,
            resolved.checkpoint.as_ref().map(|signed| &signed.checkpoint),
            &resolved.transcript_anchors,
            &resolved.forced_batches,
            &resolved.participants,
            resolved.epoch,
        )?;
        let proof_bytes = proof.encode();
        ensure!(
            proof_bytes.len() > 1_048_576
                && proof_bytes.len() <= compiled_race_profile_v1().maximum_proof_bytes as usize,
            "gate must carry a genuine native proof above one MiB within the compiled cap"
        );
        let statement_hash = game_message_hash_v1(
            &resolved.network_id,
            "execution-statement",
            &proof.statement,
        );
        let verification_id = game_message_hash_v1(
            &resolved.network_id,
            "execution-proof-verification",
            &(proof.profile_id, statement_hash),
        );
        let proof_hash = Hash::new(&proof_bytes);
        eprintln!(
            "native execution settlement candidate: profile={} proof_bytes={} prove_and_history_verify_ms={}",
            proof.profile_id,
            proof_bytes.len(),
            proof_started.elapsed().as_millis()
        );
        ensure!(
            verification(&client, verification_id).await.is_err(),
            "execution receipt existed before consensus verified the proof"
        );

        // Malformed cryptography must neither close the session nor retain a receipt.
        let mut malformed = proof.clone();
        *malformed.proof_bytes.last_mut().expect("nonempty native proof") ^= 1;
        ensure!(
            submit_instruction(&client,
                SettleGameSessionV1::new(session_id, malformed, outcome.clone()),
                fees(),
            ).await.is_err(),
            "altered proof bytes settled the session"
        );
        ensure!(record(&client, session_id).await? == resolved, "invalid proof changed session");
        ensure!(
            verification(&client, verification_id).await.is_err(),
            "invalid proof retained a verification receipt"
        );

        let settlement = SettleGameSessionV1::new(session_id, proof, outcome.clone());
        let settlement_started = std::time::Instant::now();
        let height_before_settlement = height(&client).await?;
        submit_instruction(&client, settlement.clone(), fees()).await?;
        let settled = record(&client, session_id).await?;
        let settlement_height = settled.terminal_at_height
            .ok_or_else(|| eyre!("successful native proof did not retain its settlement height"))?;
        let mut expected = resolved.clone();
        expected.revision += 1;
        expected.phase = GamePhaseV1::Settled;
        expected.result = Some(outcome);
        expected.verification_id = Some(verification_id);
        expected.terminal_at_height = Some(settlement_height);
        ensure!(settled == expected, "settlement changed immutable history or zero-stake liabilities");
        ensure!(
            settlement_height > height_before_settlement
                && settlement_height <= height(&client).await?,
            "settlement height is not committed"
        );
        assert_replicas(&network, &settled, 4).await?;
        for peer in network.peers() {
            let receipt = verification(&peer.client(), verification_id).await?;
            ensure!(
                receipt.profile_id == resolved.profile_id
                    && receipt.statement_hash == statement_hash
                    && receipt.proof_hash == proof_hash
                    && receipt.verified_at_height == settlement_height,
                "replica receipt differs from the exact proof and settlement block"
            );
        }
        ensure!(
            submit_instruction(&client, settlement, fees()).await.is_err(),
            "duplicate proof settlement succeeded"
        );
        ensure!(record(&client, session_id).await? == settled, "duplicate settlement changed result");
        assert_replicas(&network, &settled, 4).await?;
        eprintln!(
            "native execution consensus settlement: height={settlement_height} receipt={verification_id} settlement_and_convergence_ms={}",
            settlement_started.elapsed().as_millis()
        );
        Ok::<(), eyre::Report>(())
    })
    .await;
    network.shutdown().await;
    result
        .map_err(|_| eyre!("four-validator generic game scenario exceeded twenty-minute bound"))?
}
