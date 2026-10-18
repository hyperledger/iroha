//! Native SCCP on four production validator processes, with a closed Parliament launch gate.
//!
//! Genuine `NPoS` registrations precede initialization. An ordinary transaction reaches
//! finality, every peer exposes the same genesis-bound certified SCCP result, and even an
//! authorized proposer cannot substitute a missing qualified Parliament ballot.

use std::{
    num::NonZeroU64,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::{Result, ensure, eyre};
use integration_tests::{sandbox, sync::get_status_with_retry_at_least};
use iroha::{
    client::sccp::SccpFinalityAt,
    crypto::{
        Algorithm, KeyPair,
        bls::consensus::{ConsensusDigest, aggregate, sign},
    },
    data_model::{
        block::{
            consensus::{EvidencePenaltyStatus, SumeragiRootScope},
            decode_framed_signed_block,
        },
        isi::{
            chain::Keepalive,
            governance::ProposeSccpRouteGovernance,
            sccp::{InitializeSccpV1, SubmitSccpForgeryEvidenceV1},
        },
        parameter::{SumeragiParameter, system::SumeragiNposParameters},
        prelude::*,
        sccp::{
            generation::SccpGenerationCauseV1,
            governance::{
                SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
                SccpSetParametersActionV1,
            },
            params::{SCCP_MIN_HEARTBEAT_MS_V1, SccpParametersV1},
        },
        sumeragi_finality::authenticated_genesis,
        transaction::FeePaymentIntent,
    },
};
use iroha_executor_data_model::permission::sccp::CanProposeSccpRouteGovernance;
use iroha_model_base::{metadata::Metadata, name::Name, topology::LaneId};
use iroha_sccp::{
    api::{SccpCertificateV1, SccpGenerationV1},
    v1::{
        committee::committee_root,
        evidence::forgery_evidence_id,
        finality::{
            QcFixedV1, SccpFinalityHeaderV1, commit_preimage, outer_result, verify_certificate,
        },
    },
};
use iroha_test_network::{Network, NetworkBuilder, init_instruction_registry};
use iroha_test_samples::ALICE_ID;

fn builder() -> NetworkBuilder {
    configured_builder(
        SccpParametersV1::taira_default(),
        None,
        1,
        Duration::from_secs(1),
    )
}

fn configured_builder(
    parameters: SccpParametersV1,
    slashing_delay_blocks: Option<u64>,
    max_slash_bps: i64,
    cadence: Duration,
) -> NetworkBuilder {
    let cadence_ms = u64::try_from(cadence.as_millis()).expect("test cadence fits u64");
    let epoch = NonZeroU64::new(SCCP_MIN_HEARTBEAT_MS_V1 / cadence_ms).expect("nonzero epoch");
    let mut npos = SumeragiNposParameters {
        epoch_length_blocks: epoch,
        max_validators: 4,
        ..SumeragiNposParameters::default()
    };
    if let Some(delay) = slashing_delay_blocks {
        npos.slashing_delay_blocks = delay;
    }
    let proposal_permission: Permission = CanProposeSccpRouteGovernance.into();
    NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .with_npos_genesis_bootstrap(1_000_u64.into())
        .with_block_cadence(cadence)
        .with_genesis_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::EpochLengthBlocks(epoch),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
        .with_genesis_post_bootstrap_isi(vec![
            InitializeSccpV1 {
                parameters,
                reset_nonce: [0x59; 32],
            }
            .into(),
            Grant::account_permission(proposal_permission, ALICE_ID.clone()).into(),
        ])
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom({
                let mut fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
                fees.fee_sink_account_id = iroha_test_samples::ALICE_ID.clone();
                fees.base_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_byte_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_instruction_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.per_gas_unit_fee = ("0").parse().expect("explicit fixture fee quantity");
                fees.into_custom_parameter()
                    .expect("explicit signed fixture fee policy")
            }),
        ))
        .with_config_layer(move |layer| {
            layer
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                )
                .write(
                    ["nexus", "staking", "unbonding_delay_ms"],
                    1_814_400_000_i64,
                )
                .write(["nexus", "staking", "max_slash_bps"], max_slash_bps);
        })
}

#[test]
fn four_validators_publish_native_sccp_finality_and_refuse_unqualified_launch() -> Result<()> {
    init_instruction_registry();
    let (network, runtime) = sandbox::start_network_blocking_or_skip(
        builder(),
        stringify!(four_validators_publish_native_sccp_finality_and_refuse_unqualified_launch),
    )?
    .ok_or_else(|| eyre!("native SCCP qualification requires four actual validator processes"))?;
    let result = (|| -> Result<()> {
        runtime.block_on(network.ensure_blocks(1))?;
        ensure!(network.peers().len() == 4);
        let genesis = network.genesis();
        let (epoch, root_scope) = authenticated_genesis(&genesis.0)?.into_parts();
        let keys = epoch
            .committee
            .iter()
            .map(|member| {
                let (algorithm, bytes) = member.validator.public_key().try_to_bytes()?;
                ensure!(algorithm == Algorithm::BlsNormal);
                <[u8; 48]>::try_from(bytes).map_err(|_| eyre!("genesis key width"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(keys.len() == 4);
        let root = committee_root(&keys).ok_or_else(|| eyre!("invalid signed committee"))?;
        let instance = iroha_sumeragi::preimage::instance_id(
            &iroha_core::sumeragi::crypto::BlsCrypto::new(),
            &iroha_sumeragi::types::Hash32(*epoch.network_id.as_bytes()),
            network.chain_id().as_str().as_bytes(),
            iroha_sumeragi::preimage::InstanceKind::Global,
            0,
        )
        .0;
        let client = network.peers()[0].client();
        let before = client.client().get_sumeragi_status()?.committed_height;
        let account = AccountId::new(
            KeyPair::try_from_seed(vec![0x77; 32], Algorithm::Ed25519)?
                .public_key()
                .clone(),
        );
        client.submit(
            Register::account(Account::new(account)),
            FeePaymentIntent::authority(Vec::new(), None),
        )?;
        let after = client.client().get_sumeragi_status()?.committed_height;
        ensure!(
            after > before,
            "ordinary registration must commit a successor"
        );
        runtime.block_on(network.ensure_blocks(after))?;
        let mut original = None;
        let mut exported = None;
        for peer in network.peers() {
            let client = peer.client();
            let capabilities = client.sccp().capabilities()?;
            ensure!(capabilities.network_id == *epoch.network_id.as_bytes());
            ensure!(capabilities.consensus_instance == instance);
            ensure!(capabilities.parameters == Some(SccpParametersV1::taira_default()));
            ensure!(
                capabilities.coalition_slashable_floor == Some(0_u32.into()),
                "the captured 1,000-unit stakes at one basis point each round to zero"
            );
            ensure!(!capabilities.parliament_binding_ballot_available);
            let holds = client
                .sccp()
                .forgery_hold(iroha_sccp::api::SccpForgeryHoldQuery::default())?;
            ensure!(holds.revisions.is_empty() && holds.next.is_none());
            let pause = client.sccp().fast_pause()?;
            ensure!(pause.panel.is_none() && pause.seats.is_none() && !pause.eligibility_available);
            ensure!(
                pause.rounds.is_empty() && pause.active.is_empty() && pause.suspended.is_empty()
            );
            let anchor = client.sccp().anchor_witness(NonZeroU64::new(1).unwrap())?;
            ensure!(anchor.height == 1 && anchor.chunk == 0 && anchor.witness.is_none());
            let generation = client.sccp().committee(1)?;
            ensure!(generation.committee_root == root && generation.keys == keys);
            ensure!(
                generation.members.len() == 4 && generation.members.iter().all(Option::is_some)
            );
            ensure!(generation.liable && generation.start_height == 1);
            let certificate = client
                .sccp()
                .finality(SccpFinalityAt::Height(NonZeroU64::new(after).unwrap()))?;
            ensure!(certificate.committee == keys);
            let verified = verify_certificate(
                &instance,
                &certificate.qc,
                &certificate.header,
                &certificate.aggregate_signature,
                &keys,
            )?;
            ensure!(verified.header.height() == after && verified.header.is_active());
            ensure!(verified.header.network_id() == *epoch.network_id.as_bytes());
            ensure!(verified.header.generation() == 1 && verified.header.committee_root() == root);
            ensure!(verified.qc.signers.count_ones() == 3);
            // Exercise the same bounded public block read before the hour-long heartbeat run.
            let _ = read_sccp_block_wire(
                &client,
                NonZeroU64::new(after).unwrap(),
                root_scope,
                &instance,
                &verified.qc.block_hash,
                &verified.result,
                Instant::now() + network.sync_timeout(),
            )?;
            let certified_result = (certificate.header, verified.qc.block_hash, verified.result);
            if let Some(expected) = &original {
                ensure!(
                    &certified_result == expected,
                    "all peers must certify the same retained block and result"
                );
            } else {
                original = Some(certified_result);
                exported = Some((generation, certificate));
            }
        }
        let proposal = client.account_client().prepare_transaction(
            iroha::client::AccountTransactionDraft::new(
                vec![InstructionBox::from(ProposeSccpRouteGovernance {
                    proposal: SccpGovernanceProposalV1 {
                        network_id: epoch.network_id,
                        base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
                        actions: vec![SccpGovernanceActionV1::SetParameters(
                            SccpSetParametersActionV1 {
                                next: SccpParametersV1::taira_default(),
                            },
                        )],
                    },
                })],
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ),
        )?;
        let proposal = client.account_client().sign_transaction(proposal)?;
        let _ = client
            .submit_transaction_and_wait(&proposal)
            .expect_err("a proposer permission cannot supply the qualified Parliament ballot");
        let details = client
            .client()
            .get_transaction_details(proposal.hash_as_entrypoint())?;
        let committed = &details.transaction;
        ensure!(committed.entrypoint_hash() == &proposal.hash_as_entrypoint());
        ensure!(
            matches!(committed.entrypoint(), TransactionEntrypoint::External(signed) if signed == &proposal)
        );
        let rejection = committed
            .result()
            .0
            .as_ref()
            .expect_err("the exact committed proposal must remain rejected");
        ensure!(
            format!("{rejection:?}").contains("ParliamentBallotUnavailable"),
            "unexpected rejection: {rejection:?}"
        );
        for peer in network.peers() {
            ensure!(peer.client().sccp().governance_proposals()?.is_empty());
        }
        // Public original process output feeds the destination checkpoint corridor. It
        // carries no route registration or Parliament authority and no validator secrets.
        let (initial_generation, certificate) = exported.expect("four original peer replies");
        let export = norito::json!({
            "version": 1,
            "chain_id": (network.chain_id().as_str()),
            "network_id": (epoch.network_id.as_bytes()),
            "consensus_instance": instance,
            "signed_genesis_wire": (genesis.0.encode_wire()?),
            "initial_generation": initial_generation,
            "certificate": certificate,
        });
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("target/sccp-continuation");
        std::fs::create_dir_all(&directory)?;
        let temporary = directory.join("live-fourpeer-sccp.json.tmp");
        std::fs::write(&temporary, norito::json::to_vec(&export)?)?;
        std::fs::rename(temporary, directory.join("live-fourpeer-sccp.json"))?;
        Ok(())
    })();
    runtime.block_on(network.shutdown());
    result
}

fn wall_time_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn write_heartbeat_observation(directory: &Path, value: &norito::json::Value) -> Result<()> {
    let bytes = norito::json::to_vec(value)?;
    std::fs::write(
        directory.join("live-fourpeer-sccp-heartbeat-progress.json.tmp"),
        &bytes,
    )?;
    std::fs::rename(
        directory.join("live-fourpeer-sccp-heartbeat-progress.json.tmp"),
        directory.join("live-fourpeer-sccp-heartbeat-progress.json"),
    )?;
    eprintln!("SCCP_HEARTBEAT {}", String::from_utf8(bytes)?);
    Ok(())
}

fn agreed_certificate(
    network: &Network,
    instance: &[u8; 32],
    keys: &[[u8; 48]],
    height: u64,
    generation: u64,
    rotation: bool,
) -> Result<SccpCertificateV1> {
    let mut first = None;
    let mut original_result = None;
    for peer in network.peers() {
        let client = peer.client();
        // A CommitQC and Kura's durable hash journal can precede State publication.
        // Fence the exact peer's applied view before its one original certificate read.
        get_status_with_retry_at_least(&client, height)?;
        let certificate = client
            .sccp()
            .finality(SccpFinalityAt::Height(
                NonZeroU64::new(height).ok_or_else(|| eyre!("zero certificate height"))?,
            ))
            .map_err(|error| {
                let context = match &error {
                    iroha::Error::Http { body, .. } => format!(
                        "peer {} certificate height {height}; response body prefix: {:?}",
                        peer.mnemonic(),
                        String::from_utf8_lossy(&body[..body.len().min(512)]),
                    ),
                    _ => format!("peer {} certificate height {height}", peer.mnemonic()),
                };
                eyre::Report::from(error).wrap_err(context)
            })?;
        ensure!(certificate.height == height && certificate.committee == keys);
        let verified = verify_certificate(
            instance,
            &certificate.qc,
            &certificate.header,
            &certificate.aggregate_signature,
            keys,
        )?;
        ensure!(verified.header.is_active());
        ensure!(verified.header.generation() == generation);
        ensure!(verified.header.is_rotation() == rotation);
        ensure!(verified.qc.signers.count_ones() == 3);
        let result = (certificate.header, verified.qc.block_hash, verified.result);
        if let Some(expected) = original_result {
            ensure!(
                result == expected,
                "all four peers must agree on the certified result"
            );
        } else {
            original_result = Some(result);
            first = Some(certificate);
        }
    }
    first.ok_or_else(|| eyre!("four original peer certificates required"))
}

// The SCCP certificate already authenticates the native consensus hash and R under
// the independently selected genesis keys. A structural proof supplies bounded
// original bytes, whose native decision must match both authenticated values.
// The Iroha proposal-header hash is a different hash and cannot make this join.
fn read_sccp_block_wire(
    client: &iroha::blocking::Client,
    height: NonZeroU64,
    root_scope: SumeragiRootScope,
    expected_instance: &[u8; 32],
    expected_native_hash: &[u8; 32],
    expected_result: &[u8; 32],
    deadline: Instant,
) -> Result<(SignedBlock, Vec<u8>)> {
    let bounded = client.with_request_deadline(deadline)?;
    let proof = bounded
        .client()
        .get_sumeragi_finality_proof(height, root_scope)?;
    let block = check_sccp_block_proof(
        &proof,
        height,
        root_scope,
        expected_instance,
        expected_native_hash,
        expected_result,
    )?;
    ensure!(
        Instant::now() < deadline,
        "original SCCP block read deadline elapsed"
    );
    Ok((block, proof.block_wire))
}

fn check_sccp_block_proof(
    proof: &iroha::data_model::sumeragi_finality::SumeragiFinalityProof,
    height: NonZeroU64,
    root_scope: SumeragiRootScope,
    expected_instance: &[u8; 32],
    expected_native_hash: &[u8; 32],
    expected_result: &[u8; 32],
) -> Result<SignedBlock> {
    ensure!(
        height.get() > 1 && proof.height() == height.get(),
        "original SCCP block height differs or is genesis"
    );
    let wire = &proof.block_wire;
    ensure!(
        !wire.is_empty()
            && wire.len() <= iroha::data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
        "original SCCP block wire exceeds its finite bound"
    );
    // Check canonical framing, proposal/native-header binding, exact execution
    // commitments and the candidate QC. This alone does not select trusted keys.
    proof.decode_checked(root_scope.into())?;
    let block = norito::core::with_decode_limits_scope(
        norito::canonical_decode_limits(wire.len()),
        || decode_framed_signed_block(wire),
    )?;
    norito::core::reset_decode_state();
    let certificate = block
        .commit_certificate()
        .ok_or_else(|| eyre!("original SCCP native certificate missing"))?;
    let qc_bytes = certificate.commit_qc();
    let qc: iroha_sumeragi::message::Qc = norito::decode_canonical_for_admission(
        qc_bytes,
        norito::canonical_decode_limits(qc_bytes.len()),
    )?;
    ensure!(
        block.header().height() == height
            && qc.kind == iroha_sumeragi::message::VoteKind::Commit
            && qc.height == height.get(),
        "original SCCP native certificate height or kind differs"
    );
    ensure!(
        qc.instance.0 == *expected_instance,
        "original SCCP native instance differs"
    );
    ensure!(
        qc.block_hash.0 == *expected_native_hash,
        "original SCCP native block hash differs"
    );
    ensure!(
        qc.result.0 == *expected_result,
        "original SCCP certified result differs"
    );
    // Two valid witnesses may use different exact-quorum signer subsets or views.
    // The authenticated native hash and R identify the same proposal and execution.
    Ok(block)
}

fn agreed_generation(network: &Network, generation: u64) -> Result<SccpGenerationV1> {
    let first = network.peers()[0].client().sccp().committee(generation)?;
    for peer in &network.peers()[1..] {
        ensure!(peer.client().sccp().committee(generation)? == first);
    }
    Ok(first)
}

fn register_successor(network: &Network, seed: u8) -> Result<u64> {
    let client = network.peers()[0].client();
    let before = client.client().get_sumeragi_status()?.committed_height;
    let account = AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)?
            .public_key()
            .clone(),
    );
    client.submit(
        Register::account(Account::new(account)),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let after = client.client().get_sumeragi_status()?.committed_height;
    ensure!(
        after == before + 1,
        "one ordinary transaction must commit one successor"
    );
    Ok(after)
}

fn bonded_stake(observation: &norito::json::Value) -> Result<u64> {
    observation
        .get("items")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("stake response must contain items"))?
        .iter()
        .try_fold(0_u64, |total, item| {
            let bonded: u64 = item
                .get("bonded")
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| eyre!("stake share must contain bonded amount"))?
                .parse()?;
            total
                .checked_add(bonded)
                .ok_or_else(|| eyre!("stake sum overflow"))
        })
}

#[test]
fn four_validators_rotate_after_real_idle_heartbeat_and_apply_prior_generation_forgery()
-> Result<()> {
    init_instruction_registry();
    let mut parameters = SccpParametersV1::taira_default();
    parameters.committee_heartbeat_ms = SCCP_MIN_HEARTBEAT_MS_V1;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("target/sccp-continuation");
    std::fs::create_dir_all(&directory)?;
    write_heartbeat_observation(
        &directory,
        &norito::json!({
            "stage": "starting_four_validators", "wall_ms": (wall_time_ms()?),
            "heartbeat_ms": (parameters.committee_heartbeat_ms),
        }),
    )?;
    let (network, runtime) = sandbox::start_network_blocking_or_skip(
        configured_builder(parameters, Some(2), 10_000, Duration::from_millis(100)),
        stringify!(
            four_validators_rotate_after_real_idle_heartbeat_and_apply_prior_generation_forgery
        ),
    )?
    .ok_or_else(|| eyre!("heartbeat qualification requires four actual validator processes"))?;
    let result = (|| -> Result<()> {
        runtime.block_on(network.ensure_blocks(1))?;
        ensure!(network.peers().len() == 4);
        let genesis = network.genesis();
        let (epoch, root_scope) = authenticated_genesis(&genesis.0)?.into_parts();
        let keys = epoch
            .committee
            .iter()
            .map(|member| {
                let (algorithm, bytes) = member.validator.public_key().try_to_bytes()?;
                ensure!(algorithm == Algorithm::BlsNormal);
                <[u8; 48]>::try_from(bytes).map_err(|_| eyre!("genesis key width"))
            })
            .collect::<Result<Vec<_>>>()?;
        let root = committee_root(&keys).ok_or_else(|| eyre!("invalid signed committee"))?;
        let instance = iroha_sumeragi::preimage::instance_id(
            &iroha_core::sumeragi::crypto::BlsCrypto::new(),
            &iroha_sumeragi::types::Hash32(*epoch.network_id.as_bytes()),
            network.chain_id().as_str().as_bytes(),
            iroha_sumeragi::preimage::InstanceKind::Global,
            0,
        )
        .0;
        for peer in network.peers() {
            get_status_with_retry_at_least(&peer.client(), 1)?;
        }
        let initial_generation = agreed_generation(&network, 1)?;
        ensure!(initial_generation.committee_root == root && initial_generation.keys == keys);
        ensure!(
            initial_generation.members.len() == 4
                && initial_generation.members.iter().all(Option::is_some)
        );
        for peer in network.peers() {
            let capabilities = peer.client().sccp().capabilities()?;
            ensure!(capabilities.parameters == Some(parameters));
            ensure!(!capabilities.parliament_binding_ballot_available);
            ensure!(capabilities.coalition_slashable_floor == Some(2_000_u32.into()));
        }
        let normal_height = register_successor(&network, 0x81)?;
        runtime.block_on(network.ensure_blocks(normal_height))?;
        let normal = agreed_certificate(&network, &instance, &keys, normal_height, 1, false)?;
        let idle_start_ms = wall_time_ms()?;
        let idle_monotonic_start = Instant::now();
        let deadline_ms = initial_generation
            .start_timestamp_ms
            .checked_add(parameters.committee_heartbeat_ms)
            .ok_or_else(|| eyre!("heartbeat deadline"))?;
        ensure!(
            idle_start_ms < deadline_ms,
            "start before the genuine heartbeat deadline"
        );
        let required_idle_ms = deadline_ms - idle_start_ms;
        let mut observations = Vec::new();
        let heartbeat_height = loop {
            let heights = network
                .peers()
                .iter()
                .map(|peer| {
                    peer.client()
                        .client()
                        .get_sumeragi_status()
                        .map(|status| status.committed_height)
                })
                .collect::<Result<Vec<_>>>()?;
            let observed_ms = wall_time_ms()?;
            let observation = norito::json!({
                "stage": "awaiting_real_heartbeat", "wall_ms": observed_ms,
                "idle_start_ms": idle_start_ms, "deadline_ms": deadline_ms,
                "elapsed_monotonic_ms": (u64::try_from(idle_monotonic_start.elapsed().as_millis())?),
                "committed_heights": heights,
            });
            write_heartbeat_observation(&directory, &observation)?;
            observations.push(observation);
            if heights.iter().any(|height| *height > normal_height) {
                ensure!(
                    observed_ms >= deadline_ms,
                    "idle network produced an early block"
                );
                ensure!(
                    idle_monotonic_start.elapsed() >= Duration::from_millis(required_idle_ms),
                    "heartbeat requires actual elapsed time, not a forward wall-clock adjustment"
                );
                ensure!(heights.iter().all(|height| *height <= normal_height + 1));
                break normal_height + 1;
            }
            ensure!(heights.iter().all(|height| *height == normal_height));
            ensure!(
                observed_ms <= deadline_ms.saturating_add(300_000),
                "production keeper did not commit within five minutes of the admitted deadline"
            );
            let wait_ms = if observed_ms < deadline_ms {
                (deadline_ms - observed_ms).min(30_000)
            } else {
                1_000
            };
            std::thread::sleep(Duration::from_millis(wait_ms));
        };
        runtime.block_on(network.ensure_blocks(heartbeat_height))?;
        let idle_end_ms = wall_time_ms()?;
        let heartbeat = agreed_certificate(&network, &instance, &keys, heartbeat_height, 1, true)?;
        let heartbeat_verified = verify_certificate(
            &instance,
            &heartbeat.qc,
            &heartbeat.header,
            &heartbeat.aggregate_signature,
            &keys,
        )?;
        let heartbeat_header = heartbeat_verified.header;
        let heartbeat_qc = heartbeat_verified.qc;
        ensure!(heartbeat_header.height() == heartbeat_height);
        ensure!(heartbeat_header.network_id() == *epoch.network_id.as_bytes());
        ensure!(heartbeat_header.timestamp_ms() >= deadline_ms);
        ensure!(heartbeat_header.committee_root() == root);
        ensure!(heartbeat_header.next_committee_root() == root);
        let mut heartbeat_wire = None;
        let mut keepalive_entrypoint = None;
        for peer in network.peers() {
            let client = peer.client();
            let (block, original_wire) = read_sccp_block_wire(
                &client,
                NonZeroU64::new(heartbeat_height).unwrap(),
                root_scope,
                &instance,
                &heartbeat_qc.block_hash,
                &heartbeat_verified.result,
                Instant::now() + network.sync_timeout(),
            )?;
            ensure!(block.external_entrypoint_count() == 1 && !block.is_empty());
            let signed = block
                .external_transactions()
                .next()
                .ok_or_else(|| eyre!("signed Keepalive missing"))?;
            ensure!(
                matches!(signed.instructions(), Executable::Instructions(instructions)
                if matches!(instructions.as_ref(), [only] if only.as_any().is::<Keepalive>()))
            );
            let details = client
                .client()
                .get_transaction_details(signed.hash_as_entrypoint())?;
            ensure!(details.transaction.result().0.is_ok());
            ensure!(
                matches!(details.transaction.entrypoint(), TransactionEntrypoint::External(original) if original == signed)
            );
            if let Some(expected) = keepalive_entrypoint {
                ensure!(signed.hash_as_entrypoint() == expected);
            } else {
                keepalive_entrypoint = Some(signed.hash_as_entrypoint());
                heartbeat_wire = Some(original_wire);
            }
        }
        let ended_generation = agreed_generation(&network, 1)?;
        let next_generation = agreed_generation(&network, 2)?;
        ensure!(ended_generation.liable && ended_generation.end.is_some());
        ensure!(next_generation.cause == SccpGenerationCauseV1::Heartbeat);
        ensure!(next_generation.keys == keys && next_generation.committee_root == root);
        ensure!(next_generation.start_height == heartbeat_height + 1);
        ensure!(next_generation.start_timestamp_ms == heartbeat_header.timestamp_ms());
        let successor_height = register_successor(&network, 0x82)?;
        runtime.block_on(network.ensure_blocks(successor_height))?;
        ensure!(successor_height == next_generation.start_height);
        let successor = agreed_certificate(&network, &instance, &keys, successor_height, 2, false)?;
        write_heartbeat_observation(
            &directory,
            &norito::json!({
                "stage": "heartbeat_and_successor_verified", "wall_ms": (wall_time_ms()?),
                "heartbeat_height": heartbeat_height, "successor_height": successor_height,
            }),
        )?;

        // A separate, explicitly adversarial certificate exercises the destination's
        // V1 latch. Genuine Torii certificates above keep their original bytes.
        let latch_qc = QcFixedV1::parse(&normal.qc)?;
        let mut latch_fields = SccpFinalityHeaderV1::parse(&normal.header)?.fields();
        latch_fields.timestamp_ms = latch_fields
            .timestamp_ms
            .checked_add(1)
            .ok_or_else(|| eyre!("conflicting checkpoint timestamp overflow"))?;
        ensure!(
            latch_fields.timestamp_ms < heartbeat_header.timestamp_ms()
                && latch_fields.timestamp_ms < initial_generation.deadline_ms
        );
        let latch_header = SccpFinalityHeaderV1::from_fields(&latch_fields)?;
        let latch_preimage = commit_preimage(
            &instance,
            &latch_qc,
            normal_height,
            &outer_result(&latch_header, &latch_qc.result_body).0,
        );
        let latch_digest = ConsensusDigest::from_preimage(&latch_preimage)
            .ok_or_else(|| eyre!("canonical conflicting checkpoint preimage required"))?;
        let latch_shares = keys
            .iter()
            .enumerate()
            .filter(|(index, _)| latch_qc.signers & (1_u32 << index) != 0)
            .map(|(_, key)| {
                let pair = network
                    .peers()
                    .iter()
                    .filter_map(|peer| peer.bls_key_pair())
                    .find(|pair| {
                        pair.public_key()
                            .try_to_bytes()
                            .is_ok_and(|(_, bytes)| bytes == key.as_slice())
                    })
                    .ok_or_else(|| eyre!("original latch-test signing key missing"))?;
                Ok(sign(pair.private_key(), &latch_digest)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut latch_certificate = normal.clone();
        latch_certificate.header = *latch_header.as_bytes();
        latch_certificate.aggregate_signature = aggregate(latch_shares)?;
        ensure!(latch_certificate.header != normal.header);
        let checked_latch = verify_certificate(
            &instance,
            &latch_certificate.qc,
            &latch_certificate.header,
            &latch_certificate.aggregate_signature,
            &keys,
        )?;
        ensure!(checked_latch.qc.signers.count_ones() == 3);
        ensure!(checked_latch.header.height() == normal_height);

        // Publish once, before the longer anchor sequence. Destination consumers
        // replay these exact original bytes while the source network continues.
        let export = norito::json!({
            "version": 1, "chain_id": (network.chain_id().as_str()),
            "network_id": (epoch.network_id.as_bytes()), "consensus_instance": instance,
            "signed_genesis_wire": (genesis.0.encode_wire()?), "initial_generation": initial_generation,
            "certificates": [normal, heartbeat, successor],
            "certificate_roles": ["normal", "heartbeat", "successor"],
            "destination_latch": {
                "version": 1, "provenance": "runtime_test_quorum_not_chain_output",
                "rule": "V1", "certificate": latch_certificate,
            },
            "generations": [ended_generation, next_generation],
            "idle": {"start_ms": idle_start_ms, "end_ms": idle_end_ms, "deadline_ms": deadline_ms,
                "required_elapsed_ms": required_idle_ms, "initial_height": normal_height, "observations": observations},
            "heartbeat": {"height": heartbeat_height, "keepalive_entrypoint": keepalive_entrypoint,
                "signed_block_wire": heartbeat_wire},
        });
        std::fs::write(
            directory.join("live-fourpeer-sccp-heartbeat.json.tmp"),
            norito::json::to_vec(&export)?,
        )?;
        std::fs::rename(
            directory.join("live-fourpeer-sccp-heartbeat.json.tmp"),
            directory.join("live-fourpeer-sccp-heartbeat.json"),
        )?;

        // A1 closes chunk zero only when height 4097 appends the anchor of 4096.
        // Ordinary signed account-metadata updates drive the complete prefix;
        // neither empty blocks nor a source-state/clock shortcut is involved.
        let client = network.peers()[0].client();
        let anchor_started_ms = wall_time_ms()?;
        let anchor_metadata: Name = "sccp_anchor_sequence".parse()?;
        let mut next_observation = Instant::now();
        let mut anchor_height = successor_height;
        let mut sequence = 0_u64;
        let mut anchor_transactions = Vec::new();
        while anchor_height < 4_097 {
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| eyre!("anchor sequence overflow"))?;
            let transaction = client.submit(
                SetKeyValue::account(
                    ALICE_ID.clone(),
                    anchor_metadata.clone(),
                    Json::new(sequence),
                ),
                FeePaymentIntent::authority(Vec::new(), None),
            )?;
            let height = client.client().get_sumeragi_status()?.committed_height;
            ensure!(
                height > anchor_height,
                "ordinary signed metadata must advance the chain"
            );
            anchor_transactions.push(norito::json!({
                "sequence": sequence, "transaction_hash": transaction, "observed_height": height,
            }));
            anchor_height = height;
            if Instant::now() >= next_observation || height >= 4_097 {
                runtime.block_on(network.ensure_blocks(height))?;
                write_heartbeat_observation(
                    &directory,
                    &norito::json!({
                        "stage": "sealing_anchor_chunk", "wall_ms": (wall_time_ms()?),
                        "started_ms": anchor_started_ms, "height": height, "target_height": 4_097,
                        "signed_metadata_transactions": sequence,
                    }),
                )?;
                next_observation = Instant::now() + Duration::from_secs(30);
            }
        }
        runtime.block_on(network.ensure_blocks(anchor_height))?;
        get_status_with_retry_at_least(&client, 4_097)?;
        let seal = client
            .sccp()
            .finality(SccpFinalityAt::Height(NonZeroU64::new(4_097).unwrap()))?;
        let seal_header = SccpFinalityHeaderV1::parse(&seal.header)?;
        let anchor_seal_certificate = agreed_certificate(
            &network,
            &instance,
            &keys,
            4_097,
            seal_header.generation(),
            seal_header.is_rotation(),
        )?;
        // Sign a false body under the original, still-liable generation. This is
        // adversarial evidence submitted through the ordinary native ingress;
        // no consensus process, state record or protocol clock is changed.
        let client = network.peers()[0].client();
        let anchor = client
            .sccp()
            .anchor_witness(NonZeroU64::new(normal_height).unwrap())?;
        ensure!(anchor.height == normal_height && anchor.chunk == 0 && anchor.witness.is_some());
        let witness = anchor
            .witness
            .expect("completed chunk has a twelve-sibling witness");
        let authentic = verify_certificate(
            &instance,
            &normal.qc,
            &normal.header,
            &normal.aggregate_signature,
            &keys,
        )?;
        ensure!(witness.core_hash == authentic.qc.block_hash && witness.result == authentic.result);
        for peer in network.peers() {
            ensure!(
                peer.client()
                    .sccp()
                    .anchor_witness(NonZeroU64::new(normal_height).unwrap())?
                    == anchor
            );
        }
        let stake_before = client
            .client()
            .get_public_lane_stake(LaneId::SINGLE, None)?;
        ensure!(bonded_stake(&stake_before)? == 4_000);
        let mut qc = QcFixedV1::parse(&normal.qc)?;
        qc.result_body[0] ^= 1;
        let header = SccpFinalityHeaderV1::parse(&normal.header)?;
        let preimage = commit_preimage(
            &instance,
            &qc,
            header.height(),
            &outer_result(&header, &qc.result_body).0,
        );
        let digest = ConsensusDigest::from_preimage(&preimage)
            .ok_or_else(|| eyre!("canonical consensus preimage required"))?;
        let shares = keys
            .iter()
            .enumerate()
            .filter(|(index, _)| qc.signers & (1_u32 << index) != 0)
            .map(|(_, key)| {
                let pair = network
                    .peers()
                    .iter()
                    .filter_map(|peer| peer.bls_key_pair())
                    .find(|pair| {
                        pair.public_key()
                            .try_to_bytes()
                            .is_ok_and(|(_, bytes)| bytes == key.as_slice())
                    })
                    .ok_or_else(|| eyre!("original network signing key missing"))?;
                Ok(sign(pair.private_key(), &digest)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let evidence = SubmitSccpForgeryEvidenceV1 {
            qc: qc.encode(),
            header: normal.header,
            aggregate_signature: aggregate(shares)?,
            anchor: anchor.witness,
        };
        let checked = verify_certificate(
            &instance,
            &evidence.qc,
            &evidence.header,
            &evidence.aggregate_signature,
            &keys,
        )?;
        let evidence_id = forgery_evidence_id(1, &checked.message, checked.qc.signers);
        let prepared = client.account_client().prepare_transaction(
            iroha::client::AccountTransactionDraft::new(
                vec![InstructionBox::from(evidence.clone())],
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ),
        )?;
        let signed_evidence = client.account_client().sign_transaction(prepared)?;
        client.submit_transaction_and_wait(&signed_evidence)?;
        let evidence_height = client.client().get_sumeragi_status()?.committed_height;
        runtime.block_on(network.ensure_blocks(evidence_height))?;
        get_status_with_retry_at_least(&client, evidence_height)?;
        let pending = client.sccp().evidence(&evidence_id)?;
        ensure!(
            pending.generation == 1
                && pending.rule == iroha::data_model::sccp::native::SccpForgeryRuleV1::E4
                && pending.height == normal_height
                && pending.offenders.len() == 3
        );
        ensure!(
            pending.recorded_at_height == evidence_height
                && pending.penalty_status == EvidencePenaltyStatus::Pending
        );
        for peer in network.peers() {
            let peer_client = peer.client();
            get_status_with_retry_at_least(&peer_client, evidence_height)?;
            ensure!(peer_client.sccp().evidence(&evidence_id)? == pending);
            let holds = peer_client
                .sccp()
                .forgery_hold(iroha_sccp::api::SccpForgeryHoldQuery::default())?;
            ensure!(
                holds.revisions.is_empty() && holds.next.is_none(),
                "no routes were installed"
            );
        }
        let before_due = register_successor(&network, 0x83)?;
        runtime.block_on(network.ensure_blocks(before_due))?;
        ensure!(before_due == evidence_height + 1);
        get_status_with_retry_at_least(&client, before_due)?;
        ensure!(
            client.sccp().evidence(&evidence_id)?.penalty_status == EvidencePenaltyStatus::Pending
        );
        ensure!(
            bonded_stake(
                &client
                    .client()
                    .get_public_lane_stake(LaneId::SINGLE, None)?
            )? == 4_000
        );
        let penalty_height = register_successor(&network, 0x84)?;
        runtime.block_on(network.ensure_blocks(penalty_height))?;
        ensure!(penalty_height == evidence_height + 2);
        get_status_with_retry_at_least(&client, penalty_height)?;
        let applied = client.sccp().evidence(&evidence_id)?;
        ensure!(
            applied.penalty_status
                == EvidencePenaltyStatus::Applied {
                    height: penalty_height
                }
        );
        let stake_after = client
            .client()
            .get_public_lane_stake(LaneId::SINGLE, None)?;
        ensure!(
            bonded_stake(&stake_after)? == 1_000,
            "three original 1,000-unit stakes must be slashed"
        );
        for peer in network.peers() {
            let peer_client = peer.client();
            get_status_with_retry_at_least(&peer_client, penalty_height)?;
            ensure!(peer_client.sccp().evidence(&evidence_id)? == applied);
            ensure!(
                peer_client
                    .client()
                    .get_public_lane_stake(LaneId::SINGLE, None)?
                    == stake_after
            );
            ensure!(
                !peer_client
                    .sccp()
                    .capabilities()?
                    .parliament_binding_ballot_available
            );
        }
        let export = norito::json!({
            "version": 1, "network_id": (epoch.network_id.as_bytes()),
            "consensus_instance": instance, "evidence": evidence,
            "evidence_id": evidence_id, "anchor": anchor,
            "anchor_seal_certificate": anchor_seal_certificate,
            "anchor_transactions": anchor_transactions,
            "transaction": signed_evidence, "pending": pending, "applied": applied,
            "stake_before": stake_before, "stake_after": stake_after, "route_holds": [],
        });
        std::fs::write(
            directory.join("live-fourpeer-sccp-forgery.json.tmp"),
            norito::json::to_vec(&export)?,
        )?;
        std::fs::rename(
            directory.join("live-fourpeer-sccp-forgery.json.tmp"),
            directory.join("live-fourpeer-sccp-forgery.json"),
        )?;
        write_heartbeat_observation(
            &directory,
            &norito::json!({
                "stage": "complete", "wall_ms": (wall_time_ms()?), "penalty_height": penalty_height,
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = write_heartbeat_observation(
            &directory,
            &norito::json!({
                "stage": "failed", "error": (format!("{error:#}")), "wall_ms": (wall_time_ms()?),
            }),
        );
    }
    runtime.block_on(network.shutdown());
    result
}

#[test]
fn heartbeat_stake_observation_requires_exact_integer_shares() -> Result<()> {
    ensure!(
        bonded_stake(&norito::json!({"items": [{"bonded": "1000"}, {"bonded": "3000"}]}))? == 4_000
    );
    ensure!(bonded_stake(&norito::json!({"items": [{"bonded": "1.1"}]})).is_err());
    ensure!(bonded_stake(&norito::json!({"items": [{}]})).is_err());
    Ok(())
}

#[test]
fn sccp_original_block_proof_requires_native_hash_result_and_canonical_frame() -> Result<()> {
    use iroha::data_model::sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityVerifier,
    };

    init_instruction_registry();
    // Independently selected deterministic protocol fixtures: genuine native
    // three-of-four certificates over synthetic outputs, not World execution.
    let genesis = SumeragiFinalityCheckpoint::decode_canonical(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/sumeragi/native-finality/genesis-checkpoint.nrt"
    )))?;
    let second = SumeragiFinalityCheckpoint::decode_canonical(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/sumeragi/native-finality/height-2-checkpoint.nrt"
    )))?;
    let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &genesis,
        &genesis.network_id(),
        genesis.chain_id(),
    )?;
    let proof = second.tip();
    let verified = verifier.verify(proof)?;
    let height = NonZeroU64::new(verified.height()).unwrap();
    ensure!(height.get() == 2);
    let scope = verified.root_scope();
    let instance = verifier.instance().0;
    let native_hash = verified.core_hash().0;
    let result = verified.result().0;
    let data_header_hash = *verified.block().hash().as_ref();
    ensure!(
        data_header_hash != native_hash,
        "fixture must distinguish the two hash domains"
    );
    let original = check_sccp_block_proof(proof, height, scope, &instance, &native_hash, &result)?;
    ensure!(original.encode_wire()?.as_slice() == proof.block_wire.as_slice());
    let wrong_height = check_sccp_block_proof(
        proof,
        NonZeroU64::new(3).unwrap(),
        scope,
        &instance,
        &native_hash,
        &result,
    )
    .expect_err("wrong original height must fail");
    ensure!(wrong_height.to_string().contains("height differs"));
    let wrong_hash =
        check_sccp_block_proof(proof, height, scope, &instance, &data_header_hash, &result)
            .expect_err("the Iroha proposal-header hash cannot replace the native consensus hash");
    ensure!(wrong_hash.to_string().contains("native block hash differs"));
    let mut wrong_instance = instance;
    wrong_instance[0] ^= 1;
    let wrong_scope =
        check_sccp_block_proof(proof, height, scope, &wrong_instance, &native_hash, &result)
            .expect_err("a different genesis instance must fail");
    ensure!(wrong_scope.to_string() == "original SCCP native instance differs");
    let mut wrong_result = result;
    wrong_result[0] ^= 1;
    let mismatch =
        check_sccp_block_proof(proof, height, scope, &instance, &native_hash, &wrong_result)
            .expect_err("the structural proof cannot supply its own trusted R");
    ensure!(mismatch.to_string().contains("certified result differs"));
    let mut empty = proof.clone();
    empty.block_wire.clear();
    ensure!(
        check_sccp_block_proof(&empty, height, scope, &instance, &native_hash, &result).is_err()
    );
    let mut truncated = proof.clone();
    truncated.block_wire.pop();
    ensure!(
        check_sccp_block_proof(&truncated, height, scope, &instance, &native_hash, &result)
            .is_err()
    );
    let mut trailing = proof.clone();
    trailing.block_wire.push(0);
    ensure!(
        check_sccp_block_proof(&trailing, height, scope, &instance, &native_hash, &result).is_err()
    );
    Ok(())
}

#[test]
fn sccp_original_block_proof_binds_genuinely_certified_distinct_results() -> Result<()> {
    use iroha::data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

    init_instruction_registry();
    let mut first = NativeFinalityFixture::start("sccp-reader-same-proposal-result");
    let mut other = first.clone();
    let submitted = first.block_with_submitted_work(first.next_header());
    // These are synthetic World roots signed by the real fixture quorum.
    // No World transition or monetary-execution qualification is claimed.
    let first_proof = first.certify_with_world_root(
        submitted.clone(),
        iroha::crypto::Hash::new(b"SCCP reader first synthetic World"),
    );
    let other_proof = other.certify_with_world_root(
        submitted,
        iroha::crypto::Hash::new(b"SCCP reader other synthetic World"),
    );
    let first_verifier = first.verifier();
    let other_verifier = other.verifier();
    let first_verified = first_verifier.verify_retained_decision(&first_proof)?;
    let other_verified = other_verifier.verify_retained_decision(&other_proof)?;
    let height = NonZeroU64::new(first_verified.height()).unwrap();
    let scope = first_verifier.root_scope();
    let instance = first_verifier.instance().0;
    let native_hash = first_verified.core_hash().0;
    let first_result = first_verified.result().0;
    let other_result = other_verified.result().0;

    ensure!(height.get() == 2 && other_verified.height() == height.get());
    ensure!(scope == SumeragiRootScope::Global && other_verifier.root_scope() == scope);
    ensure!(other_verifier.instance().0 == instance);
    ensure!(first_verified.header().hash() == other_verified.header().hash());
    ensure!(other_verified.core_hash().0 == native_hash);
    ensure!(first_result != other_result);
    ensure!(
        first_verified.block().executed_block_wire_identity()?
            == other_verified.block().executed_block_wire_identity()?,
        "only the genuinely certified synthetic World result differs"
    );
    // Both frames and certificates are valid before the expected-R check.
    first_proof.decode_checked(scope.into())?;
    other_proof.decode_checked(scope.into())?;
    for (proof, own_result, cross_result) in [
        (&first_proof, &first_result, &other_result),
        (&other_proof, &other_result, &first_result),
    ] {
        let accepted =
            check_sccp_block_proof(proof, height, scope, &instance, &native_hash, own_result)?;
        ensure!(accepted.encode_wire()?.as_slice() == proof.block_wire.as_slice());
        let mismatch =
            check_sccp_block_proof(proof, height, scope, &instance, &native_hash, cross_result)
                .expect_err(
                    "a different genuinely certified R must not authenticate this execution",
                );
        ensure!(
            mismatch.to_string() == "original SCCP certified result differs",
            "the causal control must reach exactly the expected-result comparison: {mismatch}"
        );
    }
    Ok(())
}

#[test]
fn sccp_original_block_proof_accepts_alternate_valid_qc_witness() -> Result<()> {
    use iroha::crypto::bls::consensus;
    use iroha::data_model::{
        block::CommitCertificate, sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };
    use iroha_sumeragi::{
        message::Qc,
        types::{AggregateSignature, Bitmap},
    };

    init_instruction_registry();
    let fixture = NativeFinalityFixture::new();
    let verifier = fixture.verifier();
    let proof = fixture.latest();
    let original = verifier.verify_retained_decision(proof)?;
    let height = NonZeroU64::new(original.height()).unwrap();
    let scope = verifier.root_scope();
    let instance = verifier.instance().0;
    let native_hash = original.core_hash().0;
    let result = original.result().0;
    ensure!(height.get() == 2 && scope == SumeragiRootScope::Global);

    let mut block = original.block().clone();
    let certificate = block.commit_certificate().unwrap();
    let native_header = certificate.consensus_header().to_vec();
    let result_preimage = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical_for_admission(
        certificate.commit_qc(),
        norito::canonical_decode_limits(certificate.commit_qc().len()),
    )?;
    let original_qc = qc.clone();

    // Exactly the public fixture constructor's deterministic keys and ordering.
    // Validate that assumption against the already authenticated fixture roster.
    let mut keys: Vec<_> = (1_u8..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    ensure!(proof.committee.len() == keys.len());
    ensure!(
        keys.iter()
            .zip(&proof.committee)
            .all(|(key, validator)| key.public_key() == &validator.public_key)
    );
    qc.view = qc
        .view
        .checked_add(1)
        .expect("fixture QC view has headroom");
    let chosen = [1_u32, 2, 3];
    qc.signers = Bitmap::from_indices(keys.len(), chosen).unwrap();
    let shares: Vec<_> = chosen
        .iter()
        .map(|index| {
            consensus::sign_preimage(keys[*index as usize].private_key(), &qc.preimage())
                .expect("fixed public fixture key signs the alternate QC")
        })
        .collect();
    qc.agg_sig = AggregateSignature(
        consensus::aggregate(&shares).expect("three valid fixture signatures aggregate"),
    );
    ensure!(qc.signers.count_ones() == 3);
    ensure!(qc.view != original_qc.view && qc.signers != original_qc.signers);
    ensure!(qc.block_hash == original_qc.block_hash && qc.result == original_qc.result);
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        native_header.clone(),
        norito::encode_canonical(&qc)?,
        result_preimage.clone(),
        availability.clone(),
    )));
    let mut alternate = proof.clone();
    alternate.block_wire = block.encode_wire()?;
    ensure!(alternate.block_wire != proof.block_wire);
    let alternate_certificate = block.commit_certificate().unwrap();
    ensure!(alternate_certificate.consensus_header() == native_header.as_slice());
    ensure!(alternate_certificate.result_preimage() == result_preimage.as_slice());
    ensure!(alternate_certificate.availability() == availability.as_slice());
    // The native header, including origin_view, is byte-identical. Only the QC
    // witness changes; its aggregate signature still proves an exact quorum.
    alternate.decode_checked(scope.into())?;
    let same = verifier.verify_same_decision(proof, &alternate)?;
    ensure!(same.core_hash().0 == native_hash && same.result().0 == result);
    ensure!(same.canonical_executed_wire()? == original.canonical_executed_wire()?);
    for candidate in [proof, &alternate] {
        let accepted =
            check_sccp_block_proof(candidate, height, scope, &instance, &native_hash, &result)?;
        ensure!(accepted.encode_wire()?.as_slice() == candidate.block_wire.as_slice());
    }
    Ok(())
}
