#!/usr/bin/env python3
"""Source contract for the isolated four-validator Parliament PR corridor."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "ci/check_sora_parliament_lifecycle.sh"
WORKFLOW = ROOT / ".github/workflows/pr.yml"
MANIFEST = ROOT / "integration_tests/Cargo.toml"
CORRIDOR = ROOT / "integration_tests/tests/sora_parliament_lifecycle_smoke.rs"
NO_RESULT_PATHS = ROOT / "integration_tests/tests/sora_parliament_no_result_paths.rs"
FAILURE_PATHS = ROOT / "integration_tests/tests/sora_parliament_failure_paths.rs"
ENACTMENT = ROOT / "integration_tests/tests/sora_parliament_enactment.rs"
SUPPORT = ROOT / "integration_tests/tests/sora_parliament_lifecycle_support.rs"
NATIVE_FINALITY = ROOT / "integration_tests/tests/sora_parliament_finality.rs"
USER_CONFIG = ROOT / "crates/iroha_config/src/parameters/user.rs"
ACTUAL_CONFIG = ROOT / "crates/iroha_config/src/parameters/actual.rs"
TEST_NETWORK = ROOT / "crates/iroha_test_network/src/lib.rs"
DAEMON = ROOT / "crates/irohad/src/main.rs"
BEACON = ROOT / "crates/iroha_core/src/beacon.rs"
BEACON_TEST_SIGNER = (
    ROOT / "crates/iroha_core/src/beacon/parliament_test_network_signer.rs"
)
BEACON_LIFECYCLE = ROOT / "crates/iroha_core/src/sumeragi/epoch_beacon/producer.rs"
BEACON_PRODUCER_TESTS = ROOT / "crates/iroha_core/src/sumeragi/epoch_beacon/producer/tests.rs"
MANDATORY_NPOS_TEST_NAME = (
    "four_validator_mandatory_npos_epoch_boundary_threshold_beacon_release_gate"
)
FAIL_CLOSED_NPOS_TEST_NAME = (
    "four_validator_mandatory_npos_beacon_fails_closed_below_threshold"
)
GOVERNANCE_ISOLATION_TEST_NAME = (
    "four_validator_pending_parliament_request_never_blocks_unrelated_work_or_restart"
)
NO_RESULT_TEST_NAME = (
    "four_validator_public_finding_no_result_retries_take_later_native_slots"
)
SORTITION_ONLY_CORRIDOR_TEST_NAMES = (
    MANDATORY_NPOS_TEST_NAME,
    FAIL_CLOSED_NPOS_TEST_NAME,
    GOVERNANCE_ISOLATION_TEST_NAME,
    NO_RESULT_TEST_NAME,
    "four_validator_hidden_capacity_retains_then_releases_citizenship_bond",
)
NO_RESULT_RESTART_CONTRACT_ABSENCE = '''assert_governed_contract_absent(
        &restart_peer.client(),
        contract_address,
        "public-finding restart effect isolation",
    )
    .await?;'''
EXACT_INACTIVE_CONTRACT_PROJECTION = '''if object.len() != 3
        || object.get("found").and_then(norito::json::Value::as_bool) != Some(false)
        || object
            .get("contract_address")
            .and_then(norito::json::Value::as_str)
            != Some(contract_address.as_ref())
        || object
            .get("dataspace")
            .and_then(norito::json::Value::as_str)
            != Some("universal")'''
EXACT_NON_BOUNDARY_PULSE_ABSENCE = '''assert_no_global_beacon_pulse_at(
        &client,
        pulse_height - 1,
        "an unrequested non-boundary height must not emit a global pulse",
        &network,
    )
    .await?;'''
EXACT_ABSENCE_CLASSIFICATION_MARKERS = (
    "fn assert_governed_contract_absent(",
    ".get_gov_contract_response(&contract_address)",
    '.wrap_err_with(|| format!("{label}: inactive governed-contract lookup failed"))?;',
    "response.status() != iroha::http::StatusCode::OK",
    "expected governed-contract HTTP 200",
    '''let projection: norito::json::Value = norito::json::from_slice(response.body())
        .wrap_err_with(|| format!("{label}: inactive governed-contract response is not JSON"))?;''',
    EXACT_INACTIVE_CONTRACT_PROJECTION,
    "expected the exact inactive governed-contract projection",
    "fn assert_asset_not_found(client: &Client, asset_id: &AssetId, label: &str)",
    "let query = FindAssetById::new(asset_id.clone());",
    "query.asset_id(),",
    '"{label}: bind the exact requested asset"',
    "move || Ok(client.query_single(query))",
    "match read_on_dedicated_thread({",
    "Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(",
    "FindError::Asset(missing),",
    ")))) if missing.as_ref() == asset_id => Ok(()),",
    "Ok(asset) => Err(eyre!(",
    "expected asset `{asset_id}` to be absent, but the query returned `{}`",
    "expected typed absence of exact asset `{asset_id}",
    "fn assert_no_global_beacon_pulse_at(client: &Client, height: u64, label: &str, network: &iroha_test_network::Network,)",
    "fn exact_block(client: &Client, height: u64, network: &iroha_test_network::Network,) -> Result<SignedBlock>",
    "NonZeroU64::new(height)",
    ".get_sumeragi_finality_proof(requested_height, root_scope)",
    "read finalized block for exact height {height}",
    "decode_framed_signed_block(&proof.block_wire)",
    "if block.header().height() != requested_height",
    "finality proof returned height",
    "if block.header() != proof.block_header",
    "finality proof header differs from its finalized block",
    "let block = exact_block(client, height, network)",
    "if block.global_beacon_pulse().is_some() {",
    EXACT_NON_BOUNDARY_PULSE_ABSENCE,
)
CAPACITY_DOMAIN_REGISTRATION = (
    ".with_genesis_instruction(Register::domain(Domain::new(citizenship_domain.clone())))"
)
CAPACITY_ASSET_REGISTRATION = (
    ".with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric("
)
CAPACITY_EXACT_ASSET = '''citizenship_asset_definition.clone(),
            "Citizenship Bond".to_owned(),
            AssetBalancePolicy::Global,
            None,'''
CAPACITY_ACCOUNT_REGISTRATION = (
    ".with_genesis_instruction(Register::account(Account::new(citizen.clone())))"
)
CAPACITY_BOND_MINT = ".with_genesis_instruction(Mint::asset_quantity("
CAPACITY_CITIZEN_REGISTRATION = ".with_genesis_instruction(RegisterCitizen {"
PARLIAMENT_FAILURE_PATH_MARKERS = {
    "four_validator_hidden_capacity_retains_then_releases_citizenship_bond": (
        'DomainId::try_new("parliament-bond", "universal")?',
        'AssetDefinitionId::derive_from_components(citizenship_domain.clone(), "xor".parse()?)',
        "&citizenship_domain,\n        &citizenship_asset_definition,",
        "prove the bonded citizen passes admission and fees",
        '"hidden-capacity citizen admission control",',
        "retryable hidden-capacity evidence must retain the bond",
        "cause.downcast_ref::<iroha::client::TransactionFinalityFailure>()",
        'failure.response().status.kind,\n                    "Rejected",',
        "failure.response().status.block_height,\n                    Some(control_height + 1),",
        "GovernanceAttemptStatusV1::Rejected",
        "assert_asset_not_found(",
        "genesis citizenship escrow custody",
        "pre-request capacity evidence must not consume or demand a beacon pulse",
        "assert_no_global_beacon_pulse_at(",
        "returned_bond.value(),\n        &Quantity::from(CAPACITY_BOND_AMOUNT)",
        "terminal rejection must release the exact citizenship collateral",
        "restored_bond.value(),\n        &Quantity::from(CAPACITY_BOND_AMOUNT)",
        "restart must retain the released owner balance",
    ),
}
PARLIAMENT_NETWORK_TEST_ATTRIBUTE = "#[test]"


def read_corridor_source() -> str:
    """Read the lifecycle target together with its source-budget support module."""

    return "\n".join(
        (
            CORRIDOR.read_text(encoding="utf-8"),
            NO_RESULT_PATHS.read_text(encoding="utf-8"),
            FAILURE_PATHS.read_text(encoding="utf-8"),
            ENACTMENT.read_text(encoding="utf-8"),
            SUPPORT.read_text(encoding="utf-8"),
            NATIVE_FINALITY.read_text(encoding="utf-8"),
        )
    )


MANDATORY_NPOS_TEST = re.compile(
    rf"(?ms)^{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {MANDATORY_NPOS_TEST_NAME}\(\) -> Result<\(\)> \{{\n"
    r".*?^\}\n"
    rf"\nasync fn {MANDATORY_NPOS_TEST_NAME}_impl\(\)\s*"
    r"-> Result<\(\)>\s*\{\n.*?^\}\n"
    rf"(?=\n{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {FAIL_CLOSED_NPOS_TEST_NAME}\(\))"
)
FAIL_CLOSED_NPOS_TEST = re.compile(
    rf"(?ms)^{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {FAIL_CLOSED_NPOS_TEST_NAME}\(\) -> Result<\(\)> \{{\n"
    r".*?^\}\n"
    rf"\nasync fn {FAIL_CLOSED_NPOS_TEST_NAME}_impl\(\)\s*"
    r"-> Result<\(\)>\s*\{\n"
    r".*?^\}\n"
    rf"(?=\n{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {GOVERNANCE_ISOLATION_TEST_NAME}\(\))"
)
GOVERNANCE_ISOLATION_TEST = re.compile(
    rf"(?ms)^{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {GOVERNANCE_ISOLATION_TEST_NAME}\(\) -> Result<\(\)>\s*\{{\n"
    r".*?^\}\n"
    r"\n(?:// [^\n]*\n)*"
    rf"async fn {GOVERNANCE_ISOLATION_TEST_NAME}_impl\(\)\s*"
    r"-> Result<\(\)>\s*\{\n"
    r".*?^\}\n"
    rf"(?=\n{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {NO_RESULT_TEST_NAME}\(\))"
)
NO_RESULT_TEST = re.compile(
    rf"(?ms)^{re.escape(PARLIAMENT_NETWORK_TEST_ATTRIBUTE)}\n"
    rf"fn {NO_RESULT_TEST_NAME}\(\) -> Result<\(\)>\s*\{{\n"
    r".*?^\}\n"
    r"\n(?:// [^\n]*\n)*"
    rf"async fn {NO_RESULT_TEST_NAME}_impl\(\)\s*"
    r"-> Result<\(\)>\s*\{\n"
    r".*?^\}\n"
    r"(?=\n#\[test\]\nfn parliament_network_corridor_has_no_legacy_or_consensus_bypass_surface\(\))"
)
# A sortition slot is the first consensus-native pulse height at or after the frozen delay
# and above every earlier generation slot. The wait for it is governance-local.
SORTITION_SLOT_HELPER_MARKERS = {
    "with_signed_npos_epoch": (
        "epoch_length_blocks: NonZeroU64::new(epoch_length_blocks)",
        "evidence_horizon_blocks: epoch_length_blocks * 2,",
        "slashing_delay_blocks: epoch_length_blocks,",
        "SumeragiParameter::EpochLengthBlocks(npos.epoch_length_blocks),",
        "SetParameter::new(Parameter::Custom(npos.into_custom_parameter(),))",
    ),
    "certified_npos_epoch_length": (
        "finality::certified_block(network, client, height).await?;",
        "let epoch_length_blocks = authorization.last_height / epochs;",
        "(height - 1) / epoch_length_blocks != authorization.epoch",
    ),
    "require_beacon_horizon": (
        "move || client.get_sumeragi_status()",
        "if let Some(horizon) = status.beacon_horizon {",
        "return Ok((status, horizon));",
        "if Instant::now() >= deadline {",
        "the validator never published its native beacon horizon",
    ),
    "observe_exact_height": (
        "if observed_height == expected_height {",
        "if observed_height > expected_height {",
        "if Instant::now() >= deadline {",
    ),
    "aligned_native_pulse_height": (
        ".checked_add(epoch_length_blocks - 1 - earliest % epoch_length_blocks)",
    ),
    "expected_sortition_slot": (
        "let epoch_length_blocks = certified_npos_epoch_length(network, client).await?;",
        "attempt.sortition_pulse_epoch_length_blocks() != epoch_length_blocks",
        ".checked_add(attempt.sortition_pulse_delay_blocks())",
        "Some(previous) => delayed.max(",
        "aligned_native_pulse_height(earliest, epoch_length_blocks)?;",
    ),
    "await_native_sortition_pulse": (
        "advance_to_autonomous_predecessor(network, client, slot, label).await?;",
        "network.ensure_blocks(slot).await?;",
        "observe_exact_height(client, slot, label).await?;",
        "pulses.push(pulse_at(&peer.client(), slot, network).await?);",
        "if !pulses.windows(2).all(|pair| pair[0] == pair[1]) {",
        "if pulse.height != slot || pulse.network_id != network.network_id() {",
    ),
    "cross_native_boundary_after_pulse": (
        "if boundary_height % epoch_length_blocks != 0 {",
        "network.ensure_blocks(boundary_height).await?;",
        "network.ensure_blocks(successor_height).await?;",
        "observe_exact_height(client, successor_height, label).await?;",
        "context.authorization.epoch != successor_epoch",
        "context.authorization.last_height != boundary_height + epoch_length_blocks",
        "!= global_threshold_beacon_npos_successor_seed_v1(pulse, boundary_height, successor_epoch,)",
    ),
}
RETIRED_SORTITION_SLOT_RULES = (
    "request_height + 4",
    ".checked_add(CAPACITY_SORTITION_DELAY_BLOCKS)",
    "the demanded sortition threshold-beacon effect",
    "network.ensure_blocks(sortition_pulse_height).await?;",
)
# The isolation corridor's decisive assertions, in source order. The first group is the one
# that fails on the retired behaviour: the chain stalled at `request_height + delay`.
GOVERNANCE_ISOLATION_MARKERS = (
    "enactment::builder_with_signer_modes(",
    "FAIL_CLOSED_BEACON_SIGNER_MODES,",
    "SumeragiNposParameters::default().epoch_length_blocks.get(),",
    "let (_, horizon) = require_beacon_horizon(",
    "horizon.active_session_id.is_none(),",
    "transition: ParliamentLifecycleTransitionV1::RegisterInitialSortition,",
    ".checked_add(pending.sortition_pulse_delay_blocks())",
    "let pending_slot = aligned_native_pulse_height(retired_slot, epoch_length_blocks)?;",
    "epoch_length_blocks - 1,",
    "isolation_tip < pending_slot - 1,",
    "BodyElectionAttemptStatusV1::AwaitingPulse",
    "election.attempt().request.pulse_height,",
    "assert!(election.pulse_id().is_none());",
    "retired_slot - 1,",
    "// BASELINE-FAILING ASSERTION:",
    "network.ensure_blocks(retired_slot).await?;",
    "a pending Parliament request must not stall the chain at its retired mid-epoch slot",
    "pending.sortition_pulse_delay_blocks() + ISOLATION_CARRIERS_PAST_RETIRED_SLOT - 1,",
    "let tip_hash = exact_block(&client, isolation_tip, &network).await?.hash();",
    "for height in request_height..=isolation_tip {",
    "a pending Parliament request must not create a global beacon pulse",
    "response.state_payload_hex, pending_payload,",
    "let (status, horizon) = require_beacon_horizon(",
    "a pending Parliament request must not fail-stop a validator",
    "assert_eq!(horizon.epoch_length_blocks, epoch_length_blocks);",
    "assert_ne!(horizon.next_required_pulse_height, Some(retired_slot));",
    "horizon.next_required_pulse_height,\n            Some(pending_slot),",
    "restart_peer.shutdown_if_started().await,",
    "restart_peer.start_checked(config_layers.iter(), None),",
    "restart_peer.once_block(isolation_tip),",
    "restarted_response.state_payload_hex, pending_payload,",
    "let final_tip = isolation_tip + ISOLATION_CARRIERS_AFTER_RESTART;",
    "restart_peer.once_block(final_tip)",
    "for height in isolation_tip..=final_tip {",
    "assert_eq!(response.state_payload_hex, pending_payload);",
)
GOVERNANCE_ISOLATION_CONSTANTS = (
    "const ISOLATION_CARRIERS_PAST_RETIRED_SLOT: u64 = 12;",
    "const ISOLATION_CARRIERS_AFTER_RESTART: u64 = 3;",
    "pub const CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 128;",
)
AUTONOMOUS_PULSE_PROGRESSION = '''network.ensure_blocks(pulse_height).await?;
    assert_eq!(
        current_height(&client).await?,
        pulse_height,
        "the mandatory threshold-beacon effect must autonomously finalize its exact pre-boundary height",
    );'''
BOUNDARY_PROGRESSION = '''network.ensure_blocks(boundary_height).await?;
    assert_eq!(current_height(&client).await?, boundary_height);'''
SUCCESSOR_PROGRESSION = '''network.ensure_blocks(boundary_height + 1).await?;
    assert_eq!(current_height(&client).await?, boundary_height + 1);'''
SUCCESSOR_SEED_EQUALITY = (
    "assert_eq!(context.leader_seed, successor_seed);"
)
RETAINED_AUTHORITY_MARKERS = (
    "finality::visit_certified_prefix(\n"
    "        &network,\n"
    "        &client,\n"
    "        second_boundary_height + 1,\n"
    "        move |proof, verified| {",
    "original_authority = Some((\n"
    "                    context.authorization.authority_generation,\n"
    "                    context.authorization.authority_id,\n"
    "                ));",
    "assert_eq!(\n"
    "                (\n"
    "                    context.authorization.authority_generation,\n"
    "                    context.authorization.authority_id,\n"
    "                ),\n"
    "                original_authority.unwrap()\n"
    "            );",
    "assert_eq!(context.da_layout, recommended_data_availability_layout());",
    "assert_eq!(context.committee.len(), VALIDATOR_COUNT);",
    "assert_eq!(context.authorization.epoch, expected_epoch);",
    "assert_eq!(context.leader_seed, expected_seed);",
    "assert_eq!(context.authorization.last_height, expected_end);",
    "ValidatorEpochDecisionV1::RetainAndCancel",
    "ValidatorEpochDecisionV1::Retain",
    "assert_eq!(authorization.transition_id, [0; 32]);",
    "authorization.beacon,",
    "session_id: expected_session,",
    "transcript_hash: expected_transcript,",
    "assert_eq!(successor_pulse.session_id, beacon_record.session.session_id);",
    "assert_eq!(successor_pulse.session_id, pulse.session_id);",
)
NATIVE_FINALITY_MARKERS = (
    "letprovisioned=network.native_genesis_provisioning_bundle()?;",
    "letgenesis=iroha_genesis::validate_prepared_genesis_bundle("
    "&provisioned.signed_wire,&manifest,&provisioned.public_key,provisioned.block_hash,)?;",
    "ifiroha_data_model::NetworkId::from_genesis_hash(genesis.expected_hash())"
    "!=network.network_id()||genesis.consensus_metadata().sumeragi_context.da_layout"
    "!=recommended_data_availability_layout(){returnErr(eyre!("
    '"ParliamentsignedgenesisnetworkormandatoryRS16layoutdiffers"));}',
    "ifvalidators.len()!=VALIDATOR_COUNT{returnErr(eyre!("
    '"Parliamentrequiresexactlyfoursigned-genesisvalidators"));}',
    "letmutverifier=SumeragiFinalityVerifier::new("
    "genesis.block(),network.chain_id().as_ref(),validators)?;",
    "fornextin1..=height{",
    "letproof=client.get_sumeragi_finality_proof("
    "NonZeroU64::new(next).unwrap(),verifier.root_scope())?;",
    "letauthenticated=verifier.verify(&proof)?;",
    "ifproof.committee.len()!=VALIDATOR_COUNT||members!=expected_members{returnErr(eyre!("
    '"certifiedParliamentcommitteediffersfromtheindependentfour-validatorroster"));}',
    "ifnext>1{",
    "letqc:iroha_sumeragi::message::Qc=norito::decode_canonical(certificate.commit_qc())?;",
    "ifqc.signers.count_ones()!=3{returnErr(eyre!("
    '"Parliamentsuccessorrequiresexactlythreeequalvalidatorvotes"));}',
    "ifInstant::now()>=deadline{returnErr(eyre!("
    '"Parliamentcontiguousfinalityverificationexceededitsdeadline"));}',
    "visit(&proof,&authenticated)?;",
)
POSITIVE_BEACON_MODES = """constPOSITIVE_BEACON_SIGNER_MODES:[ParliamentBeaconSignerMode;VALIDATOR_COUNT]=[ParliamentBeaconSignerMode::Valid,ParliamentBeaconSignerMode::Valid,ParliamentBeaconSignerMode::Absent,ParliamentBeaconSignerMode::Invalid,];"""
FAIL_CLOSED_BEACON_MODES = """constFAIL_CLOSED_BEACON_SIGNER_MODES:[ParliamentBeaconSignerMode;VALIDATOR_COUNT]=[ParliamentBeaconSignerMode::Valid,ParliamentBeaconSignerMode::Absent,ParliamentBeaconSignerMode::Absent,ParliamentBeaconSignerMode::Invalid,];"""
FAIL_CLOSED_STATUS_REQUEST_BOUND = """letstatus_poll_request_timeout=status_poll_window.checked_div(requests_per_sweep).unwrap_or(Duration::ZERO).max(Duration::from_millis(1)).min(Duration::from_secs(5));"""
FAIL_CLOSED_ACTIVATION_DEADLINE = (
    "letactivation_deadline=Instant::now().checked_add(status_poll_window)"
)
FAIL_CLOSED_TIMEOUT = """letunexpected_pulse_height=tokio::time::timeout(FAIL_CLOSED_BEACON_OBSERVATION_WINDOW,network.peers()[0].once_block(pulse_height),).await;"""
FAIL_CLOSED_POST_OBSERVATION_DEADLINE = (
    "letpost_observation_deadline=Instant::now().checked_add(status_poll_window)"
)
SORANET_POW_CORRIDOR_MARKERS = (
    '.write(["network","soranet_handshake","pow","puzzle","memory_kib",],i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB),)',
    '.write(["network","soranet_handshake","pow","puzzle","time_cost"],1_i64,)',
    '.write(["network","soranet_handshake","pow","puzzle","lanes"],1_i64,)',
)
SORANET_POW_REQUIRED_OVERRIDE = (
    '["network","soranet_handshake","pow","required"]'
)
PARLIAMENT_CRYPTO_WORKFLOW_MARKERS = (
    "SORA_PARLIAMENT_CRYPTO_EVIDENCE_DIR: target/sora-parliament-crypto-evidence-",
    "pytest==9.0.3",
    "scripts/tests/check_sora_parliament_crypto_bench_test.py",
    "IROHA_PARLIAMENT_CRYPTO_ALLOCATION_EVIDENCE_V1",
    "cargo bench --locked -p iroha_crypto --bench parliament_crypto",
    "parliament_crypto_allocation_budgets.json",
    "--write-report",
    "--verify-report",
    "SHA256SUMS",
    "name: sora-parliament-crypto-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
    "if-no-files-found: error",
    "retention-days: 90",
)


class ContractError(AssertionError):
    """Raised when the source-only corridor contract is incomplete."""


def require(condition: bool, message: str) -> None:
    """Fail the source contract with one stable diagnostic."""

    if not condition:
        raise ContractError(message)


def validate_runner(source: str) -> None:
    """Validate the exact debug prebuild and no-skip execution corridor."""

    required = (
        "cargo build --locked",
        "--features test-network-parliament-signers",
        "TEST_NETWORK_BIN_IROHAD_PARLIAMENT_SIGNERS",
        "IROHA_TEST_SKIP_BUILD=1",
        "IROHA_TEST_REQUIRE_NETWORK=1",
        "IROHA_FAIL_ON_SANDBOX_SKIP=1",
        "cargo test --locked",
        "--features parliament-test-signers",
        "--test sora_parliament_lifecycle_smoke",
        "--test-threads=1",
    )
    for marker in required:
        require(marker in source, f"Parliament runner lost `{marker}`")
    require("--release" not in source, "test signer runner must remain debug-only")
    require(source.count("cargo build ") == 1, "runner needs one exact daemon prebuild")
    require(source.count("cargo test ") == 1, "runner needs one exact test invocation")
    require(
        source.index("cargo build ")
        < source.index("TEST_NETWORK_BIN_IROHAD_PARLIAMENT_SIGNERS")
        < source.index("cargo test "),
        "runner must prebuild, pin the exact daemon, then run the test",
    )


def validate_workflow(source: str) -> None:
    """Validate that PR CI schedules the isolated runner on four-peer capacity."""

    job = re.search(
        r"(?ms)^  sora_parliament_lifecycle:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        source,
    )
    require(job is not None, "PR workflow does not schedule the Parliament corridor")
    body = job.group("body")
    for marker in (
        "runs-on: [self-hosted, Linux, iroha2]",
        "CARGO_TARGET_DIR: target/sora-parliament-lifecycle",
        "python3 -I -S scripts/tests/sora_parliament_lifecycle_corridor_source_test.py",
        "bash ci/check_sora_parliament_lifecycle.sh",
        *PARLIAMENT_CRYPTO_WORKFLOW_MARKERS,
    ):
        require(marker in body, f"Parliament PR job lost `{marker}`")
    require(
        body.count("cargo bench --locked -p iroha_crypto --bench parliament_crypto") == 2,
        "Parliament crypto evidence needs one allocation and one Criterion invocation",
    )
    for marker, count in (
        ("parliament_crypto_allocation_budgets.json", 3),
        ("SHA256SUMS", 3),
        ("if-no-files-found: error", 2),
    ):
        require(
            body.count(marker) == count,
            f"Parliament PR job needs exactly {count} `{marker}` occurrences",
        )
    require("--release" not in body, "Parliament PR job must not consume release binaries")


def mutate_parliament_workflow(source: str, marker: str) -> str:
    """Remove one marker only from the dedicated Parliament workflow job."""

    job = re.search(
        r"(?ms)^  sora_parliament_lifecycle:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        source,
    )
    require(job is not None, "PR workflow does not schedule the Parliament corridor")
    body = job.group("body")
    require(marker in body, f"Parliament PR job does not contain `{marker}`")
    mutated = body.replace(marker, "", 1)
    return source[: job.start("body")] + mutated + source[job.end("body") :]


def corridor_helper(source: str, name: str) -> str:
    """Return one exact shared corridor helper by name."""

    found = list(
        re.finditer(
            rf"(?ms)^(?:pub(?:\((?:super|crate)\))? )?(?:async )?fn {re.escape(name)}\(.*?^\}}\n",
            source,
        )
    )
    require(len(found) == 1, f"corridor helper `{name}` is not one exact item")
    return found[0].group(0)


def validate_native_sortition_helpers(source: str) -> None:
    """Require the governance-local sortition wait on the consensus-native slot."""

    for name, markers in SORTITION_SLOT_HELPER_MARKERS.items():
        helper = compact(corridor_helper(source, name))
        for marker in markers:
            require(
                compact(marker) in helper,
                f"native sortition helper `{name}` lost `{marker}`",
            )
    for retired in RETIRED_SORTITION_SLOT_RULES:
        require(
            retired not in source,
            f"Parliament corridor regained the retired sortition rule `{retired}`",
        )
    require(
        'tick(&client, "finalize the demanded sortition pulse")' not in source,
        "demanded Parliament pulse regained a racing tick",
    )


def governance_isolation_test(source: str) -> tuple[re.Match[str], str]:
    """Return the one exact executable governance-isolation test item."""

    matches = list(GOVERNANCE_ISOLATION_TEST.finditer(source))
    require(len(matches) == 1, "governance-isolation corridor is not one exact test item")
    match = matches[0]
    previous_item_end = source.rfind("\n}\n", 0, match.start())
    require(previous_item_end >= 0, "governance-isolation test has no preceding item boundary")
    leading = source[previous_item_end + len("\n}\n") : match.start()]
    require("#[" not in leading, "governance-isolation corridor gained an extra attribute")
    return match, match.group(0)


def mutate_governance_isolation_test(source: str, old: str, new: str = "") -> str:
    """Apply one exact mutation only inside the governance-isolation test item."""

    match, test = governance_isolation_test(source)
    require(old in test, f"governance-isolation mutation target is absent: `{old}`")
    mutated = test.replace(old, new, 1)
    return source[: match.start()] + mutated + source[match.end() :]


def validate_governance_isolation_corridor(source: str) -> None:
    """Pin the rule that a pending Parliament request never blocks unrelated work."""

    _, test = governance_isolation_test(source)
    positions = []
    for marker in GOVERNANCE_ISOLATION_MARKERS:
        require(marker in test, f"governance-isolation corridor lost `{marker}`")
        positions.append(test.index(marker))
    require(
        positions == sorted(positions),
        "governance-isolation corridor must request, commit unrelated work past the "
        "retired slot, observe every validator, restart one, then commit more work",
    )
    for constant in GOVERNANCE_ISOLATION_CONSTANTS:
        require(source.count(constant) == 1, f"corridor constant `{constant}` is not exact")
    for forbidden in (
        "with_signed_npos_epoch(",
        "POSITIVE_BEACON_SIGNER_MODES",
        "ConsumeSortitionPulseBatch",
        ".push(pulse_at(",
        "await_native_sortition_pulse(",
        "lifecycle_certificate(",
        "FinalizeGlobalBeaconKey",
        "enactment::builder(",
    ):
        require(
            forbidden not in test,
            f"governance-isolation corridor must stay on the default epoch without a pulse: `{forbidden}`",
        )
    # The horizon is required by `require_beacon_horizon`: a guard on its presence would
    # let the session precondition and the readiness assertions pass without running.
    for vacuous in ("if let Some(horizon)", ".beacon_horizon", ".is_none_or("):
        require(
            vacuous not in test,
            f"governance-isolation corridor must not guard its horizon assertions: `{vacuous}`",
        )
    compacted = compact(test)
    for marker in (
        "std::thread::Builder::new()",
        ".stack_size(PARLIAMENT_NETWORK_STACK_BYTES)",
        ".thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)",
    ):
        require(
            compacted.count(marker) == 1,
            f"governance-isolation corridor lost stack marker `{marker}`",
        )
    require(
        compacted.count(f"{GOVERNANCE_ISOLATION_TEST_NAME}_impl()") == 2,
        "governance-isolation wrapper no longer invokes its exact async implementation",
    )


def validate_sortition_corridors_execute(source: str) -> None:
    """Require every Parliament corridor to be an executable test that is never ignored."""

    for name in SORTITION_ONLY_CORRIDOR_TEST_NAMES:
        pattern = re.compile(rf"(?m)^#\[test\]\nfn {re.escape(name)}\(\)")
        require(
            len(pattern.findall(source)) == 1,
            f"sortition-only corridor `{name}` must stay an executable test",
        )
    require(
        "#[ignore" not in source,
        "no Parliament corridor may be ignored",
    )


def validate_public_finding_no_result_retries_and_restore(source: str) -> None:
    """Require both public-finding NoResult classes, retries, and restore."""

    matches = list(NO_RESULT_TEST.finditer(source))
    require(len(matches) == 1, "public-finding NoResult corridor is not one exact test item")
    test = matches[0].group(0)
    for marker in (
        "exercise_public_finding_no_result_retries_and_restore(",
        "let builder = enactment::builder(",
        "CORRIDOR_NPOS_EPOCH_LENGTH_BLOCKS,",
        "enactment::fund_citizen_fees(&network, &client, &citizens).await?;",
        "failure_paths::install_threshold_sessions(&network, &client).await?;",
    ):
        require(marker in test, f"public-finding NoResult corridor lost `{marker}`")
    helper = re.search(
        r"(?ms)^pub\(super\) async fn "
        r"exercise_public_finding_no_result_retries_and_restore\(.*?^\}\n",
        source,
    )
    require(helper is not None, "public-finding closure helper is absent")
    helper_source = helper.group(0)
    for marker in (
        "expected_sortition_slot(network, client, attempt_id, request_height, None).await?;",
        "expected_sortition_slot(network, client, retry_id, retry_request_height, None).await?;",
        "retry_pulse_height > sortition_pulse_height,",
        "assert_ne!(retry_pulse.pulse_id, pulse.pulse_id);",
        "ParliamentLifecycleTransitionV1::RecordAttemptAbsence(",
        "failed_height < public_finding_deadline",
        "BodyInstanceStatusV1::NoResult",
        "ParliamentNoResultKindV1::PublicFindingQuorumUnreachable",
        "public-finding quorum-unreachable effect isolation",
        "public-finding peer effect isolation",
        "attempt_sequence: 1",
        "GovernanceStageV1::Qualification",
        "iroha.integration.parliament.competing-public-finding.v1",
        "deadline retry has no nonmember permissionless relayer",
        "public-finding endorsement after the inclusive frozen deadline",
        "ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(",
        "ParliamentNoResultKindV1::PublicFindingDeadlineExpired",
        "attempt_sequence: 2",
        "peer_rejected.state_payload_hex",
        "peer_retry.state_payload_hex",
        "peer_second_retry.state_payload_hex",
        "restart_peer.start_checked(config_layers.iter(), None)",
        "restored_retry.state_payload_hex",
        "restored_second_retry.state_payload_hex",
        NO_RESULT_RESTART_CONTRACT_ABSENCE,
    ):
        require(marker in helper_source, f"public-finding closure corridor lost `{marker}`")
    for marker, count in (
        ("await_native_sortition_pulse(", 2),
        ("cross_native_boundary_after_pulse(", 2),
        ("ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(", 2),
    ):
        require(
            helper_source.count(marker) == count,
            f"public-finding closure corridor needs {count} exact `{marker}` steps",
        )


def validate_exact_absence_classification(source: str) -> None:
    """Require exact positive and negative state projections, not transport success."""

    for marker in EXACT_ABSENCE_CLASSIFICATION_MARKERS:
        require(
            compact(marker) in compact(source),
            f"Parliament state coverage lost exact classifier `{marker}`",
        )
    require(
        source.count(".get_gov_contract_response(") == 1,
        "governed-contract reads must remain centralized in the exact projection helper",
    )
    asset_helper = corridor_helper(source, "assert_asset_not_found")
    require(
        asset_helper.count("let query = FindAssetById::new(asset_id.clone());") == 1
        and asset_helper.count("query.asset_id(),") == 1
        and asset_helper.count("move || Ok(client.query_single(query))") == 1
        and asset_helper.count("match read_on_dedicated_thread({") == 1
        and asset_helper.count(".await?") == 1
        and asset_helper.count("FindError::Asset(missing)") == 1
        and asset_helper.count("if missing.as_ref() == asset_id => Ok(())") == 1
        and asset_helper.count("Ok(())") == 1
        and "QueryExecutionFail::NotFound" not in asset_helper,
        "asset absence requires one bound singular query and typed absence of its exact asset ID",
    )
    require(
        source.count(
            ".get_sumeragi_finality_proof(requested_height, root_scope)\n"
            '                .map_err(|error| eyre!("read finalized block for exact height {height}: {error}"))'
        )
        == 1
        and source.count("decode_framed_signed_block(&proof.block_wire)") == 1
        and source.count("if block.header().height() != requested_height {") == 1
        and source.count("if block.header() != proof.block_header {") == 1
        and ".query(FindBlocks)" not in source,
        "exact finalized-block checks must read one finality proof and bind its exact height and header",
    )
    exact = re.search(r"(?ms)^pub async fn exact_block\(.*?^\}\n", source)
    require(exact is not None, "exact finalized-block lookup lost its invoked owner")
    require(
        "NonZeroU64::new(height)" in exact.group(0),
        "the exact finalized-block helper must reject a zero requested height",
    )

    broad_absence_patterns = {
        "governed-contract lookup": (
            r"\.get_gov_contract_json\((?:&)?contract_address\)\s*\.is_err\(\)"
        ),
        "citizenship asset lookup": (
            r"\.query_single\(FindAssetById::new\(citizen_asset_id\.clone\(\)\)\)"
            r"\s*\.is_err\(\)"
        ),
        "global beacon pulse lookup": (
            r"pulse_at\(\s*&client,\s*pulse_height\s*-\s*1\s*\)\s*\.is_err\(\)"
        ),
    }
    for label, pattern in broad_absence_patterns.items():
        require(
            re.search(pattern, source) is None,
            f"Parliament {label} regained a broad `is_err()` absence assertion",
        )


def parliament_failure_path_test(source: str, name: str) -> tuple[re.Match[str], str]:
    """Return one exact executable Parliament failure-path test and its async body."""

    pattern = re.compile(
        rf"(?ms)^#\[test\]\n"
        rf"fn {re.escape(name)}\(\) -> Result<\(\)> \{{\n"
        r".*?^\}\n"
        rf"\nasync fn {re.escape(name)}_impl\(\)\s*-> Result<\(\)>\s*\{{\n"
        r".*?^\}\n"
    )
    matches = list(pattern.finditer(source))
    require(len(matches) == 1, f"Parliament failure path `{name}` is not one exact test item")
    match = matches[0]
    return match, match.group(0)


def validate_parliament_failure_paths(source: str) -> None:
    """Pin capacity-abort and bond-release coverage."""

    for name, markers in PARLIAMENT_FAILURE_PATH_MARKERS.items():
        _, test = parliament_failure_path_test(source, name)
        for marker in markers:
            require(marker in test, f"Parliament failure path `{name}` lost `{marker}`")


def capacity_failure_builder(source: str) -> tuple[re.Match[str], str]:
    """Return the exact hidden-capacity network builder."""

    pattern = re.compile(
        r"(?ms)^fn capacity_failure_builder\(.*?^\}\n"
        r"(?=\n#\[test\]\nfn four_validator_hidden_capacity_retains_then_releases_citizenship_bond\()"
    )
    matches = list(pattern.finditer(source))
    require(len(matches) == 1, "hidden-capacity network builder is not one exact item")
    match = matches[0]
    return match, match.group(0)


def validate_capacity_failure_genesis(source: str) -> None:
    """Require the exact citizenship asset hierarchy before bond mint/custody."""

    _, builder = capacity_failure_builder(source)
    ordered = (
        CAPACITY_DOMAIN_REGISTRATION,
        CAPACITY_ASSET_REGISTRATION,
        CAPACITY_ACCOUNT_REGISTRATION,
        CAPACITY_BOND_MINT,
        CAPACITY_CITIZEN_REGISTRATION,
    )
    positions = []
    for marker in (*ordered, CAPACITY_EXACT_ASSET):
        require(marker in builder, f"hidden-capacity genesis lost `{marker}`")
        if marker in ordered:
            positions.append(builder.index(marker))
    require(
        positions == sorted(positions),
        "hidden-capacity genesis must register domain, asset, and account before mint/custody",
    )


def mutate_capacity_failure_builder(
    source: str, old: str, new: str = ""
) -> str:
    """Apply one exact mutation only inside the hidden-capacity builder."""

    match, builder = capacity_failure_builder(source)
    require(old in builder, f"hidden-capacity mutation target is absent: `{old}`")
    mutated = builder.replace(old, new, 1)
    return source[: match.start()] + mutated + source[match.end() :]


def mutate_parliament_failure_path_test(
    source: str, name: str, old: str, new: str = ""
) -> str:
    """Remove or replace one operation only inside its actual failure-path test."""

    match, test = parliament_failure_path_test(source, name)
    require(old in test, f"Parliament failure-path mutation target is absent: `{old}`")
    mutated = test.replace(old, new)
    return source[: match.start()] + mutated + source[match.end() :]


def mandatory_npos_test(source: str) -> tuple[re.Match[str], str]:
    """Return the one exact executable mandatory-NPoS test item."""

    matches = list(MANDATORY_NPOS_TEST.finditer(source))
    require(len(matches) == 1, "mandatory NPoS beacon corridor is not one exact test item")
    match = matches[0]
    previous_item_end = source.rfind("\n}\n", 0, match.start())
    require(previous_item_end >= 0, "mandatory NPoS test has no preceding item boundary")
    leading = source[previous_item_end + len("\n}\n") : match.start()]
    require(
        "#[" not in leading,
        "mandatory NPoS beacon corridor gained an extra attribute",
    )
    return match, match.group(0)


def mutate_mandatory_npos_test(source: str, old: str, new: str = "") -> str:
    """Apply one exact mutation only inside the mandatory-NPoS test item."""

    match, test = mandatory_npos_test(source)
    require(old in test, f"mandatory NPoS mutation target is absent: `{old}`")
    mutated = test.replace(old, new, 1)
    return source[: match.start()] + mutated + source[match.end() :]


def fail_closed_npos_test(source: str) -> tuple[re.Match[str], str]:
    """Return the one exact executable below-threshold NPoS test item."""

    matches = list(FAIL_CLOSED_NPOS_TEST.finditer(source))
    require(len(matches) == 1, "fail-closed NPoS beacon corridor is not one exact test item")
    match = matches[0]
    previous_item_end = source.rfind("\n}\n", 0, match.start())
    require(previous_item_end >= 0, "fail-closed NPoS test has no preceding item boundary")
    leading = source[previous_item_end + len("\n}\n") : match.start()]
    require(
        "#[" not in leading,
        "fail-closed NPoS beacon corridor gained an extra attribute",
    )
    return match, match.group(0)


def mutate_fail_closed_npos_test(source: str, old: str, new: str = "") -> str:
    """Apply one exact mutation only inside the fail-closed NPoS test item."""

    match, test = fail_closed_npos_test(source)
    require(old in test, f"fail-closed NPoS mutation target is absent: `{old}`")
    mutated = test.replace(old, new, 1)
    return source[: match.start()] + mutated + source[match.end() :]


def compact(source: str) -> str:
    """Remove formatting whitespace while retaining exact Rust tokens."""

    return re.sub(r"\s+", "", source)


def mutate_marker(
    source: str, marker: str, replacement: str = "", *, owner: str | None = None
) -> str:
    """Mutate an actual token span, including markers formatted across multiple lines."""

    offset = 0
    original = source
    if owner is not None:
        function = re.search(
            rf"(?ms)^(?:pub(?:\((?:super|crate)\))? )?(?:async )?fn {re.escape(owner)}\(.*?^\}}\n",
            source,
        )
        require(function is not None, f"mutation owner is absent: `{owner}`")
        offset = function.start()
        source = function.group(0)
    positions = [index for index, char in enumerate(source) if not char.isspace()]
    tokens = "".join(source[index] for index in positions)
    expected = compact(marker)
    require(bool(expected), "mutation marker cannot be empty")
    start = tokens.find(expected)
    require(start >= 0, f"mutation target is absent: `{marker}`")
    first = positions[start]
    end = positions[start + len(expected) - 1] + 1
    return original[:offset + first] + replacement + original[offset + end:]


def validate_required_bounded_soranet_pow(source: str) -> None:
    """Require mandatory, supported-cost SoraNet admission in every corridor."""

    tests = (
        ("shared Parliament builder", corridor_helper(source, "builder_with_signer_modes")),
        ("mandatory NPoS", mandatory_npos_test(source)[1]),
        ("fail-closed NPoS", fail_closed_npos_test(source)[1]),
    )
    compacted_source = compact(source)
    compacted_tests = "".join(compact(test) for _, test in tests)
    require(
        SORANET_POW_REQUIRED_OVERRIDE not in compacted_source,
        "corridor must not override the hard-required SoraNet PoW admission field",
    )
    actual_config = ACTUAL_CONFIG.read_text(encoding="utf-8")
    pow_shape = re.search(r"pub struct SoranetPow \{(?P<body>.*?)^\}", actual_config, re.M | re.S)
    require(pow_shape is not None, "actual SoraNet PoW configuration shape is missing")
    require(
        "required" not in pow_shape.group("body"),
        "SoraNet PoW regained a runtime required/optional toggle",
    )
    require(
        "actual::SoranetPow{difficulty,max_future_skew,min_ticket_ttl,ticket_ttl,"
        in compact(USER_CONFIG.read_text(encoding="utf-8")),
        "user configuration no longer constructs the mandatory SoraNet PoW policy",
    )
    for marker in SORANET_POW_CORRIDOR_MARKERS:
        require(
            compacted_tests.count(marker) == len(tests),
            f"SoraNet corridor marker is not present exactly once per builder: `{marker}`",
        )
    for label, test in tests:
        compacted_test = compact(test)
        for marker in SORANET_POW_CORRIDOR_MARKERS:
            require(
                compacted_test.count(marker) == 1,
                f"{label} corridor lost exact mandatory bounded SoraNet PoW marker `{marker}`",
            )


def validate_consensus_sized_test_stacks(source: str) -> None:
    """Require every four-validator corridor to run on the bounded large-stack harness."""

    require(
        source.count("const PARLIAMENT_NETWORK_STACK_BYTES: usize = 32 * 1024 * 1024;")
        == 1,
        "Parliament network stack size is not one exact 32 MiB constant",
    )
    tests = (
        (MANDATORY_NPOS_TEST_NAME, mandatory_npos_test(source)[1]),
        (FAIL_CLOSED_NPOS_TEST_NAME, fail_closed_npos_test(source)[1]),
    )
    for name, test in tests:
        compacted = compact(test)
        for marker in (
            "std::thread::Builder::new()",
            ".stack_size(PARLIAMENT_NETWORK_STACK_BYTES)",
            "tokio::runtime::Builder::new_multi_thread()",
            ".worker_threads(4)",
            ".thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)",
        ):
            require(
                compacted.count(marker) == 1,
                f"{name} lost exact consensus-sized stack marker `{marker}`",
            )
        require(
            compacted.count(f"{name}_impl()") == 2,
            f"{name} wrapper no longer invokes its exact async implementation",
        )


def validate_mandatory_npos_boundary(source: str) -> None:
    """Require genuine pulses and genesis-bound authority across retained epochs."""

    _, test = mandatory_npos_test(source)
    require(
        source.count("const MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 8;") == 1,
        "mandatory NPoS epoch length is not one exact eight-block constant",
    )
    require(
        source.count("const VALIDATOR_COUNT: usize = 4;") == 1,
        "Parliament corridor validator count is not one exact four-peer constant",
    )
    required = (
        "SumeragiNposParameters::default()",
        ".with_peers(VALIDATOR_COUNT)",
        ".with_npos_consensus()",
        ".with_parliament_beacon_signer_modes(POSITIVE_BEACON_SIGNER_MODES)",
        "assert_eq!(network.peers().len(), VALIDATOR_COUNT);",
        "assert_eq!(beacon_record.session.committee_size, 4);",
        "assert_eq!(beacon_record.session.threshold, 2);",
        "let boundary_height = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS;",
        "pulse_height = boundary_height - 1",
        AUTONOMOUS_PULSE_PROGRESSION,
        "verify_finalized_global_threshold_beacon_pulse_v1(",
        "let successor_epoch = 1;",
        "global_threshold_beacon_npos_successor_seed_v1(",
        BOUNDARY_PROGRESSION,
        SUCCESSOR_PROGRESSION,
        "assert_eq!(context.authorization.epoch, successor_epoch);",
        SUCCESSOR_SEED_EQUALITY,
        "let successor_pulse_height = boundary_height",
        "&validated_beacon_session",
        "let second_successor_epoch = 2;",
        "assert_eq!(context.authorization.epoch, second_successor_epoch);",
        "assert_eq!(context.leader_seed, second_successor_seed);",
        "!status.is_halted()",
        *RETAINED_AUTHORITY_MARKERS,
    )
    for marker in required:
        require(marker in test, f"mandatory NPoS beacon test lost `{marker}`")
    validate_native_finality_prefix(source)
    require(
        test.count("verify_finalized_global_threshold_beacon_pulse_v1(") == 2,
        "mandatory NPoS beacon test must independently verify both retained-session pulses",
    )
    require(
        test.count("&validated_beacon_session,") == 2,
        "both mandatory pulses must use the independently validated retained session",
    )
    require(
        test.count("!status.is_halted()") == 2,
        "mandatory NPoS beacon test must prove both successor epochs remain live",
    )
    require(
        ".with_permissioned_consensus()" not in test,
        "mandatory NPoS beacon test selected permissioned consensus",
    )
    require(
        'tick(&client, "commit mandatory pre-boundary pulse")' not in test,
        "mandatory pre-boundary pulse must not race a user transaction",
    )


def validate_native_finality_prefix(source: str) -> None:
    """Follow the connected native prefix helper to signed genesis and exact quorum."""

    require(
        '#[path = "sora_parliament_finality.rs"]\npub mod finality;' in source,
        "Parliament corridor lost its native finality helper registration",
    )
    helpers = list(re.finditer(
        r"(?ms)^pub async fn visit_certified_prefix\(.*?^\}\n", source,
    ))
    require(len(helpers) == 1, "Parliament native prefix helper must have one owner")
    body = compact(re.sub(r"/\*.*?\*/|//[^\n]*", "", helpers[0].group(0), flags=re.S))
    for marker in NATIVE_FINALITY_MARKERS:
        require(marker in body, f"Parliament native finality lost `{marker}`")
    positions = [body.find(marker) for marker in NATIVE_FINALITY_MARKERS]
    require(positions == sorted(positions), "native prefix must authenticate before observation")


def validate_beacon_rotation_fixture(source: str) -> None:
    """Require two complete feature-only DKG fixtures and exact-session dispatch."""

    require(
        source.count("TEST_SUCCESSOR_SESSION_ID_DOMAIN_V1") == 2,
        "rotatable beacon fixture lost the unique successor domain binding",
    )
    for marker in (
        "deterministic_parliament_beacon_successor_key_record_v1",
        "deterministic_fixture_v1(network_id, ordered_roster, true, budget)",
        "let initial_fixture =",
        "deterministic_fixture_v1(self.network_id, &self.ordered_roster, false, &self.budget)",
        "let successor_fixture =",
        "deterministic_fixture_v1(self.network_id, &self.ordered_roster, true, &self.budget)",
        "if successor_fixture.session.record() != session.record()",
        "exact_seat_signer_supports_one_domain_separated_successor_session",
        "assert_ne!(initial.session.session_id, successor.session.session_id);",
        "verify_partial_signature(payload, &partial)",
    ):
        require(marker in source, f"rotatable beacon test fixture lost `{marker}`")


def validate_beacon_mode_profiles(source: str) -> None:
    """Freeze exact 4-seat/2-threshold positive and fail-closed mode profiles."""

    compacted = compact(source)
    require(
        compacted.count(POSITIVE_BEACON_MODES) == 1,
        "positive beacon mode profile is not exact valid/valid/absent/invalid",
    )
    require(
        compacted.count(FAIL_CLOSED_BEACON_MODES) == 1,
        "fail-closed beacon mode profile is not exact valid/absent/absent/invalid",
    )
    builder = corridor_helper(source, "builder")
    require(
        "builder_with_signer_modes(builder, POSITIVE_BEACON_SIGNER_MODES)," in builder
        and ".with_parliament_beacon_signer_modes(signer_modes)"
        in corridor_helper(source, "builder_with_signer_modes"),
        "shared Parliament corridors lost the positive fault profile",
    )


def validate_fail_closed_npos_boundary(source: str) -> None:
    """Require four live validators to stall exactly below a mandatory pulse."""

    _, test = fail_closed_npos_test(source)
    required = (
        "SumeragiNposParameters::default()",
        ".with_peers(VALIDATOR_COUNT)",
        ".with_npos_consensus()",
        ".with_parliament_beacon_signer_modes(FAIL_CLOSED_BEACON_SIGNER_MODES)",
        "assert_eq!(network.peers().len(), VALIDATOR_COUNT);",
        "assert_eq!(beacon_record.session.committee_size, 4);",
        "assert_eq!(beacon_record.session.threshold, 2);",
        "filter(|mode| **mode == ParliamentBeaconSignerMode::Valid)",
        "let pulse_height = MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS - 1;",
        "let predecessor_height = pulse_height - 1;",
        "let pulse_status_is_active = |status: &SumeragiStatus| -> bool {",
        "assert!(status.applied_height <= status.committed_height);",
        "if status.height == predecessor_height {",
        "assert!(status.awaiting);",
        "!status.awaiting && status.applied_height == predecessor_height",
        "let status_poll_window = network.sync_timeout();",
        "status_poll_window.is_zero()",
        "let requests_per_sweep = u32::try_from(network.peers().len())",
        ".and_then(|peers| peers.checked_mul(2))",
        "integration_tests::sync::rebind_blocking_client(&peer.client(), |builder| {",
        "builder.torii_request_timeout = status_poll_request_timeout;",
        "let activation_deadline = Instant::now()",
        "let mut last_activation_status_error = None;",
        "for (peer_index, peer_client) in status_poll_clients.iter().enumerate() {",
        "let observed_height = match current_height(peer_client).await {",
        'Some(format!("peer {peer_index} height: {error}"));',
        "let status = match read_on_dedicated_thread({",
        "move || client.get_sumeragi_status()",
        "last_activation_status_error =",
        'Some(format!("peer {peer_index} sumeragi status: {error}"));',
        "all_pulse_heights_active = false;",
        "activation_deadline.saturating_duration_since(Instant::now())",
        "in-flight request bound; last status fetch error: {}",
        "last status fetch error: {}",
        "all_pulse_heights_active &= pulse_status_is_active(&status);",
        "unexpected_pulse_height.is_err()",
        "let post_observation_deadline = Instant::now()",
        "let mut last_post_observation_status_error = None;",
        "let mut all_post_observation_statuses_verified = true;",
        "last_post_observation_status_error =",
        "all_post_observation_statuses_verified = false;",
        "if all_post_observation_statuses_verified {",
        "post_observation_deadline.saturating_duration_since(Instant::now())",
        "after the below-threshold observation; last status fetch error: {}",
        "without leaving detached blocking",
        "peer.is_running()",
        "!status.is_halted()",
        "assert_eq!(status.committed_height, predecessor_height);",
        "assert_eq!(status.height, pulse_height);",
    )
    for marker in required:
        require(marker in test, f"fail-closed NPoS beacon test lost `{marker}`")
    compacted = compact(test)
    predecessor_handoff = compacted.index("ifstatus.height==predecessor_height{")
    active_pulse = compacted.index("assert_eq!(status.height,pulse_height);", predecessor_handoff)
    require(
        "assert!(status.awaiting);returnfalse;" in compacted[predecessor_handoff:active_pulse],
        "the committed predecessor without a successor configuration must remain a retry",
    )
    require(
        FAIL_CLOSED_STATUS_REQUEST_BOUND in compacted,
        "fail-closed NPoS beacon test lost its short non-zero per-request bound",
    )
    require(
        FAIL_CLOSED_TIMEOUT in compacted,
        "fail-closed NPoS beacon test lost its bounded no-block observation",
    )
    require(
        FAIL_CLOSED_ACTIVATION_DEADLINE in compacted,
        "fail-closed NPoS beacon test lost its monotonic pulse-context activation deadline",
    )
    require(
        FAIL_CLOSED_POST_OBSERVATION_DEADLINE in compacted,
        "fail-closed NPoS beacon test lost its fresh monotonic post-observation deadline",
    )
    require(
        compacted.index(FAIL_CLOSED_ACTIVATION_DEADLINE)
        < compacted.index(FAIL_CLOSED_TIMEOUT)
        < compacted.index(FAIL_CLOSED_POST_OBSERVATION_DEADLINE),
        "fail-closed NPoS beacon gates must order activation, observation, then post-observation verification",
    )
    require(
        test.count("let observed_height = match current_height(peer_client).await {") == 2
        and test.count('Some(format!("peer {peer_index} height: {error}"));') == 2,
        "both fail-closed NPoS status gates must retry transient authoritative-height failures",
    )
    require(
        test.count(
            'Some(format!("peer {peer_index} sumeragi status: {error}"));'
        )
        == 2,
        "both fail-closed NPoS status gates must retry transient Sumeragi-status failures",
    )
    require(
        test.count("Instant::now() >= activation_deadline") == 3
        and test.count("Instant::now() >= post_observation_deadline") == 3,
        "both fail-closed NPoS status gates must check their deadline around every synchronous request",
    )
    require(
        test.count(".saturating_duration_since(Instant::now())") == 2,
        "both fail-closed NPoS status gates must bound their retry sleep by the remaining deadline",
    )
    require(
        test.count("pulse_status_is_active(&status)") == 2,
        "fail-closed NPoS beacon test must validate the pulse context before and after observation",
    )
    require(
        ".with_permissioned_consensus()" not in test,
        "fail-closed beacon test selected permissioned consensus",
    )
    require(
        ".with_parliament_test_signers()" not in test,
        "fail-closed beacon test replaced the exact per-peer fault profile",
    )
    require(
        "spawn_blocking" not in test,
        "fail-closed beacon status polls must not leave detached blocking requests",
    )
    require(
        "network.shutdown().await;" in test,
        "fail-closed beacon test must shut down all still-live validators",
    )


def validate_native_beacon_admission_and_fixture_isolation(
    test_network: str,
    daemon: str,
    beacon: str,
    lifecycle: str,
    producer_tests: str,
) -> None:
    """Pin test-provider isolation and genuine native signed-share admission."""

    for marker in (
        "pub enum ParliamentBeaconSignerMode",
        "with_parliament_beacon_signer_modes",
        '"--test-network-parliament-beacon-signer-mode"',
        "append_parliament_beacon_signer_mode_arg",
    ):
        require(marker in test_network, f"test-network signer wiring lost `{marker}`")
    for marker in (
        '#[cfg(feature = "test-network-parliament-signers")]\n#[derive(',
        "enum TestNetworkParliamentBeaconSignerMode",
        'long = "test-network-parliament-beacon-signer-mode"',
        "hide = true",
        "TestNetworkParliamentBeaconSignerMode::Absent => None",
        "with_deliberately_invalid_outbound()",
    ):
        require(marker in daemon, f"feature-only daemon signer wiring lost `{marker}`")
    require(
        '#[cfg(feature = "test-network-parliament-signers")]\n#[doc(hidden)]\npub mod parliament_test_network_signer;' in beacon,
        "test beacon providers must remain outside the shipping feature graph",
    )
    admission = compact(lifecycle)
    ordered = (
        ".attest_partial_signing_capability(active.aggregator.session(),index)",
        ".sign_partial(active.aggregator.session(),active.aggregator.payload())",
        "letencoded=control::encode_partial(&partial)?;",
        ".accept_partial(partial)",
        "active.own=Some(encoded);",
    )
    for marker in ordered:
        require(marker in admission, f"native beacon custody lost `{marker}`")
    positions = [admission.index(marker) for marker in ordered]
    require(positions == sorted(positions), "native own-share custody must precede retention")
    for marker in (
        "self.ensure_source(state,&message.context,applied)?;",
        "ifsender.as_bytes()!=active.roster[index].as_slice(){",
        "letinserted=active.aggregator.accept_partial(partial)?;",
    ):
        require(marker in admission, f"native peer-share admission lost `{marker}`")
    require(
        "test_network_emit_invalid_outbound_partial_v1" not in lifecycle
        and "signature_share[0] ^= 1" not in lifecycle,
        "protocol code must not inject test faults",
    )
    for marker in (
        "fn wrong_source_sender_and_proof_never_change_the_owned_round()",
        "fn native_invalid_local_share_is_never_retained_or_counted()",
        "partial.signature_share[0] ^= 1;",
        ".accept(&source, applied, &fixture.keys[1], &bad)",
    ):
        require(marker in producer_tests, f"native invalid-share unit coverage lost `{marker}`")


class SoraParliamentLifecycleCorridorSourceTests(unittest.TestCase):
    """Mutation-resistant source checks for the dedicated network corridor."""

    def test_semantic_mutations_require_and_isolate_the_actual_owner(self) -> None:
        source = "fn other() {\n    check(value);\n}\nfn actual() {\n    check(\n        value\n    );\n}\n"
        mutated = mutate_marker(source, "check(value);", owner="actual")
        self.assertIn("fn other() {\n    check(value);\n}", mutated)
        self.assertNotIn("check", mutated.split("fn actual()", 1)[1])
        for marker, owner in (("absent(value);", "actual"), ("check(value);", "missing")):
            with self.subTest(marker=marker, owner=owner), self.assertRaises(ContractError):
                mutate_marker(source, marker, owner=owner)

    def test_native_share_admission_rejects_removed_custody_and_fault_controls(self) -> None:
        sources = (
            TEST_NETWORK.read_text(encoding="utf-8"),
            DAEMON.read_text(encoding="utf-8"),
            BEACON.read_text(encoding="utf-8"),
            BEACON_LIFECYCLE.read_text(encoding="utf-8"),
            BEACON_PRODUCER_TESTS.read_text(encoding="utf-8"),
        )
        validate_native_beacon_admission_and_fixture_isolation(*sources)
        for marker in (
            ".attest_partial_signing_capability(active.aggregator.session(), index)",
            ".sign_partial(active.aggregator.session(), active.aggregator.payload())",
            "let encoded = control::encode_partial(&partial)?;",
            "active.own = Some(encoded);",
            "if sender.as_bytes() != active.roster[index].as_slice() {",
            "let inserted = active.aggregator.accept_partial(partial)?;",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_native_beacon_admission_and_fixture_isolation(
                    *sources[:3], mutate_marker(sources[3], marker), sources[4]
                )
        with self.assertRaises(ContractError):
            validate_native_beacon_admission_and_fixture_isolation(
                *sources[:3], sources[3] + "\npartial.signature_share[0] ^= 1;\n", sources[4]
            )
        for marker in (
            "fn wrong_source_sender_and_proof_never_change_the_owned_round()",
            "fn native_invalid_local_share_is_never_retained_or_counted()",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_native_beacon_admission_and_fixture_isolation(
                    *sources[:4], sources[4].replace(marker, "", 1)
                )

    def test_runner_and_workflow_are_exact_and_no_skip(self) -> None:
        validate_runner(RUNNER.read_text(encoding="utf-8"))
        validate_workflow(WORKFLOW.read_text(encoding="utf-8"))

    def test_runner_contract_rejects_each_removed_security_marker(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for marker in (
            "cargo build --locked",
            "--features test-network-parliament-signers",
            "TEST_NETWORK_BIN_IROHAD_PARLIAMENT_SIGNERS",
            "IROHA_TEST_SKIP_BUILD=1",
            "IROHA_TEST_REQUIRE_NETWORK=1",
            "IROHA_FAIL_ON_SANDBOX_SKIP=1",
            "cargo test --locked",
            "--features parliament-test-signers",
            "--test sora_parliament_lifecycle_smoke",
            "--test-threads=1",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_runner(source.replace(marker, "", 1))

    def test_workflow_contract_rejects_each_removed_crypto_evidence_marker(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        for marker in PARLIAMENT_CRYPTO_WORKFLOW_MARKERS:
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_workflow(mutate_parliament_workflow(source, marker))

    def test_target_and_boundary_guards_remain_feature_isolated(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        target = re.search(
            r'(?ms)^\[\[test\]\]\nname = "sora_parliament_lifecycle_smoke"\n'
            r'path = "tests/sora_parliament_lifecycle_smoke.rs"\n'
            r'required-features = \["parliament-test-signers"\]$',
            manifest,
        )
        require(target is not None, "Parliament test target lost its opt-in feature")

        corridor = read_corridor_source()
        require(
            '#[path = "sora_parliament_no_result_paths.rs"]\nmod no_result_paths;'
            in corridor,
            "Parliament lifecycle target lost its NoResult support module",
        )
        require(
            '#[path = "sora_parliament_failure_paths.rs"]\nmod failure_paths;'
            in corridor,
            "Parliament lifecycle target lost its failure-path module",
        )
        helper_calls = corridor.count("assert_transition_rejected_without_state_change(")
        require(
            helper_calls == 3,
            "corridor must retain the helper plus two boundary/replay checks",
        )
        for retired in (
            "CastPlainBallot",
            "FinalizeReferendum",
            "EnactReferendum",
            "ConstructCertificate",
            "MarkEnacted",
        ):
            require(retired not in corridor, f"corridor regained retired `{retired}`")
        validate_required_bounded_soranet_pow(corridor)
        validate_consensus_sized_test_stacks(corridor)
        validate_native_sortition_helpers(corridor)
        validate_public_finding_no_result_retries_and_restore(corridor)
        validate_exact_absence_classification(corridor)
        validate_parliament_failure_paths(corridor)
        validate_capacity_failure_genesis(corridor)
        validate_beacon_mode_profiles(corridor)
        validate_mandatory_npos_boundary(corridor)
        validate_beacon_rotation_fixture(
            BEACON_TEST_SIGNER.read_text(encoding="utf-8")
        )
        validate_fail_closed_npos_boundary(corridor)
        validate_native_beacon_admission_and_fixture_isolation(
            TEST_NETWORK.read_text(encoding="utf-8"),
            DAEMON.read_text(encoding="utf-8"),
            BEACON.read_text(encoding="utf-8"),
            BEACON_LIFECYCLE.read_text(encoding="utf-8"),
            BEACON_PRODUCER_TESTS.read_text(encoding="utf-8"),
        )

    def test_required_bounded_soranet_pow_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        mutations = {
            "shared builder PoW override introduced": mutate_marker(
                corridor,
                ".with_config_layer(|layer| {",
                '''.with_config_layer(|layer| {
            layer.write(
                ["network", "soranet_handshake", "pow", "required"],
                false,
            );''',
                owner="builder_with_signer_modes",
            ),
            "shared builder memory cost raised": mutate_marker(
                corridor,
                "i64::from(iroha_crypto::soranet::puzzle::MIN_MEMORY_KIB)",
                "64_i64 * 1024",
                owner="builder_with_signer_modes",
            ),
            "mandatory NPoS time cost raised": mutate_mandatory_npos_test(
                corridor, '"time_cost"', '"time_cost_mutated"'
            ),
            "fail-closed NPoS lanes raised": mutate_fail_closed_npos_test(
                corridor, '"lanes"', '"lanes_mutated"'
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_required_bounded_soranet_pow(mutated)

    def test_consensus_sized_test_stacks_reject_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        mutations = {
            "mandatory caller stack removed": mutate_mandatory_npos_test(
                corridor, ".stack_size(PARLIAMENT_NETWORK_STACK_BYTES)"
            ),
            "mandatory worker stack removed": mutate_mandatory_npos_test(
                corridor, ".thread_stack_size(PARLIAMENT_NETWORK_STACK_BYTES)"
            ),
            "fail-closed wrapper disconnected": mutate_fail_closed_npos_test(
                corridor,
                f"{FAIL_CLOSED_NPOS_TEST_NAME}_impl()",
                f"{FAIL_CLOSED_NPOS_TEST_NAME}_disabled()",
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_consensus_sized_test_stacks(mutated)

    def test_native_sortition_helpers_reject_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        validate_native_sortition_helpers(corridor)
        mutations = {
            "retired mid-epoch slot": corridor + "\n    let slot = request_height + 4;\n",
            "sortition pulse transaction race": corridor
            + '\n    tick(&client, "finalize the demanded sortition pulse")?;\n',
            "restored Parliament-demanded pulse wait": corridor.replace(
                "advance_to_autonomous_predecessor(network, client, slot, label).await?;",
                "advance_to_autonomous_predecessor(network, client, slot, label).await?;\n"
                "    network.ensure_blocks(sortition_pulse_height).await?;",
                1,
            ),
        }
        for name, markers in SORTITION_SLOT_HELPER_MARKERS.items():
            for marker in markers:
                mutations[f"{name} lost {marker}"] = mutate_marker(
                    corridor, marker, "", owner=name
                )
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_native_sortition_helpers(mutated)

    def test_governance_isolation_corridor_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        validate_governance_isolation_corridor(corridor)
        mutations = {
            "ignored test": mutate_governance_isolation_test(
                corridor,
                PARLIAMENT_NETWORK_TEST_ATTRIBUTE,
                f"#[ignore]\n{PARLIAMENT_NETWORK_TEST_ATTRIBUTE}",
            ),
            "wrapper disconnected": mutate_governance_isolation_test(
                corridor,
                f"{GOVERNANCE_ISOLATION_TEST_NAME}_impl(),",
                "std::future::ready(Ok(())),",
            ),
            "short epoch": mutate_governance_isolation_test(
                corridor,
                "let builder = enactment::builder_with_signer_modes(",
                "let builder = with_signed_npos_epoch(other(",
            ),
            "positive custody": mutate_governance_isolation_test(
                corridor,
                "FAIL_CLOSED_BEACON_SIGNER_MODES,\n    )",
                "POSITIVE_BEACON_SIGNER_MODES,\n    )",
            ),
            "guarded horizon": mutate_governance_isolation_test(
                corridor,
                "assert_ne!(horizon.next_required_pulse_height, Some(retired_slot));",
                "if let Some(horizon) = status.beacon_horizon {\n"
                "    assert_ne!(horizon.next_required_pulse_height, Some(retired_slot));\n"
                "}",
            ),
            "fewer carriers": corridor.replace(
                "ISOLATION_CARRIERS_PAST_RETIRED_SLOT: u64 = 12;",
                "ISOLATION_CARRIERS_PAST_RETIRED_SLOT: u64 = 1;",
                1,
            ),
        }
        for marker in GOVERNANCE_ISOLATION_MARKERS:
            mutations[f"lost {marker}"] = mutate_governance_isolation_test(corridor, marker)
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_governance_isolation_corridor(mutated)

    def test_sortition_corridors_are_executable_and_never_ignored(self) -> None:
        corridor = read_corridor_source()
        validate_sortition_corridors_execute(corridor)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertNotIn("--ignored", runner)
        self.assertNotIn("--include-ignored", runner)
        mutations = {}
        for name in SORTITION_ONLY_CORRIDOR_TEST_NAMES:
            mutations[f"{name} bare ignore"] = corridor.replace(
                f"#[test]\nfn {name}()", f"#[test]\n#[ignore]\nfn {name}()", 1
            )
            mutations[f"{name} renamed"] = corridor.replace(
                f"#[test]\nfn {name}()", f"#[test]\nfn {name}_disabled()", 1
            )
        for label, mutated in mutations.items():
            self.assertNotEqual(mutated, corridor, f"{label}: mutation did not change the source")
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_sortition_corridors_execute(mutated)

    def test_public_finding_no_result_retries_and_restore_reject_mutations(self) -> None:
        corridor = read_corridor_source()
        validate_public_finding_no_result_retries_and_restore(corridor)
        with self.assertRaises(ContractError):
            validate_public_finding_no_result_retries_and_restore(
                corridor.replace(
                    f"#[test]\nfn {NO_RESULT_TEST_NAME}()",
                    f"#[test]\n#[ignore]\nfn {NO_RESULT_TEST_NAME}()",
                    1,
                )
            )
        for marker in (
            "expected_sortition_slot(network, client, retry_id, retry_request_height, None).await?;",
            "retry_pulse_height > sortition_pulse_height,",
            "failed_height < public_finding_deadline",
            "ParliamentNoResultKindV1::PublicFindingQuorumUnreachable",
            "public-finding quorum-unreachable effect isolation",
            "public-finding peer effect isolation",
            "attempt_sequence: 1",
            "iroha.integration.parliament.competing-public-finding.v1",
            "ParliamentNoResultKindV1::PublicFindingDeadlineExpired",
            "attempt_sequence: 2",
            "peer_retry.state_payload_hex",
            "restored_second_retry.state_payload_hex",
            NO_RESULT_RESTART_CONTRACT_ABSENCE,
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_public_finding_no_result_retries_and_restore(
                    corridor.replace(marker, "", 1)
                )

    def test_exact_absence_classification_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        validate_exact_absence_classification(corridor)
        for marker in EXACT_ABSENCE_CLASSIFICATION_MARKERS:
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                owner = {
                    "match read_on_dedicated_thread({": "assert_asset_not_found",
                    "NonZeroU64::new(height)": "exact_block",
                }.get(marker)
                validate_exact_absence_classification(
                    mutate_marker(corridor, marker, owner=owner)
                )

        broad_mutations = {
            "governed-contract lookup": corridor
            + "\nclient.get_gov_contract_json(contract_address).is_err();\n",
            "citizenship asset lookup": corridor
            + "\nclient.query_single(FindAssetById::new("
            "citizen_asset_id.clone())).is_err();\n",
            "global beacon pulse lookup": corridor
            + "\npulse_at(&client, pulse_height - 1).is_err();\n",
            "asset absence accepts a present exact match": corridor.replace(
                "Ok(asset) => Err(eyre!(",
                "Ok(asset) => Ok(eyre!(",
                1,
            ),
            "asset absence drops exact request binding": corridor.replace(
                "let query = FindAssetById::new(asset_id.clone());",
                "let query = FindAssetById::new(other_asset_id.clone());",
                1,
            ),
            "asset absence bypasses bound query": corridor.replace(
                "move || Ok(client.query_single(query))",
                "move || Ok(client.query_single(other_query))",
                1,
            ),
            "asset absence accepts status-only not-found": corridor.replace(
                "QueryExecutionFail::Find(\n            FindError::Asset(missing),\n        )",
                "QueryExecutionFail::NotFound",
                1,
            ),
            "asset absence swallows a failed query": corridor.replace(
                'Err(error) => Err(eyre!(\n            "{label}: expected typed absence',
                'Err(error) => Ok(()),\n            "{label}: expected typed absence',
                1,
            ),
            "asset absence accepts a wrong identifier": corridor.replace(
                "if missing.as_ref() == asset_id => Ok(())",
                "if missing.as_ref() != asset_id => Ok(())",
                1,
            ),
            "block lookup drops exact height check": corridor.replace(
                "if block.header().height() != requested_height {",
                "if false {",
                1,
            ),
            "block lookup drops proof header binding": corridor.replace(
                "if block.header() != proof.block_header {",
                "if false {",
                1,
            ),
            "unbounded block inventory query": corridor.replace(
                ".get_sumeragi_finality_proof(requested_height, root_scope)",
                ".query(FindBlocks)\n        .execute_all()",
                1,
            ),
            "inactive route still expects HTTP 404": corridor.replace(
                "response.status() != iroha::http::StatusCode::OK",
                "response.status() != iroha::http::StatusCode::NOT_FOUND",
                1,
            ),
            "inactive found=true projection": corridor.replace(
                "Some(false)", "Some(true)", 1
            ),
            "inactive response permits extra fields": corridor.replace(
                "object.len() != 3", "object.len() < 3", 1
            ),
        }
        for label, mutated in broad_mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_exact_absence_classification(mutated)

    def test_parliament_failure_paths_reject_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        for name, markers in PARLIAMENT_FAILURE_PATH_MARKERS.items():
            with self.subTest(name=name, marker="test name"), self.assertRaises(
                ContractError
            ):
                validate_parliament_failure_paths(
                    corridor.replace(f"fn {name}()", f"fn {name}_disabled()", 1)
                )
            for marker in markers:
                with self.subTest(name=name, marker=marker), self.assertRaises(
                    ContractError
                ):
                    validate_parliament_failure_paths(
                        mutate_parliament_failure_path_test(corridor, name, marker)
                    )

    def test_capacity_failure_genesis_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        for marker in (
            CAPACITY_DOMAIN_REGISTRATION,
            CAPACITY_ASSET_REGISTRATION,
            CAPACITY_EXACT_ASSET,
            CAPACITY_ACCOUNT_REGISTRATION,
            CAPACITY_BOND_MINT,
            CAPACITY_CITIZEN_REGISTRATION,
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_capacity_failure_genesis(
                    mutate_capacity_failure_builder(corridor, marker)
                )

        reordered = mutate_capacity_failure_builder(
            corridor, CAPACITY_DOMAIN_REGISTRATION, "__CAPACITY_DOMAIN_REGISTRATION__"
        )
        reordered = mutate_capacity_failure_builder(
            reordered, CAPACITY_ASSET_REGISTRATION, CAPACITY_DOMAIN_REGISTRATION
        )
        reordered = mutate_capacity_failure_builder(
            reordered, "__CAPACITY_DOMAIN_REGISTRATION__", CAPACITY_ASSET_REGISTRATION
        )
        with self.subTest(marker="domain/asset order"), self.assertRaises(ContractError):
            validate_capacity_failure_genesis(reordered)

    def test_beacon_rotation_fixture_rejects_adversarial_mutations(self) -> None:
        source = BEACON_TEST_SIGNER.read_text(encoding="utf-8")
        for marker in (
            "TEST_SUCCESSOR_SESSION_ID_DOMAIN_V1",
            "deterministic_fixture_v1(network_id, ordered_roster, true, budget)",
            "deterministic_fixture_v1(self.network_id, &self.ordered_roster, true, &self.budget)",
            "exact_seat_signer_supports_one_domain_separated_successor_session",
        ):
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_beacon_rotation_fixture(source.replace(marker, "", 1))

    def test_mandatory_npos_boundary_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        mutations = {
            "renamed test": mutate_mandatory_npos_test(
                corridor, MANDATORY_NPOS_TEST_NAME, f"{MANDATORY_NPOS_TEST_NAME}_disabled"
            ),
            "ignored test": mutate_mandatory_npos_test(
                corridor,
                PARLIAMENT_NETWORK_TEST_ATTRIBUTE,
                f"#[ignore]\n{PARLIAMENT_NETWORK_TEST_ATTRIBUTE}",
            ),
            "permissioned consensus": mutate_mandatory_npos_test(
                corridor, ".with_npos_consensus()", ".with_permissioned_consensus()"
            ),
            "one peer": mutate_mandatory_npos_test(
                corridor, ".with_peers(VALIDATOR_COUNT)", ".with_peers(1)"
            ),
            "one-peer validator constant": corridor.replace(
                "const VALIDATOR_COUNT: usize = 4;",
                "const VALIDATOR_COUNT: usize = 1;",
                1,
            ),
            "missing epoch constant": corridor.replace(
                "const MANDATORY_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 8;", "", 1
            ),
            "non-autonomous pulse": mutate_mandatory_npos_test(
                corridor,
                "network.ensure_blocks(pulse_height).await?;",
                'tick(&client, "commit mandatory pre-boundary pulse")?;',
            ),
            "missing autonomous-height equality": mutate_mandatory_npos_test(
                corridor, AUTONOMOUS_PULSE_PROGRESSION
            ),
            "missing boundary progression": mutate_mandatory_npos_test(
                corridor, BOUNDARY_PROGRESSION
            ),
            "missing successor progression": mutate_mandatory_npos_test(
                corridor, SUCCESSOR_PROGRESSION
            ),
            "seed read without equality": mutate_mandatory_npos_test(
                corridor,
                SUCCESSOR_SEED_EQUALITY,
                "let _ = (context.leader_seed, successor_seed);",
            ),
            "missing pulse verifier": mutate_mandatory_npos_test(
                corridor, "verify_finalized_global_threshold_beacon_pulse_v1("
            ),
            "missing committee assertion": mutate_mandatory_npos_test(
                corridor, "assert_eq!(beacon_record.session.committee_size, 4);"
            ),
            "missing threshold assertion": mutate_mandatory_npos_test(
                corridor, "assert_eq!(beacon_record.session.threshold, 2);"
            ),
            "retained transcript binding omitted": mutate_mandatory_npos_test(
                corridor, "transcript_hash: expected_transcript,"
            ),
            "genesis identity check omitted": mutate_mandatory_npos_test(
                corridor, "finality::visit_certified_prefix("
            ),
            "successor pulse not bound to retained session": mutate_mandatory_npos_test(
                corridor,
                "assert_eq!(successor_pulse.session_id, beacon_record.session.session_id);",
                "assert_ne!(successor_pulse.session_id, beacon_record.session.session_id);",
            ),
            "retained pulse not independently verified": mutate_mandatory_npos_test(
                corridor, "&validated_beacon_session,"
            ),
            "second epoch seed equality omitted": mutate_mandatory_npos_test(
                corridor,
                "assert_eq!(context.leader_seed, second_successor_seed);",
                "let _ = (context.leader_seed, second_successor_seed);",
            ),
            "successor fail-stop status omitted": mutate_mandatory_npos_test(
                corridor, "!status.is_halted()", "true"
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_mandatory_npos_boundary(mutated)

    def test_retained_authority_rejects_each_missing_authenticated_marker(self) -> None:
        corridor = read_corridor_source()
        validate_mandatory_npos_boundary(corridor)
        for marker in RETAINED_AUTHORITY_MARKERS:
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                validate_mandatory_npos_boundary(
                    mutate_mandatory_npos_test(corridor, marker)
                )

    def test_native_finality_rejects_missing_or_disconnected_authentication(self) -> None:
        """Genesis, source, committee, votes and deadline checks must precede the callback."""
        corridor = read_corridor_source()
        validate_mandatory_npos_boundary(corridor)
        for marker in NATIVE_FINALITY_MARKERS:
            with self.subTest(marker=marker), self.assertRaises(ContractError):
                changed = mutate_marker(corridor, marker, owner="visit_certified_prefix")
                validate_mandatory_npos_boundary(changed + "\n/* " + marker + " */\n")
        with self.subTest(marker="disconnected module"), self.assertRaises(ContractError):
            validate_mandatory_npos_boundary(corridor.replace(
                '#[path = "sora_parliament_finality.rs"]\npub mod finality;', "", 1,
            ))

    def test_native_finality_rejects_genesis_only_prefix_and_missing_rejections(self) -> None:
        """A present predicate without its refusal cannot establish authentication."""
        corridor = read_corridor_source()
        validate_mandatory_npos_boundary(corridor)
        for argument in ("&network", "&client", "second_boundary_height + 1"):
            marker = RETAINED_AUTHORITY_MARKERS[0]
            replacement = marker.replace(argument, "1" if argument.endswith(" + 1") else "&other")
            with self.subTest(argument=argument), self.assertRaises(ContractError):
                validate_mandatory_npos_boundary(
                    mutate_mandatory_npos_test(corridor, marker, replacement)
                )
        for marker in NATIVE_FINALITY_MARKERS:
            if "{returnErr(" not in marker:
                continue
            condition, rejection = marker.split("{", 1)
            for replacement in (condition + "{}", condition + "{let_=" + rejection[6:]):
                with self.subTest(marker=marker, replacement=replacement), self.assertRaises(ContractError):
                    validate_mandatory_npos_boundary(
                        mutate_marker(corridor, marker, replacement, owner="visit_certified_prefix")
                    )

    def test_beacon_mode_profiles_reject_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        mutations = {
            "positive invalid becomes valid": corridor.replace(
                "const POSITIVE_BEACON_SIGNER_MODES",
                "const MUTATED_POSITIVE_BEACON_SIGNER_MODES",
                1,
            ),
            "fail-closed second absent becomes valid": corridor.replace(
                "const FAIL_CLOSED_BEACON_SIGNER_MODES",
                "const MUTATED_FAIL_CLOSED_BEACON_SIGNER_MODES",
                1,
            ),
            "shared builder returns to all-valid shorthand": mutate_marker(
                corridor,
                ".with_parliament_beacon_signer_modes(signer_modes)",
                ".with_parliament_test_signers()",
                owner="builder_with_signer_modes",
            ),
            "shared builder loses the positive profile": mutate_marker(
                corridor,
                "builder_with_signer_modes(builder, POSITIVE_BEACON_SIGNER_MODES),",
                "builder_with_signer_modes(builder, FAIL_CLOSED_BEACON_SIGNER_MODES),",
                owner="builder",
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_beacon_mode_profiles(mutated)

    def test_fail_closed_npos_boundary_rejects_adversarial_mutations(self) -> None:
        corridor = read_corridor_source()
        mutations = {
            "renamed test": mutate_fail_closed_npos_test(
                corridor,
                FAIL_CLOSED_NPOS_TEST_NAME,
                f"{FAIL_CLOSED_NPOS_TEST_NAME}_disabled",
            ),
            "ignored test": mutate_fail_closed_npos_test(
                corridor,
                PARLIAMENT_NETWORK_TEST_ATTRIBUTE,
                f"#[ignore]\n{PARLIAMENT_NETWORK_TEST_ATTRIBUTE}",
            ),
            "permissioned consensus": mutate_fail_closed_npos_test(
                corridor,
                ".with_npos_consensus()",
                ".with_permissioned_consensus()",
            ),
            "one peer": mutate_fail_closed_npos_test(
                corridor,
                ".with_peers(VALIDATOR_COUNT)",
                ".with_peers(1)",
            ),
            "all-valid shorthand": mutate_fail_closed_npos_test(
                corridor,
                ".with_parliament_beacon_signer_modes(FAIL_CLOSED_BEACON_SIGNER_MODES)",
                ".with_parliament_test_signers()",
            ),
            "threshold weakened": mutate_fail_closed_npos_test(
                corridor,
                "assert_eq!(beacon_record.session.threshold, 2);",
                "assert_eq!(beacon_record.session.threshold, 1);",
            ),
            "unbounded block wait": mutate_fail_closed_npos_test(
                corridor,
                "let unexpected_pulse_height = tokio::time::timeout(",
                "let unexpected_pulse_height = passthrough(",
            ),
            "per-request context rebuild disconnected": mutate_fail_closed_npos_test(
                corridor,
                "integration_tests::sync::rebind_blocking_client(&peer.client(), |builder| {",
                "disconnected_context(&peer.client(), |builder| {",
            ),
            "per-request timeout disabled": mutate_fail_closed_npos_test(
                corridor,
                "builder.torii_request_timeout = status_poll_request_timeout;",
                "builder.torii_request_timeout = Duration::ZERO;",
            ),
            "pulse activation deadline omitted": mutate_fail_closed_npos_test(
                corridor,
                "if Instant::now() >= activation_deadline {",
                "if false {",
            ),
            "post-observation deadline omitted": mutate_fail_closed_npos_test(
                corridor,
                "if Instant::now() >= post_observation_deadline {",
                "if false {",
            ),
            "applied predecessor handoff weakened": mutate_fail_closed_npos_test(
                corridor,
                "assert!(status.awaiting);",
                "assert!(!status.awaiting);",
            ),
            "pre-application predecessor accepted as active": mutate_fail_closed_npos_test(
                corridor,
                "return false;",
                "return true;",
            ),
            "activation height-fetch retry omitted": mutate_fail_closed_npos_test(
                corridor,
                '''Err(error) => {
                    last_activation_status_error =
                        Some(format!("peer {peer_index} height: {error}"));
                    all_pulse_heights_active = false;
                    continue;
                }''',
                "Err(error) => return Err(error.into()),",
            ),
            "activation Sumeragi-status retry omitted": mutate_fail_closed_npos_test(
                corridor,
                '''Err(error) => {
                    last_activation_status_error =
                        Some(format!("peer {peer_index} sumeragi status: {error}"));
                    all_pulse_heights_active = false;
                    continue;
                }''',
                "Err(error) => return Err(error.into()),",
            ),
            "post-observation height-fetch retry omitted": mutate_fail_closed_npos_test(
                corridor,
                '''Err(error) => {
                    last_post_observation_status_error =
                        Some(format!("peer {peer_index} height: {error}"));
                    all_post_observation_statuses_verified = false;
                    continue;
                }''',
                "Err(error) => return Err(error.into()),",
            ),
            "post-observation Sumeragi-status retry omitted": mutate_fail_closed_npos_test(
                corridor,
                '''Err(error) => {
                    last_post_observation_status_error =
                        Some(format!("peer {peer_index} sumeragi status: {error}"));
                    all_post_observation_statuses_verified = false;
                    continue;
                }''',
                "Err(error) => return Err(error.into()),",
            ),
            "validator liveness omitted": mutate_fail_closed_npos_test(
                corridor,
                "peer.is_running()",
                "true",
            ),
            "validator fail-stop status omitted": mutate_fail_closed_npos_test(
                corridor,
                "!status.is_halted()",
                "true",
            ),
            "stalled height omitted": mutate_fail_closed_npos_test(
                corridor,
                "assert_eq!(status.committed_height, predecessor_height);",
            ),
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_fail_closed_npos_boundary(mutated)


if __name__ == "__main__":
    unittest.main()
