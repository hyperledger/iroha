//! Genesis manifest ownership, preparation, framing, and refusal controls.

use super::*;
use iroha_crypto::Algorithm;
use iroha_data_model::{
    block::consensus::ConsensusGenesisParams, isi::SetParameter, parameter::system::BlockParameter,
};
use iroha_version::codec::DecodeVersioned;
use std::{convert::TryInto, num::NonZeroU64, path::PathBuf};
fn manifest_chain_discriminant_value() -> norito::json::Value {
    norito::json::value::to_value(&iroha_data_model::account::address::chain_discriminant())
        .expect("serialize chain discriminant")
}
fn manifest_sumeragi_context_value() -> norito::json::Value {
    norito::json::value::to_value(&SumeragiGenesisContextParameters::recommended())
        .expect("serialize Sumeragi genesis context")
}
fn deterministic_test_topology_entries() -> Vec<GenesisTopologyEntry> {
    let mut entries = (0_u8..4)
        .map(|index| {
            let validator_seed = 0x20_u8.wrapping_add(index);
            let validator = KeyPair::try_from_seed(vec![validator_seed; 32], Algorithm::BlsNormal)
                .expect("derive deterministic genesis fixture validator");
            let pop = iroha_crypto::bls_normal_pop_prove(validator.private_key())
                .expect("derive deterministic genesis fixture proof of possession");
            GenesisTopologyEntry::new(PeerId::new(validator.public_key().clone()), pop)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.peer.cmp(&right.peer));
    entries
}
fn with_deterministic_test_topology(mut manifest: RawGenesisTransaction) -> RawGenesisTransaction {
    manifest
        .transactions
        .first_mut()
        .expect("test genesis manifest has one transaction")
        .topology = deterministic_test_topology_entries();
    manifest
}
fn split_fixture() -> RawGenesisTransaction {
    GenesisBuilder::new_without_executor(ChainId::from("split-genesis-fixture"), ".")
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .next_transaction()
        .append_instruction(Log::new(Level::INFO, "first original instruction".into()))
        .append_instruction(Log::new(Level::WARN, "second original instruction".into()))
        .next_transaction()
        .append_instruction(Log::new(Level::INFO, "third original instruction".into()))
        .append_instruction(Log::new(Level::WARN, "fourth original instruction".into()))
        .next_transaction()
        .set_topology(deterministic_test_topology_entries())
        .build_raw()
        .unwrap()
}
#[test]
fn instruction_only_split_preserves_exact_flat_semantics_and_structured_owners() {
    let original = split_fixture();
    let split = original
        .clone()
        .partition_instruction_only_transaction(1, &[1, 1])
        .unwrap();
    assert_eq!(split.transactions.len(), original.transactions.len() + 1);
    assert_eq!(
        norito::json::to_json(&split.transactions[0]).unwrap(),
        norito::json::to_json(&original.transactions[0]).unwrap()
    );
    assert_eq!(
        norito::json::to_json(split.transactions.last().unwrap()).unwrap(),
        norito::json::to_json(original.transactions.last().unwrap()).unwrap()
    );
    assert_eq!(
        norito::json::to_json(&split.transactions[3]).unwrap(),
        norito::json::to_json(&original.transactions[2]).unwrap(),
        "an unselected instruction batch retains its complete original boundary"
    );
    assert_eq!(
        split.instructions().collect::<Vec<_>>(),
        original.instructions().collect::<Vec<_>>()
    );
    assert_eq!(
        split.effective_parameters().unwrap(),
        original.effective_parameters().unwrap()
    );
    let mut restored_boundaries = split.clone();
    restored_boundaries.transactions = original.transactions.clone();
    assert_eq!(
        norito::json::to_json(&restored_boundaries).unwrap(),
        norito::json::to_json(&original).unwrap(),
        "every nontransaction manifest field is unchanged"
    );
    assert_eq!(
        norito::json::to_json(
            &split
                .clone()
                .partition_instruction_only_transaction(1, &[1])
                .unwrap()
        )
        .unwrap(),
        norito::json::to_json(&split).unwrap(),
        "separation is idempotent"
    );
    assert!(
        original
            .clone()
            .partition_instruction_only_transaction(original.transactions.len(), &[1])
            .unwrap_err()
            .to_string()
            .contains("out of bounds")
    );
    assert!(
        split.transactions[1..3]
            .iter()
            .all(|transaction| transaction.instructions.len() == 1)
    );
}
#[test]
fn instruction_only_split_refuses_mixed_structured_owners_and_parameter_instructions() {
    for owner in ["parameters", "topology", "ivm_triggers"] {
        for lengths in [vec![], vec![0, 2], vec![1], vec![3], vec![usize::MAX, 1]] {
            assert!(
                split_fixture()
                    .partition_instruction_only_transaction(1, &lengths)
                    .unwrap_err()
                    .to_string()
                    .contains("preserve its exact 2 instructions")
            );
        }
        let mut original = split_fixture();
        match owner {
            "parameters" => original.transactions[1].parameters = Some(Parameters::default()),
            "topology" => original.transactions[1].topology = deterministic_test_topology_entries(),
            "ivm_triggers" => {
                original.transactions[1]
                    .ivm_triggers
                    .push(GenesisIvmTrigger::new(
                    "split-control".parse().unwrap(),
                    GenesisIvmAction::new(
                        "original.to",
                        Repeats::Exactly(1),
                        iroha_test_samples::ALICE_ID.clone(),
                        iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter::new(),
                    ),
                ));
            }
            _ => unreachable!(),
        }
        let error = original
            .clone()
            .partition_instruction_only_transaction(1, &[1, 1])
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("transaction 1 is not instruction-only"),
            "{owner}: {error}"
        );
    }
    let mut original = split_fixture();
    original.transactions[1].instructions.push(
        SetParameter::new(Parameter::Block(BlockParameter::MaxTransactions(
            NonZeroU64::new(11).unwrap(),
        )))
        .into(),
    );
    assert!(
        original
            .partition_instruction_only_transaction(1, &[1, 1])
            .unwrap_err()
            .to_string()
            .contains("SetParameter")
    );
}
#[test]
fn normalization_preserves_authored_instruction_boundaries_and_refuses_overbudget_sources() {
    let manifest = split_fixture();
    let normalized = manifest
        .clone()
        .partition_instruction_only_transaction(1, &[1, 1])
        .unwrap()
        .normalize()
        .unwrap();
    let logs = normalized
        .transactions
        .iter()
        .filter_map(|batch| {
            let messages = batch
                .iter()
                .filter_map(|instruction| instruction.as_any().downcast_ref::<Log>())
                .map(|log| format!("{log:?}"))
                .collect::<Vec<_>>();
            (!messages.is_empty()).then_some(messages)
        })
        .collect::<Vec<_>>();
    assert_eq!(logs.iter().map(Vec::len).collect::<Vec<_>>(), [1, 1, 2]);
    assert_eq!(
        logs.concat(),
        manifest
            .instructions()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<Log>())
            .map(|log| format!("{log:?}"))
            .collect::<Vec<_>>()
    );
    let mut overbudget = manifest.clone();
    while overbudget.transactions.len() <= 11 {
        overbudget
            .transactions
            .push(manifest.transactions[1].clone());
    }
    let original = norito::json::to_json(&overbudget).unwrap();
    assert!(
        overbudget
            .clone()
            .normalize()
            .unwrap_err()
            .to_string()
            .contains("exceeding the FASTPQ bootstrap limit 11")
    );
    assert_eq!(norito::json::to_json(&overbudget).unwrap(), original);
}
#[test]
fn genesis_fixture_key_generation_preserves_algorithms() {
    assert_eq!(
        checked_genesis_fixture_keypair().public_key().algorithm(),
        Algorithm::default()
    );
    for algorithm in [Algorithm::Ed25519, Algorithm::BlsNormal] {
        assert_eq!(
            checked_genesis_fixture_keypair_with_algorithm(algorithm)
                .public_key()
                .algorithm(),
            algorithm
        );
    }
}
#[test]
fn genesis_signing_requires_an_exact_unique_committee_topology() {
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain: ChainId::from("iroha:test:genesis-topology"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    manifest
        .validate_genesis_topology()
        .expect("the exact canonical fixture topology is generation zero");

    let mut repeated = manifest.clone();
    repeated.transactions[0].topology[1] = repeated.transactions[0].topology[0].clone();
    let error = repeated
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect_err("a repeated validator must fail before genesis is signed");
    assert!(
        error.to_string().contains("repeats a validator identity"),
        "unexpected topology error: {error:#}"
    );

    let mut short = manifest;
    short.transactions[0].topology.pop();
    let error = short
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect_err("a non-3f+1 topology must fail before genesis is signed");
    assert!(
        error
            .to_string()
            .contains("exact Sumeragi `3f + 1` topology"),
        "unexpected topology error: {error:#}"
    );
}
#[test]
fn with_consensus_meta_adds_fields_and_stable_fingerprint() {
    let chain = ChainId::from("iroha:test:genesismeta");
    let tx = RawGenesisTransaction {
        chain: chain.clone(),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let tx2 = tx
        .clone()
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
    assert_eq!(tx2.consensus_mode, SumeragiConsensusMode::Permissioned);
    assert_eq!(tx2.wire_protocol_version, CONSENSUS_PROTOCOL_VERSION);
    let fp1 = tx2.consensus_fingerprint.clone().unwrap();
    let fp2 = tx
        .clone()
        .with_consensus_meta()
        .expect("valid fixture consensus parameters")
        .consensus_fingerprint
        .unwrap();
    assert_eq!(fp1, fp2);
    let mut differently_named = tx.clone();
    differently_named.chain = ChainId::from("same-parameters-different-display-name");
    let differently_named_fp = differently_named
        .with_consensus_meta()
        .expect("valid fixture consensus parameters")
        .consensus_fingerprint
        .expect("valid parameters fingerprint");
    assert_eq!(
        fp1, differently_named_fp,
        "genesis-embedded parameters fingerprint must not depend on chain display identity"
    );
    // Validate that the injected handshake payload parses as JSON.
    let normalized = tx.normalize().expect("normalize empty manifest");
    let mut saw_handshake = false;
    for instr in normalized
        .transactions
        .iter()
        .flat_map(|batch| batch.iter())
    {
        if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
            && let Parameter::Custom(custom) = set_param.inner()
            && custom.id() == &consensus_metadata::handshake_meta_id()
        {
            let payload = custom.payload();
            let parsed: norito::json::Value = norito::json::parse_value(payload.get())
                .expect("handshake payload JSON must parse");
            assert!(
                parsed.get("consensus_fingerprint").is_some(),
                "handshake payload missing fingerprint"
            );
            assert!(
                parsed.get("kagemusha_mint_finality").is_none(),
                "handshake payload must not carry the retired mint-finality authority"
            );
            saw_handshake = true;
        }
    }
    assert!(saw_handshake, "expected handshake parameter");
}
#[test]
fn with_consensus_meta_preserves_original_parameter_refusal_and_retry() {
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Custom(SumeragiNposParameters::default().into()));
    let manifest = RawGenesisTransaction {
        chain: ChainId::from("iroha:test:npos-read-refusal"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx {
            parameters: Some(parameters),
            ..RawGenesisTx::default()
        }],
        consensus_mode: SumeragiConsensusMode::Npos,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let before = manifest.encode();
    let expected = manifest
        .clone()
        .with_consensus_meta()
        .unwrap()
        .consensus_fingerprint;
    let original = manifest.clone();
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || original.with_consensus_meta(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<norito::json::Error>(),
            Some(norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            ))
        ),
        "{error:?}"
    );
    assert_eq!(manifest.encode(), before);
    assert_eq!(
        manifest
            .clone()
            .with_consensus_meta()
            .unwrap()
            .consensus_fingerprint,
        expected
    );
    let wrong_mode = manifest.with_consensus_mode(SumeragiConsensusMode::Permissioned);
    assert!(
        wrong_mode
            .with_consensus_meta()
            .unwrap_err()
            .to_string()
            .contains("permissioned genesis must omit `sumeragi_npos_parameters`")
    );
}

#[test]
fn with_consensus_meta_handles_npos_mode() {
    let chain = ChainId::from("iroha:test:nposmeta");
    let npos = SumeragiNposParameters::default();
    let mut params = Parameters::default();
    params.set_parameter(Parameter::Custom(npos.clone().into()));
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx {
            parameters: Some(params),
            ..RawGenesisTx::default()
        }],
        consensus_mode: SumeragiConsensusMode::Npos,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    })
    .with_consensus_meta()
    .expect("valid fixture consensus parameters");
    assert_eq!(manifest.consensus_mode, SumeragiConsensusMode::Npos);
    assert_eq!(manifest.wire_protocol_version, CONSENSUS_PROTOCOL_VERSION);
    let fp = manifest
        .consensus_fingerprint
        .expect("fingerprint must be present");
    assert!(
        fp.to_string().starts_with("0x"),
        "fingerprint must be hex-prefixed, got {fp}"
    );
    // Confirm the handshake payload parses and advertises Npos mode.
    let normalized = manifest
        .clone()
        .normalize()
        .expect("normalize staged NPoS manifest");
    let mut saw_handshake = false;
    for instr in normalized
        .transactions
        .iter()
        .flat_map(|batch| batch.iter())
    {
        if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
            && let Parameter::Custom(custom) = set_param.inner()
            && custom.id() == &consensus_metadata::handshake_meta_id()
        {
            let payload = custom.payload();
            let parsed: norito::json::Value = norito::json::parse_value(payload.get())
                .expect("handshake payload JSON must parse");
            assert_eq!(
                parsed
                    .get("mode")
                    .and_then(norito::json::Value::as_str)
                    .unwrap_or_default(),
                "Npos"
            );
            saw_handshake = true;
        }
    }
    assert!(saw_handshake, "expected handshake parameter");
}
#[test]
fn with_consensus_meta_respects_block_max_transactions_override() {
    let chain = ChainId::from("iroha:test:blockmax");
    let max_txs = NonZeroU64::new(13).expect("non-zero max transactions");
    let mut parameters = Parameters::default();
    parameters.set_parameter(Parameter::Block(BlockParameter::MaxTransactions(max_txs)));
    let tx = RawGenesisTx {
        parameters: Some(parameters),
        ..RawGenesisTx::default()
    };
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain: chain.clone(),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![tx],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    })
    .with_consensus_meta()
    .expect("valid fixture consensus parameters");
    let params = manifest
        .effective_parameters()
        .expect("single structured parameter block");
    assert_eq!(
        params.block().max_transactions().get(),
        max_txs.get(),
        "effective parameters must reflect block max override"
    );
    let expected = compute_consensus_parameters_fingerprint(&ConsensusGenesisParams {
        block_cadence_ms: params.sumeragi().block_cadence_ms(),
        block_max_transactions: params.block().max_transactions(),
        mode: ConsensusGenesisModeParams::Permissioned,
        protocol_version: iroha_config::parameters::defaults::sumeragi::PROTOCOL_VERSION,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
    })
    .expect("canonical permissioned parameters must fingerprint");
    let observed = manifest
        .consensus_fingerprint
        .expect("consensus fingerprint injected")
        .into_bytes();
    assert_eq!(observed, expected);
}
#[test]
fn build_and_sign_uses_stable_internal_creation_times() {
    init_instruction_registry();
    let chain = ChainId::from("iroha:test:deterministic");
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let genesis = manifest.build_and_sign(&keypair).expect("sign genesis");
    let bytes_a = genesis.0.encode_wire().expect("encode canonical genesis");
    let bytes_b = genesis.0.encode_wire().expect("encode canonical genesis");
    assert_eq!(bytes_a, bytes_b, "Genesis encoding must be deterministic");
    let tx_times: Vec<u64> = genesis
        .0
        .external_transactions()
        .map(|tx| {
            tx.creation_time()
                .as_millis()
                .try_into()
                .expect("creation_time fits into u64")
        })
        .collect();
    assert!(
        tx_times.windows(2).all(|window| window[0] <= window[1]),
        "transaction creation times must be non-decreasing"
    );
    if let Some(last_tx) = tx_times.last() {
        let block_time = genesis.0.header().creation_time().as_millis();
        let block_time = u64::try_from(block_time).expect("block creation time fits into u64");
        assert_eq!(
            block_time,
            last_tx + 1,
            "block creation time must follow the last transaction deterministically"
        );
    }
}
#[test]
fn explicit_creation_time_makes_signed_genesis_reproducible() {
    init_instruction_registry();
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain: ChainId::from("iroha:test:fixed-genesis-time"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default(), RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let batch_count = u64::try_from(
        manifest
            .clone()
            .parse()
            .expect("parse fixed-time genesis manifest")
            .len(),
    )
    .expect("genesis transaction batch count fits into u64");
    assert!(
        batch_count > 0,
        "a parsed genesis manifest must contain at least one transaction batch"
    );
    let sign = |manifest: RawGenesisTransaction| {
        manifest
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &keypair,
                None,
                None,
                1_700_000_000_000,
            )
            .expect("sign genesis at fixed time")
            .0
            .encode_wire()
            .expect("encode fixed-time genesis")
    };
    assert_eq!(sign(manifest.clone()), sign(manifest.clone()));
    let last_representable_base = u64::MAX - batch_count;
    let boundary = manifest
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &keypair,
            None,
            None,
            last_representable_base,
        )
        .expect("the last representable explicit creation-time base must succeed");
    assert_eq!(
        boundary.0.header().creation_time().as_millis(),
        u128::from(u64::MAX),
        "the block timestamp must use the final representable millisecond"
    );
    let error = manifest
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &keypair,
            None,
            None,
            last_representable_base + 1,
        )
        .expect_err("overflowing explicit creation-time base must be rejected");
    assert!(
        error.to_string().contains("cannot represent"),
        "unexpected overflow error: {error:#}"
    );
}
#[test]
fn build_and_sign_checked_genesis_transaction_signatures_verify() {
    init_instruction_registry();
    let chain = ChainId::from("iroha:test:checked-genesis-sign");
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default(), RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let genesis = manifest.build_and_sign(&keypair).expect("sign genesis");
    let transactions: Vec<_> = genesis.0.external_transactions().collect();
    assert!(
        !transactions.is_empty(),
        "genesis builder should emit signed external transactions"
    );
    for transaction in transactions {
        transaction
            .verify_signature()
            .expect("checked genesis transaction signature should verify");
    }
}
#[test]
fn collect_parameter_instructions_emits_max_clock_drift_update() {
    use iroha_data_model::parameter::{Parameters, system::SumeragiParameter};
    let current = Parameters::default();
    let mut target = current.clone();
    target.set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(333)));
    let generated = collect_parameter_instructions(&target);
    assert!(
        generated.iter().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set| {
                    matches!(
                        set.inner(),
                        Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(333))
                    )
                })
        }),
        "generated instructions must contain the mutable Sumeragi update"
    );
}
#[test]
fn build_and_sign_sets_confidential_digest() {
    init_instruction_registry();
    let chain = ChainId::from("iroha:test:confdigest");
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let genesis = manifest.build_and_sign(&keypair).expect("sign genesis");
    assert_eq!(
        genesis.0.header().confidential_features(),
        Some(ConfidentialFeatureDigest::new(
            None,
            None,
            None,
            Some(RULES_VERSION),
            Some(DEFAULT_GENESIS_CONFIDENTIAL_POLICY_HASH),
        ))
    );
}
#[test]
fn build_and_sign_sets_explicit_confidential_policy_hash() {
    init_instruction_registry();
    let chain = ChainId::from("iroha:test:confpolicy");
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let policy_hash = [0x42; 32];
    let genesis = manifest
        .build_and_sign_with_confidential_policy_hash(&keypair, Some(policy_hash))
        .expect("sign genesis with policy hash");
    assert_eq!(
        genesis.0.header().confidential_features(),
        Some(ConfidentialFeatureDigest::new(
            None,
            None,
            None,
            Some(RULES_VERSION),
            Some(policy_hash),
        ))
    );
}
#[test]
fn genesis_canonical_wire_roundtrip_preserves_digest() {
    init_instruction_registry();
    let chain = ChainId::from("iroha:test:wire-digest");
    let manifest = with_deterministic_test_topology(RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    });
    let keypair = checked_genesis_fixture_keypair();
    let genesis = manifest.build_and_sign(&keypair).expect("sign genesis");
    let wire = genesis.0.canonical_wire().expect("canonical wire encoding");
    let framed = wire.as_framed().to_vec();
    let versioned = iroha_version::codec::EncodeVersioned::encode_versioned(&genesis.0);
    let decoded =
        SignedBlock::decode_all_versioned(&versioned).expect("decode versioned signed block");
    assert_eq!(
        decoded.header().confidential_features(),
        genesis.0.header().confidential_features()
    );
    // Ensure framed payload also decodes through the deframed helper for completeness.
    let deframed = iroha_data_model::block::deframe_versioned_signed_block_bytes(framed.as_slice())
        .expect("deframe canonical block");
    let decoded_framed = SignedBlock::decode_all_versioned(deframed.bare_versioned.as_ref())
        .expect("decode deframed signed block");
    assert_eq!(
        decoded_framed.header().confidential_features(),
        genesis.0.header().confidential_features()
    );
}
#[test]
fn programmatic_raw_genesis_rejects_explicit_set_parameter_instructions() {
    use iroha_data_model::{isi::InstructionBox, parameter::system::SumeragiParameter};
    let chain = ChainId::from("iroha:test:paramagg");
    let mut base = Parameters::default();
    base.set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(
        1_000,
    )));
    let override_instruction = InstructionBox::from(SetParameter::new(Parameter::Sumeragi(
        SumeragiParameter::MaxClockDriftMs(1_500),
    )));
    let tx = RawGenesisTx {
        parameters: Some(base),
        instructions: vec![override_instruction],
        ..RawGenesisTx::default()
    };
    let manifest = RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![tx],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let error = manifest
        .effective_parameters()
        .expect_err("explicit SetParameter must not override the structured snapshot");
    assert!(
        error
            .to_string()
            .contains("SetParameter instructions (tx 0, instruction 0)"),
        "unexpected error: {error:?}"
    );
    let error = manifest
        .parse()
        .expect_err("signing must reject explicit SetParameter instructions");
    assert!(
        error
            .to_string()
            .contains("SetParameter instructions (tx 0, instruction 0)"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn transaction_replacement_rejects_explicit_set_parameter_instructions() {
    use iroha_data_model::{isi::InstructionBox, parameter::system::SumeragiParameter};
    let mut manifest = RawGenesisTransaction {
        chain: ChainId::from("iroha:test:paramagg-replacement"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let set_parameter = InstructionBox::from(SetParameter::new(Parameter::Sumeragi(
        SumeragiParameter::MaxClockDriftMs(333),
    )));
    let error = manifest
        .replace_instruction_only_transaction(0, vec![vec![set_parameter]])
        .expect_err("transaction replacement must not inject SetParameter");
    assert!(
        error
            .to_string()
            .contains("replacement batch 0, instruction 0 contains SetParameter"),
        "unexpected error: {error:?}"
    );
}

#[test]
#[should_panic(
    expected = "GenesisBuilder::append_instruction does not accept SetParameter; use GenesisBuilder::append_parameter"
)]
fn genesis_builder_rejects_set_parameter_as_generic_instruction() {
    use iroha_data_model::parameter::system::SumeragiParameter;
    let _ = GenesisBuilder::new_without_executor(ChainId::from("iroha:test:paramagg-builder"), ".")
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .append_instruction(SetParameter::new(Parameter::Sumeragi(
            SumeragiParameter::MaxClockDriftMs(333),
        )));
}
#[test]
fn multiple_structured_parameter_blocks_are_rejected_as_ambiguous_snapshots() {
    init_instruction_registry();
    use iroha_data_model::parameter::{Parameters, system::SumeragiParameter};
    let chain = ChainId::from("iroha:test:paramparse-order");
    let mut base = Parameters::default();
    base.set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(100)));
    let mut updated = base.clone();
    updated.set_parameter(Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(333)));
    let manifest = RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![
            RawGenesisTx {
                parameters: Some(base),
                ..RawGenesisTx::default()
            },
            RawGenesisTx::default(),
            RawGenesisTx {
                parameters: Some(updated),
                ..RawGenesisTx::default()
            },
        ],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let error = manifest
        .effective_parameters()
        .expect_err("multiple complete parameter snapshots must be rejected");
    assert!(
        error
            .to_string()
            .contains("multiple structured `parameters` blocks")
    );
    let error = manifest
        .clone()
        .parse()
        .expect_err("signing parse must reject ambiguous parameter snapshots");
    assert!(
        error
            .to_string()
            .contains("multiple structured `parameters` blocks")
    );
    let value = norito::json::to_value(&manifest).expect("serialize adversarial manifest");
    let error = RawGenesisTransaction::from_json_value(value)
        .expect_err("JSON admission must reject ambiguous parameter snapshots");
    assert!(
        error
            .to_string()
            .contains("multiple structured `parameters` blocks")
    );
}
#[test]
#[ignore = "debug helper for inspecting parsed genesis instruction order"]
fn debug_dump_set_parameter_order_for_manifest_path() -> Result<()> {
    use std::env;
    init_instruction_registry();
    let path = env::var("IROHA_DEBUG_GENESIS_PATH")
        .wrap_err("IROHA_DEBUG_GENESIS_PATH must point to a genesis manifest JSON")?;
    let manifest = RawGenesisTransaction::from_path(&path)?;
    let batches = manifest.parse()?;
    eprintln!("manifest={path}");
    for (batch_idx, batch) in batches.iter().enumerate() {
        eprintln!("BATCH {batch_idx}");
        for (instr_idx, instruction) in batch.iter().enumerate() {
            let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            eprintln!("  {instr_idx}: {:?}", set_parameter.inner());
        }
    }
    Ok(())
}
#[test]
#[ignore = "debug helper for inspecting signed genesis instruction order"]
fn debug_dump_set_parameter_order_for_signed_genesis_path() -> Result<()> {
    use iroha_data_model::{block::decode_framed_signed_block, transaction::Executable};
    use std::{env, fs};
    init_instruction_registry();
    let path = env::var("IROHA_DEBUG_SIGNED_GENESIS_PATH")
        .wrap_err("IROHA_DEBUG_SIGNED_GENESIS_PATH must point to a signed genesis .nrt")?;
    let bytes = fs::read(&path).wrap_err_with(|| format!("read signed genesis {path}"))?;
    let block = decode_framed_signed_block(&bytes)
        .wrap_err_with(|| format!("decode signed genesis {path}"))?;
    eprintln!("signed_genesis={path}");
    for (batch_idx, tx) in block.external_transactions().enumerate() {
        let Executable::Instructions(batch) = tx.instructions() else {
            eprintln!("BATCH {batch_idx} <non-instruction-executable>");
            continue;
        };
        eprintln!("BATCH {batch_idx}");
        for (instr_idx, instruction) in batch.iter().enumerate() {
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() {
                eprintln!("  {instr_idx}: {:?}", set_parameter.inner());
            }
        }
    }
    Ok(())
}
#[test]
#[ignore = "debug helper for inspecting build_and_sign instruction order before encoding"]
fn debug_dump_set_parameter_order_for_built_manifest_path() -> Result<()> {
    use iroha_data_model::transaction::Executable;
    use std::env;
    init_instruction_registry();
    let path = env::var("IROHA_DEBUG_GENESIS_PATH")
        .wrap_err("IROHA_DEBUG_GENESIS_PATH must point to a genesis manifest JSON")?;
    let manifest = RawGenesisTransaction::from_path(&path)?;
    let block = manifest.build_and_sign(&checked_genesis_fixture_keypair())?;
    eprintln!("built_manifest={path}");
    for (batch_idx, tx) in block.0.external_transactions().enumerate() {
        let Executable::Instructions(batch) = tx.instructions() else {
            eprintln!("BATCH {batch_idx} <non-instruction-executable>");
            continue;
        };
        eprintln!("BATCH {batch_idx}");
        for (instr_idx, instruction) in batch.iter().enumerate() {
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() {
                eprintln!("  {instr_idx}: {:?}", set_parameter.inner());
            }
        }
    }
    Ok(())
}
#[test]
#[ignore = "debug helper for inspecting build_and_sign instruction order after encode_wire roundtrip"]
fn debug_dump_set_parameter_order_for_encoded_manifest_path() -> Result<()> {
    use iroha_data_model::{block::decode_framed_signed_block, transaction::Executable};
    use std::env;
    init_instruction_registry();
    let path = env::var("IROHA_DEBUG_GENESIS_PATH")
        .wrap_err("IROHA_DEBUG_GENESIS_PATH must point to a genesis manifest JSON")?;
    let manifest = RawGenesisTransaction::from_path(&path)?;
    let block = manifest.build_and_sign(&checked_genesis_fixture_keypair())?;
    let encoded = block.0.encode_wire()?;
    let decoded = decode_framed_signed_block(&encoded)?;
    eprintln!("encoded_manifest={path}");
    for (batch_idx, tx) in decoded.external_transactions().enumerate() {
        let Executable::Instructions(batch) = tx.instructions() else {
            eprintln!("BATCH {batch_idx} <non-instruction-executable>");
            continue;
        };
        eprintln!("BATCH {batch_idx}");
        for (instr_idx, instruction) in batch.iter().enumerate() {
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() {
                eprintln!("  {instr_idx}: {:?}", set_parameter.inner());
            }
        }
    }
    Ok(())
}
#[test]
fn set_parameter_inside_instructions_is_rejected() {
    init_instruction_registry();
    use iroha_data_model::parameter::system::SumeragiParameter;
    let set_param = InstructionBox::from(SetParameter::new(Parameter::Sumeragi(
        SumeragiParameter::MaxClockDriftMs(1_000),
    )));
    let instructions = genesis_instructions_json::instructions_to_value(&[set_param]);
    let mut tx_map = norito::json::Map::new();
    tx_map.insert("instructions".to_string(), instructions);
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert(
        "chain_discriminant".to_string(),
        manifest_chain_discriminant_value(),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".into()),
    );
    manifest_fields.insert(
        "sumeragi_context".to_string(),
        manifest_sumeragi_context_value(),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(tx_map)]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let err = RawGenesisTransaction::from_json_value(manifest)
        .expect_err("SetParameter inside instructions should be rejected");
    assert!(
        err.to_string().contains("SetParameter"),
        "unexpected error message: {err}"
    );
}
#[test]
fn raw_genesis_requires_consensus_mode() {
    init_instruction_registry();
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert(
        "chain_discriminant".to_string(),
        manifest_chain_discriminant_value(),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(norito::json::Map::new())]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let err = RawGenesisTransaction::from_json_value(manifest)
        .expect_err("missing consensus_mode should be rejected");
    assert!(
        err.to_string().contains("consensus_mode"),
        "unexpected error: {err}"
    );
}
#[test]
fn raw_genesis_requires_chain_discriminant() {
    init_instruction_registry();
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".into()),
    );
    manifest_fields.insert(
        "sumeragi_context".to_string(),
        manifest_sumeragi_context_value(),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(norito::json::Map::new())]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let err = RawGenesisTransaction::from_json_value(manifest)
        .expect_err("missing chain_discriminant should be rejected");
    assert!(
        err.to_string().contains("chain_discriminant"),
        "unexpected error: {err}"
    );
}
#[test]
fn raw_genesis_roundtrip_uses_manifest_chain_discriminant_for_account_literals() -> Result<()> {
    init_instruction_registry();
    let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:testnet-prefix"),
        PathBuf::from("."),
    )
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .build_raw()
    .expect("complete test genesis builder")
    .with_consensus_mode(SumeragiConsensusMode::Permissioned)
    .with_chain_discriminant(369);
    let json = norito::json::to_json(&manifest)?;
    let decoded: RawGenesisTransaction = norito::json::from_str(&json)?;
    assert_eq!(decoded.chain_discriminant(), 369);
    Ok(())
}
#[test]
fn topology_entries_parse_with_pop_hex() {
    init_instruction_registry();
    let peer = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let peer_value = norito::json::value::to_value(&peer).expect("serialize peer");
    let topo_entry = {
        let mut map = norito::json::Map::new();
        map.insert("peer".to_string(), peer_value);
        map.insert(
            "pop_hex".to_string(),
            norito::json::Value::String("0x00".to_string()),
        );
        norito::json::Value::Object(map)
    };
    let mut tx_map = norito::json::Map::new();
    tx_map.insert(
        "topology".to_string(),
        norito::json::Value::Array(vec![topo_entry]),
    );
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert(
        "chain_discriminant".to_string(),
        manifest_chain_discriminant_value(),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".into()),
    );
    manifest_fields.insert(
        "wire_protocol_version".to_string(),
        norito::json::value::to_value(&CONSENSUS_PROTOCOL_VERSION)
            .expect("serialize wire protocol version"),
    );
    manifest_fields.insert(
        "sumeragi_context".to_string(),
        manifest_sumeragi_context_value(),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(tx_map)]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let parsed =
        RawGenesisTransaction::from_json_value(manifest).expect("topology entry should parse");
    assert_eq!(parsed.transactions.len(), 1);
    let tx = &parsed.transactions[0];
    assert_eq!(tx.topology.len(), 1);
    assert_eq!(tx.topology[0].peer, peer);
    assert_eq!(tx.topology[0].pop_hex.as_deref(), Some("00"));
}
#[test]
fn serialize_topology_embeds_pop_hex() {
    let (peer_pk, _) = checked_genesis_fixture_keypair().into_parts();
    let peer = PeerId::from(peer_pk.clone());
    let tx = RawGenesisTx {
        parameters: None,
        instructions: Vec::new(),
        ivm_triggers: Vec::new(),
        topology: vec![GenesisTopologyEntry::new(peer, vec![0xAA, 0xBB])],
    };
    let json = norito::json::to_json(&tx).expect("serialize tx");
    assert!(
        json.contains("\"pop_hex\":\"aabb\""),
        "pop_hex should be embedded alongside topology peer: {json}"
    );
}
#[test]
fn topology_entries_allow_missing_pop_hex() {
    init_instruction_registry();
    let peer = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let peer_value = norito::json::value::to_value(&peer).expect("serialize peer");
    let topo_entry = {
        let mut map = norito::json::Map::new();
        map.insert("peer".to_string(), peer_value);
        norito::json::Value::Object(map)
    };
    let mut tx_map = norito::json::Map::new();
    tx_map.insert(
        "topology".to_string(),
        norito::json::Value::Array(vec![topo_entry]),
    );
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert(
        "chain_discriminant".to_string(),
        manifest_chain_discriminant_value(),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".into()),
    );
    manifest_fields.insert(
        "wire_protocol_version".to_string(),
        norito::json::value::to_value(&CONSENSUS_PROTOCOL_VERSION)
            .expect("serialize wire protocol version"),
    );
    manifest_fields.insert(
        "sumeragi_context".to_string(),
        manifest_sumeragi_context_value(),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(tx_map)]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let parsed = RawGenesisTransaction::from_json_value(manifest)
        .expect("topology entry without pop_hex should parse");
    assert_eq!(parsed.transactions.len(), 1);
    let tx = &parsed.transactions[0];
    assert_eq!(tx.topology.len(), 1);
    assert_eq!(tx.topology[0].peer, peer);
    assert!(tx.topology[0].pop_hex.is_none());
}
#[test]
fn topology_entries_reject_peer_value() {
    init_instruction_registry();
    let peer = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let peer_value = norito::json::value::to_value(&peer).expect("serialize peer");
    let mut tx_map = norito::json::Map::new();
    tx_map.insert(
        "topology".to_string(),
        norito::json::Value::Array(vec![peer_value]),
    );
    let mut manifest_fields = norito::json::Map::new();
    manifest_fields.insert(
        "chain".to_string(),
        norito::json::Value::String("test-chain".into()),
    );
    manifest_fields.insert(
        "chain_discriminant".to_string(),
        manifest_chain_discriminant_value(),
    );
    manifest_fields.insert("executor".to_string(), norito::json::Value::Null);
    manifest_fields.insert(
        "ivm_dir".to_string(),
        norito::json::Value::String(".".into()),
    );
    manifest_fields.insert(
        "consensus_mode".to_string(),
        norito::json::Value::String("Permissioned".into()),
    );
    manifest_fields.insert(
        "wire_protocol_version".to_string(),
        norito::json::value::to_value(&CONSENSUS_PROTOCOL_VERSION)
            .expect("serialize wire protocol version"),
    );
    manifest_fields.insert(
        "sumeragi_context".to_string(),
        manifest_sumeragi_context_value(),
    );
    manifest_fields.insert(
        "transactions".to_string(),
        norito::json::Value::Array(vec![norito::json::Value::Object(tx_map)]),
    );
    let manifest = norito::json::Value::Object(manifest_fields);
    let err = RawGenesisTransaction::from_json_value(manifest)
        .expect_err("peer-only topology entries should be rejected");
    assert!(
        err.to_string().contains("topology entries must be objects"),
        "unexpected error: {err}"
    );
}
#[test]
fn clear_topology_removes_all_entries() {
    let chain = ChainId::from("iroha:test:clear-topology");
    let peer_a = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let peer_b = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let manifest = GenesisBuilder::new_without_executor(chain, ".")
        .set_topology(vec![peer_a])
        .next_transaction()
        .set_topology(vec![peer_b])
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
        .build_raw()
        .expect("complete test genesis builder")
        .with_consensus_mode(SumeragiConsensusMode::Permissioned);
    let cleared = manifest.clear_topology();
    assert!(
        cleared
            .transactions()
            .iter()
            .all(|tx| tx.topology().is_empty()),
        "expected all topology entries to be removed"
    );
}
#[test]
fn builder_preserves_consensus_metadata() {
    let manifest = RawGenesisTransaction {
        chain: ChainId::from("iroha:test:builder-meta"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: 1,
        consensus_fingerprint: Some(ConsensusFingerprint::new([0xAB; 32])),
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let rebuilt = manifest
        .clone()
        .into_builder()
        .domain(DomainId::try_new("example", "universal").expect("domain id"))
        .finish_domain()
        .build_raw()
        .expect("rebuild complete manifest");
    assert_eq!(rebuilt.consensus_mode, manifest.consensus_mode);
    assert_eq!(
        rebuilt.wire_protocol_version,
        manifest.wire_protocol_version
    );
    assert_eq!(
        rebuilt.consensus_fingerprint,
        manifest.consensus_fingerprint
    );
    assert_eq!(rebuilt.sumeragi_context, manifest.sumeragi_context);
}
#[test]
fn raw_genesis_rejects_retired_and_malformed_consensus_manifest_shapes() {
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:strict-consensus-manifest"),
        ".",
    )
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .build_raw()
    .expect("complete strict manifest fixture")
    .with_consensus_meta()
    .expect("valid fixture consensus parameters");
    let base = norito::json::to_value(&manifest).expect("serialize strict manifest");
    let protocol_version_array = norito::json::value::to_value(&vec![CONSENSUS_PROTOCOL_VERSION])
        .expect("serialize invalid protocol-version array");
    let mut old_plural = base.clone();
    let map = old_plural.as_object_mut().expect("manifest object");
    map.remove("wire_protocol_version");
    map.insert(
        "wire_proto_versions".to_owned(),
        protocol_version_array.clone(),
    );
    assert!(RawGenesisTransaction::from_json_value(old_plural).is_err());
    let mut array_version = base.clone();
    array_version
        .as_object_mut()
        .expect("manifest object")
        .insert("wire_protocol_version".to_owned(), protocol_version_array);
    assert!(RawGenesisTransaction::from_json_value(array_version).is_err());
    for malformed in [
        "0xAA00000000000000000000000000000000000000000000000000000000000000",
        "0x00",
        "aa00000000000000000000000000000000000000000000000000000000000000",
    ] {
        let mut value = base.clone();
        value.as_object_mut().expect("manifest object").insert(
            "consensus_fingerprint".to_owned(),
            norito::json::Value::String(malformed.to_owned()),
        );
        assert!(
            RawGenesisTransaction::from_json_value(value).is_err(),
            "malformed fingerprint `{malformed}` must fail closed"
        );
    }
    let mut unknown = base;
    unknown
        .as_object_mut()
        .expect("manifest object")
        .insert("unknown".to_owned(), norito::json::Value::Bool(true));
    assert!(RawGenesisTransaction::from_json_value(unknown).is_err());
}
#[test]
fn topology_entry_pop_bytes_none() {
    let peer = PeerId::new(checked_genesis_fixture_keypair().public_key().clone());
    let entry = GenesisTopologyEntry::from(peer);
    let pop = entry.pop_bytes().expect("pop_bytes");
    assert!(pop.is_none());
}
#[test]
fn normalize_exposes_instruction_batches() {
    init_instruction_registry();
    let manifest = RawGenesisTransaction {
        chain: ChainId::from("iroha:test:normalize"),
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx::default()],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let normalized = manifest.normalize().expect("normalize");
    assert!(
        !normalized.transactions.is_empty(),
        "normalize should emit at least one transaction batch"
    );
    assert_ne!(
        normalized.consensus_fingerprint,
        ConsensusFingerprint::new([0; 32]),
        "normalize should expose the computed fingerprint"
    );
}
#[allow(clippy::too_many_lines)]
#[test]
fn with_consensus_meta_uses_npos_custom_parameter() {
    use iroha_data_model::parameter::{
        Parameter as DataModelParameter,
        system::{SumeragiConsensusMode, SumeragiParameter},
    };
    fn fingerprint_for(tx: &RawGenesisTransaction) -> [u8; 32] {
        let params = tx
            .effective_parameters()
            .expect("single structured parameter block");
        let npos_param_id = SumeragiNposParameters::parameter_id();
        let npos = params
            .custom()
            .get(&npos_param_id)
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()
            .expect("valid fixture NPoS parameters")
            .flatten()
            .expect("NPoS fixture must carry signed election parameters");
        assert_eq!(tx.consensus_mode, SumeragiConsensusMode::Npos);
        let dm_params = ConsensusGenesisParams {
            block_cadence_ms: params.sumeragi().block_cadence_ms(),
            block_max_transactions: params.block().max_transactions(),
            mode: ConsensusGenesisModeParams::Npos(NposGenesisParams {
                epoch_length_blocks: npos.epoch_length_blocks(),
                epoch_seed: npos.epoch_seed(),
                max_validators: npos.max_validators(),
                min_self_bond: npos.min_self_bond().clone(),
                min_nomination_bond: npos.min_nomination_bond().clone(),
                finality_margin_blocks: npos.finality_margin_blocks(),
                evidence_horizon_blocks: npos.evidence_horizon_blocks(),
                activation_lag_blocks: npos.activation_lag_blocks(),
                slashing_delay_blocks: npos.slashing_delay_blocks(),
            }),
            protocol_version: iroha_config::parameters::defaults::sumeragi::PROTOCOL_VERSION,
            sumeragi_context: tx.sumeragi_context,
        };
        compute_consensus_parameters_fingerprint(&dm_params)
            .expect("canonical NPoS fixture must fingerprint")
    }
    fn build_manifest(chain: ChainId, seed_byte: u8) -> RawGenesisTransaction {
        let mut parameters = Parameters::default();
        parameters.set_parameter(DataModelParameter::Sumeragi(
            SumeragiParameter::MaxClockDriftMs(250),
        ));
        let npos = SumeragiNposParameters::default().with_epoch_seed([seed_byte; 32]);
        parameters.set_parameter(DataModelParameter::Custom(npos.into()));
        RawGenesisTransaction {
            chain,
            chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
            executor: None,
            ivm_dir: IvmPath::default(),
            transactions: vec![RawGenesisTx {
                parameters: Some(parameters),
                ..RawGenesisTx::default()
            }],
            consensus_mode: SumeragiConsensusMode::Npos,
            wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
            consensus_fingerprint: None,
            sumeragi_context: SumeragiGenesisContextParameters::recommended(),
            crypto: ManifestCrypto::default(),
        }
    }
    let chain = ChainId::from("iroha:test:nposmeta");
    let manifest_base_a = build_manifest(chain.clone(), 0xA0);
    let manifest_base_b = build_manifest(chain, 0xA1);
    let expected_a = fingerprint_for(&manifest_base_a);
    let expected_b = fingerprint_for(&manifest_base_b);
    let manifest_a = manifest_base_a
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
    let manifest_b = manifest_base_b
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
    assert_eq!(
        manifest_a.consensus_fingerprint,
        Some(ConsensusFingerprint::new(expected_a))
    );
    assert_eq!(
        manifest_b.consensus_fingerprint,
        Some(ConsensusFingerprint::new(expected_b))
    );
    assert_eq!(manifest_a.consensus_mode, SumeragiConsensusMode::Npos);
    assert_eq!(manifest_a.wire_protocol_version, CONSENSUS_PROTOCOL_VERSION);
}
#[test]
fn permissioned_genesis_rejects_npos_parameters() {
    use iroha_data_model::parameter::{
        Parameter as DataModelParameter, system::SumeragiConsensusMode,
    };
    let chain = ChainId::from("iroha:test:permmeta");
    let mut parameters = Parameters::default();
    let npos_defaults = SumeragiNposParameters::default();
    parameters.set_parameter(DataModelParameter::Custom(npos_defaults.into()));
    let manifest = RawGenesisTransaction {
        chain,
        chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
        executor: None,
        ivm_dir: IvmPath::default(),
        transactions: vec![RawGenesisTx {
            parameters: Some(parameters),
            ..RawGenesisTx::default()
        }],
        consensus_mode: SumeragiConsensusMode::Permissioned,
        wire_protocol_version: CONSENSUS_PROTOCOL_VERSION,
        consensus_fingerprint: None,
        sumeragi_context: SumeragiGenesisContextParameters::recommended(),
        crypto: ManifestCrypto::default(),
    };
    let error = manifest
        .normalize()
        .expect_err("permissioned genesis must reject NPoS election parameters");
    assert!(
        error
            .to_string()
            .contains("permissioned genesis must omit `sumeragi_npos_parameters`"),
        "unexpected error: {error:?}"
    );
}
#[test]
fn crypto_manifest_requires_ed25519() {
    init_instruction_registry();
    let crypto = ManifestCrypto {
        allowed_signing: vec![Algorithm::Secp256k1],
        ..ManifestCrypto::default()
    };
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:crypto-ed25519"),
        PathBuf::from("."),
    )
    .with_crypto(crypto)
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .set_topology(deterministic_test_topology_entries())
    .build_raw()
    .expect("complete crypto manifest fixture");
    let err = manifest
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect_err("manifest without ed25519 should be rejected");
    assert!(
        err.to_string().contains("allowed_signing"),
        "unexpected error: {err:?}"
    );
}
#[test]
fn crypto_manifest_rejects_noncanonical_sm_intrinsics_policy() {
    let crypto = ManifestCrypto {
        sm_intrinsics: "AUTO".to_owned(),
        ..ManifestCrypto::default()
    };
    assert!(crypto.validate().is_err());
    assert!(
        std::panic::catch_unwind(|| ActualCrypto::from(crypto)).is_err(),
        "conversion must not silently replace an invalid policy with `auto`"
    );
}
#[cfg(feature = "sm")]
#[test]
fn crypto_manifest_requires_sm_defaults_when_sm2_allowed() {
    init_instruction_registry();
    let crypto = ManifestCrypto {
        allowed_signing: vec![Algorithm::Ed25519, Algorithm::Sm2],
        ..ManifestCrypto::default()
    };
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:crypto-sm"),
        PathBuf::from("."),
    )
    .with_crypto(crypto)
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .set_topology(deterministic_test_topology_entries())
    .build_raw()
    .expect("complete crypto manifest fixture");
    let err = manifest
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect_err("manifest missing SM defaults should be rejected");
    assert!(
        err.to_string().contains("default_hash"),
        "unexpected error: {err:?}"
    );
}
#[cfg(feature = "sm")]
#[test]
fn crypto_manifest_accepts_valid_sm_configuration() {
    init_instruction_registry();
    let crypto = ManifestCrypto {
        default_hash: "sm3-256".to_owned(),
        allowed_signing: vec![Algorithm::Ed25519, Algorithm::Sm2],
        allowed_curve_ids: vec![CurveId::ED25519.as_u8(), CurveId::SM2.as_u8()],
        ..ManifestCrypto::default()
    };
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:crypto-sm-valid"),
        PathBuf::from("."),
    )
    .with_crypto(crypto)
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .set_topology(deterministic_test_topology_entries())
    .build_raw()
    .expect("complete crypto manifest fixture");
    manifest
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect("manifest with valid SM configuration should build");
}
#[test]
fn crypto_manifest_rejects_sm3_hash_without_sm2() {
    init_instruction_registry();
    let crypto = ManifestCrypto {
        default_hash: "sm3-256".to_owned(),
        ..ManifestCrypto::default()
    };
    let manifest = GenesisBuilder::new_without_executor(
        ChainId::from("iroha:test:crypto-sm3-without-sm2"),
        PathBuf::from("."),
    )
    .with_crypto(crypto)
    .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended())
    .set_topology(deterministic_test_topology_entries())
    .build_raw()
    .expect("complete crypto manifest fixture");
    let err = manifest
        .build_and_sign(&checked_genesis_fixture_keypair())
        .expect_err("manifest using sm3 default hash without sm2 should be rejected");
    assert!(
        err.to_string().contains("default_hash"),
        "unexpected error: {err:?}"
    );
}
