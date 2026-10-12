//! Exact borrowed proposal-wire equivalence across result and feature layouts.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use std::num::NonZeroU64;

fn plain_signed_block() -> SignedBlock {
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 1_000, 0);
    let key = KeyPair::try_from_seed(vec![0x49; 32], Algorithm::Ed25519).unwrap();
    let signature = BlockSignature::new(
        0,
        SignatureOf::try_from_hash(key.private_key(), header.hash()).unwrap(),
    );
    SignedBlock {
        signatures: crate::block::BlockSignatures::try_from_iter([signature])
            .expect("at most 31 block signatures"),
        payload: BlockPayload {
            header,
            external_entrypoints: Vec::new(),
            execution_context: None,
            da_commitments: None,
            da_proof_policies: None,
            da_pin_intents: None,
            npos_consensus_effects: None,
            global_beacon_pulse: None,
        },
        result: None,
        commit_certificate: None,
    }
}

fn assert_exact_borrowed_proposal_wire(block: &SignedBlock) {
    let reference = block
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    assert_eq!(reference[0], SignedBlock::WIRE_VERSION);
    assert_eq!(
        block.resultless_proposal_wire_len().unwrap(),
        reference.len()
    );
    let mut streamed = Vec::new();
    block.write_resultless_proposal_wire(&mut streamed).unwrap();
    assert_eq!(streamed, reference, "exact borrowed proposal writer");
    assert!(
        block
            .canonical_resultless_proposal()
            .expect("valid original proposal")
            .matches_resultless_proposal_wire(&reference)
            .unwrap(),
        "version, SignedBlock header and payload"
    );
    let candidate = SignedBlockOutputCandidate {
        signatures: OutputFieldRef(&block.signatures),
        payload: OutputFieldRef(&block.payload),
        result: None,
        commit_certificate: None,
    };
    let payload_len = {
        norito::core::reset_decode_state();
        let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::encoded_payload_len(&candidate).unwrap()
    };
    assert_eq!(
        payload_len + norito::core::Header::SIZE + 1,
        reference.len(),
        "version + fixed header + counted payload define the custom wire size",
    );
    assert_eq!(
        block.canonical_proposal_wire_hash().unwrap(),
        Hash::new(&reference),
    );
}

#[test]
fn borrowed_proposal_hash_matches_exact_resultless_and_executed_layouts() {
    let proposal = plain_signed_block();
    assert_exact_borrowed_proposal_wire(&proposal);
    assert_eq!(
        proposal.canonical_proposal_wire_hash().unwrap(),
        proposal.executed_block_wire_hash().unwrap(),
    );

    let mut executed = proposal.clone();
    executed.result = Some(BlockResult::default());
    assert_exact_borrowed_proposal_wire(&executed);
    assert_eq!(
        executed.canonical_proposal_wire_hash().unwrap(),
        proposal.canonical_proposal_wire_hash().unwrap(),
    );
    assert_ne!(
        executed.executed_block_wire_hash().unwrap(),
        proposal.executed_block_wire_hash().unwrap(),
    );
}

#[test]
fn borrowed_proposal_hash_includes_changed_signatures() {
    let mut proposal = plain_signed_block();
    let before = proposal.canonical_proposal_wire_hash().unwrap();
    let key = KeyPair::try_from_seed(vec![0x4a; 32], Algorithm::Ed25519).unwrap();
    proposal
        .signatures
        .try_insert(BlockSignature::new(
            1,
            SignatureOf::try_from_hash(key.private_key(), proposal.hash()).unwrap(),
        ))
        .unwrap();
    assert_exact_borrowed_proposal_wire(&proposal);
    assert_ne!(proposal.canonical_proposal_wire_hash().unwrap(), before);

    proposal.result = Some(BlockResult::default());
    assert_exact_borrowed_proposal_wire(&proposal);
    assert_ne!(proposal.canonical_proposal_wire_hash().unwrap(), before);
}

#[cfg(feature = "transparent_api")]
#[test]
fn borrowed_proposal_hash_matches_real_attached_outputs_and_post_attachment_signature() {
    let mut block = output_test_support::proposal(2);
    let before = block.canonical_proposal_wire_hash().unwrap();
    let rows = vec![
        output_test_support::network(0, Ok(Vec::default())),
        output_test_support::network(1, Ok(Vec::default())),
        output_test_support::simple_time(&block, 0),
    ];
    output_test_support::install(&mut block, rows, 3).unwrap();
    block
        .validate_execution_outputs(&output_test_support::limits())
        .unwrap();
    assert_exact_borrowed_proposal_wire(&block);
    assert_eq!(block.canonical_proposal_wire_hash().unwrap(), before);

    let key = KeyPair::try_from_seed(vec![0x4b; 32], Algorithm::Ed25519).unwrap();
    block
        .add_signature(BlockSignature::new(
            1,
            SignatureOf::try_from_hash(key.private_key(), block.hash()).unwrap(),
        ))
        .unwrap();
    assert_exact_borrowed_proposal_wire(&block);
    assert_ne!(block.canonical_proposal_wire_hash().unwrap(), before);
}

fn comparison_transaction(key: &KeyPair) -> crate::transaction::SignedTransaction {
    use crate::{
        Level,
        account::AccountId,
        isi::Log,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let authority_key = KeyPair::try_from_seed(vec![0x4c; 32], Algorithm::Ed25519).unwrap();
    let network = crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"checked resultless proposal network",
    )));
    let mut builder = TransactionBuilder::new(
        network,
        AccountId::new(authority_key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(900));
    let builder =
        builder.with_instructions([Log::new(Level::INFO, "exact instruction payload".into())]);
    // The negative fixture intentionally changes only authorization, preserving
    // the original authority and signed payload for the wire-identity check.
    let signature =
        iroha_crypto::Signature::try_new(key.private_key(), &builder.payload_hash_bytes()).unwrap();
    builder.build_with_signature(signature)
}

fn complete_comparison_proposal() -> SignedBlock {
    use crate::{
        consensus::{
            NposConsensusEffects, NposMarkConsensusEvidenceAppliedAction, NposPenaltyAction,
        },
        da::types::StorageTicketId,
        sorafs::pin_registry::ManifestDigest,
        transaction::TransactionEntrypoint,
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    let key = KeyPair::try_from_seed(vec![0x4c; 32], Algorithm::Ed25519).unwrap();
    let input = TransactionEntrypoint::from(comparison_transaction(&key));
    let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
        input.hash(),
        LaneId::new(7),
        DataSpaceId::new(2),
    )]);
    context.lane_merge = Some(crate::sumeragi_lanes::SumeragiLaneMergeSection {
        merges: vec![crate::sumeragi_lanes::SumeragiLaneMerge {
            lane: LaneId::new(7),
            incarnation: [1; 32],
            from: 1,
            to: 3,
            tip_hash: [2; 32],
            tip_result: [3; 32],
        }],
        time_floor_ms: 901,
        merged_count: 0,
    });
    let mut proposal = plain_signed_block();
    proposal.payload.external_entrypoints = vec![input];
    proposal.payload.execution_context = Some(context);
    proposal.payload.da_commitments = Some(super::tests::sample_da_bundle());
    proposal.payload.da_proof_policies = Some(DaProofPolicyBundle::new(vec![DaProofPolicy {
        lane_id: LaneId::new(7),
        dataspace_id: DataSpaceId::new(2),
        alias: "comparison lane".into(),
        proof_scheme: DaProofScheme::MerkleSha256,
    }]));
    proposal.payload.da_pin_intents =
        Some(DaPinIntentBundle::new(vec![super::tests::test_pin_intent(
            LaneId::new(7),
            1,
            1,
            StorageTicketId::new([0x66; 32]),
            ManifestDigest::new([0x22; 32]),
        )]));
    proposal.payload.npos_consensus_effects = Some(NposConsensusEffects {
        penalty_actions: vec![NposPenaltyAction::MarkConsensusEvidenceApplied(
            NposMarkConsensusEvidenceAppliedAction {
                evidence_key: Hash::new(b"comparison evidence"),
                height: 2,
            },
        )],
        ..NposConsensusEffects::default()
    });
    proposal
}

fn assert_checked_comparison_matches_wire(left: &SignedBlock, right: &SignedBlock) {
    let left_wire = left
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    let right_wire = right
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    assert_eq!(
        left.checked_raw_resultless_payload_len().unwrap(),
        left_wire.len() - 1 - norito::core::Header::SIZE,
    );
    assert_eq!(
        right.checked_raw_resultless_payload_len().unwrap(),
        right_wire.len() - 1 - norito::core::Header::SIZE,
    );
    let expected = left_wire == right_wire;
    assert_eq!(
        left.checked_resultless_proposal_eq(right).unwrap(),
        expected
    );
    assert_eq!(
        right.checked_resultless_proposal_eq(left).unwrap(),
        expected
    );
}

#[test]
fn checked_resultless_comparison_matches_complete_wire_and_ignores_only_result() {
    for proposal in [plain_signed_block(), complete_comparison_proposal()] {
        let mut executed = proposal.clone();
        executed.result = Some(BlockResult {
            committed_fragment_count: 17,
            ..BlockResult::default()
        });
        assert_checked_comparison_matches_wire(&proposal, &executed);
        assert!(proposal.checked_resultless_proposal_eq(&executed).unwrap());
        let mut different_results = executed.clone();
        different_results
            .result
            .as_mut()
            .unwrap()
            .committed_fragment_count = 23;
        assert_checked_comparison_matches_wire(&executed, &different_results);
        assert!(
            executed
                .checked_resultless_proposal_eq(&different_results)
                .unwrap()
        );
    }
}

#[test]
fn checked_resultless_comparison_binds_signatures_and_all_seven_payload_fields() {
    type ProposalMutation = (&'static str, fn(&mut SignedBlock));
    let proposal = complete_comparison_proposal();
    let edits: [ProposalMutation; 8] = [
        ("signatures", |block| {
            block.signatures = crate::block::BlockSignatures::default()
        }),
        ("header", |block| {
            block.payload.header =
                BlockHeader::new(NonZeroU64::new(3).unwrap(), None, None, 1_000, 0);
        }),
        ("external entrypoints", |block| {
            block.payload.external_entrypoints.clear()
        }),
        ("execution context", |block| {
            block.payload.execution_context.as_mut().unwrap().external[0].routing_plan_digest =
                Hash::new(b"different exact routing plan");
        }),
        ("DA commitments", |block| {
            let original = block.payload.da_commitments.as_ref().unwrap();
            let mut commitments = original.commitments().to_vec();
            commitments[0].sequence += 1;
            block.payload.da_commitments = Some(
                crate::da::commitment::DaCommitmentBundle::from_untrusted_parts(
                    original.version(),
                    commitments,
                ),
            );
        }),
        ("DA proof policies", |block| {
            let original = block.payload.da_proof_policies.as_ref().unwrap();
            let mut policies = original.policies().to_vec();
            policies[0].alias.push('x');
            block.payload.da_proof_policies = Some(DaProofPolicyBundle::from_untrusted_parts(
                original.version(),
                original.policy_hash(),
                policies,
            ));
        }),
        ("DA pin intents", |block| {
            block.payload.da_pin_intents.as_mut().unwrap().intents[0].alias =
                Some("changed".into());
        }),
        ("NPoS effects", |block| {
            block
                .payload
                .npos_consensus_effects
                .as_mut()
                .unwrap()
                .penalty_actions
                .clear();
        }),
    ];
    for (field, edit) in edits {
        let mut changed = proposal.clone();
        edit(&mut changed);
        assert_checked_comparison_matches_wire(&proposal, &changed);
        assert!(
            !proposal.checked_resultless_proposal_eq(&changed).unwrap(),
            "{field}"
        );
    }
    let original_key = KeyPair::try_from_seed(vec![0x4c; 32], Algorithm::Ed25519).unwrap();
    let changed_key = KeyPair::try_from_seed(vec![0x4d; 32], Algorithm::Ed25519).unwrap();
    let original_input = comparison_transaction(&original_key);
    let changed_input = comparison_transaction(&changed_key);
    assert_eq!(original_input.payload(), changed_input.payload());
    assert_ne!(original_input.signature(), changed_input.signature());
    assert!(original_input.verify_signature().is_ok());
    assert!(changed_input.verify_signature().is_err());
    let mut changed = proposal.clone();
    changed.payload.external_entrypoints[0] = changed_input.into();
    assert_eq!(
        proposal.hash(),
        changed.hash(),
        "header-only matching is insufficient"
    );
    assert_checked_comparison_matches_wire(&proposal, &changed);
    assert!(!proposal.checked_resultless_proposal_eq(&changed).unwrap());
}

#[test]
fn checked_resultless_comparison_uses_fixed_flags_independent_of_ambient_layout() {
    let proposal = complete_comparison_proposal();
    let expected_len = proposal.checked_raw_resultless_payload_len().unwrap();
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            proposal.checked_raw_resultless_payload_len().unwrap(),
            expected_len
        );
        assert!(proposal.checked_resultless_proposal_eq(&proposal).unwrap());
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
}

#[test]
fn checked_resultless_comparison_rejects_archive_cap_in_isolated_process() {
    struct RestoreCap(u64);
    impl Drop for RestoreCap {
        fn drop(&mut self) {
            norito::core::set_max_archive_len(self.0);
        }
    }
    const CHILD: &str = "IROHA_DATA_MODEL_CHECKED_RESULTLESS_CAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("checked_resultless_comparison_rejects_archive_cap_in_isolated_process")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .expect("run isolated resultless comparison cap test");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // No other libtest case runs in this child while changing the process-global ceiling.
    let _restore = RestoreCap(norito::core::max_archive_len());
    let small = plain_signed_block();
    let mut larger = small.clone();
    let key = KeyPair::try_from_seed(vec![0x4e; 32], Algorithm::Ed25519).unwrap();
    larger
        .signatures
        .try_insert(BlockSignature::new(
            1,
            SignatureOf::try_from_hash(key.private_key(), larger.hash()).unwrap(),
        ))
        .unwrap();
    let small_len = small.checked_raw_resultless_payload_len().unwrap();
    let larger_len = larger.checked_raw_resultless_payload_len().unwrap();
    assert!(larger_len > small_len && small_len > 1);
    norito::core::set_max_archive_len(u64::try_from(larger_len).unwrap());
    assert!(larger.checked_resultless_proposal_eq(&larger).unwrap());
    assert!(larger.canonical_proposal_wire_hash().is_ok());
    norito::core::set_max_archive_len(u64::try_from(small_len).unwrap());
    assert!(small.checked_resultless_proposal_eq(&small).unwrap());
    assert!(small.canonical_proposal_wire_hash().is_ok());
    assert!(
        small.checked_resultless_proposal_eq(&larger).is_err(),
        "count the second input before comparing fields"
    );
    assert!(
        larger.checked_resultless_proposal_eq(&small).is_err(),
        "count the original input before comparing fields"
    );
    norito::core::set_max_archive_len(u64::try_from(small_len - 1).unwrap());
    assert!(
        matches!(small.checked_resultless_proposal_eq(&small), Err(NoritoFrameError::ArchiveLengthExceeded { length, limit }) if length == small_len as u64 && limit == (small_len - 1) as u64)
    );
    assert!(small.canonical_proposal_wire_hash().is_err());
    assert!(small.resultless_proposal_wire_len().is_err());
    let mut untouched = vec![0xa5];
    assert!(
        small
            .write_resultless_proposal_wire(&mut untouched)
            .is_err()
    );
    assert_eq!(untouched, [0xa5], "reject the archive cap before writing");
    assert!(
        !small
            .checked_resultless_proposal_eq(&small)
            .unwrap_or(false),
        "two over-limit inputs never compare equal"
    );
}

#[test]
fn checked_resultless_comparison_binds_registration_metadata_beyond_entity_identity() {
    use crate::{
        account::{Account, AccountId},
        isi::{InstructionBox, Register},
        transaction::{FeePaymentIntent, TransactionBuilder, TransactionEntrypoint},
    };
    use iroha_model_base::metadata::Metadata;

    let key = KeyPair::try_from_seed(vec![0x4c; 32], Algorithm::Ed25519).unwrap();
    let account_id = AccountId::new(key.public_key().clone());
    let mut first_metadata = Metadata::default();
    first_metadata.insert("memo".parse().unwrap(), "first");
    let mut second_metadata = Metadata::default();
    second_metadata.insert("memo".parse().unwrap(), "other");
    let first_account = Account::new(account_id.clone()).with_metadata(first_metadata);
    let second_account = Account::new(account_id.clone()).with_metadata(second_metadata);
    assert_eq!(
        first_account, second_account,
        "entity equality is identity-only"
    );
    let first_instruction: InstructionBox = Register::account(first_account).into();
    let second_instruction: InstructionBox = Register::account(second_account).into();
    assert_ne!(
        first_instruction, second_instruction,
        "instruction equality binds exact metadata"
    );

    let build = |instruction| {
        let network = crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::new(b"checked resultless registration network"),
        ));
        let mut builder = TransactionBuilder::new(
            network,
            account_id.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(900));
        builder.with_instructions([instruction])
    };
    let first_builder = build(first_instruction);
    let signature =
        iroha_crypto::Signature::try_new(key.private_key(), &first_builder.payload_hash_bytes())
            .unwrap();
    let first_transaction = first_builder.build_with_signature(signature.clone());
    // Keep authorization identical to isolate payload equality. The changed
    // instruction is deliberately not re-signed: this is a codec adversary,
    // not evidence that the changed transaction would pass admission.
    let second_transaction = build(second_instruction).build_with_signature(signature);
    assert!(first_transaction.verify_signature().is_ok());
    assert!(second_transaction.verify_signature().is_err());
    assert_eq!(
        first_transaction.signature(),
        second_transaction.signature()
    );

    let mut first = plain_signed_block();
    first.payload.external_entrypoints = vec![TransactionEntrypoint::from(first_transaction)];
    let mut second = first.clone();
    second.payload.external_entrypoints = vec![TransactionEntrypoint::from(second_transaction)];
    assert_eq!(
        first.checked_raw_resultless_payload_len().unwrap(),
        second.checked_raw_resultless_payload_len().unwrap()
    );
    assert_checked_comparison_matches_wire(&first, &second);
    assert!(!first.checked_resultless_proposal_eq(&second).unwrap());
}

#[test]
fn checked_resultless_comparison_binds_da_pin_authorization_and_witnesses() {
    use crate::da::ingest::{DaPinScopeAuthorizationV1, DaPinScopeV1};

    let original = complete_comparison_proposal();
    let pin = &original.payload.da_pin_intents.as_ref().unwrap().intents[0];
    let key = KeyPair::try_from_seed(vec![0xDE; 32], Algorithm::Ed25519).unwrap();
    assert!(pin.authorization.has_valid_canonical_signatures());
    assert!(pin.pin_scope_authorization.has_valid_canonical_signatures());

    let mut changed_request = pin.clone();
    changed_request.authorization.request_content_hash = Hash::new(b"changed pin request");
    changed_request.authorization.signatures[0].signature = iroha_crypto::Signature::try_new(
        key.private_key(),
        &changed_request.authorization.signing_digest(),
    )
    .unwrap();
    changed_request.pin_scope_authorization = DaPinScopeAuthorizationV1::try_sign(
        DaPinScopeV1::new(
            &changed_request.authorization,
            pin.storage_ticket,
            pin.manifest_hash,
            pin.alias.clone(),
        ),
        &key,
    )
    .unwrap();
    assert!(
        changed_request
            .authorization
            .has_valid_canonical_signatures()
    );
    assert!(
        changed_request
            .pin_scope_authorization
            .has_valid_canonical_signatures()
    );

    // The witness-only variants deliberately sign another message. Neither
    // malformed authorization may compare equal to the original wire object.
    let unrelated_signature =
        iroha_crypto::Signature::try_new(key.private_key(), b"another signed message").unwrap();
    let mut changed_ingest_witness = pin.clone();
    changed_ingest_witness.authorization.signatures[0].signature = unrelated_signature.clone();
    assert!(
        !changed_ingest_witness
            .authorization
            .has_valid_canonical_signatures()
    );
    let mut changed_scope_witness = pin.clone();
    changed_scope_witness.pin_scope_authorization.signatures[0].signature = unrelated_signature;
    assert!(
        !changed_scope_witness
            .pin_scope_authorization
            .has_valid_canonical_signatures()
    );

    for (name, changed_pin) in [
        ("request authorization", changed_request),
        ("ingest witness only", changed_ingest_witness),
        ("pin-scope witness only", changed_scope_witness),
    ] {
        assert_eq!(
            (
                pin.lane_id,
                pin.epoch,
                pin.sequence,
                pin.storage_ticket,
                pin.manifest_hash,
                &pin.alias
            ),
            (
                changed_pin.lane_id,
                changed_pin.epoch,
                changed_pin.sequence,
                changed_pin.storage_ticket,
                changed_pin.manifest_hash,
                &changed_pin.alias
            ),
            "outer pin identity is unchanged for {name}",
        );
        let mut changed = original.clone();
        changed.payload.da_pin_intents.as_mut().unwrap().intents[0] = changed_pin;
        assert_eq!(
            original.checked_raw_resultless_payload_len().unwrap(),
            changed.checked_raw_resultless_payload_len().unwrap(),
            "equal lengths for {name}"
        );
        assert_checked_comparison_matches_wire(&original, &changed);
        assert!(
            !original.checked_resultless_proposal_eq(&changed).unwrap(),
            "must bind {name}"
        );
    }
}

#[test]
fn checked_resultless_comparison_binds_complete_native_lane_merge() {
    let original = complete_comparison_proposal();
    // These representation fixtures exercise exact wire identity. Cryptographic
    // lane authentication is checked independently before execution in Core.
    for mutation in 0..7 {
        let mut changed = original.clone();
        let section = changed
            .payload
            .execution_context
            .as_mut()
            .unwrap()
            .lane_merge
            .as_mut()
            .unwrap();
        match mutation {
            0 => section.merges[0].lane = iroha_model_base::topology::LaneId::new(8),
            1 => section.merges[0].incarnation[0] ^= 1,
            2 => section.merges[0].from += 1,
            3 => section.merges[0].to += 1,
            4 => section.merges[0].tip_hash[0] ^= 1,
            5 => section.merges[0].tip_result[0] ^= 1,
            _ => section.time_floor_ms += 1,
        }
        assert_ne!(original.lane_merge(), changed.lane_merge());
        assert_eq!(
            original.checked_raw_resultless_payload_len().unwrap(),
            changed.checked_raw_resultless_payload_len().unwrap()
        );
        assert_checked_comparison_matches_wire(&original, &changed);
        assert!(
            !original.checked_resultless_proposal_eq(&changed).unwrap(),
            "native lane merge mutation {mutation}"
        );
    }
}

#[test]
fn current_beacon_pulse_is_bound_by_header_payload_and_canonical_wire() {
    use crate::consensus::{
        FinalizedGlobalThresholdBeaconPulseV1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    };
    let mut proposal = plain_signed_block();
    let original_header = proposal.hash();
    let original_wire = proposal.canonical_proposal_wire_hash().unwrap();
    let pulse = FinalizedGlobalThresholdBeaconPulseV1 {
        version: 1,
        network_id: crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"pulse codec genesis",
        ))),
        session_id: [1; 32],
        roster_hash: [2; 32],
        transcript_hash: [3; 32],
        context: GlobalThresholdBeaconPulseContextV1 {
            instance: [7; 32],
            epoch: 0,
            epoch_context_id: [8; 32],
            parent_consensus_hash: [9; 32],
            parent_result: [10; 32],
        },
        height: 2,
        round: 0,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
            height: 1,
            block_hash: HashOf::from_untyped_unchecked(Hash::new(b"pulse codec parent")),
        },
        signature: [4; 48],
        seed: [5; 32],
        pulse_id: [6; 32],
    };
    // This test exercises representation and commitments; the Core threshold fixture verifies
    // real DKG signatures and current predecessor/session authority.
    proposal.set_global_beacon_pulse(Some(pulse));
    assert_ne!(proposal.hash(), original_header);
    assert_ne!(
        proposal.canonical_proposal_wire_hash().unwrap(),
        original_wire
    );
    assert_eq!(
        proposal.header().global_beacon_pulse_hash(),
        Some(HashOf::new(&pulse))
    );
    proposal.validate_proposal_commitments().unwrap();
    assert_exact_borrowed_proposal_wire(&proposal);
    let wire = proposal.encode_wire().unwrap();
    let decoded = decode_framed_signed_block(&wire).unwrap();
    assert_eq!(decoded.global_beacon_pulse(), Some(&pulse));
    assert_eq!(decoded.header(), proposal.header());

    let mut substituted = proposal.clone();
    substituted
        .payload
        .global_beacon_pulse
        .as_mut()
        .unwrap()
        .height += 1;
    assert!(substituted.validate_proposal_commitments().is_err());
    let mut omitted = proposal.clone();
    omitted.payload.global_beacon_pulse = None;
    assert!(omitted.validate_proposal_commitments().is_err());
    let mut missing_commitment = proposal.clone();
    missing_commitment
        .payload
        .header
        .set_global_beacon_pulse_hash(None);
    assert!(missing_commitment.validate_proposal_commitments().is_err());
    let mut changed = pulse;
    changed.finalized_chain_anchor.block_hash =
        HashOf::from_untyped_unchecked(Hash::new(b"another parent"));
    proposal.set_global_beacon_pulse(Some(changed));
    assert_ne!(proposal.hash(), decoded.hash());
    proposal.result = Some(BlockResult::default());
    proposal.set_global_beacon_pulse(None);
    assert!(proposal.is_resultless_proposal());
}

#[test]
fn proposal_writer_propagates_partial_destination_refusal_and_retries_exactly() {
    struct RefuseAfter {
        accepted: Vec<u8>,
        remaining: usize,
    }
    impl std::io::Write for RefuseAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            let count = bytes.len().min(self.remaining);
            self.accepted.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut block = plain_signed_block();
    block.result = Some(BlockResult::default());
    let expected = block
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    for accepted in [0, 1, norito::core::Header::SIZE, expected.len() - 1] {
        let mut writer = RefuseAfter {
            accepted: Vec::new(),
            remaining: accepted,
        };
        assert!(block.write_resultless_proposal_wire(&mut writer).is_err());
        assert_eq!(writer.accepted, expected[..accepted]);
        writer.accepted.clear();
        writer.remaining = expected.len();
        block.write_resultless_proposal_wire(&mut writer).unwrap();
        assert_eq!(writer.accepted, expected);
    }
}

#[test]
fn proposal_writer_preserves_ambient_codec_flags_and_source_graph() {
    let mut block = plain_signed_block();
    block.result = Some(BlockResult::default());
    let original = block.clone();
    let expected = block
        .canonical_resultless_proposal()
        .expect("valid original proposal")
        .encode_wire()
        .unwrap();
    let ambient = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _flags = norito::core::DecodeFlagsGuard::enter(ambient);
    let before = norito::core::get_decode_flags();
    let mut bytes = Vec::new();
    assert_eq!(
        block.resultless_proposal_wire_len().unwrap(),
        expected.len()
    );
    block.write_resultless_proposal_wire(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(norito::core::get_decode_flags(), before);
    assert_eq!(block, original);
}

fn merged_projection_fixture() -> (SignedBlock, SignedBlock) {
    use iroha_model_base::topology::{DataSpaceId, LaneId};
    let mut original = complete_comparison_proposal();
    SignedBlock::refresh_entrypoint_roots(&mut original.payload);
    let key = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519).unwrap();
    let merged = TransactionEntrypoint::from(comparison_transaction(&key));
    let context = ExternalExecutionContext::new(merged.hash(), LaneId::new(7), DataSpaceId::new(2));
    let expanded = original
        .clone()
        .with_merged_entrypoints(vec![merged], vec![context])
        .unwrap();
    (original, expanded)
}

#[test]
fn merged_execution_projects_exact_original_signed_proposal_in_every_borrowed_operation() {
    let (original, mut expanded) = merged_projection_fixture();
    expanded.result = Some(BlockResult::default());
    let expected = original.encode_wire().unwrap();
    assert_ne!(expanded.encode_wire().unwrap(), expected);
    assert_eq!(
        expanded
            .canonical_resultless_proposal()
            .expect("valid original proposal"),
        original
    );
    let source = expanded.clone();
    let entrypoints = expanded.payload.external_entrypoints.as_ptr();
    let contexts = expanded
        .payload
        .execution_context
        .as_ref()
        .unwrap()
        .external
        .as_ptr();
    let merge_rows = expanded.lane_merge().unwrap().merges.as_ptr();
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            expanded.resultless_proposal_wire_len().unwrap(),
            expected.len()
        );
        let mut actual = Vec::new();
        expanded
            .write_resultless_proposal_wire(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            expanded.canonical_proposal_wire_hash().unwrap(),
            Hash::new(&expected)
        );
        assert!(expanded.checked_resultless_proposal_eq(&original).unwrap());
        assert!(original.checked_resultless_proposal_eq(&expanded).unwrap());
        assert_eq!(norito::core::get_decode_flags(), flags);
    }
    assert_eq!(expanded, source);
    assert_eq!(expanded.payload.external_entrypoints.as_ptr(), entrypoints);
    assert_eq!(
        expanded
            .payload
            .execution_context
            .as_ref()
            .unwrap()
            .external
            .as_ptr(),
        contexts
    );
    assert_eq!(expanded.lane_merge().unwrap().merges.as_ptr(), merge_rows);
}

#[test]
fn merged_projection_never_normalizes_raw_proposal_ingress() {
    let (original, expanded) = merged_projection_fixture();
    assert!(expanded.is_resultless_proposal());
    assert!(
        !expanded
            .matches_resultless_proposal_wire(&original.encode_wire().unwrap())
            .unwrap()
    );
    assert!(
        expanded
            .matches_resultless_proposal_wire(&expanded.encode_wire().unwrap())
            .unwrap()
    );
}

#[test]
fn merged_projection_rejects_impossible_suffix_before_writing() {
    let (original, expanded) = merged_projection_fixture();
    for mutation in 0..3 {
        let mut malformed = expanded.clone();
        let context = malformed.payload.execution_context.as_mut().unwrap();
        match mutation {
            0 => context.lane_merge.as_mut().unwrap().merged_count = u32::MAX,
            1 => {
                context.external.pop();
            }
            2 => {
                context.external.push(context.external[0].clone());
            }
            _ => unreachable!(),
        }
        let mut destination = vec![0xa5];
        assert!(malformed.resultless_proposal_wire_len().is_err());
        assert!(
            malformed
                .write_resultless_proposal_wire(&mut destination)
                .is_err()
        );
        assert_eq!(destination, [0xa5]);
        assert!(malformed.canonical_proposal_wire_hash().is_err());
        assert!(malformed.checked_resultless_proposal_eq(&original).is_err());
        assert!(original.checked_resultless_proposal_eq(&malformed).is_err());
    }
}

#[test]
fn merged_projection_preserves_signatures_merge_authority_and_all_original_inputs() {
    let (original, expanded) = merged_projection_fixture();
    for mutation in 0..8 {
        let mut changed = expanded.clone();
        match mutation {
            0 => changed.signatures = crate::block::BlockSignatures::default(),
            1 => changed.payload.da_commitments = None,
            2 => changed.payload.da_proof_policies = None,
            3 => changed.payload.da_pin_intents = None,
            4 => changed.payload.npos_consensus_effects = None,
            5 => {
                changed.payload.execution_context.as_mut().unwrap().external[0].dataspace_id =
                    iroha_model_base::topology::DataSpaceId::new(999)
            }
            6 => {
                changed
                    .payload
                    .execution_context
                    .as_mut()
                    .unwrap()
                    .lane_merge
                    .as_mut()
                    .unwrap()
                    .merges[0]
                    .tip_hash[0] ^= 1
            }
            7 => {
                changed.payload.external_entrypoints[0] =
                    changed.payload.external_entrypoints[1].clone()
            }
            _ => unreachable!(),
        }
        assert!(
            !changed.checked_resultless_proposal_eq(&original).unwrap(),
            "mutation {mutation}"
        );
        assert_ne!(
            changed.canonical_proposal_wire_hash().unwrap(),
            original.canonical_proposal_wire_hash().unwrap(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn parent_service_original_changes_complete_proposal_commitment() {
    let mut left = plain_signed_block();
    let mut right = left.clone();
    let mut effects = crate::consensus::NposConsensusEffects {
        parent_service_commit_qc: Some(vec![0x21, 0x32]),
        ..Default::default()
    };
    left.set_npos_consensus_effects(Some(effects.clone()));
    effects.parent_service_commit_qc = Some(vec![0x21, 0x33]);
    right.set_npos_consensus_effects(Some(effects));
    left.validate_proposal_commitments().unwrap();
    right.validate_proposal_commitments().unwrap();
    assert_ne!(
        left.header().npos_effects_hash(),
        right.header().npos_effects_hash()
    );
    assert_ne!(left.hash(), right.hash());
    assert_checked_comparison_matches_wire(&left, &right);
    assert_ne!(left.checked_raw_resultless_payload_len().unwrap(), 0);
}
