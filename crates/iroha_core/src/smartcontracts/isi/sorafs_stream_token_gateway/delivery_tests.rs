//! Native source custody, immutable replay, atomicity and terminal ordering regressions.

use super::*;
use crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery;
use iroha_data_model::{
    block::BlockHeader,
    sorafs::reputation::stream_token_delivery::{
        StreamTokenReputationCancellationReasonV1 as Reason,
        StreamTokenReputationDeliveryDispositionV1 as Disposition,
    },
    transaction::SignedTransaction,
};

fn ready() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.configure();
    fixture.grant_operator();
    fixture
}

fn admit(fixture: &mut Fixture, nonce: &str) -> StreamTokenGatewayAdmissionRecordV1 {
    let instruction = fixture.instruction(Action::Admit(fixture.request(nonce)));
    assert!(fixture.commit(2, vec![instruction.into()]));
    fixture.record(fixture.current().unwrap().head.head.high_water_sequence)
}

fn source(
    fixture: &Fixture,
    record: &StreamTokenGatewayAdmissionRecordV1,
) -> (
    stream_token_delivery::Source,
    stream_token_delivery::DeliveryState,
) {
    let view = fixture.chain.state().view();
    stream_token_delivery::read(view.world(), &fixture.policy.network_id, record).unwrap()
}

fn signed_append(
    fixture: &Fixture,
    record: &StreamTokenGatewayAdmissionRecordV1,
) -> SignedTransaction {
    let (source, _) = source(fixture, record);
    TransactionBuilder::from_payload(source.intent.unwrap().payload)
        .unwrap()
        .try_sign(key(4).private_key())
        .unwrap()
}

#[expect(
    clippy::large_types_passed_by_value,
    reason = "the cancellation instruction owns the supplied original record"
)]
fn cancel(fixture: &mut Fixture, record: StreamTokenGatewayAdmissionRecordV1, seed: u8) -> bool {
    let (source, _) = source(fixture, &record);
    let action = fixture.instruction(Action::CancelReputationDelivery {
        record,
        expected_recorder_policy_digest: source.recorder_policy.policy_digest,
        reason: Reason::CredentialUnavailable,
    });
    fixture.commit(seed, vec![action.into()])
}

#[test]
fn native_delivery_source_commit_before_wal_and_full_wal_loss_reconstruct_identical_envelope() {
    let mut fixture = ready();
    let record = admit(&mut fixture, "crash-before-any-local-wal");
    let (original, state) = source(&fixture, &record);
    assert_eq!(state.disposition, Disposition::Pending);
    // No local delivery state exists: the committed source is the sole first-use authority.
    let first = signed_append(&fixture, &record);
    let original_bytes = norito::encode_canonical(&first).unwrap();
    drop(first);
    drop(original);
    // A fresh reader after losing every local byte reconstructs the same signature/envelope.
    let recovered = signed_append(&fixture, &record);
    assert_eq!(
        norito::encode_canonical(&recovered).unwrap(),
        original_bytes
    );
    assert_eq!(
        fixture
            .chain
            .commit_at(fixture.now(), vec![recovered.clone()]),
        [true]
    );
    let (_, delivered) = source(&fixture, &record);
    assert!(matches!(
        delivered.disposition,
        Disposition::Delivered {
            journal_sequence: 1,
            ..
        }
    ));
    assert_eq!(
        norito::encode_canonical(&signed_append(&fixture, &record)).unwrap(),
        original_bytes
    );
    let ack = fixture.instruction(Action::Acknowledge(record));
    assert!(fixture.commit(2, vec![ack.into()]));
    assert_eq!(source(&fixture, &record).1, delivered);
}

#[test]
fn native_delivery_append_indexes_follow_committed_order_without_source_reservations() {
    let mut fixture = ready();
    let first = admit(&mut fixture, "first-source");
    let second = admit(&mut fixture, "second-source");
    let first_signed = signed_append(&fixture, &first);
    let second_signed = signed_append(&fixture, &second);
    assert_eq!(
        fixture.chain.commit_at(fixture.now(), vec![second_signed]),
        [true]
    );
    assert_eq!(
        fixture.chain.commit_at(fixture.now(), vec![first_signed]),
        [true]
    );
    assert!(matches!(
        source(&fixture, &second).1.disposition,
        Disposition::Delivered {
            journal_sequence: 1,
            ..
        }
    ));
    assert!(matches!(
        source(&fixture, &first).1.disposition,
        Disposition::Delivered {
            journal_sequence: 2,
            ..
        }
    ));
    let out_of_order = fixture.instruction(Action::Acknowledge(second));
    assert!(!fixture.commit(2, vec![out_of_order.into()]));
    for record in [first, second] {
        let ack = fixture.instruction(Action::Acknowledge(record));
        assert!(fixture.commit(2, vec![ack.into()]));
    }
    assert_eq!(
        fixture
            .current()
            .unwrap()
            .head
            .head
            .acknowledged_through_sequence,
        2
    );
}

#[test]
fn native_delivery_terminal_order_never_counterfeits_a_successful_append() {
    let mut fixture = ready();
    let cancelled = admit(&mut fixture, "cancel-before-append");
    let signed = signed_append(&fixture, &cancelled);
    let policy_digest = source(&fixture, &cancelled).0.recorder_policy.policy_digest;
    let nested = fixture.instruction(Action::CancelReputationDelivery {
        record: cancelled,
        expected_recorder_policy_digest: policy_digest,
        reason: Reason::CredentialUnavailable,
    });
    assert!(
        !fixture.commit(
            1,
            vec![
                iroha_data_model::isi::Log::new(
                    iroha_logger::Level::INFO,
                    "cancellation companion".to_owned()
                )
                .into(),
                nested.into()
            ]
        ),
        "cancellation requires its sole exact signed instruction"
    );
    assert!(
        !cancel(&mut fixture, cancelled, 2),
        "operator alone cannot cancel reputation fees"
    );
    assert!(
        cancel(&mut fixture, cancelled, 1),
        "journal-policy manager cancels explicitly"
    );
    assert_eq!(
        fixture.chain.commit_at(fixture.now(), vec![signed]),
        [false]
    );
    let (_, terminal) = source(&fixture, &cancelled);
    assert!(matches!(
        terminal.disposition,
        Disposition::GovernanceCancelled { .. }
    ));
    let ack = fixture.instruction(Action::Acknowledge(cancelled));
    assert!(fixture.commit(2, vec![ack.into()]));
    assert_eq!(
        fixture.record(1).outcome.status,
        StreamTokenValidationStatusV1::Accepted
    );
    assert_eq!(
        source(&fixture, &cancelled).1,
        terminal,
        "drain never changes the original result into Delivered"
    );

    let delivered = admit(&mut fixture, "append-before-cancel");
    fixture.deliver_reputation(&delivered);
    let before = source(&fixture, &delivered).1;
    assert!(cancel(&mut fixture, delivered, 1));
    assert_eq!(
        source(&fixture, &delivered).1,
        before,
        "an existing exact append wins unchanged"
    );
    assert!(matches!(
        before.disposition,
        Disposition::Delivered {
            journal_sequence: 1,
            ..
        }
    ));
}

#[test]
fn native_delivery_expiry_is_consensus_owned_and_contiguous_drain_is_explicit() {
    let mut fixture = ready();
    let record = admit(&mut fixture, "original-expiry");
    let original = source(&fixture, &record).0.intent.unwrap();
    let ack = fixture.instruction(Action::Acknowledge(record));
    assert!(
        !fixture.commit(2, vec![ack.clone().into()]),
        "live Pending is not a completed callback"
    );
    let expires =
        original.payload.creation_time_ms + original.payload.time_to_live_ms.unwrap().get();
    let mut builder = TransactionBuilder::new(
        fixture.policy.network_id,
        account(2),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(expires));
    let signed = builder.with_instructions([ack]).sign(key(2).private_key());
    assert_eq!(fixture.chain.commit_at(expires + 1, vec![signed]), [true]);
    let (_, terminal) = source(&fixture, &record);
    assert!(matches!(terminal.disposition, Disposition::Expired { .. }));
    assert_eq!(
        fixture
            .current()
            .unwrap()
            .head
            .head
            .acknowledged_through_sequence,
        1
    );
    assert_eq!(fixture.record(1), record);
    assert_eq!(
        source(&fixture, &record).0.intent.unwrap().payload,
        original.payload
    );
    let retry = fixture.instruction(Action::Acknowledge(record));
    assert!(fixture.commit(2, vec![retry.into()]));
    assert_eq!(source(&fixture, &record).1, terminal);
}

#[test]
fn native_delivery_rejected_admit_has_no_partial_source_watermark_or_gateway_writes() {
    let mut fixture = ready();
    let revoke = Revoke::account_permission(
        Permission::from(CanRecordSorafsReputationJournal),
        account(4),
    );
    assert!(fixture.commit(4, vec![revoke.into()]));
    let instruction = fixture.instruction(Action::Admit(fixture.request("revoked-recorder")));
    let now = fixture.now();
    let state = fixture.chain.state();
    let header = BlockHeader::new(
        (fixture.chain.height() + 1).try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        now,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let before = transaction
        .world()
        .smart_contract_state()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    let execution = StreamTokenGatewayExecutionV1 {
        height: fixture.chain.height() + 1,
        transaction_hash: *Hash::new(b"atomic-admit").as_ref(),
        entry_index: 0,
        instruction_index: 0,
        recorded_at_unix_ms: now,
        authority: account(2),
    };
    // Exercise the actual native transition owner before caller rollback/commit can hide writes.
    assert!(super::super::apply(&instruction, &account(2), &mut transaction, &execution).is_err());
    let after = transaction
        .world()
        .smart_contract_state()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(after, before);
    assert_eq!(
        stream_token_delivery::source_time_watermark(transaction.world()).unwrap(),
        None
    );
}

#[test]
fn native_delivery_signed_payload_substitution_and_extra_instruction_fail_closed() {
    let mut fixture = ready();
    let record = admit(&mut fixture, "fixed-envelope");
    let original = source(&fixture, &record).0.intent.unwrap();
    for mutation in 0..4 {
        let mut payload = original.payload.clone();
        match mutation {
            0 => payload.creation_time_ms += 1,
            1 => payload.nonce = None,
            2 => {
                // Change the original TTL while keeping ingress valid so native payload
                // equality, rather than transaction expiry, rejects the substituted body.
                payload.time_to_live_ms =
                    std::num::NonZeroU64::new(original.payload.time_to_live_ms.unwrap().get() - 1);
            }
            3 => {
                payload.fee_payment =
                    FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1))
            }
            _ => unreachable!(),
        }
        let signed = TransactionBuilder::from_payload(payload)
            .unwrap()
            .try_sign(key(4).private_key())
            .unwrap();
        let now = fixture.now();
        assert!(
            signed.creation_time() + signed.time_to_live().unwrap() > Duration::from_millis(now),
            "the substituted envelope must reach native validation before its expiry"
        );
        assert_eq!(fixture.chain.commit_at(now, vec![signed]), [false]);
        assert_eq!(
            source(&fixture, &record).1.disposition,
            Disposition::Pending
        );
    }
    let mut payload = original.payload.clone();
    let iroha_data_model::transaction::Executable::Instructions(items) = &mut payload.instructions
    else {
        unreachable!()
    };
    let mut expanded = items.to_vec();
    expanded.push(
        iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "forbidden companion".to_owned(),
        )
        .into(),
    );
    *items = expanded.into();
    let signed = TransactionBuilder::from_payload(payload)
        .unwrap()
        .try_sign(key(4).private_key())
        .unwrap();
    assert_eq!(
        fixture.chain.commit_at(fixture.now(), vec![signed]),
        [false]
    );
    assert_eq!(
        source(&fixture, &record).1.disposition,
        Disposition::Pending
    );
    fixture.deliver_reputation(&record);
    let delivered = source(&fixture, &record).1;
    let grant = Grant::account_permission(
        Permission::from(CanRecordSorafsReputationJournal),
        account(3),
    );
    assert!(
        fixture.commit(4, vec![grant.into()]),
        "an existing exact holder delegates the recorder permission"
    );
    let mut another_authority = original.payload;
    another_authority.authority = account(3);
    let signed = TransactionBuilder::from_payload(another_authority)
        .unwrap()
        .try_sign(key(3).private_key())
        .unwrap();
    assert_eq!(
        fixture.chain.commit_at(fixture.now(), vec![signed]),
        [false],
        "another registered CanRecord holder cannot rebind or replay this original source"
    );
    assert_eq!(source(&fixture, &record).1, delivered);
}

#[test]
fn reputation_policy_origin_requires_genuine_genesis_custody_and_exact_ordinary_body() {
    use crate::executor::Executor;
    use iroha_data_model::{
        sorafs::reputation::ReputationJournalPolicyOriginV1 as Origin, transaction::Executable,
    };
    let mut world = World::new();
    let (id, value) = Account::new(account(1)).build(&account(1)).into_key_value();
    world.accounts.insert(id, value);
    let mut configuration = TestChainConfig::new(world, START);
    let manager = AccountId::new(configuration.genesis_key.public_key().clone());
    let policy = ReputationJournalAuthorityPolicyV1 {
        version: 1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: account(1),
        dispute_recorder_authority: account(1),
        token_recorder_authority: account(1),
        stream_token_delivery: StreamTokenReputationDeliveryTemplateV1::default(),
        max_source_age_ms: 3_600_000,
    };
    configuration.genesis_instructions.extend([
        Grant::account_permission(
            Permission::from(CanManageSorafsReputationJournalPolicy),
            manager,
        )
        .into(),
        SetSorafsReputationJournalAuthorityPolicy::new(policy.clone()).into(),
    ]);
    let prepared = CertifiedTestChain::prepare(configuration)
        .map_err(|failure| failure.error)
        .unwrap();
    let original_block = prepared.genesis.block();
    let (entry_index, original, instruction_index, instruction) = original_block
        .external_transactions()
        .enumerate()
        .find_map(|(entry_index, signed)| {
            let Executable::Instructions(instructions) = signed.instructions() else {
                return None;
            };
            instructions
                .iter()
                .enumerate()
                .find(|(_, item)| {
                    item.as_any()
                        .is::<SetSorafsReputationJournalAuthorityPolicy>()
                })
                .map(|(index, item)| (entry_index, signed, index, item))
        })
        .expect("signed genesis contains the governed policy");
    {
        let mut block = prepared.state.block(original_block.header());
        let mut tx = block.transaction();
        tx.current_network_entrypoint_hash = Some(original.hash_as_entrypoint());
        tx.tx_call_hash = Some(Hash::from(original.hash_as_entrypoint()));
        tx.current_tx_hash = Some(original.hash());
        tx.current_entrypoint_index = Some(entry_index.try_into().expect("entry index fits u64"));
        assert!(
            Executor::direct_reputation_policy_origin(
                &tx,
                original,
                instruction,
                instruction_index,
                true
            )
            .is_none(),
            "matching public hashes alone cannot replace the original opaque genesis scope"
        );
        assert!(
            SetSorafsReputationJournalAuthorityPolicy::new(policy.clone())
                .execute(original.authority(), &mut tx)
                .is_err()
        );
    }
    let chain = CertifiedTestChain::from_prepared(prepared)
        .map_err(|failure| failure.error)
        .unwrap();
    let view = chain.state().view();
    let retained =
        stream_token_delivery::read_policy(view.world(), policy.canonical_digest().unwrap())
            .unwrap();
    assert!(matches!(retained.origin, Origin::Genesis(ref execution) if execution.height == 1));
    drop(view);

    let fixture = ready();
    let state = fixture.chain.state();
    let direct: InstructionBox = SetSorafsReputationJournalAuthorityPolicy::new(policy).into();
    let signed = TransactionBuilder::new(
        fixture.policy.network_id,
        account(1),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([direct.clone()])
    .sign(key(1).private_key());
    let mut block = state.block(BlockHeader::new(
        (fixture.chain.height() + 1).try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        fixture.now(),
        0,
    ));
    let mut tx = block.transaction();
    tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
    tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
    tx.current_tx_hash = Some(signed.hash());
    tx.current_entrypoint_index = Some(0);
    assert!(matches!(
        Executor::direct_reputation_policy_origin(&tx, &signed, &direct, 0, true),
        Some(Origin::Network(_))
    ));
    assert!(
        Executor::direct_reputation_policy_origin(&tx, &signed, &direct, 0, false).is_none(),
        "contract/nested frames cannot inherit direct custody"
    );
    assert!(Executor::direct_reputation_policy_origin(&tx, &signed, &direct, 1, true).is_none());
    let foreign = TransactionBuilder::new(
        fixture.policy.network_id,
        account(4),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([direct.clone()])
    .sign(key(4).private_key());
    assert!(Executor::direct_reputation_policy_origin(&tx, &foreign, &direct, 0, true).is_none());
    tx.current_tx_hash = None;
    assert!(
        Executor::direct_reputation_policy_origin(&tx, &signed, &direct, 0, true).is_none(),
        "incomplete original custody fails closed"
    );
}

#[test]
fn ordinary_recorder_policy_rejects_extra_signed_instructions_without_changing_history() {
    let mut fixture = ready();
    let first = admit(&mut fixture, "policy-lineage-source");
    let original = source(&fixture, &first).0.recorder_policy;
    let mut replacement = original.policy.clone();
    replacement.revision += 1;
    replacement.predecessor_policy_digest = Some(original.policy_digest);
    let instruction: InstructionBox =
        SetSorafsReputationJournalAuthorityPolicy::new(replacement.clone()).into();
    assert!(!fixture.commit(
        1,
        vec![
                instruction.clone(),
                iroha_data_model::isi::Log::new(
                    iroha_logger::Level::INFO,
                    "forbidden policy companion".to_owned()
                )
                .into()
            ]
    ));
    assert_eq!(source(&fixture, &first).0.recorder_policy, original);
    assert!(fixture.commit(1, vec![instruction]));
    fixture.deliver_reputation(&first);
    assert_eq!(
        source(&fixture, &first).0.recorder_policy,
        original,
        "rotation preserves the original fee/TTL/recorder source interval"
    );
}

#[test]
fn native_delivery_excluded_is_original_no_append_and_cannot_be_cancelled_into_success() {
    let mut fixture = ready();
    let mut request = fixture.request("excluded-original");
    request.status = StreamTokenValidationStatusV1::Excluded(
        iroha_data_model::sorafs::reputation::StreamTokenExcludedKindV1::InvalidSignature,
    );
    let instruction = fixture.instruction(Action::Admit(request));
    assert!(fixture.commit(2, vec![instruction.into()]));
    let record = fixture.record(1);
    let (original, delivery) = source(&fixture, &record);
    assert!(original.intent.is_none());
    assert_eq!(delivery.disposition, Disposition::Excluded);
    assert!(!cancel(&mut fixture, record, 1));
    let ack = fixture.instruction(Action::Acknowledge(record));
    assert!(fixture.commit(2, vec![ack.into()]));
    assert_eq!(source(&fixture, &record), (original, delivery));
    assert!(fixture.record(1).lease_id.is_none());
}

#[test]
fn native_delivery_missing_source_never_authorizes_reconstruction_or_exact_admit_replay() {
    let mut fixture = ready();
    let request = fixture.request("missing-protocol-source");
    let instruction = fixture.instruction(Action::Admit(request.clone()));
    assert!(fixture.commit(2, vec![instruction.clone().into()]));
    let record = fixture.record(1);
    let state = fixture.chain.state();
    let now = fixture.now();
    let height = fixture.chain.height() + 1;
    let mut block = state.block(BlockHeader::new(
        height.try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        now,
        0,
    ));
    let mut tx = block.transaction();
    let source_key: iroha_model_base::state_path::StatePath = format!(
        "{}/{}/reputation/{:020}/source",
        storage::STATE_ROOT,
        hex::encode(record.admitted_under.gateway_id),
        record.outcome.binding.gateway_sequence
    )
    .parse()
    .unwrap();
    tx.world.smart_contract_state.remove(source_key);
    assert!(stream_token_delivery::read(tx.world(), &fixture.policy.network_id, &record).is_err());
    let before = tx
        .world()
        .smart_contract_state()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    let execution = StreamTokenGatewayExecutionV1 {
        height,
        transaction_hash: *Hash::new(b"source-missing-replay").as_ref(),
        entry_index: 0,
        instruction_index: 0,
        recorded_at_unix_ms: now,
        authority: account(2),
    };
    assert!(super::super::apply(&instruction, &account(2), &mut tx, &execution).is_err());
    let after = tx
        .world()
        .smart_contract_state()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        after, before,
        "missing protocol custody cannot be backfilled from an existing request"
    );
}

#[test]
fn native_delivery_source_watermark_prevents_same_block_policy_reassignment() {
    let mut fixture = ready();
    let first = admit(&mut fixture, "watermark-initial");
    let policy = source(&fixture, &first).0.recorder_policy;
    let mut next = policy.policy.clone();
    next.revision += 1;
    next.predecessor_policy_digest = Some(policy.policy_digest);
    let now = fixture.now();
    let request = fixture.request("watermark-concurrent");
    assert_eq!(request.validated_at_unix_ms, now);
    let admit = fixture.instruction(Action::Admit(request));
    let source_tx = fixture.chain.sign(&key(2), [admit.into()], now - 1);
    let rotate_tx = fixture.chain.sign(
        &key(1),
        [SetSorafsReputationJournalAuthorityPolicy::new(next.clone()).into()],
        now - 1,
    );
    assert_eq!(
        fixture.chain.commit_at(now, vec![source_tx, rotate_tx]),
        [true, false],
        "every committed source installs its watermark before a later policy action in the same block"
    );
    let second = fixture.record(2);
    assert_eq!(source(&fixture, &second).0.recorder_policy, policy);
    assert_eq!(
        stream_token_delivery::source_time_watermark(fixture.chain.state().view().world()).unwrap(),
        Some(now)
    );
    assert!(fixture.commit(
        1,
        vec![SetSorafsReputationJournalAuthorityPolicy::new(next).into()]
    ));
    fixture.deliver_reputation(&second);
    assert_eq!(source(&fixture, &second).0.recorder_policy, policy);
}

#[test]
fn native_delivery_capture_rejects_extraneous_multisig_envelopes_before_generic_validation() {
    use crate::executor::Executor;
    use iroha_data_model::transaction::{
        Executable,
        signed::{MultisigSignature, MultisigSignatures},
    };
    let mut fixture = ready();
    let record = admit(&mut fixture, "sole-ed25519-envelope");
    let original = signed_append(&fixture, &record);
    let Executable::Instructions(instructions) = original.instructions() else {
        unreachable!()
    };
    let instruction = instructions[0].clone();
    let state = fixture.chain.state();
    let mut block = state.block(BlockHeader::new(
        (fixture.chain.height() + 1).try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        fixture.now(),
        0,
    ));
    let mut tx = block.transaction();
    let bind = |tx: &mut crate::state::StateTransaction<'_, '_>, signed: &SignedTransaction| {
        tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
        tx.tx_call_hash = Some(Hash::from(signed.hash_as_entrypoint()));
        tx.current_tx_hash = Some(signed.hash());
        tx.current_entrypoint_index = Some(0);
    };
    bind(&mut tx, &original);
    assert_eq!(
        Executor::direct_stream_token_reputation_payload(&tx, &original, &instruction, true),
        Some(original.payload().clone())
    );
    let extra = key(3);
    let additional_signature =
        iroha_crypto::SignatureOf::try_new(extra.private_key(), original.payload()).unwrap();
    for bundle in [
        MultisigSignatures::new(Vec::new()),
        MultisigSignatures::new(vec![MultisigSignature::new(
            extra.public_key().clone(),
            additional_signature,
        )]),
    ] {
        let mut substituted = original.clone();
        substituted.set_multisig_signatures(bundle);
        assert_eq!(substituted.payload(), original.payload());
        assert_eq!(
            substituted.hash_as_entrypoint(),
            original.hash_as_entrypoint(),
            "unsigned identity cannot stand in for the complete authorization envelope"
        );
        bind(&mut tx, &substituted);
        // Call the source capture directly: neither queue acceptance nor generic signature
        // verification can hide a missing fixed-envelope check in this owner.
        assert_eq!(
            Executor::direct_stream_token_reputation_payload(&tx, &substituted, &instruction, true),
            None
        );
    }
}
