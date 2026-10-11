//! Lexical checkpoint epoch reuse with independent native, certificate and caller budgets.

use super::super::tests::Fixture;
use super::*;
use crate::{block::CommitCertificate, sumeragi::epoch::validation_counts};
use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeResourceError};
use std::cell::Cell;

const CHAIN: &str = "portable-finality-test";
const TEST_ALLOCATION_CEILING: usize = 64 * 1024 * 1024;

fn selected(fixture: &Fixture) -> (SumeragiFinalityVerifier, SumeragiFinalityCheckpoint) {
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    let checkpoint = verifier.export_checkpoint(&fixture.second).unwrap();
    (verifier, checkpoint)
}

// These finite test counters measure native admission, not physical pool custody. Every
// production inner decoder retains its original input-derived limits beneath this layer.
fn caller_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    )
}

#[test]
fn checkpoint_epoch_work_is_lexical_and_standalone_proofs_remain_independent() {
    let fixture = Fixture::new();
    let (verifier, checkpoint) = selected(&fixture);
    let original = checkpoint.encode_canonical().unwrap();
    let expected = verifier.verify_retained_decision(checkpoint.tip()).unwrap();
    assert!(!norito::core::decode_limits_active());
    // The exact context is reconstructed from authenticated signed source, not selected
    // by a cache key or epoch number. Public readers still validate it independently.
    let signed_epoch = authenticated_genesis(&fixture.genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_eq!(
        signed_epoch,
        checkpoint
            .tip()
            .decode_checked()
            .unwrap()
            .commitment
            .schedule
            .current
    );
    assert_eq!(signed_epoch, checkpoint.decisions[0].schedule.current);
    let before = validation_counts::calls();
    assert_eq!(
        authenticated_genesis(&fixture.genesis)
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
        signed_epoch
    );
    assert_eq!(validation_counts::calls() - before, 1);
    let before = validation_counts::calls();
    assert_eq!(fixture.verifier().genesis_epoch, signed_epoch);
    assert_eq!(validation_counts::calls() - before, 1);
    for _ in 0..2 {
        let before = validation_counts::calls();
        let (imported, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &checkpoint,
            &fixture.network,
            CHAIN,
        )
        .unwrap();
        assert_eq!(
            validation_counts::calls() - before,
            1,
            "one exact importer context also matches the authenticated signed genesis"
        );
        assert_eq!(tip.context_id(), expected.context_id());
        assert_eq!(
            tip.block().encode_wire().unwrap(),
            checkpoint.tip.block_wire
        );
        assert_eq!(tip.commitment(), expected.commitment());
        assert_eq!(
            imported.export_checkpoint(checkpoint.tip()).unwrap(),
            checkpoint
        );
    }
    // Neither public structural reading nor public retained authentication receives an
    // importer workspace. Their original result/core and successor/config scopes remain.
    let before = validation_counts::calls();
    checkpoint.tip().decode_checked().unwrap();
    assert_eq!(validation_counts::calls() - before, 2);
    let before = validation_counts::calls();
    verifier.verify_retained_decision(checkpoint.tip()).unwrap();
    assert_eq!(validation_counts::calls() - before, 4);
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn warmed_import_epoch_work_never_replaces_fresh_roster_or_quorum_authentication() {
    let fixture = Fixture::new();
    let (verifier, checkpoint) = selected(&fixture);
    let original = checkpoint.encode_canonical().unwrap();
    let mut wrong_roster = checkpoint.clone();
    wrong_roster.tip.committee[0].proof_of_possession[0] ^= 1;
    let mut wrong_quorum = checkpoint.clone();
    let mut block = decode_framed_signed_block(&wrong_quorum.tip.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut quorum: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    quorum.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header.clone(),
        norito::encode_canonical(&quorum).unwrap(),
        result.clone(),
        availability.clone(),
    )));
    wrong_quorum.tip.block_wire = block.encode_wire().unwrap();
    assert_eq!(wrong_quorum.tip.block_header, checkpoint.tip.block_header);
    assert_ne!(wrong_quorum.tip.block_wire, checkpoint.tip.block_wire);
    assert_eq!(wrong_quorum.decisions, checkpoint.decisions);
    let changed = block.commit_certificate().unwrap();
    assert_eq!(changed.consensus_header(), header);
    assert_eq!(changed.result_preimage(), result);
    assert_eq!(changed.availability(), availability);

    let calls = Cell::new(0_u32);
    for changed in [&wrong_roster, &wrong_quorum] {
        let bytes = changed.encode_canonical().unwrap();
        let expected = verifier
            .verify_retained_decision(changed.tip())
            .unwrap_err();
        let before = validation_counts::calls();
        let refusal = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
            changed,
            &fixture.network,
            CHAIN,
            |_, _, _| calls.set(calls.get() + 1),
        )
        .unwrap_err();
        let FinalityReadError::Invalid(actual) = refusal else {
            panic!("{refusal:?}");
        };
        assert_eq!(actual, expected, "the original witness gate still refuses");
        assert_eq!(validation_counts::calls() - before, 1);
        assert_eq!(calls.get(), 0);
        assert_eq!(changed.encode_canonical().unwrap(), bytes);
    }
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &checkpoint,
        &fixture.network,
        CHAIN,
    )
    .unwrap();
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        checkpoint.tip.block_wire
    );
    assert_eq!(
        verifier.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn positive_outer_budget_keeps_original_independent_import_charges() {
    let fixture = Fixture::new();
    let (_, checkpoint) = selected(&fixture);
    let original = checkpoint.encode_canonical().unwrap();
    // An active owner deliberately selects the original independent path. Measure only
    // its full import; encoding/export and comparison remain outside both measured scopes.
    let baseline = DecodeBudgetContext::new(caller_limits(TEST_ALLOCATION_CEILING));
    let calls = Cell::new(0_u32);
    let consume = |_: &SumeragiFinalityCheckpoint,
                   verifier: SumeragiFinalityVerifier,
                   tip: VerifiedSumeragiBlock| {
        calls.set(calls.get() + 1);
        (verifier, tip)
    };
    let before = validation_counts::calls();
    let (expected_verifier, expected_tip) = baseline
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &checkpoint,
                &fixture.network,
                CHAIN,
                consume,
            )
        })
        .unwrap();
    assert_eq!(validation_counts::calls() - before, 7);
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 0);
    let cap = usize::try_from(charge).unwrap();
    assert!(cap < TEST_ALLOCATION_CEILING);
    let strict = DecodeBudgetContext::new(caller_limits(cap));
    assert_eq!(calls.get(), 1);
    let before = validation_counts::calls();
    let (imported, tip) = strict
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &checkpoint,
                &fixture.network,
                CHAIN,
                consume,
            )
        })
        .unwrap();
    assert_eq!(validation_counts::calls() - before, 7);
    assert_eq!(strict.consumed_allocated_bytes(), charge);
    assert_eq!(calls.get(), 2);
    assert_eq!(tip.context_id(), expected_tip.context_id());
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        checkpoint.tip.block_wire
    );
    assert_eq!(tip.commitment(), expected_tip.commitment());
    assert_eq!(
        imported.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );
    assert_eq!(
        expected_verifier
            .export_checkpoint(checkpoint.tip())
            .unwrap(),
        checkpoint
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn positive_outer_refusal_keeps_native_provenance_and_original_source_retry() {
    let fixture = Fixture::new();
    let (_, checkpoint) = selected(&fixture);
    let original = checkpoint.encode_canonical().unwrap();
    // Measure the actual original bounds prefix, including both optional memo insertions.
    // A total-success-minus-one cap could merely decline optional retention and still pass.
    let prefix = DecodeBudgetContext::new(caller_limits(TEST_ALLOCATION_CEILING));
    prefix.with(|| checkpoint.validate_bounds()).unwrap();
    let prefix_charge = prefix.consumed_allocated_bytes();
    assert!(prefix_charge > 0);
    let cap = usize::try_from(prefix_charge)
        .unwrap()
        .checked_add(1)
        .unwrap();
    assert!(cap < TEST_ALLOCATION_CEILING);
    let expected_budget = DecodeBudgetContext::new(caller_limits(cap));
    let expected = expected_budget
        .with(|| {
            checkpoint.validate_bounds().unwrap();
            need(
                checkpoint.network_id == fixture.network && checkpoint.chain_id == CHAIN,
                "checkpoint differs from independently selected network or chain",
            )
            .unwrap();
            norito::core::with_decode_limits_scope(
                norito::canonical_decode_limits(checkpoint.genesis_wire.len()),
                || decode_framed_signed_block(&checkpoint.genesis_wire),
            )
        })
        .unwrap_err();
    assert_eq!(expected.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let expected_resource = expected.into_error().decode_resource_error().unwrap();
    assert!(matches!(
        expected_resource,
        DecodeResourceError::TotalAllocationExceeded { attempted, limit }
            if attempted > limit && limit == cap as u64
    ));
    let actual_budget = DecodeBudgetContext::new(caller_limits(cap));
    let calls = Cell::new(0_u32);
    let refusal = actual_budget
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &checkpoint,
                &fixture.network,
                CHAIN,
                |_, _, _| calls.set(calls.get() + 1),
            )
        })
        .unwrap_err();
    let FinalityReadError::DecodeResource(actual) = refusal else {
        panic!("{refusal:?}");
    };
    assert_eq!(actual.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        actual.into_error().decode_resource_error(),
        Some(expected_resource)
    );
    let consumed = actual_budget.consumed_allocated_bytes();
    assert!(consumed >= prefix_charge && consumed > 0);
    assert_eq!(consumed, expected_budget.consumed_allocated_bytes());
    assert_eq!(calls.get(), 0);
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
    let (imported, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
        &checkpoint,
        &fixture.network,
        CHAIN,
        |_, verifier, tip| {
            calls.set(calls.get() + 1);
            (verifier, tip)
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        checkpoint.tip.block_wire
    );
    assert_eq!(
        imported.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );
    assert_eq!(actual_budget.consumed_allocated_bytes(), consumed);
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn signed_genesis_signature_refusal_survives_a_matching_import_epoch() {
    use crate::block::{BlockSignature, BlockSignatures};
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};

    let fixture = Fixture::new();
    let (verifier, checkpoint) = selected(&fixture);
    let original = checkpoint.encode_canonical().unwrap();
    let original_genesis = fixture.genesis.encode_wire().unwrap();
    let mut changed = fixture.genesis.clone();
    let wrong = KeyPair::from_seed(vec![93; 32], Algorithm::Ed25519);
    let signature = SignatureOf::try_from_hash(wrong.private_key(), changed.hash()).unwrap();
    changed
        .replace_signatures(
            BlockSignatures::try_from_iter([BlockSignature::new(0, signature)]).unwrap(),
        )
        .unwrap();
    assert_eq!(changed.header(), fixture.genesis.header());
    assert_eq!(changed.hash(), fixture.genesis.hash());
    assert_eq!(
        changed.external_transactions().collect::<Vec<_>>(),
        fixture.genesis.external_transactions().collect::<Vec<_>>()
    );
    assert_eq!(
        genesis_registrations(&changed).unwrap(),
        genesis_registrations(&fixture.genesis).unwrap()
    );
    assert_ne!(changed.encode_wire().unwrap(), original_genesis);
    let before = validation_counts::calls();
    let expected =
        SumeragiFinalityVerifier::new(&changed, CHAIN, fixture.validators.clone()).unwrap_err();
    assert!(matches!(
        &expected,
        FinalityReadError::Genesis(GenesisReadError::Invalid(_))
    ));
    assert_eq!(
        validation_counts::calls() - before,
        0,
        "source signature refuses before epoch validation"
    );
    let mut selected = checkpoint.clone();
    selected.genesis_wire = changed.encode_wire().unwrap();
    assert_eq!(selected.network_id, checkpoint.network_id);
    assert_eq!(selected.decisions, checkpoint.decisions);
    assert_eq!(selected.tip, checkpoint.tip);
    let selected_bytes = selected.encode_canonical().unwrap();
    let calls = Cell::new(0_u32);
    let before = validation_counts::calls();
    let refusal = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
        &selected,
        &fixture.network,
        CHAIN,
        |_, _, _| calls.set(calls.get() + 1),
    )
    .unwrap_err();
    assert!(matches!(
        &refusal,
        FinalityReadError::Genesis(GenesisReadError::Invalid(_))
    ));
    assert_eq!(refusal.to_string(), expected.to_string());
    assert_eq!(
        validation_counts::calls() - before,
        1,
        "bounds warms the matching context before original signature refusal"
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(selected.encode_canonical().unwrap(), selected_bytes);
    let before = validation_counts::calls();
    let (imported, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
        &checkpoint,
        &fixture.network,
        CHAIN,
        |_, verifier, tip| {
            calls.set(calls.get() + 1);
            (verifier, tip)
        },
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        tip.commitment(),
        verifier
            .verify_retained_decision(checkpoint.tip())
            .unwrap()
            .commitment()
    );
    assert_eq!(
        imported.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );
    assert_eq!(fixture.genesis.encode_wire().unwrap(), original_genesis);
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn genesis_reconstruction_still_authenticates_transactions_and_changed_signed_credentials() {
    use crate::{
        isi::{InstructionBox, RegisterBox, RegisterPeerWithPop},
        transaction::{Executable, FeePaymentIntent, TransactionBuilder},
    };
    use iroha_crypto::{Algorithm, KeyPair, Signature};

    let fixture = Fixture::new();
    let original_wire = fixture.genesis.encode_wire().unwrap();
    let epoch = authenticated_genesis(&fixture.genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    let mut validation = EpochValidationScope::new();
    validation.core_epoch(&epoch).unwrap();
    let authority = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let wrong = KeyPair::from_seed(vec![94; 32], Algorithm::Ed25519);
    let original_transaction = fixture.genesis.external_transactions().next().unwrap();
    assert_eq!(
        original_transaction.authority().try_signatory(),
        Some(authority.public_key())
    );
    let Executable::Instructions(instructions) = original_transaction.instructions() else {
        panic!("fixture must use signed instructions");
    };
    let builder = TransactionBuilder::new_genesis(
        original_transaction.authority().clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions(instructions.clone());
    let hash = builder.payload_hash_bytes();
    let wrong_signature = Signature::try_new(wrong.private_key(), &hash).unwrap();
    wrong_signature.verify(wrong.public_key(), &hash).unwrap();
    let transaction = builder.build_with_signature(wrong_signature);
    assert!(transaction.verify_signature().is_err());
    let wrong_transaction =
        SignedBlock::try_genesis(vec![transaction], authority.private_key(), None, None).unwrap();
    wrong_transaction
        .signatures()
        .next()
        .unwrap()
        .signature()
        .verify_hash(authority.public_key(), wrong_transaction.hash())
        .unwrap();
    assert_eq!(
        genesis_registrations(&wrong_transaction).unwrap(),
        genesis_registrations(&fixture.genesis).unwrap()
    );
    let before = validation_counts::calls();
    let expected = authenticated_genesis(&wrong_transaction)
        .map(|genesis| genesis.into_parts().0)
        .unwrap_err();
    assert_eq!(validation_counts::calls() - before, 0);
    let before = validation_counts::calls();
    let actual = super::super::genesis::authenticated_genesis_with_validation(
        &wrong_transaction,
        Some(&validation),
    )
    .map(|genesis| genesis.into_parts().0)
    .unwrap_err();
    assert!(matches!(&actual, GenesisReadError::Invalid(_)));
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(
        validation_counts::calls() - before,
        0,
        "a warm scope never supplies a transaction signature verdict"
    );

    // Every signature is genuine here. The altered signed PoP reaches the reconstructed
    // context's original validation-only miss, rather than an earlier signature failure.
    let mut replacements = 0;
    let changed_instructions: Vec<InstructionBox> = instructions
        .iter()
        .map(|instruction| {
            if let Some(RegisterBox::Peer(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
                && replacements == 0
            {
                replacements += 1;
                let mut register: RegisterPeerWithPop = register.clone();
                register.pop[0] ^= 1;
                return register.into();
            }
            instruction.clone()
        })
        .collect();
    assert_eq!(replacements, 1);
    let transaction = TransactionBuilder::new_genesis(
        original_transaction.authority().clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions(changed_instructions)
    .sign(authority.private_key());
    transaction.verify_signature().unwrap();
    let wrong_credential =
        SignedBlock::try_genesis(vec![transaction], authority.private_key(), None, None).unwrap();
    wrong_credential
        .signatures()
        .next()
        .unwrap()
        .signature()
        .verify_hash(authority.public_key(), wrong_credential.hash())
        .unwrap();
    assert_ne!(
        genesis_registrations(&wrong_credential).unwrap(),
        genesis_registrations(&fixture.genesis).unwrap()
    );
    let before = validation_counts::calls();
    let expected = authenticated_genesis(&wrong_credential)
        .map(|genesis| genesis.into_parts().0)
        .unwrap_err();
    assert_eq!(
        validation_counts::calls() - before,
        1,
        "authenticated source reaches the actual PoP validator"
    );
    let before = validation_counts::calls();
    let actual = super::super::genesis::authenticated_genesis_with_validation(
        &wrong_credential,
        Some(&validation),
    )
    .map(|genesis| genesis.into_parts().0)
    .unwrap_err();
    assert!(matches!(&actual, GenesisReadError::Invalid(_)));
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(validation_counts::calls() - before, 1);
    // A genuinely signed different source remains valid but is not inserted by this
    // final validation-only step. Each repeated reconstruction still validates it anew.
    let mut changed_instructions = instructions.to_vec();
    changed_instructions.push(
        crate::isi::Log::new(
            crate::level::Level::INFO,
            "different signed genesis body".into(),
        )
        .into(),
    );
    let transaction = TransactionBuilder::new_genesis(
        original_transaction.authority().clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions(changed_instructions)
    .sign(authority.private_key());
    let other_genesis =
        SignedBlock::try_genesis(vec![transaction], authority.private_key(), None, None).unwrap();
    assert_ne!(other_genesis.hash(), fixture.genesis.hash());
    let other_wire = other_genesis.encode_wire().unwrap();
    let expected = authenticated_genesis(&other_genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_ne!(expected, epoch);
    for _ in 0..2 {
        let before = validation_counts::calls();
        let reconstructed = super::super::genesis::authenticated_genesis_with_validation(
            &other_genesis,
            Some(&validation),
        )
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
        assert_eq!(validation_counts::calls() - before, 1);
        assert_eq!(reconstructed, expected);
    }
    let before = validation_counts::calls();
    let resumed = SumeragiFinalityVerifier::new_with_validation(
        &other_genesis,
        CHAIN,
        fixture.validators.clone(),
        Some(&validation),
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(resumed.genesis_epoch, expected);
    assert_eq!(other_genesis.encode_wire().unwrap(), other_wire);
    let before = validation_counts::calls();
    assert_eq!(
        super::super::genesis::authenticated_genesis_with_validation(
            &fixture.genesis,
            Some(&validation)
        )
        .map(|genesis| genesis.into_parts().0)
        .unwrap(),
        epoch
    );
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(fixture.genesis.encode_wire().unwrap(), original_wire);
}

#[test]
fn operation_epoch_workspace_reuses_equal_contexts_across_distinct_canonical_imports() {
    let fixture = Fixture::new();
    let mut prefix = fixture.verifier();
    let first_tip_id = prefix.verify(&fixture.first).unwrap().context_id();
    let first = prefix.export_checkpoint(&fixture.first).unwrap();
    let second_tip_id = prefix.verify(&fixture.second).unwrap().context_id();
    assert_ne!(first_tip_id, second_tip_id);
    let second = prefix.export_checkpoint(&fixture.second).unwrap();
    let first_wire = first.encode_canonical().unwrap();
    let second_wire = second.encode_canonical().unwrap();
    assert_ne!(first_wire, second_wire);
    assert_eq!(
        first.decisions[0].schedule.current,
        second.decisions[0].schedule.current
    );
    let expected_context = first.decisions[0].schedule.current.context_id().unwrap();
    let callbacks = Cell::new(0_u32);
    {
        let mut validation = EpochValidationScope::new();
        for (index, (bytes, expected, expected_tip_id)) in [
            (&first_wire, &first, first_tip_id),
            (&second_wire, &second, second_tip_id),
            (&first_wire, &first, first_tip_id),
        ]
        .into_iter()
        .enumerate()
        {
            let before = validation_counts::calls();
            let decoded = SumeragiFinalityCheckpoint::decode_canonical_with_validation(
                bytes,
                Some(&mut validation),
            )
            .unwrap();
            assert_eq!(&decoded, expected);
            let (imported, tip) =
                SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
                    decoded,
                    &fixture.network,
                    CHAIN,
                    Some(&mut validation),
                    |source, verifier, tip| {
                        callbacks.set(callbacks.get().checked_add(1).unwrap());
                        assert_eq!(&source, expected);
                        (verifier, tip)
                    },
                )
                .unwrap();
            assert_eq!(validation_counts::calls() - before, usize::from(index == 0));
            assert_eq!(tip.block().encode_wire().unwrap(), expected.tip.block_wire);
            assert_eq!(tip.context_id(), expected_tip_id);
            assert_eq!(
                tip.commitment().schedule.current.context_id().unwrap(),
                expected_context
            );
            assert_eq!(
                imported.export_checkpoint(expected.tip()).unwrap(),
                *expected
            );
        }
        // Exporting expected values validates independently. The counter above ends before
        // export; the further decode/import below likewise counts only its own native work.
        let before = validation_counts::calls();
        let decoded = SumeragiFinalityCheckpoint::decode_canonical_with_validation(
            &second_wire,
            Some(&mut validation),
        )
        .unwrap();
        SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
            decoded,
            &fixture.network,
            CHAIN,
            Some(&mut validation),
            |_, _, tip| {
                callbacks.set(callbacks.get().checked_add(1).unwrap());
                assert_eq!(tip.block().encode_wire().unwrap(), second.tip.block_wire);
            },
        )
        .unwrap();
        assert_eq!(validation_counts::calls() - before, 0);
    }
    assert_eq!(callbacks.get(), 4);
    // A later owner has no access to the dropped operation's entries.
    let mut next = EpochValidationScope::new();
    let before = validation_counts::calls();
    let decoded =
        SumeragiFinalityCheckpoint::decode_canonical_with_validation(&second_wire, Some(&mut next))
            .unwrap();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        decoded,
        &fixture.network,
        CHAIN,
        Some(&mut next),
        |_, _, _| (),
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(first.encode_canonical().unwrap(), first_wire);
    assert_eq!(second.encode_canonical().unwrap(), second_wire);
}

#[test]
fn operation_epoch_workspace_never_accepts_context_substitution_or_fresh_quorum_corruption() {
    let fixture = Fixture::new();
    let (verifier, checkpoint) = selected(&fixture);
    let bytes = checkpoint.encode_canonical().unwrap();
    let mut validation = EpochValidationScope::new();
    let decoded =
        SumeragiFinalityCheckpoint::decode_canonical_with_validation(&bytes, Some(&mut validation))
            .unwrap();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        decoded,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, _| (),
    )
    .unwrap();
    // The epoch identity fields are untouched. A different original PoP must miss full-value
    // equality and enter the real validator, rather than reuse a digest or epoch number.
    let mut changed_context = checkpoint.clone();
    changed_context.decisions[0].schedule.current.committee[0].proof_of_possession[0] ^= 1;
    let expected = changed_context.validate_bounds().unwrap_err();
    let before = validation_counts::calls();
    assert_eq!(
        changed_context
            .validate_bounds_with_validation(Some(&mut validation))
            .unwrap_err(),
        expected
    );
    assert_eq!(validation_counts::calls() - before, 1);
    assert_ne!(
        changed_context.decisions[0].schedule.current,
        checkpoint.decisions[0].schedule.current
    );

    let mut wrong_roster = checkpoint.clone();
    wrong_roster.tip.committee[0].proof_of_possession[0] ^= 1;
    let mut wrong_quorum = checkpoint.clone();
    let mut block = decode_framed_signed_block(&wrong_quorum.tip.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut quorum: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    quorum.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&quorum).unwrap(),
        result,
        availability,
    )));
    wrong_quorum.tip.block_wire = block.encode_wire().unwrap();
    assert_ne!(wrong_quorum.tip.block_wire, checkpoint.tip.block_wire);
    assert_eq!(wrong_quorum.decisions, checkpoint.decisions);
    let callbacks = Cell::new(0_u32);
    for changed in [&wrong_roster, &wrong_quorum] {
        let expected = verifier
            .verify_retained_decision(changed.tip())
            .unwrap_err();
        let before = validation_counts::calls();
        let error = SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
            changed,
            &fixture.network,
            CHAIN,
            Some(&mut validation),
            |_, _, _| callbacks.set(callbacks.get() + 1),
        )
        .unwrap_err();
        let FinalityReadError::Invalid(actual) = error else {
            panic!("{error:?}")
        };
        assert_eq!(actual, expected);
        assert_eq!(validation_counts::calls() - before, 0);
        assert_eq!(callbacks.get(), 0);
    }
    let before = validation_counts::calls();
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        &checkpoint,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, verifier, tip| {
            callbacks.set(callbacks.get() + 1);
            (verifier, tip)
        },
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(callbacks.get(), 1);
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        checkpoint.tip.block_wire
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), bytes);
}

#[test]
fn warmed_operation_epoch_workspace_preserves_late_positive_outer_charges_and_typed_refusal() {
    let fixture = Fixture::new();
    let (_, checkpoint) = selected(&fixture);
    let bytes = checkpoint.encode_canonical().unwrap();
    let mut validation = EpochValidationScope::new();
    let decoded =
        SumeragiFinalityCheckpoint::decode_canonical_with_validation(&bytes, Some(&mut validation))
            .unwrap();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        decoded,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, _| (),
    )
    .unwrap();
    // Install this finite owner AFTER warming. Include identical canonical decode and import
    // in each measurement; encoding/export stays outside both measured regions.
    let baseline = DecodeBudgetContext::new(caller_limits(TEST_ALLOCATION_CEILING));
    let (expected, expected_tip) = baseline
        .with(|| {
            let decoded = SumeragiFinalityCheckpoint::decode_canonical(&bytes).unwrap();
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                decoded,
                &fixture.network,
                CHAIN,
                |_, verifier, tip| (verifier, tip),
            )
        })
        .unwrap();
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 0 && charge < TEST_ALLOCATION_CEILING as u64);
    let strict = DecodeBudgetContext::new(caller_limits(usize::try_from(charge).unwrap()));
    let callbacks = Cell::new(0_u32);
    let (imported, tip) = strict
        .with(|| {
            let decoded = SumeragiFinalityCheckpoint::decode_canonical_with_validation(
                &bytes,
                Some(&mut validation),
            )
            .unwrap();
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
                decoded,
                &fixture.network,
                CHAIN,
                Some(&mut validation),
                |_, verifier, tip| {
                    callbacks.set(callbacks.get() + 1);
                    (verifier, tip)
                },
            )
        })
        .unwrap();
    assert_eq!(strict.consumed_allocated_bytes(), charge);
    assert_eq!(callbacks.get(), 1);
    assert_eq!(tip.commitment(), expected_tip.commitment());
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        checkpoint.tip.block_wire
    );
    assert_eq!(
        imported.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );
    assert_eq!(
        expected.export_checkpoint(checkpoint.tip()).unwrap(),
        checkpoint
    );

    // Measure the original bounds prefix then force the genuine signed-genesis allocation
    // refusal at a positive ceiling. Optional insertion failures are not a refusal oracle.
    let prefix = DecodeBudgetContext::new(caller_limits(TEST_ALLOCATION_CEILING));
    prefix.with(|| checkpoint.validate_bounds()).unwrap();
    let cap = usize::try_from(prefix.consumed_allocated_bytes())
        .unwrap()
        .checked_add(1)
        .unwrap();
    assert!(cap > 1 && cap < TEST_ALLOCATION_CEILING);
    let original_budget = DecodeBudgetContext::new(caller_limits(cap));
    let original_error = original_budget
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &checkpoint,
                &fixture.network,
                CHAIN,
                |_, _, _| (),
            )
        })
        .unwrap_err();
    let actual_budget = DecodeBudgetContext::new(caller_limits(cap));
    let actual_error = actual_budget
        .with(|| {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
                &checkpoint,
                &fixture.network,
                CHAIN,
                Some(&mut validation),
                |_, _, _| callbacks.set(callbacks.get() + 1),
            )
        })
        .unwrap_err();
    let (
        FinalityReadError::DecodeResource(original_error),
        FinalityReadError::DecodeResource(actual_error),
    ) = (original_error, actual_error)
    else {
        panic!("original signed-genesis resource provenance required")
    };
    assert_eq!(
        original_error.kind(),
        DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(actual_error.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        actual_error.into_error().decode_resource_error(),
        original_error.into_error().decode_resource_error()
    );
    assert_eq!(
        actual_budget.consumed_allocated_bytes(),
        original_budget.consumed_allocated_bytes()
    );
    assert!(actual_budget.consumed_allocated_bytes() > 0);
    assert_eq!(callbacks.get(), 1);
    let before = validation_counts::calls();
    let decoded =
        SumeragiFinalityCheckpoint::decode_canonical_with_validation(&bytes, Some(&mut validation))
            .unwrap();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        decoded,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, tip| {
            assert_eq!(
                tip.block().encode_wire().unwrap(),
                checkpoint.tip.block_wire
            )
        },
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(checkpoint.encode_canonical().unwrap(), bytes);
}

#[test]
fn warmed_operation_epoch_workspace_keeps_signed_genesis_refusal_and_original_retry() {
    use crate::block::{BlockSignature, BlockSignatures};
    use iroha_crypto::{Algorithm, KeyPair, SignatureOf};

    let fixture = Fixture::new();
    let (_, checkpoint) = selected(&fixture);
    let bytes = checkpoint.encode_canonical().unwrap();
    let mut validation = EpochValidationScope::new();
    let decoded =
        SumeragiFinalityCheckpoint::decode_canonical_with_validation(&bytes, Some(&mut validation))
            .unwrap();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        decoded,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, _| (),
    )
    .unwrap();
    let mut changed = fixture.genesis.clone();
    let wrong = KeyPair::from_seed(vec![95; 32], Algorithm::Ed25519);
    let signature = SignatureOf::try_from_hash(wrong.private_key(), changed.hash()).unwrap();
    changed
        .replace_signatures(
            BlockSignatures::try_from_iter([BlockSignature::new(0, signature)]).unwrap(),
        )
        .unwrap();
    assert_eq!(changed.hash(), fixture.genesis.hash());
    assert_eq!(
        genesis_registrations(&changed).unwrap(),
        genesis_registrations(&fixture.genesis).unwrap()
    );
    let mut substituted = checkpoint.clone();
    substituted.genesis_wire = changed.encode_wire().unwrap();
    assert_eq!(substituted.decisions, checkpoint.decisions);
    let expected =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&substituted, &fixture.network, CHAIN)
            .unwrap_err();
    assert!(matches!(
        &expected,
        FinalityReadError::Genesis(GenesisReadError::Invalid(_))
    ));
    let calls = Cell::new(0_u32);
    let before = validation_counts::calls();
    let actual = SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        &substituted,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, _| calls.set(calls.get() + 1),
    )
    .unwrap_err();
    assert_eq!(actual.to_string(), expected.to_string());
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(calls.get(), 0);
    let before = validation_counts::calls();
    SumeragiFinalityVerifier::from_trusted_checkpoint_with_validation_consumer(
        &checkpoint,
        &fixture.network,
        CHAIN,
        Some(&mut validation),
        |_, _, tip| {
            calls.set(calls.get() + 1);
            assert_eq!(
                tip.block().encode_wire().unwrap(),
                checkpoint.tip.block_wire
            );
        },
    )
    .unwrap();
    assert_eq!(validation_counts::calls() - before, 0);
    assert_eq!(calls.get(), 1);
    assert_eq!(checkpoint.encode_canonical().unwrap(), bytes);
}
