//! Canonical AXT binding, transport and independently supplied context regressions.

use super::*;
use crate::proof::VerifyLimits;
use crate::test_producer_funding::prove_axt_bound_batch;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::id::AssetDefinitionId,
    fastpq::{TransferDeltaTranscript, TransferSmtWitness, TransferTranscript},
    nexus::{AxtAssetIncarnationV1, AxtHandleIssuerContextV1, AxtHandleReplayKey},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::Quantity;
fn finalized_transaction(seed: u8) -> TransactionEntrypoint {
    let signer = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    let network = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(
        Hash::new(b"axt-finalized-verifier-network"),
    ));
    let mut builder = iroha_data_model::transaction::TransactionBuilder::new(
        network,
        AccountId::new(signer.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(std::time::Duration::from_millis(1_000));
    TransactionEntrypoint::External(builder.try_sign(signer.private_key()).expect("sign entry"))
}

fn finalized_test_anchor(
    inputs: PublicInputs,
    transactions: &[TransactionEntrypoint],
) -> AxtFinalizedSpendAnchorV1 {
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
        iroha_data_model::block::BlockHeader,
    >::from_untyped_unchecked(
        Hash::new(b"axt-finalized-verifier-network"),
    ));
    AxtFinalizedSpendAnchorV1 {
        network_id,
        genesis_hash: *network_id.as_bytes(),
        dataspace_id: DataSpaceId::new(7),
        lane_id: LaneId::new(1),
        lane_incarnation: Hash::new(b"test lane incarnation"),
        finalized_height: 42,
        block_header_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"test block")),
        quorum_certificate_digest: Hash::new(b"test QC"),
        committee_digest: Hash::new(b"test committee"),
        pre_state_root: Hash::prehashed(inputs.old_root),
        post_state_root: Hash::prehashed(inputs.new_root),
        transaction_set_digest: axt_ordered_transaction_set_digest_v1(transactions).unwrap(),
        da_manifest_digest: Hash::new(b"test DA manifest"),
    }
}

fn finalized_proof_fixture() -> &'static (
    AxtProofEnvelope,
    AxtFinalizedSpendAnchorV1,
    Vec<TransactionEntrypoint>,
) {
    static FIXTURE: std::sync::OnceLock<(
        AxtProofEnvelope,
        AxtFinalizedSpendAnchorV1,
        Vec<TransactionEntrypoint>,
    )> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let transactions = vec![finalized_transaction(71), finalized_transaction(72)];
        let mut binding = sample_binding();
        binding.claim_type = "tx_predicate".into();
        binding.source_tx_commitment = hex::encode(transactions[0].execution_call_hash().as_ref());
        let mut batch = real_transfer_claim_batch(&binding);
        // This is a verifier boundary fixture, not evidence of a real finalized WSV.
        let anchor = finalized_test_anchor(batch.public_inputs, &transactions);
        batch.public_inputs.tx_set_hash = anchor.transaction_set_digest.into();
        bind_axt_batch_with_proof_metadata(
            &mut batch,
            &binding,
            [0x42; 32],
            Some(anchor.da_manifest_digest.into()),
            None,
            Some(100),
        )
        .expect("bind finalized fixture");
        let artifact = compact::prepare(&batch, &binding).expect("prepare finalized fixture");
        let mut envelope =
            envelope_with_payload(binding, norito::encode_canonical(&artifact).unwrap());
        envelope.da_commitment = Some(anchor.da_manifest_digest.into());
        (envelope, anchor, transactions)
    })
}

#[test]
fn anchored_axt_verifier_checks_exact_public_roots_and_ordered_wires_before_child_proof() {
    let (envelope, anchor, transactions) = finalized_proof_fixture();
    let artifact = compact::decode(&envelope.proof).unwrap();
    assert_eq!(
        artifact.statement.public_inputs.old_root,
        *anchor.pre_state_root.as_ref()
    );
    assert_eq!(
        artifact.statement.public_inputs.new_root,
        *anchor.post_state_root.as_ref()
    );
    assert_eq!(
        artifact.statement.public_inputs.tx_set_hash,
        *anchor.transaction_set_digest.as_ref()
    );
    assert_eq!(artifact.mirrors.expiry_slot, Some(100));
    // The deliberately empty child fails only after the authoritative context
    // matches. Public transport is not presented as a valid cryptographic proof.
    assert!(
        verify_axt_proof_envelope_against_anchor_v1(envelope, Some(100), anchor, transactions)
            .is_err()
    );
    for expiry in [None, Some(0), Some(101)] {
        assert!(
            verify_axt_proof_envelope_against_anchor_v1(envelope, expiry, anchor, transactions)
                .is_err()
        );
    }
}

#[test]
fn anchored_axt_verifier_rejects_root_dataspace_da_and_public_set_substitution() {
    let (envelope, anchor, transactions) = finalized_proof_fixture();
    for (field, changed) in [
        (
            "old_root",
            AxtFinalizedSpendAnchorV1 {
                pre_state_root: Hash::new(b"foreign WSV pre-root"),
                ..*anchor
            },
        ),
        (
            "new_root",
            AxtFinalizedSpendAnchorV1 {
                post_state_root: Hash::new(b"foreign WSV post-root"),
                ..*anchor
            },
        ),
        (
            "dataspace",
            AxtFinalizedSpendAnchorV1 {
                dataspace_id: DataSpaceId::new(8),
                ..*anchor
            },
        ),
        (
            "DA manifest",
            AxtFinalizedSpendAnchorV1 {
                da_manifest_digest: Hash::new(b"foreign DA"),
                ..*anchor
            },
        ),
    ] {
        let error = verify_axt_proof_envelope_against_anchor_v1(
            envelope,
            Some(100),
            &changed,
            transactions,
        )
        .expect_err("foreign authoritative context must fail");
        assert!(matches!(error, Error::InvalidAxtBinding { details } if details.contains(field)));
    }
    let mut payload = decode_axt_fastpq_payload(&envelope.proof).unwrap();
    payload.statement.public_inputs.tx_set_hash = Hash::new(b"old sorted execution digest").into();
    let mut changed = envelope.clone();
    changed.proof = encode_canonical_norito(&payload).unwrap();
    let error =
        verify_axt_proof_envelope_against_anchor_v1(&changed, Some(100), anchor, transactions)
            .expect_err("wrong public set fails before batch seal or proof replay");
    assert!(
        matches!(error, Error::InvalidAxtBinding { details } if details.contains("tx_set_hash"))
    );
}

#[test]
fn anchored_axt_verifier_requires_exact_execution_membership_and_wire_order() {
    let (envelope, anchor, transactions) = finalized_proof_fixture();
    let reversed = vec![transactions[1].clone(), transactions[0].clone()];
    let error = verify_axt_proof_envelope_against_anchor_v1(envelope, Some(100), anchor, &reversed)
        .unwrap_err();
    assert!(
        matches!(error, Error::InvalidAxtBinding { details } if details.contains("ordered transaction wires"))
    );
    for entries in [
        vec![transactions[1].clone()],
        vec![transactions[0].clone(), transactions[0].clone()],
    ] {
        let changed = AxtFinalizedSpendAnchorV1 {
            transaction_set_digest: axt_ordered_transaction_set_digest_v1(&entries).unwrap(),
            ..*anchor
        };
        let error =
            verify_axt_proof_envelope_against_anchor_v1(envelope, Some(100), &changed, &entries)
                .unwrap_err();
        assert!(
            matches!(error, Error::InvalidAxtBinding { details } if details.contains("exactly once"))
        );
    }
    let mut opaque = envelope.clone();
    opaque.fastpq_binding.as_mut().unwrap().claim_type = "authorization".into();
    assert!(matches!(
        verify_axt_proof_envelope_against_anchor_v1(&opaque, Some(100), anchor, transactions),
        Err(Error::InvalidProofSemantics { .. }),
    ));
}

#[test]
fn anchored_axt_verifier_derives_sealed_reveal_execution_from_exact_outer_wire() {
    let TransactionEntrypoint::External(transaction) = finalized_transaction(73) else {
        unreachable!()
    };
    let execution = transaction.hash_as_entrypoint();
    let reveal = TransactionEntrypoint::SealedReveal(
        iroha_data_model::transaction::signed::SealedTransactionReveal::new(
            Hash::new(b"test sealed commitment"),
            transaction,
            [0x74; 32],
        ),
    );
    assert_ne!(reveal.hash(), execution);
    let transactions = [reveal];
    let mut binding = sample_binding();
    binding.claim_type = "tx_predicate".into();
    binding.source_tx_commitment = hex::encode(execution.as_ref());
    let anchor = finalized_test_anchor(
        PublicInputs {
            old_root: [1; 32],
            new_root: [2; 32],
            ..PublicInputs::default()
        },
        &transactions,
    );
    let mut envelope = envelope_with_payload(binding, vec![0xAA]);
    envelope.da_commitment = Some(anchor.da_manifest_digest.into());
    assert!(
        matches!(
            verify_axt_proof_envelope_against_anchor_v1(
                &envelope,
                Some(100),
                &anchor,
                &transactions
            ),
            Err(Error::InvalidAxtBinding { .. }),
        ),
        "inner execution membership must pass before invalid proof bytes are decoded"
    );
    envelope
        .fastpq_binding
        .as_mut()
        .unwrap()
        .source_tx_commitment = hex::encode(transactions[0].hash().as_ref());
    let error =
        verify_axt_proof_envelope_against_anchor_v1(&envelope, Some(100), &anchor, &transactions)
            .unwrap_err();
    assert!(
        matches!(error, Error::InvalidAxtBinding { details } if details.contains("exactly once"))
    );
}

#[test]
fn anchored_axt_verifier_enforces_its_witness_count_cap_before_hashing() {
    let transaction = finalized_transaction(74);
    let maximum = iroha_data_model::nexus::MAX_AXT_FINALIZED_TRANSACTIONS_V1;
    let transactions = vec![transaction; maximum + 1];
    let envelope = envelope_with_payload(sample_binding(), Vec::new());
    let anchor = finalized_test_anchor(PublicInputs::default(), &[]);
    assert!(matches!(
        verify_axt_proof_envelope_against_anchor_v1(&envelope, Some(100), &anchor, &transactions),
        Err(Error::VerifierLimitExceeded { limit: "max_axt_finalized_transactions", actual, max })
            if actual == maximum + 1 && max == maximum,
    ));
}

#[test]
fn anchored_axt_public_inputs_compare_every_dataspace_and_digest_byte() {
    let (_, anchor, _) = finalized_proof_fixture();
    let inputs = PublicInputs {
        dsid: dsid_bytes(anchor.dataspace_id.as_u64()),
        old_root: anchor.pre_state_root.into(),
        new_root: anchor.post_state_root.into(),
        tx_set_hash: anchor.transaction_set_digest.into(),
        ..PublicInputs::default()
    };
    assert!(require_finalized_public_inputs_v1(&inputs, anchor).is_ok());
    let mut changed = inputs;
    changed.dsid[15] = 1;
    assert!(require_finalized_public_inputs_v1(&changed, anchor).is_err());
    for index in 0..32 {
        for field in [0, 1, 2] {
            let mut changed = inputs;
            match field {
                0 => changed.old_root[index] ^= 1,
                1 => changed.new_root[index] ^= 1,
                _ => changed.tx_set_hash[index] ^= 1,
            }
            assert!(require_finalized_public_inputs_v1(&changed, anchor).is_err());
        }
    }
}

fn sample_binding() -> AxtFastpqBinding {
    AxtFastpqBinding {
        parameter: DEFAULT_PARAMETER.to_string(),
        source_dsid: 7,
        source_dataspace: "taira".to_string(),
        source_receipt_id: "receipt-0001".to_string(),
        source_tx_commitment: "1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        claim_type: "authorization".to_string(),
        claim_digest: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        witness_commitment: "3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
        policy_commitment: "4444444444444444444444444444444444444444444444444444444444444444"
            .to_string(),
        verified_effect_type: "restricted_effect".to_string(),
        corridor: "test-corridor".to_string(),
        verifier_id: "fastpq".to_string(),
        verifier_version: "v1".to_string(),
        target_dsids: vec![9],
        effect_binding: None,
        remote_spend_intent_commitments: Vec::new(),
    }
}
fn alternate_norito_bytes<T: NoritoSerialize>(value: &T) -> Vec<u8> {
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    to_bytes(value).expect("encode alternate-layout fixture")
}
fn envelope_with_payload(binding: AxtFastpqBinding, proof: Vec<u8>) -> AxtProofEnvelope {
    AxtProofEnvelope {
        dsid: DataSpaceId::new(binding.source_dsid),
        manifest_root: [0x42; 32],
        da_commitment: Some([0x24; 32]),
        proof,
        fastpq_binding: Some(binding),
        committed_amount: None,
        amount_commitment: None,
    }
}
fn unbound_axt_batch(binding: &AxtFastpqBinding) -> TransitionBatch {
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 123,
            old_root: [0x10; 32],
            new_root: [0x20; 32],
            perm_root: [0x30; 32],
            tx_set_hash: [0x40; 32],
        },
    );
    let entry_hash = decode_hex_digest(&binding.source_tx_commitment, "source_tx_commitment")
        .expect("entry hash");
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), entry_hash.to_vec());
    batch
}
fn oversized_unbound_axt_batch(binding: &AxtFastpqBinding) -> (TransitionBatch, usize) {
    let mut batch = unbound_axt_batch(binding);
    let row_count = VerifyLimits::default().max_transitions + 1;
    for index in 0..row_count {
        batch.push(StateTransition::new(
            format!("account/real/axt-authorized-{index:04}").into_bytes(),
            b"pending".to_vec(),
            b"authorized".to_vec(),
            OperationKind::MetaSet,
        ));
    }
    batch.sort();
    (batch, row_count)
}
fn real_authorization_batch(binding: &AxtFastpqBinding) -> TransitionBatch {
    let mut batch = unbound_axt_batch(binding);
    batch.push(StateTransition::new(
        b"account/real/axt-authorized".to_vec(),
        b"pending".to_vec(),
        b"authorized".to_vec(),
        OperationKind::MetaSet,
    ));
    batch.sort();
    bind_axt_batch(&mut batch, binding, [0x42; 32], Some([0x24; 32])).expect("bind AXT batch");
    batch
}
fn real_transfer_claim_batch(binding: &AxtFastpqBinding) -> TransitionBatch {
    const TRANSFER_AMOUNT: u64 = 35;
    const SENDER_START: u64 = 900;
    const RECEIVER_START: u64 = 120;
    let domain = DomainId::try_new("axt", "universal").expect("domain id");
    let asset_definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "rose".parse().unwrap());
    let from_account = deterministic_account("transfer_sender", &domain);
    let to_account = deterministic_account("transfer_receiver", &domain);
    let entry_hash = decode_hex_digest(&binding.source_tx_commitment, "source_tx_commitment")
        .expect("entry hash");
    let transcript_batch_hash = Hash::prehashed(entry_hash);
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 124,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0x31; 32],
            tx_set_hash: [0x41; 32],
        },
    );
    let mut transcripts = vec![transfer_transcript(
        &asset_definition,
        &from_account,
        &to_account,
        TRANSFER_AMOUNT,
        SENDER_START,
        RECEIVER_START,
        transcript_batch_hash,
    )];
    let public = crate::gadgets::public_transfer_statement::public_claims_from_transcripts(
        &transcripts,
        crate::gadgets::public_transfer_statement::PublicTransferLimits::default(),
    )
    .unwrap();
    let built = {
        // This test fixture owns its finite tree pool; production supplies its original owner.
        let tree_claims = &public;
        let tree_limits =
            crate::gadgets::public_transfer_statement::TransferSmtBuildLimits::for_update_limit(2)
                .unwrap();
        let tree_updates = tree_claims
            .iter()
            .try_fold(0_usize, |count, claim| {
                count.checked_add(claim.deltas.len())
            })
            .expect("fixture effect count fits")
            .checked_mul(2)
            .expect("fixture row count fits");
        let tree_bytes = tree_limits
            .allocation_bytes(tree_updates, tree_updates)
            .expect("fixture tree allocation demand fits");
        let tree_budget = iroha_allocation::AllocationBudget::new(tree_bytes);
        let mut tree_reservation = tree_budget
            .try_reserve_bytes(tree_bytes)
            .expect("fixture owns complete tree credit");
        crate::gadgets::public_transfer_statement::materialize_quantity_public_transfers(
            tree_claims,
            batch.public_inputs,
            ProofSemantics::AxtTransferClaim,
            crate::gadgets::public_transfer_statement::PublicTransferLimits::default(),
            tree_limits,
            &tree_budget,
            &mut tree_reservation,
        )
    }
    .unwrap();
    let (rows, inputs, _, private) = built.into_parts();
    let witnesses = private.pairs();
    transcripts[0].deltas[0].from_smt_witness = witnesses[0][0].clone();
    transcripts[0].deltas[0].to_smt_witness = witnesses[0][1].clone();
    batch.transitions = rows;
    batch.public_inputs = inputs;
    batch.metadata.insert(
        TRANSFER_TRANSCRIPTS_METADATA_KEY.into(),
        to_bytes(&transcripts).expect("encode transfer transcripts"),
    );
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), entry_hash.to_vec());
    batch.sort();
    if !binding.remote_spend_intent_commitments.is_empty() {
        set_axt_remote_spend_claims(&mut batch, binding, &[real_transfer_claim(binding)])
            .expect("attach remote-spend claim preimage");
        let occurrences =
            source_occurrence::test_occurrences(&public, &[real_transfer_claim(binding)]);
        set_axt_source_transfer_occurrences(&mut batch, binding, &occurrences)
            .expect("attach source occurrence");
    }
    bind_axt_batch(&mut batch, binding, [0x42; 32], Some([0x24; 32]))
        .expect("bind transfer AXT batch");
    batch
}
fn real_transfer_claim(binding: &AxtFastpqBinding) -> AxtRemoteSpendClaimV1 {
    let domain = DomainId::try_new("axt", "universal").expect("domain id");
    AxtRemoteSpendClaimV1::new(
        AxtHandleReplayKey::from_parts(
            DataSpaceId::new(binding.source_dsid),
            AxtHandleIssuerContextV1::default().asset_definition_incarnation,
            [0xA5; 32],
            1,
            1,
            LaneId::new(0),
        ),
        AssetDefinitionId::derive_from_components(
            domain.clone(),
            "rose".parse().expect("asset name"),
        ),
        "transfer",
        deterministic_account("transfer_sender", &domain).to_string(),
        deterministic_account("transfer_receiver", &domain).to_string(),
        Quantity::from(35_u64),
    )
}
fn transfer_effect_binding(asset_definition: &AssetDefinitionId) -> AxtEffectBinding {
    AxtEffectBinding {
        destination_domain: None,
        destination_account_id: None,
        vault_account_id: None,
        issuance_account_id: None,
        source_asset_definition_id: Some(asset_definition.to_string()),
        destination_asset_definition_id: None,
        source_amount_i64: None,
        destination_amount_i64: None,
    }
}
fn remote_transfer_binding() -> AxtFastpqBinding {
    let domain = DomainId::try_new("axt", "universal").expect("domain id");
    let asset_definition =
        AssetDefinitionId::derive_from_components(domain, "rose".parse().unwrap());
    let mut binding = sample_binding();
    binding.claim_type = "tx_predicate".to_owned();
    binding.effect_binding = Some(transfer_effect_binding(&asset_definition));
    let claim = real_transfer_claim(&binding);
    binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claim)];
    binding
}
fn deterministic_account(label: &str, domain: &DomainId) -> AccountId {
    let seed: [u8; Hash::LENGTH] = Hash::new(format!("{label}@{domain}")).into();
    let keypair = KeyPair::try_from_seed(seed.to_vec(), Algorithm::default())
        .expect("derive AXT fixture account key");
    AccountId::new(keypair.public_key().clone())
}

fn public_metadata_bytes<'a>(
    batch: &'a TransitionBatch,
    occurrences: &'a [AxtSourceTransferOccurrenceV1],
) -> AxtPublicMetadataBytes<'a> {
    AxtPublicMetadataBytes {
        parameter: &batch.parameter,
        entry_hash: &batch.metadata[ENTRY_HASH_METADATA_KEY],
        committed_amount: batch
            .metadata
            .get(AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY)
            .map(Vec::as_slice),
        expiry_slot: &batch.metadata[AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY],
        manifest_root: &batch.metadata[AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY],
        da_commitment: &batch.metadata[AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY],
        source_transfer_occurrences: occurrences,
    }
}

#[test]
fn public_metadata_parsers_preserve_exact_errors_and_option_boundaries() {
    let binding = remote_transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    let outer = AxtProofContextMirrors {
        dsid: DataSpaceId::new(binding.source_dsid),
        manifest_root: proof_bound_manifest_root(&batch).unwrap(),
        da_commitment: proof_bound_da_commitment(&batch).unwrap(),
        committed_amount: proof_bound_committed_amount(&batch).unwrap(),
        expiry_slot: proof_bound_expiry_slot(&batch).unwrap(),
    };
    validate_axt_public_metadata(&binding, public_metadata_bytes(&batch, &[]), outer).unwrap();
    let mut conflicting = public_metadata_bytes(&batch, &[]);
    conflicting.da_commitment = &[0; 32];
    let mut wrong_manifest = outer;
    wrong_manifest.manifest_root[0] ^= 1;
    assert_eq!(
        validate_axt_public_metadata(&binding, conflicting, wrong_manifest)
            .unwrap_err()
            .to_string(),
        require_proof_mirror(
            "envelope manifest_root",
            wrong_manifest.manifest_root,
            outer.manifest_root
        )
        .unwrap_err()
        .to_string(),
        "the manifest mirror precedes malformed DA parsing",
    );
    for (key, length) in [
        (AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY, 16),
        (AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY, 8),
        (AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY, 32),
        (AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY, 33),
    ] {
        for actual_length in [0, length - 1, length + 1] {
            let mut changed = batch.clone();
            changed.metadata.insert(key.into(), vec![0; actual_length]);
            let from_private_metadata = match key {
                AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY => {
                    proof_bound_committed_amount(&changed).unwrap_err()
                }
                AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY => {
                    proof_bound_expiry_slot(&changed).unwrap_err()
                }
                AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY => {
                    proof_bound_manifest_root(&changed).unwrap_err()
                }
                AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY => {
                    proof_bound_da_commitment(&changed).unwrap_err()
                }
                _ => unreachable!(),
            };
            let public =
                validate_axt_public_metadata(&binding, public_metadata_bytes(&changed, &[]), outer)
                    .unwrap_err();
            assert_eq!(
                public.to_string(),
                from_private_metadata.to_string(),
                "{key}/{actual_length}"
            );
        }
    }
    assert_eq!(parse_committed_amount(None).unwrap(), None);
    assert_eq!(
        parse_committed_amount(Some(&u128::MAX.to_le_bytes())).unwrap(),
        Some(u128::MAX)
    );
    assert!(parse_committed_amount(Some(&[0; 16])).is_err());
    assert_eq!(parse_expiry_slot(&[0; 8]).unwrap(), None);
    assert_eq!(
        parse_expiry_slot(&u64::MAX.to_le_bytes()).unwrap(),
        Some(u64::MAX)
    );
    assert_eq!(parse_da_commitment(&[0; 33]).unwrap(), None);
    let mut present_zero = [0; 33];
    present_zero[0] = 1;
    assert_eq!(parse_da_commitment(&present_zero).unwrap(), Some([0; 32]));
}

#[test]
fn public_remote_facts_and_private_metadata_have_identical_acceptance() {
    use crate::gadgets::public_transfer_statement::{
        PublicTransferLimits, prepare_quantity_public_transfers, public_claims_from_transcripts,
    };
    let binding = remote_transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    let occurrences: Vec<AxtSourceTransferOccurrenceV1> = norito::decode_canonical(
        &batch.metadata[AXT_FASTPQ_SOURCE_TRANSFER_OCCURRENCES_METADATA_KEY],
    )
    .unwrap();
    let transcripts = decode_transcripts(&batch.metadata).unwrap().unwrap();
    let public =
        public_claims_from_transcripts(&transcripts, PublicTransferLimits::default()).unwrap();
    let prepared = prepare_quantity_public_transfers(
        &batch.transitions,
        &public,
        batch.public_inputs,
        ProofSemantics::AxtTransferClaim,
        PublicTransferLimits::default(),
    )
    .unwrap();
    let claim = real_transfer_claim(&binding);
    require_remote_spend_transcript_linkage(&batch, &binding).unwrap();
    validate_axt_public_transfer_facts(
        &binding,
        public_metadata_bytes(&batch, &occurrences),
        &prepared,
        Some(core::slice::from_ref(&claim)),
    )
    .unwrap();
    for field in 0..6 {
        let mut changed_claim = claim.clone();
        match field {
            0 => changed_claim.effective_amount = Quantity::from(34_u64),
            1 => changed_claim.kind = "mint".into(),
            2 => changed_claim.from = claim.to.clone(),
            3 => changed_claim.from.push(' '),
            4 => {
                changed_claim.handle_replay_key.asset_dsid =
                    DataSpaceId::new(binding.source_dsid + 1)
            }
            5 => {
                changed_claim.asset_definition_id = AssetDefinitionId::derive_from_components(
                    DomainId::try_new("axt", "universal").unwrap(),
                    "lily".parse().unwrap(),
                )
            }
            _ => unreachable!(),
        }
        let claims = vec![changed_claim];
        let mut changed_binding = binding.clone();
        changed_binding.remote_spend_intent_commitments = claims
            .iter()
            .map(compute_remote_spend_claim_commitment_v1)
            .collect();
        let mut changed_batch = batch.clone();
        changed_batch.metadata.insert(
            AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.into(),
            encode_canonical_norito(&claims).unwrap(),
        );
        let from_private_metadata =
            require_remote_spend_transcript_linkage(&changed_batch, &changed_binding).unwrap_err();
        let public = validate_axt_public_transfer_facts(
            &changed_binding,
            public_metadata_bytes(&batch, &occurrences),
            &prepared,
            Some(&claims),
        )
        .unwrap_err();
        assert_eq!(
            public.to_string(),
            from_private_metadata.to_string(),
            "remote field {field}"
        );
    }
    // No private decoder is reachable from the shared public-fact entry.
    let mut corrupt_private = batch.clone();
    corrupt_private
        .metadata
        .insert(TRANSFER_TRANSCRIPTS_METADATA_KEY.into(), vec![0xff]);
    assert!(require_remote_spend_transcript_linkage(&corrupt_private, &binding).is_err());
    validate_axt_public_transfer_facts(
        &binding,
        public_metadata_bytes(&corrupt_private, &occurrences),
        &prepared,
        Some(&[claim]),
    )
    .unwrap();
}

#[test]
fn shared_public_header_and_hash_checks_preserve_exact_source_identity() {
    let binding = remote_transfer_binding();
    let hash: [u8; 32] = hex::decode(&binding.source_tx_commitment)
        .unwrap()
        .try_into()
        .unwrap();
    let source = Hash::prehashed(hash);
    require_execution_header(DEFAULT_PARAMETER, dsid_bytes(binding.source_dsid), &binding).unwrap();
    assert!(require_execution_header("other", dsid_bytes(binding.source_dsid), &binding).is_err());
    let mut high_dsid = dsid_bytes(binding.source_dsid);
    high_dsid[15] = 1;
    assert!(require_execution_header(DEFAULT_PARAMETER, high_dsid, &binding).is_err());
    assert!(require_execution_rows(0).is_err());
    require_execution_rows(1).unwrap();
    require_transfer_batch_hashes(&hash, [source, source]).unwrap();
    assert!(require_transfer_batch_hashes(&hash, []).is_err());
    assert!(require_transfer_batch_hashes(&hash, [source, Hash::new(b"other source")]).is_err());
    require_public_value_eq("entry_hash", &hash, &hash).unwrap();
    assert!(require_public_value_eq("entry_hash", &hash[..31], &hash).is_err());
    assert!(require_remote_spend_claim_presence(&binding, false).unwrap());
    let mut empty = binding;
    empty.remote_spend_intent_commitments.clear();
    assert!(!require_remote_spend_claim_presence(&empty, false).unwrap());
    assert!(require_remote_spend_claim_presence(&empty, true).is_err());
}

#[test]
fn deterministic_account_uses_checked_seed_derivation() {
    let domain = DomainId::try_new("wonderland", "universal").expect("domain id");
    let seed: [u8; Hash::LENGTH] = Hash::new(format!("alice@{domain}")).into();
    let keypair = KeyPair::try_from_seed(seed.to_vec(), Algorithm::default())
        .expect("derive AXT fixture account key");
    assert_eq!(
        deterministic_account("alice", &domain),
        AccountId::new(keypair.public_key().clone())
    );
}

#[test]
fn generic_consumer_gate_accepts_transfer_and_rejects_opaque_carriers() {
    validate_axt_transfer_claim_binding(&remote_transfer_binding())
        .expect("witnessed transfer claim is admissible to generic consumers");

    let opaque = sample_binding();
    let error = validate_axt_transfer_claim_binding(&opaque)
        .expect_err("opaque authorization-labelled carrier must need an external authority");
    assert!(matches!(
        error,
        Error::InvalidProofSemantics {
            profile: "axt_opaque_effect",
            ..
        }
    ));
}

fn transfer_transcript(
    asset_definition: &AssetDefinitionId,
    from_account: &AccountId,
    to_account: &AccountId,
    amount: u64,
    from_balance_before: u64,
    to_balance_before: u64,
    batch_hash: Hash,
) -> TransferTranscript {
    let delta = TransferDeltaTranscript {
        from_account: from_account.clone(),
        to_account: to_account.clone(),
        asset_definition: asset_definition.clone(),
        amount: Quantity::from(amount),
        from_balance_before: Quantity::from(from_balance_before),
        from_balance_after: Quantity::from(from_balance_before - amount),
        to_balance_before: Quantity::from(to_balance_before),
        to_balance_after: Quantity::from(to_balance_before + amount),
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    };
    let digest = crate::gadgets::transfer::compute_poseidon_digest(&delta, &batch_hash);
    TransferTranscript {
        batch_hash,
        deltas: vec![delta],
        authority_digest: Hash::new(b"axt-transfer-authority"),
        poseidon_preimage_digest: Some(digest),
    }
}
#[test]
fn canonicalize_binding_rejects_non_fastpq_v1_or_blank_verifier_labels() {
    let mut binding = sample_binding();
    binding.verifier_id = "halo2".to_owned();
    let err = canonicalize_binding(&binding).expect_err("wrong verifier id must fail");
    assert!(matches!(err, Error::InvalidAxtBinding { details } if details.contains("verifier_id")));
    let mut binding = sample_binding();
    binding.verifier_version = "v2".to_owned();
    let err = canonicalize_binding(&binding).expect_err("wrong verifier version must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("verifier_version"))
    );
    let mut binding = sample_binding();
    binding.verifier_id.clear();
    let err = canonicalize_binding(&binding).expect_err("blank verifier id must fail");
    assert!(matches!(err, Error::InvalidAxtBinding { details } if details.contains("verifier_id")));
    let mut binding = sample_binding();
    binding.verifier_version.clear();
    let err = canonicalize_binding(&binding).expect_err("blank verifier version must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("verifier_version"))
    );
    let mut binding = sample_binding();
    binding.parameter.clear();
    let err = canonicalize_binding(&binding).expect_err("blank parameter must fail");
    assert!(matches!(
        err,
        Error::InvalidAxtBinding { details } if details.contains("parameter")
    ));
}
#[test]
fn canonicalize_binding_requires_strictly_ordered_unique_targets() {
    let mut binding = sample_binding();
    binding.target_dsids.clear();
    let err = canonicalize_binding(&binding).expect_err("empty targets must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("target_dsids"))
    );
    let mut binding = sample_binding();
    binding.target_dsids = vec![9, 9];
    let err = canonicalize_binding(&binding).expect_err("duplicate targets must fail");
    assert!(matches!(err, Error::InvalidAxtBinding { details } if details.contains("duplicate")));
    let mut binding = sample_binding();
    binding.target_dsids = vec![11, 9];
    let err = canonicalize_binding(&binding).expect_err("out-of-order targets must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("strictly ordered"))
    );
    let mut binding = sample_binding();
    binding.target_dsids = vec![9, 11];
    assert_eq!(
        canonicalize_binding(&binding)
            .expect("strict target order")
            .target_dsids,
        vec![9, 11]
    );
}
#[test]
fn canonicalize_binding_bounds_and_canonicalizes_remote_spend_commitments() {
    let mut binding = sample_binding();
    binding.remote_spend_intent_commitments = vec![[0x11; 32], [0x22; 32]];
    assert_eq!(
        canonicalize_binding(&binding)
            .expect("strict remote-spend commitment order")
            .remote_spend_intent_commitments,
        binding.remote_spend_intent_commitments
    );

    binding.remote_spend_intent_commitments = vec![[0x11; 32], [0x11; 32]];
    let err = canonicalize_binding(&binding).expect_err("duplicate commitment must fail");
    assert!(matches!(
        err,
        Error::InvalidAxtBinding { details } if details.contains("strictly ordered")
    ));

    binding.remote_spend_intent_commitments = vec![[0x22; 32], [0x11; 32]];
    let err = canonicalize_binding(&binding).expect_err("unordered commitment must fail");
    assert!(matches!(
        err,
        Error::InvalidAxtBinding { details } if details.contains("strictly ordered")
    ));

    let oversized =
        vec![[0_u8; 32]; iroha_data_model::nexus::MAX_REMOTE_SPEND_INTENT_COMMITMENTS_V1 + 1];
    let err = canonical_remote_spend_intent_commitments(&oversized)
        .expect_err("oversized commitment set must fail before canonicalization");
    assert!(matches!(
        err,
        Error::InvalidAxtBinding { details } if details.contains("V1 limit")
    ));
}
#[test]
fn canonicalize_binding_normalizes_labels_and_manifest_hash() {
    let mut binding = sample_binding();
    binding.parameter = format!("  {DEFAULT_PARAMETER}  ");
    binding.source_dataspace = "  taira  ".to_owned();
    binding.source_receipt_id = "  receipt-0001  ".to_owned();
    binding.source_tx_commitment =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    binding.claim_type = "  AUTHORIZATION  ".to_owned();
    binding.claim_digest =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();
    binding.verifier_id = "  fastpq  ".to_owned();
    binding.verifier_version = "  v1  ".to_owned();
    binding.corridor = "  corridor-a  ".to_owned();
    let canonical = canonicalize_binding(&binding).expect("canonical binding");
    assert_eq!(canonical.parameter, DEFAULT_PARAMETER);
    assert_eq!(canonical.source_dataspace, "taira");
    assert_eq!(canonical.source_receipt_id, "receipt-0001");
    assert_eq!(
        canonical.source_tx_commitment,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(canonical.claim_type, "authorization");
    assert_eq!(
        canonical.claim_digest,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(canonical.verifier_id, "fastpq");
    assert_eq!(canonical.verifier_version, "v1");
    assert_eq!(canonical.corridor, "corridor-a");
    assert_eq!(
        batch_manifest_sha256(&binding).expect("raw manifest"),
        batch_manifest_sha256(&canonical).expect("canonical manifest")
    );
}
#[test]
fn verification_rejects_normalizable_but_noncanonical_binding_values() {
    let mutations: [fn(&mut AxtFastpqBinding); 4] = [
        |binding: &mut AxtFastpqBinding| binding.parameter = format!(" {DEFAULT_PARAMETER}"),
        |binding: &mut AxtFastpqBinding| {
            binding.claim_type = "AUTHORIZATION".to_owned();
        },
        |binding: &mut AxtFastpqBinding| {
            binding.claim_digest =
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        },
        |binding: &mut AxtFastpqBinding| binding.verifier_id = "fastpq ".to_owned(),
    ];
    for mutate in mutations {
        let mut binding = sample_binding();
        mutate(&mut binding);
        let envelope = envelope_with_payload(binding, vec![0x00]);
        let err = verify_axt_proof_envelope(&envelope)
            .expect_err("normalizable noncanonical binding must fail before proof decoding");
        assert!(
            matches!(&err, Error::InvalidAxtBinding { details } if details.contains("exact canonical")),
            "unexpected error: {err:?}"
        );
    }
}
#[test]
fn bind_axt_batch_pins_canonical_norito_flags_under_an_ambient_layout() {
    let binding = sample_binding();
    let canonical = real_authorization_batch(&binding);
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let under_alternate_layout = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        real_authorization_batch(&binding)
    };
    assert_eq!(
        under_alternate_layout
            .metadata
            .get(AXT_FASTPQ_BINDING_METADATA_KEY),
        canonical.metadata.get(AXT_FASTPQ_BINDING_METADATA_KEY)
    );
    assert_eq!(
        under_alternate_layout
            .metadata
            .get(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY),
        canonical.metadata.get(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY)
    );
}
#[test]
fn canonicalize_binding_rejects_malformed_digest_and_claim_type() {
    let mut binding = sample_binding();
    binding.claim_digest = "abcd".to_owned();
    let err = canonicalize_binding(&binding).expect_err("short digest must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("claim_digest"))
    );
    let mut binding = sample_binding();
    binding.claim_type = "synthetic".to_owned();
    let err = canonicalize_binding(&binding).expect_err("unsupported claim type must fail");
    assert!(matches!(err, Error::InvalidAxtBinding { details } if details.contains("claim_type")));
}
#[test]
fn transition_batch_model_roundtrip_preserves_operations_and_metadata() {
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(77),
            slot: 321,
            old_root: [0x01; 32],
            new_root: [0x02; 32],
            perm_root: [0x03; 32],
            tx_set_hash: [0x04; 32],
        },
    );
    batch.push(StateTransition::new(
        b"asset/xor/transfer".to_vec(),
        3_u64.to_le_bytes().to_vec(),
        2_u64.to_le_bytes().to_vec(),
        OperationKind::Transfer,
    ));
    batch.push(StateTransition::new(
        b"asset/xor/mint".to_vec(),
        3_u64.to_le_bytes().to_vec(),
        5_u64.to_le_bytes().to_vec(),
        OperationKind::Mint,
    ));
    batch.push(StateTransition::new(
        b"asset/xor/burn".to_vec(),
        5_u64.to_le_bytes().to_vec(),
        4_u64.to_le_bytes().to_vec(),
        OperationKind::Burn,
    ));
    let grant_role = [0x11; 32];
    let grant_permission = [0x22; 32];
    let grant_epoch = 7;
    let grant_leaf = crate::trace::permission_hash(&grant_role, &grant_permission, grant_epoch)
        .expect("canonical grant permission leaf");
    batch.push(StateTransition::new(
        crate::trace::permission_transition_key(&grant_role, &grant_permission),
        Vec::new(),
        grant_leaf.to_le_bytes().to_vec(),
        OperationKind::RoleGrant {
            role_id: grant_role,
            permission_id: grant_permission,
            epoch: grant_epoch,
        },
    ));
    let revoke_role = [0x33; 32];
    let revoke_permission = [0x44; 32];
    let revoke_epoch = 8;
    let revoke_leaf = crate::trace::permission_hash(&revoke_role, &revoke_permission, revoke_epoch)
        .expect("canonical revoke permission leaf");
    batch.push(StateTransition::new(
        crate::trace::permission_transition_key(&revoke_role, &revoke_permission),
        revoke_leaf.to_le_bytes().to_vec(),
        Vec::new(),
        OperationKind::RoleRevoke {
            role_id: revoke_role,
            permission_id: revoke_permission,
            epoch: revoke_epoch,
        },
    ));
    batch.push(StateTransition::new(
        b"account/meta".to_vec(),
        b"old".to_vec(),
        b"new".to_vec(),
        OperationKind::MetaSet,
    ));
    batch
        .metadata
        .insert("fixture".to_owned(), b"roundtrip".to_vec());
    let model = transition_batch_to_model(&batch);
    let borrowed_roundtrip = transition_batch_from_model(&model);
    let owned_roundtrip = transition_batch_from_model_owned(model);
    assert_eq!(borrowed_roundtrip, batch);
    assert_eq!(owned_roundtrip, batch);
}

#[test]
fn direct_axt_batch_producer_checks_limits_before_missing_binding_metadata() {
    let binding = sample_binding();
    let (batch, row_count) = oversized_unbound_axt_batch(&binding);
    let limits = VerifyLimits::default();

    let err = prove_axt_bound_batch(&batch, &binding)
        .expect_err("limits must take precedence over missing AXT binding metadata");
    assert!(matches!(
        err,
        Error::VerifierLimitExceeded {
            limit: "max_transitions",
            actual,
            max,
        } if actual == row_count && max == limits.max_transitions
    ));
}

#[test]
fn bind_axt_batch_rejects_empty_execution_batch() {
    let binding = sample_binding();
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 123,
            old_root: [0x10; 32],
            new_root: [0x20; 32],
            perm_root: [0x30; 32],
            tx_set_hash: [0x40; 32],
        },
    );
    let entry_hash = decode_hex_digest(&binding.source_tx_commitment, "source_tx_commitment")
        .expect("entry hash");
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), entry_hash.to_vec());
    let err = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("empty batch must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("state transitions"))
    );
}
#[test]
fn bind_axt_batch_rejects_transfer_row_in_opaque_authorization_claim() {
    let binding = sample_binding();
    let mut batch = unbound_axt_batch(&binding);
    batch.push(StateTransition::new(
        b"asset/rose/mallory".to_vec(),
        1_u64.to_le_bytes().to_vec(),
        2_u64.to_le_bytes().to_vec(),
        OperationKind::Transfer,
    ));

    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("opaque authorization must not prove a transfer row");
    assert!(matches!(
        error,
        Error::InvalidProofSemantics {
            profile: "axt_opaque_effect",
            ..
        }
    ));
}
#[test]
fn bind_axt_batch_rejects_metadata_appended_to_transfer_claim() {
    let mut binding = sample_binding();
    binding.claim_type = "value_conservation".to_owned();
    let mut batch = unbound_axt_batch(&binding);
    batch.push(StateTransition::new(
        b"asset/rose/alice".to_vec(),
        10_u64.to_le_bytes().to_vec(),
        7_u64.to_le_bytes().to_vec(),
        OperationKind::Transfer,
    ));
    batch.push(StateTransition::new(
        b"metadata/attacker".to_vec(),
        b"old".to_vec(),
        b"new".to_vec(),
        OperationKind::MetaSet,
    ));

    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("transfer claim must reject an appended metadata row");
    assert!(matches!(
        error,
        Error::InvalidProofSemantics {
            profile: "axt_transfer_claim",
            ..
        }
    ));
}

#[test]
fn bind_axt_batch_rejects_parameter_mismatch() {
    let binding = sample_binding();
    let mut batch = TransitionBatch::new(
        "fastpq-lane-minimal",
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 123,
            old_root: [0x10; 32],
            new_root: [0x20; 32],
            perm_root: [0x30; 32],
            tx_set_hash: [0x40; 32],
        },
    );
    batch.push(StateTransition::new(
        b"account/real/axt-authorized".to_vec(),
        b"pending".to_vec(),
        b"authorized".to_vec(),
        OperationKind::MetaSet,
    ));
    let entry_hash = decode_hex_digest(&binding.source_tx_commitment, "source_tx_commitment")
        .expect("entry hash");
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), entry_hash.to_vec());
    let err = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("parameter mismatch must fail");
    assert!(matches!(err, Error::InvalidAxtBinding { details } if details.contains("parameter")));
}
#[test]
fn bind_axt_batch_rejects_missing_entry_hash() {
    let binding = sample_binding();
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 123,
            old_root: [0x10; 32],
            new_root: [0x20; 32],
            perm_root: [0x30; 32],
            tx_set_hash: [0x40; 32],
        },
    );
    batch.push(StateTransition::new(
        b"account/real/axt-authorized".to_vec(),
        b"pending".to_vec(),
        b"authorized".to_vec(),
        OperationKind::MetaSet,
    ));
    let err = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("entry hash is required");
    assert!(matches!(err, Error::MissingMetadata { key } if key == ENTRY_HASH_METADATA_KEY));
}
#[test]
fn bind_axt_batch_rejects_entry_hash_mismatch() {
    let binding = sample_binding();
    let mut batch = TransitionBatch::new(
        DEFAULT_PARAMETER,
        PublicInputs {
            dsid: dsid_bytes(binding.source_dsid),
            slot: 123,
            old_root: [0x10; 32],
            new_root: [0x20; 32],
            perm_root: [0x30; 32],
            tx_set_hash: [0x40; 32],
        },
    );
    batch.push(StateTransition::new(
        b"account/real/axt-authorized".to_vec(),
        b"pending".to_vec(),
        b"authorized".to_vec(),
        OperationKind::MetaSet,
    ));
    batch
        .metadata
        .insert(ENTRY_HASH_METADATA_KEY.into(), vec![0xAA; 32]);
    let err = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("wrong entry hash fails");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains(ENTRY_HASH_METADATA_KEY))
    );
}

#[test]
fn embedded_axt_binding_rejects_alternate_norito_layout() {
    let binding = sample_binding();
    let mut batch = real_authorization_batch(&binding);
    let alternate = alternate_norito_bytes(&binding);
    assert_ne!(
        alternate,
        encode_canonical_norito(&binding).expect("canonical binding")
    );
    assert_eq!(
        decode_from_bytes::<AxtFastpqBinding>(&alternate)
            .expect("ordinary Norito accepts advertised alternate layout"),
        binding
    );
    batch
        .metadata
        .insert(AXT_FASTPQ_BINDING_METADATA_KEY.into(), alternate);
    let err = embedded_axt_binding(&batch).expect_err("alternate binding layout must fail");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("canonical Norito"))
    );
}
#[test]
fn embedded_axt_binding_rejects_semantically_noncanonical_metadata() {
    let binding = sample_binding();
    let mut batch = real_authorization_batch(&binding);
    let mut noncanonical = binding;
    noncanonical.claim_type = " AUTHORIZATION ".to_owned();
    batch.metadata.insert(
        AXT_FASTPQ_BINDING_METADATA_KEY.into(),
        encode_canonical_norito(&noncanonical).expect("canonical Norito layout"),
    );
    let err = embedded_axt_binding(&batch)
        .expect_err("normalizable metadata value must not be accepted as canonical");
    assert!(
        matches!(err, Error::InvalidAxtBinding { details } if details.contains("exact canonical"))
    );
}

#[test]
fn verify_axt_envelope_rejects_transfer_claim_without_transfer_rows() {
    let mut binding = sample_binding();
    binding.claim_type = "value_conservation".to_owned();
    let mut batch = unbound_axt_batch(&binding);
    batch.push(StateTransition::new(
        b"account/opaque/not-a-transfer".to_vec(),
        b"before".to_vec(),
        b"after".to_vec(),
        OperationKind::MetaSet,
    ));
    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("transfer claim without exclusively transfer rows must fail");
    assert!(matches!(
        error,
        Error::InvalidProofSemantics {
            profile: "axt_transfer_claim",
            ..
        }
    ));
}

#[test]
fn remote_spend_claim_rejects_mismatched_transcript_amount() {
    let binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    claims[0].effective_amount = Quantity::from(34_u64);
    batch.metadata.insert(
        AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.into(),
        encode_canonical_norito(&claims).expect("encode mismatched claim"),
    );
    let mut malicious_binding = binding;
    malicious_binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claims[0])];
    let error = bind_axt_batch(&mut batch, &malicious_binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("claim amount without an exact transcript must fail closed");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("one-for-one")
    ));
}
#[test]
fn remote_spend_claim_rejects_invalid_asset_incarnation_before_transcript_linkage() {
    let mut binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    let mut logical_zero =
        norito::json::to_value(&claims[0].handle_replay_key.asset_definition_incarnation)
            .expect("encode replay-key incarnation");
    logical_zero
        .as_array_mut()
        .expect("transparent incarnation JSON tuple")[0] =
        norito::json::to_value(&Hash::prehashed([0; Hash::LENGTH]))
            .expect("encode logical-zero hash");
    claims[0].handle_replay_key.asset_definition_incarnation =
        norito::json::from_value(logical_zero)
            .expect("decode syntactically valid logical-zero incarnation");
    binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claims[0])];
    set_axt_remote_spend_claims(&mut batch, &binding, &claims)
        .expect("attach malformed claim preimage for verifier regression");

    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("a logical-zero claim incarnation must fail closed");
    let Error::InvalidAxtBinding { details } = error else {
        panic!("expected an invalid AXT binding error, got {error:?}");
    };
    assert_eq!(
        details,
        "remote-spend claim contains an invalid handle replay key: replay key has an invalid asset-definition incarnation: AXT asset-definition incarnation is zero"
    );
}
#[test]
fn remote_spend_claim_commitment_separates_asset_incarnations() {
    let binding = remote_transfer_binding();
    let first = real_transfer_claim(&binding);
    let mut reincarnated = first.clone();
    reincarnated.handle_replay_key.asset_definition_incarnation =
        AxtAssetIncarnationV1::try_from_bytes([0xC3; Hash::LENGTH])
            .expect("non-zero alternate asset incarnation");

    assert_ne!(
        compute_remote_spend_claim_commitment_v1(&first),
        compute_remote_spend_claim_commitment_v1(&reincarnated),
        "historical proof claims must not authenticate a newly registered asset incarnation"
    );
}
#[test]
fn remote_spend_claim_rejects_two_handle_claims_for_one_transfer_delta() {
    let mut binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    let mut second = claims[0].clone();
    second.handle_replay_key.sub_nonce += 1;
    let mut claims = vec![claims[0].clone(), second];
    claims.sort_unstable_by_key(compute_remote_spend_claim_commitment_v1);
    binding.remote_spend_intent_commitments = claims
        .iter()
        .map(compute_remote_spend_claim_commitment_v1)
        .collect();
    set_axt_remote_spend_claims(&mut batch, &binding, &claims)
        .expect("attach two distinct handle-bound claims");
    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("one transfer delta cannot satisfy two handle-bound claims");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("one-for-one") && details.contains("cardinality")
    ));
}
#[test]
fn remote_spend_claim_rejects_handle_dataspace_different_from_proof_source() {
    let mut binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    claims[0].handle_replay_key.asset_dsid = DataSpaceId::new(binding.source_dsid + 1);
    binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claims[0])];
    set_axt_remote_spend_claims(&mut batch, &binding, &claims)
        .expect("attach mismatched-dataspace claim preimage");
    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("claim dataspace must equal the proof source partition");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("asset_dsid") && details.contains("source_dsid")
    ));
}
#[test]
fn remote_spend_claim_rejects_alias_account_text() {
    let binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    claims[0].from = "spender@payments".to_owned();
    batch.metadata.insert(
        AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY.into(),
        encode_canonical_norito(&claims).expect("encode alias claim"),
    );
    let mut malicious_binding = binding;
    malicious_binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claims[0])];
    let error = bind_axt_batch(&mut batch, &malicious_binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("an alias claim account must fail closed");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details } if details.contains("canonical I105")
    ));
}
#[test]
fn canonical_remote_account_preserves_enclosing_parse_allocation_budget() {
    let literal = iroha_test_samples::ALICE_ID.canonical_i105().unwrap();
    let unrestricted =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    let (parsed, usage) = norito::core::with_decode_limits_measured(unrestricted, || {
        AccountId::parse_encoded(&literal)
    });
    let expected = parsed.expect("canonical account parses");
    assert!(usage.total_allocated_bytes() > 0);
    let exact_parse = norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usage.total_allocated_bytes(),
        32,
    );
    assert!(
        norito::core::with_decode_limits_scope(exact_parse, || AccountId::parse_encoded(&literal))
            .is_ok()
    );
    let result = norito::core::with_decode_limits_scope(exact_parse, || {
        canonical_remote_account(&literal, "from")
    });
    assert_eq!(
        result.expect("exact inbound parse budget is sufficient"),
        expected
    );
    let exhausted = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 32);
    let rejected = norito::core::with_decode_limits_scope(exhausted, || {
        canonical_remote_account(&literal, "from")
    });
    assert!(
        matches!(rejected, Err(Error::InvalidAxtBinding { details }) if details.contains("is not canonical I105"))
    );
    assert_eq!(
        canonical_remote_account(&literal, "from").unwrap(),
        expected
    );
}

#[test]
fn canonical_remote_account_rejects_padded_i105() {
    let binding = remote_transfer_binding();
    let claim = real_transfer_claim(&binding);
    let padded = format!(" {} ", claim.from);
    let error = canonical_remote_account(&padded, "from")
        .expect_err("padded I105 account text must fail closed");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("must use canonical I105 text")
    ));
}
#[test]
fn remote_spend_claim_rejects_opaque_profile_and_wrong_asset() {
    let mut opaque_binding = remote_transfer_binding();
    opaque_binding.claim_type = "authorization".to_owned();
    let mut opaque_batch = unbound_axt_batch(&opaque_binding);
    opaque_batch.push(StateTransition::new(
        b"account/axt/opaque".to_vec(),
        b"pending".to_vec(),
        b"authorized".to_vec(),
        OperationKind::MetaSet,
    ));
    let claim = real_transfer_claim(&opaque_binding);
    set_axt_remote_spend_claims(&mut opaque_batch, &opaque_binding, &[claim])
        .expect("attach exact commitment preimage");
    let error = bind_axt_batch(
        &mut opaque_batch,
        &opaque_binding,
        [0x42; 32],
        Some([0x24; 32]),
    )
    .expect_err("opaque proof must never authorize a remote spend");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("opaque AXT proofs cannot authorize handles")
    ));

    let mut wrong_asset_binding = remote_transfer_binding();
    let mut wrong_asset_batch = real_transfer_claim_batch(&wrong_asset_binding);
    wrong_asset_batch
        .metadata
        .remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let wrong_domain = DomainId::try_new("other", "universal").expect("domain id");
    let wrong_asset =
        AssetDefinitionId::derive_from_components(wrong_domain, "rose".parse().unwrap());
    wrong_asset_binding.effect_binding = Some(transfer_effect_binding(&wrong_asset));
    let error = bind_axt_batch(
        &mut wrong_asset_batch,
        &wrong_asset_binding,
        [0x42; 32],
        Some([0x24; 32]),
    )
    .expect_err("wrong source asset must fail before proof generation");
    assert!(matches!(
        error,
        Error::InvalidAxtBinding { details }
            if details.contains("asset other than source_asset_definition_id")
    ));
}
#[test]
fn remote_spend_claim_rejects_asset_substitution_against_transfer_transcript() {
    let mut binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut claims: Vec<AxtRemoteSpendClaimV1> = decode_from_bytes(
        batch
            .metadata
            .get(AXT_FASTPQ_REMOTE_SPEND_CLAIMS_METADATA_KEY)
            .expect("remote-spend claim metadata"),
    )
    .expect("decode remote-spend claims");
    let wrong_domain = DomainId::try_new("other", "universal").expect("domain id");
    let wrong_asset =
        AssetDefinitionId::derive_from_components(wrong_domain, "rose".parse().unwrap());
    claims[0].asset_definition_id = wrong_asset.clone();
    binding.effect_binding = Some(transfer_effect_binding(&wrong_asset));
    binding.remote_spend_intent_commitments =
        vec![compute_remote_spend_claim_commitment_v1(&claims[0])];
    set_axt_remote_spend_claims(&mut batch, &binding, &claims)
        .expect("attach substituted claim and matching outer commitment");

    let error = bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32]))
        .expect_err("claim asset substitution must not rewrite the transfer transcript");
    let Error::InvalidAxtBinding { details } = error else {
        panic!("expected an invalid AXT binding error, got {error:?}");
    };
    assert_eq!(
        details,
        "remote-spend proof contains a transfer for an asset other than source_asset_definition_id"
    );
}

#[test]
fn verify_axt_envelope_rejects_oversized_payload_before_binding_or_decode() {
    let mut binding = sample_binding();
    binding.verifier_id = " FASTPQ ".to_owned();
    let oversized = vec![0xA5; DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES + 1];
    let envelope = envelope_with_payload(binding, oversized);
    let err = verify_axt_proof_envelope(&envelope).expect_err("oversized payload must fail");
    assert!(matches!(
        err,
        Error::VerifierLimitExceeded {
            limit: "max_axt_fastpq_payload_bytes",
            actual,
            max,
        } if actual == DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES + 1
            && max == DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES
    ));
}
#[test]
fn verify_axt_proof_blob_rejects_oversized_payload_before_decode() {
    let blob = ProofBlob {
        payload: vec![0xA5; MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1],
        expiry_slot: None,
    };
    let err = verify_axt_proof_blob(&blob).expect_err("oversized blob must fail before decode");
    assert!(matches!(
        err,
        Error::VerifierLimitExceeded {
            limit: "max_axt_proof_blob_payload_bytes",
            actual,
            max,
        } if actual == MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1
            && max == MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES
    ));
}
fn compact_codec_fixture() -> iroha_data_model::fastpq::FastpqAxtCompactArtifactV1 {
    use iroha_data_model::fastpq::{
        FastpqAxtCompactArtifactV1, FastpqAxtPreProofMirrorsV1, FastpqAxtPublicMetadataV1,
        FastpqPublicTransferStatementV1,
    };
    let mut binding = sample_binding();
    binding.claim_type = "tx_predicate".into();
    let batch = transition_batch_to_model(&unbound_axt_batch(&binding));
    FastpqAxtCompactArtifactV1 {
        profile_id: crate::offline_compact::quantity_profile_id(),
        statement: FastpqPublicTransferStatementV1 {
            public_inputs: batch.public_inputs,
            ordering_hash: [0; 32],
            transitions: batch.transitions,
            transcripts: Vec::new(),
        },
        metadata: FastpqAxtPublicMetadataV1 {
            source_transfer_occurrences: Vec::new(),
            parameter: binding.parameter.clone(),
            entry_hash: [0x11; 32],
            committed_amount: None,
            expiry_slot: 0_u64.to_le_bytes(),
            manifest_root: [0x42; 32],
            da_commitment: [0; 33],
        },
        mirrors: FastpqAxtPreProofMirrorsV1 {
            dsid: DataSpaceId::new(binding.source_dsid),
            manifest_root: [0x42; 32],
            da_commitment: None,
            committed_amount: None,
            expiry_slot: None,
        },
        binding,
        remote_spend_claims: None,
        bundle_frame: Vec::new(),
    }
}

#[test]
fn compact_artifact_decoder_enforces_canonical_bytes_and_restores_layout() {
    let payload = compact_codec_fixture();
    let canonical = encode_canonical_norito(&payload).unwrap();
    assert_eq!(decode_axt_fastpq_payload(&canonical).unwrap(), payload);
    let mut cases = vec![alternate_norito_bytes(&payload), vec![]];
    for length in [5, norito::core::Header::SIZE - 1] {
        cases.push(canonical[..length].to_vec());
    }
    let mut unknown = canonical.clone();
    unknown[6..22].copy_from_slice(&norito::core::schema_hash_for_name("unknown:AXT:artifact"));
    cases.push(unknown);
    let mut corrupt = canonical.clone();
    corrupt[31] ^= 1;
    cases.push(corrupt);
    let mut trailing = canonical.clone();
    trailing.push(0);
    cases.push(trailing);
    for flags in [0, norito::core::default_encode_flags()] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(decode_axt_fastpq_payload(&canonical).unwrap(), payload);
        for encoded in &cases {
            assert!(decode_axt_fastpq_payload(encoded).is_err());
            assert_eq!(norito::core::get_decode_flags(), flags);
        }
    }
}

#[test]
fn compact_artifact_decoder_rejects_malformed_and_wrong_route_frames() {
    use iroha_data_model::fastpq::{
        FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME, FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
    };
    for schema in [
        FASTPQ_ORDINARY_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
        FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME,
    ] {
        let mut encoded = norito::encode_canonical(&0_u8).unwrap();
        encoded[6..22].copy_from_slice(&norito::core::schema_hash_for_name(schema));
        encoded.truncate(norito::core::Header::SIZE);
        encoded[23..31].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut binding = sample_binding();
        binding.claim_type = "tx_predicate".into();
        assert!(decode_axt_fastpq_payload(&encoded).is_err());
        assert!(
            verify_axt_proof_envelope(&envelope_with_payload(binding.clone(), encoded.clone()))
                .is_err()
        );
        encoded.resize(DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES + 1, 0xff);
        for result in [
            decode_axt_fastpq_payload(&encoded).map(|_| ()),
            verify_axt_proof_envelope(&envelope_with_payload(binding, encoded.clone())).map(|_| ()),
        ] {
            assert!(matches!(result, Err(Error::VerifierLimitExceeded {
                limit: "max_axt_fastpq_payload_bytes", actual, max,
            }) if actual == encoded.len() && max == DEFAULT_MAX_AXT_FASTPQ_PAYLOAD_BYTES));
        }
    }
}

#[test]
fn compact_axt_schema_is_exact_and_has_no_predecessor_fallback() {
    use iroha_data_model::fastpq::{
        FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME, FastpqAxtCompactArtifactV1,
    };
    let payload = compact_codec_fixture();
    let canonical = encode_canonical_norito(&payload).unwrap();
    assert_eq!(
        norito::schema::identity::frame_hash::<FastpqAxtCompactArtifactV1>(),
        norito::core::schema_hash_for_name(FASTPQ_AXT_COMPACT_ARTIFACT_V1_SCHEMA_NAME)
    );
    for retired in [
        "fastpq_prover::axt_binding::AxtFastpqProofPayload",
        "fastpq_prover::axt_binding::AxtFastpqProofPayloadV1",
    ] {
        let mut bytes = canonical.clone();
        bytes[6..22].copy_from_slice(&norito::core::schema_hash_for_name(retired));
        assert!(decode_axt_fastpq_payload(&bytes).is_err());
    }
    let alternate = alternate_norito_bytes(&payload);
    assert_ne!(alternate, canonical);
    assert_eq!(
        decode_from_bytes::<FastpqAxtCompactArtifactV1>(&alternate).unwrap(),
        payload
    );
    assert!(decode_axt_fastpq_payload(&alternate).is_err());
    let _layout = norito::core::DecodeFlagsGuard::enter(0);
    assert_eq!(encode_canonical_norito(&payload).unwrap(), canonical);
}

#[test]
fn proof_metadata_rejects_malformed_manifest_and_da_encodings() {
    let binding = sample_binding();
    let mut batch = real_authorization_batch(&binding);

    batch.metadata.remove(AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY);
    assert!(matches!(
        proof_bound_manifest_root(&batch).expect_err("missing manifest must fail"),
        Error::MissingMetadata { key } if key == AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY
    ));
    batch
        .metadata
        .insert(AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.into(), vec![1; 31]);
    assert!(matches!(
        proof_bound_manifest_root(&batch).expect_err("short manifest must fail"),
        Error::MetadataLength {
            key,
            expected: 32,
            actual: 31,
        } if key == AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY
    ));
    batch
        .metadata
        .insert(AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.into(), vec![0; 32]);
    assert!(
        matches!(proof_bound_manifest_root(&batch), Err(Error::InvalidAxtBinding { details }) if details.contains("manifest_root") && details.contains("non-zero"))
    );

    batch.metadata.remove(AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY);
    assert!(matches!(
        proof_bound_da_commitment(&batch).expect_err("missing DA encoding must fail"),
        Error::MissingMetadata { key } if key == AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY
    ));
    batch
        .metadata
        .insert(AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.into(), vec![0; 32]);
    assert!(matches!(
        proof_bound_da_commitment(&batch).expect_err("short DA encoding must fail"),
        Error::MetadataLength {
            key,
            expected: 33,
            actual: 32,
        } if key == AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY
    ));
    let mut unsupported_tag = vec![0; 33];
    unsupported_tag[0] = 2;
    batch.metadata.insert(
        AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.into(),
        unsupported_tag,
    );
    assert!(
        matches!(proof_bound_da_commitment(&batch), Err(Error::InvalidAxtBinding { details }) if details.contains("option tag"))
    );
    let mut noncanonical_none = vec![0; 33];
    noncanonical_none[1] = 1;
    batch.metadata.insert(
        AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.into(),
        noncanonical_none,
    );
    assert!(
        matches!(proof_bound_da_commitment(&batch), Err(Error::InvalidAxtBinding { details }) if details.contains("zeroed payload"))
    );
    let mut present_zero_digest = vec![0; 33];
    present_zero_digest[0] = 1;
    batch.metadata.insert(
        AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.into(),
        present_zero_digest,
    );
    assert_eq!(
        proof_bound_da_commitment(&batch).expect("tag-one zero digest is a present value"),
        Some([0; 32])
    );

    let mut batch = real_authorization_batch(&binding);
    assert!(
        matches!(bind_axt_batch(&mut batch, &binding, [0; 32], None), Err(Error::InvalidAxtBinding { details }) if details.contains("manifest_root") && details.contains("non-zero"))
    );
}

fn transfer_binding() -> AxtFastpqBinding {
    let mut binding = sample_binding();
    binding.claim_type = "tx_predicate".into();
    binding
}

#[test]
fn canonical_artifact_preparation_preserves_quantity_rows_context_and_remote_claims() {
    for claim_type in ["tx_predicate", "value_conservation"] {
        let mut binding = transfer_binding();
        binding.claim_type = claim_type.into();
        binding.corridor.clear();
        let batch = real_transfer_claim_batch(&binding);
        let prepared = compact::prepare(&batch, &binding).unwrap();
        assert_eq!(prepared.binding, binding);
        assert_eq!(
            prepared.statement.public_inputs,
            transition_batch_to_model(&batch).public_inputs
        );
        assert_eq!(
            prepared.statement.transitions,
            transition_batch_to_model(&batch).transitions
        );
        assert_eq!(prepared.statement.transcripts.len(), 1);
        assert!(prepared.bundle_frame.is_empty());
        assert_eq!(prepared.mirrors.expiry_slot, None);
        assert_eq!(prepared.metadata.expiry_slot, [0; 8]);
        for row in &batch.transitions {
            crate::gadgets::public_transfer_statement::decode_quantity_units_v1(&row.pre_value)
                .unwrap();
            crate::gadgets::public_transfer_statement::decode_quantity_units_v1(&row.post_value)
                .unwrap();
        }
        let bytes = norito::encode_canonical(&prepared).unwrap();
        assert_eq!(compact::decode(&bytes).unwrap(), prepared);
        assert!(verify_axt_bound_batch(&batch, &bytes, &binding).is_err());
        assert!(encode_axt_fastpq_payload(&batch, bytes).is_err());
    }
    let binding = remote_transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    let prepared = compact::prepare(&batch, &binding).unwrap();
    assert_eq!(
        prepared.remote_spend_claims,
        Some(vec![real_transfer_claim(&binding)])
    );
    require_remote_spend_transcript_linkage(&batch, &binding).unwrap();
}

#[test]
fn opaque_metadata_carriers_have_no_canonical_prover_or_verifier_route() {
    let binding = sample_binding();
    let batch = real_authorization_batch(&binding);
    assert!(matches!(
        compact::prepare(&batch, &binding),
        Err(Error::InvalidProofSemantics { .. })
    ));
    assert!(matches!(
        prove_axt_bound_batch(&batch, &binding),
        Err(Error::InvalidProofSemantics { .. })
    ));
    assert!(matches!(
        verify_axt_bound_batch(&batch, &[], &binding),
        Err(Error::InvalidProofSemantics { .. })
    ));
    assert!(matches!(
        verify_axt_proof_envelope(&envelope_with_payload(binding, vec![0])),
        Err(Error::InvalidProofSemantics { .. })
    ));
}

#[test]
fn canonical_bound_verifier_preserves_batch_limits_before_binding_and_private_work() {
    let binding = transfer_binding();
    let (batch, rows) = oversized_unbound_axt_batch(&binding);
    assert!(matches!(verify_axt_bound_batch(&batch, &[], &binding),
        Err(Error::VerifierLimitExceeded { limit: "max_transitions", actual, max })
            if actual == rows && max == VerifyLimits::default().max_transitions));
}

#[test]
fn canonical_preparation_rejects_missing_and_changed_bound_metadata_before_proving() {
    let binding = transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    let required = [
        AXT_FASTPQ_BINDING_METADATA_KEY,
        AXT_FASTPQ_BATCH_SEAL_METADATA_KEY,
        AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY,
        AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY,
        AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY,
        ENTRY_HASH_METADATA_KEY,
        TRANSFER_TRANSCRIPTS_METADATA_KEY,
        "source_tx_commitment",
        "target_dsids",
        "claim_digest",
        "witness_commitment",
        "policy_commitment",
        "source_receipt_id",
        "verified_effect_type",
        "corridor",
    ];
    for key in required {
        assert!(batch.metadata.contains_key(key), "fixture requires {key}");
        let mut missing = batch.clone();
        missing.metadata.remove(key);
        assert!(
            compact::prepare(&missing, &binding).is_err(),
            "missing {key}"
        );
        assert!(
            verify_axt_bound_batch(&missing, &[], &binding).is_err(),
            "missing {key}"
        );
        let mut changed = batch.clone();
        changed.metadata.get_mut(key).unwrap().push(0xFF);
        assert!(
            compact::prepare(&changed, &binding).is_err(),
            "changed {key}"
        );
    }
    let mut changed = batch.clone();
    changed.parameter = "different-parameter".into();
    assert!(compact::prepare(&changed, &binding).is_err());
    changed = batch.clone();
    changed.public_inputs.dsid = dsid_bytes(binding.source_dsid + 1);
    assert!(compact::prepare(&changed, &binding).is_err());
    changed = batch.clone();
    changed.transitions[0].post_value[0] ^= 1;
    assert!(compact::prepare(&changed, &binding).is_err());
    let mut other_binding = binding.clone();
    other_binding.claim_digest = hex::encode([0x55; 32]);
    assert!(compact::prepare(&batch, &other_binding).is_err());
    changed = batch;
    changed
        .metadata
        .insert(AXT_FASTPQ_BINDING_METADATA_KEY.into(), vec![0xFF]);
    assert!(matches!(
        compact::prepare(&changed, &binding),
        Err(Error::TransferMetadataDecode { .. })
    ));
}

#[test]
fn canonical_preparation_rejects_wrong_transfer_statement_even_when_resealed() {
    let binding = transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    batch.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    let mut transcripts = decode_transcripts(&batch.metadata).unwrap().unwrap();
    transcripts[0].batch_hash = Hash::new(b"unrelated source execution");
    transcripts[0].poseidon_preimage_digest =
        Some(crate::gadgets::transfer::compute_poseidon_digest(
            &transcripts[0].deltas[0],
            &transcripts[0].batch_hash,
        ));
    batch.metadata.insert(
        TRANSFER_TRANSCRIPTS_METADATA_KEY.into(),
        to_bytes(&transcripts).unwrap(),
    );
    let before = batch.clone();
    assert!(matches!(
        bind_axt_batch(&mut batch, &binding, [0x42; 32], Some([0x24; 32])),
        Err(Error::InvalidAxtBinding { details })
            if details.contains("transfer transcript batch_hash does not match source_tx_commitment")
    ));
    assert_eq!(
        batch, before,
        "rejected source binding must not rewrite metadata"
    );
    assert!(compact::prepare(&batch, &binding).is_err());
    batch.push(StateTransition::new(
        b"opaque appended row".to_vec(),
        vec![],
        vec![1],
        OperationKind::MetaSet,
    ));
    assert!(compact::prepare(&batch, &binding).is_err());
}

#[test]
fn envelope_selectors_reject_mismatch_before_canonical_artifact_decoding() {
    let binding = transfer_binding();
    let mut envelope = envelope_with_payload(binding.clone(), vec![0xFF]);
    envelope.fastpq_binding = None;
    assert!(
        matches!(verify_axt_proof_envelope(&envelope), Err(Error::InvalidAxtBinding { details }) if details.contains("missing fastpq_binding"))
    );
    envelope.fastpq_binding = Some(binding.clone());
    envelope.fastpq_binding.as_mut().unwrap().verifier_id = "halo2".into();
    assert!(
        matches!(verify_axt_proof_envelope(&envelope), Err(Error::InvalidAxtBinding { details }) if details.contains("verifier_id"))
    );
    envelope.fastpq_binding = Some(binding);
    envelope.dsid = DataSpaceId::new(8);
    assert!(
        matches!(verify_axt_proof_envelope(&envelope), Err(Error::InvalidAxtBinding { details }) if details.contains("dsid"))
    );
}

#[test]
fn canonical_artifact_outer_mirrors_are_compared_before_child_proof_decode() {
    let binding = transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    bind_axt_batch_with_proof_metadata(
        &mut batch,
        &binding,
        [0x42; 32],
        Some([0x24; 32]),
        Some(50),
        Some(5),
    )
    .unwrap();
    let artifact = compact::prepare(&batch, &binding).unwrap();
    assert_eq!(artifact.mirrors.committed_amount, Some(50));
    assert_eq!(artifact.mirrors.expiry_slot, Some(5));
    let mut envelope = envelope_with_payload(binding, norito::encode_canonical(&artifact).unwrap());
    envelope.committed_amount = Some(50);
    for field in 0..4 {
        let mut changed = envelope.clone();
        match field {
            0 => changed.manifest_root[0] ^= 1,
            1 => changed.da_commitment = None,
            2 => changed.committed_amount = Some(51),
            _ => changed.committed_amount = None,
        }
        let error = verify_axt_proof_envelope(&changed).unwrap_err();
        assert!(
            matches!(
                error,
                Error::InvalidAxtBinding { .. } | Error::PublicIoMismatch { .. }
            ),
            "field {field}: {error:?}"
        );
    }
    for expiry in [None, Some(0), Some(500)] {
        assert!(
            axt_proof_blob_from_bound_batch(&batch, vec![], [0x42; 32], Some([0x24; 32]), expiry)
                .is_err()
        );
    }
    for (manifest, da) in [
        ([0x99; 32], Some([0x24; 32])),
        ([0x42; 32], None),
        ([0x42; 32], Some([0x77; 32])),
    ] {
        assert!(axt_proof_envelope_from_bound_batch(&batch, vec![], manifest, da).is_err());
    }
    let mut unbound = batch.clone();
    unbound.metadata.remove(AXT_FASTPQ_BINDING_METADATA_KEY);
    assert!(
        axt_proof_envelope_from_bound_batch(&unbound, vec![], [0x42; 32], Some([0x24; 32]))
            .is_err()
    );
}

#[test]
fn canonical_expiry_and_amount_metadata_reject_missing_malformed_and_zero_values() {
    let binding = transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    for (key, malformed) in [
        (AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY, vec![0; 7]),
        (AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY, vec![1; 15]),
        (AXT_FASTPQ_COMMITTED_AMOUNT_METADATA_KEY, vec![0; 16]),
    ] {
        let mut changed = batch.clone();
        changed.metadata.insert(key.into(), malformed);
        assert!(compact::prepare(&changed, &binding).is_err());
        let parsed = if key == AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY {
            proof_bound_expiry_slot(&changed).map(|_| ())
        } else {
            proof_bound_committed_amount(&changed).map(|_| ())
        };
        assert!(parsed.is_err());
    }
    let mut changed = batch.clone();
    changed.metadata.remove(AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY);
    assert!(matches!(
        proof_bound_expiry_slot(&changed),
        Err(Error::MissingMetadata { .. })
    ));
    for (amount, expiry) in [(None, Some(0)), (Some(0), None)] {
        assert!(
            bind_axt_batch_with_proof_metadata(
                &mut changed,
                &binding,
                [0x42; 32],
                None,
                amount,
                expiry
            )
            .is_err()
        );
    }
}

#[test]
#[ignore = "full masked 8M-row AXT proof and public envelope/blob verification; explicit resource diagnostic"]
fn canonical_masked_axt_proof_roundtrip_and_context_mutations() {
    let binding = remote_transfer_binding();
    let mut batch = real_transfer_claim_batch(&binding);
    bind_axt_batch_with_proof_metadata(
        &mut batch,
        &binding,
        [0x42; 32],
        Some([0x24; 32]),
        Some(50),
        Some(100),
    )
    .unwrap();
    let proof = prove_axt_bound_batch(&batch, &binding).unwrap();
    verify_axt_bound_batch(&batch, &proof, &binding).unwrap();
    let envelope =
        axt_proof_envelope_from_bound_batch(&batch, proof.clone(), [0x42; 32], Some([0x24; 32]))
            .unwrap();
    let verified = verify_axt_proof_envelope(&envelope).unwrap();
    assert_eq!(verified.old_root, batch.public_inputs.old_root);
    assert_eq!(verified.new_root, batch.public_inputs.new_root);
    assert_eq!(verified.tx_set_hash, batch.public_inputs.tx_set_hash);
    assert_eq!(verified.expiry_slot, Some(100));
    assert_ne!(verified.statement_digest, [0; 32]);
    assert_ne!(verified.proof_digest, Hash::prehashed([0; 32]));
    let blob = axt_proof_blob_from_bound_batch(
        &batch,
        proof.clone(),
        [0x42; 32],
        Some([0x24; 32]),
        Some(100),
    )
    .unwrap();
    verify_axt_proof_blob(&blob).unwrap();
    for expiry in [None, Some(0), Some(101)] {
        let mut changed = blob.clone();
        changed.expiry_slot = expiry;
        assert!(verify_axt_proof_blob(&changed).is_err());
    }
    let mut altered = envelope.clone();
    altered.manifest_root[0] ^= 1;
    assert!(verify_axt_proof_envelope(&altered).is_err());
    altered = envelope.clone();
    altered.da_commitment = None;
    assert!(verify_axt_proof_envelope(&altered).is_err());
    altered = envelope.clone();
    altered.committed_amount = None;
    assert!(verify_axt_proof_envelope(&altered).is_err());
    let mut other = batch.clone();
    other.metadata.remove(AXT_FASTPQ_BATCH_SEAL_METADATA_KEY);
    bind_axt_batch_with_proof_metadata(
        &mut other,
        &binding,
        [0x42; 32],
        Some([0x24; 32]),
        Some(50),
        Some(500),
    )
    .unwrap();
    assert!(verify_axt_bound_batch(&other, &proof, &binding).is_err());
    assert!(encode_axt_fastpq_payload(&other, proof).is_err());
    altered = envelope;
    let last = altered.proof.len() - 1;
    altered.proof[last] ^= 1;
    assert!(verify_axt_proof_envelope(&altered).is_err());
}

#[path = "tests/anchored.rs"]
mod anchored;

#[test]
fn canonical_bound_producer_reports_typed_contention_and_preserves_original_retry() {
    use crate::offline_compact::{
        ExpectedAxtContext, ExpectedStatement, ProvingError, ProvingLimits, VerificationLimits,
    };
    use crate::test_producer_funding::prove_quantity_axt_artifact;

    let binding = transfer_binding();
    let batch = real_transfer_claim_batch(&binding);
    let artifact = compact::prepare(&batch, &binding).expect("original valid AXT statement");
    let original = norito::encode_canonical(&artifact).expect("encode original public statement");
    let expected = ExpectedStatement {
        inputs: artifact.statement.public_inputs,
        ordering_hash: artifact.statement.ordering_hash,
        public_statement_digest: Hash::new(
            norito::encode_canonical(&artifact.statement).expect("encode original statement"),
        )
        .into(),
    };
    let context = ExpectedAxtContext {
        binding: &artifact.binding,
        metadata: &artifact.metadata,
        mirrors: artifact.mirrors,
        remote_spend_claims: artifact.remote_spend_claims.as_deref(),
    };
    // This real caller policy deliberately forbids trace work. The producer
    // acquires its original permit before checking that policy, so held versus
    // released outcomes prove admission changed without generating a proof.
    let no_trace_work = ProvingLimits {
        max_total_trace_cells: 0,
        ..ProvingLimits::default()
    };
    {
        let _held = crate::backend::hold_quantity_producer_for_test();
        assert!(matches!(
            prove_axt_bound_batch(&batch, &binding),
            Err(Error::ProducerBusy)
        ));
        let mut opaque = binding.clone();
        opaque.claim_type = "authorization".into();
        let expected_refusal = validate_axt_transfer_claim_binding(&opaque)
            .expect_err("opaque binding cannot select the transfer producer");
        let refused = prove_axt_bound_batch(&batch, &opaque)
            .expect_err("semantic binding refusal must precede producer admission");
        assert!(matches!(refused, Error::InvalidProofSemantics { .. }));
        assert_eq!(refused.to_string(), expected_refusal.to_string());
        assert!(matches!(
            prove_quantity_axt_artifact(
                &artifact.statement,
                expected,
                context,
                no_trace_work,
                VerificationLimits::default(),
            ),
            Err(ProvingError::Busy)
        ));
    }
    let retry = loop {
        match prove_quantity_axt_artifact(
            &artifact.statement,
            expected,
            context,
            no_trace_work,
            VerificationLimits::default(),
        ) {
            Err(ProvingError::Busy) => std::thread::sleep(std::time::Duration::from_millis(10)),
            result => break result,
        }
    };
    assert!(matches!(
        retry,
        Err(ProvingError::Prove(Error::VerifierLimitExceeded {
            limit: "max_compact_prover_trace_cells",
            actual,
            max: 0,
        })) if actual > 0
    ));
    assert_eq!(
        norito::encode_canonical(&artifact).expect("encode retained original"),
        original,
    );
    assert_eq!(
        norito::encode_canonical(&compact::prepare(&batch, &binding).expect("retry preparation"))
            .expect("encode retry public statement"),
        original,
    );
}
