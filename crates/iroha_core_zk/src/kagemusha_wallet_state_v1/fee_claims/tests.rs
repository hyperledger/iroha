//! Genuine native certificates authenticate synthetic payout rows; no mock finality verdict.
use super::*;
use iroha_data_model::sumeragi_finality::{
    WorldStateElementKindV1, WorldStateSnapshotEntryV1, WorldStateSnapshotV1,
    test_fixtures::NativeFinalityFixture, world_state_value_hash_v1,
};

fn retained_request_fixture() -> KagemushaWalletRequestV1 {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"].as_str() == Some("Request"))
        .unwrap();
    let envelope: KagemushaWalletEnvelopeV1 =
        archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("retained Request envelope");
    };
    request
}

fn snapshot(
    scheme: &KagemushaWalletSchemeV1,
    payout: &KagemushaWalletPayoutRecordV1,
) -> WorldStateSnapshotV1 {
    let bytes = norito::to_bytes(payout).unwrap();
    WorldStateSnapshotV1 {
        schema_hash: iroha_crypto::Hash::new(b"wallet synthetic payout schema"),
        entries: vec![WorldStateSnapshotEntryV1 {
            field_id: "world.kagemusha_wallet_ledger".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(
                world_state_value_hash_v1(&payout.key.ledger_key(scheme.scheme_id())).unwrap(),
            ),
            value_hash: world_state_value_hash_v1(&bytes).unwrap(),
        }],
    }
}
fn certify(
    native: &mut NativeFinalityFixture,
    snapshot: &WorldStateSnapshotV1,
) -> VerifiedSumeragiBlock {
    let block = native.block_with_submitted_work(native.next_header());
    let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
    native.verifier().verify_retained_decision(&proof).unwrap()
}
fn claim() -> FeeClaimEntry {
    FeeClaimEntry {
        payment: [3; 32],
        content: [4; 32],
        fee: 17,
        payout: None,
    }
}
fn payout() -> KagemushaWalletPayoutRecordV1 {
    KagemushaWalletPayoutRecordV1 {
        key: KagemushaWalletPayoutKeyV1::Fee([2; 32]),
        source: [3; 32],
        amount: 17,
        transaction: [5; 32],
    }
}

#[test]
fn acknowledged_claim_metadata_stays_inside_the_authenticated_index_bound() {
    let mut value = claim();
    value.payout = Some(payout());
    assert!(archive::encode(&value).unwrap().len() <= index::INDEX_VALUE_LIMIT);
}

#[test]
fn exact_finalized_payout_binds_native_scope_and_row_and_survives_growth() {
    let mut native = NativeFinalityFixture::start("wallet-payout-test");
    let mut scheme: KagemushaWalletSchemeV1 =
        super::super::tests::fixture("KagemushaWalletSchemeV1");
    scheme.network_id = *native.network_id().as_bytes();
    let snapshot = snapshot(&scheme, &payout());
    let block = certify(&mut native, &snapshot);
    let world = snapshot.authenticate(&block).unwrap();
    let evidence = FinalizedPayoutEvidence {
        block: &block,
        world: &world,
        payout: payout(),
    };
    assert!(verify_payout(&scheme, native.chain_id(), [2; 32], &claim(), &evidence).is_ok());
    let later = certify(&mut native, &snapshot);
    assert!(later.height() > block.height());
    assert!(verify_payout(&scheme, native.chain_id(), [2; 32], &claim(), &evidence).is_ok());
    let wrong_block = FinalizedPayoutEvidence {
        block: &later,
        world: &world,
        payout: payout(),
    };
    assert!(verify_payout(&scheme, native.chain_id(), [2; 32], &claim(), &wrong_block).is_err());
    assert!(verify_payout(&scheme, "other-chain", [2; 32], &claim(), &evidence).is_err());
    assert!(verify_payout(&scheme, native.chain_id(), [9; 32], &claim(), &evidence).is_err());
    let mut foreign = scheme.clone();
    foreign.relation_id[0] ^= 1;
    assert!(verify_payout(&foreign, native.chain_id(), [2; 32], &claim(), &evidence).is_err());
    foreign = scheme.clone();
    foreign.network_id[0] ^= 1;
    assert!(verify_payout(&foreign, native.chain_id(), [2; 32], &claim(), &evidence).is_err());
    for mutation in 0..5 {
        let mut changed = payout();
        match mutation {
            0 => changed.key = KagemushaWalletPayoutKeyV1::Unload([2; 32]),
            1 => changed.source[0] ^= 1,
            2 => changed.amount += 1,
            3 => changed.transaction[0] ^= 1,
            _ => changed.transaction = [0; 32],
        }
        let evidence = FinalizedPayoutEvidence {
            block: &block,
            world: &world,
            payout: changed,
        };
        assert!(
            verify_payout(&scheme, native.chain_id(), [2; 32], &claim(), &evidence).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn acknowledgement_retries_reverify_and_never_delete_before_durable_payout() {
    let mut native = NativeFinalityFixture::start("wallet-payout-custody-test");
    let mut scheme: KagemushaWalletSchemeV1 =
        super::super::tests::fixture("KagemushaWalletSchemeV1");
    scheme.network_id = *native.network_id().as_bytes();
    let snapshot = snapshot(&scheme, &payout());
    let block = certify(&mut native, &snapshot);
    let world = snapshot.authenticate(&block).unwrap();
    let evidence = FinalizedPayoutEvidence {
        block: &block,
        world: &world,
        payout: payout(),
    };
    for failure in 0..3 {
        let mut wallet = super::super::tests::synthetic_payout_wallet(
            scheme.clone(),
            native.chain_id().to_owned(),
        );
        let (old, mut manifest) = wallet.manifest().unwrap();
        manifest.claims = manifest
            .claims
            .set(
                &mut wallet.archive,
                [2; 32],
                &archive::encode(&claim()).unwrap(),
            )
            .unwrap();
        wallet.publish_manifest(old, &manifest).unwrap();
        // The indexed record is synthetic; this test exercises publication ordering and
        // independently verified native payout evidence, not original-payment validation.
        let key = ArchiveKey::FeeClaim([2; 32]);
        wallet.archive.put(key, b"retained originals").unwrap();
        match failure {
            0 => wallet.custody.fail_publication = Some(false),
            1 => wallet.custody.fail_publication = Some(true),
            _ => wallet.archive.fail_remove = true,
        }
        assert!(wallet.acknowledge_fee_payout([2; 32], &evidence).is_err());
        assert_eq!(
            wallet.archive.get(key, 128).unwrap(),
            Some(b"retained originals".to_vec())
        );
        let (_, manifest) = wallet.manifest().unwrap();
        let selected: FeeClaimEntry = archive::decode(
            &manifest
                .claims
                .get(&mut wallet.archive, &[2; 32])
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(selected.payout.is_some(), failure != 0);
        wallet = Coordinator::new(
            wallet.custody,
            wallet.archive,
            wallet.proofs,
            wallet.scheme_id,
            wallet.wallet_id,
        )
        .unwrap();
        let mut foreign = payout();
        foreign.transaction[0] ^= 1;
        let invalid = FinalizedPayoutEvidence {
            block: &block,
            world: &world,
            payout: foreign,
        };
        assert!(wallet.acknowledge_fee_payout([2; 32], &invalid).is_err());
        assert!(wallet.archive.get(key, 128).unwrap().is_some());
        wallet.acknowledge_fee_payout([2; 32], &evidence).unwrap();
        assert_eq!(wallet.archive.get(key, 128).unwrap(), None);
        assert_eq!(wallet.fee_claim([2; 32]).unwrap(), None);
        wallet.acknowledge_fee_payout([2; 32], &evidence).unwrap();
        assert!(wallet.acknowledge_fee_payout([2; 32], &invalid).is_err());
        assert!(wallet.acknowledge_fee_payout([9; 32], &evidence).is_err());
    }
}

// Shared only by native-ledger ingress tests; originals remain explicit synthetic custody.
pub(in crate::kagemusha_wallet_state_v1) fn seed_ledger_acknowledgement(
    wallet: &mut super::super::tests::Wallet,
) {
    let (root, mut manifest) = wallet.manifest().unwrap();
    manifest.claims = manifest
        .claims
        .set(
            &mut wallet.archive,
            [2; 32],
            &archive::encode(&claim()).unwrap(),
        )
        .unwrap();
    wallet.publish_manifest(root, &manifest).unwrap();
    wallet
        .archive
        .put(ArchiveKey::FeeClaim([2; 32]), b"retained originals")
        .unwrap();
}

#[test]
fn aggregate_fee_original_encoding_bound_and_canonical_projection() {
    // At both permitted original byte limits the canonical carrier has its actual maximum
    // encoding length. Payload DATA here is not a valid Payment; 1024 is a conservative
    // metadata allowance, not a claim about valid monetary proof sizes.
    let maximum = RetainedFeeClaim {
        payment: vec![1; 10_000],
        request: vec![2; 10_000],
    };
    let encoded = archive::encode(&maximum).unwrap();
    println!(
        "fee claim maximum original carrier encoding: {} bytes",
        encoded.len()
    );
    assert!(encoded.len() <= FEE_CLAIM_MAX_BYTES_V1);
    assert_eq!(FEE_CLAIM_MAX_BYTES_V1, 21_024);
    assert!(
        RetainedFeeClaim::decode_canonical(&vec![0; FEE_CLAIM_MAX_BYTES_V1 + 1], &[0; 32]).is_err()
    );
    let payment: KagemushaWalletPaymentV1 =
        super::super::tests::fixture("KagemushaWalletPaymentV1");
    let request = retained_request_fixture();
    let claim = RetainedFeeClaim {
        payment: payment.to_canonical_bytes().unwrap(),
        request: archive::encode(&request).unwrap(),
    };
    let scheme = payment.send.statement.scheme_id;
    let bytes = claim.to_canonical_bytes(&scheme).unwrap();
    assert_eq!(
        RetainedFeeClaim::decode_canonical(&bytes, &scheme).unwrap(),
        claim
    );
    assert!(RetainedFeeClaim::decode_canonical(&bytes, &[9; 32]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        RetainedFeeClaim::decode_canonical(&trailing, &scheme),
        Err(Error::Invalid(_))
    ));
    let mut changed = claim;
    changed.request.push(0);
    assert!(changed.to_canonical_bytes(&scheme).is_err());
}

#[test]
fn native_fee_transport_roundtrips_exact_pair_and_refuses_foreign_beneficiary_or_zero_fee() {
    let claim: KagemushaWalletFeeClaimV1 =
        super::super::tests::fixture("KagemushaWalletFeeClaimV1");
    let request = retained_request_fixture();
    let scheme = claim.payment.request.body.scheme_id;
    let retained = RetainedFeeClaim {
        payment: claim.payment.to_canonical_bytes().unwrap(),
        request: archive::encode(&request).unwrap(),
    };
    let beneficiary = archive::encode(&claim.beneficiary).unwrap();
    let bytes = retained.ledger_claim_bytes(&scheme, &beneficiary).unwrap();
    assert_eq!(bytes, claim.to_canonical_bytes().unwrap());
    assert_eq!(
        retained.ledger_claim_bytes(&scheme, &beneficiary).unwrap(),
        bytes
    );
    assert_eq!(
        KagemushaWalletFeeClaimV1::decode_canonical(&bytes, &scheme).unwrap(),
        claim
    );
    let foreign = iroha_data_model::account::AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![189; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    assert!(
        retained
            .ledger_claim_bytes(&scheme, &archive::encode(&foreign).unwrap())
            .is_err()
    );
    assert!(retained.ledger_claim_bytes(&[9; 32], &beneficiary).is_err());
    let mut trailing = beneficiary.clone();
    trailing.push(0);
    assert!(retained.ledger_claim_bytes(&scheme, &trailing).is_err());
    assert!(
        retained
            .ledger_claim_bytes(
                &scheme,
                &vec![0; KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1 + 1]
            )
            .is_err()
    );
    assert!(
        KagemushaWalletFeeClaimV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1 + 1],
            &scheme
        )
        .is_err()
    );
    let mut zero = claim.payment;
    zero.request.body.fee = 0;
    let zero = RetainedFeeClaim {
        payment: archive::encode(&zero).unwrap(),
        request: retained.request,
    };
    assert!(zero.ledger_claim_bytes(&scheme, &beneficiary).is_err());
}

#[test]
fn fee_transport_encoding_fits_existing_cap_at_large_original_boundaries() {
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    let mut claim: KagemushaWalletFeeClaimV1 =
        super::super::tests::fixture("KagemushaWalletFeeClaimV1");
    // Encoding capacity only: opaque proof padding is not genuine proof evidence, and the
    // enlarged account is not the fixture's authorized schedule beneficiary.
    let mut low = 1;
    let mut high = 10_001;
    while high - low > 1 {
        let next = (low + high) / 2;
        claim.payment.send.step_proof.bytes.resize(next, 0);
        if archive::encode(&claim.payment).unwrap().len() <= 10_000 {
            low = next;
        } else {
            high = next;
        }
    }
    claim.payment.send.step_proof.bytes.resize(low, 0);
    let payment_bytes = archive::encode(&claim.payment).unwrap().len();
    let mut members = Vec::new();
    let mut last_fitting = claim.beneficiary.clone();
    let mut overflowing = None;
    for seed in 1..=128u8 {
        members.push(
            MultisigMember::new(
                iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
                1,
            )
            .unwrap(),
        );
        claim.beneficiary =
            AccountId::new_multisig(MultisigPolicy::new(1, members.clone()).unwrap());
        let account_bytes = archive::encode(&claim.beneficiary).unwrap().len();
        assert!(account_bytes <= KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1);
        let bytes = archive::encode(&claim).unwrap();
        if bytes.len() > KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1 {
            overflowing = Some(bytes);
            break;
        }
        assert!(bytes.len() <= payment_bytes + account_bytes + 128);
        last_fitting = claim.beneficiary.clone();
    }
    let overflow =
        overflowing.expect("large individually bounded originals exceed the aggregate cap");
    assert!(
        KagemushaWalletFeeClaimV1::decode_canonical(
            &overflow,
            &claim.payment.request.body.scheme_id
        )
        .is_err()
    );
    claim.beneficiary = last_fitting;
    let account_bytes = archive::encode(&claim.beneficiary).unwrap().len();
    assert!(payment_bytes > 9_900 && payment_bytes <= 10_000);
    assert!(account_bytes > 4_096 && account_bytes < KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1);
    let bytes = archive::encode(&claim).unwrap();
    println!(
        "fee transport encoding: payment={payment_bytes}, beneficiary={account_bytes}, claim={}",
        bytes.len()
    );
    assert!(bytes.len() > KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1 - 128);
    assert!(bytes.len() <= KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1);
}
