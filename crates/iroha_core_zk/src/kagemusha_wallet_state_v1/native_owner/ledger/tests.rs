//! Genuine native certificates and explicit mock custody exercise online-prefix publication.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, fixture, synthetic_payout_wallet};
use iroha_data_model::sumeragi_finality::{
    WorldStateElementKindV1, WorldStateSnapshotEntryV1, test_fixtures::NativeFinalityFixture,
    world_state_value_hash_v1,
};
fn wallet(native: &NativeFinalityFixture) -> Wallet {
    let mut scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    scheme.network_id = *native.network_id().as_bytes();
    synthetic_payout_wallet(scheme, native.chain_id().to_owned())
}
fn certify(native: &mut NativeFinalityFixture) -> Vec<u8> {
    let block = native.block_with_submitted_work(native.next_header());
    archive::encode(&native.certify(block)).unwrap()
}
fn restart(wallet: Wallet) -> Wallet {
    Coordinator::new(
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    )
    .unwrap()
}
#[test]
fn enrollment_cannot_publish_a_ledger_checkpoint_before_bootstrap() {
    let native = NativeFinalityFixture::start("wallet-ledger-before-bootstrap");
    let mut w = crate::kagemusha_wallet_state_v1::tests::wallet();
    assert!(matches!(
        w.ingest_ledger_original(
            &native.verifier(),
            &archive::encode(native.genesis_proof()).unwrap()
        ),
        Err(Error::NoHead)
    ));
    assert!(w.custody.archive_checkpoint().unwrap().is_none());
    assert!(w.manifest().unwrap().1.indexed.is_none());
}
#[test]
fn ledger_original_bounds_refuse_empty_trailing_oversized_and_checkpoint_frames() {
    assert!(proof_original(&[]).is_err());
    assert!(payout_original(&[]).is_err());
    assert!(payout_original(&vec![0; PAYOUT_RECORD_MAX_BYTES_V1 + 1]).is_err());
    let native = NativeFinalityFixture::start("ledger-original-bound");
    let mut raw = archive::encode(native.genesis_proof()).unwrap();
    assert!(proof_original(&raw).is_ok());
    raw.push(0);
    assert!(matches!(proof_original(&raw), Err(Error::Invalid(_))));
    assert!(matches!(payout_original(&raw), Err(Error::Invalid(_))));
    assert!(proof_original(&native.checkpoint().encode_canonical().unwrap()).is_err());
    assert!(proof_original(&vec![0; LEDGER_PROOF_MAX_BYTES_V1 + 1]).is_err());
}

#[test]
fn ledger_continuity_exact_retry_foreign_root_and_selected_original_loss() {
    let mut native = NativeFinalityFixture::start("wallet-ledger-continuity");
    let genesis = native.verifier();
    let mut w = wallet(&native);
    assert_eq!(w.ledger_progress_selected(&genesis).unwrap(), None);
    let first = certify(&mut native);
    let second = certify(&mut native);
    assert!(w.ingest_ledger_original(&genesis, &second).is_err());
    let one = w.ingest_ledger_original(&genesis, &first).unwrap();
    assert_eq!(one.height, 2);
    assert_eq!(w.ingest_ledger_original(&genesis, &first).unwrap(), one);
    let mut alternate: SumeragiFinalityProof = archive::decode(&first).unwrap();
    alternate.block_wire[0] ^= 1;
    assert!(
        w.ingest_ledger_original(&genesis, &archive::encode(&alternate).unwrap())
            .is_err()
    );
    let selected_checkpoint = w.manifest().unwrap().1.ledger_checkpoint;
    let mut foreign = NativeFinalityFixture::start("foreign-ledger");
    assert!(
        w.ingest_ledger_original(&genesis, &certify(&mut foreign))
            .is_err()
    );
    assert_eq!(w.ledger_progress_selected(&genesis).unwrap(), Some(one));
    assert_eq!(
        w.manifest().unwrap().1.ledger_checkpoint,
        selected_checkpoint
    );
    let two = w.ingest_ledger_original(&genesis, &second).unwrap();
    assert_eq!(two.height, 3);
    assert!(w.ingest_ledger_original(&genesis, &first).is_err());
    let mut w = restart(w);
    assert_eq!(w.ledger_progress_selected(&genesis).unwrap(), Some(two));
    assert!(w.ledger_progress_selected(&foreign.verifier()).is_err());
    let (_, manifest) = w.manifest().unwrap();
    assert!(manifest.ledger_retired.is_none());
    w.archive
        .remove(ArchiveKey::Object(manifest.ledger_checkpoint.unwrap()))
        .unwrap();
    assert!(matches!(
        w.ledger_progress_selected(&genesis),
        Err(Error::WitnessLost(_))
    ));
    assert!(w.ingest_ledger_original(&genesis, &second).is_err());
}
#[test]
fn ledger_fresh_and_same_height_ingress_reject_wrong_committee_and_nonexact_quorums() {
    use iroha_data_model::block::{CommitCertificate, decode_framed_signed_block};
    use iroha_sumeragi::{message::Qc, types::Bitmap};
    let mut native = NativeFinalityFixture::start("wallet-ledger-quorum");
    let genesis = native.verifier();
    let original = certify(&mut native);
    let proof: SumeragiFinalityProof = archive::decode(&original).unwrap();
    let mut malformed = Vec::new();
    let mut foreign = proof.clone();
    foreign.committee[0].proof_of_possession[0] ^= 1;
    malformed.push(archive::encode(&foreign).unwrap());
    for count in [2u32, 4] {
        let mut wrong = proof.clone();
        let mut block = decode_framed_signed_block(&wrong.block_wire).unwrap();
        let certificate = block.commit_certificate().unwrap();
        let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
        qc.signers = Bitmap::from_indices(4, 0..count).unwrap();
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            certificate.consensus_header().to_vec(),
            norito::encode_canonical(&qc).unwrap(),
            certificate.result_preimage().to_vec(),
            certificate.availability().to_vec(),
        )));
        wrong.block_wire = block.encode_wire().unwrap();
        malformed.push(archive::encode(&wrong).unwrap());
    }
    let mut w = wallet(&native);
    for raw in &malformed {
        assert!(w.ingest_ledger_original(&genesis, raw).is_err());
        assert_eq!(w.ledger_progress_selected(&genesis).unwrap(), None);
    }
    let selected = w.ingest_ledger_original(&genesis, &original).unwrap();
    for raw in &malformed {
        assert!(w.ingest_ledger_original(&genesis, raw).is_err());
        assert_eq!(
            w.ledger_progress_selected(&genesis).unwrap(),
            Some(selected)
        );
    }
    assert_eq!(
        w.ingest_ledger_original(&genesis, &original).unwrap(),
        selected
    );
}
#[test]
fn ledger_uncertain_publication_reconciles_selected_tip_and_bounds_cleanup() {
    for after in [false, true] {
        let mut native = NativeFinalityFixture::start("wallet-ledger-uncertain");
        let genesis = native.verifier();
        let mut w = wallet(&native);
        let first = certify(&mut native);
        w.custody.fail_publication = Some(after);
        assert!(w.ingest_ledger_original(&genesis, &first).is_err());
        let mut w = restart(w);
        assert_eq!(
            w.ledger_progress_selected(&genesis).unwrap().is_some(),
            after
        );
        let one = w.ingest_ledger_original(&genesis, &first).unwrap();
        assert_eq!(one.height, 2);
        let second = certify(&mut native);
        w.archive.fail_remove = true;
        assert!(w.ingest_ledger_original(&genesis, &second).is_err());
        let (_, manifest) = w.manifest().unwrap();
        assert!(manifest.ledger_retired.is_some());
        assert_ne!(manifest.ledger_checkpoint, manifest.ledger_retired);
        let mut w = restart(w);
        assert_eq!(
            w.ledger_progress_selected(&genesis)
                .unwrap()
                .unwrap()
                .height,
            3
        );
        w.custody.fail_publication = Some(after);
        assert!(w.ingest_ledger_original(&genesis, &second).is_err());
        // The old object was already removed. A lost cleanup selection cannot make its
        // absence corrupt the still-selected new checkpoint, and cleanup remains idempotent.
        let mut w = restart(w);
        assert_eq!(
            w.ingest_ledger_original(&genesis, &second).unwrap().height,
            3
        );
        assert!(w.manifest().unwrap().1.ledger_retired.is_none());
    }
}
#[test]
fn payout_originals_require_selected_tip_exact_world_and_row_before_custody_release() {
    let mut native = NativeFinalityFixture::start("wallet-ledger-payout");
    let genesis = native.verifier();
    let mut w = wallet(&native);
    crate::kagemusha_wallet_state_v1::fee_claims::tests::seed_ledger_acknowledgement(&mut w);
    let payout = KagemushaWalletPayoutRecordV1 {
        key: KagemushaWalletPayoutKeyV1::Fee([2; 32]),
        source: [3; 32],
        amount: 17,
        transaction: [5; 32],
    };
    let world = WorldStateSnapshotV1 {
        schema_hash: iroha_crypto::Hash::new(b"native payout ingress schema"),
        entries: vec![WorldStateSnapshotEntryV1 {
            field_id: "world.kagemusha_wallet_ledger".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(world_state_value_hash_v1(&payout.key.ledger_key(w.scheme_id)).unwrap()),
            value_hash: world_state_value_hash_v1(&norito::to_bytes(&payout).unwrap()).unwrap(),
        }],
    };
    let world_bytes = archive::encode(&world).unwrap();
    let payout_bytes = archive::encode(&payout).unwrap();
    assert!(
        w.acknowledge_payout_originals(&genesis, [2; 32], &world_bytes, &payout_bytes)
            .is_err()
    );
    let block = native.block_with_submitted_work(native.next_header());
    let original =
        archive::encode(&native.certify_with_world_root(block, world.root().unwrap())).unwrap();
    w.ingest_ledger_original(&genesis, &original).unwrap();
    let mut foreign = payout;
    foreign.amount += 1;
    assert!(
        w.acknowledge_payout_originals(
            &genesis,
            [2; 32],
            &world_bytes,
            &archive::encode(&foreign).unwrap()
        )
        .is_err()
    );
    let mut wrong_world = world;
    wrong_world.schema_hash = iroha_crypto::Hash::new(b"wrong");
    assert!(
        w.acknowledge_payout_originals(
            &genesis,
            [2; 32],
            &archive::encode(&wrong_world).unwrap(),
            &payout_bytes
        )
        .is_err()
    );
    assert!(
        w.archive
            .get(ArchiveKey::FeeClaim([2; 32]), 128)
            .unwrap()
            .is_some()
    );
    for after in [false, true] {
        w.custody.fail_publication = Some(after);
        assert!(
            w.acknowledge_payout_originals(&genesis, [2; 32], &world_bytes, &payout_bytes)
                .is_err()
        );
        assert!(
            w.archive
                .get(ArchiveKey::FeeClaim([2; 32]), 128)
                .unwrap()
                .is_some()
        );
        w = restart(w);
    }
    w.acknowledge_payout_originals(&genesis, [2; 32], &world_bytes, &payout_bytes)
        .unwrap();
    assert_eq!(
        w.archive.get(ArchiveKey::FeeClaim([2; 32]), 128).unwrap(),
        None
    );
    let mut w = restart(w);
    w.acknowledge_payout_originals(&genesis, [2; 32], &world_bytes, &payout_bytes)
        .unwrap();
    assert!(
        w.acknowledge_payout_originals(&genesis, [9; 32], &world_bytes, &payout_bytes)
            .is_err()
    );
}
