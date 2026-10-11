//! Real BLS epoch synchronization with explicit mock archive and manifest custody.
//! This exercises restart and publication uncertainty, not complete monetary proof admission.

use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, fixture, synthetic_payout_wallet};
use iroha_data_model::sumeragi_finality::{
    MAX_COMMIT_CERTIFICATE_BYTES_V1, SumeragiFinalityProof, test_fixtures::NativeFinalityFixture,
};

mod later_epochs;

fn chain() -> (
    NativeFinalityFixture,
    Vec<SumeragiFinalityProof>,
    SumeragiFinalityVerifier,
) {
    let (fixture, chain) =
        NativeFinalityFixture::short_npos_boundary_chain_with_explicit_parameters(4);
    let genesis = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    (fixture, chain, genesis)
}

fn certificate(fixture: &NativeFinalityFixture, proof: &SumeragiFinalityProof) -> Vec<u8> {
    SumeragiCommitCertificateV1::from_verified(
        &fixture.verifier().verify_retained_decision(proof).unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap()
}

fn wallet(native: &NativeFinalityFixture) -> Wallet {
    let mut scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    scheme.network_id = *native.network_id().as_bytes();
    synthetic_payout_wallet(scheme, native.chain_id().to_owned())
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
fn epoch_boundary_survives_restart_without_ordinary_block_replay() {
    let (native, chain, genesis) = chain();
    let mut w = wallet(&native);
    let initial = w.epoch_progress_selected(&genesis).unwrap();
    assert_eq!(
        initial,
        NativeEpochProgressV1 {
            epoch: 0,
            first_height: 1,
            boundary_height: 3
        }
    );
    let original = certificate(&native, &chain[2]);
    let selected = w.ingest_epoch_original(&genesis, 0, &original).unwrap();
    assert_eq!(
        selected,
        NativeEpochProgressV1 {
            epoch: 1,
            first_height: 4,
            boundary_height: 6
        }
    );
    assert_eq!(
        w.ingest_epoch_original(&genesis, 0, &original).unwrap(),
        selected
    );
    let manifest_before = w.manifest().unwrap().0;
    let mut w = restart(w);
    assert_eq!(w.epoch_progress_selected(&genesis).unwrap(), selected);
    assert_eq!(
        w.ingest_epoch_original(&genesis, 0, &original).unwrap(),
        selected
    );
    assert_eq!(w.manifest().unwrap().0, manifest_before);
    let (_, manifest) = w.manifest().unwrap();
    let (mut current, _) = w.selected_commit_epoch(&manifest, &genesis, 1).unwrap();
    let successor =
        SumeragiCommitCertificateV1::decode_canonical(&certificate(&native, &chain[3])).unwrap();
    assert_eq!(current.verify(&successor).unwrap().height(), 4);
    let (mut old, _) = w.selected_commit_epoch(&manifest, &genesis, 0).unwrap();
    let delayed =
        SumeragiCommitCertificateV1::decode_canonical(&certificate(&native, &chain[1])).unwrap();
    assert_eq!(old.verify(&delayed).unwrap().height(), 2);
    assert!(old.verify(&successor).is_err());
    assert!(w.selected_commit_epoch(&manifest, &genesis, 2).is_err());
    assert_ne!(epoch_key(0), epoch_key(1));
    assert_ne!(epoch_key(1), epoch_key(u64::MAX));
}

#[test]
fn ordinary_forged_and_foreign_certificates_cannot_publish_an_epoch() {
    let (native, chain, genesis) = chain();
    let mut w = wallet(&native);
    let selected = w.manifest().unwrap().0;
    let ordinary = certificate(&native, &chain[1]);
    assert!(w.ingest_epoch_original(&genesis, 0, &ordinary).is_err());
    let original = certificate(&native, &chain[2]);
    assert!(w.ingest_epoch_original(&genesis, 1, &original).is_err());
    let mut forged = SumeragiCommitCertificateV1::decode_canonical(&original).unwrap();
    let mut qc: iroha_sumeragi::message::Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(
        w.ingest_epoch_original(&genesis, 0, &forged.to_canonical_bytes().unwrap())
            .is_err()
    );
    let foreign = NativeFinalityFixture::start("foreign-native-epoch-root");
    assert!(
        w.ingest_epoch_original(&foreign.verifier(), 0, &original)
            .is_err()
    );
    assert_eq!(w.manifest().unwrap().0, selected);
    assert_eq!(w.epoch_progress_selected(&genesis).unwrap().epoch, 0);
    w.ingest_epoch_original(&genesis, 0, &original).unwrap();
    assert!(w.ingest_epoch_original(&genesis, 1, &original).is_err());
    assert!(
        w.ingest_epoch_original(&genesis, 0, &forged.to_canonical_bytes().unwrap())
            .is_err()
    );
    assert_eq!(w.epoch_progress_selected(&genesis).unwrap().epoch, 1);
}

#[test]
fn epoch_original_ingress_refuses_unbounded_and_checkpoint_data_before_publication() {
    let (native, chain, genesis) = chain();
    let mut w = wallet(&native);
    let original = certificate(&native, &chain[2]);
    let (_, manifest) = w.manifest().unwrap();
    let (_, checkpoint) = w.selected_commit_epoch(&manifest, &genesis, 0).unwrap();
    let mut trailing = original.clone();
    trailing.push(0);
    for raw in [
        vec![],
        vec![0; MAX_COMMIT_CERTIFICATE_BYTES_V1 + 1],
        trailing,
        checkpoint.encode_canonical().unwrap(),
    ] {
        assert!(w.ingest_epoch_original(&genesis, 0, &raw).is_err());
        assert!(w.manifest().unwrap().1.finality_epoch.is_none());
    }
    let mut enrollment = crate::kagemusha_wallet_state_v1::tests::wallet();
    assert!(matches!(
        enrollment.ingest_epoch_original(&genesis, 0, &original),
        Err(Error::NoHead)
    ));
    assert!(enrollment.custody.archive_checkpoint().unwrap().is_none());
}

#[test]
fn uncertain_epoch_publication_uses_selected_custody_on_retry() {
    let (native, chain, genesis) = chain();
    let original = certificate(&native, &chain[2]);
    for after in [false, true] {
        let mut w = wallet(&native);
        w.custody.fail_publication = Some(after);
        assert!(w.ingest_epoch_original(&genesis, 0, &original).is_err());
        let mut w = restart(w);
        assert_eq!(
            w.epoch_progress_selected(&genesis).unwrap().epoch,
            u64::from(after)
        );
        let recovered = w.ingest_epoch_original(&genesis, 0, &original).unwrap();
        assert_eq!(recovered.epoch, 1);
        let mut w = restart(w);
        assert_eq!(w.epoch_progress_selected(&genesis).unwrap(), recovered);
        assert_eq!(
            w.ingest_epoch_original(&genesis, 0, &original).unwrap(),
            recovered
        );
    }
}

#[test]
fn epoch_retry_requires_the_exact_original_digest_selected_by_custody() {
    let (native, chain, genesis) = chain();
    let original = certificate(&native, &chain[2]);
    let mut w = wallet(&native);
    let selected = w.ingest_epoch_original(&genesis, 0, &original).unwrap();
    let (root, mut manifest) = w.manifest().unwrap();
    let mut entry = w.epoch_entry(&manifest, 1).unwrap();
    entry.boundary_original[0] ^= 1;
    manifest.finality_epochs = manifest
        .finality_epochs
        .set(
            &mut w.archive,
            epoch_key(1),
            &archive::encode(&entry).unwrap(),
        )
        .unwrap();
    // Explicit mock-custody corruption leaves the genuine checkpoint and incoming
    // BLS certificate intact, reaching the original-digest join after verification.
    let published = w.publish_manifest(root, &manifest).unwrap();
    assert!(matches!(
        w.ingest_epoch_original(&genesis, 0, &original),
        Err(Error::Proof("epoch retry differs from selected original"))
    ));
    assert_eq!(w.manifest().unwrap().0, published);
    assert_eq!(w.epoch_progress_selected(&genesis).unwrap(), selected);
}

#[test]
fn selected_epoch_loss_or_substitution_never_falls_back_to_genesis() {
    let (native, chain, genesis) = chain();
    let original = certificate(&native, &chain[2]);
    let mut w = wallet(&native);
    w.ingest_epoch_original(&genesis, 0, &original).unwrap();
    let (root, mut manifest) = w.manifest().unwrap();
    let entry = w.epoch_entry(&manifest, 1).unwrap();
    let (_, initial) = w.selected_commit_epoch(&manifest, &genesis, 0).unwrap();
    let replacement = w
        .archive
        .write_object(
            &initial.encode_canonical().unwrap(),
            MAX_COMMIT_CHECKPOINT_BYTES,
        )
        .unwrap();
    let substituted = EpochEntry {
        checkpoint: replacement,
        boundary_original: entry.boundary_original,
    };
    manifest.finality_epochs = manifest
        .finality_epochs
        .set(
            &mut w.archive,
            epoch_key(1),
            &archive::encode(&substituted).unwrap(),
        )
        .unwrap();
    w.publish_manifest(root, &manifest).unwrap();
    assert!(matches!(
        w.epoch_progress_selected(&genesis),
        Err(Error::WitnessLost(_))
    ));
    assert!(w.ingest_epoch_original(&genesis, 0, &original).is_err());

    let mut w = wallet(&native);
    w.ingest_epoch_original(&genesis, 0, &original).unwrap();
    let (_, manifest) = w.manifest().unwrap();
    let entry = w.epoch_entry(&manifest, 1).unwrap();
    w.archive
        .remove(ArchiveKey::Object(entry.checkpoint))
        .unwrap();
    let mut w = restart(w);
    assert!(w.epoch_progress_selected(&genesis).is_err());
    assert!(w.ingest_epoch_original(&genesis, 0, &original).is_err());
}
