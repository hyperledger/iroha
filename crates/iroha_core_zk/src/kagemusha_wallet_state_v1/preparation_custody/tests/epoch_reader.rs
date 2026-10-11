//! Epoch lookup keeps authenticated absence distinct from unavailable or lost custody.

use super::*;
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

#[test]
fn sealed_epoch_index_restores_verified_authority_for_current_and_older_receipts() {
    use iroha_data_model::sumeragi_finality::{
        MAX_COMMIT_CHECKPOINT_BYTES, SumeragiCommitCertificateV1, SumeragiCommitVerifierV1,
        SumeragiFinalityVerifier,
    };
    let (native, blocks) =
        NativeFinalityFixture::short_npos_boundary_chain_with_explicit_parameters(4);
    let genesis = SumeragiFinalityVerifier::new(
        native.genesis(),
        native.chain_id(),
        native.genesis_proof().committee.clone(),
    )
    .unwrap();
    let certificate = |index: usize| {
        SumeragiCommitCertificateV1::from_verified(
            &native
                .verifier()
                .verify_retained_decision(&blocks[index])
                .unwrap(),
        )
        .unwrap()
    };
    let mut reader = SumeragiCommitVerifierV1::new(&genesis).unwrap();
    let boundary = certificate(2);
    let checkpoint = reader.verify_epoch_boundary(&boundary).unwrap();
    let (mut store, state, source) = setup();
    let address = store
        .write_object(
            &checkpoint.encode_canonical().unwrap(),
            MAX_COMMIT_CHECKPOINT_BYTES,
        )
        .unwrap();
    let entry = native_owner::epochs::EpochEntry {
        checkpoint: address,
        boundary_original: [1; 32],
    };
    let root = IndexRoot::default()
        .set(
            &mut store,
            manifest::sequence_key(1),
            &archive::encode(&entry).unwrap(),
        )
        .unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::Load,
        None,
        IndexRoot::default(),
        IndexRoot::default(),
        root,
    )
    .unwrap();
    assert_eq!(
        custody
            .load_finality_reader(&genesis, 1)
            .unwrap()
            .verify(&certificate(3))
            .unwrap()
            .height(),
        4
    );
    assert_eq!(
        custody
            .load_finality_reader(&genesis, 0)
            .unwrap()
            .verify(&certificate(1))
            .unwrap()
            .height(),
        2
    );
    assert!(
        custody
            .load_finality_reader(&genesis, 0)
            .unwrap()
            .verify(&certificate(3))
            .is_err()
    );
    assert!(custody.load_finality_reader(&genesis, 2).is_err());
    let foreign = NativeFinalityFixture::start("foreign-sealed-epoch");
    assert!(
        custody
            .load_finality_reader(&foreign.verifier(), 1)
            .is_err()
    );
    drop(custody);
    store.remove(ArchiveKey::Object(address)).unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::Load,
        None,
        IndexRoot::default(),
        IndexRoot::default(),
        root,
    )
    .unwrap();
    assert!(custody.load_finality_reader(&genesis, 1).is_err());
}

struct UnavailableEpochStore {
    inner: MemoryArchive,
    unavailable: [u8; 32],
}

impl ObjectStore for UnavailableEpochStore {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        if *key == self.unavailable {
            return Err(Error::Storage(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "epoch original temporarily unavailable",
            )));
        }
        self.inner.read_object(key, maximum)
    }

    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        self.inner.write_object(bytes, maximum)
    }
}

#[test]
fn epoch_reader_preserves_absent_unavailable_and_lost_index_results() {
    let native = NativeFinalityFixture::start("load-epoch-custody-errors");
    let genesis = native.verifier();
    let (mut store, state, source) = setup();

    // A zero authenticated index proves only that this later epoch is not selected.
    assert!(matches!(
        view(&mut store, &state, &source).load_finality_reader(&genesis, 1),
        Err(Error::Invalid("Load epoch has not been synchronized"))
    ));

    // The value is deliberately DATA: all failures below must precede its decoder.
    let root = IndexRoot::default()
        .set(&mut store, manifest::sequence_key(1), b"unread entry DATA")
        .unwrap();
    let mut unavailable = UnavailableEpochStore {
        inner: store.clone(),
        unavailable: root.0,
    };
    let mut custody = PreparationCustodyV1::new(
        &mut unavailable,
        &source,
        &state,
        K::Load,
        None,
        IndexRoot::default(),
        IndexRoot::default(),
        root,
    )
    .unwrap();
    assert!(matches!(
        custody.load_finality_reader(&genesis, 1),
        Err(Error::Storage(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    drop(custody);

    // Losing the actual selected node is custody loss, not the zero-index answer.
    store.remove(ArchiveKey::Object(root.0)).unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::Load,
        None,
        IndexRoot::default(),
        IndexRoot::default(),
        root,
    )
    .unwrap();
    assert!(matches!(
        custody.load_finality_reader(&genesis, 1),
        Err(Error::WitnessLost("index object"))
    ));
}
