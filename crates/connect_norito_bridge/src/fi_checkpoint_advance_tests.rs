//! Genuine certified empty-block history; these tests grant no application execution authority.
use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier;

struct Fixture {
    checkpoint: Vec<u8>,
    network: NetworkId,
    chain: String,
    context: [u8; 32],
    proofs: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &checkpoint,
            &chain.network_id(),
            checkpoint.chain_id(),
        )
        .unwrap();
        let context = *tip.context_id().as_ref();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let view = chain.state().view();
        let proofs = (2..=4)
            .map(|height| norito::encode_canonical(&build_proof(&view, height).unwrap()).unwrap())
            .collect();
        Self {
            checkpoint: checkpoint.encode_canonical().unwrap(),
            network: chain.network_id(),
            chain: checkpoint.chain_id().to_owned(),
            context,
            proofs,
        }
    }
    fn advance(&self, proofs: &[Vec<u8>]) -> Result<VerifiedFiCheckpointAdvance, String> {
        advance_fi_checkpoint(
            &self.checkpoint,
            &proofs.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            self.network,
            &self.chain,
            sha256(&self.checkpoint),
            2,
            self.context,
        )
    }
}

#[test]
fn native_advance_matches_partitioned_existing_page_algorithm_byte_for_byte() {
    let fixture = Fixture::new();
    let direct = fixture.advance(&fixture.proofs).unwrap();
    let first = fixture.advance(&fixture.proofs[..2]).unwrap();
    let first_checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&first.checkpoint).unwrap();
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &first_checkpoint,
        &fixture.network,
        &fixture.chain,
    )
    .unwrap();
    let second = advance_fi_checkpoint(
        &first.checkpoint,
        &fixture.proofs[1..]
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        fixture.network,
        &fixture.chain,
        sha256(&first.checkpoint),
        3,
        *tip.context_id().as_ref(),
    )
    .unwrap();
    assert_eq!(direct.checkpoint, second.checkpoint);
    let metadata = norito::json::from_slice_value(&direct.metadata).unwrap();
    assert_eq!(metadata.as_object().unwrap().len(), 9);
    assert!(
        metadata
            .as_object()
            .unwrap()
            .values()
            .all(norito::json::Value::is_string)
    );
    assert_eq!(metadata["anchorHeight"].as_str(), Some("2"));
    assert_eq!(metadata["height"].as_str(), Some("4"));
    assert_eq!(metadata["proofCount"].as_str(), Some("3"));
    assert_eq!(
        metadata["checkpointSha256"].as_str(),
        Some(hex::encode(sha256(&direct.checkpoint)).as_str())
    );
}

#[test]
fn native_advance_rejects_gaps_missing_anchor_mutations_noop_and_foreign_pins() {
    let fixture = Fixture::new();
    assert!(fixture.advance(&fixture.proofs[..1]).is_err());
    assert!(fixture.advance(&fixture.proofs[1..]).is_err());
    assert!(
        fixture
            .advance(&[fixture.proofs[0].clone(), fixture.proofs[2].clone()])
            .is_err()
    );
    let mut changed = fixture.proofs.clone();
    changed[1][0] ^= 1;
    assert!(fixture.advance(&changed).is_err());
    let wires: Vec<_> = fixture.proofs.iter().map(Vec::as_slice).collect();
    for (sha, height, context, chain) in [
        ([0x55; 32], 2, fixture.context, fixture.chain.as_str()),
        (
            sha256(&fixture.checkpoint),
            3,
            fixture.context,
            fixture.chain.as_str(),
        ),
        (
            sha256(&fixture.checkpoint),
            2,
            [0x55; 32],
            fixture.chain.as_str(),
        ),
        (
            sha256(&fixture.checkpoint),
            2,
            fixture.context,
            "other-chain",
        ),
    ] {
        assert!(
            advance_fi_checkpoint(
                &fixture.checkpoint,
                &wires,
                fixture.network,
                chain,
                sha,
                height,
                context
            )
            .is_err()
        );
    }
}

#[test]
fn native_advance_enforces_existing_frame_count_and_aggregate_bounds_before_decode() {
    let fixture = Fixture::new();
    let frame = b"not a proof".as_slice();
    assert!(
        advance_fi_checkpoint(
            &fixture.checkpoint,
            &vec![frame; MAX_PROOFS + 1],
            fixture.network,
            &fixture.chain,
            sha256(&fixture.checkpoint),
            2,
            fixture.context
        )
        .is_err()
    );
    let excessive = vec![0; MAX_PROOF_BYTES];
    assert!(
        advance_fi_checkpoint(
            &fixture.checkpoint,
            &[&excessive, frame],
            fixture.network,
            &fixture.chain,
            sha256(&fixture.checkpoint),
            2,
            fixture.context
        )
        .is_err()
    );
}

#[test]
fn native_advance_rejects_genuine_private_root_even_when_all_original_pins_match() {
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        nexus::DataSpaceId, sumeragi_finality::test_fixtures::NativeFinalityFixture,
    };
    let parent = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"advance parent fixture",
    )));
    let private = NativeFinalityFixture::start_with_scope(
        "private-advance",
        SumeragiRootScope::Dataspace {
            parent_network_id: parent,
            dataspace_id: DataSpaceId::new(7),
        },
    );
    let checkpoint = private.checkpoint();
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &checkpoint,
        &private.network_id(),
        private.chain_id(),
    )
    .unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    let frame = norito::encode_canonical(private.latest()).unwrap();
    let error = advance_fi_checkpoint(
        &bytes,
        &[&frame, &frame],
        private.network_id(),
        private.chain_id(),
        sha256(&bytes),
        checkpoint.height(),
        *tip.context_id().as_ref(),
    )
    .err()
    .unwrap();
    assert!(error.contains("Global"));
}

#[test]
fn ffi_advance_returns_two_owned_outputs_and_clears_both_on_invalid_page_count() {
    let fixture = Fixture::new();
    let network = fixture.network.to_string();
    let digest = sha256(&fixture.checkpoint);
    let pointers: Vec<_> = fixture.proofs.iter().map(|proof| proof.as_ptr()).collect();
    let lengths: Vec<_> = fixture
        .proofs
        .iter()
        .map(|proof| proof.len() as c_ulong)
        .collect();
    for count in [3, 1, 4097] {
        let mut checkpoint = ptr::null_mut();
        let mut checkpoint_len = 0;
        let mut metadata = ptr::null_mut();
        let mut metadata_len = 0;
        let result = unsafe {
            connect_norito_advance_fi_checkpoint_v1(
                fixture.checkpoint.as_ptr(),
                fixture.checkpoint.len() as c_ulong,
                pointers.as_ptr(),
                lengths.as_ptr(),
                count,
                network.as_ptr(),
                network.len() as c_ulong,
                fixture.chain.as_ptr(),
                fixture.chain.len() as c_ulong,
                digest.as_ptr(),
                32,
                b"2".as_ptr(),
                1,
                fixture.context.as_ptr(),
                32,
                &mut checkpoint,
                &mut checkpoint_len,
                &mut metadata,
                &mut metadata_len,
            )
        };
        if count == 3 {
            assert_eq!(result, 0);
            assert!(!checkpoint.is_null() && !metadata.is_null());
            assert!(checkpoint_len > 0 && metadata_len > 0);
            let output = unsafe { slice::from_raw_parts(checkpoint, checkpoint_len as usize) };
            assert_eq!(
                SumeragiFinalityCheckpoint::decode_canonical(output)
                    .unwrap()
                    .height(),
                4
            );
            crate::connect_norito_free(checkpoint);
            crate::connect_norito_free(metadata);
        } else {
            assert_eq!(result, ERR_FI_CHECKPOINT_ADVANCE);
            assert!(checkpoint.is_null() && metadata.is_null());
            assert_eq!((checkpoint_len, metadata_len), (0, 0));
        }
    }
}
