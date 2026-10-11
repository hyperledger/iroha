//! Genuine generated-genesis observation through one callback-owned original proof reader.

use super::*;
use crate::{
    localnet::{LocalnetServiceProfile, prepare_localnet_at},
    managed::{LocalnetPorts, service_authority::NetworkPurpose},
};
use iroha_data_model::{asset::AssetId, isi::Log};
use std::num::NonZeroUsize;

#[inline(never)]
fn with_generated_chain(height: u64, check: fn(&NativeFixture, &ServiceAuthority)) {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "native-proof-reader",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let fee_asset = AssetId::new(
        policy(&authority).asset_definition,
        authority.config.account.clone(),
    );
    let funded = balance(native.chain.state(), &fee_asset);
    while native.chain.height() < height {
        let signed = quote_instructions(
            &native,
            &authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "genuine paid scoped proof-reader history".into(),
            ))],
        );
        assert_eq!(native.chain.commit(vec![signed]), vec![true]);
    }
    assert_eq!(native.chain.height(), height);
    assert!(
        balance(native.chain.state(), &fee_asset) < funded,
        "the actual ordinary native policy charged each genuine Log history"
    );
    check(&native, &authority);
}

// This records actual calls only. Every proof and every fresh signed attestation
// comes from its original source, with no fabricated response or verifier verdict.
struct CountedSource<'a, S> {
    source: &'a S,
    heights: RefCell<Vec<u64>>,
    attesters: RefCell<Vec<PeerId>>,
}
impl<S: FinalitySource> FinalitySource for CountedSource<'_, S> {
    type Error = S::Error;

    fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error> {
        self.heights.borrow_mut().push(height.get());
        self.source.finality_proof(height)
    }

    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> Result<crate::verify::finality::FinalityAttestation, Self::Error> {
        self.attesters.borrow_mut().push(peer.clone());
        let actual = self.source.latest_attestation(peer, challenge)?;
        assert_eq!(&actual.attestation().body.challenge, challenge);
        actual.attestation().verify().unwrap();
        Ok(actual)
    }
}

#[test]
fn generated_scoped_observation_keeps_four_fresh_attesters_and_exact_paid_history() {
    with_generated_chain(4, check_original_observation);
}

#[inline(never)]
fn check_original_observation(native: &NativeFixture, authority: &ServiceAuthority) {
    let genesis = native.finality_proof(NonZeroU64::new(1).unwrap()).unwrap();
    let tip = native.finality_proof(NonZeroU64::new(4).unwrap()).unwrap();
    let mut original = FinalityVerifier::from_genesis(&authority.genesis, &genesis).unwrap();
    assert_eq!(original.observe(native, &[81; 32]).unwrap().verified(), 4);
    let before = native
        .chain
        .state()
        .view()
        .block_hashes()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    let view = native.chain.state().view();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    let mut actual = FinalityVerifier::from_genesis(&authority.genesis, &genesis).unwrap();
    with_proof_reader(&view, |reader| {
        let source = NativeObservationSource {
            native,
            reader: RefCell::new(reader),
        };
        let counted = CountedSource {
            source: &source,
            heights: RefCell::new(Vec::new()),
            attesters: RefCell::new(Vec::new()),
        };
        let observed = actual.observe(&counted, &[82; 32]).unwrap();
        assert_eq!(observed.verified(), 4);
        assert_eq!(observed.required, 3);
        assert_eq!(observed.height.get(), 4);
        assert_eq!(observed.block_hash, tip.block_header.hash());
        assert_eq!(*counted.heights.borrow(), [2, 3]);
        let mut attesters = counted.attesters.borrow().clone();
        attesters.sort();
        let expected = native
            .validators
            .iter()
            .map(|(key, _)| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        assert_eq!(attesters, expected);
        assert_eq!(actual.checkpoint(), original.checkpoint());
        assert_eq!(actual.checkpoint().tip(), &tip);
        for height in [2, 3] {
            let proof = source
                .finality_proof(NonZeroU64::new(height).unwrap())
                .unwrap();
            assert_eq!(
                proof,
                native
                    .finality_proof(NonZeroU64::new(height).unwrap())
                    .unwrap()
            );
            proof.decode_checked().unwrap();
        }
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(
        native.observe(authority).checkpoint(),
        original.checkpoint()
    );
    assert_eq!(native.chain.height(), 4);
    assert_eq!(
        view.block_hashes().iter().copied().collect::<Vec<_>>(),
        before
    );
    for height in 2..=4 {
        let block = native.chain.committed(height);
        assert_eq!(block.block().network_entrypoint_count(), 1);
        assert_eq!(block.block().external_transactions().count(), 1);
    }
}

#[test]
fn generated_scoped_source_preserves_original_active_decode_refusal_and_retry() {
    with_generated_chain(2, check_generated_refusal);
}

#[inline(never)]
fn check_generated_refusal(native: &NativeFixture, _authority: &ServiceAuthority) {
    let height = NonZeroU64::new(2).unwrap();
    let original = native.finality_proof(height).unwrap();
    let view = native.chain.state().view();
    let budget = view.execution_budget();
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        let source = NativeObservationSource {
            native,
            reader: RefCell::new(reader),
        };
        assert_eq!(source.finality_proof(height).unwrap(), original);
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let expected =
            norito::with_decode_limits_scope(limits, || native.finality_proof(height)).unwrap_err();
        let refused =
            norito::with_decode_limits_scope(limits, || source.finality_proof(height)).unwrap_err();
        assert_eq!(refused.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        assert_eq!(source.finality_proof(height).unwrap(), original);
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(native.chain.height(), 2);
    assert_eq!(
        native.chain.committed(2).block().encode_wire().unwrap(),
        original.block_wire
    );
}

#[test]
fn generated_scoped_source_cannot_hide_a_replaced_earlier_real_quorum() {
    with_generated_chain(3, check_generated_source_loss);
}

#[inline(never)]
fn check_generated_source_loss(native: &NativeFixture, _authority: &ServiceAuthority) {
    let view = native.chain.state().view();
    let height = NonZeroU64::new(3).unwrap();
    let original = native.finality_proof(height).unwrap();
    let qc = native
        .chain
        .committed(2)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    let budget = view.execution_budget();
    // The corruption helper evicts Kura's published owner. Retain that existing
    // physical allocation while measuring reader cleanup; no retained image
    // is offered to the proof producer or used to authenticate the new source.
    let original_publications = [native
        .chain
        .kura()
        .get_block(NonZeroUsize::new(2).unwrap(), &budget)
        .unwrap()
        .unwrap()];
    let reserved = budget.reserved_bytes();
    with_proof_reader(&view, |reader| {
        let source = NativeObservationSource {
            native,
            reader: RefCell::new(reader),
        };
        source.finality_proof(NonZeroU64::new(2).unwrap()).unwrap();
        native.chain.corrupt_local_quorum_for_test(
            2,
            iroha_core::sumeragi::test_chain::Signers::BelowQuorum,
        );
        let expected = native.finality_proof(height).unwrap_err();
        let refused = source.finality_proof(height).unwrap_err();
        assert_eq!(refused.to_string(), expected.to_string());
        assert_eq!(budget.reserved_bytes(), reserved);
        native
            .chain
            .kura()
            .corrupt_commit_certificate_for_testing(NonZeroUsize::new(2).unwrap(), Some(qc))
            .unwrap();
        assert_eq!(source.finality_proof(height).unwrap(), original);
    });
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(original_publications);
    assert_eq!(native.chain.height(), 3);
    assert_eq!(
        native.chain.committed(3).block().encode_wire().unwrap(),
        original.block_wire
    );
}

#[path = "http_admission_tests.rs"]
mod http_admission_tests;
