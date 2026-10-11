//! Canonical node attestation policy over original signed proposals and executed counts.
//! The SDK TopUp fixture is shape-valid rejected work, never monetary authorization.

use super::*;

#[test]
fn native_top_up_proposal_requires_attestation_before_an_epoch_boundary() {
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey};
    use iroha_data_model::{
        account::AccountId,
        block::{BlockHeader, BlockSignatures, builder::BlockBuilder},
        isi::kagemusha_v1::{KagemushaTopUpRequestV1, TopUpKagemushaV1},
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let request: KagemushaTopUpRequestV1 = norito::decode_canonical(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/offline/kagemusha_top_up_request_v1.nrt"
    )))
    .expect("the unchanged canonical SDK TopUp request");
    request
        .validate_shape()
        .expect("structurally valid rejected work");
    let payer = KeyPair::from_private_key(
        PrivateKey::from_bytes(Algorithm::Ed25519, &[0x42; 32])
            .expect("documented public SDK fixture seed"),
    )
    .expect("actual fixture payer key");
    assert_eq!(request.payer, AccountId::of(payer.public_key().clone()));
    let mut transaction = TransactionBuilder::new(
        request.network_id,
        request.payer.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([TopUpKagemushaV1::new(request).expect("canonical TopUp instruction")]);
    transaction.set_creation_time(Duration::from_millis(2_000));
    let signed = transaction.sign(payer.private_key());
    let mut builder = BlockBuilder::new(BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        None,
        None,
        2_001,
        0,
    ));
    builder.push_transaction(signed);
    let original = builder.build(BlockSignatures::default());
    let wire = original.encode_wire().unwrap();
    let input = original.external_entrypoints_slice().as_ptr();
    assert!(original.is_resultless_proposal());
    assert!(proposal_requires_attestation(&original, 10));
    assert_eq!(original.external_entrypoints_slice().as_ptr(), input);
    assert_eq!(original.encode_wire().unwrap(), wire);
}

#[test]
fn ordinary_nonboundary_proposal_has_no_mint_attestation_requirement() {
    publication_tests::with_worker(|chain, worker, _blocks, _events| {
        let source = publication_tests::proposal(chain, worker);
        let proposal = payload::decode(source.payload().as_slice()).unwrap();
        let scheduled = worker.scheduled(source.header().height).unwrap();
        assert_ne!(
            proposal.header().height().get(),
            scheduled.epoch.authorization.last_height
        );
        assert!(!proposal_requires_attestation(
            &proposal,
            scheduled.epoch.authorization.last_height
        ));
        assert!(!source.header().attest);
    });
}

#[test]
fn ordinary_boundary_proposal_requires_its_authenticated_scheduled_attestation() {
    publication_tests::with_worker_from(
        super::super::test_chain::CertifiedTestChain::npos_boundary_fixture,
        ConsensusMode::Npos,
        |chain, worker, _blocks, _events| {
            let source = publication_tests::proposal(chain, worker);
            let proposal = payload::decode(source.payload().as_slice()).unwrap();
            let scheduled = worker.scheduled(source.header().height).unwrap();
            assert_eq!(
                proposal.header().height().get(),
                scheduled.epoch.authorization.last_height
            );
            assert!(proposal_requires_attestation(
                &proposal,
                scheduled.epoch.authorization.last_height
            ));
            assert!(source.header().attest);
        },
    );
}

#[test]
fn executed_top_up_count_cannot_finalize_without_the_flag_even_if_static_work_is_ordinary() {
    publication_tests::with_worker(|chain, worker, _blocks, _events| {
        let source = publication_tests::proposal(chain, worker);
        let proposal = payload::decode(source.payload().as_slice()).unwrap();
        let scheduled = worker.scheduled(source.header().height).unwrap();
        assert!(!proposal_requires_attestation(
            &proposal,
            scheduled.epoch.authorization.last_height
        ));
        let mut result = chain.committed(chain.height()).commitment().clone();
        assert_eq!(result.execution.kagemusha_top_up_count, 0);
        assert!(!top_ups_without_flag(&result, false));
        // A predicate-level negative observation only. This is not an executed
        // IVM mint or a replacement R, and it is never published or certified.
        result.execution.kagemusha_top_up_count = 1;
        assert!(top_ups_without_flag(&result, false));
        assert!(!top_ups_without_flag(&result, true));
    });
}
