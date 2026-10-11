//! Real generated fixture carriers through the same native Core verifier.
use super::*;
use iroha_data_model::{kaigi::KaigiPrivacyMode, proof::ProofBox, zk::OpenVerifyEnvelope};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;

#[test]
fn real_kaigi_release_builders_preserve_governed_keys_and_final_carriers() {
    let network = super::super::release_network_id_from_genesis_hash([0x35; 32]);
    let host = iroha_test_samples::ALICE_ID.clone();
    let participant = iroha_test_samples::BOB_ID.clone();
    let mut call = NewKaigi::with_defaults(
        KaigiId::new(
            DomainId::try_new("kaigi", "universal").unwrap(),
            "release".parse::<Name>().unwrap(),
        ),
        host.clone(),
    );
    call.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
    let references = kaigi_release_verifier_references_v1();
    let keys = kaigi_release_verifier_registrations_v1();
    for (reference, key) in references.iter().zip(&keys) {
        assert_eq!(
            key.id,
            VerifyingKeyId::new(reference.backend.as_str(), reference.name.as_str())
        );
        assert_eq!(key.record.status, ConfidentialStatus::Active);
        assert_eq!(key.record.max_proof_bytes, 64 * 1024);
        assert!(key.record.key.is_some());
    }
    let mut record = KaigiRecord::from_new(&call, 1);
    let created = build_kaigi_release_authorization_v1(
        network,
        &record,
        &host,
        0,
        KaigiAuthorizationActionV1::HostCreate,
    );
    let create = created.create(call.clone());
    assert_eq!(create.call.id(), call.id());
    assert_eq!(create.commitment, Some(created.commitment.clone()));
    record.host_commitment = Some(created.commitment.clone());
    for action in [
        KaigiAuthorizationActionV1::Join,
        KaigiAuthorizationActionV1::Leave,
        KaigiAuthorizationActionV1::HostEnd,
    ] {
        let subject = if action == KaigiAuthorizationActionV1::HostEnd {
            &host
        } else {
            &participant
        };
        let sequence = if action == KaigiAuthorizationActionV1::HostEnd {
            0
        } else {
            1
        };
        let generated =
            build_kaigi_release_authorization_v1(network, &record, subject, sequence, action);
        assert_eq!(generated.root, record.roster_root());
        let proof = ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.into(), generated.proof.clone());
        assert!(crate::zk::verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &proof,
            keys[0].record.key.as_ref()
        ));
        match action {
            KaigiAuthorizationActionV1::Join => assert_eq!(
                generated.join(call.id(), subject).proof,
                Some(generated.proof)
            ),
            KaigiAuthorizationActionV1::Leave => assert_eq!(
                generated.leave(call.id(), subject).proof,
                Some(generated.proof)
            ),
            KaigiAuthorizationActionV1::HostEnd => {
                assert_eq!(generated.end(call.id()).proof, Some(generated.proof))
            }
            _ => unreachable!(),
        }
    }
    assert!(crate::zk::verify_backend(
        ZK_BACKEND_NATIVE_PIPA_R,
        &ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.into(), created.proof),
        keys[0].record.key.as_ref()
    ));
    let usage = build_kaigi_release_usage_v1(network, &record);
    assert_eq!(usage.duration_ms, 1200);
    assert_eq!(usage.billed_gas, 345);
    let proof = ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.into(), usage.proof.unwrap());
    assert!(crate::zk::verify_backend(
        ZK_BACKEND_NATIVE_PIPA_R,
        &proof,
        keys[1].record.key.as_ref()
    ));
    let mut changed: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
    changed.aux.push(1);
    assert!(!crate::zk::verify_backend(
        ZK_BACKEND_NATIVE_PIPA_R,
        &ProofBox::new(
            ZK_BACKEND_NATIVE_PIPA_R.into(),
            norito::encode_canonical(&changed).unwrap()
        ),
        keys[1].record.key.as_ref()
    ));
}
