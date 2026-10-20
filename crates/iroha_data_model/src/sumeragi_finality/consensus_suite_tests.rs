//! Portable consensus readers use the sole allowlisted SHA-256/DST_SIG relation.

use super::{tests::Fixture, *};

#[test]
fn proof_crypto_uses_consensus_suite_and_preserves_pop_admission() {
    let fixture = Fixture::new();
    let (crypto, committee) = ProofCrypto::new(&fixture.validators).unwrap();
    let block = decode_framed_signed_block(&fixture.second.block_wire).unwrap();
    let qc: Qc = norito::decode_canonical(block.commit_certificate().unwrap().commit_qc()).unwrap();
    let preimage = qc.preimage();
    let key = &committee.members()[0];
    let pair = fixture
        .keys
        .iter()
        .find(|pair| pair.public_key().try_to_bytes().unwrap().1 == key.as_bytes())
        .unwrap();
    let native = Signature(consensus::sign_preimage(pair.private_key(), &preimage).unwrap());
    assert!(crypto.verify(key, &preimage, &native));
    assert!(crypto.verify_aggregate(
        &[key],
        &preimage,
        &crypto.aggregate(std::slice::from_ref(&native)).unwrap()
    ));
    assert!(
        iroha_crypto::Signature::from_bytes(&native.0)
            .verify(pair.public_key(), &preimage)
            .is_err(),
        "a consensus signature is not a generic w3f signature"
    );

    let generic = iroha_crypto::Signature::try_new(pair.private_key(), &preimage).unwrap();
    assert!(generic.verify(pair.public_key(), &preimage).is_ok());
    let old = Signature(generic.payload().try_into().unwrap());
    assert!(!crypto.verify(key, &preimage, &old));
    assert!(!crypto.verify_aggregate(&[key], &preimage, &crypto.aggregate(&[old]).unwrap()));

    // The generic attestation context remains outside the consensus allowlist.
    let mut unlisted = preimage.clone();
    unlisted[b"sumeragi/sig".len()] = 0x06;
    assert!(consensus::sign_preimage(pair.private_key(), &unlisted).is_err());
    let generic = iroha_crypto::Signature::try_new(pair.private_key(), &unlisted).unwrap();
    assert!(generic.verify(pair.public_key(), &unlisted).is_ok());
    let generic = Signature(generic.payload().try_into().unwrap());
    assert!(!crypto.verify(key, &unlisted, &generic));
    assert!(!crypto.verify_aggregate(&[key], &unlisted, &crypto.aggregate(&[generic]).unwrap()));

    // Single-key verification remains a cryptographic relation; the caller owns authority.
    // Aggregates still require the committee's original validated PoPs.
    let outsider = iroha_crypto::KeyPair::from_seed(vec![0xEE; 32], Algorithm::BlsNormal);
    let external_key =
        CoreKey::new(outsider.public_key().try_to_bytes().unwrap().1.to_vec()).unwrap();
    let external_sig =
        Signature(consensus::sign_preimage(outsider.private_key(), &preimage).unwrap());
    assert!(crypto.verify(&external_key, &preimage, &external_sig));
    assert!(!crypto.verify_aggregate(
        &[&external_key],
        &preimage,
        &crypto.aggregate(&[external_sig]).unwrap()
    ));
    let mut no_pop = fixture.validators.clone();
    no_pop[0].proof_of_possession[0] ^= 1;
    assert!(ProofCrypto::new(&no_pop).is_err());
}

#[test]
fn proof_crypto_multi_message_aggregate_binds_each_allowlisted_digest() {
    let fixture = Fixture::new();
    let (crypto, committee) = ProofCrypto::new(&fixture.validators).unwrap();
    let block = decode_framed_signed_block(&fixture.second.block_wire).unwrap();
    let mut qc: Qc =
        norito::decode_canonical(block.commit_certificate().unwrap().commit_qc()).unwrap();
    let first = qc.preimage();
    qc.result.0[0] ^= 1;
    let second = qc.preimage();
    let keys = [&committee.members()[0], &committee.members()[1]];
    let shares: Vec<_> = keys
        .iter()
        .zip([&first, &second])
        .map(|(key, preimage)| {
            let pair = fixture
                .keys
                .iter()
                .find(|pair| pair.public_key().try_to_bytes().unwrap().1 == key.as_bytes())
                .unwrap();
            Signature(consensus::sign_preimage(pair.private_key(), preimage).unwrap())
        })
        .collect();
    let aggregate = crypto.aggregate(&shares).unwrap();
    let groups = [
        (vec![keys[0]], first.clone()),
        (vec![keys[1]], second.clone()),
    ];
    assert!(crypto.verify_aggregate_multi(&groups, &aggregate));
    assert!(!crypto.verify_aggregate_multi(
        &[(vec![keys[0]], second), (vec![keys[1]], first)],
        &aggregate
    ));
    let mut unlisted = groups.clone();
    unlisted[1].1[b"sumeragi/sig".len()] = 0x06;
    assert!(!crypto.verify_aggregate_multi(&unlisted, &aggregate));
    assert!(!crypto.verify_aggregate_multi(&[], &aggregate));
    assert!(crypto.aggregate(&[]).is_err());
}

#[test]
fn proof_crypto_stack_pairing_matches_explicit_scratch_on_valid_and_rejected_proofs() {
    use iroha_crypto::bls::consensus::ConsensusAggregateScratch;

    let fixture = Fixture::new();
    let (crypto, committee) = ProofCrypto::new(&fixture.validators).unwrap();
    let block = decode_framed_signed_block(&fixture.second.block_wire).unwrap();
    let qc: Qc = norito::decode_canonical(block.commit_certificate().unwrap().commit_qc()).unwrap();
    let message = qc.preimage();
    let digest = ConsensusDigest::from_preimage(&message).unwrap();
    let key = &committee.members()[0];
    let pair = fixture
        .keys
        .iter()
        .find(|pair| pair.public_key().try_to_bytes().unwrap().1 == key.as_bytes())
        .unwrap();
    let signature = consensus::sign_preimage(pair.private_key(), &message).unwrap();
    let admitted = crypto.keys.get(key).unwrap();
    let mut scratch = ConsensusAggregateScratch::new(|_| Ok::<_, ()>(())).unwrap();
    for signature in [signature, [0; 96], signature] {
        let aggregate = AggregateSignature(signature);
        assert_eq!(
            crypto.verify_aggregate(&[key], &message, &aggregate),
            scratch.verify_fast_aggregate(core::iter::once(admitted), &digest, &signature),
            "portable stack and admitted original scratch have the same relation",
        );
        let groups = [(vec![key], message.clone())];
        assert_eq!(
            crypto.verify_aggregate_multi(&groups, &aggregate),
            scratch.verify_aggregate_multi(
                core::iter::once((core::iter::once(admitted), digest)),
                &signature
            ),
        );
        assert!(!crypto.verify_aggregate(&[key, key], &message, &aggregate));
        assert!(
            !crypto.verify_aggregate_multi(&[groups[0].clone(), groups[0].clone()], &aggregate)
        );
    }
}
