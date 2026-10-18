//! Four-validator campaign agreement on authenticated decisions, independent of QC witnesses.
//!
//! The existing native verifier owns certificate, prefix, schedule and execution admission.
//! The local fixture regression signs genuine QCs over synthetic results; it executes no World
//! transition and grants no monetary, network or release qualification.

use super::*;

pub(super) fn same_four_validator_decision(
    verifier: &SumeragiFinalityVerifier,
    retained: &SumeragiFinalityProof,
    candidate: &SumeragiFinalityProof,
) -> Result<VerifiedSumeragiBlock> {
    // This rechecks both witnesses cryptographically against the retained prefix. It binds
    // the Iroha block hash, core header/R, committee, schedule, beacon and executed body.
    let verified = verifier.verify_same_decision(retained, candidate)?;
    ensure!(
        retained.committee.len() == 4 && candidate.committee.len() == 4,
        "exact four-seat retained decision required"
    );
    if verified.height() > 1 {
        let certificate = verified
            .block()
            .commit_certificate()
            .ok_or_else(|| eyre!("missing retained decision certificate"))?;
        let qc: iroha_sumeragi::message::Qc = canonical(certificate.commit_qc())?;
        ensure!(qc.signers.count_ones() == 3, "exact quorum required");
    }
    Ok(verified)
}

#[test]
fn campaign_accepts_alternate_exact_quorum_and_rejects_changed_header_or_result() {
    use iroha_crypto::bls::consensus;
    use iroha_data_model::{
        block::{CommitCertificate, decode_framed_signed_block},
        testing::native_finality::NativeFinalityFixture,
    };
    use iroha_sumeragi::{
        message::Qc,
        types::{AggregateSignature, Bitmap},
    };

    let parent = NativeFinalityFixture::start("kagemusha-campaign-witness-agreement");
    let work = parent.block_with_submitted_work(parent.next_header());
    let mut selected = parent.clone();
    let retained = selected.certify(work.clone());
    let verifier = selected.verifier();
    let original = same_four_validator_decision(&verifier, &retained, &retained).unwrap();

    // Reuse the public fixed keys of NativeFinalityFixture, with the same ordering as
    // its builder. This is the genuine alternate-witness construction used by native
    // finality's own regression, never an unchecked VerifiedSumeragiBlock or fake verifier.
    let mut keys = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    for (key, validator) in keys.iter().zip(&retained.committee) {
        assert_eq!(key.public_key(), &validator.public_key);
    }
    let witness = |chosen: &[u32]| {
        let mut candidate = retained.clone();
        let mut block = decode_framed_signed_block(&candidate.block_wire).unwrap();
        let certificate = block.commit_certificate().unwrap();
        let header = certificate.consensus_header().to_vec();
        let result = certificate.result_preimage().to_vec();
        let availability = certificate.availability().to_vec();
        let mut qc: Qc = canonical(certificate.commit_qc()).unwrap();
        qc.view += 1;
        qc.signers = Bitmap::from_indices(keys.len(), chosen.iter().copied()).unwrap();
        let shares = chosen
            .iter()
            .map(|index| {
                consensus::sign_preimage(keys[*index as usize].private_key(), &qc.preimage())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        qc.agg_sig = AggregateSignature(consensus::aggregate(&shares).unwrap());
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            header,
            norito::encode_canonical(&qc).unwrap(),
            result,
            availability,
        )));
        candidate.block_wire = block.encode_wire().unwrap();
        candidate
    };
    let alternate = witness(&[1, 2, 3]);
    assert_ne!(retained.block_wire, alternate.block_wire);
    let authenticated = same_four_validator_decision(&verifier, &retained, &alternate).unwrap();
    assert_eq!(original.header(), authenticated.header());
    assert_eq!(original.root_scope(), authenticated.root_scope());
    assert_eq!(original.context_id(), authenticated.context_id());
    assert_eq!(original.core_hash(), authenticated.core_hash());
    assert_eq!(original.result(), authenticated.result());
    assert_eq!(original.commitment(), authenticated.commitment());
    assert_eq!(
        original.canonical_executed_wire().unwrap(),
        authenticated.canonical_executed_wire().unwrap()
    );
    // Missing votes and signer supersets remain invalid, despite real signatures.
    assert!(same_four_validator_decision(&verifier, &retained, &witness(&[1, 2])).is_err());
    assert!(same_four_validator_decision(&verifier, &retained, &witness(&[0, 1, 2, 3])).is_err());
    assert!(same_four_validator_decision(&parent.verifier(), &retained, &alternate).is_err());

    // Independently certify a different header from the SAME parent. Each branch is a
    // valid native proof by itself; agreement must reject the changed selected decision.
    let mut header_branch = parent.clone();
    let mut header = parent.next_header();
    header.creation_time_ms += 1;
    let changed = header_branch.certify(parent.block_with_submitted_work(header));
    let checked = header_branch
        .verifier()
        .verify_retained_decision(&changed)
        .unwrap();
    assert_ne!(checked.header(), original.header());
    assert!(same_four_validator_decision(&verifier, &retained, &changed).is_err());

    // Keep the Iroha header/body but genuinely certify a different synthetic World root.
    let mut result_branch = parent;
    let changed =
        result_branch.certify_with_world_root(work, Hash::new(b"different synthetic World root"));
    let checked = result_branch
        .verifier()
        .verify_retained_decision(&changed)
        .unwrap();
    assert_eq!(checked.header(), original.header());
    assert_ne!(checked.result(), original.result());
    assert!(same_four_validator_decision(&verifier, &retained, &changed).is_err());
}
