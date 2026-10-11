//! Model-valid adversarial DATA signed with the retained simulated C key.
//!
//! This test fixture is not a provider operation or a released wallet claim. It changes
//! only sigma's final IPA blinding scalar and its receipt, leaving actual custody intact.

use super::*;
use ff::{Field as _, PrimeField as _};
use iroha_pasta::{Eq, Fp};
use iroha_plonk::{
    DescriptorBinding, Protocol,
    cs::{CurveV1, ProofSuffixV1, TranscriptV2},
    protocol::schedule::{ProofMessage, TranscriptStep},
    transcript::{decode_point, decode_scalar},
};
use p256::ecdsa::signature::Signer as _;

fn increment_blinding(proof: &mut [u8]) {
    assert!(proof.len() >= 96 && proof.len().is_multiple_of(32));
    let f_offset = proof.len() - 64;
    let c: [u8; 32] = proof[f_offset - 32..f_offset].try_into().unwrap();
    let f: [u8; 32] = proof[f_offset..f_offset + 32].try_into().unwrap();
    let suffix: [u8; 32] = proof[f_offset + 32..].try_into().unwrap();
    decode_scalar::<Fp>(&c).unwrap();
    decode_point::<Eq>(&suffix).unwrap();
    let changed = (decode_scalar::<Fp>(&f).unwrap() + Fp::ONE).to_repr();
    assert_ne!(changed, f);
    proof[f_offset..f_offset + 32].copy_from_slice(&changed);
}

#[allow(clippy::too_many_lines)]
pub(super) fn claim(
    sources: &Sources,
    device: &HostDevice,
    original: &KagemushaWalletUnloadClaimV1,
) -> Vec<u8> {
    let selector = original.package.verifying_key_selector(None).unwrap();
    assert_eq!(selector, (KagemushaWalletOperationKindV1::Unload, 0));
    let matching = sources
        .installed
        .originals()
        .steps
        .iter()
        .filter(|step| (step.kind, step.enabled_controls) == selector)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    let binding = DescriptorBinding::decode_v2(&matching[0].artifact.descriptor).unwrap();
    let descriptor = binding.descriptor();
    assert_eq!(descriptor.curve, CurveV1::Vesta); // Vesta scalar field is Fp.
    assert_eq!(
        descriptor.transcript,
        TranscriptV2::KagemushaPoseidonRp57Base
    );
    assert_eq!(descriptor.proof_suffix, ProofSuffixV1::FoldedGenerator);
    let protocol = Protocol::new(descriptor).unwrap();
    assert_eq!(
        protocol.proof_length(),
        original.package.step_proof.bytes.len()
    );
    let schedule = protocol.transcript_schedule();
    assert_eq!(
        schedule.iter().filter(|step| step.is_proof_bytes()).count() * 32,
        protocol.proof_length()
    );
    assert_eq!(
        &schedule[schedule.len() - 3..],
        &[
            TranscriptStep::Message(ProofMessage::IpaC),
            TranscriptStep::Message(ProofMessage::IpaF),
            TranscriptStep::Suffix,
        ]
    );

    let scheme = sources.installed.verifier().scheme();
    original.verify(scheme).unwrap();
    let mut bad = original.clone();
    increment_blinding(&mut bad.package.step_proof.bytes);
    assert!(
        bad.verify(scheme).is_err(),
        "the old receipt must reject changed sigma"
    );
    let proof_digest = bad.package.proof_digest().unwrap();
    let signer = KagemushaWalletReceiptSignerV1::from_credential(&bad.credential).unwrap();
    let body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        &bad.package.statement,
        &proof_digest,
        bad.package.receipt.capsule_digest,
        bad.package.receipt.payment_digest,
    )
    .unwrap();
    // Explicit malicious-signer fixture, outside Advance: one signature using C's already
    // retained software test key. No key generation, platform sign counter or custody write.
    let signature: p256::ecdsa::Signature = device.platform.with(|state| {
        assert_eq!(state.keys.len(), 1);
        let key = state.keys.values().next().unwrap();
        assert_eq!(public_key(key), bad.credential.body.payment_key);
        key.sign(&body.signing_message())
    });
    let signature_bytes: [u8; 64] = signature.to_bytes().into();
    bad.package.receipt = KagemushaWalletReceiptV1::sign(
        &bad.credential,
        &bad.package.statement,
        &proof_digest,
        bad.package.receipt.capsule_digest,
        bad.package.receipt.payment_digest,
        KagemushaWalletSignerOutputV1::Raw(signature_bytes),
    )
    .unwrap();
    bad.verify(scheme).unwrap();
    let bytes = bad.to_canonical_bytes().unwrap();
    let decoded =
        KagemushaWalletUnloadClaimV1::decode_canonical(&bytes, &scheme.scheme_id()).unwrap();
    assert_eq!(decoded, bad);
    decoded.verify(scheme).unwrap();
    assert_eq!(
        sources.installed.verifier().verify_package_proofs(
            &decoded.package,
            None,
            MemoryBudget::DEFAULT,
        ),
        Err(crate::kagemusha_wallet_proofs_v1::Error::Proof)
    );
    // The schedule reads f after the last challenge and before the unabsorbed generator.
    // f -> f+1 changes the final IPA equation by the nonzero blinding generator; all
    // transcript point/scalar encodings and the original proof length remain canonical.
    bad.package.step_proof = original.package.step_proof.clone();
    bad.package.receipt = original.package.receipt.clone();
    assert_eq!(&bad, original, "every other claim field must stay exact");
    bytes
}

#[test]
fn blinding_mutation_preserves_canonical_tail_and_wraps_in_vesta_scalar_field() {
    use iroha_pasta::{EqAffine, Fq, PastaAffine as _};
    use iroha_plonk::transcript::encode_point;

    let point = Option::<EqAffine>::from(EqAffine::from_xy(-Fq::ONE, Fq::from(2))).unwrap();
    let suffix = encode_point::<Eq>(&point);
    for before in [Fp::ZERO, Fp::from(23), -Fp::ONE] {
        let mut proof = [77; 128];
        proof[32..64].copy_from_slice(&Fp::from(19).to_repr());
        proof[64..96].copy_from_slice(&before.to_repr());
        proof[96..].copy_from_slice(&suffix);
        let original = proof;
        increment_blinding(&mut proof);
        assert_eq!(&proof[..64], &original[..64]);
        assert_eq!(&proof[96..], &original[96..]);
        assert_eq!(
            decode_scalar::<Fp>(&proof[64..96].try_into().unwrap()),
            Ok(before + Fp::ONE)
        );
        assert_ne!(proof, original);
    }
}

#[test]
fn blinding_mutation_refuses_truncated_noncanonical_or_invalid_tail() {
    use iroha_pasta::{EqAffine, Fq, PastaAffine as _};
    use iroha_plonk::transcript::encode_point;

    let point = Option::<EqAffine>::from(EqAffine::from_xy(-Fq::ONE, Fq::from(2))).unwrap();
    let mut canonical = [0; 96];
    canonical[64..].copy_from_slice(&encode_point::<Eq>(&point));
    for mut malformed in [vec![0; 64], vec![0; 97]] {
        assert!(std::panic::catch_unwind(move || increment_blinding(&mut malformed)).is_err());
    }
    for offset in [0, 32, 64] {
        let mut changed = canonical;
        changed[offset..offset + 32].fill(255);
        assert!(std::panic::catch_unwind(move || increment_blinding(&mut changed)).is_err());
    }
    canonical[64..].fill(0); // Identity is not a valid generator suffix.
    assert!(std::panic::catch_unwind(move || increment_blinding(&mut canonical)).is_err());
}
