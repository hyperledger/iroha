//! Production-shaped Archive Q verifier metadata for source-only capacity checks.
//!
//! All sigma and Q identities are derived from their actual unknown circuits,
//! using k12/k14 folded Receive and the serialized-two-bus Q sources of the
//! genuine Archive fixture and native importers. The predecessor is either an
//! explicitly constructor-only metadata circuit or bounded descriptor/VK bytes
//! from a separately captured genuine Bootstrap proof. Neither path produces
//! operation proofs, a funded wallet, artifact admission or chain qualification.

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp};
use iroha_plonk::{
    DescriptorBinding, VerifyingKey,
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    frontend::Circuit,
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    transcript::decode_point,
};
use iroha_plonk_gadgets::p256::native::{self, Affine};
use iroha_plonk_recursion::{FOLD_WITNESS_BYTES, VESTA_TRIVIAL_GENERATOR};

use super::{Metadata, PhantomData};
use crate::{
    PrefixMode, RelationShape, SigmaCircuit, SigmaParams, SigmaRelation,
    a_relation::{
        AProofPlan, QProofPlan, archive::authorization::ArchiveAuthorizationObjects,
        own::OwnPolicy, schedule::sigma_selector,
    },
    admin_sigma::{ArchiveCircuit, ArchiveWitness, StateWitness},
    limb_bits_for,
    omega::OmegaPlan,
    q_sigma::{
        IncomingSigmaWitness, QSigmaCircuit, QSigmaPlan, QSigmaWitness, SigmaClass,
        SigmaSlotWitness,
    },
    q_signature::{QSignatureCircuit, QSignaturePlan, SignatureWitness},
    witness::{CORE_FIELDS, REST_FIELDS},
};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierPlan};

const SIGMA_K: u32 = 12;
const Q_K: u32 = 16;
const Q_RANGE_BUSES: usize = 2;

/// Derive exact sigma/Q source identities and an explicitly unauthenticated
/// predecessor identity for a fixed Archive variant. There are no caller-selected
/// sizes, shapes, keys or witness tapes. VK-only construction retains no PK.
pub(super) fn operation(variant: Variant) -> (AProofPlan, OwnPolicy, VerifyingKey<Ep>) {
    assert!(matches!(
        variant,
        Variant::ArchiveReceive | Variant::ArchiveStatus
    ));
    with_predecessor(variant, None, SIGMA_K)
}

/// Substitute an exact captured outer source for the constructor-only metadata.
/// Parsing and layout planning confer no scheme or artifact authority.
pub(super) fn captured_operation(
    variant: Variant,
    binding: DescriptorBinding,
    predecessor: VerifyingKey<Ep>,
    incoming_k: u32,
) -> (AProofPlan, OwnPolicy, VerifyingKey<Ep>) {
    with_predecessor(variant, Some((binding, predecessor)), incoming_k)
}

fn with_predecessor(
    variant: Variant,
    captured: Option<(DescriptorBinding, VerifyingKey<Ep>)>,
    incoming_k: u32,
) -> (AProofPlan, OwnPolicy, VerifyingKey<Ep>) {
    assert!(matches!(
        variant,
        Variant::ArchiveReceive | Variant::ArchiveStatus
    ));
    assert!(matches!(incoming_k, 12 | 14));
    assert!(variant == Variant::ArchiveReceive || incoming_k == SIGMA_K);
    let root = native::mul(&Affine::GENERATOR, &[23, 0, 0, 0]).unwrap();
    let policy = OwnPolicy::new([31, 32], root).unwrap();
    let pallas = PinnedParams::<Ep>::derive(Q_K).unwrap();
    let vesta = PinnedParams::<Eq>::derive(Q_K).unwrap();
    let leaf_params = PinnedParams::<Eq>::derive(SIGMA_K).unwrap();
    // Values below are discarded before synthesis. They supply only fixed
    // witness buffer shapes and are never checked or passed to a prover.
    let empty = StateWitness {
        core: [Fp::ZERO; CORE_FIELDS],
        rest: [Fp::ZERO; REST_FIELDS],
        lineage: [Fp::ZERO; 18],
    };
    let own = ArchiveCircuit::new(&ArchiveWitness {
        predecessor: empty,
        successor: empty,
        statement: [Fp::ZERO; 26],
    })
    .without_witnesses();
    let (own_binding, own_key) = keygen_vk_with_binding_v2(
        &leaf_params,
        &own,
        &KeygenConfigV2::pipa_r(ArchiveCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let own_class = SigmaClass::new(
        VerifierPlan::new(own_binding.clone(), leaf_params.clone()).unwrap(),
        vec![(
            sigma_selector(5, 0).unwrap(),
            own_key.kagemusha_digest(&own_binding).unwrap(),
        )],
    )
    .unwrap();
    let incoming = (variant == Variant::ArchiveReceive).then(|| {
        let incoming_params = PinnedParams::<Eq>::derive(incoming_k).unwrap();
        let params = SigmaParams::new(
            RelationShape::new(SigmaRelation::RECEIVE, PrefixMode::Folded),
            1,
            limb_bits_for(incoming_k),
        )
        .unwrap();
        let circuit = SigmaCircuit::<Fp>::keygen(params);
        let (binding, key) = keygen_vk_with_binding_v2(
            &incoming_params,
            &circuit,
            &KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]),
        )
        .unwrap();
        let class = SigmaClass::new(
            VerifierPlan::new(binding.clone(), incoming_params).unwrap(),
            vec![(
                sigma_selector(4, 0).unwrap(),
                key.kagemusha_digest(&binding).unwrap(),
            )],
        )
        .unwrap();
        (class, key)
    });
    let sigma = QSigmaPlan::new(
        own_class,
        incoming.as_ref().map(|(class, _)| class.clone()),
        &vesta,
    )
    .unwrap();
    // Same structural source construction as QSigmaSource::circuit in the
    // native importer. No PreparedQSigma or proof verification is invoked.
    let slot = |index: usize, key: &VerifyingKey<Eq>| {
        let length = sigma.class(index).unwrap().verifier().proof_length();
        assert!(
            length <= 10_000,
            "fixed k12 sigma bound before tape allocation"
        );
        SigmaSlotWitness {
            key: key.clone(),
            statement: Fp::ZERO,
            proof: vec![0; length],
            length: u32::try_from(length).unwrap(),
        }
    };
    let own = slot(0, &own_key);
    let incoming = incoming.as_ref().map(|(_, key)| IncomingSigmaWitness {
        sigma: slot(1, key),
        mode: [false; 3],
        corrected: Eq::from(decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap()),
        fold: [0; FOLD_WITNESS_BYTES],
    });
    let circuit = QSigmaCircuit::new(sigma.clone(), QSigmaWitness { own, incoming })
        .unwrap()
        .without_witnesses()
        .with_serialized_foreign(Q_RANGE_BUSES)
        .unwrap();
    let (binding, key) = keygen_vk_with_binding_v2(
        &pallas,
        &circuit,
        &KeygenConfigV2::pipa_r(QSigmaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let mut qs =
        vec![QProofPlan::new(VerifierPlan::new(binding, pallas.clone()).unwrap(), key).unwrap()];
    for schema in ArchiveAuthorizationObjects::signature_schemas(policy).unwrap() {
        let count = schema.slots().len();
        assert!(matches!(count, 1 | 3));
        let circuit = QSignatureCircuit::new(
            schema,
            vec![
                SignatureWitness {
                    digest: Fp::ZERO,
                    key: [[0; 4]; 2],
                    signature: [[0; 4]; 2],
                };
                count
            ],
        )
        .unwrap()
        .without_witnesses();
        let (binding, key) = keygen_vk_with_binding_v2(
            &pallas,
            &circuit,
            &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
        )
        .unwrap();
        qs.push(QProofPlan::new(VerifierPlan::new(binding, pallas.clone()).unwrap(), key).unwrap());
    }
    // The predecessor has no operation relation or proof. It supplies only
    // constructor-compatible framing for source-only A/W layout planning.
    let (binding, predecessor) = captured.unwrap_or_else(|| {
        keygen_vk_with_binding_v2(
            &pallas,
            &Metadata(vec![1, 2, 16], PhantomData),
            &KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec()),
        )
        .unwrap()
    });
    let omega = VerifierPlan::new(binding, pallas.clone()).unwrap();
    let operation = AProofPlan::new(variant, sigma, qs, Some(omega), &pallas).unwrap();
    (operation, policy, predecessor)
}

/// Strict bounded diagnostic parsing; acceptance authenticates no source.
pub(super) fn captured_metadata(
    descriptor: &[u8],
    key: &[u8],
) -> Option<(DescriptorBinding, VerifyingKey<Ep>)> {
    const CAP: usize = 1_048_576;
    if descriptor.is_empty() || descriptor.len() > CAP || key.is_empty() || key.len() > CAP {
        return None;
    }
    let binding = DescriptorBinding::decode_v2(descriptor).ok()?;
    let d = binding.descriptor();
    if d.curve != CurveV1::Pallas
        || d.k != 16
        || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != InstanceModeV1::Direct
        || d.proof_suffix != ProofSuffixV1::FoldedGenerator
        || d.instance_lengths != [1, 2, 16]
        || d.instance_types.as_deref() != Some(&OmegaPlan::instance_types())
        || binding.encoded() != descriptor
    {
        return None;
    }
    let key = VerifyingKey::<Ep>::read(key, &binding).ok()?;
    Some((binding, key))
}

/// Read independently selected current originals; no historical identity fallback.
pub(super) fn read_selected_fixture() -> super::omega_fixture::LoadedFixture {
    use super::omega_fixture::{load_selected, pin};
    let value = |name| std::env::var(name).expect("explicit independent current fixture selection");
    load_selected(
        &std::path::PathBuf::from(value("KAGEMUSHA_HARD_PREDECESSOR_FIXTURE")),
        pin(&value("KAGEMUSHA_HARD_PREDECESSOR_MANIFEST_SHA256")),
        pin(&value("KAGEMUSHA_HARD_PREDECESSOR_DESCRIPTOR_SHA256")),
        pin(&value("KAGEMUSHA_HARD_PREDECESSOR_KEY_SHA256")),
    )
}

/// Source-capacity DATA diagnostic; source/binary admission remains independent.
pub(super) fn read_captured_metadata() -> (DescriptorBinding, VerifyingKey<Ep>) {
    let fixture = read_selected_fixture();
    let parsed = captured_metadata(&fixture.originals[0], &fixture.originals[1])
        .expect("exact selected current Omega profile");
    fixture.recheck();
    eprintln!(
        "ARCHIVE_CAPTURED_PREDECESSOR descriptor_digest={:02x?} key_digest={:?} key_bytes={} diagnostic_only=true no_artifact_admission=true",
        parsed.0.digest(),
        parsed.1.kagemusha_digest(&parsed.0).unwrap(),
        fixture.originals[1].len()
    );
    parsed
}

#[test]
fn captured_metadata_is_bounded_canonical_and_requires_exact_outer_profile() {
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let (binding, key) = keygen_vk_with_binding_v2(
        &p,
        &Metadata(vec![1, 2, 16], PhantomData),
        &KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec()),
    )
    .unwrap();
    let bytes = key.to_bytes();
    let (decoded, parsed) = captured_metadata(binding.encoded(), bytes).unwrap();
    assert_eq!(decoded, binding);
    assert_eq!(parsed.to_bytes(), bytes);
    assert!(captured_metadata(&[], bytes).is_none());
    assert!(captured_metadata(&vec![0; 1_048_577], bytes).is_none());
    assert!(captured_metadata(binding.encoded(), &vec![0; 1_048_577]).is_none());
    assert!(captured_metadata(&binding.encoded()[..binding.encoded().len() - 1], bytes).is_none());
    assert!(captured_metadata(binding.encoded(), &bytes[..bytes.len() - 1]).is_none());
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(captured_metadata(binding.encoded(), &trailing).is_none());
    let (foreign, key) = keygen_vk_with_binding_v2(
        &p,
        &Metadata(vec![1, 2, 15], PhantomData),
        &KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec()),
    )
    .unwrap();
    assert!(captured_metadata(foreign.encoded(), key.to_bytes()).is_none());
}
