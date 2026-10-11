//! Genuine `ArchiveReceive` sigma/Q sources from the exact retained Send Payment.
//!
//! The predecessor helper currently has superseded Load ancestry. This module
//! proves source leaves only; it never admits an Archive terminal or monetary head.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    SigmaProver, SigmaRelation,
    a_relation::{
        QProofPlan,
        archive::{authorization::ArchiveAuthorizationObjects, stage::ArchiveStagePlan},
        context::ContextObjectSpec,
        own::OwnPolicy,
        schedule::sigma_selector,
    },
    admin_sigma::{ArchiveCircuit, StateWitness},
    operation_relation::objects::ObjectKind,
    q_sigma::{
        QSigmaPlan, SigmaClass, SigmaSlotWitness,
        native::{IncomingMode, IncomingSigma, QSigmaProver},
    },
    q_signature::{QSignatureCircuit, QSignaturePlan, SignatureWitness},
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, Witness, create_proof_owned_with_claim,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::{accumulate_generator, verify_full},
};
use iroha_plonk_gadgets::bytes::{le_value, p_bytes_native};
use iroha_plonk_recursion::{
    FoldConfig, FoldInput, obligation::ledger::Variant, verifier::VerifierPlan,
};

use super::{
    archive_objects::{self, ArchiveFixture},
    bootstrap_objects::{self, Signed},
    common, compact_catalog, receive_objects, send_objects,
};

/// Actual source proof, its exact fixed verifier and complete Pallas opening.
pub struct QSource {
    pub(super) plan: QProofPlan,
    pub(super) proof: Vec<u8>,
    pub(super) instances: Vec<Vec<Fq>>,
    pub(super) opening: FoldInput<Ep>,
}

/// Immutable original sources for one `ArchiveReceive` result, before A ownership.
pub struct ArchiveSource {
    pub(super) predecessor: compact_catalog::CompactSendOmega,
    pub(super) archive: ArchiveFixture,
    pub(super) own_sigma: Vec<u8>,
    pub(super) incoming_sigma: Vec<u8>,
    pub(super) incoming_statement: [Fp; 26],
    pub(super) sigma_plan: QSigmaPlan,
    pub(super) q: [QSource; 3],
    pub(super) part: FoldInput<Eq>,
    pub(super) policy: OwnPolicy,
    /// Current credential, direct certificate and own receipt, in context order.
    pub(super) own: [Signed; 3],
    /// Original Request, payer credential, Send receipt and quoted receiver.
    pub(super) retained: [Vec<u8>; 4],
    /// Original Request, quoted receiver and incoming Receive receipt.
    pub(super) incoming: [Vec<u8>; 3],
    pub(super) payment: Vec<u8>,
    pub(super) credited: Vec<u8>,
    /// Exact commitments for the sixteen original source slots, before results.
    pub(super) commitments: [[Fp; 3]; 16],
    pub(super) specs: Vec<ContextObjectSpec>,
    pub(super) valid: bool,
}
impl ArchiveSource {
    /// Bind the caller's fixed owner metadata and all three derived result bits.
    /// The stage plan supplies owner indices; the source cannot choose them.
    pub(super) fn context_triples(&self, result_words: &[Fp]) -> [[Fp; 3]; 17] {
        assert_eq!(result_words.len(), 11);
        assert_eq!(&result_words[..2], &[Fp::ONE, Fp::ONE]);
        assert_eq!(
            &result_words[8..],
            &[Fp::from(u64::from(self.valid)), Fp::ONE, Fp::ONE]
        );
        let mut values = self.commitments.to_vec();
        values.push(internal(self.specs[16], result_words));
        values.try_into().unwrap()
    }
}

fn framed(raw: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(raw);
    bytes
}
fn internal(spec: ContextObjectSpec, values: &[Fp]) -> [Fp; 3] {
    assert_eq!(usize::try_from(spec.capacity).unwrap(), values.len() * 32);
    let mut words = vec![
        Fp::from(u64::from(spec.tag)),
        Fp::from(u64::try_from(values.len()).unwrap()),
    ];
    words.extend_from_slice(values);
    let digest = hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &words);
    [digest, Fp::from(u64::from(spec.capacity)), digest]
}
fn commitment(spec: ContextObjectSpec, raw: &[u8], digest: Fp, active: bool) -> [Fp; 3] {
    let length = u64::try_from(raw.len()).unwrap();
    assert!(length <= u64::from(spec.capacity));
    if !active {
        assert_eq!(length, u64::from(spec.capacity));
    }
    let mut words = vec![
        Fp::from(u64::from(spec.tag)),
        Fp::from(u64::from(spec.capacity)),
    ];
    let tape = framed(raw);
    let domain = if active {
        words.extend([
            Fp::from(length),
            p_bytes_native(u64::from_le_bytes(*b"kgwcact1"), &tape),
        ]);
        *b"kgwcact1"
    } else {
        words.extend(tape.chunks(31).map(|chunk| le_value::<Fp>(chunk).unwrap()));
        *b"kgwctap1"
    };
    [
        digest,
        Fp::from(length),
        hash_with_domain(u64::from_le_bytes(domain), &words),
    ]
}

fn signed(kind: ObjectKind, raw: &[u8], secret: u64) -> Signed {
    assert_eq!(raw.len(), kind.body_len() + 64);
    let end = kind.body_len();
    let point = bootstrap_objects::key(secret);
    let integer = |raw: &[u8]| {
        core::array::from_fn(|i| {
            u64::from_be_bytes(raw[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
        })
    };
    Signed {
        kind,
        bytes: raw.to_vec(),
        signature: SignatureWitness {
            digest: p_bytes_native(kind.signing_domain(), &raw[..end]),
            key: [point.x, point.y],
            signature: [integer(&raw[end..end + 32]), integer(&raw[end + 32..])],
        },
    }
}

fn signature_q(schema: &QSignaturePlan, witnesses: Vec<SignatureWitness>, seed: u8) -> QSource {
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let circuit = QSignatureCircuit::new(schema.clone(), witnesses).unwrap();
    let instances = circuit
        .instances(&vec![true; schema.slots().len()])
        .unwrap()
        .to_vec();
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let output = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &instances).unwrap(),
        common::recovery(seed),
        ProverConfig::default(),
    )
    .unwrap();
    verify_full(
        &params,
        key.binding(),
        key.vk(),
        &instances,
        &output.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    output
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    QSource {
        plan: QProofPlan::new(
            VerifierPlan::new(key.binding().clone(), params).unwrap(),
            key.vk().clone(),
        )
        .unwrap(),
        proof: output.proof,
        instances,
        opening: FoldInput::from_opening(*output.opening.g(), output.opening.challenges()).unwrap(),
    }
}

/// Exact incoming original to carry through the total verifier.
#[derive(Clone, Copy, Debug)]
pub enum IncomingOriginal {
    /// Complete genuine Receive sigma.
    Valid,
    /// Descriptor-sized sigma with one altered proof byte.
    CorruptedProof,
    /// Genuine prefix followed by a tail filling the complete Credited budget.
    FullEnvelopeTail,
}

/// Prove the exact own Archive and incoming Receive leaves plus all three Qs.
/// Invalid originals are re-signed and re-hashed, so receipt and body still pass
/// while Q0 soft-fails and selects Trivial. Q receives only its fixed safe view;
/// A must bind the entire original, including an over-descriptor tail.
pub fn build(
    predecessor: compact_catalog::CompactSendOmega,
    original: IncomingOriginal,
) -> ArchiveSource {
    let valid = matches!(original, IncomingOriginal::Valid);
    let retained_send = &predecessor.source.maps.witness;
    let send = send_objects::from_load(&retained_send.before);
    assert_eq!(send.statement, retained_send.statement);
    assert_eq!(send.objects, retained_send.objects);
    let (_, certificate, credential) = bootstrap_objects::enrollment();
    assert_eq!(credential.bytes, retained_send.objects[0]);
    assert_eq!(certificate.bytes, predecessor.source.own_objects[0]);
    let quoted = send_objects::receiver_credential();
    let send_receipt = signed(ObjectKind::Receipt, &predecessor.source.own_objects[1], 29);
    let proof_tape = [
        framed(&predecessor.source.predecessor_omega),
        framed(&predecessor.source.sigma),
    ]
    .concat();
    let retained_proof: Fp = p_bytes_native(u64::from_le_bytes(*b"kgwprf_1"), &proof_tape);
    assert_eq!(
        retained_proof.to_repr(),
        send_receipt.bytes[242..274],
        "retained receipt must bind the exact original transported Omega and sigma",
    );
    let payment = archive_objects::payment(
        &send.objects[1],
        &send.objects[0],
        &send.statement,
        &send_receipt,
    );
    let payment_digest = p_bytes_native(u64::from_le_bytes(*b"kgwpay_1"), &payment);
    let (receiver, _, _) = receive_objects::receiver();
    let receive = receive_objects::from_send(
        &send,
        &StateWitness::from(&receiver),
        payment_digest,
        true,
        true,
    );
    let incoming = SigmaProver::<Eq>::keygen_with_params(
        common::pinned_shape(common::folded(SigmaRelation::RECEIVE), (12, 1)),
        common::vesta_params(12),
    )
    .unwrap();
    let incoming_proof = incoming
        .prove(&receive.step, common::recovery(161))
        .unwrap();
    let mut incoming_sigma = incoming_proof.bytes;
    let incoming_proof_length = incoming_sigma.len();
    match original {
        IncomingOriginal::Valid => {}
        IncomingOriginal::CorruptedProof => {
            let last = incoming_sigma.len() - 1;
            incoming_sigma[last] ^= 1;
        }
        IncomingOriginal::FullEnvelopeTail => {
            let capacity = iroha_kagemusha_proof::a_relation::archive::MAX_RECEIVE_SIGMA_RAW_BYTES;
            assert!(incoming_sigma.len() < capacity);
            incoming_sigma.resize(capacity, 0x37);
        }
    }
    let incoming_receipt = archive_objects::step_receipt(
        &receive.before,
        &receive.statement,
        &incoming_sigma,
        payment_digest,
        43,
        83,
    );
    let credited = archive_objects::credited_receive(
        send.statement[17],
        payment_digest,
        &receive.statement,
        &incoming_receipt,
        &incoming_sigma,
    );
    let credited_digest = p_bytes_native(u64::from_le_bytes(*b"kgwcrdd1"), &credited);
    let descriptor = send.statement[17..24].try_into().unwrap();
    let pending = archive_objects::pending(descriptor);
    let archive = archive_objects::from_pending(
        &predecessor.source.state,
        descriptor,
        credited_digest,
        valid,
        &pending,
        &pending,
    );
    let leaf = ArchiveCircuit::new(&archive.witness);
    let leaf_params = common::vesta_params(12);
    let own_key = keygen_pk_v2(
        &leaf_params,
        &leaf,
        &KeygenConfigV2::pipa_r(ArchiveCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let own_sigma = create_proof_owned_with_claim(
        &leaf_params,
        &own_key,
        Witness::from_circuit(&own_key, &leaf, &leaf.instances()).unwrap(),
        common::recovery(162),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    verify_full(
        &leaf_params,
        own_key.binding(),
        own_key.vk(),
        &leaf.instances(),
        &own_sigma,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let own_receipt = archive_objects::step_receipt(
        &archive.witness.predecessor,
        &archive.witness.statement,
        &own_sigma,
        Fp::ZERO,
        29,
        89,
    );
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    let pparams = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = common::vesta_params(16);
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(own_key.binding().clone(), leaf_params).unwrap(),
            vec![(
                sigma_selector(5, 0).unwrap(),
                own_key.vk().kagemusha_digest(own_key.binding()).unwrap(),
            )],
        )
        .unwrap(),
        Some(
            SigmaClass::from_verifiers(&[(sigma_selector(4, 0).unwrap(), &incoming.verifier())])
                .unwrap(),
        ),
        &vparams,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: own_key.vk().clone(),
                statement: leaf.instances()[0][0],
                length: own_sigma.len().try_into().unwrap(),
                proof: own_sigma.clone(),
            },
            Some(IncomingSigma {
                sigma: SigmaSlotWitness {
                    key: incoming.proving_key().vk().clone(),
                    statement: incoming_proof.public.instance()[0],
                    length: incoming_sigma.len().try_into().unwrap(),
                    proof: incoming_sigma[..incoming_proof_length].to_vec(),
                },
                mode: if valid {
                    IncomingMode::Accept
                } else {
                    IncomingMode::Trivial
                },
            }),
            &vparams,
            Fq::from(163),
            &FoldConfig::default(),
        )
        .unwrap();
    drop(own_key);
    drop(incoming);
    let qprover = QSigmaProver::keygen_serialized_foreign(&prepared, pparams.clone(), 2).unwrap();
    let qproof = qprover
        .prove(&prepared, common::recovery(164), ProverConfig::default())
        .unwrap();
    let opening = accumulate_generator(
        &pparams,
        qprover.binding(),
        qprover.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&pparams, MemoryBudget::DEFAULT).unwrap();
    prepared
        .part()
        .decide(&vparams, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(qproof.instances[3][0], Fq::ONE);
    assert_eq!(qproof.instances[3][1], Fq::from(u64::from(valid)));
    let q0 = QSource {
        plan: QProofPlan::new(
            VerifierPlan::new(qprover.binding().clone(), pparams).unwrap(),
            qprover.verifying_key().clone(),
        )
        .unwrap(),
        proof: qproof.bytes,
        instances: qproof.instances,
        opening: FoldInput::from_opening(*opening.g(), opening.challenges()).unwrap(),
    };
    drop(qprover);
    let schemas = ArchiveAuthorizationObjects::signature_schemas(policy).unwrap();
    let q1 = signature_q(
        &schemas[0],
        vec![
            own_receipt.signature,
            credential.signature,
            certificate.signature,
        ],
        165,
    );
    let q2 = signature_q(&schemas[1], vec![incoming_receipt.signature], 166);
    let own = [credential, certificate, own_receipt];
    let retained = [
        send.objects[1].clone(),
        send.objects[0].clone(),
        send_receipt.bytes,
        quoted.bytes.clone(),
    ];
    let incoming = [retained[0].clone(), quoted.bytes, incoming_receipt.bytes];
    let specs = ArchiveStagePlan::full_context_specs(Variant::ArchiveReceive).unwrap();
    assert_eq!(specs.len(), 17);
    let mut triples = Vec::new();
    for (i, object) in own.iter().enumerate() {
        triples.push(commitment(specs[i], &object.bytes, object.digest(), false));
    }
    for (i, (kind, raw)) in [
        ObjectKind::Request,
        ObjectKind::Credential,
        ObjectKind::Receipt,
        ObjectKind::Credential,
    ]
    .into_iter()
    .zip(&retained)
    .enumerate()
    {
        triples.push(commitment(
            specs[3 + i],
            raw,
            archive_objects::object_digest(kind, raw),
            false,
        ));
    }
    triples.push(commitment(specs[7], &payment, payment_digest, false));
    triples.push(internal(specs[8], &send.statement));
    for (i, raw) in [
        &predecessor.source.predecessor_omega,
        &predecessor.source.sigma,
    ]
    .into_iter()
    .enumerate()
    {
        triples.push(commitment(specs[9 + i], raw, retained_proof, true));
    }
    triples.push(internal(specs[11], &descriptor));
    triples.push(commitment(
        specs[12],
        &incoming[2],
        archive_objects::object_digest(ObjectKind::Receipt, &incoming[2]),
        false,
    ));
    triples.push(commitment(
        specs[13],
        &incoming_sigma,
        archive_objects::step_digest(&incoming_sigma),
        true,
    ));
    triples.push(internal(specs[14], &receive.statement));
    triples.push(commitment(specs[15], &credited, credited_digest, false));
    ArchiveSource {
        predecessor,
        archive,
        own_sigma,
        incoming_sigma,
        incoming_statement: receive.statement,
        sigma_plan,
        q: [q0, q1, q2],
        part: prepared.part().clone(),
        policy,
        own,
        retained,
        incoming,
        payment,
        credited,
        commitments: triples.try_into().unwrap(),
        specs,
        valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_original_and_native_commitments_preserve_every_byte_and_category() {
        let (_, certificate, credential) = bootstrap_objects::enrollment();
        for (original, secret) in [(&certificate, 23), (&credential, 17)] {
            let recovered = signed(original.kind, &original.bytes, secret);
            assert_eq!(recovered.bytes, original.bytes);
            assert_eq!(recovered.digest(), original.digest());
            assert_eq!(recovered.signature.digest, original.signature.digest);
            assert_eq!(recovered.signature.key, original.signature.key);
            assert_eq!(recovered.signature.signature, original.signature.signature);
        }
        let spec = ContextObjectSpec {
            tag: 14,
            capacity: 16,
        };
        let digest = Fp::from(9);
        let a = commitment(spec, &[1, 2, 3], digest, true);
        assert_ne!(a, commitment(spec, &[1, 2, 3, 0], digest, true));
        assert_ne!(a, commitment(spec, &[1, 2, 4], digest, true));
        assert_ne!(
            a,
            commitment(
                ContextObjectSpec { tag: 10, ..spec },
                &[1, 2, 3],
                digest,
                true
            )
        );
        let words = [Fp::ONE, Fp::from(2)];
        let spec = ContextObjectSpec {
            tag: 15,
            capacity: 64,
        };
        let a = internal(spec, &words);
        assert_eq!(a[0], a[2]);
        assert_eq!(a[1], Fp::from(64));
        assert_ne!(a, internal(ContextObjectSpec { tag: 9, ..spec }, &words));
        assert_ne!(a, internal(spec, &[words[1], words[0]]));
    }
}
