//! Fixed-owner Receive continuation over real sigma, signature-Q and Omega proofs.
//!
//! Burn uses an unrelated but real receiver Omega under a correctly signed
//! Send package. Accepted credit uses distinct payer Load and receiver Bootstrap
//! heads proved under the same immutable compact catalog. Every owner must fit
//! k16, including fixed maximum incoming capacities; these diagnostic catalogs
//! do not admit the Receive terminal or establish full release qualification.
#![allow(clippy::duplicate_mod)]
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
/// Real rooted receiver predecessor, with explicit partial-catalog provenance.
#[path = "bootstrap_omega.rs"]
pub mod bootstrap_outer;
mod common;
/// Genuine distinct payer/receiver heads rebuilt under one compact outer key.
#[path = "compact_catalog.rs"]
pub mod compact_catalog;
#[path = "common/native_source_factory_checks.rs"]
mod native_source_factory_checks;
/// Real Receive/Send source proofs and exact depth32 map witnesses.
#[path = "a_receive.rs"]
pub mod receive_components;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, IncomingLineageCells, LineagePublicCells, ProofMessageCells, QProofPlan,
        SigmaBindingCells, VestaClaimCells,
        context::{
            ContextIncoming, ContextIncomingProof, ContextInputs, ContextObjectSpec, ContextPlan,
            ContextPredecessor, ContextState,
        },
        incoming_transport::IncomingTransportPlan,
        own::OwnPolicy,
        receive::{
            MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES, PAYMENT_PROOF_BUDGET, ReceiveObjectInputs,
            ReceiveObjectSources, ReceiveObjects, ReceiveProofDigest, ReceiveProofInputs,
            ReceiveProofSources, ReceiveSignedObjects, ReceiveStageInputs, ReceiveStagePlan,
            ReceiveStageWitness,
            authorization::{
                ReceiveAuthorizationObjects, ReceiveAuthorizationSources,
                ReceiveSignatureQProjection,
            },
        },
        results::ReceiveResultClaims,
        schedule::OperationTask,
        split::{SplitPlan, WCircuit, WKey, close_first, close_stage, resume_context},
        verify_predecessor, verify_q,
    },
    admin_sigma::StateWitness,
    operation_relation::{
        incoming_statement::IncomingStatementCells,
        map_effects::{InsertCells, ReceiveMapWitness},
        objects::ObjectKind,
        state::StateCells,
        statement::StatementCells,
    },
    q_sigma::native::IncomingMode,
    q_signature::{QSignatureCircuit, QSignaturePlan, SignatureWitness},
    tree::IndexedInsert,
};
use iroha_pasta::{
    Ep, Eq, EqAffine, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain,
};
use iroha_plonk::{
    ProverConfig, ProverOutput, ProvingKey, VerifyingKey, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    verifier::verify_full,
};
use iroha_plonk_gadgets::{
    UintChip, Word,
    bytes::{
        chunk_segments, p_bytes_native,
        tape::{BytesChip, BytesConfig, SegmentSpec},
        variable::ActiveBytes,
    },
    imt::{LeafCells, OpeningCells, PathCells},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::{ModeCells, ledger::Variant},
    verifier::{VerifierChip, VerifierConfig, VerifierKeyCells, VerifierPlan},
};
use std::sync::Arc;

#[derive(Clone)]
struct QSource {
    plan: QProofPlan,
    proof: Vec<u8>,
    instances: Vec<Vec<Fq>>,
    opening: FoldInput<Ep>,
}
/// Exact original lineage artifact, independent of the operation that produced it.
#[derive(Clone)]
struct Head {
    state: StateWitness,
    key: VerifyingKey<Ep>,
    binding: iroha_plonk::DescriptorBinding,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
    opening: FoldInput<Ep>,
}
impl From<bootstrap_outer::RootedBootstrapOmega> for Head {
    fn from(artifact: bootstrap_outer::RootedBootstrapOmega) -> Self {
        Self {
            state: StateWitness::from(&artifact.source.state),
            key: artifact.key,
            binding: artifact.binding,
            proof: artifact.proof,
            pallas: artifact.source.pallas,
            vesta: artifact.vesta,
            opening: artifact.opening,
        }
    }
}
struct Source {
    own: receive_components::ReceiveQ,
    predecessor: Head,
    incoming_head: Head,
    accept: bool,
    objects_valid: bool,
    corrected_vesta: bool,
    vesta_correction: EqAffine,
    plan: ReceiveStagePlan,
    q: Vec<QSource>,
    objects: [Vec<u8>; 11],
    commitments: Vec<[Fp; 3]>,
    incoming: Vec<u8>,
    params: PinnedParams<Ep>,
}
impl Source {
    fn proofs_valid(&self) -> bool {
        // Every fixture Omega is an actual succinct proof. The combined proof
        // result therefore follows the already verified Q0 incoming verdict.
        self.own.instances[3][1] == Fq::ONE
    }
    fn variant(&self) -> Variant {
        self.plan.context().operation().frame().variant()
    }
    fn mode(&self, index: usize) -> IncomingMode {
        if self.accept {
            IncomingMode::Accept
        } else if index == 2 && self.corrected_vesta {
            IncomingMode::Corrected
        } else {
            IncomingMode::Trivial
        }
    }
    fn mode_words(&self, index: usize) -> [Fp; 3] {
        match self.mode(index) {
            IncomingMode::Accept => [Fp::ONE, Fp::ZERO, Fp::ZERO],
            IncomingMode::Trivial => [Fp::ZERO, Fp::ONE, Fp::ZERO],
            IncomingMode::Corrected => [Fp::ZERO, Fp::ZERO, Fp::ONE],
        }
    }
    fn vesta_correction_words(&self) -> [Fp; 4] {
        let (x, y) = self.vesta_correction.coordinates().unwrap();
        let [x0, x1] = foreign_limbs(&x).map(Fp::from_u128);
        let [y0, y1] = foreign_limbs(&y).map(Fp::from_u128);
        [x0, x1, y0, y1]
    }
}
#[derive(Clone, Copy, Debug)]
enum IngestionCapacity {
    Descriptor,
    CanonicalEnvelope,
}
impl IngestionCapacity {
    fn capacities(self, omega: usize, sigma: usize) -> [usize; 2] {
        match self {
            Self::Descriptor => [omega, sigma],
            Self::CanonicalEnvelope => [MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES],
        }
    }
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    out.extend(bytes);
    out
}
pub(crate) fn public_bytes(fields: &[Fp; 18]) -> Vec<u8> {
    let mut out = 1u16.to_le_bytes().to_vec();
    for i in [1, 2, 3, 4] {
        out.extend(&fields[i].to_repr()[..16]);
    }
    out.extend(fields[5].to_repr());
    for i in [6, 7] {
        out.extend(&fields[i].to_repr()[..16]);
    }
    out.extend(fields[8].to_repr());
    out.push(4);
    for i in [10, 9, 12, 11] {
        out.extend(fields[i].to_repr()[..16].iter().rev());
    }
    out.extend(&fields[13].to_repr()[..13]);
    out.extend(&fields[14].to_repr()[..16]);
    out.extend(fields[15].to_repr());
    out.extend(fields[16].to_repr());
    assert_eq!(out.len(), 320);
    out
}
fn signed_digest(kind: ObjectKind, raw: &[u8]) -> Fp {
    let end = kind.body_len();
    let mut words = vec![p_bytes_native(kind.signing_domain(), &raw[..end])];
    for offset in [16, 0, 48, 32] {
        words.push(Fp::from_u128(u128::from_be_bytes(
            raw[end + offset..end + offset + 16].try_into().unwrap(),
        )));
    }
    hash_with_domain(kind.object_domain(), &words)
}
/// Build the transitive Payment from the retained payer credential. Request is
/// signed by the receiver, but Payment's key identifies the payer's Send.
fn payment_transcript(
    request: &[u8],
    payer: &[u8],
    statement: &[Fp; 26],
    proof_digest: Fp,
    receipt: Fp,
) -> Vec<u8> {
    let package = hash_with_domain(
        u64::from_le_bytes(*b"kgwpkg_1"),
        &[
            hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, statement),
            proof_digest,
            receipt,
        ],
    );
    let mut payment = 1u16.to_le_bytes().to_vec();
    payment.extend(signed_digest(ObjectKind::Request, request).to_repr());
    payment.extend(&payer[130..195]);
    payment.extend(signed_digest(ObjectKind::Credential, payer).to_repr());
    payment.extend(package.to_repr());
    assert_eq!(payment.len(), 163);
    payment
}

#[test]
fn payment_transcript_uses_payer_key_not_receiver_request_signer() {
    let (_, _, payer) = bootstrap_objects::enrollment();
    let (_, _, receiver) = bootstrap_objects::enrollment_for(bootstrap_objects::Identity::Receiver);
    let request = vec![0; ObjectKind::Request.body_len() + 64];
    let payment = payment_transcript(&request, &payer.bytes, &[Fp::ZERO; 26], Fp::ONE, Fp::ONE);
    assert_eq!(
        &payment[34..99],
        bootstrap_objects::sec1(bootstrap_objects::key(29))
    );
    assert_ne!(&payment[34..99], &receiver.bytes[130..195]);
    assert_eq!(&payment[99..131], payer.digest().to_repr());
}

fn commitment(spec: ContextObjectSpec, raw: &[u8], digest: Fp, active: bool) -> [Fp; 3] {
    let mut words = vec![
        Fp::from(u64::from(spec.tag)),
        Fp::from(u64::from(spec.capacity)),
    ];
    let tape_digest = if active {
        words.extend([
            Fp::from(u64::try_from(raw.len()).unwrap()),
            p_bytes_native(u64::from_le_bytes(*b"kgwcact1"), &frame(raw)),
        ]);
        hash_with_domain(u64::from_le_bytes(*b"kgwcact1"), &words)
    } else {
        for chunk in frame(raw).chunks(31) {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            words.push(Fp::from_repr(repr).unwrap());
        }
        hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &words)
    };
    [
        digest,
        Fp::from(u64::try_from(raw.len()).unwrap()),
        tape_digest,
    ]
}
fn receipt(
    statement: &[Fp; 26],
    wallet: &[Fp],
    proof: Fp,
    payment: Fp,
    secret: u64,
    nonce: u64,
) -> bootstrap_objects::Signed {
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[wallet[0], wallet[1], statement[16], statement[17]],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(statement[3], statement[4]));
    body.extend(bootstrap_objects::id(wallet[0], wallet[1]));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&statement[9].to_repr()[..16]);
    for word in [
        operation,
        statement[14],
        statement[15],
        hash_with_domain(iroha_plonk_gadgets::statement::STATEMENT_DOMAIN, statement),
        proof,
    ] {
        body.extend(word.to_repr());
    }
    body.extend(bootstrap_objects::small_id(501, 502));
    body.extend(payment.to_repr());
    bootstrap_objects::sign(ObjectKind::Receipt, body, secret, nonce)
}
fn signature_q(
    params: &PinnedParams<Ep>,
    schema: &QSignaturePlan,
    witnesses: Vec<SignatureWitness>,
    seed: u8,
) -> QSource {
    let circuit = QSignatureCircuit::new(schema.clone(), witnesses).unwrap();
    let instances = circuit
        .instances(&vec![true; schema.slots().len()])
        .unwrap()
        .to_vec();
    let key = keygen_pk_v2(
        params,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let output = create_proof_owned_with_claim(
        params,
        &key,
        Witness::from_circuit(&key, &circuit, &instances).unwrap(),
        common::recovery(seed),
        ProverConfig::default(),
    )
    .unwrap();
    output
        .opening
        .decide(params, MemoryBudget::DEFAULT)
        .unwrap();
    QSource {
        plan: QProofPlan::new(
            VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
            key.vk().clone(),
        )
        .unwrap(),
        proof: output.proof,
        instances,
        opening: FoldInput::from_opening(*output.opening.g(), output.opening.challenges()).unwrap(),
    }
}
fn source(predecessor: Head, payer: Option<Head>, capacity: IngestionCapacity) -> Source {
    source_variant(predecessor, payer, capacity, Variant::Receive, None)
}
fn source_variant(
    predecessor: Head,
    payer: Option<Head>,
    capacity: IngestionCapacity,
    variant: Variant,
    insert_override: Option<bool>,
) -> Source {
    source_with_correction(
        predecessor,
        payer,
        capacity,
        variant,
        insert_override,
        None,
        true,
    )
}
fn source_with_correction(
    predecessor: Head,
    payer: Option<Head>,
    capacity: IngestionCapacity,
    variant: Variant,
    insert_override: Option<bool>,
    correction: Option<EqAffine>,
    incoming_sigma_valid: bool,
) -> Source {
    use OperationTask::*;
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let before = predecessor.state;
    let objects_valid = payer.is_some();
    let accept = objects_valid && correction.is_none();
    let insert = insert_override.unwrap_or(objects_valid);
    assert!(!accept || insert);
    let incoming_head = payer.unwrap_or_else(|| predecessor.clone());
    assert_eq!(incoming_head.binding, predecessor.binding);
    assert_eq!(incoming_head.key.to_bytes(), predecessor.key.to_bytes());
    assert_eq!(incoming_head.state.lineage[17], before.lineage[17]);
    let (_, certificate, credential) =
        bootstrap_objects::enrollment_for(bootstrap_objects::Identity::Receiver);
    assert_eq!(credential.digest(), before.core[7]);
    let quoted = if variant == Variant::ReceiveRenewed {
        // A distinct genuine issuer signature changes the credential content
        // address while retaining its wallet, account, key and certificate.
        bootstrap_objects::sign(
            ObjectKind::Credential,
            credential.bytes[..ObjectKind::Credential.body_len()].to_vec(),
            17,
            79,
        )
    } else {
        credential.clone()
    };
    assert_eq!(
        quoted.digest() == credential.digest(),
        variant == Variant::Receive
    );
    let mut own = if !incoming_sigma_valid {
        assert!(!objects_valid && !insert && correction.is_none());
        assert_eq!(variant, Variant::Receive);
        receive_components::genuine_receive_source_with_invalid_sigma(&before)
    } else if variant == Variant::ReceiveRenewed {
        receive_components::genuine_receive_source_for_quoted(
            &before,
            objects_valid.then_some(&incoming_head.state),
            &quoted.bytes,
            accept,
            insert,
            if accept {
                IncomingMode::Accept
            } else {
                IncomingMode::Trivial
            },
        )
    } else if objects_valid {
        receive_components::genuine_receive_source_for_heads(
            &before,
            &incoming_head.state,
            accept,
            insert,
            if accept {
                IncomingMode::Accept
            } else {
                IncomingMode::Trivial
            },
        )
    } else {
        receive_components::genuine_receive_source_for(
            &before,
            false,
            insert,
            IncomingMode::Trivial,
        )
    };
    let mut incoming = public_bytes(&incoming_head.state.lineage);
    incoming.extend(&incoming_head.proof);
    incoming.extend(incoming_head.pallas.to_bytes());
    incoming.extend(incoming_head.vesta.to_bytes());
    assert!(incoming.len() - 320 <= 4_821);
    assert!(incoming.len() - 320 + own.incoming_sigma.len() <= PAYMENT_PROOF_BUDGET);
    let proof_digest = p_bytes_native(
        u64::from_le_bytes(*b"kgwprf_1"),
        &[frame(&incoming), frame(&own.incoming_sigma)].concat(),
    );
    let send_receipt = receipt(
        &own.send.statement,
        &own.send.before.lineage[6..8],
        proof_digest,
        Fp::ZERO,
        29,
        71,
    );
    let request = own.send.objects[1].clone();
    let payer = own.send.objects[0].clone();
    let payment = payment_transcript(
        &request,
        &payer,
        &own.send.statement,
        proof_digest,
        send_receipt.digest(),
    );
    let payment_digest = p_bytes_native(u64::from_le_bytes(*b"kgwpay_1"), &payment);
    own.bind_payment(payment_digest, accept, insert);
    let own_receipt = receipt(
        &own.witness.statement,
        &before.lineage[6..8],
        p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &frame(&own.sigma)),
        payment_digest,
        43,
        73,
    );
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    let schemas = ReceiveStagePlan::signature_schemas(variant, policy).unwrap();
    let q_own = signature_q(
        &params,
        &schemas[0],
        vec![
            own_receipt.signature,
            credential.signature,
            certificate.signature,
        ],
        245,
    );
    let request_signature = {
        let (_, _, receiver) =
            bootstrap_objects::enrollment_for(bootstrap_objects::Identity::Receiver);
        assert_eq!(receiver.signature.key, credential.signature.key);
        // Re-sign the exact Request body under its actual receiver key; the
        // deterministic nonce must reproduce the retained signature bytes.
        let signed = bootstrap_objects::sign(
            ObjectKind::Request,
            request[..ObjectKind::Request.body_len()].to_vec(),
            43,
            59,
        );
        assert_eq!(signed.bytes, request);
        signed.signature
    };
    let mut incoming_signatures = vec![send_receipt.signature, request_signature];
    if variant == Variant::ReceiveRenewed {
        incoming_signatures.extend([quoted.signature, certificate.signature]);
    }
    let q_incoming = signature_q(&params, &schemas[1], incoming_signatures, 246);
    let q = vec![
        QSource {
            plan: own.q.clone(),
            proof: own.proof.clone(),
            instances: own.instances.clone(),
            opening: own.opening.clone(),
        },
        q_own,
        q_incoming,
    ];
    let operation = AProofPlan::new(
        variant,
        own.sigma_plan.clone(),
        q.iter().map(|q| q.plan.clone()).collect(),
        Some(VerifierPlan::new(predecessor.binding.clone(), params.clone()).unwrap()),
        &params,
    )
    .unwrap();
    let [omega_capacity, sigma_capacity] =
        capacity.capacities(incoming.len(), own.incoming_sigma.len());
    assert!(incoming.len() <= omega_capacity && own.incoming_sigma.len() <= sigma_capacity);
    eprintln!(
        "RECEIVE_INGESTION {capacity:?} omega_capacity={omega_capacity} sigma_capacity={sigma_capacity}"
    );
    let specs = ReceiveStagePlan::context_specs(variant, omega_capacity, sigma_capacity).unwrap();
    let context = ContextPlan::with_schedule(
        operation,
        vec![
            vec![],
            vec![0],
            vec![],
            vec![],
            vec![],
            vec![1],
            vec![2],
            vec![],
            vec![],
            vec![],
        ],
        Some(0),
        specs.clone(),
    )
    .unwrap()
    .with_operation_tasks(vec![
        vec![
            ReceiveOwnProof,
            ReceiveConsumedEffects,
            ReceiveCreditEffects,
        ],
        vec![],
        vec![ReceiveProofs],
        vec![ReceiveProofDigest],
        vec![ReceiveObjects],
        vec![ReceiveAuthorization],
        vec![],
        vec![ReceiveSignatures],
        vec![ReceiveNonmembership, ReceiveBlacklist],
        vec![ReceiveEffects],
    ])
    .unwrap();
    let plan = ReceiveStagePlan::new(context, policy).unwrap();
    let objects = [
        request.clone(),
        payer.clone(),
        send_receipt.bytes,
        payment,
        incoming.clone(),
        own.incoming_sigma.clone(),
        credential.bytes.clone(),
        certificate.bytes.clone(),
        own_receipt.bytes,
        quoted.bytes,
        certificate.bytes,
    ];
    let kinds = [
        Some(ObjectKind::Request),
        Some(ObjectKind::Credential),
        Some(ObjectKind::Receipt),
        None,
        None,
        None,
        Some(ObjectKind::Credential),
        Some(ObjectKind::Certificate),
        Some(ObjectKind::Receipt),
        Some(ObjectKind::Credential),
        Some(ObjectKind::Certificate),
    ];
    let commitments = specs
        .into_iter()
        .enumerate()
        .map(|(i, spec)| {
            let digest = kinds[i].map_or_else(
                || match i {
                    3 => payment_digest,
                    4 => proof_digest,
                    5 => p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &frame(&objects[i])),
                    _ => unreachable!(),
                },
                |kind| signed_digest(kind, &objects[i]),
            );
            commitment(spec, &objects[i], digest, matches!(i, 4 | 5))
        })
        .collect();
    Source {
        own,
        predecessor,
        incoming_head,
        accept,
        objects_valid,
        corrected_vesta: correction.is_some(),
        vesta_correction: correction.unwrap_or_else(|| {
            *AccumulatorT::<Eq>::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT)
                .unwrap()
                .g()
        }),
        plan,
        q,
        objects,
        commitments,
        incoming,
        params,
    }
}

#[derive(Clone, Copy)]
struct Cells {
    known: bool,
}
impl Cells {
    fn value<T: Copy>(self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn bytes(self, source: &[u8]) -> Vec<Value<u8>> {
        source.iter().map(|v| self.value(*v)).collect()
    }
    fn words<const N: usize>(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        values: &[Fp; N],
    ) -> Result<[Word<Fp>; N], Error> {
        chip.uint()
            .glue()
            .witnesses(region, &values.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
    fn scalar(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: Fq,
    ) -> Result<ScalarCells<Ep>, Error> {
        let [low, high] = foreign_limbs(&value);
        let low = chip.uint().assign::<128>(region, self.value(low))?;
        let high = chip.uint().assign::<127>(region, self.value(high))?;
        ScalarCells::from_limbs(&mut chip.uint(), region, &low, &high)
    }
    fn q_instance(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: Fq,
        ty: InstanceType,
    ) -> Result<ScalarCells<Ep>, Error> {
        if matches!(ty, InstanceType::Bounded | InstanceType::Bits(0..=253)) {
            // A hard Q input of this declared type has an injective native Fp
            // representation. Preserve that checked certificate for downstream
            // context/type checks; never reduce a foreign scalar modulo p.
            let native =
                Option::<Fp>::from(Fp::from_repr(value.to_repr())).ok_or(Error::Synthesis)?;
            let word = chip.uint().glue().witness(region, self.value(native))?;
            ScalarCells::from_native_word(&mut chip.uint(), region, &word)
        } else {
            self.scalar(chip, region, value)
        }
    }
    fn pallas(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: &FoldInput<Ep>,
    ) -> Result<FoldInputCells<Ep>, Error> {
        let point = chip.witness_point(region, self.value(Ep::from(*value.g())))?;
        let scalars = value
            .challenges()
            .iter()
            .map(|v| self.scalar(chip, region, *v))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        FoldInputCells::from_normalized(chip, region, value.source_k(), point, scalars)
    }
    fn vesta(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        value: &AccumulatorT<Eq>,
    ) -> Result<VestaClaimCells, Error> {
        let (x, y) = Option::from(value.g().coordinates()).ok_or(Error::Synthesis)?;
        let coordinates = [self.scalar(chip, region, x)?, self.scalar(chip, region, y)?];
        let challenges = self.words(chip, region, value.challenges())?;
        VestaClaimCells::constrain(chip, region, 16, coordinates, challenges)
    }
    fn state(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        state: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = self.words(chip, region, &state.core)?;
        let rest = self.words(chip, region, &state.rest)?;
        let state_cells = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = self.words(chip, region, &state.lineage)?;
        Ok((
            state_cells,
            LineagePublicCells::constrain(&mut chip.uint(), region, &public)?,
        ))
    }
    fn proof(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        raw: &[u8],
    ) -> Result<ProofMessageCells, Error> {
        if !raw.len().is_multiple_of(32) {
            return Err(Error::Synthesis);
        }
        let length = chip.uint().assign::<32>(
            region,
            self.value(u128::try_from(raw.len()).map_err(|_| Error::BoundsFailure)?),
        )?;
        let messages = raw
            .chunks_exact(32)
            .map(|chunk| {
                iroha_plonk_gadgets::bytes::element::LeElement::assign(
                    &mut chip.uint(),
                    region,
                    self.value(chunk.try_into().map_err(|_| Error::Synthesis)?),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(ProofMessageCells::from_messages(Vec::new(), length.clone()).is_err());
        ProofMessageCells::from_messages(messages, length)
    }
    fn key(
        self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        key: &VerifyingKey<Ep>,
    ) -> Result<VerifierKeyCells<Ep>, Error> {
        let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *key.transcript_repr() else {
            return Err(Error::Synthesis);
        };
        let fixed = key
            .fixed_commitments()
            .iter()
            .map(|p| self.value(Ep::from(*p)))
            .collect::<Vec<_>>();
        let permutation = key
            .permutation_commitments()
            .iter()
            .map(|p| self.value(Ep::from(*p)))
            .collect::<Vec<_>>();
        chip.witness_key(region, self.value(repr), &fixed, &permutation)
    }
    fn active(
        self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        raw: &[u8],
        capacity: usize,
        segments: &[SegmentSpec],
    ) -> Result<ActiveBytes<Fp>, Error> {
        let values = if self.known {
            Value::known(raw.to_vec())
        } else {
            Value::unknown()
        };
        ActiveBytes::assign(&mut chip.uint(), bytes, region, capacity, &values, segments)
    }
    fn insertion(
        self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        witness: &IndexedInsert<Fp>,
    ) -> Result<InsertCells, Error> {
        let leaf = witness.leaf;
        let values = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let mut paths = Vec::new();
        for (index, siblings) in [
            (witness.leaf_slot, witness.leaf_siblings),
            (witness.slot, witness.slot_siblings),
        ] {
            let index = uint
                .glue()
                .witness(region, self.value(Fp::from(u64::from(index))))?;
            let siblings = uint
                .glue()
                .witnesses(region, &siblings.map(|v| self.value(v)))?
                .try_into()
                .map_err(|_| Error::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells {
                leaf: LeafCells::from_words(values),
                path: low,
            },
            slot,
        })
    }
}
#[derive(Clone)]
struct Continuation {
    plan: SplitPlan,
    proof: Vec<u8>,
    carried: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
struct Stage {
    source: Arc<Source>,
    continuation: Option<Continuation>,
    pallas: AccumulatorT<Ep>,
    fold: Vec<u8>,
    known: bool,
    mutation: Option<ContinuationMutation>,
}
#[derive(Clone, Copy, Debug)]
enum ContinuationMutation {
    Object { slot: usize, word: usize },
    SwapObjects,
    Result(usize),
    Opening,
    Mode,
    IncomingStatement,
    QChunk,
    Q2Verdict,
    CarriedP,
    WPart,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Circuit<Fp> for Stage {
    type Config = Config;
    type Params = usize;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> usize {
        // Only operation-terminal A keys can enter the uniform tagged3 Omega
        // catalog. Internal tagged4 keys are pinned by their exact W wrapper.
        if self
            .continuation
            .as_ref()
            .is_some_and(|c| c.plan.is_terminal())
        {
            3
        } else {
            4
        }
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, 4)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, buses: usize) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, buses).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(69);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let cells = Cells { known: self.known };
        let source = &self.source;
        let stage = self.continuation.as_ref().map_or(0, |c| c.plan.stage());
        let plan = source.plan.context();
        let tasks = plan.operation_tasks(stage).ok_or(Error::Synthesis)?;
        let out = layouter.assign_region(
            || "genuine Receive fixed owner stage",
            |mut region| {
                let (old, pred_public) =
                    cells.state(&mut chip, &mut region, &source.own.witness.before)?;
                let (new, next_public) =
                    cells.state(&mut chip, &mut region, &source.own.witness.after)?;
                let fields = cells.words(&mut chip, &mut region, &source.own.witness.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    source.variant(),
                    &fields,
                )?;
                let mut incoming_fields = source.own.send.statement;
                if matches!(self.mutation, Some(ContinuationMutation::IncomingStatement)) {
                    incoming_fields[17] += Fp::ONE;
                }
                let fields = cells.words(&mut chip, &mut region, &incoming_fields)?;
                let lanes = chip.operation_lanes()?;
                let incoming_statement = IncomingStatementCells::constrain(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let q_instances = source
                    .q
                    .iter()
                    .enumerate()
                    .map(|(q_index, q)| {
                        q.instances
                            .iter()
                            .enumerate()
                            .map(|(column, col)| {
                                col.iter()
                                    .enumerate()
                                    .map(|(index, v)| {
                                        let mut value = *v;
                                        if q_index == 0
                                            && column == 0
                                            && index
                                                == source
                                                    .own
                                                    .sigma_plan
                                                    .chunk_range(1)
                                                    .ok_or(Error::Synthesis)?
                                                    .start
                                            && matches!(
                                                self.mutation,
                                                Some(ContinuationMutation::QChunk)
                                            )
                                        {
                                            value += Fq::ONE;
                                        }
                                        if q_index == 2
                                            && column == 0
                                            && index == 9
                                            && matches!(
                                                self.mutation,
                                                Some(ContinuationMutation::Q2Verdict)
                                            )
                                        {
                                            value = Fq::ONE - value;
                                        }
                                        let ty = *q
                                            .plan
                                            .verifier()
                                            .binding()
                                            .descriptor()
                                            .instance_types
                                            .as_ref()
                                            .and_then(|types| types.get(column))
                                            .ok_or(Error::Synthesis)?;
                                        cells.q_instance(&mut chip, &mut region, value, ty)
                                    })
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let pp = cells.pallas(
                    &mut chip,
                    &mut region,
                    &source.predecessor.pallas.as_input(),
                )?;
                let pv = cells.vesta(&mut chip, &mut region, &source.predecessor.vesta)?;
                let ip = cells.pallas(
                    &mut chip,
                    &mut region,
                    &source.incoming_head.pallas.as_input(),
                )?;
                let iv = cells.vesta(&mut chip, &mut region, &source.incoming_head.vesta)?;
                let original_fields =
                    cells.words(&mut chip, &mut region, &source.incoming_head.state.lineage)?;
                let public_valid = chip.uint().glue().boolean(&mut region, cells.value(true))?;
                let incoming_public = IncomingLineageCells::constrain(
                    &mut chip.uint(),
                    &mut region,
                    &original_fields,
                    &public_valid,
                )?;
                let modes = (0..4)
                    .map(|index| {
                        let values = if index == 0
                            && matches!(self.mutation, Some(ContinuationMutation::Mode))
                        {
                            if source.accept {
                                [Fp::ZERO, Fp::ONE, Fp::ZERO]
                            } else {
                                [Fp::ONE, Fp::ZERO, Fp::ZERO]
                            }
                        } else {
                            source.mode_words(index)
                        };
                        let bits = cells.words(&mut chip, &mut region, &values)?;
                        ModeCells::constrain(chip.uint().glue(), &mut region, &bits)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let trivial = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT)
                    .map_err(|_| Error::Synthesis)?;
                let corrections = [
                    chip.witness_point(&mut region, cells.value(Ep::from(*trivial.g())))?,
                    chip.witness_point(&mut region, cells.value(Ep::from(*trivial.g())))?,
                ];
                let (x, y) =
                    Option::from(source.vesta_correction.coordinates()).ok_or(Error::Synthesis)?;
                let vcorrections = [[
                    cells.scalar(&mut chip, &mut region, x)?,
                    cells.scalar(&mut chip, &mut region, y)?,
                ]];
                let exported = if matches!(self.mutation, Some(ContinuationMutation::Opening)) {
                    trivial.as_input()
                } else {
                    source.incoming_head.opening.clone()
                };
                let opening = cells.pallas(&mut chip, &mut region, &exported)?;
                let mut verdicts = [
                    source.proofs_valid(),
                    source.objects_valid,
                    true,
                    true,
                    true,
                ];
                if let Some(ContinuationMutation::Result(index)) = self.mutation {
                    verdicts[index] = !verdicts[index];
                }
                let results = ReceiveResultClaims::assign(
                    chip.uint().glue(),
                    &mut region,
                    plan.receive_results().ok_or(Error::Synthesis)?,
                    verdicts.map(|v| cells.value(v)),
                )?
                .with_opening(&opening)?;
                let mut proposals = source.commitments.clone();
                match self.mutation {
                    Some(ContinuationMutation::Object { slot, word }) => {
                        proposals[slot][word] += Fp::ONE;
                    }
                    Some(ContinuationMutation::SwapObjects) => proposals.swap(0, 1),
                    _ => {}
                }
                let commitments = proposals
                    .iter()
                    .map(|v| v.map(|v| cells.value(v)))
                    .collect::<Vec<_>>();
                let context =
                    plan.assign_receive_object_claims(&mut chip, &mut region, &commitments)?;
                // Fixed owner predicates derive both selectors from the original
                // Request/Send statement. Reuse the hard Q exports here so this
                // circuit covers every admitted control mask with one schema.
                let own_index = iroha_kagemusha_proof::a_relation::bounded_word(
                    &mut chip,
                    &mut region,
                    &q_instances[0][2][0],
                )?;
                let incoming_index = iroha_kagemusha_proof::a_relation::bounded_word(
                    &mut chip,
                    &mut region,
                    &q_instances[0][2][1],
                )?;
                let own_chunks = source
                    .own
                    .sigma_plan
                    .chunk_range(0)
                    .ok_or(Error::Synthesis)?
                    .map(|i| {
                        iroha_kagemusha_proof::a_relation::bounded_word(
                            &mut chip,
                            &mut region,
                            &q_instances[0][0][i],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let incoming_chunks = source
                    .own
                    .sigma_plan
                    .chunk_range(1)
                    .ok_or(Error::Synthesis)?
                    .map(|i| {
                        iroha_kagemusha_proof::a_relation::bounded_word(
                            &mut chip,
                            &mut region,
                            &q_instances[0][0][i],
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut own_sigma =
                    SigmaBindingCells::from_statement(&statement, own_index.clone(), own_chunks);
                let mut incoming_sigma = SigmaBindingCells::from_incoming(
                    &incoming_statement,
                    incoming_index.clone(),
                    incoming_chunks,
                );
                if tasks.contains(&OperationTask::ReceiveOwnProof) {
                    let raw = frame(&source.own.sigma);
                    let run = bytes.run(
                        &mut region,
                        &cells.bytes(&raw),
                        &chunk_segments(0, raw.len()),
                        &[SegmentSpec::little(0, 4)],
                    )?;
                    own_sigma = SigmaBindingCells::from_run(
                        &mut chip,
                        &mut region,
                        &statement,
                        own_index,
                        &run,
                    )?;
                }
                let needs_transport = tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveObjects | OperationTask::ReceiveProofs
                    )
                });
                let needs_digest = tasks.contains(&OperationTask::ReceiveProofDigest);
                let transport_plan = IncomingTransportPlan::new(plan.operation())?;
                let omega_raw = if needs_transport || needs_digest {
                    let segments = if needs_transport {
                        transport_plan.active_segments()?
                    } else {
                        vec![]
                    };
                    Some(cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.incoming,
                        plan.object_specs()[4].capacity as usize,
                        &segments,
                    )?)
                } else {
                    None
                };
                let sigma_raw = if tasks.contains(&OperationTask::ReceiveObjects) || needs_digest {
                    let segments = if tasks.contains(&OperationTask::ReceiveObjects) {
                        SigmaBindingCells::incoming_segments(
                            source
                                .own
                                .sigma_plan
                                .class(1)
                                .ok_or(Error::Synthesis)?
                                .verifier()
                                .proof_length(),
                        )?
                    } else {
                        vec![]
                    };
                    Some(cells.active(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.own.incoming_sigma,
                        plan.object_specs()[5].capacity as usize,
                        &segments,
                    )?)
                } else {
                    None
                };
                let transport = if needs_transport {
                    Some(transport_plan.decode_active(
                        &mut chip,
                        &mut region,
                        omega_raw.as_ref().ok_or(Error::Synthesis)?,
                        next_public.omega_key_digest(),
                    )?)
                } else {
                    None
                };
                if tasks.contains(&OperationTask::ReceiveObjects) {
                    incoming_sigma = SigmaBindingCells::from_incoming_active(
                        &mut chip,
                        &mut region,
                        &incoming_statement,
                        incoming_index,
                        sigma_raw.as_ref().ok_or(Error::Synthesis)?,
                        source
                            .own
                            .sigma_plan
                            .class(1)
                            .ok_or(Error::Synthesis)?
                            .verifier()
                            .proof_length(),
                    )?;
                }
                let proof_digest = if needs_digest {
                    Some(ReceiveProofDigest::from_active(
                        &mut chip,
                        &mut region,
                        omega_raw.as_ref().ok_or(Error::Synthesis)?,
                        sigma_raw.as_ref().ok_or(Error::Synthesis)?,
                        context[5].authenticated_digest(),
                    )?)
                } else {
                    None
                };
                let values = source.objects.each_ref().map(|raw| cells.bytes(raw));
                let objects = if tasks.contains(&OperationTask::ReceiveObjects) {
                    Some(ReceiveObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        OwnPolicy::new([31, 32], bootstrap_objects::key(23))?,
                        ReceiveObjectSources {
                            request: &values[0],
                            payer: &values[1],
                            receipt: &values[2],
                            payment: &values[3],
                        },
                        ReceiveObjectInputs {
                            own: &statement,
                            receiver: &pred_public,
                            incoming: transport.as_ref().ok_or(Error::Synthesis)?,
                            sigma: &incoming_sigma,
                            consuming_digest: context[4].authenticated_digest(),
                        },
                    )?)
                } else {
                    None
                };
                let signed = if tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveSignatures | OperationTask::ReceiveBlacklist
                    )
                }) {
                    Some(ReceiveSignedObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        [&values[0], &values[1], &values[2]],
                    )?)
                } else {
                    None
                };
                let auth = if tasks.iter().any(|t| {
                    matches!(
                        t,
                        OperationTask::ReceiveAuthorization
                            | OperationTask::ReceiveOwnProof
                            | OperationTask::ReceiveSignatures
                    )
                }) {
                    Some(ReceiveAuthorizationObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        source.variant(),
                        ReceiveAuthorizationSources {
                            current: &values[6],
                            certificate: &values[7],
                            receipt: &values[8],
                            quoted: [&values[9], &values[10]],
                        },
                    )?)
                } else {
                    None
                };
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: Some(&incoming_statement),
                    predecessor: Some(ContextPredecessor {
                        state: &old,
                        public: &pred_public,
                        pallas: &pp,
                        vesta: &pv,
                    }),
                    successor: ContextState {
                        state: &new,
                        public: &next_public,
                    },
                    incoming: Some(ContextIncoming {
                        public: &incoming_public,
                        pallas: &ip,
                        vesta: &iv,
                        proof: ContextIncomingProof::ReceiveActive,
                    }),
                    q_instances: &q_instances,
                    objects: &context,
                    modes: &modes,
                    pallas_corrections: &corrections,
                    vesta_corrections: &vcorrections,
                    receive_results: Some(&results),
                };
                let sigma = [own_sigma.clone(), incoming_sigma.clone()];
                let pred = if stage == 0 {
                    let key = cells.key(&mut chip, &mut region, &source.predecessor.key)?;
                    let proof = cells.proof(&mut chip, &mut region, &source.predecessor.proof)?;
                    Some(verify_predecessor(
                        &mut chip,
                        &mut region,
                        plan.operation(),
                        &key,
                        &pred_public,
                        &next_public,
                        &pp,
                        &pv,
                        &proof,
                    )?)
                } else {
                    None
                };
                let mut verified = Vec::new();
                let mut own_signature = None;
                for index in plan.q_partition(stage).ok_or(Error::Synthesis)? {
                    let proof = cells.proof(&mut chip, &mut region, &source.q[*index].proof)?;
                    let q = verify_q(
                        &mut chip,
                        &mut region,
                        plan.operation(),
                        *index,
                        &q_instances[*index],
                        &proof,
                    )?;
                    if *index == 1 {
                        let slots = iroha_kagemusha_proof::a_relation::bind_signature_q(
                            &mut chip,
                            &mut region,
                            plan.operation(),
                            *index,
                            source
                                .plan
                                .signature_schema(*index)
                                .ok_or(Error::Synthesis)?,
                            &q,
                        )?;
                        own_signature = Some(slots);
                    }
                    verified.push(q);
                }
                let proof_sources = transport
                    .as_ref()
                    .map(|transport| {
                        ReceiveProofSources::from_active_omega(transport, &incoming_sigma)
                    })
                    .transpose()?;
                let proof_key = if tasks.contains(&OperationTask::ReceiveProofs) {
                    Some(cells.key(&mut chip, &mut region, &source.incoming_head.key)?)
                } else {
                    None
                };
                let nonmembership = if tasks.contains(&OperationTask::ReceiveNonmembership) {
                    Some(
                        cells
                            .insertion(&mut chip.uint(), &mut region, &source.own.witness.consumed)?
                            .low,
                    )
                } else {
                    None
                };
                let blacklist = if tasks.contains(&OperationTask::ReceiveBlacklist) {
                    Some(
                        cells
                            .insertion(&mut chip.uint(), &mut region, &source.own.witness.consumed)?
                            .low,
                    )
                } else {
                    None
                };
                let effects = if tasks.iter().any(|task| {
                    matches!(
                        task,
                        OperationTask::ReceiveConsumedEffects | OperationTask::ReceiveCreditEffects
                    )
                }) {
                    let consumed = cells.insertion(
                        &mut chip.uint(),
                        &mut region,
                        &source.own.witness.consumed,
                    )?;
                    let credit = cells.insertion(
                        &mut chip.uint(),
                        &mut region,
                        &source.own.witness.credit,
                    )?;
                    let inserted_key = statement.fields()[17].clone();
                    let inserted_value = chip.hash_words(
                        &mut region,
                        iroha_kagemusha_proof::operation_relation::map_effects::CONSUMED_DOMAIN,
                        &[
                            inserted_key.clone(),
                            statement.fields()[20].clone(),
                            statement.fields()[9].clone(),
                        ],
                    )?;
                    let insert = chip
                        .uint()
                        .glue()
                        .boolean(&mut region, cells.value(source.own.witness.insert))?;
                    Some(ReceiveMapWitness {
                        consumed,
                        credit,
                        inserted_key,
                        inserted_value,
                        insert,
                        payment_digest: context[3].authenticated_digest().clone(),
                    })
                } else {
                    None
                };
                let incoming_signature = if tasks.contains(&OperationTask::ReceiveSignatures) {
                    Some(ReceiveSignatureQProjection::from_context(
                        &mut chip,
                        &mut region,
                        plan,
                        u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                        OwnPolicy::new([31, 32], bootstrap_objects::key(23))?,
                        &input,
                    )?)
                } else {
                    None
                };
                source.plan.constrain_stage(
                    &mut chip,
                    &mut region,
                    u32::try_from(stage).map_err(|_| Error::BoundsFailure)?,
                    ReceiveStageInputs {
                        context: &input,
                        proof_digest: proof_digest.as_ref(),
                        objects: objects.as_ref(),
                        signed: signed.as_ref(),
                        authorization: auth.as_ref(),
                        own_sigma: tasks
                            .contains(&OperationTask::ReceiveOwnProof)
                            .then_some(&own_sigma),
                    },
                    ReceiveStageWitness {
                        proofs: proof_key.as_ref().map(|key| ReceiveProofInputs {
                            sources: proof_sources.as_ref().unwrap(),
                            omega_key: key,
                            own_sigma: &own_sigma,
                        }),
                        own_signatures: own_signature.as_ref(),
                        incoming_signatures: incoming_signature.as_ref(),
                        nonmembership: nonmembership.as_ref(),
                        blacklist: blacklist.as_ref(),
                        effects: effects.as_ref(),
                    },
                )?;
                let fold = cells.proof(&mut chip, &mut region, &self.fold)?;
                if let Some(continuation) = &self.continuation {
                    let carried = if matches!(self.mutation, Some(ContinuationMutation::CarriedP)) {
                        AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap()
                    } else {
                        continuation.carried.clone()
                    };
                    let pallas = cells.pallas(&mut chip, &mut region, &carried.as_input())?;
                    let part = if matches!(self.mutation, Some(ContinuationMutation::WPart)) {
                        AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT)
                            .unwrap()
                    } else {
                        continuation.vesta.clone()
                    };
                    let vesta = cells.vesta(&mut chip, &mut region, &part)?;
                    let proof = cells.proof(&mut chip, &mut region, &continuation.proof)?;
                    let resumed = resume_context(
                        &mut chip,
                        &mut region,
                        &continuation.plan,
                        &input,
                        &pallas,
                        &vesta,
                        &proof,
                        &sigma,
                    )?;
                    let selected = if continuation.plan.is_terminal() {
                        Some(resumed.select_receive_incoming(
                            &mut chip,
                            &mut region,
                            &continuation.plan,
                        )?)
                    } else {
                        None
                    };
                    let closed = close_stage(
                        &mut chip,
                        &mut region,
                        &continuation.plan,
                        &resumed,
                        None,
                        selected.as_ref().map(|v| &v.0),
                        selected.as_ref().map(|v| &v.1),
                        &verified,
                        &fold,
                    )?;
                    if continuation.plan.is_terminal() {
                        closed.words(&mut chip, &mut region, &next_public)
                    } else {
                        closed.continuation()?.words(&mut chip, &mut region)
                    }
                } else {
                    close_first(
                        &mut chip,
                        &mut region,
                        plan,
                        &input,
                        pred.as_ref(),
                        &verified,
                        &sigma,
                        Some(&fold),
                        &source.params,
                    )?
                    .words(&mut chip, &mut region)
                }
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) {
    let (x, y) = claim.g().coordinates().unwrap();
    words.extend([Fp::from(u64::from(claim.source_k())), x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = claim.g().coordinates().unwrap();
    let mut out = Vec::new();
    for v in [x, y] {
        out.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    out.extend(claim.challenges());
    out
}
fn context_digest(source: &Source) -> Fp {
    let mut words = source.plan.context().schema().to_vec();
    words.extend(source.own.witness.statement);
    words.extend(source.own.send.statement);
    let before = &source.own.witness.before;
    let after = &source.own.witness.after;
    words.extend(before.core);
    words.extend(before.rest);
    words.extend(before.lineage);
    push_pallas(&mut words, &source.predecessor.pallas.as_input());
    words.extend(vesta_words(&source.predecessor.vesta.as_input()));
    words.extend(after.core);
    words.extend(after.rest);
    words.extend(after.lineage);
    words.extend(source.incoming_head.state.lineage);
    words.push(Fp::ONE);
    push_pallas(&mut words, &source.incoming_head.pallas.as_input());
    words.extend(vesta_words(&source.incoming_head.vesta.as_input()));
    for q in &source.q {
        for (column, ty) in q.instances.iter().zip(
            q.plan
                .verifier()
                .binding()
                .descriptor()
                .instance_types
                .as_ref()
                .unwrap(),
        ) {
            for value in column {
                if matches!(*ty, InstanceType::Bounded | InstanceType::Bits(0..=253)) {
                    words.push(Fp::from_repr(value.to_repr()).unwrap());
                } else {
                    words.extend(foreign_limbs(value).map(Fp::from_u128));
                }
            }
        }
    }
    words.extend(source.commitments.iter().flatten().copied());
    words.extend([
        Fp::from(u64::from(source.proofs_valid())),
        Fp::from(u64::from(source.objects_valid)),
        Fp::ONE,
        Fp::ONE,
        Fp::ONE,
    ]);
    push_pallas(&mut words, &source.incoming_head.opening);
    for index in 0..4 {
        words.extend(source.mode_words(index));
    }
    let trivial = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
    let (x, y) = trivial.g().coordinates().unwrap();
    words.extend([x, y, x, y]);
    words.extend(source.vesta_correction_words());
    hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words)
}
fn stage_digest(plan: &ContextPlan, stage: usize, base: Fp, current: &AccumulatorT<Ep>) -> Fp {
    assert!(stage + 1 < plan.stage_count());
    let mut words = vec![
        Fp::ONE,
        plan.schema()[1],
        Fp::from(u64::try_from(stage + 1).unwrap()),
        base,
    ];
    push_pallas(&mut words, &current.as_input());
    hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
}
fn internal_public(digest: Fp, part: &FoldInput<Eq>) -> Vec<Vec<Fp>> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part));
    let trivial = AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
    let trivial = vesta_words(&trivial.as_input());
    words.extend(&trivial);
    words.extend(&trivial);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&trivial[..4]);
    assert_eq!(words.len(), 69);
    vec![words]
}
impl Stage {
    fn public(&self) -> Vec<Vec<Fp>> {
        let root = context_digest(&self.source);
        let Some(continuation) = &self.continuation else {
            return internal_public(
                stage_digest(self.source.plan.context(), 0, root, &self.pallas),
                &self.source.own.part,
            );
        };
        if !continuation.plan.is_terminal() {
            let digest = stage_digest(
                self.source.plan.context(),
                continuation.plan.stage(),
                root,
                &self.pallas,
            );
            return internal_public(digest, &continuation.vesta.as_input());
        }
        let mut lineage = self.source.own.witness.after.lineage.to_vec();
        let (x, y) = self.pallas.g().coordinates().unwrap();
        lineage.extend([x, y]);
        for u in self.pallas.challenges() {
            lineage.extend(foreign_limbs(u).map(Fp::from_u128));
        }
        let mut words = vec![
            hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &lineage),
            Fp::from(16),
        ];
        words.extend(vesta_words(&continuation.vesta.as_input()));
        words.extend(vesta_words(&self.source.predecessor.vesta.as_input()));
        // A exports the ORIGINAL incoming V and its mode; Omega performs the
        // mode selection and includes the chosen deciding claim exactly once.
        words.extend(vesta_words(&self.source.incoming_head.vesta.as_input()));
        words.extend(self.source.mode_words(2));
        words.extend(self.source.vesta_correction_words());
        assert_eq!(words.len(), 69);
        vec![words]
    }
}
fn prove_stage(circuit: &Stage) -> (ProvingKey<Eq>, ProverOutput<Eq>, Vec<Vec<Fp>>) {
    let public = circuit.public();
    let stage = circuit.continuation.as_ref().map_or(0, |c| c.plan.stage());
    let (assigned, k) = match synthesize(circuit, 16, Some(&public)) {
        Ok(a) => (a, 16),
        Err(error) => {
            eprintln!(
                "Receive A{} k16 capacity failure {error:?}; diagnostic k18 only",
                stage + 1
            );
            (synthesize(circuit, 18, Some(&public)).unwrap(), 18)
        }
    };
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(
        report.is_satisfied(),
        "stage={} failures={:?}",
        stage + 1,
        &report.failures()[..report.failures().len().min(12)]
    );
    let unknown = synthesize(&circuit.without_witnesses(), k, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    let rows: Vec<_> = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .collect();
    eprintln!(
        "Receive A{} taggedA{} tasks={:?} Q={:?} lanes={rows:?} k16_fit={}",
        stage + 1,
        circuit.params(),
        circuit.source.plan.context().operation_tasks(stage),
        circuit.source.plan.context().q_partition(stage),
        k == 16
    );
    assert_eq!(k, 16, "Receive stage must fit unchanged k16 gate");
    drop(assigned);
    drop(unknown);
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let params = common::vesta_params(16);
    let key = keygen_pk_v2(&params, circuit, &config).unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, &public).unwrap(),
        common::recovery(200 + u8::try_from(stage).unwrap()),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    verify_full(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    (key, proof, public)
}

fn assert_continuation_rejects(circuit: &Stage, mutation: ContinuationMutation) {
    let hostile = Stage {
        mutation: Some(mutation),
        ..circuit.clone()
    };
    if let Ok(assigned) = synthesize(&hostile, 16, Some(&circuit.public())) {
        let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
        assert!(
            !report.is_satisfied(),
            "authenticated W continuation accepted {mutation:?}"
        );
    }
}

fn assert_foreign_wrapper_rejects(circuit: &Stage, previous_wrapper: &[u8]) {
    let mut hostile = circuit.clone();
    assert_eq!(
        hostile.continuation.as_ref().unwrap().proof.len(),
        previous_wrapper.len(),
        "foreign W mutation must preserve the admitted message schedule"
    );
    hostile.continuation.as_mut().unwrap().proof = previous_wrapper.to_vec();
    if let Ok(assigned) = synthesize(&hostile, 16, Some(&circuit.public())) {
        let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
        assert!(
            !report.is_satisfied(),
            "continuation accepted a real W proof under another preceding-stage key"
        );
    }
}
#[test]
#[ignore = "real receiver Bootstrap, both sigmas, three Qs and ten fixed A/W stages; run optimized"]
fn genuine_receive_burn_owner_chain_preserves_all_proofs_and_result_claims() {
    receive_owner_chain(IngestionCapacity::Descriptor);
}

#[test]
#[ignore = "real compact predecessor and every Receive owner at fixed maximum external capacities; run optimized"]
fn canonical_envelope_receive_burn_owner_chain() {
    receive_owner_chain(IngestionCapacity::CanonicalEnvelope);
}

#[test]
#[ignore = "current genuine Bootstrap, invalid original sigma, full10A9W and strict original-import/custody replay"]
fn bootstrap_only_invalid_sigma_burn_imports_all_native_sources_and_checkpoints() {
    let receiver = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap_with_identity(
        bootstrap_outer::bootstrap_chain::BootstrapIdentity::Receiver,
    );
    let source = source_with_correction(
        receiver.into(),
        None,
        IngestionCapacity::CanonicalEnvelope,
        Variant::Receive,
        Some(false),
        None,
        false,
    );
    let _ = prove_bootstrap_invalid_sigma_source(source);
    eprintln!(
        "BOOTSTRAP_ONLY_INVALID_SIGMA_RECEIVE full10A9W=true incoming_Q_soft_false=true exact_resigned_originals=true all_modes_Trivial=true consumed_root_unchanged=true adjusted_spendable_balance_zero=true no_Load_trust=true strict_original_import_and_canonical_custody_all19=true terminal_omega=false"
    );
}

fn prove_bootstrap_invalid_sigma_source(source: Source) -> AuthenticatedReceive {
    assert!(!source.accept && !source.objects_valid && !source.proofs_valid());
    assert!(!source.own.witness.insert);
    assert_eq!(
        source.own.instances[3],
        [Fq::ONE, Fq::ZERO, Fq::ZERO, Fq::ONE, Fq::ZERO]
    );
    for index in 0..4 {
        assert_eq!(source.mode(index), IncomingMode::Trivial);
    }
    let before = &source.own.witness.before;
    let after = &source.own.witness.after;
    assert_eq!(before.core[8], Fp::ZERO);
    assert_eq!(before.lineage[14], Fp::ZERO);
    assert_eq!(after.core[8] - after.lineage[14], Fp::ZERO);
    assert_eq!(after.core[16], before.core[16]);
    assert_ne!(after.lineage[16], before.lineage[16]);
    prove_receive_owner_chain(source)
        .expect("complete native Receive terminal and canonical custody")
}

#[test]
#[ignore = "real full-envelope Receive burn with authenticated consumed-credit insertion"]
fn canonical_envelope_receive_burn_inserts_consumed_credit() {
    let receiver = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap_with_identity(
        bootstrap_outer::bootstrap_chain::BootstrapIdentity::Receiver,
    );
    let source = source_variant(
        receiver.into(),
        None,
        IngestionCapacity::CanonicalEnvelope,
        Variant::Receive,
        Some(true),
    );
    assert!(source.own.witness.insert);
    assert_ne!(
        source.own.witness.before.core[16],
        source.own.witness.after.core[16]
    );
    assert_eq!(
        source.own.witness.after.lineage[14] - source.own.witness.before.lineage[14],
        source.own.witness.statement[20]
    );
    let _ = prove_receive_owner_chain(source);
}

#[test]
#[ignore = "real renewed Receive soft3V1F Q and every owner at fixed maximum incoming capacities"]
fn canonical_envelope_receive_renewed_burn_owner_chain() {
    let receiver = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap_with_identity(
        bootstrap_outer::bootstrap_chain::BootstrapIdentity::Receiver,
    );
    let _ = prove_receive_owner_chain(source_variant(
        receiver.into(),
        None,
        IngestionCapacity::CanonicalEnvelope,
        Variant::ReceiveRenewed,
        None,
    ));
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn canonical_envelope_receive_accepts_exact_payer_and_receiver_heads(
    fixture: &compact_catalog::LoadFixture,
) {
    let wallets = compact_catalog::compact_payer_load_and_receiver(fixture);
    let (receiver, payer) = shared_wallet_heads(&wallets);
    let source = source(receiver, Some(payer), IngestionCapacity::CanonicalEnvelope);
    assert_exact_payer_source(&source);
    assert_eq!(
        source.own.witness.after.lineage[14], source.own.witness.before.lineage[14],
        "accepted value never enters the burn accumulator"
    );
    let _ = prove_receive_owner_chain(source);
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Shared builder; some component harnesses select other branches.
pub fn canonical_envelope_receive_renewed_accepts_exact_payer_and_receiver_heads(
    fixture: &compact_catalog::LoadFixture,
) {
    let wallets = compact_catalog::compact_payer_load_and_receiver(fixture);
    let (receiver, payer) = shared_wallet_heads(&wallets);
    let source = source_variant(
        receiver,
        Some(payer),
        IngestionCapacity::CanonicalEnvelope,
        Variant::ReceiveRenewed,
        None,
    );
    assert_exact_payer_source(&source);
    assert_eq!(
        source.own.witness.after.lineage[14], source.own.witness.before.lineage[14],
        "renewed accepted value never enters the burn accumulator"
    );
    let _ = prove_receive_owner_chain(source);
}

fn shared_wallet_heads(wallets: &compact_catalog::SharedKeyWallets) -> (Head, Head) {
    let receiver = Head {
        state: StateWitness::from(&wallets.receiver.source.state),
        key: wallets.receiver.key.clone(),
        binding: wallets.receiver.binding.clone(),
        proof: wallets.receiver.proof.clone(),
        pallas: wallets.receiver.source.pallas.clone(),
        vesta: wallets.receiver.vesta.clone(),
        opening: wallets.receiver.opening.clone(),
    };
    let payer = Head {
        state: wallets.payer.source.state,
        key: wallets.payer.key.clone(),
        binding: wallets.payer.binding.clone(),
        proof: wallets.payer.proof.clone(),
        pallas: wallets.payer.source.pallas.clone(),
        vesta: wallets.payer.vesta.clone(),
        opening: wallets.payer.opening.clone(),
    };
    assert_ne!(receiver.state.core[5..7], payer.state.core[5..7]);
    (receiver, payer)
}
fn assert_exact_payer_source(source: &Source) {
    assert_eq!(source.own.send.before.core, source.incoming_head.state.core);
    assert_eq!(source.own.send.before.rest, source.incoming_head.state.rest);
    assert_eq!(
        source.own.send.before.lineage,
        source.incoming_head.state.lineage
    );
    assert_eq!(
        source.own.witness.after.core[iroha_kagemusha_proof::witness::core_index::BALANCE]
            - source.own.witness.before.core[iroha_kagemusha_proof::witness::core_index::BALANCE],
        source.own.witness.statement[20],
    );
}

/// Run the retained composition assertions with genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn genuine_omega_can_carry_a_succinct_but_nondeciding_vesta_claim(
    fixture: &compact_catalog::LoadFixture,
) {
    let (wallets, correction) =
        compact_catalog::compact_payer_load_and_receiver_with_bad_vesta(fixture);
    let (receiver, payer) = shared_wallet_heads(&wallets);
    assert_eq!(receiver.key.to_bytes(), payer.key.to_bytes());
    assert_eq!(payer.proof.len(), 3712);
    let params = common::vesta_params(16);
    assert!(payer.vesta.decide(&params, MemoryBudget::DEFAULT).is_err());
    assert_ne!(*payer.vesta.g(), correction);
    let corrected =
        FoldInput::<Eq>::from_normalized(correction, 16, *payer.vesta.challenges()).unwrap();
    corrected.decide(&params, MemoryBudget::DEFAULT).unwrap();
    eprintln!(
        "GENUINE_NONDECIDING_VESTA_OMEGA actual_proof=3712 original_V_fails_decide=true distinct_same_challenges_correction_decides=true explicit_native_Load_originals=true full_Receive=false"
    );
}

/// Run the corrected-claim assertions using explicit genuine native Load originals.
#[allow(dead_code)] // Registered by receive_omega; other consumers select shared helpers only.
pub fn canonical_envelope_receive_corrected_vesta_burn_inserts_credit(
    fixture: &compact_catalog::LoadFixture,
) {
    receive_corrected_vesta_chain(true, fixture);
}
/// Run the corrected-claim assertions using explicit genuine native Load originals.
#[allow(dead_code)] // Shared builder; some component harnesses select other branches.
pub fn canonical_envelope_receive_corrected_vesta_burn_without_consumed_insert(
    fixture: &compact_catalog::LoadFixture,
) {
    receive_corrected_vesta_chain(false, fixture);
}
fn receive_corrected_vesta_chain(insert: bool, fixture: &compact_catalog::LoadFixture) {
    let (wallets, correction) =
        compact_catalog::compact_payer_load_and_receiver_with_bad_vesta(fixture);
    let (receiver, payer) = shared_wallet_heads(&wallets);
    assert!(
        payer
            .vesta
            .decide(&common::vesta_params(16), MemoryBudget::DEFAULT)
            .is_err()
    );
    let source = source_with_correction(
        receiver,
        Some(payer),
        IngestionCapacity::CanonicalEnvelope,
        Variant::Receive,
        Some(insert),
        Some(correction),
        true,
    );
    assert_exact_payer_source(&source);
    assert!(source.objects_valid && !source.accept);
    assert_eq!(source.mode(2), IncomingMode::Corrected);
    assert_eq!(
        source.own.witness.after.lineage[14] - source.own.witness.before.lineage[14],
        source.own.witness.statement[20]
    );
    assert_eq!(source.own.witness.insert, insert);
    let _ = prove_receive_owner_chain(source);
}

fn receive_owner_chain(capacity: IngestionCapacity) {
    let receiver = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap_with_identity(
        bootstrap_outer::bootstrap_chain::BootstrapIdentity::Receiver,
    );
    let _ = prove_receive_owner_chain(source(receiver.into(), None, capacity));
}

/// Check every fixed owner shape before expensive proof production. Unknown
/// advice removes no rows: the genuine proof loop separately checks parity and
/// soundness with the actual authenticated W/source witnesses.
fn preflight_owner_shapes(source: &Arc<Source>) {
    let pallas = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
    let vparams = common::vesta_params(16);
    let vesta = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
    let (first_fold, _) = create_fold(
        &source.params,
        &[pallas.as_input(), pallas.as_input()],
        Fp::from(901).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let mut stage = Stage {
        source: source.clone(),
        continuation: None,
        pallas: pallas.clone(),

        fold: first_fold.to_bytes().to_vec(),
        known: false,
        mutation: None,
    };
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let mut wrapper_template = None;
    let mut overflow = Vec::new();
    for index in 0..source.plan.context().stage_count() {
        let assigned = synthesize(&stage, 18, None).unwrap();
        let rows = assigned
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
            .collect::<Vec<_>>();
        eprintln!(
            "RECEIVE_SHAPE_PREFLIGHT A{} tagged{} rows={rows:?} actual_proof=false",
            index + 1,
            stage.params()
        );
        if rows.iter().any(|n| *n >= 65_529) {
            overflow.push((index + 1, *rows.iter().max().unwrap()));
        }
        drop(assigned);
        if index + 1 == source.plan.context().stage_count() {
            break;
        }
        // Only sizing: all internal A descriptors are identical, and changing
        // the fixed W stage/key constants does not change its verifier shape.
        // Reusing one same-descriptor key here permits measuring every owner,
        // even after an earlier owner overflows. These imported diagnostic keys
        // are never proved, restored or admitted; the actual chain below keys
        // and verifies every exact stage independently.
        let (binding, key, wrapper_length) = wrapper_template.get_or_insert_with(|| {
            let key = keygen_pk_v2(&vparams, &stage, &config).unwrap();
            let proof_length = VerifierPlan::new(key.binding().clone(), vparams.clone())
                .unwrap()
                .proof_length();
            let (fold, _) = create_fold(
                &vparams,
                &[
                    vesta.as_input(),
                    vesta.as_input(),
                    vesta.as_input(),
                    vesta.as_input(),
                ],
                Fq::from(902).to_repr(),
                &FoldConfig::default(),
            )
            .unwrap();
            let wrapper = WCircuit::new(
                source.plan.context(),
                index,
                key.binding().clone(),
                vparams.clone(),
                vec![key.vk().kagemusha_digest(key.binding()).unwrap()],
                iroha_kagemusha_proof::omega::OmegaWitness {
                    key: key.vk().clone(),
                    instances: stage.public()[0].clone(),
                    length: u32::try_from(proof_length).unwrap(),
                    proof: vec![0; proof_length],
                    fold: fold.to_bytes(),
                },
            )
            .unwrap()
            .without_witnesses();
            let (wkey, wprover) = WKey::keygen(&wrapper, &source.params).unwrap();
            (
                wprover.binding().clone(),
                wkey.verifying_key().clone(),
                wkey.verifier().proof_length(),
            )
        });
        let wkey = WKey::from_artifact(
            source.plan.context(),
            index,
            binding.clone(),
            source.params.clone(),
            key.clone(),
        )
        .unwrap();
        let wrapper_length = *wrapper_length;
        let split = SplitPlan::new(
            source.plan.context().clone(),
            index + 1,
            wkey,
            &source.params,
        )
        .unwrap();
        let count = 2
            + if split.is_terminal() { 2 } else { 0 }
            + source.plan.context().q_partition(index + 1).unwrap().len();
        let (fold, _) = create_fold(
            &source.params,
            &vec![pallas.as_input(); count],
            Fp::from(903).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        stage = Stage {
            source: source.clone(),
            continuation: Some(Continuation {
                plan: split,
                proof: vec![0; wrapper_length],
                carried: pallas.clone(),
                vesta: vesta.clone(),
            }),
            pallas: pallas.clone(),

            fold: fold.to_bytes().to_vec(),
            known: false,
            mutation: None,
        };
    }
    assert!(
        overflow.is_empty(),
        "Receive fixed owners exceed k16: {overflow:?}"
    );
}

fn native_inputs(
    source: &Source,
) -> (
    iroha_kagemusha_proof::a_relation::native::receive::Plan,
    iroha_kagemusha_proof::a_relation::native::receive::Inputs,
) {
    use iroha_kagemusha_proof::a_relation::native::receive as native;
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    let plan = native::Plan::new(
        source.plan.context().operation().clone(),
        policy,
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    assert_eq!(plan.context().schema(), source.plan.context().schema());
    let trivial_p = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
    let inputs = native::Inputs {
        transition: native::Transition {
            before: source.own.witness.before,
            after: source.own.witness.after,
            statement: source.own.witness.statement,
            consumed: source.own.witness.consumed,
            credit: source.own.witness.credit,
            blacklist: source.own.witness.consumed,
            insert: source.own.witness.insert,
        },
        incoming_statement: source.own.send.statement,
        sigma: source.own.sigma.clone(),
        objects: source.objects.clone(),
        q: core::array::from_fn(|i| native::QInput {
            proof: source.q[i].proof.clone(),
            instances: source.q[i].instances.clone(),
        }),
        predecessor: native::PredecessorInput {
            proof: source.predecessor.proof.clone(),
            pallas: source.predecessor.pallas.to_bytes(),
            vesta: source.predecessor.vesta.to_bytes(),
        },
        incoming: native::IncomingWitness {
            public: source.incoming_head.state.lineage,
            public_valid: true,
            pallas: source.incoming_head.pallas.clone(),
            vesta: source.incoming_head.vesta.clone(),
            opening: source.incoming_head.opening.clone(),
            results: [
                source.proofs_valid(),
                source.objects_valid,
                true,
                true,
                true,
            ],
            modes: core::array::from_fn(|i| source.mode(i)),
            pallas_corrections: [*trivial_p.g(); 2],
            vesta_correction: source.vesta_correction,
        },
    };
    (plan, inputs)
}

fn assert_native_first_relation(source: &Source, first: &Stage) {
    let (plan, inputs) = native_inputs(source);
    let signature_inputs = inputs.q[2].instances[0]
        .chunks_exact(10)
        .map(|slot| {
            let integer = |lo: Fq, hi: Fq| {
                let mut bytes = [0u8; 32];
                bytes[..16].copy_from_slice(&lo.to_repr()[..16]);
                bytes[16..].copy_from_slice(&hi.to_repr()[..16]);
                core::array::from_fn(|i| {
                    u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap())
                })
            };
            iroha_kagemusha_proof::q_signature::SignatureWitness {
                digest: Option::<Fp>::from(Fp::from_repr(slot[0].to_repr())).unwrap(),
                key: [integer(slot[1], slot[2]), integer(slot[3], slot[4])],
                signature: [integer(slot[5], slot[6]), integer(slot[7], slot[8])],
            }
        })
        .collect();
    let predicate_inputs = iroha_kagemusha_proof::a_relation::native::receive::PredicateInputs {
        before: inputs.transition.before,
        after: inputs.transition.after,
        statement: inputs.transition.statement,
        consumed: inputs.transition.consumed,
        blacklist: inputs.transition.blacklist,
        incoming_statement: inputs.incoming_statement,
        objects: inputs.objects.clone(),
        signatures: signature_inputs,
        predecessor_pallas: AccumulatorT::from_bytes(&inputs.predecessor.pallas).unwrap(),
        predecessor_vesta: AccumulatorT::from_bytes(&inputs.predecessor.vesta).unwrap(),
        own_selector: inputs.q[0].instances[2][0].to_repr()[0],
        incoming_selector: inputs.q[0].instances[2][1].to_repr()[0],
    };
    let proposed = plan.propose_nonproof(predicate_inputs.clone()).unwrap();
    assert_eq!(proposed, [source.objects_valid, true, true, true]);
    let mut substituted = predicate_inputs.clone();
    substituted.objects[3][131] ^= 1;
    assert!(
        plan.propose_nonproof(substituted).is_err(),
        "changed transitive Payment package binding"
    );
    eprintln!(
        "NATIVE_RECEIVE_PREDICATES same_object_signature_map_code=true native_four_results={proposed:?} no_synthetic_Q=true"
    );
    let prepared = plan.prepare(inputs, MemoryBudget::DEFAULT).unwrap();
    let (native, public) = prepared
        .first_circuit(Fp::from(247), &FoldConfig::default())
        .unwrap();
    assert_eq!(public, first.public()[0]);
    let actual = synthesize(first, 16, Some(&first.public())).unwrap();
    let native = synthesize(&native, 16, Some(&[public])).unwrap();
    assert_eq!(actual.tables.fixed(), native.tables.fixed());
    assert_eq!(actual.tables.permutation(), native.tables.permutation());
    assert_eq!(
        actual.tables.advice_assigned(),
        native.tables.advice_assigned()
    );
    assert!(
        check(&native.cs, &native.tables, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    eprintln!(
        "NATIVE_RECEIVE_A1_PARITY exact_context=true fixed_permutation_advice_layout_equal=true native_constraint_check=true final_catalog=false"
    );
}

/// Retained native restore evidence contains verifier metadata only. Each native
/// parity check reconstructs and releases one stage PK; no full PK catalog is held.
/// These component checks remain separate from mobile or M3 memory qualification.
#[derive(Default)]
struct NativeCheckpoints {
    a: Vec<iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<Eq>>,
    w: Vec<iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<Ep>>,
    a_proofs: Vec<Vec<u8>>,
    w_proofs: Vec<Vec<u8>>,
    pallas: Vec<[u8; 544]>,
    vesta: Vec<[u8; 544]>,
}
impl NativeCheckpoints {
    fn check(
        self,
        source: &Source,
        terminal_public: &[Fp],
    ) -> iroha_kagemusha_proof::a_relation::native::receive::Terminal {
        use iroha_kagemusha_proof::a_relation::native::receive as native;
        let (plan, inputs) = native_inputs(source);
        let a: [_; native::A_STAGE_COUNT] = self.a.try_into().ok().unwrap();
        let w: [_; native::A_STAGE_COUNT - 1] = self.w.try_into().ok().unwrap();
        let parity_keys = a.clone();
        native_source_factory_checks::assert_factories(
            plan.context(),
            &PinnedParams::<Ep>::derive(16).unwrap(),
            &common::vesta_params(16),
            &a,
            &w,
            |stage, previous| plan.source_circuit(stage, previous),
            |stage, binding, key| plan.wrapper_source(stage, binding, key),
        );
        let prover = native::Prover::from_artifacts(plan.clone(), a, w).unwrap();
        for object in 6..9 {
            for offset in [0, inputs.objects[object].len() - 1] {
                let mut bad = inputs.clone();
                bad.objects[object][offset] ^= 1;
                assert!(
                    plan.prepare(bad, MemoryBudget::DEFAULT).is_err(),
                    "own tape {object}/{offset}"
                );
            }
        }
        let mut bad = inputs.clone();
        bad.sigma[0] ^= 1;
        assert!(
            plan.prepare(bad, MemoryBudget::DEFAULT).is_err(),
            "own sigma differs from Q0"
        );
        let prepared = plan.prepare(inputs.clone(), MemoryBudget::DEFAULT).unwrap();
        let (first_circuit, _) = prepared
            .first_circuit(Fp::from(247), &FoldConfig::default())
            .unwrap();
        // Validate the actual known source against the metadata-only unknown
        // factory before any subsequent one-stage native proving call.
        drop(import_native_a(&prover, 0, &first_circuit, &parity_keys[0]));
        drop((prepared, first_circuit));
        let session = prover
            .prepare(inputs.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(prover.descriptors().len(), 2 * native::A_STAGE_COUNT - 1);
        let layouts = prover.checkpoint_layouts().unwrap();
        assert_eq!(layouts.len(), prover.descriptors().len());
        for (layout, descriptor) in layouts.iter().zip(prover.descriptors()) {
            assert_eq!(layout.descriptor_digest(), descriptor.digest());
        }
        let mut checkpoint = session
            .restore_first(
                self.a_proofs[0].clone(),
                &self.pallas[0],
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert_eq!(checkpoint.stage(), 0);
        let first_original = session
            .encode_a_checkpoint(&checkpoint, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(first_original.len(), layouts[0].payload_bytes());
        checkpoint = session
            .restore_first_checkpoint(&first_original, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(checkpoint.proof(), self.a_proofs[0]);
        assert_eq!(checkpoint.pallas_bytes(), self.pallas[0]);
        assert_eq!(
            session
                .encode_a_checkpoint(&checkpoint, MemoryBudget::DEFAULT)
                .unwrap(),
            first_original,
            "restoration must retain the canonical original checkpoint bytes"
        );
        let mut extra = first_original.clone();
        extra.push(0);
        for original in [&first_original[..first_original.len() - 1], &extra] {
            assert!(
                session
                    .restore_first_checkpoint(original, MemoryBudget::DEFAULT)
                    .is_err(),
                "checkpoint framing must reject truncation and trailing bytes"
            );
        }
        assert!(
            session
                .terminal(&checkpoint, MemoryBudget::DEFAULT)
                .is_err()
        );
        let mut truncated = self.a_proofs[0].clone();
        truncated.pop();
        assert!(
            session
                .restore_first(truncated, &self.pallas[0], MemoryBudget::DEFAULT)
                .is_err()
        );
        // Even identical inputs belong to a distinct checked session. Opaque
        // checkpoints cannot be mixed across preparation/custody handles.
        let foreign = prover
            .prepare(inputs.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        assert!(
            foreign
                .restore_wrapper(
                    &checkpoint,
                    self.w_proofs[0].clone(),
                    &self.vesta[0],
                    MemoryBudget::DEFAULT
                )
                .is_err()
        );
        let mut changed = inputs.clone();
        changed.objects[3][0] ^= 1;
        if let Ok(rebound) = prover.prepare(changed, MemoryBudget::DEFAULT) {
            assert!(
                rebound
                    .restore_first(
                        self.a_proofs[0].clone(),
                        &self.pallas[0],
                        MemoryBudget::DEFAULT
                    )
                    .is_err(),
                "changed original Payment cannot restore original A1"
            );
            assert!(
                rebound
                    .restore_first_checkpoint(&first_original, MemoryBudget::DEFAULT)
                    .is_err(),
                "canonical custody cannot rebind the original Payment"
            );
        }
        // Restart has no surviving opaque checkpoint capability. Recreate a
        // checked session from retained originals and recover the entire chain
        // through canonical bytes under that new session's source identity.
        let session = prover.prepare(inputs, MemoryBudget::DEFAULT).unwrap();
        checkpoint = session
            .restore_first_checkpoint(&first_original, MemoryBudget::DEFAULT)
            .unwrap();
        for stage in 0..native::A_STAGE_COUNT - 1 {
            check_native_w_import(&prover, &plan, stage, &parity_keys[stage]);
            let wrapper = session
                .restore_wrapper(
                    &checkpoint,
                    self.w_proofs[stage].clone(),
                    &self.vesta[stage],
                    MemoryBudget::DEFAULT,
                )
                .unwrap();
            let wrapper_original = session
                .encode_wrapper_checkpoint(&wrapper, MemoryBudget::DEFAULT)
                .unwrap();
            assert_eq!(
                wrapper_original.len(),
                layouts[2 * stage + 1].payload_bytes()
            );
            let wrapper = session
                .restore_wrapper_checkpoint(&checkpoint, &wrapper_original, MemoryBudget::DEFAULT)
                .unwrap();
            assert_eq!(
                session
                    .encode_wrapper_checkpoint(&wrapper, MemoryBudget::DEFAULT)
                    .unwrap(),
                wrapper_original
            );
            assert!(
                session
                    .restore_wrapper_checkpoint(&checkpoint, &first_original, MemoryBudget::DEFAULT)
                    .is_err(),
                "A custody bytes cannot select a W stage"
            );
            assert_eq!(wrapper.stage(), stage);
            assert_eq!(wrapper.proof(), self.w_proofs[stage]);
            assert_eq!(wrapper.vesta_bytes(), self.vesta[stage]);
            let (native_circuit, native_public) = session
                .next_circuit(
                    &wrapper,
                    Fp::from(262 + u64::try_from(stage).unwrap()),
                    &FoldConfig::default(),
                )
                .unwrap();
            // Reconstruct only this native stage PK and compare its exact VK
            // commitments with the independent A proof's installed metadata.
            // This checks fixed/permutation commitments without retaining ten PKs.
            let native_seal =
                import_native_a(&prover, stage + 1, &native_circuit, &parity_keys[stage + 1]);
            let native_key = prover.bind_a(stage + 1, &native_seal, None).unwrap();
            assert_eq!(native_key.binding(), parity_keys[stage + 1].binding());
            assert_eq!(
                native_key.verifying_key().to_bytes(),
                parity_keys[stage + 1].key().to_bytes()
            );
            if stage == 0 {
                assert!(
                    matches!(
                        session.first(
                            &native_key,
                            Fp::from(247),
                            &FoldConfig::default(),
                            common::recovery(200),
                            ProverConfig::default(),
                        ),
                        Err(native::Error::Artifact)
                    ),
                    "same descriptor but wrong stage VK must reject before proving"
                );
                let reproved = session
                    .advance(
                        &native_key,
                        &wrapper,
                        Fp::from(262),
                        &FoldConfig::default(),
                        common::recovery(201),
                        ProverConfig::default(),
                    )
                    .unwrap();
                assert_eq!(
                    reproved.proof(),
                    self.a_proofs[1],
                    "metadata-rebuilt native stage key preserves exact deterministic proof bytes"
                );
            }
            drop(native_seal);
            let native_tables = synthesize(
                &native_circuit,
                16,
                Some(std::slice::from_ref(&native_public)),
            )
            .unwrap();
            let report =
                check(&native_tables.cs, &native_tables.tables, CheckMode::Strict).unwrap();
            assert!(
                report.is_satisfied(),
                "native A{}: {:?}",
                stage + 2,
                report.failures().first()
            );
            drop(native_tables);
            if stage == 0 {
                let mut truncated = self.w_proofs[0].clone();
                truncated.pop();
                assert!(
                    session
                        .restore_wrapper(
                            &checkpoint,
                            truncated,
                            &self.vesta[0],
                            MemoryBudget::DEFAULT
                        )
                        .is_err()
                );
                assert!(
                    session
                        .restore_wrapper(
                            &checkpoint,
                            self.w_proofs[1].clone(),
                            &self.vesta[1],
                            MemoryBudget::DEFAULT
                        )
                        .is_err(),
                    "cannot skip the fixed W owner"
                );
                assert!(
                    session
                        .restore_a(
                            &wrapper,
                            self.a_proofs[2].clone(),
                            &self.pallas[2],
                            MemoryBudget::DEFAULT
                        )
                        .is_err(),
                    "cannot drop an A checkpoint"
                );
            }
            let next = session
                .restore_a(
                    &wrapper,
                    self.a_proofs[stage + 1].clone(),
                    &self.pallas[stage + 1],
                    MemoryBudget::DEFAULT,
                )
                .unwrap();
            let next_original = session
                .encode_a_checkpoint(&next, MemoryBudget::DEFAULT)
                .unwrap();
            assert_eq!(next_original.len(), layouts[2 * stage + 2].payload_bytes());
            checkpoint = session
                .restore_a_checkpoint(&wrapper, &next_original, MemoryBudget::DEFAULT)
                .unwrap();
            assert_eq!(
                session
                    .encode_a_checkpoint(&checkpoint, MemoryBudget::DEFAULT)
                    .unwrap(),
                next_original
            );
            assert!(
                session
                    .restore_a_checkpoint(&wrapper, &first_original, MemoryBudget::DEFAULT)
                    .is_err(),
                "custody cannot replay A1 as a later A"
            );
            assert_eq!(checkpoint.stage(), stage + 1);
            assert_eq!(checkpoint.proof(), self.a_proofs[stage + 1]);
            assert_eq!(checkpoint.pallas_bytes(), self.pallas[stage + 1]);
            assert_eq!(checkpoint.instances(), native_public);
        }
        assert_eq!(checkpoint.instances(), terminal_public);
        let terminal = session
            .terminal(&checkpoint, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(terminal.proof, *self.a_proofs.last().unwrap());
        assert_eq!(terminal.pallas.to_bytes(), *self.pallas.last().unwrap());
        assert_eq!(terminal.incoming_vesta, source.incoming_head.vesta);
        assert_eq!(terminal.predecessor_vesta, source.predecessor.vesta);
        eprintln!(
            "NATIVE_RECEIVE_RESTORE all10A_all9W=true all_native_A_verifier_commitments_and_constraints_equal=true strict_original_import_all19=true native_producer_retains_no_PK=true rebuilt_PK_proof_bytes_equal=true canonical_custody_all19_exact_bytes=true fresh_session_from_originals=true wrong_stage_truncated_foreign_session_original_substitution_rejected=true terminal_exports_equal=true final_catalog=false"
        );
        terminal
    }
}

fn import_native_a(
    prover: &iroha_kagemusha_proof::a_relation::native::receive::Prover,
    stage: usize,
    source: &iroha_kagemusha_proof::a_relation::native::receive::StageCircuit,
    expected: &iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<Eq>,
) -> iroha_plonk::keys::SourceAdmissionSealV2<Eq> {
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let key = keygen_pk_v2(&common::vesta_params(16), source, &config).unwrap();
    assert_eq!(key.binding(), expected.binding());
    assert_eq!(key.vk().to_bytes(), expected.key().to_bytes());
    let original = key.artifact_bytes_v2().unwrap();
    drop(key);
    let read = iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    assert!(
        prover
            .import_a(stage, &original[..original.len() - 1], read)
            .is_err()
    );
    let imported_seal = prover.import_a(stage, &original, read).unwrap();
    let imported = prover.bind_a(stage, &imported_seal, None).unwrap();
    assert_eq!(
        imported.verifying_key().to_bytes(),
        expected.key().to_bytes()
    );
    imported_seal
}

fn check_native_w_import(
    prover: &iroha_kagemusha_proof::a_relation::native::receive::Prover,
    plan: &iroha_kagemusha_proof::a_relation::native::receive::Plan,
    stage: usize,
    source_a: &iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<Eq>,
) {
    let length = iroha_plonk::Protocol::new(source_a.binding().descriptor())
        .unwrap()
        .proof_length();
    let source = WCircuit::new(
        plan.context(),
        stage,
        source_a.binding().clone(),
        common::vesta_params(16),
        vec![source_a.key().kagemusha_digest(source_a.binding()).unwrap()],
        iroha_kagemusha_proof::omega::OmegaWitness {
            key: source_a.key().clone(),
            instances: vec![Fp::ZERO; 69],
            proof: vec![0; length],
            length: u32::try_from(length).unwrap(),
            fold: [0; 1120],
        },
    )
    .unwrap()
    .without_witnesses();
    let mut config =
        KeygenConfigV2::pipa_r(iroha_kagemusha_proof::omega::OmegaPlan::instance_types().to_vec());
    config.compress_selectors = false;
    let key = keygen_pk_v2(&PinnedParams::<Ep>::derive(16).unwrap(), &source, &config).unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let expected = key.vk().to_bytes().to_vec();
    drop(key);
    let read = iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    assert!(
        prover
            .import_w(stage, &original[..original.len() - 1], read)
            .is_err()
    );
    let imported_seal = prover.import_w(stage, &original, read).unwrap();
    let imported = prover.bind_w(stage, &imported_seal, None).unwrap();
    assert_eq!(imported.verifying_key().to_bytes(), expected);
}

/// Complete genuine Receive terminal after all source owners and native restores.
/// It is an input to a separately authenticated outer program, not an admitted head.
#[allow(
    dead_code,
    reason = "shared exact-source export for Receive Omega and ArchiveStatus consumers"
)]
pub(crate) struct AuthenticatedReceive {
    /// Exact native terminal descriptor.
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    /// Exact measured terminal key.
    pub(crate) key: VerifyingKey<Eq>,
    /// Fully restored original terminal proof and every carried obligation.
    pub(crate) terminal: iroha_kagemusha_proof::a_relation::native::receive::Terminal,
    /// Complete resulting state, including its source-bound public lineage.
    pub(crate) state: StateWitness,
    /// Exact Receive statement, retained for subsequent `ArchiveStatus` evidence.
    pub(crate) statement: [Fp; 26],
    /// Exact authenticated Payment digest committed by the credit record.
    pub(crate) payment_digest: Fp,
    /// Exact accepted-credit verdict constrained by all result and mode owners.
    pub(crate) accepted_credit: bool,
    /// Actual own sigma proof whose original digest is signed by the receipt.
    pub(crate) sigma: Vec<u8>,
    /// Original Request, payer credential, Send receipt, Payment, incoming Omega,
    /// incoming sigma, own credential/certificate/receipt and quoted credential/certificate.
    pub(crate) objects: [Vec<u8>; 11],
    /// Authenticated consumed map update (including the original free-slot path).
    pub(crate) consumed: IndexedInsert<Fp>,
    /// Authenticated resulting credit record and its membership path.
    pub(crate) credit: IndexedInsert<Fp>,
}

/// Derive the exact terminal identity using every fixed A and W source key.
/// Unknown advice is only for key planning; no fabricated proof is admitted.
/// The genuine rebuilt chain must match this descriptor and complete VK bytes.
#[allow(
    dead_code,
    reason = "used by the separate Receive Omega integration target"
)]
pub(crate) fn receive_terminal_identity(
    wallets: &compact_catalog::SharedKeyWallets,
) -> (iroha_plonk::DescriptorBinding, VerifyingKey<Eq>) {
    let (receiver, payer) = shared_wallet_heads(wallets);
    terminal_identity_from_source(source(
        receiver,
        Some(payer),
        IngestionCapacity::CanonicalEnvelope,
    ))
}

type CatalogBootstrap =
    compact_catalog::send_chain::load_outer::load_chain::bootstrap_outer::RootedBootstrapOmega;

fn catalog_bootstrap_head(receiver: &CatalogBootstrap) -> Head {
    Head {
        state: StateWitness::from(&receiver.source.state),
        key: receiver.key.clone(),
        binding: receiver.binding.clone(),
        proof: receiver.proof.clone(),
        pallas: receiver.source.pallas.clone(),
        vesta: receiver.vesta.clone(),
        opening: receiver.opening.clone(),
    }
}

fn bootstrap_invalid_sigma_source(receiver: &CatalogBootstrap) -> Source {
    source_with_correction(
        catalog_bootstrap_head(receiver),
        None,
        IngestionCapacity::CanonicalEnvelope,
        Variant::Receive,
        Some(false),
        None,
        false,
    )
}

/// Plan the fixed terminal source for a Bootstrap-only invalid-sigma burn.
/// This constructs exact original Q sources but does not admit an A proof.
#[allow(
    dead_code,
    reason = "used by the separate Receive Omega integration target"
)]
pub(crate) fn bootstrap_burn_terminal_identity(
    receiver: &CatalogBootstrap,
) -> (iroha_plonk::DescriptorBinding, VerifyingKey<Eq>) {
    terminal_identity_from_source(bootstrap_invalid_sigma_source(receiver))
}

/// Prove all original owners and native custody under the rebuilt common key.
/// The original invalid sigma must soft-fail and cannot create spendable value.
#[allow(
    dead_code,
    reason = "used by the separate Receive Omega integration target"
)]
pub(crate) fn authenticated_bootstrap_burn(receiver: CatalogBootstrap) -> AuthenticatedReceive {
    let source = bootstrap_invalid_sigma_source(&receiver);
    drop(receiver);
    prove_bootstrap_invalid_sigma_source(source)
}

fn terminal_identity_from_source(
    source: Source,
) -> (iroha_plonk::DescriptorBinding, VerifyingKey<Eq>) {
    let source = Arc::new(source);
    let pallas = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
    let vparams = common::vesta_params(16);
    let vesta = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
    let (first_fold, _) = create_fold(
        &source.params,
        &[pallas.as_input(), pallas.as_input()],
        Fp::from(907).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let mut stage = Stage {
        source: source.clone(),
        continuation: None,
        pallas: pallas.clone(),

        fold: first_fold.to_bytes().to_vec(),
        known: false,
        mutation: None,
    };
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let mut w_config =
        KeygenConfigV2::pipa_r(iroha_kagemusha_proof::omega::OmegaPlan::instance_types().to_vec());
    w_config.compress_selectors = false;
    for index in 0..source.plan.context().stage_count() {
        let (binding, key) = keygen_vk_with_binding_v2(&vparams, &stage, &a_config).unwrap();
        eprintln!("RECEIVE_EXACT_KEY_PLAN A{} actual_proof=false", index + 1);
        if index + 1 == source.plan.context().stage_count() {
            return (binding, key);
        }
        let proof_length = VerifierPlan::new(binding.clone(), vparams.clone())
            .unwrap()
            .proof_length();
        let (fold, _) = create_fold(
            &vparams,
            &vec![vesta.as_input(); 4],
            Fq::from(908).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        let wrapper = WCircuit::new(
            source.plan.context(),
            index,
            binding.clone(),
            vparams.clone(),
            vec![key.kagemusha_digest(&binding).unwrap()],
            iroha_kagemusha_proof::omega::OmegaWitness {
                key,
                instances: stage.public()[0].clone(),
                length: u32::try_from(proof_length).unwrap(),
                proof: vec![0; proof_length],
                fold: fold.to_bytes(),
            },
        )
        .unwrap()
        .without_witnesses();
        let (w_binding, w_key) =
            keygen_vk_with_binding_v2(&source.params, &wrapper, &w_config).unwrap();
        let w_key = WKey::from_artifact(
            source.plan.context(),
            index,
            w_binding,
            source.params.clone(),
            w_key,
        )
        .unwrap();
        let wrapper_length = w_key.verifier().proof_length();
        let split = SplitPlan::new(
            source.plan.context().clone(),
            index + 1,
            w_key,
            &source.params,
        )
        .unwrap();
        let count = 2
            + if split.is_terminal() { 2 } else { 0 }
            + source.plan.context().q_partition(index + 1).unwrap().len();
        let (fold, _) = create_fold(
            &source.params,
            &vec![pallas.as_input(); count],
            Fp::from(909).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        stage = Stage {
            source: source.clone(),
            continuation: Some(Continuation {
                plan: split,
                proof: vec![0; wrapper_length],
                carried: pallas.clone(),
                vesta: vesta.clone(),
            }),
            pallas: pallas.clone(),

            fold: fold.to_bytes().to_vec(),
            known: false,
            mutation: None,
        };
    }
    unreachable!("Receive has a fixed nonempty terminal schedule")
}

/// Prove Receive from these original same-key wallets, including an optional
/// adversarial original Vesta claim with its distinct same-challenges correction.
#[allow(
    dead_code,
    reason = "used by the separate Receive Omega integration target"
)]
pub(crate) fn authenticated_receive_from_wallets(
    wallets: compact_catalog::SharedKeyWallets,
    correction: Option<EqAffine>,
) -> AuthenticatedReceive {
    let (receiver, payer) = shared_wallet_heads(&wallets);
    drop(wallets); // Release the superseded source packages before proving the Receive chain.
    let source = source_with_correction(
        receiver,
        Some(payer),
        IngestionCapacity::CanonicalEnvelope,
        Variant::Receive,
        Some(true),
        correction,
        true,
    );
    assert_exact_payer_source(&source);
    assert!(source.objects_valid);
    assert_eq!(source.corrected_vesta, correction.is_some());
    prove_receive_owner_chain(source).unwrap()
}

fn prove_receive_owner_chain(source: Source) -> Option<AuthenticatedReceive> {
    let source = Arc::new(source);
    preflight_owner_shapes(&source);
    let (first_fold, pallas) = create_fold(
        &source.params,
        &[
            source.predecessor.pallas.as_input(),
            source.predecessor.opening.clone(),
        ],
        Fp::from(247).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let first = Stage {
        source: source.clone(),
        continuation: None,
        pallas: pallas.clone(),

        fold: first_fold.to_bytes().to_vec(),
        known: true,
        mutation: None,
    };
    let native_capacity = source.plan.context().object_specs()[4].capacity
        == u32::try_from(MAX_OMEGA_RAW_BYTES).unwrap();
    if native_capacity {
        assert_native_first_relation(&source, &first);
    }
    let (mut key, mut proof, mut public) = prove_stage(&first);
    let mut native = NativeCheckpoints::default();
    native.a_proofs.push(proof.proof.clone());
    native.pallas.push(pallas.to_bytes());
    let mut carried = pallas;
    let mut part = source.own.part.clone();
    let mut previous_wrapper: Option<Vec<u8>> = None;
    let vparams = common::vesta_params(16);
    for stage in 1..source.plan.context().stage_count() {
        let own = FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap();
        let trivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT)
            .unwrap()
            .as_input();
        let (vfold, vesta) = create_fold(
            &vparams,
            &[part, own, trivial.clone(), trivial],
            Fq::from(251 + u64::try_from(stage).unwrap()).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        vesta.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
        let witness = iroha_kagemusha_proof::omega::OmegaWitness {
            key: key.vk().clone(),
            instances: public[0].clone(),
            length: proof.proof.len().try_into().unwrap(),
            proof: proof.proof,
            fold: vfold.to_bytes(),
        };
        let wrapper = WCircuit::new(
            source.plan.context(),
            stage - 1,
            key.binding().clone(),
            vparams.clone(),
            vec![key.vk().kagemusha_digest(key.binding()).unwrap()],
            witness,
        )
        .unwrap();
        native.a.push(
            iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                key.binding().clone(),
                key.vk().clone(),
            )
            .unwrap(),
        );
        drop(key);
        let (wkey, wprover) = WKey::keygen(&wrapper, &source.params).unwrap();
        let (x, y) = vesta.g().coordinates().unwrap();
        let wpublic = vec![
            vec![Fq::from_repr(public[0][0].to_repr()).unwrap()],
            vec![x, y],
            vesta
                .challenges()
                .iter()
                .map(|v| Fq::from_repr(v.to_repr()).unwrap())
                .collect(),
        ];
        let wproof = create_proof_owned_with_claim(
            &source.params,
            &wprover,
            Witness::from_circuit(&wprover, &wrapper, &wpublic).unwrap(),
            common::recovery(210 + u8::try_from(stage).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        wproof
            .opening
            .decide(&source.params, MemoryBudget::DEFAULT)
            .unwrap();
        verify_full(
            &source.params,
            wprover.binding(),
            wprover.vk(),
            &wpublic,
            &wproof.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        native.w.push(
            iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                wprover.binding().clone(),
                wprover.vk().clone(),
            )
            .unwrap(),
        );
        drop(wprover);
        native.w_proofs.push(wproof.proof.clone());
        native.vesta.push(vesta.to_bytes());
        let mut claims = vec![
            carried.as_input(),
            FoldInput::from_opening(*wproof.opening.g(), wproof.opening.challenges()).unwrap(),
        ];
        let split =
            SplitPlan::new(source.plan.context().clone(), stage, wkey, &source.params).unwrap();
        if split.is_terminal() {
            if source.accept {
                claims.extend([
                    source.incoming_head.pallas.as_input(),
                    source.incoming_head.opening.clone(),
                ]);
            } else {
                let trivial = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
                claims.extend([trivial.as_input(), trivial.as_input()]);
            }
        }
        claims.extend(
            source
                .plan
                .context()
                .q_partition(stage)
                .unwrap()
                .iter()
                .map(|i| source.q[*i].opening.clone()),
        );
        let (fold, pallas) = create_fold(
            &source.params,
            &claims,
            Fp::from(261 + u64::try_from(stage).unwrap()).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        let continuation = Stage {
            source: source.clone(),
            continuation: Some(Continuation {
                plan: split,
                proof: wproof.proof,
                carried: carried.clone(),
                vesta: vesta.clone(),
            }),
            pallas: pallas.clone(),

            fold: fold.to_bytes().to_vec(),
            known: true,
            mutation: None,
        };
        (key, proof, public) = prove_stage(&continuation);
        native.a_proofs.push(proof.proof.clone());
        native.pallas.push(pallas.to_bytes());
        if let Some(previous) = &previous_wrapper {
            assert_foreign_wrapper_rejects(&continuation, previous);
        }
        previous_wrapper = Some(continuation.continuation.as_ref().unwrap().proof.clone());
        if stage == 1 {
            // These values are proposals in this Q-only stage, so only the
            // genuine preceding W/context binding can authenticate them here.
            for slot in 0..11 {
                for word in 0..3 {
                    assert_continuation_rejects(
                        &continuation,
                        ContinuationMutation::Object { slot, word },
                    );
                }
            }
            for index in 0..5 {
                assert_continuation_rejects(&continuation, ContinuationMutation::Result(index));
            }
            for mutation in [
                ContinuationMutation::SwapObjects,
                ContinuationMutation::Opening,
                ContinuationMutation::Mode,
                ContinuationMutation::IncomingStatement,
                ContinuationMutation::QChunk,
            ] {
                assert_continuation_rejects(&continuation, mutation);
            }
            eprintln!(
                "Receive genuine W rejects all33 object words, all5 results, source reorder, opening, mode and statement substitution"
            );
        }
        if source
            .plan
            .context()
            .operation_tasks(stage)
            .unwrap()
            .contains(&OperationTask::ReceiveSignatures)
        {
            assert_continuation_rejects(&continuation, ContinuationMutation::Q2Verdict);
            assert_continuation_rejects(&continuation, ContinuationMutation::CarriedP);
            eprintln!(
                "Receive projected Signatures owner rejects changed Q2 verdict and substituted carried P obligation"
            );
        }
        if stage == 3 {
            assert_continuation_rejects(&continuation, ContinuationMutation::CarriedP);
            assert_continuation_rejects(&continuation, ContinuationMutation::WPart);
        }
        carried = pallas;
        part = vesta.as_input();
    }
    carried
        .decide(&source.params, MemoryBudget::DEFAULT)
        .unwrap();
    native.a.push(
        iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
            key.binding().clone(),
            key.vk().clone(),
        )
        .unwrap(),
    );
    let artifact = (key.binding().clone(), key.vk().clone());
    drop(key);
    let (binding, key) = artifact;
    let terminal = native_capacity.then(|| native.check(&source, &public[0]));
    eprintln!(
        "RECEIVE_OWNER_CHAIN stages={} accepted_credit={} original_sources_bound=true final_catalog=false release_qualified=false",
        source.plan.context().stage_count(),
        source.accept,
    );
    terminal.map(|terminal| AuthenticatedReceive {
        binding,
        key,
        terminal,
        state: source.own.witness.after,
        statement: source.own.witness.statement,
        payment_digest: source.own.witness.payment,
        accepted_credit: source.accept,
        sigma: source.own.sigma.clone(),
        objects: source.objects.clone(),
        consumed: source.own.witness.consumed,
        credit: source.own.witness.credit,
    })
}
