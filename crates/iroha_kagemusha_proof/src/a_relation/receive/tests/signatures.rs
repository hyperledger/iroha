//! Real soft signature Q, hard recursive extraction and exact receipt/mode binding.
//!
//! This is a component proof: the unused sigma/lineage programs are metadata
//! fixtures, and no complete Receive key or operation is admitted here.

use super::*;
use crate::{
    a_relation::{
        AProofPlan, ProofMessageCells, QProofPlan, bind_modes, bind_signature_q, verify_q,
    },
    q_signature::{
        QSignatureCircuit, QSignaturePlan, SignatureKey, SignatureSlot, SignatureWitness,
    },
};
use iroha_pasta::{Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{bytes::element::le_message_segments, p256::VerifyMode};
use iroha_plonk_recursion::{codec::ScalarCells, obligation::ModeCells, verifier::VerifierPlan};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[derive(Clone)]
struct Binding {
    plan: AProofPlan,
    schema: QSignaturePlan,
    proof: Vec<u8>,
    instances: Vec<Fq>,
    receipt: Vec<u8>,
    key: [u128; 4],
    valid: bool,
    accept: bool,
    known: bool,
}

impl Circuit<Fp> for Binding {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let columns = [meta.advice_column(), meta.advice_column()];
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes: BytesConfig::configure(meta, columns[0], columns[1]),
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "actual signature Q receipt binding",
            |mut region| {
                let value = |v: Fp| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let byte = |v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                };
                let raw = self.proof.iter().map(|b| byte(*b)).collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &raw,
                    &iroha_plonk_gadgets::bytes::chunk_segments(0, raw.len()),
                    &le_message_segments(0, raw.len() / 32),
                )?;
                let proof =
                    ProofMessageCells::fixed_slice(&mut chip, &mut region, &run, 0, raw.len())?;
                let column = self
                    .instances
                    .iter()
                    .map(|scalar| {
                        let field = Fp::from_repr(scalar.to_repr())
                            .into_option()
                            .ok_or(Error::Synthesis)?;
                        let word = chip.uint().glue().witness(&mut region, value(field))?;
                        ScalarCells::from_native_word(&mut chip.uint(), &mut region, &word)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let verified = verify_q(&mut chip, &mut region, &self.plan, 1, &[column], &proof)?;
                let bundle = bind_signature_q(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    1,
                    &self.schema,
                    &verified,
                )?;
                let raw = self.receipt.iter().map(|b| byte(*b)).collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &raw,
                    &ObjectKind::Receipt.primary_segments(),
                    &ObjectKind::Receipt.secondary_segments(),
                )?;
                let lanes = chip.operation_lanes()?;
                let mut uint = UintChip::new(lanes.glue, lanes.range);
                let object = SignedObjectCells::decode_soft(
                    &mut uint,
                    lanes.hash,
                    &mut region,
                    ObjectKind::Receipt,
                    &run,
                )?
                .0;
                let key = self
                    .key
                    .map(|v| uint.glue().constant(&mut region, Fp::from_u128(v)))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let valid = object.bind_signature(&mut region, &bundle.slots()[0], &key)?;
                let modes = (0..4)
                    .map(|_| {
                        let words = uint
                            .glue()
                            .witnesses(
                                &mut region,
                                &[
                                    value(Fp::from(u64::from(self.accept))),
                                    value(Fp::from(u64::from(!self.accept))),
                                    value(Fp::ZERO),
                                ],
                            )?
                            .try_into()
                            .map_err(|_| Error::Synthesis)?;
                        ModeCells::constrain(uint.glue(), &mut region, &words)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let result = bind_modes(&mut chip, &mut region, &self.plan, &[valid], &modes)?;
                Ok([object.digest().clone(), result.word().clone()])
            },
        )?;
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

impl Binding {
    fn public(&self) -> [Vec<Fp>; 1] {
        [vec![
            object_digest(ObjectKind::Receipt, &self.receipt),
            Fp::from(u64::from(self.valid)),
        ]]
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 16, &self.public(), CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}

fn scalar_words(bytes: &[u8]) -> [u64; 4] {
    core::array::from_fn(|i| {
        u64::from_be_bytes(bytes[(3 - i) * 8..(4 - i) * 8].try_into().unwrap())
    })
}

#[test]
#[ignore = "native k16 Q proof plus complete recursive verifier component"]
fn actual_bound_invalid_signature_forces_trivial_without_auxiliary_substitution() {
    let fixture = Objects::fixture().with_context();
    let operation = fixture.context.as_ref().unwrap().operation();
    let original_receipt = fixture.source[2].clone();
    // The active-proof fixture updates the receipt body. Use the original G1
    // signed receipt for the honest signature test instead.
    let j: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = j["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["object"].as_str() == Some("Send receipt"))
        .unwrap();
    let mut receipt = decode(row["transcript_hex"].as_str().unwrap());
    receipt.extend(decode(row["signature_hex"].as_str().unwrap()));
    assert_eq!(original_receipt.len(), receipt.len());
    let key = &fixture.source[1][130..195];
    let point = [scalar_words(&key[1..33]), scalar_words(&key[33..65])];
    let key = point
        .into_iter()
        .flat_map(|v| {
            [
                u128::from(v[0]) + (u128::from(v[1]) << 64),
                u128::from(v[2]) + (u128::from(v[3]) << 64),
            ]
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let schema = QSignaturePlan::new(vec![SignatureSlot {
        mode: VerifyMode::Soft,
        key: SignatureKey::Variable,
    }])
    .unwrap();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    for malformed in [false, true] {
        let mut receipt = receipt.clone();
        let end = ObjectKind::Receipt.body_len();
        if malformed {
            receipt[end..end + 32].fill(0);
        }
        let witness = SignatureWitness {
            digest: p_bytes_native(ObjectKind::Receipt.signing_domain(), &receipt[..end]),
            key: point,
            signature: [
                scalar_words(&receipt[end..end + 32]),
                scalar_words(&receipt[end + 32..]),
            ],
        };
        let q = QSignatureCircuit::new(schema.clone(), vec![witness]).unwrap();
        let instances = q.instances(&[!malformed]).unwrap();
        assert!(
            check_circuit(&q, 16, &instances, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let pk = keygen_pk_v2(
            &params,
            &q,
            &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
        )
        .unwrap();
        let proof = create_proof_owned_with_claim(
            &params,
            &pk,
            Witness::from_circuit(&pk, &q, &instances).unwrap(),
            ProverRandomness::recovery(|_: &[u8; 32]| {
                Ok::<_, core::convert::Infallible>(ChaCha20Rng::from_seed([79; 32]))
            }),
            ProverConfig::default(),
        )
        .unwrap();
        accumulate_generator(
            &params,
            pk.binding(),
            pk.vk(),
            &instances,
            &proof.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap()
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
        let qplan = QProofPlan::new(
            VerifierPlan::new(pk.binding().clone(), params.clone()).unwrap(),
            pk.vk().clone(),
        )
        .unwrap();
        let plan = AProofPlan::new(
            Variant::Receive,
            operation.sigma.clone(),
            vec![operation.q(0).unwrap().clone(), qplan],
            operation.omega().cloned(),
            &params,
        )
        .unwrap();
        let circuit = Binding {
            plan,
            schema: schema.clone(),
            proof: proof.proof,
            instances: instances[0].clone(),
            receipt,
            key,
            valid: !malformed,
            accept: !malformed,
            known: true,
        };
        assert!(circuit.accepts(), "actual soft signature {malformed}");
        for mutation in 0..5 {
            let mut wrong = circuit.clone();
            match mutation {
                0 => wrong.receipt[end] ^= 1,
                1 => wrong.receipt[2] ^= 1,
                2 => wrong.instances[9] = Fq::ONE - wrong.instances[9],
                3 => wrong.accept = !wrong.accept,
                _ => wrong.proof[0] ^= 1,
            }
            assert!(
                !wrong.accepts(),
                "signature splice/mode {malformed}/{mutation}"
            );
        }
        let known = synthesize(&circuit, 16, None).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        let lanes = known
            .tables
            .advice_assigned()
            .iter()
            .map(|lane| lane.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect::<Vec<_>>();
        eprintln!("Receive signature-Q ownership component lanes={lanes:?}");
    }
}

#[test]
#[ignore = "native k16 renewed incoming3V1F proof and public-input mutations"]
fn actual_renewed_three_variable_one_fixed_leaf_preserves_every_signature() {
    let j: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let point = |name: &str| {
        let row = j["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"].as_str() == Some(name))
            .unwrap();
        let raw = decode(row["public_key_hex"].as_str().unwrap());
        Affine {
            x: scalar_words(&raw[1..33]),
            y: scalar_words(&raw[33..65]),
        }
    };
    let root = point("scheme_root");
    let policy = OwnPolicy::new([3, 4], root).unwrap();
    let schemas = ReceiveStagePlan::signature_schemas(Variant::ReceiveRenewed, policy).unwrap();
    assert_eq!(schemas[0].slots().len(), 3);
    let schema = schemas[1].clone();
    assert_eq!(schema.slots().len(), 4);
    assert_eq!(schema.slots()[3].key, SignatureKey::Fixed(root));
    let witnesses = [
        ("Send receipt", "payer_payment", ObjectKind::Receipt),
        ("Request", "receiver_payment", ObjectKind::Request),
        ("payer credential", "payer_issuer", ObjectKind::Credential),
        (
            "payer issuer certificate",
            "scheme_root",
            ObjectKind::Certificate,
        ),
    ]
    .into_iter()
    .map(|(name, signer, kind)| {
        let row = j["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["object"].as_str() == Some(name))
            .unwrap();
        let body = decode(row["transcript_hex"].as_str().unwrap());
        let signature = decode(row["signature_hex"].as_str().unwrap());
        let key = point(signer);
        SignatureWitness {
            digest: p_bytes_native(kind.signing_domain(), &body),
            key: [key.x, key.y],
            signature: [
                scalar_words(&signature[..32]),
                scalar_words(&signature[32..]),
            ],
        }
    })
    .collect::<Vec<_>>();
    let circuit = QSignatureCircuit::new(schema.clone(), witnesses.clone()).unwrap();
    let instances = circuit.instances(&[true; 4]).unwrap();
    assert!(
        check_circuit(&circuit, 16, &instances, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let pk = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let output = create_proof_owned_with_claim(
        &params,
        &pk,
        Witness::from_circuit(&pk, &circuit, &instances).unwrap(),
        ProverRandomness::recovery(|_: &[u8; 32]| {
            Ok::<_, core::convert::Infallible>(ChaCha20Rng::from_seed([81; 32]))
        }),
        ProverConfig::default(),
    )
    .unwrap();
    accumulate_generator(
        &params,
        pk.binding(),
        pk.vk(),
        &instances,
        &output.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .decide(&params, MemoryBudget::DEFAULT)
    .unwrap();
    for slot in 0..4 {
        let mut malformed = witnesses.clone();
        malformed[slot].signature[0] = [0; 4];
        let malformed = QSignatureCircuit::new(schema.clone(), malformed).unwrap();
        let mut verdicts = [true; 4];
        verdicts[slot] = false;
        assert!(
            check_circuit(
                &malformed,
                16,
                &malformed.instances(&verdicts).unwrap(),
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        assert!(
            !check_circuit(&malformed, 16, &instances, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let mut substitution = instances.clone();
        substitution[0][slot * crate::q_signature::SLOT_WORDS] += Fq::ONE;
        assert!(
            accumulate_generator(
                &params,
                pk.binding(),
                pk.vk(),
                &substitution,
                &output.proof,
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
    }
    let known = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let rows = known
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!(
        "Receive renewed actual soft3V1F Q proof={}B lanes={rows:?}",
        output.proof.len()
    );
}
