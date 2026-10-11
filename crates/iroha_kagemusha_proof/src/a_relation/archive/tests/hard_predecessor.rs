//! Deferred actual-Omega hard-verifier boundary; no operation or release admission.

use super::{
    omega_fixture::{NAMES, bounded, hex, retain, sha, words_bytes},
    real_sources,
};
use crate::a_relation::{
    AProofPlan, LineagePublicCells, ProofMessageCells, VestaClaimCells, verify_predecessor,
};
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, VerifyingKey,
    check::{CheckMode, check_circuit},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Instance, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1,
        TranscriptV2,
    },
    frontend::{
        Circuit, Error, Layouter, Region, SimpleFloorPlanner, Synthesized, Value, synthesize,
    },
    pcs::ipa::PinnedParams,
    transcript::TranscriptRepr,
    verifier::{accumulate_generator, verify_full},
};
use iroha_plonk_gadgets::{Word, bytes::element::LeElement, statement::foreign_limbs};
use iroha_plonk_recursion::{
    AccumulatorT, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig},
};
use std::{fs, path::PathBuf};

const K: u32 = 16;
const OUTPUT_WORDS: usize = 36;

#[derive(Clone)]
struct HardBoundary {
    plan: AProofPlan,
    key: VerifyingKey<Ep>,
    proof: Vec<u8>,
    actual_length: u32,
    public: [Fp; 18],
    pallas: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
    successor_digest_delta: Fp,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    output: Column<Instance>,
}
impl HardBoundary {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn words<const N: usize>(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        values: &[Fp; N],
    ) -> Result<[Word<Fp>; N], Error> {
        chip.uint()
            .glue()
            .witnesses(r, &values.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
    fn scalar(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        value: Fq,
    ) -> Result<ScalarCells<Ep>, Error> {
        let [lo, hi] = foreign_limbs(&value);
        let lo = chip.uint().assign::<128>(r, self.value(lo))?;
        let hi = chip.uint().assign::<127>(r, self.value(hi))?;
        ScalarCells::from_limbs(&mut chip.uint(), r, &lo, &hi)
    }
}
impl Circuit<Fp> for HardBoundary {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        // Same first-stage serialized foreign layout family as actual A owners.
        // Fixed k16 test wrapper only; it is not an admitted operation descriptor.
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 4).unwrap();
        let output = meta.instance_column(OUTPUT_WORDS);
        meta.enable_equality(output);
        Config { verifier, output }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let output = layouter.assign_region(
            || "actual Omega hard predecessor boundary",
            |mut r| {
                let public = self.words(&mut chip, &mut r, &self.public)?;
                let public = LineagePublicCells::constrain(&mut chip.uint(), &mut r, &public)?;
                let mut next = self.public;
                next[17] += self.successor_digest_delta;
                let next = self.words(&mut chip, &mut r, &next)?;
                let next = LineagePublicCells::constrain(&mut chip.uint(), &mut r, &next)?;
                let point = chip.witness_point(&mut r, self.value(Ep::from(*self.pallas.g())))?;
                let challenges = self
                    .pallas
                    .challenges()
                    .iter()
                    .map(|v| self.scalar(&mut chip, &mut r, *v))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let pallas =
                    FoldInputCells::from_normalized(&mut chip, &mut r, K, point, challenges)?;
                let (x, y) = Option::<(Fq, Fq)>::from(self.vesta.g().coordinates())
                    .ok_or(Error::Synthesis)?;
                let coords = [
                    self.scalar(&mut chip, &mut r, x)?,
                    self.scalar(&mut chip, &mut r, y)?,
                ];
                let challenges = self.words(&mut chip, &mut r, self.vesta.challenges())?;
                let vesta = VestaClaimCells::constrain(&mut chip, &mut r, K, coords, challenges)?;
                let TranscriptRepr::Base(repr) = *self.key.transcript_repr() else {
                    return Err(Error::Synthesis);
                };
                let points = |p: &[iroha_pasta::EpAffine]| {
                    p.iter()
                        .map(|p| self.value(Ep::from(*p)))
                        .collect::<Vec<_>>()
                };
                let key = chip.witness_key(
                    &mut r,
                    self.value(repr),
                    &points(self.key.fixed_commitments()),
                    &points(self.key.permutation_commitments()),
                )?;
                let messages = self
                    .proof
                    .chunks_exact(32)
                    .map(|bytes| {
                        LeElement::assign(
                            &mut chip.uint(),
                            &mut r,
                            self.value(bytes.try_into().map_err(|_| Error::Synthesis)?),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let length = chip
                    .uint()
                    .assign::<32>(&mut r, self.value(u128::from(self.actual_length)))?;
                let proof = ProofMessageCells::from_messages(messages, length)?;
                let result = verify_predecessor(
                    &mut chip, &mut r, &self.plan, &key, &public, &next, &pallas, &vesta, &proof,
                )?;
                // Digest equality is enforced by the actual verify_predecessor call.
                let mut out = vec![
                    result.public[17].clone(),
                    result.opening.source_k().clone(),
                    result.opening.g().x().clone(),
                    result.opening.g().y().clone(),
                ];
                for u in result.opening.challenges() {
                    out.extend([u.lo().word().clone(), u.hi().word().clone()]);
                }
                Ok(out)
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.output, row)?;
        }
        Ok(())
    }
}

fn wrapper_descriptor(layout: &Synthesized<Fp>) -> DescriptorBinding {
    let finalized = layout
        .cs
        .clone()
        .finalize(layout.tables.selectors(), true)
        .unwrap();
    let base = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Vesta,
            k: K,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .unwrap();
    DescriptorBinding::new_v2(
        CircuitDescriptorV2::from_layout(
            base,
            TranscriptV2::KagemushaPoseidonRp57Base,
            vec![InstanceType::Field],
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
#[ignore = "actual retained Omega proof/public/P/V and pinned source receipt required; fixed k16 synthesis only, no proofs"]
fn actual_omega_hard_predecessor_matches_native_and_witnessless_layout() {
    let fixture = real_sources::read_selected_fixture();
    let originals = &fixture.originals;
    let manifest_bytes = &fixture.manifest_bytes;
    let producer_receipt = &fixture.producer_receipt;
    let expected_manifest = sha(manifest_bytes);
    let descriptor_sha = fixture.manifest.files[0].sha256;
    let key_sha = fixture.manifest.files[1].sha256;
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_HARD_PREDECESSOR_OUTPUT").expect("fresh output path"),
    );
    let public: [Fp; 18] = originals[3]
        .chunks_exact(32)
        .map(|v| Option::<Fp>::from(Fp::from_repr(v.try_into().unwrap())).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(public[0], Fp::ONE);
    for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
        assert!(public[index].to_repr()[16..].iter().all(|b| *b == 0));
    }
    assert!(public[13].to_repr()[13..].iter().all(|b| *b == 0));
    let pallas = AccumulatorT::<Ep>::from_bytes(&originals[4]).unwrap();
    let vesta = AccumulatorT::<Eq>::from_bytes(&originals[5]).unwrap();
    let (binding, key) = real_sources::captured_metadata(&originals[0], &originals[1])
        .expect("actual selected Omega profile");
    assert_eq!(key.to_bytes(), originals[1]);
    let p = PinnedParams::<Ep>::derive(K).unwrap();
    let v = PinnedParams::<Eq>::derive(K).unwrap();
    let digest = key.kagemusha_digest(&binding).unwrap();
    assert_eq!(public[17], digest);
    let mut words = public.to_vec();
    let (x, y) = Option::<(Fp, Fp)>::from(pallas.g().coordinates()).unwrap();
    words.extend([x, y]);
    for u in pallas.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    assert_eq!(words.len(), 52);
    let digest_a = hash_with_domain(crate::a_relation::LINEAGE_DOMAIN, &words);
    let (x, y) = Option::<(Fq, Fq)>::from(vesta.g().coordinates()).unwrap();
    let to_fq = |word: Fp| Option::<Fq>::from(Fq::from_repr(word.to_repr())).unwrap();
    let instances = [
        vec![to_fq(digest_a)],
        vec![x, y],
        vesta.challenges().iter().copied().map(to_fq).collect(),
    ];
    // Full native decisions precede construction/synthesis of the hard wrapper.
    verify_full(
        &p,
        &binding,
        &key,
        &instances,
        &originals[2],
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    pallas.decide(&p, MemoryBudget::DEFAULT).unwrap();
    vesta.decide(&v, MemoryBudget::DEFAULT).unwrap();
    let claim = accumulate_generator(
        &p,
        &binding,
        &key,
        &instances,
        &originals[2],
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let opening = FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap();
    opening.decide(&p, MemoryBudget::DEFAULT).unwrap();
    assert_eq!(opening.source_k(), K);
    let (x, y) = Option::<(Fp, Fp)>::from(opening.g().coordinates()).unwrap();
    let mut expected = vec![digest, Fp::from(u64::from(K)), x, y];
    for u in opening.challenges() {
        expected.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    assert_eq!(expected.len(), OUTPUT_WORDS);
    let (plan, _policy, selected_key) =
        real_sources::captured_operation(Variant::ArchiveStatus, binding.clone(), key.clone(), 12);
    assert_eq!(selected_key.to_bytes(), key.to_bytes());
    assert_eq!(plan.omega().unwrap().binding(), &binding);
    let circuit = HardBoundary {
        plan,
        key,
        proof: originals[2].clone(),
        actual_length: originals[2].len().try_into().unwrap(),
        public,
        pallas,
        vesta,
        successor_digest_delta: Fp::ZERO,
        known: true,
    };
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&output).expect("fresh output; no overwrite");
    retain(&output, "fixture.norito", manifest_bytes);
    retain(&output, "producer-receipt.json", producer_receipt);
    for (name, bytes) in NAMES.iter().zip(originals) {
        retain(&output, name, bytes);
    }
    retain(
        &output,
        "native-opening-public.bin",
        &words_bytes(&expected),
    );
    let instance_bytes = instances
        .iter()
        .flatten()
        .flat_map(|v| v.to_repr())
        .collect::<Vec<_>>();
    retain(&output, "native-omega-instances.bin", &instance_bytes);
    let public = vec![expected.clone()];
    assert!(
        check_circuit(&circuit, K, &public, CheckMode::Strict)
            .expect("fixed k16 only; no larger-domain retry")
            .is_satisfied()
    );
    let known = synthesize(&circuit, K, Some(&public)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), K, None).unwrap();
    let known_descriptor = wrapper_descriptor(&known);
    let unknown_descriptor = wrapper_descriptor(&unknown);
    assert_eq!(known_descriptor, unknown_descriptor);
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.fixed_assigned(),
        unknown.tables.fixed_assigned()
    );
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(
        known.tables.permutation().mapping_digest(),
        unknown.tables.permutation().mapping_digest()
    );
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    retain(
        &output,
        "test-wrapper.descriptor.norito",
        known_descriptor.encoded(),
    );
    retain(
        &output,
        "test-wrapper.copy-digest",
        &known.tables.permutation().mapping_digest(),
    );
    drop(known);
    drop(unknown);
    for mutation in 0..4 {
        let mut bad = circuit.clone();
        match mutation {
            0 => bad.actual_length -= 1,
            1 => bad.proof[..32].fill(0),
            2 => {
                let end = bad.proof.len();
                bad.proof[end - 96..end - 64].fill(0xff);
            } // final c is noncanonical
            3 => bad.successor_digest_delta = Fp::ONE,
            _ => unreachable!(),
        }
        if matches!(mutation, 1 | 2) {
            assert!(
                verify_full(
                    &p,
                    &binding,
                    &bad.key,
                    &instances,
                    &bad.proof,
                    MemoryBudget::DEFAULT
                )
                .is_err()
            );
        }
        assert!(
            !check_circuit(&bad, K, &public, CheckMode::Strict)
                .expect("hard malformed case remains synthesizeable")
                .is_satisfied(),
            "mutation {mutation}"
        );
    }
    let mut wrong = public.clone();
    wrong[0][4] += Fp::ONE;
    assert!(
        !check_circuit(&circuit, K, &wrong, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    fixture.recheck();
    for (name, bytes) in NAMES.iter().zip(originals) {
        assert_eq!(bounded(&output.join(name), bytes.len()), *bytes);
    }
    assert_eq!(
        bounded(&output.join("fixture.norito"), 8192),
        *manifest_bytes
    );
    assert_eq!(
        bounded(&output.join("producer-receipt.json"), 65_536),
        *producer_receipt
    );
    assert_eq!(
        bounded(&output.join("native-opening-public.bin"), OUTPUT_WORDS * 32),
        words_bytes(&expected)
    );
    assert_eq!(
        bounded(&output.join("native-omega-instances.bin"), 19 * 32),
        instance_bytes
    );
    assert_eq!(
        bounded(
            &output.join("test-wrapper.descriptor.norito"),
            known_descriptor.encoded().len()
        ),
        known_descriptor.encoded()
    );
    retain(&output,"result.json",&norito::json::to_vec(&norito::json!({
        "scope":"actual native Omega to shared hard verifier; test-only wrapper, no operation/catalog/privacy/release qualification",
        "native_full_omega_and_three_claim_decisions":true,"exact_G_u_key_digest":true,
        "wrapper_known_unknown_descriptor_fixed_selectors_copy_equal":true,"hard_mutations_rejected":5,
        "k":16,"generated_proofs":0,"descriptor_sha256":(hex(&descriptor_sha)),"key_sha256":(hex(&key_sha)),
        "fixture_manifest_sha256":(hex(&expected_manifest)),"wrapper_descriptor_digest":(hex(known_descriptor.digest()))
    })).unwrap());
}
