//! Current-Omega local verifier/decoder differential, requiring retained real proof bytes.
//!
//! This calls the actual private native transport helper and public circuit components.
//! Its test-only joins do not exercise AProofPlan, IncomingTransportPlan::verify or the
//! complete Receive/Archive operation. The paired proof-lib incoming test consumes
//! these exact native outputs. TODO: qualify complete operations separately.
//!
//! Fixture hashes and full native verification grant no source/catalog admission.
//! A current compiled Bootstrap component may supply the fixture; that does not
//! qualify the installed complete catalog. No historical Load stage count is used.

#[path = "../../../../../iroha_kagemusha_proof/tests/common/proof_fixtures/omega_hard_fixture.rs"]
mod omega_fixture;

use ff::{Field, PrimeField};
use iroha_data_model::kagemusha::kagemusha_wallet_v1::{
    KagemushaDevicePublicKeyV1, KagemushaWalletLifecycleV1, KagemushaWalletLineagePublicV1,
    KagemushaWalletStateCommitmentV1,
};
use iroha_kagemusha_proof::{
    a_relation::{IncomingLineageCells, VestaClaimCells, own::ConsumingProofCells},
    omega::OmegaPlan,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, Protocol, VerifyingKey,
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
    verifier::verify_full,
};
use iroha_plonk_gadgets::{
    GlueChip, UintChip, Word,
    bytes::{
        element::{LeElement, decode_le_element},
        p_bytes_native,
        tape::{ByteRun, BytesChip, BytesConfig, SegmentSpec},
        variable::ActiveBytes,
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    ACCUMULATOR_BYTES, AccumulatorT, FoldInput,
    accumulation_circuit::{FoldInputCells, FoldInputDecodePlan},
    codec::ScalarCells,
    verifier::{VerificationMode, VerifierChip, VerifierConfig, VerifierPlan},
};
use omega_fixture::{NAMES, bounded, hex, load_selected, pin, retain, sha, words_bytes};
use std::{fs, path::PathBuf};

const K: u32 = 16;
const RAW_DOMAIN: u64 = u64::from_le_bytes(*b"kgwlin_1");
const LINEAGE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwomg_1");
// final/local/public/P/V verdicts, key, public18, P(k,x,y,u limbs),
// V(k,x/y limbs,u), local opening(k,x,y,u limbs), original length/digest.
const OUTPUT_WORDS: usize = 117;
const OPENING_START: usize = 80;

#[derive(Clone)]
struct LocalBoundary {
    plan: VerifierPlan<Ep>,
    pallas: FoldInputDecodePlan<Ep>,
    key: VerifyingKey<Ep>,
    original: Vec<u8>,
    capacity: usize,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    output: Column<Instance>,
}
fn slice(
    chip: &mut VerifierChip<Ep>,
    r: &mut Region<'_, Fp>,
    run: &ByteRun<Fp>,
    start: usize,
    len: usize,
) -> Result<Vec<LeElement<Fp>>, Error> {
    (0..len / 32)
        .map(|i| decode_le_element(&mut chip.uint(), r, run, start + 32 * i))
        .collect()
}
fn append_p(out: &mut Vec<Word<Fp>>, claim: &FoldInputCells<Ep>) {
    out.extend([
        claim.source_k().clone(),
        claim.g().x().clone(),
        claim.g().y().clone(),
    ]);
    for u in claim.challenges() {
        out.extend([u.lo().word().clone(), u.hi().word().clone()]);
    }
}
impl Circuit<Fp> for LocalBoundary {
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
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 4).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let output = meta.instance_column(OUTPUT_WORDS);
        meta.enable_equality(output);
        Config {
            verifier,
            bytes,
            output,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "local Omega components and test-only joins",
            |mut r| {
                let segments = ConsumingProofCells::omega_segments(self.plan.proof_length())?
                    .into_iter()
                    .filter(|s| s.start != 0)
                    .map(|s| SegmentSpec {
                        start: s.start - 4,
                        ..s
                    })
                    .collect::<Vec<_>>();
                let value = if self.known {
                    Value::known(self.original.clone())
                } else {
                    Value::unknown()
                };
                let raw = ActiveBytes::assign(
                    &mut chip.uint(),
                    &mut bytes,
                    &mut r,
                    self.capacity,
                    &value,
                    &segments,
                )?;
                let digest = self
                    .key
                    .kagemusha_digest(self.plan.binding())
                    .map_err(|_| Error::Synthesis)?;
                let carried_key = chip.uint().glue().constant(&mut r, digest)?;
                let public = IncomingLineageCells::from_active(
                    &mut chip.uint(),
                    &mut r,
                    &raw,
                    self.plan.proof_length(),
                    &carried_key,
                )?;
                let proof = slice(&mut chip, &mut r, raw.run(), 320, self.plan.proof_length())?;
                let start_p = 320 + self.plan.proof_length();
                let pbytes = slice(&mut chip, &mut r, raw.run(), start_p, ACCUMULATOR_BYTES)?;
                let vbytes = slice(
                    &mut chip,
                    &mut r,
                    raw.run(),
                    start_p + ACCUMULATOR_BYTES,
                    ACCUMULATOR_BYTES,
                )?;
                let claim_length = chip
                    .uint()
                    .constant::<32>(&mut r, ACCUMULATOR_BYTES as u128)?;
                let p = FoldInputCells::decode_soft(
                    &mut chip,
                    &mut r,
                    &self.pallas,
                    &pbytes,
                    &claim_length,
                )?;
                let (v, v_valid) =
                    VestaClaimCells::decode_soft(&mut chip, &mut r, &vbytes, &claim_length)?;
                let mut words = public.fields().to_vec();
                words.extend([p.value.g().x().clone(), p.value.g().y().clone()]);
                for u in p.value.challenges() {
                    words.extend([u.lo().word().clone(), u.hi().word().clone()]);
                }
                let d_a = chip.hash_words(&mut r, LINEAGE_DOMAIN, &words)?;
                let d_a = ScalarCells::from_native_word(&mut chip.uint(), &mut r, &d_a)?;
                let mut challenges = Vec::with_capacity(16);
                for u in v.challenges() {
                    challenges.push(ScalarCells::from_native_word(&mut chip.uint(), &mut r, u)?);
                }
                let instances = [vec![d_a], v.coordinates().to_vec(), challenges];
                let key = chip.constant_key(&mut r, &self.plan, &self.key)?;
                let length = chip
                    .uint()
                    .constant::<32>(&mut r, self.plan.proof_length() as u128)?;
                let local = chip.verify(
                    &mut r,
                    &self.plan,
                    &key,
                    &instances,
                    &proof,
                    &length,
                    VerificationMode::Soft,
                )?;
                GlueChip::assert_equal(&mut r, &local.key_digest, &carried_key)?;
                // Test-only conjunction, deliberately not the full A owner relation.
                let mut valid = local.valid.clone();
                for bit in [public.valid(), &p.valid, &v_valid] {
                    valid = chip.uint().glue().and(&mut r, &valid, bit)?;
                }
                let opening = FoldInputCells::from_claim(&mut chip, &mut r, &local.claim)?;
                let mut out = vec![
                    valid.word().clone(),
                    local.valid.word().clone(),
                    public.valid().word().clone(),
                    p.valid.word().clone(),
                    v_valid.word().clone(),
                    local.key_digest,
                ];
                out.extend(public.fields().iter().cloned());
                append_p(&mut out, &p.value);
                out.push(
                    chip.uint()
                        .glue()
                        .constant(&mut r, Fp::from(u64::from(v.source_k())))?,
                );
                out.extend(v.words());
                append_p(&mut out, &opening);
                out.push(raw.length().word().clone());
                let lanes = chip.operation_lanes()?;
                let mut uint = UintChip::new(lanes.glue, lanes.range);
                out.push(raw.packed().digest(
                    &mut uint,
                    lanes.hash.sponge_mut()?,
                    &mut r,
                    RAW_DOMAIN,
                )?);
                assert_eq!(out.len(), OUTPUT_WORDS);
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

// Fixture adaptation only. Encoding is the actual data-model transcript and its
// field conversion is checked against the actual native owner's conversion.
fn public_model(words: &[Fp; 18]) -> KagemushaWalletLineagePublicV1 {
    let low = |i: usize| {
        let bytes = words[i].to_repr();
        assert!(bytes[16..].iter().all(|b| *b == 0));
        <[u8; 16]>::try_from(&bytes[..16]).unwrap()
    };
    let pair = |i| {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&low(i));
        bytes[16..].copy_from_slice(&low(i + 1));
        bytes
    };
    assert_eq!(words[0], Fp::ONE);
    let mut payment = [0; 65];
    payment[0] = 4;
    for (i, start) in [(9, 1), (11, 33)] {
        let mut value = pair(i);
        value.reverse();
        payment[start..start + 32].copy_from_slice(&value);
    }
    let policy = words[13].to_repr();
    assert!(policy[13..].iter().all(|b| *b == 0));
    let model = KagemushaWalletLineagePublicV1 {
        version: 1,
        scheme_id: pair(1),
        relation_id: pair(3),
        head: KagemushaWalletStateCommitmentV1 {
            value: words[5].to_repr(),
        },
        wallet_id: pair(6),
        credential_digest: words[8].to_repr(),
        payment_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(&payment).unwrap(),
        lifecycle: match policy[0] {
            1 => KagemushaWalletLifecycleV1::Active,
            2 => KagemushaWalletLifecycleV1::Retiring,
            _ => panic!("fixture lifecycle"),
        },
        policy_epoch: u64::from_le_bytes(policy[1..9].try_into().unwrap()),
        enabled_controls: u32::from_le_bytes(policy[9..13].try_into().unwrap()),
        burned_total: u128::from_le_bytes(low(14)),
        pending_outgoing_root: words[15].to_repr(),
        credit_digest_root: words[16].to_repr(),
    };
    assert_eq!(
        crate::kagemusha_wallet_proofs_v1::lineage_public_fields(&model, words[17].to_repr())
            .unwrap(),
        *words
    );
    assert_eq!(model.transcript().len(), 320);
    model
}
fn instances(value: &super::TransportV1) -> [Vec<Fq>; 3] {
    let mut words = value.public.to_vec();
    let (x, y) = Option::<(Fp, Fp)>::from(value.pallas.g().coordinates()).unwrap();
    words.extend([x, y]);
    for u in value.pallas.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    assert_eq!(words.len(), 52);
    let to_fq = |word: Fp| Option::<Fq>::from(Fq::from_repr(word.to_repr())).unwrap();
    let digest = to_fq(hash_with_domain(LINEAGE_DOMAIN, &words));
    let (x, y) = Option::<(Fq, Fq)>::from(value.vesta.g().coordinates()).unwrap();
    [
        vec![digest],
        vec![x, y],
        value
            .vesta
            .challenges()
            .iter()
            .copied()
            .map(to_fq)
            .collect(),
    ]
}
fn p_words(claim: &FoldInput<Ep>) -> Vec<Fp> {
    let (x, y) = Option::<(Fp, Fp)>::from(claim.g().coordinates()).unwrap();
    let mut out = vec![Fp::from(u64::from(claim.source_k())), x, y];
    for u in claim.challenges() {
        out.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    out
}
fn expected(
    p: &PinnedParams<Ep>,
    v: &PinnedParams<Eq>,
    key: &super::KeyArtifact<Ep>,
    original: &[u8],
) -> (Vec<Fp>, super::TransportV1) {
    let result = super::transport(p, v, key, original, MemoryBudget::DEFAULT, None).unwrap();
    let len = Protocol::new(key.binding().descriptor())
        .unwrap()
        .proof_length();
    let proof = (0..len)
        .map(|i| original.get(320 + i).copied().unwrap_or(0))
        .collect::<Vec<_>>();
    // Call the actual local native checker independently of outer validity.
    let local = super::opening(
        p,
        key,
        &instances(&result),
        &proof,
        MemoryBudget::DEFAULT,
        None,
    )
    .unwrap();
    let is_p =
        AccumulatorT::<Ep>::from_bytes(&super::view::<ACCUMULATOR_BYTES>(original, 320 + len))
            .is_ok();
    let is_v = AccumulatorT::<Eq>::from_bytes(&super::view::<ACCUMULATOR_BYTES>(
        original,
        320 + len + ACCUMULATOR_BYTES,
    ))
    .is_ok();
    assert_eq!(
        result.valid,
        result.public_valid && is_p && is_v && local.is_some()
    );
    if let Some(local) = &local {
        assert_eq!(p_words(local), p_words(&result.opening));
    }
    let mut out = vec![
        Fp::from(u64::from(result.valid)),
        Fp::from(u64::from(local.is_some())),
        Fp::from(u64::from(result.public_valid)),
        Fp::from(u64::from(is_p)),
        Fp::from(u64::from(is_v)),
        key.key().kagemusha_digest(key.binding()).unwrap(),
    ];
    out.extend(result.public);
    out.extend(p_words(&result.pallas.as_input()));
    out.push(Fp::from(u64::from(K)));
    let (x, y) = Option::<(Fq, Fq)>::from(result.vesta.g().coordinates()).unwrap();
    for coordinate in [x, y] {
        out.extend(foreign_limbs(&coordinate).map(Fp::from_u128));
    }
    out.extend(result.vesta.challenges());
    out.extend(p_words(&result.opening));
    out.extend([
        Fp::from(u64::try_from(original.len()).unwrap()),
        p_bytes_native(RAW_DOMAIN, original),
    ]);
    assert_eq!(out.len(), OUTPUT_WORDS);
    (out, result)
}

#[cfg(test)]
#[test]
#[ignore = "current selected Omega six-file fixture + producer source/binary admission required; fixed-k16 local components only"]
fn current_omega_soft_local_decoders_match_native_and_retain_opening() {
    let fixture = load_selected(
        &PathBuf::from(
            std::env::var("KAGEMUSHA_HARD_PREDECESSOR_FIXTURE")
                .expect("explicit current fixture/output selection"),
        ),
        pin(&std::env::var("KAGEMUSHA_HARD_PREDECESSOR_MANIFEST_SHA256")
            .expect("explicit current fixture/output selection")),
        pin(
            &std::env::var("KAGEMUSHA_HARD_PREDECESSOR_DESCRIPTOR_SHA256")
                .expect("explicit current fixture/output selection"),
        ),
        pin(&std::env::var("KAGEMUSHA_HARD_PREDECESSOR_KEY_SHA256")
            .expect("explicit current fixture/output selection")),
    );
    let binding = DescriptorBinding::decode_v2(&fixture.originals[0]).unwrap();
    assert_eq!(binding.encoded(), fixture.originals[0]);
    let descriptor = binding.descriptor();
    assert_eq!(descriptor.curve, CurveV1::Pallas);
    assert_eq!(u32::from(descriptor.k), K);
    assert_eq!(
        descriptor.transcript,
        TranscriptV2::KagemushaPoseidonRp57Base
    );
    assert_eq!(descriptor.instance_mode, InstanceModeV1::Direct);
    assert_eq!(descriptor.proof_suffix, ProofSuffixV1::FoldedGenerator);
    assert_eq!(descriptor.instance_lengths, [1, 2, 16]);
    assert_eq!(
        descriptor.instance_types.as_deref(),
        Some(OmegaPlan::instance_types().as_slice())
    );
    let key = VerifyingKey::<Ep>::read(&fixture.originals[1], &binding).unwrap();
    assert_eq!(key.to_bytes(), fixture.originals[1]);
    let artifact = super::KeyArtifact::new(binding.clone(), key.clone()).unwrap();
    let proof_length = Protocol::new(binding.descriptor()).unwrap().proof_length();
    assert_eq!(fixture.originals[2].len(), proof_length);
    let public: [Fp; 18] = fixture.originals[3]
        .chunks_exact(32)
        .map(|b| Option::<Fp>::from(Fp::from_repr(b.try_into().unwrap())).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(public[17], key.kagemusha_digest(&binding).unwrap());
    let mut original = public_model(&public).transcript();
    for i in [2, 4, 5] {
        original.extend_from_slice(&fixture.originals[i]);
    }
    let p = PinnedParams::<Ep>::derive(K).unwrap();
    let v = PinnedParams::<Eq>::derive(K).unwrap();
    let (positive, native) = expected(&p, &v, &artifact, &original);
    assert!(native.valid);
    assert_eq!(native.public, public);
    assert_eq!(native.pallas.to_bytes().as_slice(), fixture.originals[4]);
    assert_eq!(native.vesta.to_bytes().as_slice(), fixture.originals[5]);
    verify_full(
        &p,
        &binding,
        &key,
        &instances(&native),
        &fixture.originals[2],
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    native.pallas.decide(&p, MemoryBudget::DEFAULT).unwrap();
    native.vesta.decide(&v, MemoryBudget::DEFAULT).unwrap();
    native.opening.decide(&p, MemoryBudget::DEFAULT).unwrap();
    let base = LocalBoundary {
        plan: VerifierPlan::new(binding.clone(), p.clone()).unwrap(),
        pallas: FoldInputDecodePlan::new(&p, K).unwrap(),
        key,
        original: original.clone(),
        capacity: original.len() + 1,
        known: true,
    };
    let output = PathBuf::from(
        std::env::var("KAGEMUSHA_SOFT_LOCAL_OUTPUT")
            .expect("explicit current fixture/output selection"),
    );
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&output).expect("fresh output, no overwrite");
    retain(&output, "fixture.norito", &fixture.manifest_bytes);
    retain(&output, "producer-receipt.json", &fixture.producer_receipt);
    for (name, bytes) in NAMES.iter().zip(&fixture.originals) {
        retain(&output, name, bytes);
    }
    let mut cases = Vec::new();
    for name in [
        "valid",
        "overlong",
        "truncated-proof",
        "identity-proof",
        "noncanonical-scalar",
        "malformed-p",
        "malformed-v",
        "noncanonical-public",
    ] {
        let mut raw = original.clone();
        match name {
            "valid" => (),
            "overlong" => raw.push(0xa5),
            "truncated-proof" => raw.truncate(320 + proof_length - 96),
            "identity-proof" => raw[320..352].fill(0),
            "noncanonical-scalar" => {
                raw[320 + proof_length - 96..320 + proof_length - 64].fill(0xff)
            }
            "malformed-p" => raw[320 + proof_length..352 + proof_length].fill(0),
            "malformed-v" => raw
                [320 + proof_length + ACCUMULATOR_BYTES..352 + proof_length + ACCUMULATOR_BYTES]
                .fill(0),
            "noncanonical-public" => raw[66..98].fill(0xff),
            _ => unreachable!(),
        }
        let (values, proposal) = expected(&p, &v, &artifact, &raw);
        assert_eq!(proposal.valid, name == "valid");
        if name == "valid" {
            assert_eq!(values, positive);
        }
        if name == "overlong" {
            assert_eq!(values[0], Fp::ZERO);
            assert_eq!(values[1], Fp::ONE);
            assert_eq!(p_words(&proposal.opening), p_words(&native.opening));
            assert_ne!(values[116], positive[116]);
        }
        if matches!(
            name,
            "truncated-proof" | "identity-proof" | "noncanonical-scalar"
        ) {
            assert_eq!(values[1], Fp::ZERO);
        }
        let circuit = LocalBoundary {
            original: raw.clone(),
            ..base.clone()
        };
        let public = vec![values.clone()];
        assert!(
            check_circuit(&circuit, K, &public, CheckMode::Strict)
                .expect("fixed k16 only; capacity failure is unresolved, never retry larger")
                .is_satisfied(),
            "{name}"
        );
        if name == "valid" {
            let known = synthesize(&circuit, K, Some(&public)).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), K, None).unwrap();
            let desc = wrapper_descriptor(&known);
            assert_eq!(desc, wrapper_descriptor(&unknown));
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(
                known.tables.fixed_assigned(),
                unknown.tables.fixed_assigned()
            );
            assert_eq!(known.tables.selectors(), unknown.tables.selectors());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            assert_eq!(
                known.tables.permutation().mapping_digest(),
                unknown.tables.permutation().mapping_digest()
            );
            retain(&output, "local-wrapper.descriptor.norito", desc.encoded());
            retain(
                &output,
                "local-wrapper.copy-digest",
                &known.tables.permutation().mapping_digest(),
            );
        }
        if name == "overlong" {
            // Final validity stays zero: neither the real opening nor original-byte
            // provenance may become an unconstrained don't-care on that branch.
            for index in [OPENING_START + 1, OPENING_START + 3, OUTPUT_WORDS - 1] {
                let mut forged = public.clone();
                forged[0][index] += Fp::ONE;
                assert_eq!(forged[0][0], Fp::ZERO);
                assert!(
                    !check_circuit(&circuit, K, &forged, CheckMode::Strict)
                        .unwrap()
                        .is_satisfied(),
                    "forged output {index}"
                );
            }
        }
        retain(&output, &format!("{name}.original.bin"), &raw);
        retain(
            &output,
            &format!("{name}.expected.bin"),
            &words_bytes(&values),
        );
        assert_eq!(
            bounded(&output.join(format!("{name}.original.bin")), raw.len()),
            raw
        );
        assert_eq!(
            bounded(
                &output.join(format!("{name}.expected.bin")),
                OUTPUT_WORDS * 32
            ),
            words_bytes(&values)
        );
        cases.push(norito::json!({"name":name,"original_bytes":(raw.len()),"original_sha256":(hex(&sha(&raw))),
            "expected_sha256":(hex(&sha(&words_bytes(&values)))),"final_valid":(proposal.valid),
            "local_valid":(values[1] == Fp::ONE)}));
    }
    fixture.recheck();
    for (name, bytes) in NAMES.iter().zip(&fixture.originals) {
        assert_eq!(bounded(&output.join(name), bytes.len()), *bytes);
    }
    retain(&output, "result.json", &norito::json::to_vec(&norito::json!({
        "scope":"current Omega local native/verifier/decoder differential; test-only joins, full A owner integration outstanding",
        "generated_proofs":0,"key_generation":0,"k":16,"cases":cases,
        "native_full_and_three_decisions":true,"known_unknown_local_layout_equal":true,
        "forged_outputs_rejected_with_final_valid_zero":3,"full_incoming_owner_qualified":false,
        "fixture_manifest_sha256":(hex(&sha(&fixture.manifest_bytes))),
        "descriptor_sha256":(hex(&fixture.manifest.files[0].sha256)),"key_sha256":(hex(&fixture.manifest.files[1].sha256))
    })).unwrap());
}
