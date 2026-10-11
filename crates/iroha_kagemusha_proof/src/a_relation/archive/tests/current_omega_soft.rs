//! Deferred current-Omega incoming API differential against retained native case outputs.
//!
//! Uses the actual ArchiveReceive AProofPlan and incoming decoder/verifier chain.
//! It does not qualify a complete Archive/Receive operation, fold or release.

use super::{
    omega_fixture::{LoadedFixture, NAMES, bounded, hex, pin, retain, sha, words_bytes},
    real_sources,
};
use crate::a_relation::{
    AProofPlan, incoming_transport::IncomingTransportPlan, proof::IncomingProofBinding,
    split::bind_proof,
};
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fp};
use iroha_plonk::{
    DescriptorBinding, Protocol, VerifyingKey,
    check::{CheckMode, check_circuit},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Instance, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1,
        TranscriptV2,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Synthesized, Value, synthesize},
};
use iroha_plonk_gadgets::{
    UintChip, Word,
    bytes::{
        p_bytes_native,
        tape::{BytesChip, BytesConfig},
        variable::ActiveBytes,
    },
};
use iroha_plonk_recursion::{
    ACCUMULATOR_BYTES,
    accumulation_circuit::FoldInputCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::{
    fs::{self, File},
    path::PathBuf,
};

const K: u32 = 16;
const RAW_DOMAIN: u64 = u64::from_le_bytes(*b"kgwlin_1");
const NATIVE_WORDS: usize = 117;
// Native columns [0] + [5..117]: final validity, carried key, public18,
// safe P35/V21, actual local opening35, exact original length/digest.
// Local/public/P/V component bits are not reconstructed in this consumer.
const OUTPUT_WORDS: usize = 113;
const OPENING_START: usize = 76;
const CASES: [&str; 8] = [
    "valid",
    "overlong",
    "truncated-proof",
    "identity-proof",
    "noncanonical-scalar",
    "malformed-p",
    "malformed-v",
    "noncanonical-public",
];
const FORGED_INDICES: [usize; 11] = [0, 1, 7, 21, 23, 56, 60, 77, 79, 111, 112];

#[derive(Clone)]
struct IncomingBoundary {
    decode_plan: IncomingTransportPlan,
    operation: AProofPlan,
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
impl Circuit<Fp> for IncomingBoundary {
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
            || "current Omega actual incoming transport owner",
            |mut r| {
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
                    &self.decode_plan.active_segments()?,
                )?;
                let program = self.decode_plan.verifier();
                let digest = self
                    .key
                    .kagemusha_digest(program.binding())
                    .map_err(|_| Error::Synthesis)?;
                let carried = chip.uint().glue().constant(&mut r, digest)?;
                let transport = self
                    .decode_plan
                    .decode_active(&mut chip, &mut r, &raw, &carried)?;
                let key = chip.constant_key(&mut r, program, &self.key)?;
                // This is the production chain. No locally supplied decoder bits
                // or test-only conjunction determine incoming.valid.
                let incoming =
                    transport.verify(&mut chip, &mut r, &self.operation, &key, &carried)?;
                let IncomingProofBinding::Messages(proof) = &incoming.proof else {
                    return Err(Error::Synthesis);
                };
                // Exercise the returned exact proof view as well as the active
                // carrier. Reuse production copy binding, including all 256 bits.
                bind_proof(&mut r, proof, transport.proof())?;
                let mut out = vec![incoming.valid.word().clone(), incoming.carried_key.clone()];
                out.extend(incoming.public.iter().cloned());
                append_p(&mut out, &incoming.pallas);
                out.push(
                    chip.uint()
                        .glue()
                        .constant(&mut r, Fp::from(u64::from(incoming.vesta.source_k())))?,
                );
                out.extend(incoming.vesta.words());
                append_p(&mut out, &incoming.opening);
                let carrier = transport.active_carrier()?;
                out.push(carrier.length().word().clone());
                let lanes = chip.operation_lanes()?;
                let mut uint = UintChip::new(lanes.glue, lanes.range);
                out.push(carrier.packed().digest(
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
fn field_words(bytes: &[u8], count: usize) -> Vec<Fp> {
    assert_eq!(bytes.len(), count * 32);
    bytes
        .chunks_exact(32)
        .map(|b| {
            Option::<Fp>::from(Fp::from_repr(b.try_into().unwrap()))
                .expect("canonical native output")
        })
        .collect()
}
fn mutation(original: &[u8], proof_length: usize, name: &str) -> Vec<u8> {
    let mut raw = original.to_vec();
    match name {
        "valid" => (),
        "overlong" => raw.push(0xa5),
        "truncated-proof" => raw.truncate(320 + proof_length - 96),
        "identity-proof" => raw[320..352].fill(0),
        "noncanonical-scalar" => raw[320 + proof_length - 96..320 + proof_length - 64].fill(0xff),
        "malformed-p" => raw[320 + proof_length..352 + proof_length].fill(0),
        "malformed-v" => raw
            [320 + proof_length + ACCUMULATOR_BYTES..352 + proof_length + ACCUMULATOR_BYTES]
            .fill(0),
        "noncanonical-public" => raw[66..98].fill(0xff),
        _ => panic!("fixed case inventory"),
    }
    raw
}
struct NativeCase {
    name: &'static str,
    raw: Vec<u8>,
    native_bytes: Vec<u8>,
    native: Vec<Fp>,
    expected: Vec<Fp>,
}
struct NativeCases {
    root: PathBuf,
    _guard: File,
    originals: Vec<(String, Vec<u8>)>,
    cases: Vec<NativeCase>,
}
impl NativeCases {
    fn read(fixture: &LoadedFixture, proof_length: usize) -> Self {
        let root = PathBuf::from(
            std::env::var("KAGEMUSHA_INCOMING_NATIVE_CASES")
                .expect("separately admitted native case outputs"),
        );
        assert!(fs::symlink_metadata(&root).unwrap().file_type().is_dir());
        let guard = File::open(&root).unwrap();
        guard
            .try_lock()
            .expect("immutable completed native output only");
        let result = bounded(&root.join("result.json"), 65_536);
        let selected = pin(&std::env::var("KAGEMUSHA_INCOMING_NATIVE_RESULT_SHA256")
            .expect("independently selected native result"));
        assert_eq!(sha(&result), selected);
        let value: norito::json::Value = norito::json::from_slice(&result).unwrap();
        assert_eq!(
            value["scope"].as_str(),
            Some(
                "current Omega local native/verifier/decoder differential; test-only joins, full A owner integration outstanding"
            )
        );
        assert_eq!(value["k"].as_u64(), Some(16));
        assert_eq!(value["generated_proofs"].as_u64(), Some(0));
        assert_eq!(value["key_generation"].as_u64(), Some(0));
        for flag in [
            "native_full_and_three_decisions",
            "known_unknown_local_layout_equal",
        ] {
            assert_eq!(value[flag].as_bool(), Some(true));
        }
        assert_eq!(
            value["full_incoming_owner_qualified"].as_bool(),
            Some(false)
        );
        assert_eq!(
            value["forged_outputs_rejected_with_final_valid_zero"].as_u64(),
            Some(3)
        );
        for (field, hash) in [
            ("fixture_manifest_sha256", sha(&fixture.manifest_bytes)),
            ("descriptor_sha256", fixture.manifest.files[0].sha256),
            ("key_sha256", fixture.manifest.files[1].sha256),
        ] {
            assert_eq!(value[field].as_str(), Some(hex(&hash).as_str()));
        }
        let mut originals = vec![("result.json".to_owned(), result.clone())];
        for (name, bytes) in [
            ("fixture.norito", &fixture.manifest_bytes),
            ("producer-receipt.json", &fixture.producer_receipt),
        ]
        .into_iter()
        .chain(NAMES.iter().copied().zip(fixture.originals.iter()))
        {
            assert_eq!(bounded(&root.join(name), bytes.len()), *bytes);
            originals.push((name.to_owned(), bytes.clone()));
        }
        let entries = value["cases"].as_array().unwrap();
        assert_eq!(entries.len(), CASES.len());
        let capacity = 320 + proof_length + 2 * ACCUMULATOR_BYTES + 1;
        let mut cases = Vec::new();
        for (name, entry) in CASES.into_iter().zip(entries) {
            assert_eq!(entry["name"].as_str(), Some(name));
            let raw_name = format!("{name}.original.bin");
            let expected_name = format!("{name}.expected.bin");
            let raw = bounded(&root.join(&raw_name), capacity);
            let native_bytes = bounded(&root.join(&expected_name), NATIVE_WORDS * 32);
            assert_eq!(entry["original_bytes"].as_u64(), Some(raw.len() as u64));
            assert_eq!(
                entry["original_sha256"].as_str(),
                Some(hex(&sha(&raw)).as_str())
            );
            assert_eq!(
                entry["expected_sha256"].as_str(),
                Some(hex(&sha(&native_bytes)).as_str())
            );
            let native = field_words(&native_bytes, NATIVE_WORDS);
            for bit in &native[..5] {
                assert!(*bit == Fp::ZERO || *bit == Fp::ONE);
            }
            assert_eq!(entry["final_valid"].as_bool(), Some(native[0] == Fp::ONE));
            assert_eq!(entry["local_valid"].as_bool(), Some(native[1] == Fp::ONE));
            assert_eq!(native[0], Fp::from(u64::from(name == "valid")));
            assert_eq!(native[115], Fp::from(raw.len() as u64));
            assert_eq!(native[116], p_bytes_native(RAW_DOMAIN, &raw));
            let expected = std::iter::once(native[0])
                .chain(native[5..].iter().copied())
                .collect::<Vec<_>>();
            assert_eq!(expected.len(), OUTPUT_WORDS);
            originals.extend([
                (raw_name, raw.clone()),
                (expected_name, native_bytes.clone()),
            ]);
            cases.push(NativeCase {
                name,
                raw,
                native_bytes,
                native,
                expected,
            });
        }
        let good = &cases[0];
        assert_eq!(&good.native[..5], &[Fp::ONE; 5]);
        assert_eq!(good.raw.len(), capacity - 1);
        assert_eq!(
            &good.raw[320..320 + proof_length],
            fixture.originals[2].as_slice()
        );
        assert_eq!(
            &good.raw[320 + proof_length..320 + proof_length + ACCUMULATOR_BYTES],
            fixture.originals[4].as_slice()
        );
        assert_eq!(
            &good.raw[320 + proof_length + ACCUMULATOR_BYTES..],
            fixture.originals[5].as_slice()
        );
        assert_eq!(words_bytes(&good.native[6..24]), fixture.originals[3]);
        for case in &cases {
            assert_eq!(case.raw, mutation(&good.raw, proof_length, case.name));
        }
        assert_eq!(
            cases[1].native[1],
            Fp::ONE,
            "outer failure retains native local success"
        );
        assert_eq!(cases[1].native[80..115], good.native[80..115]);
        assert_ne!(cases[1].native[116], good.native[116]);
        for case in &cases[2..5] {
            assert_eq!(case.native[1], Fp::ZERO);
        }
        Self {
            root,
            _guard: guard,
            originals,
            cases,
        }
    }
    fn recheck(&self) {
        for (name, bytes) in &self.originals {
            assert_eq!(bounded(&self.root.join(name), bytes.len()), *bytes);
        }
    }
}

#[test]
#[ignore = "current six-file Omega fixture + admitted native soft case outputs; five real VK keygens and fixed-k16 checks, no new proofs"]
fn current_omega_incoming_api_matches_native_originals_and_rejects_forged_outputs() {
    let fixture = real_sources::read_selected_fixture();
    let (binding, key) =
        real_sources::captured_metadata(&fixture.originals[0], &fixture.originals[1]).unwrap();
    assert_eq!(key.to_bytes(), fixture.originals[1]);
    let proof_length = Protocol::new(binding.descriptor()).unwrap().proof_length();
    assert!(proof_length >= 96 && proof_length.is_multiple_of(32));
    assert_eq!(fixture.originals[2].len(), proof_length);
    let native = NativeCases::read(&fixture, proof_length);
    let key_digest = key.kagemusha_digest(&binding).unwrap();
    for case in &native.cases {
        assert_eq!(case.native[5], key_digest);
    }
    assert_eq!(native.cases[0].native[23], key_digest);
    let output =
        PathBuf::from(std::env::var("KAGEMUSHA_INCOMING_BOUNDARY_OUTPUT").expect("fresh output"));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&output)
        .expect("fresh output, no replacement/resume");
    // Preserve admitted inputs before potentially expensive actual plan keygen.
    for (name, bytes) in &native.originals {
        let name = if name == "result.json" {
            "native-result.json"
        } else {
            name
        };
        retain(&output, name, bytes);
    }
    let (operation, _policy, selected_key) =
        real_sources::captured_operation(Variant::ArchiveReceive, binding.clone(), key.clone(), 12);
    assert_eq!(operation.frame().variant(), Variant::ArchiveReceive);
    assert_eq!(operation.q_count(), 3);
    assert_eq!(selected_key.to_bytes(), key.to_bytes());
    assert_eq!(operation.omega().unwrap().binding(), &binding);
    let decode_plan = IncomingTransportPlan::new(&operation).unwrap();
    assert_eq!(
        decode_plan.payload_length().unwrap(),
        native.cases[0].raw.len()
    );
    let base = IncomingBoundary {
        decode_plan,
        operation,
        key,
        original: native.cases[0].raw.clone(),
        capacity: native.cases[0].raw.len() + 1,
        known: true,
    };
    let mut observed = Vec::new();
    for case in &native.cases {
        let circuit = IncomingBoundary {
            original: case.raw.clone(),
            ..base.clone()
        };
        let public = vec![case.expected.clone()];
        assert!(
            check_circuit(&circuit, K, &public, CheckMode::Strict)
                .expect("fixed k16; no wider fallback if capacity fails")
                .is_satisfied(),
            "{}",
            case.name
        );
        if case.name == "valid" {
            let known = synthesize(&circuit, K, Some(&public)).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), K, None).unwrap();
            let descriptor = wrapper_descriptor(&known);
            assert_eq!(descriptor, wrapper_descriptor(&unknown));
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
            retain(
                &output,
                "incoming-wrapper.descriptor.norito",
                descriptor.encoded(),
            );
            retain(
                &output,
                "incoming-wrapper.copy-digest",
                &known.tables.permutation().mapping_digest(),
            );
        }
        if case.name == "overlong" {
            assert_eq!(public[0][0], Fp::ZERO);
            assert_eq!(
                public[0][OPENING_START..OPENING_START + 35],
                native.cases[0].expected[OPENING_START..OPENING_START + 35]
            );
            for index in FORGED_INDICES {
                let mut forged = public.clone();
                forged[0][index] += Fp::ONE;
                if index != 0 {
                    assert_eq!(forged[0][0], Fp::ZERO);
                }
                assert!(
                    !check_circuit(&circuit, K, &forged, CheckMode::Strict)
                        .unwrap()
                        .is_satisfied(),
                    "forged output {index}"
                );
            }
        }
        let projected = words_bytes(&case.expected);
        let projected_name = format!("{}.projected.bin", case.name);
        retain(&output, &projected_name, &projected);
        assert_eq!(
            bounded(&output.join(&projected_name), OUTPUT_WORDS * 32),
            projected
        );
        observed.push(
            norito::json!({"name":(case.name),"original_sha256":(hex(&sha(&case.raw))),
            "native_expected_sha256":(hex(&sha(&case.native_bytes))),
            "projected_sha256":(hex(&sha(&words_bytes(&case.expected)))),
            "final_valid":(case.expected[0] == Fp::ONE)}),
        );
    }
    // Rejection-only metadata mutation. Existing gates are reordered, not
    // replaced by a synthetic source; this binding/key pair is never admitted.
    // Original decoder + foreign operation must error before returning a soft bit.
    let mut foreign = CircuitDescriptorV2::decode(binding.encoded()).unwrap();
    assert!(foreign.gates.len() > 1);
    foreign.gates.reverse();
    let foreign = DescriptorBinding::new_v2(foreign).unwrap();
    assert_ne!(foreign, binding);
    let original_program = base.operation.omega().unwrap();
    let foreign_plan = AProofPlan::new(
        Variant::ArchiveReceive,
        base.operation.sigma.clone(),
        (0..base.operation.q_count())
            .map(|i| base.operation.q(i).unwrap().clone())
            .collect(),
        Some(VerifierPlan::new(foreign.clone(), original_program.params().clone()).unwrap()),
        original_program.params(),
    )
    .unwrap();
    let mismatch = IncomingBoundary {
        operation: foreign_plan,
        ..base.clone()
    };
    assert!(
        matches!(synthesize(&mismatch, K, None), Err(Error::Synthesis)),
        "descriptor mismatch is an API error, not a soft false result"
    );
    retain(
        &output,
        "rejected-operation.descriptor.norito",
        foreign.encoded(),
    );
    fixture.recheck();
    native.recheck();
    for (name, bytes) in &native.originals {
        let name = if name == "result.json" {
            "native-result.json"
        } else {
            name
        };
        assert_eq!(bounded(&output.join(name), bytes.len()), *bytes);
    }
    retain(&output, "result.json", &norito::json::to_vec(&norito::json!({
        "scope":"actual incoming transport/AProofPlan boundary; full ArchiveReceive/Receive operation and folds unqualified",
        "k":16,"generated_proofs":0,"actual_plan_vk_keygens":5,"cases":observed,
        "known_unknown_layout_equal":true,"actual_incoming_verify_chain":true,
        "forged_export_checks":(FORGED_INDICES.len()),"descriptor_mismatch_synthesis_error":true,
        "native_result_sha256":(hex(&sha(&native.originals[0].1))),
        "fixture_manifest_sha256":(hex(&sha(&fixture.manifest_bytes))),
        "descriptor_sha256":(hex(&sha(&fixture.originals[0]))),"key_sha256":(hex(&sha(&fixture.originals[1]))),
        "full_operation_chain_qualified":false
    })).unwrap());
}
