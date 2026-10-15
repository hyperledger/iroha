//! Explicit current native inputs for the independent 46-case reference verifier.
//!
//! This unit-test owner retains every source/profile case without historical
//! transcript overrides. It writes a new external directory, never the canonical
//! fixture. Native full verification is a producer check, not independent evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, PastaCurve, msm::MemoryBudget, poseidon::PoseidonField};
use norito::json::{Map, Value};

use crate::{
    captured_goldens::{
        circuits::{SigmaCircuit, WideCircuit},
        export::{create_output, digest, file_pin, hex, write_original},
    },
    cs::{InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1, TranscriptV2},
    frontend::Circuit,
    keys::{
        KeygenConfig, KeygenConfigV2, ProvingKey, builtin_source_identity_v1, keygen_pk,
        keygen_pk_v2,
    },
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverRandomness, Witness, create_proof},
    verifier::verify_full,
};

const EXPORT_TEST: &str = "native_reference_capture::export_current_reference_corpus";
const FORMAT: &str = "iroha.native_prover.reference.v1";

/// The complete first-release matrix, independent of any stored proof or verdict.
fn expected_cases() -> BTreeMap<String, (&'static str, u32, u64)> {
    let mut names = BTreeMap::new();
    for curve in ["ep", "eq"] {
        for profile in ["blake", "poseidon"] {
            for k in [6, 8] {
                names.insert(format!("{curve}/native/{profile}/{k}"), (curve, k, 1));
            }
            for mode in ["Committed", "Direct"] {
                for compressed in [false, true] {
                    names.insert(
                        format!("{curve}/v1/{profile}/{mode}/{compressed}"),
                        (curve, 6, 1),
                    );
                }
                names.insert(format!("{curve}/v2/{profile}/{mode}/field"), (curve, 6, 2));
            }
        }
        names.insert(format!("{curve}/v2/base/Direct/field"), (curve, 6, 2));
        names.insert(format!("{curve}/v2/base/k6/bits4"), (curve, 6, 2));
        for k in 6..=10 {
            names.insert(
                format!("{curve}/v2/base/k{k}/bounded-or-field"),
                (curve, k, 2),
            );
        }
    }
    names
}

/// Refuse omitted, duplicated, relabeled or historical-override cases.
fn validate_matrix(document: &Value) {
    assert_eq!(document["format"].as_str(), Some(FORMAT));
    let cases = document["cases"].as_array().expect("reference cases");
    assert_eq!(cases.len(), 46, "all current reference cases");
    let expected_cases = expected_cases();
    let actual = cases
        .iter()
        .map(|case| {
            let record = case.as_object().expect("reference record");
            assert!(
                !record.contains_key("oracle_repr"),
                "no transcript override"
            );
            let name = case["name"].as_str().expect("case identity");
            let &(curve, k, version) = expected_cases.get(name).expect("current case identity");
            assert_eq!(case["curve"].as_str(), Some(curve), "case curve");
            assert_eq!(case["k"].as_u64(), Some(u64::from(k)), "case domain");
            assert_eq!(
                case["descriptor_version"].as_u64(),
                Some(version),
                "case descriptor version"
            );
            name.to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        expected_cases.into_keys().collect(),
        "exact native source matrix"
    );
    let parameters = document["parameters"].as_object().expect("parameter map");
    let expected = ["ep", "eq"]
        .into_iter()
        .flat_map(|curve| (6..=10).map(move |k| format!("{curve}/{k}")))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        parameters.keys().cloned().collect::<BTreeSet<_>>(),
        expected
    );
}

/// Prove under the actual descriptor and decide the complete native equation.
fn record<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    curve: &str,
    label: &str,
    k: u32,
    params: &PinnedParams<C>,
    circuit: &Ci,
    instances: &[Vec<C::ScalarExt>],
    pk: &ProvingKey<C>,
) -> Value
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let witness = Witness::from_circuit(pk, circuit, instances)
        .expect("current synthetic witness matches exact native key");
    let proof = create_proof(
        params,
        pk,
        &witness,
        ProverRandomness::fixed_seed_for_tests([42; 32]),
        ProverConfig::default(),
    )
    .expect("ordinary descriptor-bound native proof");
    verify_full(
        params,
        pk.binding(),
        pk.vk(),
        instances,
        &proof,
        MemoryBudget::DEFAULT,
    )
    .expect("complete native proof and generator verification before export");

    // Exercise the same complete verifier boundary on altered public values,
    // proof bytes and exact extents before publishing any accepted original.
    let mut wrong_public = instances.to_vec();
    wrong_public[0][0] += C::ScalarExt::ONE;
    assert!(
        verify_full(
            params,
            pk.binding(),
            pk.vk(),
            &wrong_public,
            &proof,
            MemoryBudget::DEFAULT
        )
        .is_err()
    );
    let mut changed = proof.clone();
    changed[0] ^= 1;
    let mut extended = proof.clone();
    extended.push(0);
    for invalid in [&changed[..], &extended[..], &proof[..proof.len() - 1]] {
        assert!(
            verify_full(
                params,
                pk.binding(),
                pk.vk(),
                instances,
                invalid,
                MemoryBudget::DEFAULT
            )
            .is_err()
        );
    }
    let encoded_instances = instances
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|value| hex(value.to_repr().as_ref()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    norito::json!({
        "name": (format!("{curve}/{label}")), "curve": curve, "k": k,
        "descriptor_version": (if pk.binding().is_v2() { 2_u64 } else { 1_u64 }),
        "descriptor": (hex(pk.binding().encoded())),
        "verifying_key": (hex(pk.vk().to_bytes())),
        "proof": (hex(&proof)), "proof_sha256": (digest(&proof)),
        "instances": encoded_instances,
    })
}

/// Reconstruct one public source family and all profiles assigned to its domain.
fn capture_source<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(
    curve: &str,
    k: u32,
    circuit: &Ci,
    public: Vec<C::ScalarExt>,
    parameters: &mut Map,
    cases: &mut Vec<Value>,
) where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let params = PinnedParams::<C>::derive(k).expect("native pinned parameter derivation");
    assert!(
        parameters
            .insert(
                format!("{curve}/{k}"),
                Value::String(hex(&params.params().to_bytes()))
            )
            .is_none()
    );
    let instances = vec![public];
    let source = circuit.without_witnesses();
    if k == 6 || k == 8 {
        for (profile, transcript) in [
            ("blake", TranscriptV1::Blake2bChallenge255),
            ("poseidon", TranscriptV1::KagemushaPoseidonRp57),
        ] {
            let mut config = KeygenConfig::new(transcript);
            config.instance_mode = InstanceModeV1::Committed;
            config.compress_selectors = false;
            config.proof_suffix = if profile == "poseidon" {
                ProofSuffixV1::FoldedGenerator
            } else {
                ProofSuffixV1::None
            };
            let pk = keygen_pk(&params, &source, &config).expect("native source key");
            cases.push(record(
                curve,
                &format!("native/{profile}/{k}"),
                k,
                &params,
                circuit,
                &instances,
                &pk,
            ));
        }
    }
    if k == 6 {
        for (profile, transcript) in [
            ("blake", TranscriptV1::Blake2bChallenge255),
            ("poseidon", TranscriptV1::KagemushaPoseidonRp57),
        ] {
            for mode in [InstanceModeV1::Committed, InstanceModeV1::Direct] {
                for compressed in [false, true] {
                    let mut config = KeygenConfig::new(transcript);
                    config.instance_mode = mode;
                    config.compress_selectors = compressed;
                    config.proof_suffix = if compressed {
                        ProofSuffixV1::FoldedGenerator
                    } else {
                        ProofSuffixV1::None
                    };
                    let pk = keygen_pk(&params, &source, &config).expect("V1 native source key");
                    cases.push(record(
                        curve,
                        &format!("v1/{profile}/{mode:?}/{compressed}"),
                        k,
                        &params,
                        circuit,
                        &instances,
                        &pk,
                    ));
                }
            }
        }
        for (profile, transcript) in [
            ("blake", TranscriptV2::Blake2bChallenge255),
            ("poseidon", TranscriptV2::KagemushaPoseidonRp57),
            ("base", TranscriptV2::KagemushaPoseidonRp57Base),
        ] {
            for mode in [InstanceModeV1::Committed, InstanceModeV1::Direct] {
                if transcript == TranscriptV2::KagemushaPoseidonRp57Base
                    && mode == InstanceModeV1::Committed
                {
                    continue;
                }
                let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Field]);
                config.transcript = transcript;
                config.instance_mode = mode;
                let pk = keygen_pk_v2(&params, &source, &config).expect("V2 native source key");
                cases.push(record(
                    curve,
                    &format!("v2/{profile}/{mode:?}/field"),
                    k,
                    &params,
                    circuit,
                    &instances,
                    &pk,
                ));
            }
        }
        assert!(
            instances[0]
                .iter()
                .all(|value| (0_u64..16).any(|small| *value == C::ScalarExt::from(small))),
            "the actual Sigma public input must fit the Bits4 case"
        );
        let config = KeygenConfigV2::pipa_r(vec![InstanceType::Bits(4)]);
        let pk = keygen_pk_v2(&params, &source, &config).expect("Bits4 native source key");
        cases.push(record(
            curve,
            "v2/base/k6/bits4",
            k,
            &params,
            circuit,
            &instances,
            &pk,
        ));
    }
    let mut config = KeygenConfigV2::pipa_r(vec![if k == 6 {
        InstanceType::Bounded
    } else {
        InstanceType::Field
    }]);
    config.compress_selectors = k != 8;
    let pk = keygen_pk_v2(&params, &source, &config).expect("typed native source key");
    cases.push(record(
        curve,
        &format!("v2/base/k{k}/bounded-or-field"),
        k,
        &params,
        circuit,
        &instances,
        &pk,
    ));
}

fn capture_curve<C: PastaCurve>(curve: &str, parameters: &mut Map, cases: &mut Vec<Value>)
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    for k in 6..=10 {
        if matches!(k, 8 | 10) {
            let circuit = WideCircuit::<C::ScalarExt>::new(k);
            capture_source::<C, _>(curve, k, &circuit, circuit.public(), parameters, cases);
        } else {
            let circuit = SigmaCircuit::<C::ScalarExt>::new(k);
            capture_source::<C, _>(curve, k, &circuit, circuit.public(), parameters, cases);
        }
    }
}

#[test]
#[ignore = "explicit native46 corpus capture; requires new private external directory"]
fn export_current_reference_corpus() {
    let directory = PathBuf::from(
        std::env::var_os("IROHA_NATIVE_PROVER_CAPTURE_DIR")
            .expect("select new private external capture directory"),
    );
    create_output(&directory);
    let executable = std::env::current_exe()
        .expect("current native test executable")
        .canonicalize()
        .expect("canonical executable");
    let executable_pin = file_pin(&executable);
    let source = builtin_source_identity_v1().expect("complete compiled source census");
    let provenance = norito::json!({
        "schema": "iroha.native_prover.reference-capture.v1", "generator_test": EXPORT_TEST,
        "generator_executable": (executable_pin.clone()), "bootstrap_source_digest": (hex(&source)),
        "compiled_source_closure_complete": true,
        "transcript": "ordinary native descriptor-bound framing; no historical representation override",
        "seed_reference_sha256": (digest(include_bytes!("../../../fixtures/native_prover/reference_v1.json"))),
        "seed_builtin_data_sha256": (digest(include_bytes!("keys/keygen/builtin/generated.rs"))),
        "synthetic_circuits_sha256": (digest(include_bytes!("captured_goldens/circuits.rs"))),
        "exporter_source_sha256": (digest(include_bytes!("native_reference_capture.rs"))),
        "scope": "Native synthetic bootstrap capture with unmatched seed corpus and DATA; current independent reference input, not an independent prover oracle or release/catalog admission.",
        "shipping_qualification": false,
    });
    let start = write_original(&directory, "capture-start.json", &provenance);
    let mut parameters = Map::new();
    let mut cases = Vec::new();
    capture_curve::<Ep>("ep", &mut parameters, &mut cases);
    capture_curve::<Eq>("eq", &mut parameters, &mut cases);
    // Provenance is custody metadata only. The independent reader derives every
    // challenge and equation from the descriptor, key, parameters and proof.
    let document = norito::json!({
        "format": FORMAT, "parameters": parameters, "cases": cases,
        "capture": (provenance.clone()),
    });
    validate_matrix(&document);
    let reference = write_original(&directory, "reference_v1.json", &document);
    assert_eq!(
        file_pin(&executable),
        executable_pin,
        "same capture executable"
    );
    for (name, expected) in [
        ("capture-start.json", &start),
        ("reference_v1.json", &reference),
    ] {
        assert_eq!(
            file_pin(&directory.join(name)),
            *expected,
            "retained original unchanged"
        );
    }
    let members = fs::read_dir(&directory)
        .expect("capture inventory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8 name")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        members,
        ["capture-start.json", "reference_v1.json"]
            .map(str::to_owned)
            .into_iter()
            .collect()
    );
    fs::File::open(&directory)
        .expect("output directory")
        .sync_all()
        .expect("durable originals");
    let receipt = norito::json!({
        "schema": "iroha.native_prover.reference-capture-result.v1", "generator_test": EXPORT_TEST,
        "generator_executable": executable_pin, "bootstrap_source_digest": (hex(&source)),
        "capture_start": start, "reference": reference, "cases": 46, "parameter_sets": 10,
        "current_native_production_framing": true, "native_full_verification_and_mutations_passed": true,
        "independent_python_verification_passed": false, "shipping_qualification": false,
        "admission_requires_successful_test_exit_and_terminal": true, "passed": true,
    });
    write_original(&directory, "capture-result.json", &receipt);
    fs::File::open(&directory)
        .expect("output directory")
        .sync_all()
        .expect("durable receipt");
    println!("NATIVE_REFERENCE_CAPTURE_COMPLETE cases=46 parameters=10");
}

#[test]
fn reference_matrix_is_exact_and_refuses_retired_labels() {
    let names = expected_cases();
    assert_eq!(names.len(), 46);
    for curve in ["ep", "eq"] {
        assert_eq!(
            names
                .keys()
                .filter(|name| name.starts_with(&format!("{curve}/")))
                .count(),
            23
        );
        assert_eq!(
            names
                .keys()
                .filter(|name| name.starts_with(&format!("{curve}/native/")))
                .count(),
            4
        );
    }
    let parameters = ["ep", "eq"]
        .into_iter()
        .flat_map(|curve| {
            (6..=10).map(move |k| (format!("{curve}/{k}"), Value::String(String::new())))
        })
        .collect::<Map>();
    let cases = names
        .iter()
        .map(|(name, (curve, k, version))| {
            norito::json!({
                "name": name, "curve": curve, "k": k, "descriptor_version": version,
            })
        })
        .collect::<Vec<_>>();
    let valid = norito::json!({"format": FORMAT, "parameters": parameters, "cases": cases});
    validate_matrix(&valid);
    let mut duplicate = valid.clone();
    let rows = duplicate
        .get_mut("cases")
        .expect("cases field")
        .as_array_mut()
        .expect("cases");
    rows[1] = rows[0].clone();
    assert!(std::panic::catch_unwind(|| validate_matrix(&duplicate)).is_err());
    let mut retired_label = valid.clone();
    let row = &mut retired_label
        .get_mut("cases")
        .expect("cases field")
        .as_array_mut()
        .expect("cases")[0];
    let name = row["name"]
        .as_str()
        .expect("name")
        .replace("/native/", "/oracle/");
    row.as_object_mut()
        .expect("row")
        .insert("name".to_owned(), Value::String(name));
    assert!(std::panic::catch_unwind(|| validate_matrix(&retired_label)).is_err());
    let mut retired = valid.clone();
    retired
        .get_mut("cases")
        .expect("cases field")
        .as_array_mut()
        .expect("cases")[0]
        .as_object_mut()
        .expect("row")
        .insert("oracle_repr".to_owned(), Value::String("00".repeat(32)));
    assert!(std::panic::catch_unwind(|| validate_matrix(&retired)).is_err());
    for (field, value) in [
        ("curve", Value::String("wrong".to_owned())),
        ("k", norito::json!(99_u64)),
        ("descriptor_version", norito::json!(99_u64)),
    ] {
        let mut wrong_metadata = valid.clone();
        wrong_metadata
            .get_mut("cases")
            .expect("cases field")
            .as_array_mut()
            .expect("cases")[0]
            .as_object_mut()
            .expect("row")
            .insert(field.to_owned(), value);
        assert!(std::panic::catch_unwind(|| validate_matrix(&wrong_metadata)).is_err());
    }
    let mut omitted = valid.clone();
    omitted
        .get_mut("cases")
        .expect("cases field")
        .as_array_mut()
        .expect("cases")
        .pop();
    assert!(std::panic::catch_unwind(|| validate_matrix(&omitted)).is_err());
    let mut missing_parameters = valid.clone();
    missing_parameters
        .get_mut("parameters")
        .expect("parameters field")
        .as_object_mut()
        .expect("parameters")
        .remove("ep/6");
    assert!(std::panic::catch_unwind(|| validate_matrix(&missing_parameters)).is_err());
    let mut old_format = valid;
    old_format.as_object_mut().expect("document").insert(
        "format".to_owned(),
        Value::String("iroha.pipa.reference.v1".to_owned()),
    );
    assert!(std::panic::catch_unwind(|| validate_matrix(&old_format)).is_err());
}
