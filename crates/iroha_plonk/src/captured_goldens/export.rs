//! Explicit capture of current native public synthetic development fixtures.
//!
//! The ignored test writes a new external directory and never installs fixtures.
//! Its bootstrap source includes unmatched seed corpora and DATA; the capture is
//! neither an independent implementation oracle nor release/catalog admission.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use ff::PrimeField;
use group::GroupEncoding;
use norito::json::Value;
use sha2::Digest;

use super::{
    Circuit, Ep, Eq, KeygenConfig, MemoryBudget, PastaCurve, PinnedParams, PoseidonField,
    ProofSuffixV1, ProverConfig, ProverRandomness, Sha256, SigmaCircuit, TranscriptV1, WideCircuit,
    Witness, bytes, create_proof, keygen_pk, replay_circuit, validate_matrix, verify_full,
};
use crate::{
    keys::{DescriptorBinding, VerifyingKey, builtin_source_identity_v1},
    verifier::captured_succinct_tests::{native_claim_with_challenges, validate_document},
};

const EXPORT_TEST: &str = "captured_goldens::export::export_current_native_corpora";
const SOURCE_FAMILY: &str = "f17349f2880f818be27f6508950cfaf909354b4a14e3f55bf7375a0fa3d03129";

/// Encode an actual original with canonical lower-case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

/// Hash the exact original bytes, without interpreting their contents.
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Stream an exclusive regular original while checking its physical identity.
pub fn file_pin(path: &Path) -> Value {
    let before = fs::symlink_metadata(path).expect("file metadata");
    assert!(before.is_file(), "regular original required");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(before.nlink(), 1, "exclusive original required");
    }
    let mut source = File::open(path).expect("open exact regular file");
    same_file(
        &before,
        &source.metadata().expect("opened original metadata"),
    );
    let mut hash = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = source.read(&mut buffer).expect("read exact original");
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        length += u64::try_from(count).expect("bounded read");
    }
    same_file(
        &before,
        &source.metadata().expect("retained original metadata"),
    );
    same_file(
        &before,
        &fs::symlink_metadata(path).expect("original path still exists"),
    );
    assert_eq!(length, before.len(), "complete exact original read");
    norito::json!({"sha256": (hex(&hash.finalize())), "bytes": (length)})
}

fn same_file(before: &fs::Metadata, after: &fs::Metadata) {
    assert!(after.is_file(), "original changed kind");
    assert_eq!(before.len(), after.len(), "original changed length");
    assert_eq!(
        before.modified().expect("mtime"),
        after.modified().expect("mtime")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.nlink(),
                before.mode(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.nlink(),
                after.mode(),
                after.ctime(),
                after.ctime_nsec()
            ),
            "original physical identity changed"
        );
    }
}

fn capture_group<C: PastaCurve, Ci: Circuit<C::ScalarExt> + Sync>(
    circuit: &Ci,
    public: Vec<C::ScalarExt>,
    curve: &str,
    family: &str,
    k: u32,
    profile: &str,
    seeds: &[u8],
) -> Vec<Value>
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let params = PinnedParams::<C>::derive(k).expect("pinned native parameters");
    let mut config = match profile {
        "blake" => KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
        "poseidon" => {
            let mut config = KeygenConfig::new(TranscriptV1::KagemushaPoseidonRp57);
            config.proof_suffix = ProofSuffixV1::FoldedGenerator;
            config
        }
        _ => panic!("closed native corpus profile"),
    };
    // Preserve the public Sigma/Wide uncompressed-selector matrix. The actual
    // generated descriptor records this choice; no old key or proof is reused.
    config.compress_selectors = false;
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config)
        .expect("current native circuit key generation");
    let instances = vec![public];
    let witness = Witness::from_circuit(&pk, circuit, &instances)
        .expect("synthetic witness matches current key");
    let mut cases = Vec::new();
    for &seed in seeds {
        let proof = create_proof(
            &params,
            &pk,
            &witness,
            ProverRandomness::fixed_seed_for_tests([seed; 32]),
            ProverConfig::default(),
        )
        .expect("native proof with deterministic test-only entropy");
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &instances,
            &proof,
            MemoryBudget::DEFAULT,
        )
        .expect("complete native verification before capture");
        let encoded_instances = instances
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|value| hex(value.to_repr().as_ref()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        cases.push(norito::json!({
            "curve": (curve), "family": (family), "k": (k), "profile": (profile),
            "seed_byte": (seed), "descriptor": (hex(pk.binding().encoded())),
            "verifying_key": (hex(pk.vk().to_bytes())), "instances": (encoded_instances),
            "transcript_repr": (hex(&pk.vk().transcript_repr_bytes())),
            "proof": (hex(&proof)), "proof_sha256": (digest(&proof)),
            "params_sha256": (hex(&params.digest())),
        }));
    }
    // Reuse every maintained key/proof equality, worker1/2/4/7 and mutation check.
    replay_circuit::<C, _>(
        circuit,
        instances[0].clone(),
        &cases.iter().collect::<Vec<_>>(),
    );
    cases
}

fn capture_curve<C: PastaCurve>(curve: &str) -> Vec<Value>
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let mut cases = Vec::new();
    for k in [6, 9, 11] {
        let circuit = SigmaCircuit::<C::ScalarExt>::new(k);
        for profile in ["blake", "poseidon"] {
            cases.extend(capture_group::<C, _>(
                &circuit,
                circuit.public(),
                curve,
                "sigma",
                k,
                profile,
                &[42, 43],
            ));
        }
    }
    for k in [8, 10, 13] {
        let circuit = WideCircuit::<C::ScalarExt>::new(k);
        for profile in ["blake", "poseidon"] {
            if k == 13 && profile == "poseidon" {
                continue;
            }
            cases.extend(capture_group::<C, _>(
                &circuit,
                circuit.public(),
                curve,
                "wide",
                k,
                profile,
                if k == 13 { &[167] } else { &[42, 43] },
            ));
        }
    }
    cases
}

fn succinct_case<C: PastaCurve>(case: &Value) -> Value
where
    C::Base: PoseidonField,
    C::ScalarExt: PoseidonField,
{
    let k = u32::try_from(case["k"].as_u64().expect("case exponent")).expect("bounded k");
    let params = PinnedParams::<C>::derive(k).expect("same pinned native parameters");
    let binding = DescriptorBinding::decode(&bytes(&case["descriptor"]))
        .expect("admit captured descriptor original");
    let vk = VerifyingKey::<C>::read(&bytes(&case["verifying_key"]), &binding)
        .expect("admit captured key original");
    let instances = case["instances"]
        .as_array()
        .expect("columns")
        .iter()
        .map(|column| {
            column
                .as_array()
                .expect("column values")
                .iter()
                .map(super::scalar::<C::ScalarExt>)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let proof = bytes(&case["proof"]);
    let (claim, challenges) = native_claim_with_challenges(
        &params,
        &binding,
        &vk,
        &instances,
        &proof,
        MemoryBudget::DEFAULT,
    )
    .expect("actual native claim and raw squeeze tape");
    claim
        .clone()
        .decide(&params, MemoryBudget::DEFAULT)
        .expect("complete generator decision before publication");
    let rounds = claim.challenges();
    let generator = claim.g().to_bytes();
    let mut tape = Vec::new();
    for value in &challenges {
        tape.extend_from_slice(value.to_repr().as_ref());
    }
    tape.extend_from_slice(generator.as_ref());
    for value in rounds {
        tape.extend_from_slice(value.to_repr().as_ref());
    }
    let mut result = case.clone();
    let record = result.as_object_mut().expect("captured case object");
    record.remove("profile");
    record.insert(
        "family".to_owned(),
        Value::String(match case["family"].as_str() {
            Some("sigma") => "Sigma".to_owned(),
            Some("wide") => "Wide".to_owned(),
            _ => panic!("closed source family"),
        }),
    );
    record.insert("g".to_owned(), Value::String(hex(generator.as_ref())));
    record.insert(
        "u".to_owned(),
        norito::json!(
            rounds
                .iter()
                .map(|value| hex(value.to_repr().as_ref()))
                .collect::<Vec<_>>()
        ),
    );
    record.insert(
        "challenges".to_owned(),
        norito::json!(
            challenges
                .iter()
                .map(|value| hex(value.to_repr().as_ref()))
                .collect::<Vec<_>>()
        ),
    );
    record.insert("tape_sha256".to_owned(), Value::String(digest(&tape)));
    record.insert(
        "mutations".to_owned(),
        norito::json!([
            "instance:reject",
            "proof:reject",
            "suffix:reject",
            "trailing:reject",
            "truncated:reject"
        ]),
    );
    result
}

/// Claim a new capture directory outside the source tree, without replacement.
pub fn create_output(path: &Path) {
    assert!(path.is_absolute(), "absolute output directory required");
    let parent = path.parent().expect("output parent");
    assert_eq!(
        parent.canonicalize().expect("existing output parent"),
        parent
    );
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .canonicalize()
        .expect("canonical build root");
    assert!(
        !path.starts_with(source_root),
        "capture outside the source checkout"
    );
    assert!(
        !path.exists(),
        "never replace an existing capture or fixture"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        assert_eq!(
            fs::metadata(parent)
                .expect("parent metadata")
                .permissions()
                .mode()
                & 0o077,
            0,
            "owner-only parent required"
        );
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .expect("create a new private capture directory");
    }
    #[cfg(not(unix))]
    panic!("this development exporter requires an owner-only Unix capture directory");
    assert_eq!(path.canonicalize().expect("new output"), path);
}

/// Publish one new read-only original and verify its exact bytes before returning.
pub fn write_original(directory: &Path, name: &str, value: &Value) -> Value {
    let mut components = Path::new(name).components();
    assert!(
        matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none(),
        "one output filename required"
    );
    let path = directory.join(name);
    let mut payload = norito::json::to_vec_pretty(value).expect("Norito JSON serialization");
    payload.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut file = options
        .open(&path)
        .expect("create output without replacement");
    file.write_all(&payload).expect("write complete original");
    file.sync_all().expect("durable output file");
    let expected = norito::json!({"sha256": (digest(&payload)), "bytes": (payload.len())});
    assert_eq!(
        file_pin(&path),
        expected,
        "written original matches captured bytes"
    );
    expected
}

#[test]
#[ignore = "explicit native corpus capture; requires a new private external output directory"]
fn export_current_native_corpora() {
    let directory = PathBuf::from(
        std::env::var_os("IROHA_NATIVE_PROVER_CAPTURE_DIR")
            .expect("select a new absolute private external capture directory"),
    );
    create_output(&directory);
    let executable = std::env::current_exe()
        .expect("current native test executable")
        .canonicalize()
        .expect("canonical current executable");
    let executable_pin = file_pin(&executable);
    let source = builtin_source_identity_v1().expect("complete build-time source census");
    let provenance = norito::json!({
        "schema": ("iroha.native_prover.capture.v1"), "generator_test": (EXPORT_TEST),
        "generator_executable": (executable_pin.clone()), "bootstrap_source_digest": (hex(&source)),
        "compiled_source_closure_complete": (true),
        "scope": ("Current native synthetic proof capture; bootstrap source includes unmatched seed corpora and DATA. Not an independent implementation oracle, final catalog, release or monetary admission."),
        "transcript": ("ordinary native descriptor-bound framing; no historical representation override"),
        "seed_goldens_sha256": (digest(include_bytes!("../../../../fixtures/native_prover/golden_sources_v1.json"))),
        "seed_succinct_sha256": (digest(include_bytes!("../../../../fixtures/native_prover/succinct_v1.json"))),
        "seed_builtin_data_sha256": (digest(include_bytes!("../keys/keygen/builtin/generated.rs"))),
        "synthetic_circuits_sha256": (digest(include_bytes!("circuits.rs"))),
        "exporter_source_sha256": (digest(include_bytes!("export.rs"))),
        "worker_counts": ([1, 2, 4, 7]), "shipping_qualification": (false),
        "challenge_tape": ("scalar after field conversion, before role maps; not raw base-field Theta"),
    });
    let start = write_original(&directory, "capture-start.json", &provenance);
    let mut cases = capture_curve::<Ep>("ep");
    cases.extend(capture_curve::<Eq>("eq"));
    let golden = norito::json!({"format": ("iroha.native_prover.golden_sources.v1"),
        "original_circuit_source_sha256": (SOURCE_FAMILY),
        "capture": (provenance.clone()), "cases": (cases.clone())});
    validate_matrix(&golden);
    let mut succinct = Vec::new();
    for case in &cases {
        if case["profile"].as_str() == Some("poseidon")
            && matches!(
                (case["family"].as_str(), case["k"].as_u64()),
                (Some("sigma"), Some(6)) | (Some("wide"), Some(8))
            )
        {
            succinct.push(match case["curve"].as_str() {
                Some("ep") => succinct_case::<Ep>(case),
                Some("eq") => succinct_case::<Eq>(case),
                _ => panic!("closed curve matrix"),
            });
        }
    }
    let succinct = norito::json!({"format": ("iroha.native_prover.succinct.v1"),
        "capture": (provenance), "cases": (succinct)});
    // Reuse all matrix/tape, complete-decision, forged-round and five original mutations.
    validate_document::<Ep>(&succinct, "ep");
    validate_document::<Eq>(&succinct, "eq");
    let golden_pin = write_original(&directory, "golden_sources_v1.json", &golden);
    let succinct_pin = write_original(&directory, "succinct_v1.json", &succinct);
    assert_eq!(
        file_pin(&executable),
        executable_pin,
        "capture executable unchanged"
    );
    for (name, expected) in [
        ("capture-start.json", &start),
        ("golden_sources_v1.json", &golden_pin),
        ("succinct_v1.json", &succinct_pin),
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
                .expect("capture member")
                .file_name()
                .into_string()
                .expect("UTF-8 filename")
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        members,
        [
            "capture-start.json",
            "golden_sources_v1.json",
            "succinct_v1.json"
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
    File::open(&directory)
        .expect("output directory")
        .sync_all()
        .expect("durable originals");
    let receipt = norito::json!({
        "schema": ("iroha.native_prover.capture-result.v1"), "generator_test": (EXPORT_TEST),
        "generator_executable": (executable_pin), "bootstrap_source_digest": (hex(&source)),
        "capture_start": (start), "golden_sources": (golden_pin), "succinct": (succinct_pin),
        "golden_cases": (42), "succinct_cases": (8), "current_native_production_framing": (true),
        "full_verification_and_mutations_passed": (true), "shipping_qualification": (false),
        "admission_requires_successful_test_exit_and_terminal": (true),
        "passed": (true),
    });
    write_original(&directory, "capture-result.json", &receipt);
    File::open(&directory)
        .expect("output directory")
        .sync_all()
        .expect("durable directory");
    println!("NATIVE_CORPUS_CAPTURE_COMPLETE golden_cases=42 succinct_cases=8");
}

#[cfg(unix)]
#[test]
fn capture_outputs_refuse_replacement_aliases_and_path_escape() {
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    let temporary = std::env::temp_dir()
        .canonicalize()
        .expect("temporary parent");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let parent = temporary.join(format!(
        "iroha-native-capture-{}-{nonce}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&parent)
        .expect("private test owner");
    let output = parent.join("capture");
    create_output(&output);
    let value = norito::json!({"retained": (7)});
    let original = write_original(&output, "original.json", &value);
    assert!(std::panic::catch_unwind(|| create_output(&output)).is_err());
    assert!(
        std::panic::catch_unwind(|| write_original(&output, "original.json", &Value::Null))
            .is_err()
    );
    assert_eq!(file_pin(&output.join("original.json")), original);
    assert!(
        std::panic::catch_unwind(|| write_original(&output, "../escape.json", &value)).is_err()
    );
    assert!(!parent.join("escape.json").exists());
    symlink(output.join("original.json"), output.join("alias.json")).expect("test alias");
    assert!(std::panic::catch_unwind(|| file_pin(&output.join("alias.json"))).is_err());
    fs::remove_file(output.join("alias.json")).expect("remove test alias");
    fs::hard_link(output.join("original.json"), output.join("link.json")).expect("test hardlink");
    assert!(std::panic::catch_unwind(|| file_pin(&output.join("original.json"))).is_err());
    fs::remove_file(output.join("link.json")).expect("remove test hardlink");
    assert_eq!(file_pin(&output.join("original.json")), original);
    for length in [0, 1, 65_535, 65_536, 65_537, 131_079] {
        let payload = (0..length)
            .map(|index| u8::try_from(index % 251).expect("remainder fits one byte"))
            .collect::<Vec<_>>();
        let path = output.join(format!("stream-{length}.bin"));
        fs::write(&path, &payload).expect("write this test's fresh stream fixture");
        assert_eq!(
            file_pin(&path),
            norito::json!({
                "sha256": (digest(&payload)), "bytes": (length)
            })
        );
    }
    fs::remove_dir_all(&parent).expect("remove this test's disposable output");
}
