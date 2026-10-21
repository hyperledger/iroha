use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::{AccountId, address::chain_discriminant};
use pyo3::types::{PyByteArray, PyDict};
use std::sync::OnceLock;

struct Fixture {
    artifact: Vec<u8>,
    code_hash: String,
    abi_hash: String,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (artifact, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                "seiyaku ArgumentPins {
                    view fn quote(AccountId destination, quantity amount) authorize(anyone)
                        -> quantity { amount }
                    view fn ready() authorize(anyone) -> bool { true }
                }",
            )
            .expect("compile actual parameterized artifact");
        let verified = ivm::verify_contract_artifact(&artifact).unwrap();
        Fixture {
            code_hash: hex::encode(verified.code_hash.as_ref()),
            abi_hash: hex::encode(verified.abi_hash.as_ref()),
            artifact,
        }
    })
}

fn account(seed: u8, discriminant: u16) -> String {
    let key = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    AccountId::new(key.public_key().clone())
        .to_i105_for_discriminant(discriminant)
        .unwrap()
}

fn payload(seed: u8, discriminant: u16, amount: &str) -> String {
    format!(
        r#"{{"amount":"{amount}","destination":"{}"}}"#,
        account(seed, discriminant)
    )
}

fn request(payload_json: Option<&str>) -> ArgumentEncodingRequest<'_> {
    let fixture = fixture();
    ArgumentEncodingRequest {
        artifact: &fixture.artifact,
        entrypoint: "quote",
        payload_json,
        expected_code_hash_hex: &fixture.code_hash,
        expected_abi_hash_hex: &fixture.abi_hash,
        chain_discriminant: 369,
    }
}

#[test]
fn contract_argument_encoding_matches_native_schema_and_distinguishes_payment_fields() {
    let text = payload(31, 369, "12.5");
    let encoded = encode(request(Some(&text))).unwrap().unwrap();
    let verified = ivm::verify_contract_artifact(&fixture().artifact).unwrap();
    let schema = verified
        .contract_interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "quote")
        .unwrap()
        .argument_schema
        .as_ref()
        .unwrap();
    let _guard = ChainDiscriminantGuard::enter(369);
    assert_eq!(
        encoded,
        ivm_abi::arguments::encode_argument_record_from_json_detailed(
            schema,
            &Json::from_str_norito(&text).unwrap()
        )
        .unwrap()
    );
    for changed in [payload(31, 369, "12.6"), payload(32, 369, "12.5")] {
        assert_ne!(encoded, encode(request(Some(&changed))).unwrap().unwrap());
    }
}

#[test]
fn contract_argument_encoding_authenticates_entire_artifact_and_both_pins() {
    let text = payload(31, 369, "12.5");
    let wrong_hash = "00".repeat(32);
    let mut wrong_code = request(Some(&text));
    wrong_code.expected_code_hash_hex = &wrong_hash;
    assert!(
        encode(wrong_code)
            .unwrap_err()
            .contains("expected_code_hash_hex")
    );
    let mut wrong_abi = request(Some(&text));
    wrong_abi.expected_abi_hash_hex = &wrong_hash;
    assert!(
        encode(wrong_abi)
            .unwrap_err()
            .contains("expected_abi_hash_hex")
    );
    let mut corrupt = fixture().artifact.clone();
    corrupt[0] ^= 1;
    let mut invalid = request(Some(&text));
    invalid.artifact = &corrupt;
    assert!(
        encode(invalid)
            .unwrap_err()
            .contains("invalid contract artifact")
    );
    for selector in ["missing", " quote", "quote ", ""] {
        let mut invalid = request(Some(&text));
        invalid.entrypoint = selector;
        assert!(encode(invalid).is_err());
    }
    for pin in [
        "AA".repeat(32),
        format!("0x{}", fixture().code_hash),
        "0".repeat(63),
    ] {
        let mut invalid = request(Some(&text));
        invalid.expected_code_hash_hex = &pin;
        assert!(encode(invalid).is_err());
    }
}

#[test]
fn contract_argument_encoding_preserves_absence_and_rejects_null_as_no_arguments() {
    assert!(
        encode(request(None))
            .unwrap_err()
            .contains("requires a payload")
    );
    assert!(encode(request(Some("null"))).is_err());
    let mut no_arguments = request(None);
    no_arguments.entrypoint = "ready";
    assert_eq!(encode(no_arguments).unwrap(), None);
    for text in ["null", "{}", "[]"] {
        let mut supplied = request(Some(text));
        supplied.entrypoint = "ready";
        assert!(
            encode(supplied)
                .unwrap_err()
                .contains("must not receive a payload")
        );
    }
}

#[test]
fn contract_argument_encoding_rejects_inexact_json_fields_and_values() {
    let valid = payload(31, 369, "12.5");
    for text in [
        "{}".to_owned(),
        "{".to_owned(),
        format!(" {valid}"),
        valid.replace("\"12.5\"", "12.5"),
        valid.replace("\"12.5\"", "\"12.50\""),
        valid.replace("\"amount\":", "\"unexpected\":"),
        valid.replace("\"amount\":", "\"amount\":\"1\",\"amount\":"),
        valid.replace(&account(31, 369), "not-an-account"),
    ] {
        assert!(encode(request(Some(&text))).is_err(), "accepted {text}");
    }
}

#[test]
fn contract_argument_encoding_binds_chain_context_and_restores_ambient_state() {
    let _ambient = ChainDiscriminantGuard::enter(19);
    let mut reference = None;
    for discriminant in [117, 369, 753] {
        let text = payload(31, discriminant, "12.5");
        let mut selected = request(Some(&text));
        selected.chain_discriminant = discriminant;
        let wire = encode(selected).unwrap();
        assert_eq!(chain_discriminant(), 19);
        if let Some(previous) = &reference {
            assert_eq!(&wire, previous, "wire identity is prefix-neutral");
        } else {
            reference = Some(wire);
        }
        for foreign in [117, 369, 753]
            .into_iter()
            .filter(|value| *value != discriminant)
        {
            let mut wrong = request(Some(&text));
            wrong.chain_discriminant = foreign;
            assert!(encode(wrong).is_err());
            assert_eq!(chain_discriminant(), 19);
        }
    }
}

#[test]
fn contract_argument_encoding_bounds_inputs_before_artifact_and_payload_parsing() {
    let mut invalid = request(Some("null"));
    invalid.artifact = &[];
    assert!(
        encode(invalid)
            .unwrap_err()
            .contains("artifact must contain")
    );
    let too_large_artifact = vec![0; MAX_ARTIFACT_BYTES + 1];
    let mut invalid = request(Some("null"));
    invalid.artifact = &too_large_artifact;
    assert!(
        encode(invalid)
            .unwrap_err()
            .contains("artifact must contain")
    );
    let too_large_json = " ".repeat(MAX_JSON_BYTES + 1);
    assert!(
        encode(request(Some(&too_large_json)))
            .unwrap_err()
            .contains("payload_json exceeds")
    );
    let too_long_selector = "x".repeat(MAX_ENTRYPOINT_BYTES + 1);
    let mut invalid = request(None);
    invalid.entrypoint = &too_long_selector;
    assert!(
        encode(invalid)
            .unwrap_err()
            .contains("entrypoint must contain")
    );
}

#[test]
fn contract_argument_python_boundary_requires_exact_types_and_returns_immutable_bytes() {
    Python::initialize();
    Python::attach(|py| {
        let function = pyo3::wrap_pyfunction!(encode_contract_arguments_v1_py, py).unwrap();
        let kwargs = PyDict::new(py);
        kwargs
            .set_item("expected_code_hash_hex", &fixture().code_hash)
            .unwrap();
        kwargs
            .set_item("expected_abi_hash_hex", &fixture().abi_hash)
            .unwrap();
        kwargs.set_item("chain_discriminant", 369).unwrap();
        let artifact = PyBytes::new(py, &fixture().artifact);
        let text = payload(31, 369, "12.5");
        let value = function
            .call((&artifact, "quote", &text), Some(&kwargs))
            .unwrap();
        assert!(value.is_exact_instance_of::<PyBytes>());
        assert_eq!(
            value.cast::<PyBytes>().unwrap().as_bytes(),
            encode(request(Some(&text))).unwrap().unwrap()
        );
        let mutable = PyByteArray::new(py, &fixture().artifact);
        assert!(
            function
                .call((&mutable, "quote", &text), Some(&kwargs))
                .unwrap_err()
                .is_instance_of::<PyTypeError>(py)
        );
        for invalid in [
            py.None(),
            7_i32.into_pyobject(py).unwrap().into_any().unbind(),
        ] {
            assert!(
                function
                    .call((&artifact, invalid, &text), Some(&kwargs))
                    .is_err()
            );
        }
        assert!(
            function
                .call((&artifact, "quote", PyDict::new(py)), Some(&kwargs))
                .is_err()
        );
        kwargs.set_item("chain_discriminant", true).unwrap();
        assert!(
            function
                .call((&artifact, "quote", &text), Some(&kwargs))
                .unwrap_err()
                .is_instance_of::<PyTypeError>(py)
        );
        kwargs.set_item("chain_discriminant", 369).unwrap();
        assert!(
            function
                .call((&artifact, "ready"), Some(&kwargs))
                .unwrap()
                .is_none()
        );
        assert!(
            function
                .call((&artifact, "ready", "null"), Some(&kwargs))
                .is_err()
        );
    });
}
