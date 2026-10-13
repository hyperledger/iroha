//! Runtime coverage for Kotodama VRF request transport normalization.
use blstrs::{G1Projective, G2Projective, Scalar};
use group::{Curve, Group};
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use ivm::{
    IVM, IVMHost, ProgramMetadata, VMError,
    host::DefaultHost,
    pointer_abi::PointerType,
    vrf::{VrfVerifyBatchRequest, VrfVerifyRequest},
};
use std::collections::BTreeMap;
mod common;
fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn argument_record_tlv(entrypoint: &ivm::EmbeddedEntrypointDescriptor, payload: &Json) -> Vec<u8> {
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("parameterized VRF entrypoint argument schema");
    let record = ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
        .expect("encode argument record");
    tlv(PointerType::NoritoBytes, &record)
}
struct ObservedVrfHost {
    inner: DefaultHost,
    status: Option<[u64; 3]>,
}
impl IVMHost for ObservedVrfHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        self.inner.prepare_syscall(number, vm)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        let result = self.inner.syscall(number, vm);
        if matches!(
            number,
            ivm::syscalls::SYSCALL_VRF_VERIFY | ivm::syscalls::SYSCALL_VRF_VERIFY_BATCH
        ) {
            self.status = Some([vm.register(10), vm.register(11), vm.register(12)]);
        }
        result
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
fn compile_and_run(source: &str, arguments: Option<&Json>) -> (IVM, Result<(), VMError>, [u64; 3]) {
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile VRF transport contract");
    let parsed = ProgramMetadata::parse(&code).expect("parse VRF transport metadata");
    let run = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint descriptor");
    let entry_pc = u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + run.entry_pc;
    let host = if let Some(arguments) = arguments {
        let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
            .parse()
            .expect("public input key");
        DefaultHost::new()
            .with_network_id(common::test_network_id(0x71))
            .with_public_inputs(BTreeMap::from([(key, argument_record_tlv(run, arguments))]))
    } else {
        DefaultHost::new().with_network_id(common::test_network_id(0x71))
    };
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).expect("load VRF transport contract");
    vm.set_program_counter(entry_pc)
        .expect("select run entrypoint");
    let mut host = ObservedVrfHost {
        inner: host,
        status: None,
    };
    let outcome = vm.run_with_host(&mut host);
    (vm, outcome, host.status.expect("VRF syscall must execute"))
}
fn valid_vrf_request() -> (Vec<u8>, [u8; 32]) {
    const DST: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1";
    let mut seed = [0_u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::try_from(index + 1).expect("fixture index fits u8");
    }
    let secret = Scalar::from_bytes_be(&seed).expect("canonical non-zero fixture scalar");
    let public_key = (G1Projective::generator() * secret)
        .to_affine()
        .to_compressed();
    let network_id = common::test_network_id(0x71);
    let input = b"entrypoint-bytes";
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"iroha:vrf:v1:input|");
    preimage.extend_from_slice(network_id.as_bytes());
    preimage.push(b'|');
    preimage.extend_from_slice(input);
    let message: [u8; 32] = Hash::new(&preimage).into();
    let proof = (G2Projective::hash_to_curve(&message, DST, &[]) * secret)
        .to_affine()
        .to_compressed();
    let mut output_preimage = Vec::new();
    output_preimage.extend_from_slice(b"iroha:vrf:v1:output");
    output_preimage.extend_from_slice(&proof);
    let expected: [u8; 32] = Hash::new(&output_preimage).into();
    let request = VrfVerifyRequest {
        variant: 1,
        pk: public_key.to_vec(),
        proof: proof.to_vec(),
        network_id,
        input: input.to_vec(),
    };
    (
        norito::to_bytes(&request).expect("encode canonical VRF request"),
        expected,
    )
}
#[test]
fn vrf_verify_accepts_entrypoint_bytes_and_returns_expected_blob() {
    let source = r#"
seiyaku VrfEntrypointBytes {
  view fn run(bytes request) authorize(anyone) -> bytes {
    return crypto::vrf::verify(request: request);
  }
}
"#;
    let (request, expected) = valid_vrf_request();
    let request_hex = format!("0x{}", hex::encode(request));
    let arguments = Json::from(norito::json!({
        "request": request_hex,
    }));
    let (vm, outcome, _) = compile_and_run(source, Some(&arguments));
    outcome.expect("valid VRF result");
    let output = vm
        .validate_tlv(vm.public_call_result_word(0).expect("completed VRF result"))
        .expect("VRF output pointer");
    assert_eq!(output.type_id, PointerType::Blob);
    assert_eq!(output.payload, expected);
}
#[test]
fn vrf_verify_batch_rejects_empty_entrypoint_bytes() {
    let source = r#"
seiyaku VrfBatchEntrypointBytes {
  view fn run(bytes batch) authorize(anyone) -> bytes {
    return crypto::vrf::verify_batch(request: batch);
  }
}
"#;
    let request = norito::to_bytes(&VrfVerifyBatchRequest { items: Vec::new() })
        .expect("encode empty VRF batch request");
    let request_hex = format!("0x{}", hex::encode(request));
    let arguments = Json::from(norito::json!({
        "batch": request_hex,
    }));
    let (vm, outcome, status) = compile_and_run(source, Some(&arguments));
    assert!(matches!(outcome, Err(VMError::NoritoInvalid)));
    assert!(vm.call_result_word_count().is_err());
    assert_eq!(status, [0, 9, u64::MAX], "empty batch bound status");
}
#[test]
fn malformed_vrf_bytes_literal_reaches_decode_error() {
    let source = r#"
seiyaku MalformedVrfLiteral {
  view fn run() authorize(anyone) -> bytes {
    return crypto::vrf::verify(request: b"\x01\x02\x03");
  }
}
"#;
    let (vm, outcome, status) = compile_and_run(source, None);
    assert!(matches!(outcome, Err(VMError::NoritoInvalid)));
    assert!(vm.call_result_word_count().is_err());
    assert_eq!(status[0], 0);
    assert_eq!(status[1], 2, "malformed Norito request status");
    assert_ne!(status[1], 1, "request must not fail as a Blob type error");
}
