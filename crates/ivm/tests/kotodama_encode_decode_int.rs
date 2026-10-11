//! Kotodama rejects retired source-level integer codec plumbing.
use std::any::Any;

use iroha_primitives::bigint::BigInt;
use ivm::{CoreHost, IVM, IVMHost, PointerType, VMError, numeric_tlv, syscalls};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;

mod common;

struct CapturingHost {
    inner: CoreHost,
    logs: Vec<Vec<u8>>,
}

impl CapturingHost {
    fn new() -> Self {
        Self {
            inner: CoreHost::new(),
            logs: Vec::new(),
        }
    }
}

impl IVMHost for CapturingHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        self.inner.prepare_syscall(number, vm)
    }

    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        if number == syscalls::SYSCALL_DEBUG_LOG {
            let log = vm.validate_tlv(vm.register(10))?;
            assert_eq!(log.type_id, PointerType::NoritoBytes);
            self.logs.push(log.payload.to_vec());
        }
        self.inner.syscall(number, vm)
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[test]
fn kotodama_source_rejects_retired_integer_codec_helpers() {
    let src = r#"
        seiyaku IntegerCodecRoundtrip {
            view fn main() authorize(anyone) {
                let encoded = codec::encode_i64(7);
                let decoded = codec::decode_i64(encoded);
                let _ = decoded;
            }
        }
    "#;
    let error = KotodamaCompiler::new()
        .compile_source(src)
        .expect_err("source-level integer codec helpers are compiler-internal");
    assert!(error.contains("codec::encode_i64"), "{error}");
    assert!(error.contains("codec::decode_i64"), "{error}");
}

#[test]
fn debug_info_logs_full_width_int_envelope_at_runtime() {
    let source = r#"
        seiyaku WideInfo {
            view fn main() authorize(anyone) -> int {
                let value = 1267650600228229401496703205376;
                debug::info(value);
                return value;
            }
        }
    "#;
    let artifact = KotodamaCompiler::new()
        .compile_source(source)
        .expect("compile wide Int debug logging");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CapturingHost::new());
    vm.load_program(&artifact).expect("load wide Int program");
    common::select_kotodama_entrypoint(&mut vm, &artifact, "main");
    vm.run().expect("execute wide Int logging");

    let expected = BigInt::from_i128(1_i128 << 100);
    assert_eq!(common::decode_int_return_word(&vm, 0), expected);
    let host = vm
        .host_mut_any()
        .expect("host configured")
        .downcast_mut::<CapturingHost>()
        .expect("capturing host");
    assert_eq!(host.logs.len(), 1, "exactly one source debug event");
    assert_eq!(numeric_tlv::decode_int_bytes(&host.logs[0]), Ok(expected));
}
