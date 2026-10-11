//! Runtime façade for embedding the IVM safely.
//!
//! This module groups the VM construction types used by embedded hosts.
//!
//! Typical usage:
//! ```
//! use ivm::runtime::{IvmBuilder, IvmConfig};
//!
//! // Start from a configuration preset.
//! let config = IvmConfig::deterministic(1_000);
//! // Optionally tweak via the builder helpers.
//! let mut builder = IvmBuilder::with_config(config).suppress_startup_banner();
//! builder.set_gas_limit(2_000);
//! let (cfg, mut vm) = builder.build_with_config();
//! // `cfg` can be reused to spawn another VM later.
//! let mut vm2 = IvmBuilder::with_config(cfg)
//!     .suppress_startup_banner()
//!     .build();
//! // ... attach host, load programs, run, etc.
//! ```
pub use crate::ivm::{
    AccelerationPolicy, HardwareCapabilities, IvmBuilder, IvmConfig, IvmConfigBuilder,
};
pub use crate::stack_policy::IvmStackPolicy;
use crate::{VMError, host::IVMHost, ivm::IVM};
use std::any::Any;
/// Wrapper that enforces syscall policy and retains the host's prepared argument owner.
pub(crate) struct SyscallDispatcher<H> {
    inner: H,
}
impl<H> SyscallDispatcher<H> {
    /// Create a dispatcher around `host`.
    pub(crate) fn new(host: H) -> Self {
        Self { inner: host }
    }
}
impl<H: IVMHost> IVMHost for SyscallDispatcher<H> {
    fn prepared_entrypoint_arguments(&self) -> Option<crate::PreparedArgumentRecord> {
        self.inner.prepared_entrypoint_arguments()
    }
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
        self.inner.prepare_syscall(number, vm)
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        if !self.allows_syscall(vm.syscall_policy(), number) {
            return Err(VMError::UnknownSyscall(number));
        }
        self.inner.syscall(number, vm)
    }
    fn allows_syscall(&self, policy: crate::SyscallPolicy, number: u32) -> bool {
        self.inner.allows_syscall(policy, number)
    }
    fn as_any(&mut self) -> &mut dyn Any
    where
        Self: 'static,
    {
        self.inner.as_any()
    }
    fn checkpoint(&self) -> Option<Box<dyn Any + Send>> {
        self.inner.checkpoint()
    }
    fn restore(&mut self, snapshot: &dyn Any) -> Result<(), VMError> {
        self.inner.restore(snapshot)
    }
    fn begin_tx(&mut self, declared: &crate::parallel::StateAccessSet) -> Result<(), VMError> {
        self.inner.begin_tx(declared)
    }
    fn finish_tx(&mut self) -> Result<crate::host::AccessLog, VMError> {
        self.inner.finish_tx()
    }
    fn access_logging_supported(&self) -> bool {
        self.inner.access_logging_supported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PreparedArgumentRecord;
    use iroha_primitives::json::Json;
    use std::sync::Arc;

    struct PreparedHost(PreparedArgumentRecord);

    impl IVMHost for PreparedHost {
        fn prepared_entrypoint_arguments(&self) -> Option<PreparedArgumentRecord> {
            Some(self.0.clone())
        }

        fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
            Err(VMError::PermissionDenied)
        }

        fn syscall(&mut self, _number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
            panic!("prepared arguments must not request public input")
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    #[test]
    fn owned_host_retains_prepared_arguments_and_requires_exact_prepayment() {
        let (program, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(
                "seiyaku Prepared { view fn echo(bool ready) authorize(anyone) -> bool { return ready; } }",
            )
            .expect("compile parameterized view");
        let verified = crate::verify_contract_artifact(&program).expect("verify view");
        let schema = verified
            .contract_interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "echo")
            .expect("echo entrypoint")
            .argument_schema
            .as_ref()
            .expect("argument schema");
        let canonical = ivm_abi::arguments::encode_argument_record_from_json(
            schema,
            &Json::from(norito::json!({"ready": true})),
        )
        .expect("encode arguments");
        crate::reset_argument_record_decode_count();
        let prepared =
            crate::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), 100_000)
                .expect("prepare arguments");

        let mut vm = IVM::new(100_000);
        vm.load_program(&program).expect("load view");
        vm.select_entrypoint("echo").expect("select view");
        prepared.precharge_vm(&mut vm).expect("prepay arguments");
        vm.set_host(PreparedHost(prepared.clone()));
        vm.run().expect("owned host retains preparation");
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        assert_eq!(vm.public_call_result_word(0).unwrap(), 1);
        #[cfg(debug_assertions)]
        assert_eq!(crate::argument_record_decode_count(), 1);

        let mut unpaid = IVM::new(100_000);
        unpaid.load_program(&program).unwrap();
        unpaid.select_entrypoint("echo").unwrap();
        unpaid.set_host(PreparedHost(prepared));
        assert_eq!(unpaid.run(), Err(VMError::DecodeError));
        assert!(unpaid.call_result_word_count().is_err());
        #[cfg(debug_assertions)]
        assert_eq!(crate::argument_record_decode_count(), 1);
    }

    struct SoracloudTemplateHost {
        arguments: PreparedArgumentRecord,
        inner: crate::host::DefaultHost,
    }
    impl IVMHost for SoracloudTemplateHost {
        fn prepared_entrypoint_arguments(&self) -> Option<PreparedArgumentRecord> {
            Some(self.arguments.clone())
        }
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
            self.inner.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            self.inner.syscall(number, vm)
        }
        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }
    #[test]
    fn compiler_soracloud_template_uses_exact_context_schema_and_completed_json_result() {
        let source = include_str!(
            "../../iroha_cli/src/soracloud/templates/v1/static/single_api_contract.ko"
        )
        .replace("__CONTRACT_NAME__", "CanonicalSoracloud")
        .replace("__APP_NAME__", "canonical-app");
        let (program, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(&source)
            .expect("compile actual CLI Soracloud template");
        let contract =
            crate::prepare_contract(Arc::from(program)).expect("canonical compiled contract");
        let descriptor = contract
            .entrypoint_descriptor("serve_healthz")
            .expect("template query");
        let schema = descriptor
            .argument_schema
            .as_ref()
            .expect("template context fields");
        assert_eq!(
            schema
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["_request_body", "_request_meta", "observed_height"]
        );
        assert_eq!(
            schema
                .fields
                .iter()
                .map(|field| field.ty.nodes.as_slice())
                .collect::<Vec<_>>(),
            [
                &[ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                    ivm_abi::entrypoint::EntrypointValueKindV1::Blob
                )][..],
                &[ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                    ivm_abi::entrypoint::EntrypointValueKindV1::Json
                )][..],
                &[ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                    ivm_abi::entrypoint::EntrypointValueKindV1::Int
                )][..],
            ]
        );
        let canonical = ivm_abi::arguments::encode_argument_record_from_json(schema,
            &Json::from(norito::json!({"_request_body": "0x616263", "_request_meta": {"method": "GET"}, "observed_height": "17"})))
            .expect("exact authenticated template fields");
        let arguments =
            crate::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), u64::MAX)
                .expect("prepare canonical template input");
        let mut vm = IVM::new(u64::MAX);
        vm.load_prepared(&contract).unwrap();
        vm.select_entrypoint("serve_healthz").unwrap();
        arguments.precharge_vm(&mut vm).unwrap();
        vm.set_host(SoracloudTemplateHost {
            arguments,
            inner: crate::host::DefaultHost::new(),
        });
        vm.run().expect("execute actual compiler-produced query");
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        let tlv = vm
            .validate_tlv(vm.public_call_result_word(0).unwrap())
            .unwrap();
        assert_eq!(tlv.type_id, crate::pointer_abi::PointerType::Json);
        let json: Json = norito::decode_canonical(tlv.payload).unwrap();
        let value: norito::json::Value = norito::json::from_str(json.get()).unwrap();
        assert_eq!(
            value,
            norito::json!({"app": "canonical-app", "observed_height": "17", "route": "/api/healthz", "status": "ready"})
        );
    }
}
