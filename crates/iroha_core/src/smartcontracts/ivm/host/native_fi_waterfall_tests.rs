// Staged compiler-to-host boundary tests for the next coordinated candidate.
// These inspect queued effects; separate native executor tests prove settlement.
use super::tests::{norito_blob, store_quantity, store_tlv};
use super::*;
use iroha_data_model::{
    escrow::control::{AssetLockWaterfallSettlementV1, controlled_asset_lock_id},
    isi::{
        asset_fi::TransferToLinkedFiV1,
        escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock},
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1, ExpireControlledAssetLockV1,
        },
    },
};
use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use ivm::IVMHost;

const SOURCE: &str = r#"seiyaku LinkedFiSettlement {
    kotoage fn settle(
        bytes key, AccountId wallet, AssetDefinitionId asset,
        quantity amount, quantity remaining, int policy_revision, int link_revision
    ) authorize(anyone) {
        ledger::fi::transfer_linked(asset_definition: asset, account: wallet, amount: amount, policy_revision: policy_revision, link_revision: link_revision);
        ledger::asset_lock::drawdown_with_waterfall(
            key: key, amount: amount, expected_remaining: remaining,
            policy_revision: policy_revision, link_revision: link_revision
        );
        ledger::asset_lock::cancel_with_waterfall(
            key: key, expected_remaining: remaining,
            policy_revision: policy_revision, link_revision: link_revision
        );
        ledger::asset_lock::expire_with_waterfall(key: key, policy_revision: policy_revision, link_revision: link_revision);
    }
}"#;

#[test]
fn compiled_linked_fi_and_waterfall_calls_preserve_full_revision_pins_and_native_terms() {
    check_compiled_calls(SOURCE, &[0, 1, 2, 3]);
}

#[test]
fn each_linked_fi_and_waterfall_call_checks_both_revision_ranges_before_queueing() {
    // An invalid first call in the combined program cannot exercise lowering
    // for the later calls. Compile each builtin as the only effect so every
    // revision conversion must independently reject negatives and overflow.
    for (index, call) in ISOLATED_CALLS.iter().enumerate() {
        check_compiled_calls(&isolated_source(call), &[index]);
    }
}

const ISOLATED_CALLS: [&str; 4] = [
    "ledger::fi::transfer_linked(asset_definition: asset, account: wallet, amount: amount, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::drawdown_with_waterfall(key: key, amount: amount, expected_remaining: remaining, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::cancel_with_waterfall(key: key, expected_remaining: remaining, policy_revision: policy_revision, link_revision: link_revision);",
    "ledger::asset_lock::expire_with_waterfall(key: key, policy_revision: policy_revision, link_revision: link_revision);",
];

fn isolated_source(call: &str) -> String {
    format!(
        "seiyaku IsolatedSettlement {{
            kotoage fn settle(
                bytes key, AccountId wallet, AssetDefinitionId asset,
                quantity amount, quantity remaining, int policy_revision, int link_revision
            ) authorize(anyone) {{ {call} }}
        }}"
    )
}

fn check_compiled_calls(source: &str, expected_indices: &[usize]) {
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .expect("compile typed FI and controlled waterfall calls");
    let metadata = ivm::ProgramMetadata::parse(&program).unwrap();
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .unwrap()
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "settle")
        .unwrap();
    let schema = entrypoint.argument_schema.as_ref().unwrap();
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("escrow", "universal").unwrap(),
        "ds".parse().unwrap(),
    );
    let controller = iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &ALICE_ID,
        92,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    // Distinct pins detect register swaps; full u64 detects truncation to i64.
    for (policy_revision, link_revision, accepted) in [
        ("18446744073709551615", "18446744073709551614", true),
        ("0", "1", true),
        ("-1", "1", false),
        ("1", "-1", false),
        ("18446744073709551616", "1", false),
        ("1", "18446744073709551616", false),
    ] {
        let arguments = Json::new(std::collections::BTreeMap::from([
            ("key", "0x6c6f636b".to_owned()),
            ("wallet", BOB_ID.canonical_i105().unwrap()),
            ("asset", asset.canonical_address()),
            ("amount", "5".to_owned()),
            ("remaining", "13".to_owned()),
            ("policy_revision", policy_revision.to_owned()),
            ("link_revision", link_revision.to_owned()),
        ]));
        let canonical =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &arguments).unwrap();
        let prepared =
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), 50_000_000)
                .unwrap();
        let mut host = CoreHost::new(ALICE_ID.clone());
        host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
            contract_subject: controller.subject_id(),
            contract_address: controller.clone(),
            contract_alias: None,
            entrypoint: "settle".to_owned(),
        }));
        host.set_entrypoint_argument_record(Some(prepared.clone()));
        let mut vm = IVM::new(50_000_000);
        vm.load_program(&program).unwrap();
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(metadata.prefix_len() as u64 + entrypoint.entry_pc)
            .unwrap();
        prepared.precharge_vm(&mut vm).unwrap();
        let result = vm.run_with_host(&mut host);
        if !accepted {
            assert!(result.is_err(), "out-of-range revision must not wrap");
            assert!(host.queued.is_empty());
            continue;
        }
        result.expect("execute typed marshalling through the actual host");
        let policy_revision = policy_revision.parse::<u64>().unwrap();
        let link_revision = link_revision.parse::<u64>().unwrap();
        let waterfall = Some(AssetLockWaterfallSettlementV1 {
            expected_policy_revision: policy_revision,
            expected_link_revision: link_revision,
        });
        let id = controlled_asset_lock_id(&controller, b"lock");
        let expected = [
            InstructionBox::from(TransferToLinkedFiV1 {
                asset_definition_id: asset.clone(),
                account_id: BOB_ID.clone(),
                amount: 5_u32.into(),
                expected_policy_revision: policy_revision,
                expected_link_revision: link_revision,
            }),
            InstructionBox::from(DrawdownControlledAssetLockV1 {
                drawdown: DrawdownAssetLock::new(id, 5_u32, 13_u32),
                waterfall,
            }),
            InstructionBox::from(CancelControlledAssetLockV1 {
                cancel: CancelAssetLock::new(id, 13_u32),
                waterfall,
            }),
            InstructionBox::from(ExpireControlledAssetLockV1 {
                expiry: ExpireAssetLock::new(id),
                waterfall,
            }),
        ];
        assert_eq!(host.queued.len(), expected_indices.len());
        for (effect, index) in host.queued.iter().zip(expected_indices) {
            assert_eq!(effect.instruction(), Some(&expected[*index]));
            assert_eq!(effect.authority, controller.subject_id());
            assert_ne!(effect.authority, *ALICE_ID);
            assert_eq!(
                effect
                    .contract_runtime_context
                    .as_ref()
                    .unwrap()
                    .contract_address,
                controller,
            );
        }
    }
}

#[test]
fn linked_fi_and_waterfall_effects_are_unavailable_to_views() {
    assert!(
        kotodama_lang::compiler::Compiler::new()
            .compile_source(&SOURCE.replace("kotoage fn", "view fn"))
            .is_err()
    );
}

#[derive(Clone, Copy, Debug)]
enum NativeCall {
    LinkedFi,
    Draw,
    Cancel,
    Expire,
}

const CALLS: [(NativeCall, usize); 4] = [
    (NativeCall::LinkedFi, 14),
    (NativeCall::Draw, 14),
    (NativeCall::Cancel, 13),
    (NativeCall::Expire, 12),
];

fn configured_host() -> CoreHost {
    let controller = iroha_data_model::smart_contract::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &ALICE_ID,
        92,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let mut host = CoreHost::new(ALICE_ID.clone());
    host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
        contract_subject: controller.subject_id(),
        contract_address: controller,
        contract_alias: None,
        entrypoint: "settle".to_owned(),
    }));
    host
}

fn arguments_for(call: NativeCall) -> IVM {
    let mut vm = IVM::new(100_000);
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("escrow", "universal").unwrap(),
        "ds".parse().unwrap(),
    );
    let key = store_tlv(&mut vm, PointerType::Blob, b"lock");
    let asset = store_tlv(
        &mut vm,
        PointerType::AssetDefinitionId,
        &norito_blob(&asset),
    );
    let wallet = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*BOB_ID));
    let amount = store_quantity(&mut vm, &5_u32.into());
    let remaining = store_quantity(&mut vm, &13_u32.into());
    let words = match call {
        NativeCall::LinkedFi => vec![asset, wallet, amount, u64::MAX, u64::MAX - 1],
        NativeCall::Draw => vec![key, amount, remaining, u64::MAX, u64::MAX - 1],
        NativeCall::Cancel => vec![key, remaining, u64::MAX, u64::MAX - 1],
        NativeCall::Expire => vec![key, u64::MAX, u64::MAX - 1],
    };
    for (index, value) in words.into_iter().enumerate() {
        vm.set_register(10 + index, value);
    }
    vm
}

fn dispatch(call: NativeCall, host: &mut CoreHost, vm: &IVM) -> Result<u64, ivm::VMError> {
    match call {
        NativeCall::LinkedFi => host.transfer_to_linked_fi(vm),
        NativeCall::Draw => host.controlled_asset_lock_with_waterfall(
            vm,
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL,
        ),
        NativeCall::Cancel => host.controlled_asset_lock_with_waterfall(
            vm,
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL_WATERFALL,
        ),
        NativeCall::Expire => host.controlled_asset_lock_with_waterfall(
            vm,
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL,
        ),
    }
}

#[test]
fn linked_fi_and_waterfall_hosts_require_the_actual_controller_frame() {
    for (call, _) in CALLS {
        let vm = arguments_for(call);
        let mut absent = CoreHost::new(ALICE_ID.clone());
        assert!(matches!(
            dispatch(call, &mut absent, &vm),
            Err(ivm::VMError::PermissionDenied)
        ));
        assert!(absent.queued.is_empty());
        let mut substituted = configured_host();
        substituted
            .current_contract_runtime_context
            .as_mut()
            .unwrap()
            .contract_subject = ALICE_ID.clone();
        assert!(matches!(
            dispatch(call, &mut substituted, &vm),
            Err(ivm::VMError::PermissionDenied)
        ));
        assert!(substituted.queued.is_empty());
    }
}

#[test]
fn every_linked_fi_and_waterfall_argument_must_be_public_before_queueing() {
    for (call, last_register) in CALLS {
        for register in 10..=last_register {
            let mut vm = arguments_for(call);
            vm.set_zk_mode(true)
                .expect("enable private-tag boundary fixture");
            vm.registers.set_tag(register, true);
            let mut host = configured_host();
            assert!(
                matches!(
                    dispatch(call, &mut host, &vm),
                    Err(ivm::VMError::PrivacyViolation)
                ),
                "{call:?} accepted private register {register}"
            );
            assert!(host.queued.is_empty());
        }
    }
}

// Observation only: every VM argument, policy, quote and syscall operation is
// forwarded unchanged to the real CoreHost. No fabricated gas quote or handler.
struct GasObservedHost {
    inner: CoreHost,
    target: u32,
    prepared_remaining: std::cell::Cell<Option<u64>>,
    invoked_reserve: Option<u64>,
    actual_gas: Option<u64>,
}

impl ivm::IVMHost for GasObservedHost {
    fn prepared_entrypoint_arguments(&self) -> Option<ivm::PreparedArgumentRecord> {
        self.inner.prepared_entrypoint_arguments()
    }

    fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
        self.inner.allows_syscall(policy, number)
    }

    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, ivm::VMError> {
        if number == self.target {
            assert!(
                self.prepared_remaining
                    .replace(Some(vm.remaining_gas()))
                    .is_none()
            );
        }
        self.inner.prepare_syscall(number, vm)
    }

    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
        if number == self.target {
            assert!(
                self.invoked_reserve
                    .replace(vm.syscall_reserved_gas())
                    .is_none()
            );
            assert!(
                vm.syscall_reserved_gas() > 0,
                "target must use VM-reserved gas"
            );
        }
        let result = self.inner.syscall(number, vm);
        if number == self.target {
            self.actual_gas = result.as_ref().ok().copied();
        }
        result
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

fn run_gas_probe(
    program: &[u8],
    target: u32,
    gas_limit: u64,
) -> (Result<(), ivm::VMError>, IVM, GasObservedHost) {
    let metadata = ivm::ProgramMetadata::parse(program).unwrap();
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .unwrap()
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "settle")
        .unwrap();
    let schema = entrypoint.argument_schema.as_ref().unwrap();
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("escrow", "universal").unwrap(),
        "ds".parse().unwrap(),
    );
    let arguments = Json::new(std::collections::BTreeMap::from([
        ("key", "0x6c6f636b".to_owned()),
        ("wallet", BOB_ID.canonical_i105().unwrap()),
        ("asset", asset.canonical_address()),
        ("amount", "5".to_owned()),
        ("remaining", "13".to_owned()),
        ("policy_revision", "18446744073709551615".to_owned()),
        ("link_revision", "18446744073709551614".to_owned()),
    ]));
    let canonical =
        ivm_abi::arguments::encode_argument_record_from_json(schema, &arguments).unwrap();
    let prepared =
        ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), gas_limit)
            .expect("fixture argument preparation fits before the native effect");
    let mut inner = configured_host();
    inner.set_entrypoint_argument_record(Some(prepared.clone()));
    let mut host = GasObservedHost {
        inner,
        target,
        prepared_remaining: std::cell::Cell::new(None),
        invoked_reserve: None,
        actual_gas: None,
    };
    let mut vm = IVM::new(gas_limit);
    vm.load_program(program).unwrap();
    vm.set_register(1, vm.memory.code_len());
    vm.set_program_counter(metadata.prefix_len() as u64 + entrypoint.entry_pc)
        .unwrap();
    prepared.precharge_vm(&mut vm).unwrap();
    let result = vm.run_with_host(&mut host);
    (result, vm, host)
}

#[test]
fn linked_fi_and_waterfall_hosts_preserve_queue_on_gas_refusal() {
    const CONTROL_GAS: u64 = 50_000_000;
    for (call, target) in ISOLATED_CALLS.into_iter().zip([
        ivm::syscalls::SYSCALL_TRANSFER_TO_LINKED_FI,
        ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN_WATERFALL,
        ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL_WATERFALL,
        ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE_WATERFALL,
    ]) {
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(&isolated_source(call))
            .expect("compile the isolated native effect");
        let (result, _, control) = run_gas_probe(&program, target, CONTROL_GAS);
        result.expect("successful native VM-dispatched gas control");
        assert_eq!(control.inner.queued.len(), 1);
        let actual = control
            .actual_gas
            .expect("native handler returned its exact cost");
        assert!(actual > 0);
        assert!(control.invoked_reserve.unwrap() >= actual);
        let before_target = CONTROL_GAS - control.prepared_remaining.get().unwrap();
        // Retain all real setup/decoder/conversion gas. Only the selected native
        // instruction lacks one unit: a preceding numeric error cannot pass.
        let (result, _, refused) = run_gas_probe(&program, target, before_target + actual - 1);
        let error = result.expect_err("native instruction cannot exceed its VM budget");
        assert!(matches!(error.as_unmetered(), ivm::VMError::OutOfGas));
        assert_eq!(refused.prepared_remaining.get(), Some(actual - 1));
        if let Some(reserved) = refused.invoked_reserve {
            assert!(
                reserved < actual,
                "native preflight must see the insufficient reserve"
            );
        }
        assert!(refused.actual_gas.is_none());
        assert!(refused.inner.queued.is_empty());
        assert_eq!(refused.inner.instruction_queue_encoded_bytes, 0);
    }
}
