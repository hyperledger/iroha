//! Typed contract-bound native lock effects. Authority comes only from the admitted frame.

use super::*;
use iroha_data_model::{
    escrow::control::{
        AssetLockControlV1, MAX_CONTROLLED_ASSET_LOCK_KEY_BYTES_V1, controlled_asset_lock_id,
    },
    isi::{
        escrow::{CancelAssetLock, DrawdownAssetLock, ExpireAssetLock, OpenAssetLock},
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
            ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
        },
    },
};
use std::num::NonZeroU64;

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn controlled_lock_key(
        vm: &IVM,
        pointer: u64,
        controller: &iroha_data_model::smart_contract::ContractAddress,
    ) -> Result<(EscrowId, Vec<u8>), ivm::VMError> {
        let key = Self::decode_pointer_tlv(vm, pointer, PointerType::Blob)?;
        if key.payload.is_empty() || key.payload.len() > MAX_CONTROLLED_ASSET_LOCK_KEY_BYTES_V1 {
            return Err(ivm::VMError::DecodeError);
        }
        Ok((
            controlled_asset_lock_id(controller, key.payload),
            key.payload.to_vec(),
        ))
    }

    pub(super) fn controlled_asset_lock(
        &mut self,
        vm: &mut IVM,
        number: u32,
    ) -> Result<u64, ivm::VMError> {
        // Never accept a controller supplied by the guest, an account alias, or metadata.
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        let controller = context.contract_address.clone();
        if context.contract_subject != controller.subject_id() {
            return Err(ivm::VMError::PermissionDenied);
        }
        vm.ensure_public_register(10)?;
        let mut custody_return = None;
        let instruction = match number {
            ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN => {
                let base = vm.register(10);
                if !base.is_multiple_of(8) {
                    return Err(ivm::VMError::DecodeError);
                }
                // This validates both allocation provenance and public memory tags.
                vm.ensure_owned_heap_range(base, 64)?;
                let mut words = [0_u64; 8];
                for (index, word) in words.iter_mut().enumerate() {
                    *word = vm.load_u64(base + index as u64 * 8)?;
                }
                let (escrow_id, key) = Self::controlled_lock_key(vm, words[0], &controller)?;
                let source: AccountId =
                    Self::decode_tlv_typed(vm, words[1], PointerType::AccountId)?;
                let destination: AccountId =
                    Self::decode_tlv_typed(vm, words[2], PointerType::AccountId)?;
                let asset_definition: AssetDefinitionId =
                    Self::decode_tlv_typed(vm, words[3], PointerType::AssetDefinitionId)?;
                let amount = Self::decode_quantity(vm, words[4])?;
                // The network is the actual admitted ledger domain, never a guest value
                // or a default chain label. Use the same derivation as native settlement.
                let network = self.network_id.as_ref().ok_or(ivm::VMError::PermissionDenied)?;
                let custody = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                    network, &escrow_id, &asset_definition,
                );
                custody_return = Some(Self::encode_tlv_payload(
                    PointerType::AccountId, &Self::encode_norito_payload(&custody)?,
                )?);
                InstructionBox::from(OpenControlledAssetLockV1 {
                    source,
                    key,
                    lock: OpenAssetLock::with_options(
                        escrow_id,
                        asset_definition,
                        destination,
                        amount,
                        Some(controller.subject_id()),
                        NonZeroU64::new(words[7]).map(NonZeroU64::get),
                        vec![],
                    ),
                    control: AssetLockControlV1 {
                        controller,
                        release_until_ms: NonZeroU64::new(words[5]),
                        cancel_not_before_ms: NonZeroU64::new(words[6]),
                    },
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN => {
                vm.ensure_public_register(11)?;
                vm.ensure_public_register(12)?;
                let (escrow_id, _) = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                        Self::decode_quantity(vm, vm.register(12))?,
                    ),
                    waterfall: None,
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL => {
                vm.ensure_public_register(11)?;
                let (escrow_id, _) = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(
                        escrow_id,
                        Self::decode_quantity(vm, vm.register(11))?,
                    ),
                    waterfall: None,
                })
            }
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE => {
                let (escrow_id, _) = Self::controlled_lock_key(vm, vm.register(10), &controller)?;
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(escrow_id),
                    waterfall: None,
                })
            }
            _ => return Err(ivm::VMError::UnknownSyscall(number)),
        };
        if let Some(encoded_custody) = custody_return {
            self.ensure_instruction_queue_allowed(&instruction)?;
            let instruction_gas = crate::gas::meter_instruction(&instruction, &self.confidential_gas)
                .map_err(ivm::VMError::VerificationDeferred)?;
            let output_gas = u64::try_from(encoded_custody.len())
                .map_err(|_| ivm::VMError::GasCostOverflow)?
                .checked_mul(ivm::gas::SYSCALL_GAS_PER_BYTE)
                .ok_or(ivm::VMError::GasCostOverflow)?;
            let gas = instruction_gas.checked_add(output_gas)
                .ok_or(ivm::VMError::GasCostOverflow)?;
            // Complete gas, VM allocation, and retained-effect capacity checks before
            // allocating a return or publishing any queue entry or result register.
            ivm::host::preflight_reserved_syscall_gas(vm, gas)?;
            vm.preflight_host_tlv_allocations_with_reserved_heap(&[encoded_custody.len()], 0)?;
            if !self.try_reserve_serialized_output(&instruction, 1) {
                return self.ensure_output_budget().map(|()| gas);
            }
            let pointer = vm.alloc_host_tlv(&encoded_custody)?;
            self.queued.push(QueuedEffect {
                payload: QueuedEffectPayload::Instruction(instruction),
                authority: self.effect_authority(),
                contract_runtime_context: self.current_contract_runtime_context.clone(),
                entrypoint_authorization: self.current_entrypoint_authorization.clone(),
            });
            vm.set_register(10, pointer);
            return Ok(gas);
        }
        // Other operations retain their original gas and effect-only behavior.
        self.queue_instruction_after_preflight(vm, instruction)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{norito_blob, store_quantity, store_tlv};
    use super::*;
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use ivm::host::IVMHost;

    fn host() -> CoreHost {
        let caller = ALICE_ID.clone();
        let controller = iroha_data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &caller,
            92,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let mut host = CoreHost::new(caller);
        host.set_network_id(
            "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse().unwrap(),
        );
        host.set_contract_runtime_context(Some(ContractRuntimeExecutionContext {
            contract_subject: controller.subject_id(),
            contract_address: controller,
            contract_alias: None,
            entrypoint: "lock".to_owned(),
        }));
        host
    }

    #[test]
    fn opening_preserves_payer_beneficiary_and_independent_deadlines_in_queued_effect() {
        let mut host = host();
        let mut vm = IVM::new(100_000);
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrow", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let words = [
            store_tlv(&mut vm, PointerType::Blob, b"ns:1/lock"),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*ALICE_ID)),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*BOB_ID)),
            store_tlv(
                &mut vm,
                PointerType::AssetDefinitionId,
                &norito_blob(&asset),
            ),
            store_quantity(&mut vm, &100_u32.into()),
            300,
            701,
            701,
        ];
        let table = vm.alloc_heap(64).unwrap();
        for (index, word) in words.iter().enumerate() {
            vm.store_u64(table + index as u64 * 8, *word).unwrap();
        }
        vm.set_register(10, table);
        host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm)
            .unwrap();
        assert_eq!(host.queued.len(), 1);
        let effect = &host.queued[0];
        let opening = effect
            .instruction()
            .unwrap()
            .as_any()
            .downcast_ref::<OpenControlledAssetLockV1>()
            .unwrap();
        let returned = CoreHost::decode_tlv_typed::<AccountId>(
            &vm, vm.register(10), PointerType::AccountId,
        ).unwrap();
        assert_eq!(returned, crate::smartcontracts::isi::escrow::escrow_custody_account_id(
            host.network_id.as_ref().unwrap(), &opening.lock.escrow_id, &asset,
        ));
        assert_ne!(returned, opening.source);
        assert_ne!(returned, opening.lock.destination);
        assert_ne!(returned, opening.control.controller.subject_id());
        assert_eq!(opening.source, *ALICE_ID);
        assert_eq!(opening.key, b"ns:1/lock");
        assert_eq!(opening.lock.destination, *BOB_ID);
        assert_eq!(opening.lock.amount, 100_u32.into());
        assert_eq!(opening.control.release_until_ms.unwrap().get(), 300);
        assert_eq!(opening.control.cancel_not_before_ms.unwrap().get(), 701);
        assert_eq!(opening.lock.expires_at_ms, Some(701));
        assert_eq!(effect.authority, opening.control.controller.subject_id());
        assert_ne!(effect.authority, opening.source);
        assert_eq!(
            effect
                .contract_runtime_context
                .as_ref()
                .unwrap()
                .contract_address,
            opening.control.controller
        );
    }

    #[test]
    fn draw_cancel_expire_reuse_controller_scoped_identity_and_cas_amounts() {
        let mut host = host();
        let mut vm = IVM::new(100_000);
        let key = store_tlv(&mut vm, PointerType::Blob, b"ns:1/lock");
        let amount = store_quantity(&mut vm, &20_u32.into());
        let remaining = store_quantity(&mut vm, &100_u32.into());
        let controller = host
            .current_contract_runtime_context
            .as_ref()
            .unwrap()
            .contract_address
            .clone();
        let id = controlled_asset_lock_id(&controller, b"ns:1/lock");
        for (number, expected, second, third) in [
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN,
                InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(id, 20_u32, 100_u32),
                    waterfall: None,
                }),
                amount,
                remaining,
            ),
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL,
                InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(id, 100_u32),
                    waterfall: None,
                }),
                remaining,
                0,
            ),
            (
                ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE,
                InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(id),
                    waterfall: None,
                }),
                0,
                0,
            ),
        ] {
            vm.set_register(10, key);
            vm.set_register(11, second);
            vm.set_register(12, third);
            host.syscall(number, &mut vm).unwrap();
            assert_eq!(host.queued.last().unwrap().instruction(), Some(&expected));
        }
    }

    #[test]
    fn lock_calls_reject_missing_frame_bad_key_and_unowned_table_without_effects() {
        let mut vm = IVM::new(100_000);
        let mut plain = CoreHost::new(ALICE_ID.clone());
        for number in [
            ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN,
            ivm::syscalls::SYSCALL_ASSET_LOCK_DRAWDOWN,
            ivm::syscalls::SYSCALL_ASSET_LOCK_CANCEL,
            ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE,
        ] {
            assert!(plain.syscall(number, &mut vm).is_err());
            assert!(plain.queued.is_empty());
        }
        let mut host = host();
        for bytes in [vec![], vec![1; 4097]] {
            let key = store_tlv(&mut vm, PointerType::Blob, &bytes);
            vm.set_register(10, key);
            assert!(
                host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_EXPIRE, &mut vm)
                    .is_err()
            );
            assert!(host.queued.is_empty());
        }
        // INPUT cannot impersonate a compiler-owned mutable argument table.
        let input = store_tlv(&mut vm, PointerType::Blob, &[0; 64]);
        vm.set_register(10, input);
        assert!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm)
                .is_err()
        );
        assert!(host.queued.is_empty());
    }

    #[test]
    fn compiled_calls_preserve_all_typed_arguments_and_reject_negative_deadlines() {
        let source = r#"
seiyaku ControlledLock {
    kotoage fn lock(
        bytes key, AccountId source, AccountId destination,
        AssetDefinitionId asset_definition, quantity amount, quantity remaining,
        int release_until_ms, int cancel_not_before_ms, int expires_at_ms
    ) authorize(anyone) {
        ledger::asset_lock::open(
            key, source, destination, asset_definition, amount,
            release_until_ms, cancel_not_before_ms, expires_at_ms
        );
        ledger::asset_lock::drawdown(key, amount, expected_remaining: remaining);
        ledger::asset_lock::cancel(key, expected_remaining: remaining);
        ledger::asset_lock::expire(key);
    }
}"#;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(source)
            .expect("compile typed native lock calls");
        let metadata = ivm::ProgramMetadata::parse(&program).unwrap();
        let entrypoint = metadata
            .contract_interface
            .as_ref()
            .unwrap()
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "lock")
            .unwrap();
        let schema = entrypoint.argument_schema.as_ref().unwrap();
        let asset = AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrow", "universal").unwrap(),
            "ds".parse().unwrap(),
        );
        let payer = ALICE_ID.canonical_i105().unwrap();
        let beneficiary = BOB_ID.canonical_i105().unwrap();
        for release in [271_i64, -1] {
            let args = Json::new(std::collections::BTreeMap::from([
                ("key", "0x6c6f636b".to_owned()),
                ("source", payer.clone()),
                ("destination", beneficiary.clone()),
                ("asset_definition", asset.canonical_address()),
                ("amount", "5".to_owned()),
                ("remaining", "13".to_owned()),
                ("release_until_ms", release.to_string()),
                ("cancel_not_before_ms", "737".to_owned()),
                ("expires_at_ms", "739".to_owned()),
            ]));
            let canonical =
                ivm_abi::arguments::encode_argument_record_from_json(schema, &args).unwrap();
            let prepared = ivm::prepare_argument_record_with_gas_limit(
                schema,
                Arc::from(canonical),
                50_000_000,
            )
            .unwrap();
            let mut host = host();
            host.set_entrypoint_argument_record(Some(prepared.clone()));
            let mut vm = IVM::new(50_000_000);
            vm.load_program(&program).unwrap();
            vm.set_register(1, vm.memory.code_len());
            vm.set_program_counter(metadata.prefix_len() as u64 + entrypoint.entry_pc)
                .unwrap();
            prepared.precharge_vm(&mut vm).unwrap();
            let result = vm.run_with_host(&mut host);
            if release < 0 {
                assert!(result.is_err(), "negative deadline must not wrap into u64");
                assert!(host.queued.is_empty());
                continue;
            }
            result.expect("execute compiler marshalling through real native host");
            assert_eq!(host.queued.len(), 4);
            let open = host.queued[0]
                .instruction()
                .unwrap()
                .as_any()
                .downcast_ref::<OpenControlledAssetLockV1>()
                .unwrap();
            assert_eq!(open.source, *ALICE_ID);
            assert_eq!(open.key, b"lock");
            assert_eq!(open.lock.destination, *BOB_ID);
            assert_eq!(open.lock.asset_definition, asset);
            assert_eq!(open.lock.amount, 5_u32.into());
            assert_eq!(open.control.release_until_ms.unwrap().get(), 271);
            assert_eq!(open.control.cancel_not_before_ms.unwrap().get(), 737);
            assert_eq!(open.lock.expires_at_ms, Some(739));
            let id = controlled_asset_lock_id(&open.control.controller, b"lock");
            assert_eq!(open.lock.escrow_id, id);
            assert_eq!(
                host.queued[1].instruction(),
                Some(&InstructionBox::from(DrawdownControlledAssetLockV1 {
                    drawdown: DrawdownAssetLock::new(id, 5_u32, 13_u32),
                    waterfall: None,
                },))
            );
            assert_eq!(
                host.queued[2].instruction(),
                Some(&InstructionBox::from(CancelControlledAssetLockV1 {
                    cancel: CancelAssetLock::new(id, 13_u32),
                    waterfall: None,
                },))
            );
            assert_eq!(
                host.queued[3].instruction(),
                Some(&InstructionBox::from(ExpireControlledAssetLockV1 {
                    expiry: ExpireAssetLock::new(id),
                    waterfall: None,
                },))
            );
        }
    }

    const CUSTODY_SOURCE: &str = r#"seiyaku CustodyReturn {
    kotoage fn open(
        bytes key, AccountId source, AccountId destination,
        AssetDefinitionId asset, quantity amount
    ) authorize(anyone) -> AccountId {
        let custody = ledger::asset_lock::open(
            key: key, source: source, destination: destination,
            asset_definition: asset, amount: amount,
            release_until_ms: 0, cancel_not_before_ms: 0, expires_at_ms: 0
        );
        custody
    }
}"#;

    fn asset_for(name: &str) -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("escrow", "universal").unwrap(),
            name.parse().unwrap(),
        )
    }

    fn opening_vm(asset: &AssetDefinitionId, key: &[u8]) -> IVM {
        let mut vm = IVM::new(100_000);
        let words = [
            store_tlv(&mut vm, PointerType::Blob, key),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*ALICE_ID)),
            store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&*BOB_ID)),
            store_tlv(&mut vm, PointerType::AssetDefinitionId, &norito_blob(asset)),
            store_quantity(&mut vm, &5_u32.into()),
            0,
            0,
            0,
        ];
        let table = vm.alloc_heap(64).unwrap();
        for (index, word) in words.into_iter().enumerate() {
            vm.store_u64(table + index as u64 * 8, word).unwrap();
        }
        vm.set_register(10, table);
        vm
    }

    #[test]
    fn open_returns_exact_network_controller_key_asset_custody_and_charges_output() {
        let mut returned_accounts = std::collections::BTreeSet::new();
        for (network_seed, nonce, key, asset_name) in [
            (b"first".as_slice(), 92, b"lock".as_slice(), "ds"),
            (b"second".as_slice(), 92, b"lock".as_slice(), "ds"),
            (b"first".as_slice(), 93, b"lock".as_slice(), "ds"),
            (b"first".as_slice(), 92, b"other".as_slice(), "ds"),
            (b"first".as_slice(), 92, b"lock".as_slice(), "other"),
        ] {
            let mut host = host();
            // Hold the controller network constant so the second case isolates
            // the actual host network rather than accidentally testing it twice.
            let controller = iroha_data_model::smart_contract::ContractAddress::derive(
                host.network_id.as_ref().unwrap(),
                &ALICE_ID,
                nonce,
                DataSpaceId::UNIVERSAL,
            )
            .unwrap();
            let context = host.current_contract_runtime_context.as_mut().unwrap();
            context.contract_subject = controller.subject_id();
            context.contract_address = controller.clone();
            let network = NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(network_seed)),
            );
            host.set_network_id(network);
            let asset = asset_for(asset_name);
            let mut vm = opening_vm(&asset, key);
            let gas = host
                .syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm)
                .unwrap();
            let pointer = vm.register(10);
            let returned =
                CoreHost::decode_tlv_typed::<AccountId>(&vm, pointer, PointerType::AccountId)
                    .unwrap();
            let expected = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                &network,
                &controlled_asset_lock_id(&controller, key),
                &asset,
            );
            assert_eq!(returned, expected);
            assert!(returned_accounts.insert(returned));
            assert_eq!(host.queued.len(), 1);
            let instruction = host.queued[0].instruction().unwrap();
            let opening = instruction
                .as_any()
                .downcast_ref::<OpenControlledAssetLockV1>()
                .unwrap();
            assert_eq!(
                opening.lock.escrow_id,
                controlled_asset_lock_id(&controller, key)
            );
            assert_eq!(opening.source, *ALICE_ID);
            assert_eq!(opening.lock.destination, *BOB_ID);
            assert_eq!(opening.lock.asset_definition, asset);
            assert_eq!(opening.lock.amount, 5_u32.into());
            assert_eq!(host.queued[0].authority, controller.subject_id());
            let encoded = CoreHost::encode_tlv_payload(
                PointerType::AccountId,
                &CoreHost::encode_norito_payload(&expected).unwrap(),
            )
            .unwrap();
            assert_eq!(
                gas,
                crate::gas::meter_instruction(instruction, &host.confidential_gas).unwrap()
                    + encoded.len() as u64 * ivm::gas::SYSCALL_GAS_PER_BYTE
            );
        }
        assert_eq!(returned_accounts.len(), 5);
    }

    #[test]
    fn open_refuses_missing_network_or_substituted_frame_without_return_or_effect() {
        for absent_network in [true, false] {
            let mut host = host();
            if absent_network {
                host.network_id = None;
            } else {
                host.current_contract_runtime_context
                    .as_mut()
                    .unwrap()
                    .contract_subject = ALICE_ID.clone();
            }
            let mut vm = opening_vm(&asset_for("ds"), b"lock");
            let before = vm.register(10);
            assert!(matches!(
                host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm),
                Err(ivm::VMError::PermissionDenied)
            ));
            assert_eq!(vm.register(10), before);
            assert!(host.queued.is_empty());
            assert_eq!(host.instruction_queue_count, 0);
            assert_eq!(host.instruction_queue_encoded_bytes, 0);
        }
    }

    #[test]
    fn open_whole_return_allocation_refusal_preserves_queue_and_both_arenas() {
        let mut host = host();
        let mut vm = opening_vm(&asset_for("ds"), b"lock");
        let next = vm.alloc_input_tlv(&[]).unwrap() - ivm::Memory::INPUT_START;
        vm.alloc_input_tlv(&vec![0; (ivm::Memory::INPUT_SIZE - next) as usize])
            .unwrap();
        let heap_before = (vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START);
        vm.memory.set_heap_limit(heap_before).unwrap();
        let argument_table = vm.register(10);
        assert!(matches!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm),
            Err(ivm::VMError::OutOfMemory)
        ));
        assert_eq!(vm.register(10), argument_table);
        assert_eq!((vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START), heap_before);
        assert!(host.queued.is_empty());
        assert_eq!(host.instruction_queue_count, 0);
        assert_eq!(host.instruction_queue_encoded_bytes, 0);
        // A failed whole-allocation check cannot consume the INPUT cursor.
        assert_eq!(
            vm.alloc_input_tlv(&[]).unwrap(),
            ivm::Memory::INPUT_START + ivm::Memory::INPUT_SIZE
        );
    }

    #[test]
    fn open_retained_effect_capacity_refusal_does_not_publish_return() {
        let mut host = host();
        host.instruction_queue_limits.max_items = 0;
        let mut vm = opening_vm(&asset_for("ds"), b"lock");
        let argument_table = vm.register(10);
        let input_before = vm.alloc_input_tlv(&[]).unwrap();
        let heap_before = (vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START);
        assert!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN, &mut vm)
                .is_err()
        );
        assert!(host.queued.is_empty());
        assert_eq!(vm.register(10), argument_table);
        assert_eq!((vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START), heap_before);
        assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), input_before);
    }

    // Pure observation wrapper: all policy, preparation and execution use CoreHost.
    struct OpenGasProbe {
        inner: CoreHost,
        before: std::cell::Cell<Option<u64>>,
        reserve: Option<u64>,
        actual: Option<u64>,
    }

    impl IVMHost for OpenGasProbe {
        fn prepared_entrypoint_arguments(&self) -> Option<ivm::PreparedArgumentRecord> {
            self.inner.prepared_entrypoint_arguments()
        }
        fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
            self.inner.allows_syscall(policy, number)
        }
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN {
                assert!(self.before.replace(Some(vm.remaining_gas())).is_none());
            }
            self.inner.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN {
                assert!(self.reserve.replace(vm.syscall_reserved_gas()).is_none());
                assert!(vm.syscall_reserved_gas() > 0);
            }
            let result = self.inner.syscall(number, vm);
            if number == ivm::syscalls::SYSCALL_ASSET_LOCK_OPEN {
                self.actual = result.as_ref().ok().copied();
            }
            result
        }
        fn as_any(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    fn run_open_probe(
        program: &[u8],
        gas_limit: u64,
    ) -> (Result<(), ivm::VMError>, IVM, OpenGasProbe) {
        let metadata = ivm::ProgramMetadata::parse(program).unwrap();
        let entry = metadata
            .contract_interface
            .as_ref()
            .unwrap()
            .entrypoints
            .iter()
            .find(|entry| entry.name == "open")
            .unwrap();
        let schema = entry.argument_schema.as_ref().unwrap();
        let arguments = Json::new(std::collections::BTreeMap::from([
            ("key", "0x6c6f636b".to_owned()),
            ("source", ALICE_ID.canonical_i105().unwrap()),
            ("destination", BOB_ID.canonical_i105().unwrap()),
            ("asset", asset_for("ds").canonical_address()),
            ("amount", "5".to_owned()),
        ]));
        let canonical =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &arguments).unwrap();
        let prepared =
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), gas_limit)
                .unwrap();
        let mut inner = host();
        inner.set_entrypoint_argument_record(Some(prepared.clone()));
        let mut host = OpenGasProbe {
            inner,
            before: std::cell::Cell::new(None),
            reserve: None,
            actual: None,
        };
        let mut vm = IVM::new(gas_limit);
        vm.load_program(program).unwrap();
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(metadata.prefix_len() as u64 + entry.entry_pc)
            .unwrap();
        prepared.precharge_vm(&mut vm).unwrap();
        let result = vm.run_with_host(&mut host);
        (result, vm, host)
    }

    #[test]
    fn compiled_open_returns_custody_and_vm_dispatch_refuses_one_unit_short_before_queue() {
        const CONTROL: u64 = 50_000_000;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(CUSTODY_SOURCE)
            .unwrap();
        let (result, vm, control) = run_open_probe(&program, CONTROL);
        result.expect("real compiled open and AccountId result capture");
        assert_eq!(control.inner.queued.len(), 1);
        assert_eq!(vm.call_result_word_count().unwrap(), 1);
        let returned = CoreHost::decode_tlv_typed::<AccountId>(
            &vm,
            vm.public_call_result_word(0).unwrap(),
            PointerType::AccountId,
        )
        .unwrap();
        let controller = &control
            .inner
            .current_contract_runtime_context
            .as_ref()
            .unwrap()
            .contract_address;
        assert_eq!(
            returned,
            crate::smartcontracts::isi::escrow::escrow_custody_account_id(
                control.inner.network_id.as_ref().unwrap(),
                &controlled_asset_lock_id(controller, b"lock"),
                &asset_for("ds"),
            )
        );
        let actual = control.actual.unwrap();
        assert!(actual > 0);
        assert!(control.reserve.unwrap() >= actual);
        let setup = CONTROL - control.before.get().unwrap();
        let (result, refused_vm, refused) = run_open_probe(&program, setup + actual - 1);
        assert!(matches!(
            result.unwrap_err().as_unmetered(),
            ivm::VMError::OutOfGas
        ));
        assert_eq!(refused.before.get(), Some(actual - 1));
        if let Some(reserved) = refused.reserve {
            assert!(reserved < actual);
        }
        assert!(refused.actual.is_none());
        assert!(refused_vm.call_result_word_count().is_err());
        assert!(refused.inner.queued.is_empty());
        assert_eq!(refused.inner.instruction_queue_count, 0);
        assert_eq!(refused.inner.instruction_queue_encoded_bytes, 0);
    }
}
