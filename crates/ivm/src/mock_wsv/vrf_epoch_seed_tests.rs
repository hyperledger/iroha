//! Exact deterministic epoch-seed fixtures through the typed source boundary.

use super::*;

fn execute(epoch: &str) -> (IVM, crate::PreparedContract, Result<(), VMError>) {
    let source = "seiyaku SeedReader { view fn read(int epoch) authorize(anyone) -> Option<bytes> { return crypto::vrf::epoch_seed(epoch: epoch); } }";
    let artifact = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let prepared = crate::prepare_contract(artifact.into()).unwrap();
    let mut wsv = MockWorldStateView::new();
    wsv.set_vrf_epoch_seed_fixture(7, [0x42; 32]);
    wsv.set_vrf_epoch_seed_fixture(99, [0xA5; 32]);
    let mut vm = IVM::new(1_000_000);
    vm.load_prepared(&prepared).unwrap();
    vm.select_entrypoint("read").unwrap();
    let arguments = Json::from(norito::json!({"epoch": epoch}));
    let schema = prepared.contract_interface().entrypoints[0]
        .argument_schema
        .as_ref()
        .unwrap();
    let record = ivm_abi::arguments::encode_argument_record_from_json(schema, &arguments).unwrap();
    let input = pointer_abi::encode_tlv(PointerType::NoritoBytes, &record).unwrap();
    vm.set_host(
        WsvHost::new_with_subject(
            wsv,
            test_account_id(
                "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
                "fixture",
            ),
        )
        .with_public_inputs(BTreeMap::from([(
            ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
                .parse()
                .unwrap(),
            input,
        )])),
    );
    let result = vm.run();
    (vm, prepared, result)
}

#[test]
fn typed_epoch_seed_returns_some_exact_seed_or_none_without_fallback() {
    for (epoch, seed) in [
        ("0", None),
        ("7", Some([0x42; 32])),
        ("8", None),
        ("99", Some([0xA5; 32])),
        ("18446744073709551615", None),
    ] {
        let (vm, prepared, result) = execute(epoch);
        result.unwrap();
        let entry = &prepared.contract_interface().entrypoints[0];
        let value = crate::value_record::decode_entrypoint_return(
            &vm,
            entry.return_schema.as_ref().unwrap(),
        )
        .unwrap();
        let expected = if let Some(seed) = seed {
            {
                let encoded = format!("0x{}", hex::encode(seed));
                norito::json!({"some": encoded})
            }
        } else {
            norito::json!({"none": true})
        };
        assert_eq!(value, expected, "epoch {epoch}");
    }
}

#[test]
fn typed_epoch_seed_rejects_epoch_outside_u64_without_truncation() {
    for epoch in ["-1", "18446744073709551616"] {
        let (_, _, result) = execute(epoch);
        assert!(
            matches!(
                result.unwrap_err().as_unmetered(),
                VMError::NumericFault(crate::numeric::NumericFaultV1::InexactConversion)
            ),
            "epoch {epoch}"
        );
    }
}

#[test]
fn mock_epoch_seed_quote_matches_fixed_output_and_preserves_r11() {
    let mut wsv = MockWorldStateView::new();
    wsv.set_vrf_epoch_seed_fixture(7, [0x42; 32]);
    let mut host = WsvHost::new_with_subject(
        wsv,
        test_account_id(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
            "fixture",
        ),
    );
    for epoch in [7, 8, u64::MAX] {
        let mut vm = IVM::new(10_000);
        vm.set_register(10, epoch);
        vm.set_register(11, 0xA5);
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_VRF_EPOCH_SEED, &vm)
            .unwrap();
        let gas = host
            .syscall(syscalls::SYSCALL_VRF_EPOCH_SEED, &mut vm)
            .unwrap();
        assert_eq!(gas, quote);
        assert_eq!(gas, crate::vrf::epoch_seed_gas(epoch == 7));
        assert_eq!(vm.register(11), 0xA5);
        if epoch == 7 {
            let seed = vm.validate_tlv(vm.register(10)).unwrap();
            assert_eq!(seed.type_id, PointerType::Blob);
            assert_eq!(seed.payload, [0x42; 32]);
        } else {
            assert_eq!(vm.register(10), 0);
        }
    }
}
