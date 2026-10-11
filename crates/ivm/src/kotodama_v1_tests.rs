//! Executable acceptance tests for the final Kotodama V1 language surface.
use crate::{CoreHost, IVM, VMError, host::IVMHost, parallel::StateAccessSet};
use kotodama_lang::compiler::Compiler;

fn compiled_main(source: &str) -> IVM {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile final V1 contract");
    let mut vm = IVM::new(1_000_000_000);
    vm.load_program(&code).expect("load V1 contract");
    vm.select_entrypoint("main")
        .expect("select public main entrypoint");
    vm
}

fn returned_int(vm: &IVM) -> String {
    iroha_primitives::numeric_abi::IntValueV1::decode_frame(
        vm.validate_tlv(vm.public_call_result_word(0).expect("completed int result"))
            .expect("returned int envelope")
            .payload,
    )
    .expect("canonical int")
    .into_int()
    .to_string()
}

fn transaction_main(source: &str) -> Vec<u8> {
    Compiler::new().compile_source(source).unwrap()
}

/// Execute `code` as one transaction against the VM's installed host `H`.
///
/// The host is checkpointed first and restored when execution fails, when the
/// host cannot finish the transaction, or when it reports accesses outside
/// `declared`, so a failed transaction leaves no host side effects.
fn run_transaction<H: IVMHost + 'static>(
    vm: &mut IVM,
    code: &[u8],
    declared: &StateAccessSet,
) -> bool {
    fn host<H: 'static>(vm: &mut IVM) -> &mut H {
        vm.host_mut_any()
            .and_then(|host| host.downcast_mut::<H>())
            .expect("transaction host type")
    }
    let snapshot = host::<H>(vm)
        .checkpoint()
        .expect("transactional host checkpoint");
    host::<H>(vm).begin_tx(declared).expect("begin transaction");
    vm.load_program(code).expect("load transaction");
    vm.set_gas_limit(1_000_000_000);
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.select_entrypoint("main")
        .expect("select public transaction entrypoint");
    let ran = vm.run().is_ok();
    let success = host::<H>(vm).finish_tx().is_ok_and(|log| {
        ran && log.read_keys.is_subset(&declared.read_keys)
            && log.write_keys.is_subset(&declared.write_keys)
            && log.reg_tags.is_subset(&declared.reg_tags)
    });
    if !success {
        host::<H>(vm)
            .restore(snapshot.as_ref())
            .expect("restore transactional host checkpoint");
    }
    success
}

#[test]
fn checked_list_errors_revert_prior_state_effects_with_exact_identity() {
    for (operation, code, name) in [
        ("values.push(9)", 2, "CapacityExceeded"),
        ("values.set(index: 1, value: 9)", 1, "IndexOutOfBounds"),
    ] {
        let source = format!(
            r#"seiyaku Checked {{ permission Writer;
            state int changed;
            hajimari() {{ changed = 0; }}
            fn full() -> List<int, 1> {{ [3] }}
            kotoage fn main() authorize(Writer) {{
                changed = 7;
                var List<int, 1> values = full();
                {operation};
            }}
        }}"#
        );
        let mut vm = compiled_main(&source);
        let mut host = CoreHost::new();
        let error = vm
            .run_with_host(&mut host)
            .expect_err("checked mutation aborts");
        let expected = ivm_abi::error_types::list_error_type();
        let VMError::ContractAbort {
            error_type,
            schema_hash,
            code: observed,
            name: observed_name,
            ..
        } = error.as_unmetered()
        else {
            panic!("expected nominal list error, observed {error:?}");
        };
        assert_eq!(error_type, &expected.identity);
        assert_eq!(schema_hash, &expected.schema_hash());
        assert_eq!((*observed, observed_name.as_str()), (code, name));
        assert_eq!(
            host.state_paths(),
            ["changed"],
            "the raw interpreter reached its prior write"
        );
        let mut transactional = IVM::new(1_000_000_000);
        transactional.set_host(CoreHost::new());
        let execute = |vm: &mut IVM, source: &str| {
            let mut access = StateAccessSet::new();
            access.write_keys.insert("changed".to_owned());
            run_transaction::<CoreHost>(vm, &transaction_main(source), &access)
        };
        assert!(!execute(&mut transactional, &source));
        assert!(
            transactional
                .host_mut_any()
                .unwrap()
                .downcast_mut::<CoreHost>()
                .unwrap()
                .state_paths()
                .is_empty(),
            "transactional execution must restore prior state on checked failure"
        );
        let successful = source.replace(operation, "values.set(index: 0, value: 9)");
        assert!(
            execute(&mut transactional, &successful),
            "the same transaction harness must accept a valid checked write"
        );
        assert_eq!(
            transactional
                .host_mut_any()
                .unwrap()
                .downcast_mut::<CoreHost>()
                .unwrap()
                .state_paths(),
            ["changed"]
        );
    }
}

#[test]
fn fallible_list_errors_preserve_values_and_length() {
    let mut vm = compiled_main(
        r#"seiyaku Fallible {
        error enum Check { Failed = 1 }
        view fn main() authorize(anyone) -> int {
            var List<int, 2> values = [3, 4];
            match values.try_set(index: -1, value: 9) {
                Result::ok(_) => { require(false, Check::Failed); },
                Result::err(failure) => { require(failure == ListError::IndexOutOfBounds, Check::Failed); },
            };
            match values.try_push(9) {
                Result::ok(_) => { require(false, Check::Failed); },
                Result::err(failure) => { require(failure == ListError::CapacityExceeded, Check::Failed); },
            };
            var sum = 0;
            for value in values { sum += value; }
            sum * 10 + values.len()
        }
    }"#,
    );
    vm.run_with_host(&mut CoreHost::new())
        .expect("recoverable list failures");
    assert_eq!(returned_int(&vm), "72");
}

#[test]
fn named_call_arguments_and_struct_patterns_evaluate_once_in_source_order() {
    let mut vm = compiled_main(
        r#"seiyaku Named { permission Writer;
        struct Receipt { int second; int first; () memo; }
        state int trace;
        hajimari() { trace = 0; }
        fn mark(int _ value) -> int { trace = trace * 10 + value; value }
        fn pack(int first, int second) -> Receipt {
            Receipt { first: first, second: second, memo: () }
        }
        kotoage fn main() authorize(Writer) -> int {
            trace = 0;
            let Receipt { first, second: renamed, memo: _ } = pack(second: mark(2), first: mark(1));
            trace * 100 + first * 10 + renamed
        }
    }"#,
    );
    let mut host = CoreHost::new();
    vm.run_with_host(&mut host).expect("named values execute");
    assert_eq!(returned_int(&vm), "2112");
    let trace: ivm_abi::state_value::StateValueRecordV1 = norito::decode_from_bytes(
        &host
            .state_bytes("trace")
            .expect("callee persisted its state trace"),
    )
    .expect("canonical state record");
    let [ivm_abi::state_value::StateValueAtomV1::Pointer(envelope)] = trace.atoms.as_slice() else {
        panic!("trace state contains one int pointer");
    };
    assert_eq!(
        crate::numeric_tlv::decode_int_bytes(envelope)
            .expect("trace int envelope")
            .to_string(),
        "21"
    );
}

#[test]
fn generated_pages_materialize_pairs_and_resume_across_large_overlays() {
    let mut vm = compiled_main(
        r#"seiyaku Pages { permission Writer;
        state StateMap<int, int> orders;
        kotoage fn main() authorize(Writer) -> int {
            for index in range(200) { orders[index] = index; }
            var Option<StateCursor<int>> cursor = Option::none;
            var sum = 0;
            for iteration in range(4) {
                let page = orders.page(after: cursor, limit: 64);
                for (key, value) in page.items { sum += value; }
                cursor = page.next;
            }
            sum
        }
    }"#,
    );
    vm.run_with_host(&mut CoreHost::new())
        .expect("execute generated keyset pages");
    assert_eq!(returned_int(&vm), "19900");
}

#[test]
fn fused_rounding_matches_constant_folding_through_generated_code_in_every_mode() {
    for mode in [
        "toward_zero",
        "away_from_zero",
        "floor",
        "ceil",
        "nearest_even",
        "nearest_away",
        "nearest_toward_zero",
    ] {
        let source = format!(
            r#"seiyaku Rounded {{
            error enum Check {{ Mismatch = 1 }}
            const quantity SAMPLE = 13;
            fn repeated(decimal _ value) -> decimal {{
                value.mul_div_round(multiplier: 1.17, divisor: 7.0, scale: 2, mode: Rounding::{mode})
            }}
            fn tie(decimal _ value) -> decimal {{
                value.mul_div_round(multiplier: 1.0, divisor: 1.0, scale: 2, mode: Rounding::{mode})
            }}
            fn amount(quantity _ value) -> quantity {{
                value.mul_div_round(multiplier: 1.17, divisor: 7.0, scale: 2, mode: Rounding::{mode})
            }}
            view fn main() authorize(anyone) {{
                require(repeated(7.13) == 7.13.mul_div_round(multiplier: 1.17, divisor: 7.0, scale: 2, mode: Rounding::{mode}), Check::Mismatch);
                require(repeated(-7.13) == (-7.13).mul_div_round(multiplier: 1.17, divisor: 7.0, scale: 2, mode: Rounding::{mode}), Check::Mismatch);
                require(tie(2.345) == 2.345.mul_div_round(multiplier: 1.0, divisor: 1.0, scale: 2, mode: Rounding::{mode}), Check::Mismatch);
                require(tie(-2.345) == (-2.345).mul_div_round(multiplier: 1.0, divisor: 1.0, scale: 2, mode: Rounding::{mode}), Check::Mismatch);
                require(amount(SAMPLE) == SAMPLE.mul_div_round(multiplier: 1.17, divisor: 7.0, scale: 2, mode: Rounding::{mode}), Check::Mismatch);
            }}
        }}"#
        );
        let mut vm = compiled_main(&source);
        vm.run_with_host(&mut CoreHost::new())
            .unwrap_or_else(|error| {
                panic!("generated fused arithmetic differs in {mode}: {error}")
            });
        assert_eq!(vm.public_call_result_word(0), Ok(0));
    }
}

#[test]
fn unit_and_nominal_errors_round_trip_through_durable_values() {
    let mut vm = compiled_main(
        r#"seiyaku Values { permission Writer;
        error enum Check { Failed = 1 }
        state () marker;
        state List<(), 2> markers;
        state Option<()> optional;
        state Result<(), Check> outcome;
        state Check failure;
        hajimari() {
            marker = (); markers = []; optional = Option::none;
            outcome = Result::ok(()); failure = Check::Failed;
        }
        fn verify() {
            require(marker == (), Check::Failed);
            require(markers.len() == 2, Check::Failed);
            require(failure == Check::Failed, Check::Failed);
            match optional {
                Option::some(value) => { require(value == (), Check::Failed); },
                Option::none => { require(false, Check::Failed); },
            };
            match outcome {
                Result::ok(_) => { require(false, Check::Failed); },
                Result::err(value) => { require(value == Check::Failed, Check::Failed); },
            };
            ()
        }
        kotoage fn main() authorize(Writer) -> () {
            marker = ();
            markers = [(), ()];
            optional = Option::some(());
            outcome = Result::err(Check::Failed);
            failure = Check::Failed;
            verify();
        }
    }"#,
    );
    vm.run_with_host(&mut CoreHost::new())
        .expect("durable Unit and nominal errors");
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed Unit result"),
        0,
        "Unit has one canonical zero scalar word"
    );
}

#[test]
fn bounded_transfer_lists_evaluate_before_begin_and_skip_empty_batches() {
    use crate::{IVMHost, syscalls};
    struct ObservedHost {
        core: CoreHost,
        events: Vec<u32>,
        quantities: Vec<String>,
    }
    impl IVMHost for ObservedHost {
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, VMError> {
            self.core.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
            self.events.push(number);
            if number == syscalls::SYSCALL_TRANSFER_V1 {
                self.quantities.push(
                    iroha_primitives::numeric_abi::QuantityValueV1::decode_frame(
                        vm.validate_tlv(vm.register(13))?.payload,
                    )
                    .map_err(|_| VMError::NoritoInvalid)?
                    .into_quantity()
                    .to_string(),
                );
            }
            self.core.syscall(number, vm)
        }
        fn as_any(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }
    let source = r#"seiyaku BatchOrder { permission Writer;
        state int seen;
        hajimari() { seen = 0; }
        fn amount(int digit) -> quantity { seen = seen * 10 + digit; 1 }
        kotoage fn main() authorize(Writer) -> int {
            seen = 0;
            let account = context::authority();
            let asset = AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM");
            ledger::asset::transfer_batch(transfers: [
                (account, account, asset, amount(digit: 1)),
                (account, account, asset, amount(digit: 2))
            ]);
            let List<(AccountId, AccountId, AssetDefinitionId, quantity), 8> empty = [];
            ledger::asset::transfer_batch(transfers: empty);
            ledger::asset::transfer_batch(transfers: []);
            seen
        }
    }"#;
    let mut vm = compiled_main(source);
    let mut host = ObservedHost {
        core: CoreHost::new(),
        events: Vec::new(),
        quantities: Vec::new(),
    };
    vm.run_with_host(&mut host).expect("bounded batch executes");
    assert_eq!(
        returned_int(&vm),
        "12",
        "list elements evaluate left-to-right"
    );
    let begin = host
        .events
        .iter()
        .position(|number| *number == syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN)
        .unwrap();
    assert!(
        host.events
            .iter()
            .enumerate()
            .filter(|(_, number)| **number == syscalls::SYSCALL_STATE_SET)
            .all(|(index, _)| index < begin)
    );
    let batch_events = host
        .events
        .into_iter()
        .filter(|number| {
            matches!(
                *number,
                syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN
                    | syscalls::SYSCALL_TRANSFER_V1
                    | syscalls::SYSCALL_TRANSFER_V1_BATCH_END
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        batch_events,
        [
            syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN,
            syscalls::SYSCALL_TRANSFER_V1,
            syscalls::SYSCALL_TRANSFER_V1,
            syscalls::SYSCALL_TRANSFER_V1_BATCH_END
        ]
    );
    assert_eq!(host.quantities, ["1", "1"]);
}

#[test]
fn saved_transfer_lists_apply_in_order_and_roll_back_on_failure() {
    use crate::mock_wsv::{MockWorldStateView, PermissionToken, WsvHost};
    use iroha_data_model::{AccountId, AssetDefinitionId};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Quantity;
    let account = |key: &str| AccountId::new(key.parse().unwrap());
    let alice = account("ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774");
    let bob = account("ed01201509A611AD6D97B01D871E58ED00C8FD7C3917B6CA61A8C2833A19E000AAC2E4");
    let carol = account("ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245");
    let asset = AssetDefinitionId::derive_from_components(
        DomainId::try_new("domain", "universal").unwrap(),
        "asset".parse().unwrap(),
    );
    for (second_amount, success, balances) in [(5, true, [40, 5, 5]), (11, false, [50, 0, 0])] {
        let source = format!(
            r#"seiyaku BatchAtomic {{ permission Writer;
            kotoage fn main() authorize(Writer) {{
                let alice = AccountId::parse("{alice}");
                let bob = AccountId::parse("{bob}");
                let carol = AccountId::parse("{carol}");
                let asset = AssetDefinitionId::parse("{asset}");
                let List<(AccountId, AccountId, AssetDefinitionId, quantity), 8> entries = [
                    (alice, bob, asset, 10), (bob, carol, asset, {second_amount})
                ];
                ledger::asset::transfer_batch(transfers: entries);
            }}
        }}"#
        );
        let mut wsv = MockWorldStateView::with_balances(&[
            ((alice.clone(), asset.clone()), Quantity::from(50_u64)),
            ((bob.clone(), asset.clone()), Quantity::from(0_u64)),
            ((carol.clone(), asset.clone()), Quantity::from(0_u64)),
        ]);
        wsv.grant_permission(&alice, PermissionToken::TransferAsset(asset.clone()));
        let mut vm = IVM::new(1_000_000_000);
        vm.set_host(WsvHost::new_with_subject(wsv, alice.clone()));
        let outcome =
            run_transaction::<WsvHost>(&mut vm, &transaction_main(&source), &StateAccessSet::new());
        assert_eq!(outcome, success, "{second_amount}");
        let host = vm
            .host_mut_any()
            .unwrap()
            .downcast_mut::<WsvHost>()
            .unwrap();
        for (account, balance) in [&alice, &bob, &carol].into_iter().zip(balances) {
            assert_eq!(
                host.wsv.balance(account.clone(), asset.clone()),
                Quantity::from(balance as u64)
            );
        }
    }
}

#[test]
fn static_error_messages_preserve_nominal_schema_and_reach_rejections() {
    fn source(message: &str) -> String {
        format!(
            r#"seiyaku Explained {{
            error enum Failure {{ #[message("{message}")] Rejected = 7 }}
            view fn main() authorize(anyone) {{ require(false, Failure::Rejected); }}
        }}"#
        )
    }
    let (first, first_manifest) = Compiler::new()
        .compile_source_with_manifest(&source("残高が不足しています"))
        .unwrap();
    let (second, second_manifest) = Compiler::new()
        .compile_source_with_manifest(&source("Insufficient balance"))
        .unwrap();
    assert_eq!(first_manifest.error_types, second_manifest.error_types);
    assert_ne!(first_manifest.code_hash, second_manifest.code_hash);
    assert_ne!(first, second);
    let mut vm = compiled_main(&source("残高が不足しています"));
    let error = vm.run().expect_err("declared failure");
    assert!(
        matches!(error.as_unmetered(), VMError::ContractAbort { code: 7, message: Some(text), .. } if text.as_ref() == "残高が不足しています")
    );
    assert!(error.to_string().contains("残高が不足しています"));
    let mut second_vm = compiled_main(&source("Insufficient balance"));
    second_vm.run().expect_err("declared failure");
    assert_eq!(
        second_vm.remaining_gas() - vm.remaining_gas(),
        ("残高が不足しています".len() - "Insufficient balance".len()) as u64,
        "abort execution and its quote charge the exact UTF-8 message bytes"
    );
}
